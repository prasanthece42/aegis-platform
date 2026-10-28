"""Validate telemetry configs and alert transitions in isolated, cached pinned images.

No cluster access, live credentials, image pulls, published ports or notifications.
"""

import argparse
import base64
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from aegis_platform.observability import observability_plan
from aegis_platform.observability_policy import ObservabilityPolicy


def alert_test():
    labels = 'k8s_namespace_name="aegis-hello-aegis-dev",aegis_cluster_uid="test-cluster"'
    return {
        "rule_files": ["/etc/aegis/rules.json"],
        "evaluation_interval": "15s",
        "tests": [
            {
                "interval": "15s",
                "input_series": [
                    {
                        "series": "http_server_requests_total{"
                        + labels
                        + ',http_response_status_code="200"}',
                        "values": "0+100x12",
                    },
                    {
                        "series": "http_server_requests_total{"
                        + labels
                        + ',http_response_status_code="500"}',
                        "values": "0 0 100 200 300 400 400 400 400 400 400 400 400",
                    },
                ],
                "alert_rule_test": [
                    {"eval_time": "15s", "alertname": "AegisHighErrorRate", "exp_alerts": []},
                    {
                        "eval_time": "1m",
                        "alertname": "AegisHighErrorRate",
                        "exp_alerts": [
                            {
                                "exp_labels": {
                                    "k8s_namespace_name": "aegis-hello-aegis-dev",
                                    "aegis_cluster_uid": "test-cluster",
                                    "severity": "warning",
                                },
                                "exp_annotations": {
                                    "summary": "Application HTTP errors exceed 5%",
                                    "grafana_url": "http://127.0.0.1:3000/d/aegis-application"
                                    "?var-cluster=test-cluster&var-namespace=aegis-hello-aegis-dev",
                                },
                            }
                        ],
                    },
                    {"eval_time": "3m", "alertname": "AegisHighErrorRate", "exp_alerts": []},
                ],
            }
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=Path("policies/observability.json"))
    parser.add_argument("--output", type=Path, default=Path(".local/observability-validation"))
    args = parser.parse_args()
    policy = ObservabilityPolicy.model_validate_json(args.policy.read_text())
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=True)
    auth, sa = root / "auth", root / "serviceaccount"
    auth.mkdir(exist_ok=True)
    sa.mkdir(exist_ok=True)
    password = "synthetic-validation-password"
    hashed = subprocess.run(
        ["openssl", "passwd", "-apr1", "-stdin"],
        input=password + "\n",
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    for name in ["query", "ingest", "agent"]:
        (auth / (name + "-password")).write_text("synthetic-validation-password")
        (auth / (name + ".htpasswd")).write_text(name + ":" + hashed + "\n")
    (sa / "token").write_text("synthetic-validation-token")
    (sa / "namespace").write_text("aegis-observability")
    (sa / "ca.crt").write_text(policy.kubelet_ca_pem)
    plan = observability_plan(policy, "a" * 40)
    for resource in plan.values():
        if resource.get("kind") != "ConfigMap" or "config.yaml" not in resource.get("data", {}):
            continue
        folder = root / resource["metadata"]["name"].removesuffix("-config")
        folder.mkdir(exist_ok=True)
        for key, value in resource["data"].items():
            (folder / key).write_text(value)
    (root / "prometheus" / "alert-test.json").write_text(json.dumps(alert_test()))
    commands = {
        "prometheus": ["/bin/promtool", "check", "config", "/etc/aegis/config.yaml"],
        "alertmanager": ["/bin/amtool", "check-config", "/etc/aegis/config.yaml"],
        "loki": ["/usr/bin/loki", "-config.file=/etc/aegis/config.yaml", "-verify-config=true"],
        "tempo": ["/tempo", "-config.file=/etc/aegis/config.yaml", "-config.verify=true"],
        "collector": ["/otelcol-contrib", "validate", "--config=/etc/aegis/config.yaml"],
    }
    jobs = [(name, name, name, cmd) for name, cmd in commands.items()]
    jobs += [
        (name + "-proxy", "proxy", name, ["nginx", "-t", "-c", "/etc/aegis/nginx.conf"])
        for name in commands
    ]
    jobs.append(
        (
            "alert-fire-clear",
            "prometheus",
            "prometheus",
            ["/bin/promtool", "test", "rules", "/etc/aegis/alert-test.json"],
        )
    )

    basic = base64.b64encode(("query:" + password).encode()).decode()
    # No upstream runs: 502 proves valid credentials passed authentication.
    auth_check = r"""
set -eu
nginx -c /etc/aegis/nginx.conf -g 'daemon off;' >/tmp/nginx.log 2>&1 &
proxy_pid=$!
trap 'kill "$proxy_pid" 2>/dev/null || true' EXIT
attempt=0
until wget -S -O /dev/null http://127.0.0.1:8080/api/v1/alerts >/tmp/response 2>&1; do
  if grep -q '401 Unauthorized' /tmp/response; then break; fi
  attempt=$((attempt+1))
  if [ "$attempt" -ge 30 ]; then cat /tmp/nginx.log; exit 1; fi
  sleep 0.1
done
grep -q '401 Unauthorized' /tmp/response
wget -S -O /dev/null --header='Authorization: Basic aW52YWxpZDppbnZhbGlk' \
  http://127.0.0.1:8080/api/v1/alerts >/tmp/response 2>&1 || true
grep -q '401 Unauthorized' /tmp/response
wget -S -O /dev/null --header='Authorization: Basic BASIC_VALUE' \
  http://127.0.0.1:8080/api/v1/alerts >/tmp/response 2>&1 || true
grep -q '502 Bad Gateway' /tmp/response
wget -S -O /dev/null --post-data='' --header='Authorization: Basic BASIC_VALUE' \
  http://127.0.0.1:8080/api/v1/alerts >/tmp/response 2>&1 || true
grep -q '405 Not Allowed' /tmp/response
wget -S -O /dev/null --header='Authorization: Basic BASIC_VALUE' \
  http://127.0.0.1:8080/unapproved-path >/tmp/response 2>&1 || true
grep -q '404 Not Found' /tmp/response
echo 'Anonymous/invalid credentials denied; valid query authenticated; writes/unknown paths denied.'
""".replace("BASIC_VALUE", basic)
    jobs.append(("query-authentication", "proxy", "prometheus", ["/bin/sh", "-c", auth_check]))

    def check(job):
        name, image, config, command = job
        args = [
            "docker",
            "run",
            "--rm",
            "--pull=never",
            "--network",
            "none",
            "--read-only",
            "--memory",
            "512m",
            "--cpus",
            "1",
            "--user",
            "10001:10001",
        ]
        for folder in ["/tmp", "/data", "/var/tempo"]:
            args += ["--tmpfs", folder + ":rw,size=64m,uid=10001,gid=10001"]
        for source, target in [
            (root / config, "/etc/aegis"),
            (auth, "/run/telemetry-auth"),
            (sa, "/var/run/secrets/kubernetes.io/serviceaccount"),
        ]:
            args += ["--mount", f"type=bind,src={source},dst={target},readonly"]
        args += [
            "-e",
            "KUBERNETES_SERVICE_HOST=127.0.0.1",
            "-e",
            "KUBERNETES_SERVICE_PORT=6443",
            "-e",
            "K8S_NODE_NAME=" + policy.node_name,
            "-e",
            "K8S_NODE_IP=127.0.0.1",
            "--entrypoint",
            command[0],
            policy.images[image],
            *command[1:],
        ]
        result = subprocess.run(args, capture_output=True, text=True, timeout=60)
        return {
            "check": name,
            "exit_code": result.returncode,
            "output": (result.stdout + result.stderr)[-2400:],
        }

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(check, jobs))
    (root / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    for result in results:
        print(json.dumps(result), flush=True)
    if any(result["exit_code"] for result in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
