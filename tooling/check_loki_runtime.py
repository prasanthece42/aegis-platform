"""Real isolated Loki push/query check; validates internal ring connectivity without a cluster."""

import json
import secrets
import subprocess
from pathlib import Path

from aegis_platform.observability_config import loki_config
from aegis_platform.observability_policy import ObservabilityPolicy

# Runs in the Python utility image sharing only Loki's isolated loopback namespace.
PROBE = r"""
import json, time, urllib.request, urllib.parse, urllib.error
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
base = 'http://127.0.0.1:3100'
for _ in range(120):
    try:
        with opener.open(base + '/ready', timeout=1) as response:
            if response.status == 200:
                break
    except (OSError, urllib.error.HTTPError):
        pass
    time.sleep(0.5)
else:
    raise SystemExit('Loki did not become ready')
health_query = urllib.parse.urlencode({'query': 'vector(1)+vector(1)', 'time': '4000000000'})
with opener.open(base + '/loki/api/v1/query?' + health_query, timeout=8) as response:
    health = json.load(response)
assert health['data']['result'][0]['value'][1] == '2'
now = time.time_ns()
payload = {'streams': [{'stream': {'service_name': 'synthetic-validation',
    'aegis_cluster_uid': 'synthetic-isolated-cluster'},
    'values': [[str(now), 'synthetic Loki ring validation']]}]}
request = urllib.request.Request(base + '/loki/api/v1/push',
    data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json'}, method='POST')
with opener.open(request, timeout=8) as response:
    assert response.status == 204
query = urllib.parse.urlencode({'query': '{aegis_cluster_uid="synthetic-isolated-cluster"}',
    'start': str(now - 60000000000), 'end': str(now + 60000000000), 'limit': '5'})
for _ in range(20):
    with opener.open(base + '/loki/api/v1/query_range?' + query, timeout=8) as response:
        result = json.load(response)
    if result.get('data', {}).get('result'):
        assert any(row[1] == 'synthetic Loki ring validation'
            for stream in result['data']['result'] for row in stream.get('values', []))
        print('Real Loki readiness, Grafana health query, ingestion and indexed query passed')
        break
    time.sleep(0.5)
else:
    raise SystemExit('Accepted synthetic log was not queryable')
"""


def main():
    policy = ObservabilityPolicy.model_validate_json(
        Path("policies/observability.json").read_text()
    )
    root = Path(".local/loki-runtime-validation").resolve()
    root.mkdir(parents=True, exist_ok=True)
    (root / "config.yaml").write_text(json.dumps(loki_config(), indent=2) + "\n")
    name = "aegis-loki-runtime-" + secrets.token_hex(4)

    def docker(*args, check=True, timeout=120):
        result = subprocess.run(
            ["docker", *args], capture_output=True, text=True, check=False, timeout=timeout
        )
        if check and result.returncode:
            raise RuntimeError("Isolated Loki validation failed: " + result.stderr[-1600:])
        return result

    try:
        docker(
            "run",
            "-d",
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            "--user=10001:10001",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--memory=512m",
            "--cpus=1",
            "--name",
            name,
            "--tmpfs",
            "/data:rw,uid=10001,gid=10001,size=128m",
            "--tmpfs",
            "/tmp:rw,uid=10001,gid=10001,size=64m",
            "--mount",
            f"type=bind,src={root},dst=/etc/aegis,readonly",
            "--entrypoint",
            "/usr/bin/loki",
            policy.images["loki"],
            "-config.file=/etc/aegis/config.yaml",
        )
        result = docker(
            "run",
            "--rm",
            "--pull=never",
            "--network=container:" + name,
            "--read-only",
            "--user=10001:10001",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--memory=128m",
            "--cpus=1",
            "--entrypoint",
            "python",
            policy.images["log_agent"],
            "-c",
            PROBE,
        )
        report = {
            "passed": True,
            "result": result.stdout.strip(),
            "external_network": False,
            "cluster_changes": False,
        }
        (root / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report))
    finally:
        docker("rm", "-f", name, check=False)


if __name__ == "__main__":
    main()
