"""Actual cached-image provisioning/auth smoke; no cluster writes or backend fixtures."""

import base64
import json
import os
import secrets
import subprocess
import time
from pathlib import Path

from aegis_platform.grafana import ASSETS, IMAGE, dashboards, grafana_plan
from aegis_platform.observability_policy import ObservabilityPolicy


def main():
    root = Path(".local/grafana-validation").resolve()
    for folder in ["provisioning/datasources", "provisioning/dashboards", "dashboards"]:
        (root / folder).mkdir(parents=True, exist_ok=True)
    for filename, dest in [("datasources.yaml", "datasources"), ("dashboards.yaml", "dashboards")]:
        (root / "provisioning" / dest / "aegis.yaml").write_text((ASSETS / filename).read_text())
    for filename, board in dashboards("validation-cluster").items():
        (root / "dashboards" / filename).write_text(json.dumps(board))
    password = secrets.token_hex(24)
    env_file = root / "runtime.env"
    env_file.touch(mode=0o600)
    os.chmod(env_file, 0o600)
    policy = ObservabilityPolicy.model_validate_json(
        Path("policies/observability.json").read_text()
    )
    plan = grafana_plan(policy, "a" * 40)
    deployment = next(v for v in plan.values() if v.get("kind") == "Deployment")
    env = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
    runtime = {item["name"]: item["value"] for item in env if "value" in item}
    runtime.update(AEGIS_QUERY_PASSWORD="synthetic-query-only", GF_LOG_LEVEL="error")
    env_file.write_text("".join(f"{key}={value}\n" for key, value in runtime.items()))
    auth_dir = root / "auth"
    auth_dir.mkdir(exist_ok=True)
    (auth_dir / "admin-password").write_text(password)
    (auth_dir / "secret-key").write_text(secrets.token_hex(32))
    name = "aegis-grafana-validation-" + secrets.token_hex(4)

    def docker(*args, check=True):
        return subprocess.run(
            ["docker", *args], capture_output=True, text=True, check=check, timeout=60
        )

    results = []
    try:
        docker(
            "run",
            "-d",
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            "--user=472:472",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--memory=512m",
            "--cpus=1",
            "--name",
            name,
            "--env-file",
            str(env_file),
            "--tmpfs",
            "/var/lib/grafana:rw,uid=472,gid=472,size=128m",
            "--tmpfs",
            "/tmp:rw,uid=472,gid=472,size=64m",
            "--mount",
            f"type=bind,src={root / 'provisioning'},dst=/etc/grafana/provisioning,readonly",
            "--mount",
            f"type=bind,src={root / 'dashboards'},dst=/etc/grafana/dashboards,readonly",
            "--mount",
            f"type=bind,src={auth_dir},dst=/run/grafana-auth,readonly",
            IMAGE,
        )
        auth = base64.b64encode(("operator:" + password).encode()).decode()

        def get(path, authenticated=True):
            headers = ["--header", "Authorization: Basic " + auth] if authenticated else []
            return docker(
                "exec",
                name,
                "wget",
                "-q",
                "-O",
                "-",
                *headers,
                "http://127.0.0.1:3000" + path,
                check=False,
            )

        for _ in range(40):
            response = get("/api/health", False)
            if response.returncode == 0:
                break
            time.sleep(0.5)
        assert response.returncode == 0, "Grafana did not become healthy"
        assert json.loads(response.stdout)["database"] == "ok"
        results.append("Grafana process and database healthy")
        assert get("/api/datasources", False).returncode != 0
        results.append("Anonymous data source API denied")
        settings = json.loads(get("/api/admin/settings").stdout)
        assert settings["security"]["allow_embedding"] == "false"
        assert settings["auth.anonymous"]["enabled"] == "false"
        assert settings["unified_alerting"]["enabled"] == "false"
        assert settings["users"]["allow_sign_up"] == "false"
        results.append("Effective settings disable embedding, anonymous access, signup and alerts")
        sources = json.loads(get("/api/datasources").stdout)
        assert {d["uid"] for d in sources} == {"aegis-prometheus", "aegis-loki", "aegis-tempo"}
        for listed in sources:
            source = json.loads(get("/api/datasources/uid/" + listed["uid"]).stdout)
            assert source["secureJsonFields"]["basicAuthPassword"]
            assert "synthetic-query-only" not in json.dumps(source)
            assert source["readOnly"]
        results.append(
            "Three real provisioned data sources; credentials encrypted and omitted from API"
        )
        for board in dashboards("validation-cluster").values():
            actual = json.loads(get("/api/dashboards/uid/" + board["uid"]).stdout)
            assert actual["dashboard"]["uid"] == board["uid"]
            assert actual["meta"]["provisioned"]
        results.append("Six dashboards loaded by real Grafana provisioning")
        report = {
            "passed": results,
            "backend_connectivity": "NOT VERIFIED: no telemetry stack deployed",
            "cross_tenant_isolation": "NOT ESTABLISHED: operator-only profile",
            "image": IMAGE,
            "cluster_changes": False,
        }
        (root / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    finally:
        docker("rm", "-f", name, check=False)
        env_file.unlink(missing_ok=True)
        for filename in ["admin-password", "secret-key"]:
            (auth_dir / filename).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
