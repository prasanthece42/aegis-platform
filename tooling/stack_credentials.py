"""Operator-only credential bootstrap. Default is public verification; never prints values."""

import argparse
import json
import secrets
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aegis_platform.canonical import canonical, strict_json  # noqa: E402
from aegis_platform.local_agent import LocalAgent, LocalConfig  # noqa: E402
from aegis_platform.proposal import required_bootstrap  # noqa: E402
from aegis_platform.stack import PROFILE, chart_family  # noqa: E402
from tooling.delivery import ROOT, worker  # noqa: E402


def credential_material(entry, environment):
    """Private result must go directly to Kubernetes stdin, never logs or files."""
    if entry.runtime.profile_id != PROFILE or environment not in entry.environments:
        raise ValueError("Expected an enabled multi-service application environment")
    if entry.runtime.credentials_secret != entry.app_id + "-runtime":
        raise ValueError("Credentials must belong to this application")
    password, redis_password = secrets.token_hex(32), secrets.token_hex(32)
    app_id = entry.app_id
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "type": "Opaque",
        "metadata": {
            "name": entry.runtime.credentials_secret,
            "namespace": entry.environments[environment].namespace,
            "labels": {"aegis.io/app": app_id, "aegis.io/environment": environment},
        },
        "stringData": {
            "postgres-password": password,
            "redis-password": redis_password,
            "database-url": f"postgresql://commerce:{password}@{app_id}-postgres:5432/commerce",
            "redis-url": f"redis://:{redis_password}@{app_id}-redis:6379/0",
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent-config", type=Path, required=True)
    parser.add_argument("--app", required=True)
    parser.add_argument("--environment", choices=["dev", "staging", "prod"], default="dev")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    delivery = worker()
    _, catalog, policy, _, bootstrap = delivery.snapshot()
    entry = catalog.apps[args.app]
    if entry.runtime.profile_id != PROFILE:
        raise ValueError("Credential provisioning is restricted to the multi-service profile")
    config = LocalConfig.model_validate(strict_json(args.agent_config.read_bytes()))
    agent = LocalAgent(config, delivery)
    agent.enroll(entry, args.environment, policy)
    target = entry.environments[args.environment]
    _, files, _ = delivery.target_files(entry, args.environment)
    expected = required_bootstrap(
        catalog,
        entry.app_id,
        args.environment,
        policy,
        bootstrap,
        ROOT / f"charts/{chart_family(entry.runtime)}/{entry.versions.chart_version}",
    )
    for path, data in expected.items():
        if path.startswith("reviews/"):
            continue
        if files.get(path) != (data if isinstance(data, bytes) else canonical(data) + b"\n"):
            # Git formatting of JSON is not an authorization input; compare its strict value.
            if isinstance(data, bytes) or path not in files or strict_json(files[path]) != data:
                raise ValueError("Reviewed application bootstrap must be merged first")
    namespace = agent.get("namespace", target.namespace)
    if namespace["metadata"].get("labels", {}).get("aegis.io/app") != entry.app_id:
        raise ValueError("Live namespace is not owned by this application")
    public = {
        "app_id": entry.app_id,
        "environment": args.environment,
        "namespace": target.namespace,
        "secret": entry.runtime.credentials_secret,
        "keys": ["postgres-password", "redis-password", "database-url", "redis-url"],
    }
    if args.apply:
        result = subprocess.run(
            agent.kube
            + [
                "-n",
                target.namespace,
                "get",
                "secret",
                entry.runtime.credentials_secret,
                "--ignore-not-found",
                "-o",
                "name",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        if result.stdout.strip():
            raise ValueError(
                "Existing credentials are preserved; use a separate rotation procedure"
            )
        subprocess.run(
            agent.kube + ["create", "-f", "-"],
            input=canonical(credential_material(entry, args.environment)),
            capture_output=True,
            check=True,
        )
        public["status"] = "created"
    else:
        public["status"] = "verified-not-created"
    print(json.dumps(public))


if __name__ == "__main__":
    main()
