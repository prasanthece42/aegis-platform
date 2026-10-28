"""Install only reviewed local telemetry bootstrap and private secrets; Argo owns workloads.

Default is verification only. --apply is ineffective unless exact merged-head review,
trusted status, branch protection, enrollment and credential checks all pass.
"""

import argparse
import base64
import json
import os
import secrets
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from aegis_platform.canonical import strict_json
from aegis_platform.delivery import verify_status
from aegis_platform.github_api import GitHubAPI
from aegis_platform.local_agent import LocalAgent, LocalConfig
from aegis_platform.observability_policy import (
    OBS_BASE,
    OBS_NAMESPACE,
    password_fingerprint,
    query_password,
)
from aegis_platform.observability_service import (
    CONTEXT,
    SUCCESS,
    verify_exact_tree,
    verify_operator_review,
    verify_proposal,
)
from aegis_platform.worker import DeliveryWorker, tree_files
from tooling.bootstrap_portal import merged_branch_pr, private_file
from tooling.observability_service import admitted_plan

ROOT = Path(__file__).resolve().parents[1]


def prepare_credentials(destination, oauth_credentials, policy):
    """One-time local secret preparation; never overwrites or emits secret values."""
    oauth = strict_json(private_file(oauth_credentials))
    query = query_password(oauth["client_secret"], policy.cluster_uid)
    if password_fingerprint(query) != policy.query_password_sha256:
        raise ValueError("OAuth-derived query capability differs from reviewed fingerprint")
    # mkdir is exclusive: partial preparation fails closed and is never reused implicitly.
    destination.mkdir(mode=0o700)
    values = {"query-password": query}
    values.update(
        {
            k: secrets.token_hex(32)
            for k in [
                "ingest-password",
                "agent-password",
                "admin-password",
                "secret-key",
            ]
        }
    )
    for name, value in values.items():
        fd = os.open(destination / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(value)
    print("Prepared private local telemetry credentials; no cluster changes")


def credential_secrets(directory, policy):
    if directory.is_symlink() or directory.stat().st_mode & 0o077:
        raise ValueError("Use an operator-private credential directory")
    values = {
        name: private_file(directory / name)
        for name in [
            "query-password",
            "ingest-password",
            "agent-password",
            "admin-password",
            "secret-key",
        ]
    }
    if password_fingerprint(values["query-password"].decode()) != policy.query_password_sha256:
        raise ValueError("Query capability fingerprint differs from reviewed policy")
    if len(set(values.values())) != len(values) or any(
        len(value) < 32 or len(value) > 256 or any(c in value for c in [b"\n", b"\r", b"\x00"])
        for value in values.values()
    ):
        raise ValueError("Credentials must be bounded, strong, independent single-line values")
    data = {k: values[k] for k in ["query-password", "ingest-password", "agent-password"]}
    for name in ["query", "ingest", "agent"]:
        hashed = subprocess.run(
            ["openssl", "passwd", "-apr1", "-stdin"],
            input=values[name + "-password"] + b"\n",
            capture_output=True,
            check=True,
        ).stdout.strip()
        data[name + ".htpasswd"] = name.encode() + b":" + hashed + b"\n"
    return {
        "aegis-observability-auth": data,
        "aegis-grafana-auth": {k: values[k] for k in ["admin-password", "secret-key"]},
    }


def verify_protection(protection):
    required = protection.get("required_status_checks") or {}
    reviews = protection.get("required_pull_request_reviews") or {}
    if (
        not (protection.get("enforce_admins") or {}).get("enabled")
        or reviews.get("required_approving_review_count", 0) < 1
        or not reviews.get("dismiss_stale_reviews")
        or not required.get("strict")
        or not any(
            c.get("context") == CONTEXT and c.get("app_id") == 15368
            for c in required.get("checks", [])
        )
        or (protection.get("allow_force_pushes") or {}).get("enabled")
        or (protection.get("allow_deletions") or {}).get("enabled")
        or reviews.get("bypass_pull_request_allowances", {}).get("users")
        or reviews.get("bypass_pull_request_allowances", {}).get("teams")
        or reviews.get("bypass_pull_request_allowances", {}).get("apps")
    ):
        raise ValueError(
            "Telemetry branch must enforce review, trusted strict status and no bypass"
        )


def verify_merged(engine):
    expected, policy, access, delivery = admitted_plan(engine)
    user = engine.gitops.call("GET", "/user")
    if str(user["id"]) not in access.operator_user_ids or user.get("type") != "User":
        raise ValueError("Current CLI identity is not an enrolled human telemetry operator")
    verify_protection(engine.gitops.repo("GET", f"branches/{access.branch}/protection"))
    head = engine.gitops.repo("GET", "commits/" + access.branch)["sha"]
    pr = merged_branch_pr(engine.gitops, access.branch, head)
    verify_proposal(
        pr, engine.gitops.pages(f"pulls/{pr['number']}/files"), policy, access, expected
    )
    review_hash = verify_operator_review(
        pr,
        engine.gitops.pages(f"pulls/{pr['number']}/reviews"),
        access,
        delivery,
    )
    verify_status(
        engine.gitops.pages(f"commits/{pr['head']['sha']}/statuses"),
        CONTEXT,
        SUCCESS,
        pr["head"]["sha"],
        delivery.model_copy(
            update={
                "observer_user_ids": delivery.workflow_bot_user_ids,
            }
        ),
        datetime.now(UTC),
    )
    verify_exact_tree(
        tree_files(engine.gitops, head, lambda p: p.startswith(OBS_BASE + "/")),
        expected,
    )
    return expected, policy, access, delivery, head, review_hash


def preflight_resources(kube, files):
    """Validate public objects and reject adoption of unrelated cluster resources."""
    for resource in files.values():
        if "apiVersion" not in resource or "kind" not in resource:
            continue
        meta = resource["metadata"]
        scope = ["-n", meta["namespace"]] if "namespace" in meta else []
        existing = subprocess.check_output(
            kube
            + scope
            + ["get", resource["kind"], meta["name"], "--ignore-not-found", "-o", "json"],
            text=True,
        )
        if (
            existing
            and strict_json(existing)["metadata"].get("labels", {}).get("app.kubernetes.io/part-of")
            != "aegis-observability"
        ):
            raise ValueError("Refusing to adopt an unrelated existing telemetry resource")
        subprocess.run(
            kube + ["apply", "--dry-run=client", "-f", "-"],
            input=json.dumps(resource),
            text=True,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-config", type=Path)
    parser.add_argument("--credentials", type=Path, required=True)
    parser.add_argument("--prepare-from-oauth", type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--report", type=Path, default=Path(".local/observability-bootstrap.json"))
    args = parser.parse_args()
    if args.prepare_from_oauth:
        if args.apply:
            parser.error("Secret preparation cannot be combined with apply")
        from aegis_platform.observability_policy import ObservabilityPolicy

        policy = ObservabilityPolicy.model_validate_json(
            (ROOT / "policies/observability.json").read_text()
        )
        prepare_credentials(args.credentials, args.prepare_from_oauth, policy)
        return
    if not args.agent_config:
        parser.error("Explicit enrolled agent configuration is required")
    token = subprocess.check_output(
        ["gh", "auth", "token", "--hostname", "github.com"], text=True
    ).strip()
    engine = DeliveryWorker(
        GitHubAPI(token, "prasanthece42/aegis-platform"),
        GitHubAPI(token, "prasanthece42/aegis-gitops"),
        lambda _entry: None,
        ROOT,
    )
    files, policy, access, delivery, head, review_hash = verify_merged(engine)
    config = LocalConfig.model_validate(strict_json(args.agent_config.read_bytes()))
    agent = LocalAgent(config, engine)
    _revision, catalog, _delivery, _trust, _bootstrap = engine.snapshot()
    agent.enroll(catalog.apps["hello-aegis"], "dev", delivery)
    if config.cluster_uid != policy.cluster_uid or config.kind_node != policy.node_name:
        raise ValueError("Local enrollment differs from reviewed telemetry policy")
    node = agent.get("node", policy.node_name)
    if policy.node_ip not in {
        a["address"] for a in node["status"]["addresses"] if a["type"] == "InternalIP"
    }:
        raise ValueError("Reviewed kubelet address no longer matches the enrolled node")
    secret_data = credential_secrets(args.credentials, policy)
    # Salted htpasswd hashes are stable once installed: validate them against supplied
    # plaintext before reusing existing bytes, rather than rotating salts on each run.
    from cryptography.hazmat.primitives import constant_time

    secrets_to_create = []
    for name, data in secret_data.items():
        existing_raw = subprocess.check_output(
            agent.kube
            + ["-n", OBS_NAMESPACE, "get", "secret", name, "--ignore-not-found", "-o", "json"],
            text=True,
        )
        if existing_raw:
            existing = strict_json(existing_raw)
            if (
                existing["metadata"].get("labels", {}).get("app.kubernetes.io/part-of")
                != "aegis-observability"
            ):
                raise ValueError("Existing secret is not owned by telemetry bootstrap")
            actual = {k: base64.b64decode(v, validate=True) for k, v in existing["data"].items()}
            if set(actual) != set(data):
                raise ValueError("Existing credential keys differ; explicit rotation required")
            for key, value in data.items():
                if key.endswith(".htpasswd"):
                    user, encoded = actual[key].decode().strip().split(":", 1)
                    salt = encoded.split("$")[2]
                    hashed = subprocess.run(
                        ["openssl", "passwd", "-apr1", "-salt", salt, "-stdin"],
                        input=data[user + "-password"] + b"\n",
                        capture_output=True,
                        check=True,
                    ).stdout.strip()
                    value = user.encode() + b":" + hashed + b"\n"
                if not constant_time.bytes_eq(actual[key], value):
                    raise ValueError("Existing credential differs; explicit rotation required")
            continue
        secrets_to_create.append(
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "type": "Opaque",
                "metadata": {
                    "name": name,
                    "namespace": OBS_NAMESPACE,
                    "labels": {
                        "app.kubernetes.io/part-of": "aegis-observability",
                    },
                },
                "data": {k: base64.b64encode(v).decode() for k, v in data.items()},
            }
        )
    bootstrap = [v for path, v in files.items() if "/bootstrap/" in path]
    namespace = subprocess.check_output(
        agent.kube
        + [
            "get",
            "namespace",
            OBS_NAMESPACE,
            "--ignore-not-found",
            "-o",
            "json",
        ],
        text=True,
    )
    if (
        namespace
        and strict_json(namespace)["metadata"].get("labels", {}).get("app.kubernetes.io/part-of")
        != "aegis-observability"
    ):
        raise ValueError("Existing namespace is not enrolled for telemetry")
    preflight_resources(agent.kube, files)
    # Recheck both control-plane and desired-state snapshots immediately before mutation.
    current, _p, _a, _d, latest_head, latest_review = verify_merged(engine)
    if current != files or latest_head != head or latest_review != review_hash:
        raise ValueError("Trusted platform or telemetry branch changed during validation")
    report = {
        "applied": False,
        "branch_revision": head,
        "review_hash": review_hash,
        "cluster_uid": policy.cluster_uid,
        "namespace": OBS_NAMESPACE,
    }
    if args.apply:
        # Namespace first, controller Application last. Never apply workload manifests here.
        ordered = sorted(
            bootstrap,
            key=lambda v: {
                "Namespace": 0,
                "ResourceQuota": 1,
                "LimitRange": 2,
                "AppProject": 3,
                "Application": 4,
            }[v["kind"]],
        )
        for value in ordered:
            if value["kind"] == "Application":
                for secret in secrets_to_create:
                    subprocess.run(
                        agent.kube + ["create", "-f", "-"],
                        input=json.dumps(secret),
                        text=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=True,
                    )
            subprocess.run(
                agent.kube + ["apply", "-f", "-"],
                input=json.dumps(value),
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
        report["applied"] = True
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(
        "Reviewed bootstrap applied; Argo owns workloads"
        if args.apply
        else "Verified only; no cluster changes"
    )


if __name__ == "__main__":
    main()
