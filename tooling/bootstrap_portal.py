"""Apply only reviewed portal controller bootstrap and operator-injected credentials.

Run from the platform checkout with `python -m tooling.bootstrap_portal`. Workloads
and public configuration are reconciled by Argo from the protected system branch.
"""

import argparse
import base64
import json
import os
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from aegis_platform.canonical import canonical, strict_json
from aegis_platform.delivery import verify_production_approval, verify_status
from aegis_platform.github_api import GitHubAPI
from aegis_platform.local_agent import LocalAgent, LocalConfig
from aegis_platform.portal_system import BASE, NAMESPACE, PortalSystemPolicy, validate_credentials
from aegis_platform.worker import DeliveryWorker
from tooling.delivery import app_token
from tooling.portal_system import admitted_plan

ROOT = Path(__file__).resolve().parents[1]


def private_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Credential files must be owned by the operator and private regular files")
    return path.read_bytes()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-config", type=Path, required=True)
    parser.add_argument("--credentials", type=Path, required=True)
    parser.add_argument("--operator-from-gh", action="store_true", required=True)
    parser.add_argument("--report", type=Path, default=Path(".local/portal-system-bootstrap.json"))
    args = parser.parse_args()
    token = subprocess.check_output(
        ["gh", "auth", "token", "--hostname", "github.com"], text=True
    ).strip()
    engine = DeliveryWorker(
        GitHubAPI(token, "prasanthece42/aegis-platform"),
        GitHubAPI(token, "prasanthece42/aegis-gitops"),
        lambda entry: GitHubAPI(token, entry.source.owner + "/" + entry.source.name),
        ROOT,
    )
    revision, catalog, delivery, trust, _bootstrap = engine.snapshot()
    policy = PortalSystemPolicy.model_validate(
        strict_json(engine.platform.file("policies/portal-system.json", revision))
    )
    user = engine.gitops.call("GET", "/user")
    if str(user["id"]) not in policy.operator_user_ids or user.get("type") != "User":
        raise ValueError("Current CLI identity is not an enrolled local operator")
    config = LocalConfig.model_validate(strict_json(args.agent_config.read_bytes()))
    agent = LocalAgent(config, engine)
    agent.enroll(catalog.apps["aegis-portal"], "dev", delivery)
    protection = engine.gitops.repo("GET", "branches/" + policy.branch + "/protection")
    if (
        protection["enforce_admins"]["enabled"] is not True
        or protection["required_pull_request_reviews"]["required_approving_review_count"] < 1
        or not any(
            check["context"] == "aegis/platform-service-policy" and check["app_id"] == 15368
            for check in protection["required_status_checks"]["checks"]
        )
    ):
        raise ValueError("System branch must enforce operator review and trusted manifest checks")
    head = engine.gitops.repo("GET", "commits/" + policy.branch)["sha"]
    prs = engine.gitops.pages("pulls", state="closed", base=policy.branch)
    matching = [pr for pr in prs if pr.get("merge_commit_sha") == head and pr.get("merged_at")]
    if len(matching) != 1:
        raise ValueError("System branch head must be an independently reviewed merged PR")
    pr = engine.gitops.repo("GET", "pulls/" + str(matching[0]["number"]))
    if str(pr["user"]["id"]) != policy.configuration.platform_bot_user_id:
        raise ValueError("System PR must come from the enrolled App issuer")
    review_policy = delivery.model_copy(
        update={"production_reviewer_user_ids": policy.operator_user_ids}
    )
    review_hash = verify_production_approval(
        pr, engine.gitops.pages(f"pulls/{pr['number']}/reviews"), review_policy
    )
    ci_policy = delivery.model_copy(update={"observer_user_ids": delivery.workflow_bot_user_ids})
    verify_status(
        engine.gitops.pages(f"commits/{pr['head']['sha']}/statuses"),
        "aegis/platform-service-policy",
        "Exact system manifests, release/cache and operator review verified",
        pr["head"]["sha"],
        ci_policy,
        datetime.now(UTC),
    )
    if args.credentials.is_symlink() or args.credentials.stat().st_mode & 0o077:
        raise ValueError("Use the operator-private credential directory")
    credentials = strict_json(private_file(args.credentials / "credentials.json"))
    app_key = private_file(args.credentials / "github-app.pem")
    signing_key = private_file(args.credentials / "request-signing.pem")
    if (
        str(credentials["id"]) != policy.configuration.app_id
        or credentials["client_id"] != policy.configuration.client_id
    ):
        raise ValueError("Credential App identity differs from reviewed public configuration")
    validate_credentials(app_key, signing_key, credentials["client_secret"], policy, trust)
    os.environ.pop("AEGIS_APP_PRIVATE_KEY", None)
    os.environ.update(
        {
            "AEGIS_APP_ID": policy.configuration.app_id,
            "AEGIS_APP_PRIVATE_KEY_FILE": str(args.credentials / "github-app.pem"),
        }
    )
    # Validate that GitHub accepts the actual RSA key for this App/installation.
    app_token(
        policy.configuration.platform_installation_id,
        policy.configuration.platform_repository_id,
        {"contents": "read"},
    )
    review = strict_json(engine.gitops.file(BASE + "/review.json", head))
    agent.prepare("aegis-portal", review["release_id"])
    files, _policy, _delivery = admitted_plan(engine, review["release_id"])
    for path, expected in files.items():
        actual = engine.gitops.file(path, head)
        if (
            actual != expected
            if isinstance(expected, bytes)
            else canonical(strict_json(actual)) != canonical(expected)
        ):
            raise ValueError("System branch differs from the exact approved runtime plan")
    if engine.gitops.repo("GET", "commits/" + policy.branch)["sha"] != head:
        raise ValueError(
            "System branch changed during validation; retry from its new reviewed head"
        )
    kube = agent.kube

    def apply(resource, *, dry_run=None):
        command = kube + ["apply"] + (["--dry-run=" + dry_run] if dry_run else []) + ["-f", "-"]
        subprocess.run(command, input=json.dumps(resource), text=True, check=True)

    bootstrap = [
        files[BASE + "/bootstrap/" + name + ".json"]
        for name in ["namespace", "quota", "limits", "project", "application"]
    ]
    for resource in bootstrap:
        apply(resource, dry_run="client")
    namespace = subprocess.check_output(
        kube + ["get", "namespace", NAMESPACE, "--ignore-not-found", "-o", "json"], text=True
    )
    if (
        namespace
        and strict_json(namespace)["metadata"]["labels"].get("aegis.io/component")
        != "portal-system"
    ):
        raise ValueError("Existing namespace is not enrolled as the portal system namespace")
    apply(bootstrap[0])
    for resource in bootstrap[1:3]:
        apply(resource, dry_run="server")
        apply(resource)
    secret_data = {
        key: base64.b64encode(value).decode()
        for key, value in {
            "github-app.pem": app_key,
            "request-signing.pem": signing_key,
            "client-secret": credentials["client_secret"].encode(),
        }.items()
    }
    existing = subprocess.check_output(
        kube
        + [
            "-n",
            NAMESPACE,
            "get",
            "secret",
            "aegis-portal-runtime",
            "--ignore-not-found",
            "-o",
            "json",
        ],
        text=True,
    )
    if existing:
        if strict_json(existing).get("data") != secret_data:
            raise ValueError(
                "Existing runtime Secret differs; use an explicit reviewed rotation procedure"
            )
    else:
        secret = {
            "apiVersion": "v1",
            "kind": "Secret",
            "type": "Opaque",
            "metadata": {
                "name": "aegis-portal-runtime",
                "namespace": NAMESPACE,
                "labels": {"aegis.io/component": "portal-system"},
            },
            "data": secret_data,
        }
        # Create, not apply: no last-applied annotation containing credential bytes.
        subprocess.run(
            kube + ["create", "-f", "-"], input=json.dumps(secret), text=True, check=True
        )
    for resource in bootstrap[3:]:
        apply(resource, dry_run="server")
        apply(resource)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(
            {
                "branch_revision": head,
                "namespace": NAMESPACE,
                "cluster_uid": config.cluster_uid,
                "operator_user_id": str(user["id"]),
                "review_hash": review_hash,
                "image": review["image"],
                "applied_at": datetime.now(UTC).isoformat(),
            },
            indent=2,
        )
        + "\n"
    )
    print("Controller bootstrap and private runtime Secret installed; Argo reconciles workloads")


if __name__ == "__main__":
    main()
