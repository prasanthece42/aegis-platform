"""Read-only enrollment review for the preserved schema-2 sample pipeline.

This is a binding audit, not release admission, catalog enrollment or a cutover.
Run as a module from the platform checkout with explicit operator/cluster configuration.
"""

import argparse
import hashlib
import json
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import yaml
from pydantic import Field

from aegis_platform.canonical import canonical, strict_json
from aegis_platform.catalog import checked_path
from aegis_platform.contracts import Contract, Identifier
from aegis_platform.github_api import GitHubAPI
from aegis_platform.local_agent import LocalConfig
from aegis_platform.migration import verify_baseline

ROOT = Path(__file__).resolve().parents[1]


class LegacyTarget(Contract):
    namespace: str
    argo_application: str
    argo_project: str
    gitops_branch: str
    values_path: str
    controller_path: str
    chart_path: Literal["charts/sample-api"]
    helm_release: Literal["sample-api"]
    delivery_mode: Literal["automatic", "manual"]


class EnrollmentReview(Contract):
    schema_version: Literal[1]
    stage: Literal["review-only-not-enrolled"]
    app_id: Literal["sample-api"]
    display_name: str
    source_repository: str
    source_repository_id: Identifier
    source_installation_id: Identifier
    gitops_repository: str
    gitops_repository_id: Identifier
    owner_user_ids: list[Identifier] = Field(min_length=1)
    cluster_id: str
    cluster_uid: str
    release_schema_version: Literal[2]
    pipeline: Literal["existing-sample-pipeline"]
    portal_delivery_enabled: Literal[False]
    create_or_rename_resources: Literal[False]
    production_human_review_required: Literal[True]
    protected_sync_mode: Literal["operator"]
    environments: dict[Literal["dev", "staging", "prod"], LegacyTarget]


def validate_review(review, baseline, cluster):
    if (
        review.source_repository != baseline["source_repository"]
        or review.gitops_repository != baseline["gitops_repository"]
        or review.cluster_id != cluster["cluster_id"]
        or review.cluster_uid != cluster["cluster_uid"]
        or review.gitops_repository_id != cluster["gitops_repository_id"]
        or set(review.environments) != set(baseline["environments"])
    ):
        raise ValueError("Legacy review differs from the preserved source/cluster enrollment")
    for environment, target in review.environments.items():
        original = baseline["environments"][environment]
        expected = {
            **original,
            "values_path": f"environments/{environment}/values.yaml",
            "controller_path": f"argocd/applications/{original['argo_application']}.yaml",
            "chart_path": "charts/sample-api",
            "helm_release": "sample-api",
            "delivery_mode": "automatic" if environment == "dev" else "manual",
        }
        if target.model_dump() != expected:
            raise ValueError("Legacy review would change existing bindings: " + environment)


def validate_runtime(
    review,
    environment,
    manifest,
    app,
    project_manifest,
    project,
    values,
    pointer,
    receipt,
    deployment,
):
    target = review.environments[environment]
    source = {
        "repoURL": "https://github.com/" + review.gitops_repository + ".git",
        "targetRevision": target.gitops_branch,
        "path": target.chart_path,
        "helm": {
            "releaseName": target.helm_release,
            "valueFiles": [
                "../../" + target.values_path,
                "../../environments/cluster-kind/values.yaml",
            ],
        },
    }
    for value in [manifest, app]:
        if (
            value["metadata"]["name"] != target.argo_application
            or value["spec"]["source"] != source
            or value["spec"]["project"] != target.argo_project
            or value["spec"]["destination"]
            != {"server": "https://kubernetes.default.svc", "namespace": target.namespace}
            or bool(value["spec"].get("syncPolicy", {}).get("automated")) != (environment == "dev")
        ):
            raise ValueError("Live/reviewed Argo controller differs from preserved bindings")
    if project["metadata"]["name"] != target.argo_project or canonical(
        project["spec"]
    ) != canonical(project_manifest["spec"]):
        raise ValueError("Live Argo project differs from its reviewed repository definition")
    image = values["image"]["repository"] + "@" + values["image"]["digest"]
    if (
        receipt.get("schema_version") != 2
        or receipt.get("source_repository") != review.source_repository
        or receipt.get("release_tag") != pointer["release_tag"]
        or receipt.get("source_commit") != pointer["source_commit"]
        or receipt.get("image") != pointer["image"]
        or image != pointer["image"]
        or values["sourceCommit"] != pointer["source_commit"]
        or deployment["metadata"]["namespace"] != target.namespace
        or deployment["metadata"]["name"] != target.helm_release
        or len(deployment["spec"]["template"]["spec"]["containers"]) != 1
        or deployment["spec"]["template"]["spec"]["containers"][0]["image"] != image
    ):
        raise ValueError("Legacy values/pointer/retained receipt/live image binding differs")
    return {
        "image": image,
        "source_commit": pointer["source_commit"],
        "release_tag": pointer["release_tag"],
        "namespace": target.namespace,
        "argo_application": target.argo_application,
        "argo_sync": app["status"]["sync"]["status"],
        "argo_health": app["status"]["health"]["status"],
    }


def verify_remote_baseline(api, revision, files, local):
    tree = api.repo("GET", "git/trees/" + revision + "?recursive=1")
    if tree.get("truncated"):
        raise ValueError("Cannot verify a truncated repository tree")
    blobs = {item["path"]: item for item in tree["tree"]}
    for path in files:
        data = (local / checked_path(path)).read_bytes()
        expected = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        actual = blobs.get(path, {})
        if actual.get("sha") != expected or actual.get("mode") not in {"100644", "100755"}:
            raise ValueError("Remote baseline file differs: " + path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--review", type=Path, default=Path("migrations/sample-api.enrollment-review.json")
    )
    parser.add_argument("--agent-config", type=Path, required=True)
    parser.add_argument("--operator-from-gh", action="store_true", required=True)
    parser.add_argument("--output", type=Path, default=Path(".local/legacy-enrollment-audit.json"))
    args = parser.parse_args()
    review = EnrollmentReview.model_validate(strict_json(args.review.read_bytes()))
    baseline = strict_json((ROOT / "migrations/sample-api.baseline.json").read_bytes())
    cluster = strict_json((ROOT / "catalog/clusters/kind-local.json").read_bytes())
    validate_review(review, baseline, cluster)
    if verify_baseline(baseline, ROOT.parent):
        raise ValueError("Local legacy baseline changed; inspect before enrollment review")
    token = subprocess.check_output(["gh", "auth", "token"], text=True).strip()
    source = GitHubAPI(token, review.source_repository)
    gitops = GitHubAPI(token, review.gitops_repository)
    user = gitops.call("GET", "/user")
    if str(user["id"]) not in review.owner_user_ids or user.get("type") != "User":
        raise ValueError("Use an enrolled individual operator for the binding audit")
    for api, repository_id in [
        (source, review.source_repository_id),
        (gitops, review.gitops_repository_id),
    ]:
        metadata = api.repo("GET", "")
        if str(metadata["id"]) != repository_id or metadata["private"] is not False:
            raise ValueError("Repository identity/visibility differs from the enrollment review")
    revisions = {"source": source.repo("GET", "commits/main")["sha"]}
    revisions.update(
        {
            env: gitops.repo("GET", "commits/" + target.gitops_branch)["sha"]
            for env, target in review.environments.items()
        }
    )
    for name, api, revision in [
        ("aegis-cicd", source, revisions["source"]),
        ("aegis-gitops", gitops, revisions["dev"]),
    ]:
        verify_remote_baseline(
            api, revision, baseline["repositories"][name]["files"], ROOT.parent / name
        )
    config = LocalConfig.model_validate(strict_json(args.agent_config.read_bytes()))
    if (
        not Path(config.kubeconfig).is_absolute()
        or config.cluster_id != review.cluster_id
        or config.cluster_uid != review.cluster_uid
    ):
        raise ValueError("Selected cluster differs from the reviewed enrollment")
    kube = ["kubectl", "--kubeconfig", config.kubeconfig, "--context", config.context]

    def read(command):
        return strict_json(subprocess.check_output(kube + command))

    server = urlsplit(
        read(["config", "view", "--minify", "-o", "json"])["clusters"][0]["cluster"]["server"]
    )
    if server.scheme != "https" or server.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Use the explicitly enrolled loopback cluster")
    if (
        read(["get", "namespace", "kube-system", "-o", "json"])["metadata"]["uid"]
        != review.cluster_uid
    ):
        raise ValueError("Live cluster UID differs from enrollment")
    environments = {}
    for env, target in review.environments.items():
        revision = revisions[env]

        def file(path, ref=revision):
            return yaml.safe_load(gitops.file(path, ref))

        app = read(["-n", "argocd", "get", "application", target.argo_application, "-o", "json"])
        project = read(["-n", "argocd", "get", "appproject", target.argo_project, "-o", "json"])
        deployment = read(
            ["-n", target.namespace, "get", "deployment", target.helm_release, "-o", "json"]
        )
        pointer = file(f"environments/{env}/release.json")
        tag = checked_path(pointer["release_tag"])
        if not re.fullmatch(r"release-[1-9][0-9]*-[1-9][0-9]*", tag):
            raise ValueError("Expected an immutable legacy release tag")
        environments[env] = validate_runtime(
            review,
            env,
            file(target.controller_path),
            app,
            file(f"argocd/projects/{target.argo_project}.yaml"),
            project,
            file(target.values_path),
            pointer,
            file(f"releases/catalog/{tag}.json"),
            deployment,
        )
        protection = gitops.repo("GET", "branches/" + target.gitops_branch + "/protection")
        contexts = {
            check["context"]
            for check in protection["required_status_checks"]["checks"]
            if check["app_id"] == 15368
        }
        if (
            not protection["enforce_admins"]["enabled"]
            or not {"chart", "promotion-policy", "aegis/delivery-policy"} <= contexts
        ):
            raise ValueError("Legacy branch checks are not enforced")
        if (
            env == "prod"
            and protection["required_pull_request_reviews"]["required_approving_review_count"] < 1
        ):
            raise ValueError("PROD must enforce actual human review")
    report = {
        "stage": review.stage,
        "catalog_enrolled": False,
        "portal_delivery_enabled": False,
        "resources_changed": False,
        "release_eligibility": "not-evaluated-legacy-adapter-required",
        "observed_at": datetime.now(UTC).isoformat(),
        "revisions": revisions,
        "environments": environments,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
