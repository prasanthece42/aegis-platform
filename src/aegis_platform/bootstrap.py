"""Render app-scoped operator bootstrap and desired values; never apply resources."""

import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path

from aegis_platform.canonical import digest
from aegis_platform.catalog import Catalog, checked_path
from aegis_platform.release import ReleaseEvidence, validate_repository


def chart_identity(chart: Path) -> dict:
    if chart.is_symlink() or not chart.is_dir():
        raise ValueError("Chart must be a real versioned directory")
    files = {}
    for path in sorted(chart.rglob("*")):
        if path.is_symlink():
            raise ValueError("Chart symlinks are unsupported")
        if path.is_file():
            files[checked_path(str(path.relative_to(chart)))] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    if not {"Chart.yaml", "values.yaml", "values.schema.json"} <= files.keys():
        raise ValueError("Incomplete chart family")
    version = chart.name
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Chart directory must identify an immutable version")
    if not re.search(
        r"(?m)^version:\s*[\"']?" + re.escape(version) + r"[\"']?\s*$",
        (chart / "Chart.yaml").read_text(),
    ):
        raise ValueError("Chart metadata version and directory disagree")
    return {"schema_version": 1, "version": version, "sha256": digest(files), "files": files}


def validate_profile(policy: dict, profile_id: str) -> dict:
    if policy.get("schema_version") != 1 or policy.get("argo_namespace") != "argocd":
        raise ValueError("Unsupported bootstrap policy")
    if not re.fullmatch(r"v1\.[0-9]+", policy.get("pod_security_version", "")):
        raise ValueError("Pin the approved Pod Security version")
    profile = policy["resource_profiles"][profile_id]
    if set(profile) != {"requests", "limits", "max_replicas", "quota"}:
        raise ValueError("Unexpected profile fields")
    if type(profile["max_replicas"]) is not int or not 1 <= profile["max_replicas"] <= 2:
        raise ValueError("Unsupported replica budget")
    for group in ["requests", "limits"]:
        if set(profile[group]) != {"cpu", "memory"}:
            raise ValueError("Unexpected resource override")
        for resource, unit in [("cpu", "m"), ("memory", "Mi")]:
            if not re.fullmatch(r"[1-9][0-9]*" + unit, profile[group][resource]):
                raise ValueError("Use bounded integral resource units")
    for resource, unit in [("cpu", "m"), ("memory", "Mi")]:
        request = int(profile["requests"][resource].removesuffix(unit))
        limit = int(profile["limits"][resource].removesuffix(unit))
        if request > limit or limit > {"cpu": 500, "memory": 256}[resource]:
            raise ValueError("Resource profile exceeds first-milestone bounds")
        for group, value in [("requests", request), ("limits", limit)]:
            expected = value * (profile["max_replicas"] + 1)
            if profile["quota"].get(group + "." + resource) != str(expected) + unit:
                raise ValueError("Quota must cover bounded replicas plus one rollout surge")
    expected = {
        "pods": str(profile["max_replicas"] + 1),
        "services": "1",
        "count/deployments.apps": "1",
        "count/serviceaccounts": "2",
    }
    if any(profile["quota"].get(k) != v for k, v in expected.items()) or set(
        profile["quota"]
    ) != set(expected) | {"requests.cpu", "requests.memory", "limits.cpu", "limits.memory"}:
        raise ValueError("Namespace quota exceeds the supported resource set")
    return deepcopy(profile)


def bootstrap_plan(
    catalog: Catalog, app_id: str, environment: str, context: dict, policy: dict, chart: Path
) -> dict[str, dict | bytes]:
    resolved = catalog.resolve(app_id, environment)
    target, versions = resolved["target"], resolved["versions"]
    if set(context) != {"gitops_repository", "gitops_repository_id", "cluster_id", "cluster_uid"}:
        raise ValueError("Unexpected bootstrap context fields")
    validate_repository(context["gitops_repository"])
    for field in ["gitops_repository_id", "cluster_id", "cluster_uid"]:
        if context[field] != target[field]:
            raise ValueError("Bootstrap context differs from enrolled target")
    identity = chart_identity(chart)
    if (
        versions["chart_version"] != identity["version"]
        or versions["chart_sha256"] != identity["sha256"]
    ):
        raise ValueError("Chart does not match the approved catalog identity")
    profile = validate_profile(policy, resolved["runtime"]["resource_profile_id"])
    namespace = target["namespace"]
    labels = {"aegis.io/app": app_id, "aegis.io/environment": environment}
    namespace_labels = {**labels}
    for mode in ["enforce", "audit", "warn"]:
        namespace_labels[f"pod-security.kubernetes.io/{mode}"] = "restricted"
        namespace_labels[f"pod-security.kubernetes.io/{mode}-version"] = policy[
            "pod_security_version"
        ]
    repo_url = "https://github.com/" + context["gitops_repository"] + ".git"
    project = {
        "apiVersion": "argoproj.io/v1alpha1",
        "kind": "AppProject",
        "metadata": {"name": target["argo_project"], "namespace": "argocd", "labels": labels},
        "spec": {
            "sourceRepos": [repo_url],
            "destinations": [{"server": "https://kubernetes.default.svc", "namespace": namespace}],
            "clusterResourceWhitelist": [],
            "namespaceResourceWhitelist": [
                {"group": "apps", "kind": "Deployment"},
                {"group": "", "kind": "Service"},
                {"group": "", "kind": "ServiceAccount"},
            ],
        },
    }
    chart_path = f"charts/web-service/{identity['version']}"
    values_relative = "../../../" + target["values_path"]
    application = {
        "apiVersion": "argoproj.io/v1alpha1",
        "kind": "Application",
        "metadata": {
            "name": target["argo_application"],
            "namespace": "argocd",
            "labels": labels,
            "annotations": {
                "aegis.io/catalog-entry-hash": resolved["catalog_entry_hash"],
                "aegis.io/chart-sha256": identity["sha256"],
                "aegis.io/human-review-required": str(environment == "prod").lower(),
            },
        },
        "spec": {
            "project": target["argo_project"],
            "source": {
                "repoURL": repo_url,
                "targetRevision": target["gitops_branch"],
                "path": chart_path,
                "helm": {"releaseName": app_id, "valueFiles": [values_relative]},
            },
            "destination": {"server": "https://kubernetes.default.svc", "namespace": namespace},
            "syncPolicy": {
                "syncOptions": [
                    "ServerSideApply=true",
                    "PruneLast=true",
                    "FailOnSharedResource=true",
                ]
            },
        },
    }
    if environment == "dev":
        application["spec"]["syncPolicy"]["automated"] = {
            "prune": True,
            "selfHeal": True,
            "allowEmpty": False,
        }
    base = f"clusters/{target['cluster_id']}/bootstrap/{app_id}/{environment}"
    files = {
        f"{base}/namespace.json": {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": namespace, "labels": namespace_labels},
        },
        f"{base}/quota.json": {
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": {"name": "aegis-budget", "namespace": namespace, "labels": labels},
            "spec": {"hard": profile["quota"]},
        },
        f"{base}/limits.json": {
            "apiVersion": "v1",
            "kind": "LimitRange",
            "metadata": {
                "name": "aegis-container-limits",
                "namespace": namespace,
                "labels": labels,
            },
            "spec": {
                "limits": [
                    {
                        "type": "Container",
                        "defaultRequest": profile["requests"],
                        "default": profile["limits"],
                        "max": profile["limits"],
                    }
                ]
            },
        },
        f"argocd/projects/{target['argo_project']}.json": project,
        f"argocd/applications/{target['argo_application']}.json": application,
    }
    for relative in identity["files"]:
        files[f"{chart_path}/{relative}"] = (chart / relative).read_bytes()
    files[f"reviews/bootstrap/{target['cluster_id']}/{app_id}/{environment}.json"] = {
        "schema_version": 1,
        "app_id": app_id,
        "environment": environment,
        "cluster_uid": target["cluster_uid"],
        "catalog_entry_hash": resolved["catalog_entry_hash"],
        "bootstrap_policy_hash": digest(policy),
        "chart_sha256": identity["sha256"],
        "requires_operator_bootstrap": True,
        "requires_production_review": environment == "prod",
        "status": "review-only-not-applied",
    }
    return files


def release_values(
    catalog: Catalog,
    app_id: str,
    environment: str,
    release: ReleaseEvidence,
    policy: dict,
    replicas: int = 1,
) -> dict:
    if environment != "dev":
        raise ValueError("Protected release planning requires the later promotion admission path")
    resolved = catalog.resolve(app_id, environment)
    source, versions = resolved["source"], resolved["versions"]
    if (
        release.app_id != app_id
        or release.source_repository_id != source["repository_id"]
        or release.source_repository.lower() != (source["owner"] + "/" + source["name"]).lower()
        or release.platform_commit != versions["workflow_commit"]
    ):
        raise ValueError("Release is not bound to the approved application/workflow")
    profile = validate_profile(policy, resolved["runtime"]["resource_profile_id"])
    if type(replicas) is not int or not 1 <= replicas <= profile["max_replicas"]:
        raise ValueError("Replica request exceeds the approved profile")
    image, image_digest = release.image.split("@")
    return {
        "appId": app_id,
        "environment": environment,
        "replicaCount": replicas,
        "image": {"repository": image, "digest": image_digest, "pullPolicy": "Never"},
        "sourceCommit": release.source_commit,
        "containerPort": resolved["runtime"]["container_port"],
        "healthPath": resolved["runtime"]["health_path"],
        "resources": {"requests": profile["requests"], "limits": profile["limits"]},
    }


def write_plan(files: dict[str, dict | bytes], output: Path):
    if output.is_symlink() or (output.exists() and any(output.iterdir())):
        raise ValueError("Write review plans only into a new or empty directory")
    for relative in files:
        checked_path(relative)
    output.mkdir(parents=True, exist_ok=True)
    for relative, content in files.items():
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(
            content
            if isinstance(content, bytes)
            else (json.dumps(content, indent=2) + "\n").encode()
        )
