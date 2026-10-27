"""Catalog validation and deterministic destination resolution; no network or cluster writes."""

import re
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import Field

from aegis_platform.canonical import digest, strict_json
from aegis_platform.contracts import CatalogEntry, Contract, Environment, Identifier

KUBE_NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class CatalogPolicy(Contract):
    schema_version: Literal[1]
    resource_profile_ids: list[str] = Field(min_length=1)
    runtime_profile_ids: list[str] = Field(min_length=1)
    environment_branches: dict[Environment, str]
    production_human_review_required: Literal[True]
    protected_sync_mode: Literal["operator"]
    max_applications: int = Field(ge=1, le=1000)


class Cluster(Contract):
    schema_version: Literal[1] = 1
    cluster_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,39}$")
    cluster_uid: str = Field(min_length=1)
    gitops_repository_id: Identifier
    profile_id: str = Field(min_length=1)


def checked_path(value: str) -> str:
    if (
        not value
        or "\\" in value
        or "%" in value
        or not value.isascii()
        or any(ord(c) < 33 or ord(c) == 127 for c in value)
        or PurePosixPath(value).is_absolute()
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ValueError("Expected a normalized repository-relative path")
    return value


class Catalog:
    def __init__(self, entries: list[CatalogEntry], clusters: list[Cluster], policy: CatalogPolicy):
        self.policy = policy
        self.apps: dict[str, CatalogEntry] = {}
        self.clusters: dict[str, Cluster] = {}
        if len(entries) > policy.max_applications:
            raise ValueError("Catalog exceeds application budget")
        if policy.environment_branches != {"dev": "main", "staging": "staging", "prod": "prod"}:
            raise ValueError("Environment branches must preserve DEV/STAGING/PROD boundaries")
        cluster_uids = set()
        for cluster in clusters:
            if cluster.cluster_id in self.clusters or cluster.cluster_uid in cluster_uids:
                raise ValueError("Duplicate cluster enrollment")
            self.clusters[cluster.cluster_id] = cluster
            cluster_uids.add(cluster.cluster_uid)
        sources, source_names, destinations, applications, paths = set(), set(), set(), set(), set()
        for entry in entries:
            source_name = (entry.source.owner.lower(), entry.source.name.lower())
            if (
                entry.app_id in self.apps
                or entry.source.repository_id in sources
                or source_name in source_names
            ):
                raise ValueError("Duplicate application ID or source repository")
            if (
                entry.versions.workflow_commit != entry.versions.helper_commit
                or entry.versions.workflow_commit == "0" * 40
                or entry.versions.chart_sha256 == "sha256:" + "0" * 64
            ):
                raise ValueError(
                    "Use matching non-placeholder workflow/helper pins and chart identity"
                )
            if not entry.environments or "dev" not in entry.environments:
                raise ValueError("Applications must explicitly enable DEV")
            if entry.runtime.profile_id not in policy.runtime_profile_ids:
                raise ValueError("Unsupported runtime profile")
            if entry.runtime.resource_profile_id not in policy.resource_profile_ids:
                raise ValueError("Unsupported resource profile")
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", entry.source.owner) or not re.fullmatch(
                r"[A-Za-z0-9_.-]+", entry.source.name
            ):
                raise ValueError("Invalid source repository identity")
            if entry.source.owner in {".", ".."} or entry.source.name in {".", ".."}:
                raise ValueError("Invalid source repository identity")
            owners = entry.access.owner_user_ids
            if len(owners) != len(set(owners)):
                raise ValueError("Duplicate owner grant")
            if any(
                env not in entry.environments
                for env in entry.access.deployer_user_ids_by_environment
            ):
                raise ValueError("Deployer grant names a disabled environment")
            for environment, target in entry.environments.items():
                cluster = self.clusters.get(target.cluster_id)
                if cluster is None or cluster.cluster_uid != target.cluster_uid:
                    raise ValueError("Destination is not bound to the enrolled cluster UID")
                if target.gitops_repository_id != cluster.gitops_repository_id:
                    raise ValueError("Destination GitOps repository is not enrolled")
                if target.gitops_branch != policy.environment_branches[environment]:
                    raise ValueError("Destination branch does not match environment policy")
                expected_path = (
                    f"applications/{entry.app_id}/environments/{environment}/values.yaml"
                )
                if checked_path(target.values_path) != expected_path:
                    raise ValueError("Values path is outside the application's environment")
                if (
                    target.namespace != f"aegis-{entry.app_id}-{environment}"
                    or target.argo_application != f"{entry.app_id}-{environment}"
                    or target.argo_project != f"{entry.app_id}-{environment}"
                    or not KUBE_NAME.fullmatch(target.namespace)
                    or not KUBE_NAME.fullmatch(target.argo_application)
                ):
                    raise ValueError(
                        "Destination/controller names do not belong to the application"
                    )
                destination = (target.cluster_uid, target.namespace)
                application = (target.cluster_uid, target.argo_application)
                path = (target.gitops_repository_id, target.gitops_branch, target.values_path)
                if destination in destinations or application in applications or path in paths:
                    raise ValueError("Overlapping application destination or GitOps path")
                destinations.add(destination)
                applications.add(application)
                paths.add(path)
            self.apps[entry.app_id] = entry
            sources.add(entry.source.repository_id)
            source_names.add(source_name)

    def resolve(self, app_id: str, environment: str) -> dict:
        if app_id not in self.apps or environment not in self.apps[app_id].environments:
            raise ValueError("Unknown application or disabled environment")
        entry = self.apps[app_id]
        return {
            "app_id": app_id,
            "environment": environment,
            "source": entry.source.model_dump(),
            "runtime": entry.runtime.model_dump(),
            "versions": entry.versions.model_dump(),
            "target": entry.environments[environment].model_dump(),
            "catalog_entry_hash": digest(entry.model_dump()),
            "requires_human_review": environment == "prod",
            "sync_mode": "automatic" if environment == "dev" else "operator",
        }

    def check_delivery_paths(
        self, app_id: str, environment: str, release_tag: str, paths: list[str]
    ):
        self.resolve(app_id, environment)
        if not re.fullmatch(r"release-[1-9][0-9]*-[1-9][0-9]*", release_tag):
            raise ValueError("Expected an immutable source release identifier")
        base = f"applications/{app_id}"
        allowed = {
            f"{base}/environments/{environment}/values.yaml",
            f"{base}/environments/{environment}/release.json",
            f"{base}/releases/{release_tag}.json",
        }
        if (
            not paths
            or len(paths) != len(set(paths))
            or any(checked_path(p) not in allowed for p in paths)
        ):
            raise ValueError("Delivery diff changes unexpected or duplicate paths")


def load_catalog(root: Path, policy_path: Path) -> Catalog:
    def files(directory):
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("Catalog directories must be real directories")
        paths = sorted(directory.iterdir())
        if any(p.is_symlink() or (p.name != ".gitkeep" and p.suffix != ".json") for p in paths):
            raise ValueError("Unexpected catalog file or symlink")
        return [p for p in paths if p.suffix == ".json"]

    def read(path, model):
        if path.stat().st_size > 65536:
            raise ValueError("Catalog record exceeds 64 KiB")
        return model.model_validate(strict_json(path.read_bytes()))

    policy = read(policy_path, CatalogPolicy)
    entries = []
    for path in files(root / "apps"):
        entry = read(path, CatalogEntry)
        if path.name != entry.app_id + ".json":
            raise ValueError("Catalog filename does not match immutable app ID")
        entries.append(entry)
    clusters = []
    for path in files(root / "clusters"):
        cluster = read(path, Cluster)
        if path.name != cluster.cluster_id + ".json":
            raise ValueError("Cluster filename does not match enrollment ID")
        clusters.append(cluster)
    return Catalog(entries, clusters, policy)
