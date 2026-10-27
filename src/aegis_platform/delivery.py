"""Fail-closed delivery admission, independent of HTTP, GitHub credentials and Kubernetes.

Adapters supply freshly fetched GitHub metadata. This module never treats a receipt,
status description, issue label or browser field as proof of identity on its own.
"""

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Literal

from pydantic import Field

from aegis_platform.canonical import digest
from aegis_platform.contracts import (
    AppId,
    CatalogEntry,
    Commit,
    Contract,
    DeploymentIntent,
    Digest,
    Environment,
    Identifier,
)
from aegis_platform.release import ReleaseEvidence


class DeliveryPolicy(Contract):
    schema_version: Literal[1] = 1
    platform_repository: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    platform_repository_id: Identifier
    gitops_repository: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    gitops_repository_id: Identifier
    workflow_bot_user_ids: list[Identifier] = Field(min_length=1)
    observer_user_ids: list[Identifier] = Field(min_length=1)
    production_reviewer_user_ids: list[Identifier] = Field(min_length=1)
    maximum_evidence_age_seconds: int = Field(default=86400, ge=60, le=86400)
    production_human_review_required: Literal[True] = True
    protected_sync_mode: Literal["operator"] = "operator"


class DeploymentFields(Contract):
    app_id: AppId
    environment: Environment
    release_id: Identifier


class DeploymentSubmission(DeploymentFields):
    review_token: str = Field(min_length=20, max_length=16384)


class CurrentIntent(Contract):
    """App-scoped pointer; anchor is the last commit that changed this pointer."""

    fingerprint: Digest
    intent_anchor: Commit
    source_commit: Commit
    image_root_digest: Digest
    release_id: Identifier


def timestamp(value: str) -> datetime:
    when = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if when.tzinfo is None:
        raise ValueError("Evidence must include its timezone")
    return when.astimezone(UTC)


def request_id(issuer: str, principal: str, key: str) -> str:
    return "req-" + digest([issuer, principal, "deployment", key]).split(":")[1]


def authorize(entry: CatalogEntry, principal_id: str, environment: str, source_push: bool):
    if (
        environment not in entry.environments
        or principal_id not in entry.access.deployer_user_ids_by_environment.get(environment, [])
        or not source_push
    ):
        raise ValueError("Deployment requires a current environment grant and source push access")


def admit_release(
    entry: CatalogEntry,
    raw_receipt: bytes,
    release: dict,
    repository: dict,
    run: dict,
    policy: DeliveryPolicy,
) -> ReleaseEvidence:
    """Admit retained bytes only after source/run identity is independently fetched."""
    from aegis_platform.canonical import strict_json

    evidence = ReleaseEvidence.model_validate(strict_json(raw_receipt))
    source = entry.source
    repo_name = source.owner + "/" + source.name
    if (
        str(repository.get("id")) != source.repository_id
        or repository.get("full_name", "").lower() != repo_name.lower()
        or repository.get("private") is not False
        or repository.get("default_branch") != source.default_branch
        or evidence.app_id != entry.app_id
        or evidence.source_repository_id != source.repository_id
        or evidence.source_repository.lower() != repo_name.lower()
        or evidence.platform_commit != entry.versions.workflow_commit
        or entry.versions.helper_commit != entry.versions.workflow_commit
        or release.get("draft") is not False
        or release.get("prerelease") is not False
        or not release.get("published_at")
        or release.get("tag_name") != evidence.release_tag
        or str(release.get("author", {}).get("id")) not in policy.workflow_bot_user_ids
        or release.get("author", {}).get("type") != "Bot"
    ):
        raise ValueError("Release identity differs from the approved source/catalog")
    if (
        str(run.get("id")) != evidence.workflow_run_id
        or str(run.get("run_attempt")) != evidence.run_attempt
        or str(run.get("repository", {}).get("id")) != source.repository_id
        or run.get("head_sha") != evidence.source_commit
        or run.get("head_branch") != source.default_branch
        or run.get("event") not in {"push", "workflow_dispatch"}
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("path") != ".github/workflows/release.yml"
    ):
        raise ValueError("Release was not produced by a successful default-branch release run")
    expected = {
        f"{policy.platform_repository}/.github/workflows/python-web-release.yml",
        f"{policy.platform_repository}/.github/workflows/python-web-ci.yml",
    }
    found = set()
    for workflow in run.get("referenced_workflows", []):
        path, _, ref = workflow.get("path", "").partition("@")
        if path in expected:
            if (
                path in found
                or ref != entry.versions.workflow_commit
                or workflow.get("sha") != entry.versions.workflow_commit
            ):
                raise ValueError("Reusable workflow reference is not the approved immutable pin")
            found.add(path)
    if found != expected:
        raise ValueError("Release run did not use both approved reusable workflows")
    assets = release.get("assets", [])
    for name in ("release.json", "image.oci.tar"):
        matches = [asset for asset in assets if asset.get("name") == name]
        if len(matches) != 1 or matches[0].get("state") != "uploaded":
            raise ValueError("Release assets are missing or ambiguous")
    return evidence


def receipt_hash(raw_receipt: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw_receipt).hexdigest()


def cache_fingerprint(entry: CatalogEntry, environment: str, evidence: ReleaseEvidence) -> str:
    target = entry.environments[environment]
    return digest(
        {
            "app_id": entry.app_id,
            "cluster_uid": target.cluster_uid,
            "source_repository_id": entry.source.repository_id,
            "source_commit": evidence.source_commit,
            "image": evidence.image,
            "bundle_sha256": evidence.bundle_sha256,
        }
    )


def verify_status(
    statuses: list[dict],
    context: str,
    description: str,
    anchor: str,
    policy: DeliveryPolicy,
    now: datetime,
) -> dict:
    matches = [status for status in statuses if status.get("context") == context]
    if not matches:
        raise ValueError("Required observer evidence is missing")
    # Latest observation wins, including failure. Older success never masks a failure.
    latest = max(matches, key=lambda item: (timestamp(item["created_at"]), int(item["id"])))
    observed = timestamp(latest["created_at"])
    if (
        latest.get("state") != "success"
        or latest.get("description") != description
        or latest.get("sha") != anchor
        or str(latest.get("creator", {}).get("id")) not in policy.observer_user_ids
        or observed > now + timedelta(seconds=300)
        or now - observed > timedelta(seconds=policy.maximum_evidence_age_seconds)
    ):
        raise ValueError("Observer evidence is failed, stale or bound to another desired state")
    return latest


def verify_intent(
    intent: DeploymentIntent,
    entry: CatalogEntry,
    policy: DeliveryPolicy,
    catalog_revision: str,
    current: CurrentIntent | None,
    evidence: ReleaseEvidence,
    raw_receipt: bytes,
):
    target = entry.environments[intent.environment]
    if (
        intent.platform_repository_id != policy.platform_repository_id
        or target.gitops_repository_id != policy.gitops_repository_id
        or intent.catalog_revision != catalog_revision
        or intent.catalog_entry_hash != digest(entry.model_dump())
        or intent.resolved_policy_hash != digest(policy.model_dump())
        or intent.source_repository_id != entry.source.repository_id
        or intent.source_commit != evidence.source_commit
        or intent.release_workflow_run_id != evidence.workflow_run_id
        or intent.release_evidence_hash != receipt_hash(raw_receipt)
        or intent.image_root_digest != evidence.image.rsplit("@", 1)[1]
        or intent.platform_digests
        != {key: child.image.rsplit("@", 1)[1] for key, child in evidence.platforms.items()}
        or intent.expected_desired_fingerprint != (current.fingerprint if current else None)
        or intent.expected_intent_anchor != (current.intent_anchor if current else None)
    ):
        raise ValueError("Intent was superseded or differs from current approved bindings")


def verify_production_approval(pr: dict, reviews: list[dict], policy: DeliveryPolicy) -> str:
    """Current-head, independent human approval. A later dismissal/request blocks admission."""
    head = pr["head"]["sha"]
    latest = {}
    for review in sorted(reviews, key=lambda item: int(item["id"])):
        if review.get("state") != "COMMENTED":
            latest[str(review["user"]["id"])] = review
    approved = []
    for user_id, review in latest.items():
        if review.get("state") == "CHANGES_REQUESTED":
            raise ValueError("An outstanding change request blocks production")
        if (
            user_id in policy.production_reviewer_user_ids
            and user_id != str(pr["user"]["id"])
            and review["user"].get("type") == "User"
            and review.get("state") == "APPROVED"
            and review.get("commit_id") == head
        ):
            approved.append({"review_id": str(review["id"]), "user_id": user_id, "head": head})
    if pr.get("draft") or not approved:
        raise ValueError("Production requires independent human approval of the exact PR head")
    return digest(approved)
