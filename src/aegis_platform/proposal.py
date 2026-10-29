"""Produce an exact app-scoped Git diff after live delivery admission.

The caller fetches fresh metadata and complete Git files. No mutation occurs here;
the same function is used to generate and independently validate a proposal.
"""

from datetime import UTC, datetime
from pathlib import Path

from aegis_platform.bootstrap import bootstrap_plan, release_values, validate_profile
from aegis_platform.canonical import canonical, digest, strict_json
from aegis_platform.catalog import Catalog
from aegis_platform.contracts import DeploymentIntent, DesiredState
from aegis_platform.delivery import (
    CurrentIntent,
    DeliveryPolicy,
    admit_release,
    authorize,
    cache_fingerprint,
    verify_intent,
    verify_status,
)
from aegis_platform.stack import PROFILE


def required_bootstrap(catalog, app_id, environment, policy, bootstrap_policy, chart):
    target = catalog.apps[app_id].environments[environment]
    return bootstrap_plan(
        catalog,
        app_id,
        environment,
        {
            "gitops_repository": policy.gitops_repository,
            "gitops_repository_id": policy.gitops_repository_id,
            "cluster_id": target.cluster_id,
            "cluster_uid": target.cluster_uid,
        },
        bootstrap_policy,
        chart,
    )


def current_state(entry, environment, files, anchor, policy_hash=None):
    """Validate a pointer against actual Git values and current catalog-owned bindings."""
    target = entry.environments[environment]
    path = target.values_path.rsplit("/", 1)[0] + "/release.json"
    raw = files.get(path)
    if raw is None:
        return None
    pointer = strict_json(raw)
    state = DesiredState.model_validate(pointer["desired_state"])
    if (
        pointer["fingerprint"] != digest(state.model_dump())
        or strict_json(files[target.values_path]) != state.effective_values
        or state.app_id != entry.app_id
        or state.environment != environment
        or state.cluster_uid != target.cluster_uid
        or state.cluster_id != target.cluster_id
        or state.namespace != target.namespace
        or state.source_repository_id != entry.source.repository_id
        or state.chart_sha256 != entry.versions.chart_sha256
        or state.chart_version != entry.versions.chart_version
        or state.source_commit != state.effective_values.get("sourceCommit")
        or state.image_root_digest != state.effective_values.get("image", {}).get("digest")
        or (policy_hash is not None and pointer["intent"]["resolved_policy_hash"] != policy_hash)
    ):
        raise ValueError("Current pointer differs from approved app bindings or actual values")
    for binding_path, binding in state.controller_bindings.items():
        if binding_path not in files or strict_json(files[binding_path]) != binding:
            raise ValueError("Controller/bootstrap bindings changed outside the current intent")
    return CurrentIntent(
        fingerprint=pointer["fingerprint"],
        intent_anchor=anchor,
        source_commit=state.source_commit,
        image_root_digest=state.image_root_digest,
        release_id=str(pointer["release_id"]),
        release_evidence_hash=pointer["intent"].get("release_evidence_hash"),
    )


def proposal(
    *,
    intent: DeploymentIntent,
    catalog: Catalog,
    catalog_revision: str,
    policy: DeliveryPolicy,
    bootstrap_policy: dict,
    chart: Path,
    raw_receipt: bytes,
    release: dict,
    repository: dict,
    run: dict,
    source_push: bool,
    source_comparison: str | None,
    git_files: dict[str, bytes],
    current_anchor: str | None,
    cache_statuses: list[dict],
    prior: CurrentIntent | None = None,
    prior_statuses: list[dict] | None = None,
    now: datetime | None = None,
) -> dict[str, bytes]:
    now = now or datetime.now(UTC)
    entry = catalog.apps[intent.app_id]
    environment = intent.environment
    target = entry.environments[environment]
    if digest(bootstrap_policy) != policy.bootstrap_policy_hash:
        raise ValueError("Bootstrap policy changed outside the approved delivery policy")
    authorize(entry, intent.requester_user_id, environment, source_push)
    evidence = admit_release(entry, raw_receipt, release, repository, run, policy)
    if str(release["id"]) != intent.release_id:
        raise ValueError("Release ID differs from confirmed intent")
    current = current_state(
        entry, environment, git_files, current_anchor, digest(policy.model_dump())
    )
    verify_intent(intent, entry, policy, catalog_revision, current, evidence, raw_receipt)
    if current and source_comparison not in {"ahead", "identical"}:
        raise ValueError("Normal delivery cannot regress or cross source lineage")
    verify_status(
        cache_statuses,
        f"aegis/{entry.app_id}/{target.cluster_id}-cache",
        "cachefp:" + cache_fingerprint(entry, environment, evidence).split(":")[1],
        evidence.source_commit,
        policy,
        now,
    )
    if environment != "dev":
        expected = intent.prior_environment_evidence
        if (
            prior is None
            or expected is None
            or prior_statuses is None
            or prior.fingerprint != expected.fingerprint
            or prior.intent_anchor != expected.intent_anchor
            or prior.source_commit != evidence.source_commit
            or prior.image_root_digest != evidence.image.rsplit("@", 1)[1]
            or (
                entry.runtime.profile_id == PROFILE
                and prior.release_evidence_hash != intent.release_evidence_hash
            )
        ):
            raise ValueError("Promotion no longer matches current prior-environment desired state")
        observed = verify_status(
            prior_statuses,
            f"aegis/{entry.app_id}/{expected.environment}-health",
            "Healthy " + prior.fingerprint,
            prior.intent_anchor,
            policy,
            now,
        )
        if (
            str(observed["id"]) != expected.evidence_reference
            or observed["created_at"] != expected.observed_at
        ):
            raise ValueError("Prior health evidence changed; confirm the refreshed promotion")
    bootstrap = required_bootstrap(
        catalog, intent.app_id, environment, policy, bootstrap_policy, chart
    )
    bindings = {}
    for path, expected_file in bootstrap.items():
        if path.startswith("reviews/"):
            continue
        actual = git_files.get(path)
        if actual is None or (
            actual != expected_file
            if isinstance(expected_file, bytes)
            else strict_json(actual) != expected_file
        ):
            raise ValueError(
                "Reviewed chart/controller/namespace bootstrap is missing or changed: " + path
            )
        if not path.startswith("charts/"):
            bindings[path] = expected_file
    # The renderer's public CLI stays DEV-only. Protected values are derived from
    # the same admitted release/profile after the prior-environment gate above.
    if environment == "dev" or entry.runtime.profile_id == PROFILE:
        values = release_values(catalog, entry.app_id, environment, evidence, bootstrap_policy)
    else:
        profile = validate_profile(bootstrap_policy, entry.runtime.resource_profile_id)
        image, image_digest = evidence.image.split("@")
        values = {
            "appId": entry.app_id,
            "environment": environment,
            "replicaCount": 1,
            "image": {"repository": image, "digest": image_digest, "pullPolicy": "Never"},
            "sourceCommit": evidence.source_commit,
            "containerPort": entry.runtime.container_port,
            "healthPath": entry.runtime.health_path,
            "resources": {"requests": profile["requests"], "limits": profile["limits"]},
        }
    resolved_profile = validate_profile(bootstrap_policy, entry.runtime.resource_profile_id)
    if entry.runtime.profile_id == PROFILE:
        from aegis_platform.stack_plan import budget

        resolved_profile["quota"] = budget(entry.runtime.stack, resolved_profile)
    state = DesiredState(
        app_id=entry.app_id,
        environment=environment,
        cluster_id=target.cluster_id,
        cluster_uid=target.cluster_uid,
        namespace=target.namespace,
        source_repository_id=entry.source.repository_id,
        source_commit=evidence.source_commit,
        image_root_digest=intent.image_root_digest,
        platform_digests=intent.platform_digests,
        chart_version=entry.versions.chart_version,
        chart_sha256=entry.versions.chart_sha256,
        effective_values=values,
        resolved_cluster_profile=resolved_profile,
        controller_bindings=bindings,
    )
    base = f"applications/{entry.app_id}"
    result = {
        target.values_path: canonical(values) + b"\n",
        target.values_path.rsplit("/", 1)[0] + "/release.json": canonical(
            {
                "schema_version": 1,
                "delivery_id": intent.request_id,
                "release_id": intent.release_id,
                "release_tag": evidence.release_tag,
                "fingerprint": digest(state.model_dump()),
                "desired_state": state.model_dump(),
                "intent": intent.model_dump(),
            }
        )
        + b"\n",
        f"{base}/releases/{evidence.release_tag}.json": raw_receipt,
    }
    catalog.check_delivery_paths(entry.app_id, environment, evidence.release_tag, list(result))
    # Retained release evidence is immutable across retries and promotions.
    receipt_path = f"{base}/releases/{evidence.release_tag}.json"
    if receipt_path in git_files and git_files[receipt_path] != raw_receipt:
        raise ValueError("Retained release receipt already has different bytes")
    return result
