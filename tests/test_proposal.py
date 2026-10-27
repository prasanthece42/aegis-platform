from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis_platform.canonical import canonical, digest, strict_json
from aegis_platform.catalog import Catalog, CatalogPolicy, Cluster
from aegis_platform.contracts import DeploymentIntent
from aegis_platform.delivery import cache_fingerprint, receipt_hash
from aegis_platform.proposal import proposal, required_bootstrap
from aegis_platform.release import ReleaseEvidence
from tests.test_delivery import policy as policy
from tests.test_delivery import release_case as release_case


@pytest.fixture
def admitted(release_case, policy):
    entry, raw, release, repository, run = release_case
    bootstrap_policy = strict_json(Path("policies/bootstrap.json").read_bytes())
    policy.bootstrap_policy_hash = digest(bootstrap_policy)
    catalog = Catalog(
        [entry],
        [
            Cluster.model_validate(
                strict_json(Path("examples/catalog/clusters/example-kind.json").read_bytes())
            )
        ],
        CatalogPolicy.model_validate(strict_json(Path("policies/catalog.json").read_bytes())),
    )
    evidence = ReleaseEvidence.model_validate(strict_json(raw))
    now = datetime.now(UTC)
    intent = DeploymentIntent(
        request_id="req-" + "a" * 64,
        issuer_id="test",
        platform_repository_id=policy.platform_repository_id,
        requester_user_id=entry.access.deployer_user_ids_by_environment["dev"][0],
        created_at=now.isoformat(),
        idempotency_key_hash=digest("key"),
        payload_hash=digest("fields"),
        app_id=entry.app_id,
        environment="dev",
        operation="deploy",
        origin="portal",
        catalog_revision="a" * 40,
        catalog_entry_hash=digest(entry.model_dump()),
        resolved_policy_hash=digest(policy.model_dump()),
        source_repository_id=entry.source.repository_id,
        source_commit=evidence.source_commit,
        release_id="700",
        release_workflow_run_id=evidence.workflow_run_id,
        release_evidence_hash=receipt_hash(raw),
        image_root_digest=evidence.image.rsplit("@", 1)[1],
        platform_digests={k: v.image.rsplit("@", 1)[1] for k, v in evidence.platforms.items()},
        expected_desired_fingerprint=None,
        expected_intent_anchor=None,
        prior_environment_evidence=None,
    )
    release["id"] = 700
    chart = Path("charts/web-service/1.0.0")
    files = required_bootstrap(catalog, entry.app_id, "dev", policy, bootstrap_policy, chart)
    return {
        "intent": intent,
        "catalog": catalog,
        "catalog_revision": "a" * 40,
        "policy": policy,
        "bootstrap_policy": bootstrap_policy,
        "chart": chart,
        "raw_receipt": raw,
        "release": release,
        "repository": repository,
        "run": run,
        "source_push": True,
        "source_comparison": None,
        "git_files": {
            p: value if isinstance(value, bytes) else canonical(value) for p, value in files.items()
        },
        "current_anchor": None,
        "cache_statuses": [
            {
                "id": 1,
                "context": f"aegis/{entry.app_id}/{entry.environments['dev'].cluster_id}-cache",
                "description": "cachefp:" + cache_fingerprint(entry, "dev", evidence).split(":")[1],
                "sha": evidence.source_commit,
                "state": "success",
                "creator": {"id": 123},
                "created_at": now.isoformat(),
            }
        ],
        "now": now,
    }


def test_proposal_is_exact_and_app_scoped(admitted):
    files = proposal(**admitted)
    assert len(files) == 3
    assert all(path.startswith("applications/orders-api/") for path in files)
    pointer = strict_json(files["applications/orders-api/environments/dev/release.json"])
    assert pointer["delivery_id"] == admitted["intent"].request_id
    assert pointer["fingerprint"] == digest(pointer["desired_state"])
    assert pointer["desired_state"]["image_root_digest"] == admitted["intent"].image_root_digest


@pytest.mark.parametrize(
    "mutation", ["grant", "policy", "cache", "chart", "project", "release", "intent"]
)
def test_proposal_fails_before_mutation_for_changed_authority_or_bootstrap(admitted, mutation):
    if mutation == "grant":
        admitted["source_push"] = False
    elif mutation == "policy":
        admitted["bootstrap_policy"]["pod_security_version"] = "v1.34"
    elif mutation == "cache":
        admitted["cache_statuses"][0]["state"] = "failure"
    elif mutation == "chart":
        admitted["git_files"]["charts/web-service/1.0.0/Chart.yaml"] = b"wrong chart"
    elif mutation == "project":
        del admitted["git_files"]["argocd/projects/orders-api-dev.json"]
    elif mutation == "release":
        admitted["release"]["id"] = 701
    else:
        admitted["intent"].source_commit = "f" * 40
    with pytest.raises(ValueError):
        proposal(**admitted)
