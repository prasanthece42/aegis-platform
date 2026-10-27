from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aegis_platform.canonical import canonical, strict_json
from aegis_platform.contracts import CatalogEntry
from aegis_platform.delivery import (
    DeliveryPolicy,
    admit_release,
    authorize,
    request_id,
    verify_production_approval,
    verify_status,
)
from tests.release_fixtures import release_fixture


@pytest.fixture
def policy():
    return DeliveryPolicy(
        platform_repository="example/aegis-platform",
        platform_repository_id="400",
        gitops_repository="example/aegis-gitops",
        gitops_repository_id="401",
        workflow_bot_user_ids=["41898282"],
        observer_user_ids=["123"],
        production_reviewer_user_ids=["123"],
    )


@pytest.fixture
def release_case(tmp_path, policy):
    evidence = release_fixture(tmp_path)["evidence"]
    entry = strict_json(Path("examples/catalog/apps/orders-api.json").read_bytes())
    entry["app_id"] = evidence.app_id
    owner, name = evidence.source_repository.split("/")
    entry["source"].update(owner=owner, name=name, repository_id=evidence.source_repository_id)
    entry["versions"].update(
        workflow_commit=evidence.platform_commit, helper_commit=evidence.platform_commit
    )
    entry = CatalogEntry.model_validate(entry)
    repository = {
        "id": int(evidence.source_repository_id),
        "full_name": evidence.source_repository,
        "private": False,
        "default_branch": entry.source.default_branch,
    }
    release = {
        "draft": False,
        "prerelease": False,
        "published_at": "2026-10-26T00:00:00Z",
        "tag_name": evidence.release_tag,
        "author": {"id": 41898282, "type": "Bot"},
        "assets": [
            {"name": name, "state": "uploaded"} for name in ["release.json", "image.oci.tar"]
        ],
    }
    run = {
        "id": int(evidence.workflow_run_id),
        "run_attempt": int(evidence.run_attempt),
        "repository": {"id": int(evidence.source_repository_id)},
        "head_sha": evidence.source_commit,
        "head_branch": entry.source.default_branch,
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "path": ".github/workflows/release.yml",
        "referenced_workflows": [
            {
                "path": f"{policy.platform_repository}/.github/workflows/{name}.yml"
                f"@{evidence.platform_commit}",
                "sha": evidence.platform_commit,
            }
            for name in ["python-web-release", "python-web-ci"]
        ],
    }
    return entry, canonical(evidence.model_dump()), release, repository, run


def test_admits_source_bound_release(release_case, policy):
    assert admit_release(*release_case, policy).schema_version == 3


@pytest.mark.parametrize(
    "mutation", ["private", "renamed", "bot", "draft", "attempt", "pr", "pin", "missing", "assets"]
)
def test_release_admission_rejects_forged_or_incomplete_github_evidence(
    release_case, policy, mutation
):
    entry, raw, release, repo, run = deepcopy(release_case)
    if mutation == "private":
        repo["private"] = True
    elif mutation == "renamed":
        repo["full_name"] = "attacker/replacement"
    elif mutation == "bot":
        release["author"]["id"] = 999
    elif mutation == "draft":
        release["draft"] = True
    elif mutation == "attempt":
        run["run_attempt"] += 1
    elif mutation == "pr":
        run["event"] = "pull_request"
    elif mutation == "pin":
        run["referenced_workflows"][0]["path"] = (
            run["referenced_workflows"][0]["path"].split("@")[0] + "@main"
        )
    elif mutation == "missing":
        run["referenced_workflows"].pop()
    else:
        release["assets"].append(release["assets"][0])
    with pytest.raises(ValueError):
        admit_release(entry, raw, release, repo, run, policy)


def test_latest_failed_observation_overrides_old_success(policy):
    now = datetime.now(UTC)
    status = {
        "id": 1,
        "context": "aegis/orders-api/dev-health",
        "description": "Healthy sha256:abc",
        "sha": "a" * 40,
        "state": "success",
        "creator": {"id": 123},
        "created_at": (now - timedelta(minutes=1)).isoformat(),
    }
    args = (status["context"], status["description"], status["sha"], policy, now)
    assert verify_status([status], *args) == status
    failed = {**status, "id": 2, "created_at": now.isoformat(), "state": "failure"}
    with pytest.raises(ValueError):
        verify_status([status, failed], *args)
    for changed in [
        {"creator": {"id": 999}},
        {"sha": "b" * 40},
        {"created_at": (now - timedelta(days=2)).isoformat()},
        {"created_at": (now + timedelta(minutes=6)).isoformat()},
    ]:
        with pytest.raises(ValueError):
            verify_status([{**status, **changed}], *args)


def test_prod_requires_independent_human_at_current_head(policy):
    pr = {"user": {"id": 456}, "head": {"sha": "a" * 40}, "draft": False}
    review = {
        "id": 1,
        "user": {"id": 123, "type": "User"},
        "state": "APPROVED",
        "commit_id": "a" * 40,
    }
    assert verify_production_approval(pr, [review], policy).startswith("sha256:")
    for changed in [
        {"commit_id": "b" * 40},
        {"state": "DISMISSED"},
        {"user": {"id": 456, "type": "User"}},
        {"user": {"id": 123, "type": "Bot"}},
    ]:
        with pytest.raises(ValueError):
            verify_production_approval(pr, [{**review, **changed}], policy)
    with pytest.raises(ValueError):
        verify_production_approval(
            pr, [review, {**review, "id": 2, "state": "CHANGES_REQUESTED"}], policy
        )


def test_request_identity_and_current_permission(release_case):
    entry = release_case[0]
    assert request_id("issuer", "1", "key") == request_id("issuer", "1", "key")
    assert request_id("issuer", "1", "key") != request_id("issuer", "2", "key")
    user_id = entry.access.deployer_user_ids_by_environment["dev"][0]
    authorize(entry, user_id, "dev", True)
    for user, env, push in [
        (user_id, "dev", False),
        ("999999", "dev", True),
        (user_id, "prod", True),
    ]:
        with pytest.raises(ValueError):
            authorize(entry, user, env, push)
