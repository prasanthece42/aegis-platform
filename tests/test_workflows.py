from pathlib import Path

import pytest
import yaml

from aegis_platform.workflow import (
    PLATFORM_REPOSITORY,
    WORKFLOW,
    resolve_workflow_commit,
    validate_inputs,
)
from tooling.make_caller import make_caller
from tooling.render_workflows import render_ci, render_workflow


def referenced(ref, sha):
    return {
        "referenced_workflows": [
            {"path": f"{PLATFORM_REPOSITORY}/.github/workflows/{WORKFLOW}@{ref}", "sha": sha}
        ]
    }


def test_helper_checkout_is_bound_to_the_immutable_called_workflow():
    sha = "a" * 40
    assert resolve_workflow_commit(referenced(sha, sha), PLATFORM_REPOSITORY, WORKFLOW) == sha
    for ref in ["main", "v1", "b" * 40]:
        with pytest.raises(ValueError):
            resolve_workflow_commit(referenced(ref, sha), PLATFORM_REPOSITORY, WORKFLOW)
    with pytest.raises(ValueError):
        resolve_workflow_commit({}, PLATFORM_REPOSITORY, WORKFLOW)


@pytest.mark.parametrize(
    "platforms", ["[]", '["arm64","arm64"]', '["unknown"]', '"amd64"', '["amd64","arm64","amd64"]']
)
def test_matrix_is_bounded_before_allocation(platforms):
    with pytest.raises(ValueError):
        validate_inputs("orders-api", platforms, "8000", "/health")


def test_generated_bootstrap_matches_tested_source_and_has_no_write_authority():
    root = Path(__file__).resolve().parents[1]
    saved = (root / ".github/workflows/python-web-ci.yml").read_text()
    assert saved == render_ci()
    workflow = yaml.load(saved, Loader=yaml.BaseLoader)
    assert workflow["on"]["workflow_call"]
    assert workflow["permissions"] == {"contents": "read", "actions": "read"}
    assert "secrets" not in workflow["on"]["workflow_call"]
    for job in ["checks", "container"]:
        steps = workflow["jobs"][job]["steps"]
        checkouts = [
            step["with"] for step in steps if step.get("uses", "").startswith("actions/checkout@")
        ]
        assert checkouts[0]["ref"] == "${{ needs.prepare.outputs.platform_commit }}"
        assert checkouts[0]["path"] == "platform"
        assert checkouts[1]["path"] == "source"
        assert all(c["persist-credentials"] == "false" for c in checkouts)
        assert all("GH_TOKEN" not in step.get("env", {}) for step in steps)


def test_callers_select_the_same_shared_workflow_family_with_distinct_app_ids():
    sha = "a" * 40
    orders = yaml.load(make_caller("orders-api", sha), Loader=yaml.BaseLoader)
    payments = yaml.load(make_caller("payments-api", sha), Loader=yaml.BaseLoader)
    assert orders["jobs"]["validate"]["uses"] == payments["jobs"]["validate"]["uses"]
    assert (
        orders["jobs"]["validate"]["with"]["app-id"]
        != payments["jobs"]["validate"]["with"]["app-id"]
    )
    for ref in ["main", "v1", "0" * 40]:
        with pytest.raises(ValueError):
            make_caller("orders-api", ref)
    with pytest.raises(ValueError):
        make_caller("orders-api", sha, "main\nunsafe:")


def test_release_workflow_keeps_write_credentials_away_from_app_source():
    root = Path(__file__).resolve().parents[1]
    saved = (root / ".github/workflows/python-web-release.yml").read_text()
    assert saved == render_workflow("release")
    workflow = yaml.load(saved, Loader=yaml.BaseLoader)
    assert workflow["jobs"]["validate"]["uses"] == "./.github/workflows/python-web-ci.yml"
    assert workflow["jobs"]["validate"]["permissions"] == {"contents": "read", "actions": "read"}
    assert 'WORKFLOW = "python-web-release.yml"' in workflow["jobs"]["prepare"]["steps"][0]["run"]
    for job_name in ["publish", "release-index"]:
        job = workflow["jobs"][job_name]
        assert job["permissions"]["packages"] == "write"
        checkouts = [
            s["with"] for s in job["steps"] if s.get("uses", "").startswith("actions/checkout@")
        ]
        assert len(checkouts) == 1
        assert checkouts[0]["repository"] == "${{ needs.prepare.outputs.platform_repository }}"
        assert checkouts[0]["ref"] == "${{ needs.prepare.outputs.platform_commit }}"
        assert checkouts[0]["persist-credentials"] == "false"
        assert all("secrets" not in s for s in job["steps"])
    caller = yaml.load(make_caller("orders-api", "a" * 40, release=True), Loader=yaml.BaseLoader)
    assert "pull_request" not in caller["on"]
    assert caller["permissions"]["packages"] == "write"
    assert "python-web-release.yml@" in caller["jobs"]["validate"]["uses"]


@pytest.mark.parametrize(
    "event,ref", [("pull_request", "refs/heads/main"), ("push", "refs/heads/feature")]
)
def test_candidate_export_rejects_untrusted_event_before_any_output(
    tmp_path, monkeypatch, event, ref
):
    import io
    import json

    from aegis_platform import workflow

    metadata = {
        **referenced("a" * 40, "a" * 40),
        "id": 123,
        "run_attempt": 1,
        "repository": {"id": 101},
    }
    monkeypatch.setattr(
        workflow, "urlopen", lambda *_args, **_kwargs: io.BytesIO(json.dumps(metadata).encode())
    )
    event_file, output = tmp_path / "event.json", tmp_path / "output"
    event_file.write_text(json.dumps({"repository": {"default_branch": "main"}}))
    values = {
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_REPOSITORY": "example/orders-api",
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_REPOSITORY_ID": "101",
        "AEGIS_APP_ID": "orders-api",
        "AEGIS_PLATFORMS": '["amd64","arm64"]',
        "AEGIS_PORT": "8000",
        "AEGIS_HEALTH_PATH": "/health",
        "AEGIS_EXPORT_CANDIDATE": "true",
        "GH_TOKEN": "synthetic-token",
        "GITHUB_EVENT_PATH": str(event_file),
        "GITHUB_EVENT_NAME": event,
        "GITHUB_REF": ref,
        "GITHUB_OUTPUT": str(output),
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match="default-branch"):
        workflow.main()
    assert not output.exists()
