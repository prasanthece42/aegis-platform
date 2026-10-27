import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from tooling.audit_legacy_enrollment import (
    EnrollmentReview,
    validate_review,
    validate_runtime,
    verify_remote_baseline,
)


@pytest.fixture
def review():
    return EnrollmentReview.model_validate(
        json.loads(Path("migrations/sample-api.enrollment-review.json").read_text())
    )


def validate(review):
    validate_review(
        review,
        json.loads(Path("migrations/sample-api.baseline.json").read_text()),
        json.loads(Path("catalog/clusters/kind-local.json").read_text()),
    )


def test_review_preserves_all_original_bindings_without_enabling_portal_delivery(review):
    validate(review)
    assert not review.portal_delivery_enabled and not review.create_or_rename_resources
    assert review.stage == "review-only-not-enrolled"
    assert review.environments["prod"].delivery_mode == "manual"


@pytest.mark.parametrize(
    "field,value",
    [
        ("portal_delivery_enabled", True),
        ("release_schema_version", 3),
        ("production_human_review_required", False),
        ("create_or_rename_resources", True),
    ],
)
def test_review_cannot_claim_cutover_or_weaken_production_controls(review, field, value):
    data = review.model_dump()
    data[field] = value
    with pytest.raises(ValidationError):
        EnrollmentReview.model_validate(data)


@pytest.mark.parametrize(
    "field,value",
    [
        ("namespace", "aegis-sample-api-dev"),
        ("argo_application", "sample-api-dev"),
        ("argo_project", "default"),
        ("gitops_branch", "prod"),
        ("values_path", "applications/sample-api/environments/dev/values.yaml"),
        ("controller_path", "arbitrary.yaml"),
        ("delivery_mode", "manual"),
    ],
)
def test_review_refuses_implicit_binding_migration(review, field, value):
    data = review.model_dump()
    data["environments"]["dev"][field] = value
    with pytest.raises(ValueError, match="existing bindings"):
        validate(EnrollmentReview.model_validate(data))


def runtime(review, env="dev"):
    target = review.environments[env]
    fixture = json.loads(Path(f"tests/fixtures/legacy/{env}.json").read_text())
    manifest, project = fixture["application"], fixture["project"]
    app = deepcopy(manifest)
    app["status"] = {"sync": {"status": "Synced"}, "health": {"status": "Healthy"}}
    image = "ghcr.io/" + review.source_repository + "@sha256:" + "a" * 64
    pointer = {"image": image, "source_commit": "b" * 40, "release_tag": "release-123-1"}
    receipt = {"schema_version": 2, "source_repository": review.source_repository, **pointer}
    values = {
        "image": {"repository": image.split("@")[0], "digest": image.split("@")[1]},
        "sourceCommit": pointer["source_commit"],
    }
    deployment = {
        "metadata": {"name": "sample-api", "namespace": target.namespace},
        "spec": {"template": {"spec": {"containers": [{"image": image}]}}},
    }
    return [
        review,
        env,
        manifest,
        app,
        project,
        deepcopy(project),
        values,
        pointer,
        receipt,
        deployment,
    ]


def test_binding_audit_does_not_relabel_schema_two_as_admitted_schema_three(review):
    case = runtime(review)
    result = validate_runtime(*case)
    assert result["namespace"] == "aegis-dev"
    case[8]["schema_version"] = 3
    with pytest.raises(ValueError, match="receipt/live image"):
        validate_runtime(*case)


def test_runtime_rejects_controller_project_or_image_drift(review):
    case = runtime(review)
    case[3]["spec"]["destination"]["namespace"] = "unrelated"
    with pytest.raises(ValueError, match="controller"):
        validate_runtime(*case)
    case = runtime(review)
    case[5]["spec"]["roles"] = [{"name": "extra"}]
    with pytest.raises(ValueError, match="project"):
        validate_runtime(*case)
    case = runtime(review)
    case[9]["spec"]["template"]["spec"]["containers"][0]["image"] = "mutable:latest"
    with pytest.raises(ValueError, match="receipt/live image"):
        validate_runtime(*case)


def test_runtime_rejects_automatic_production_sync(review):
    case = runtime(review, "prod")
    case[3]["spec"]["syncPolicy"]["automated"] = {"prune": True}
    with pytest.raises(ValueError, match="controller"):
        validate_runtime(*case)


def test_remote_baseline_rejects_changed_missing_or_symlinked_files(tmp_path):
    (tmp_path / "config.json").write_text("{}")
    for tree in [
        [],
        [{"path": "config.json", "mode": "100644", "sha": "wrong"}],
        [{"path": "config.json", "mode": "120000", "sha": "wrong"}],
    ]:
        api = SimpleNamespace(repo=lambda *args, tree=tree: {"tree": tree})
        with pytest.raises(ValueError, match="Remote baseline file"):
            verify_remote_baseline(api, "a" * 40, ["config.json"], tmp_path)
