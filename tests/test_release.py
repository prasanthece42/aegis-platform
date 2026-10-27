import json
from copy import deepcopy

import pytest

from aegis_platform.release import (
    ReleaseEvidence,
    file_hash,
    validate_index,
    verify_candidate,
    verify_oci_bundle,
)
from tests.release_fixtures import candidate_fixture, encoded, release_fixture, write_tar


def test_complete_two_platform_bundle_has_source_bound_release_evidence(tmp_path):
    fixture = release_fixture(tmp_path)
    evidence = fixture["evidence"]
    assert evidence.schema_version == 3
    assert evidence.bundle_sha256 == file_hash(fixture["bundle"])
    assert evidence.release_tag == "release-123-1"
    assert set(evidence.platforms) == {"linux/amd64", "linux/arm64"}


@pytest.mark.parametrize(
    "mutation",
    ["app", "repository", "repository_id", "source", "run", "attempt", "helper", "platform", "tag"],
)
def test_release_rejects_foreign_or_mismatched_children(tmp_path, mutation):
    data = release_fixture(tmp_path)["evidence"].model_dump()
    child = data["platforms"]["linux/arm64"]
    key, value = {
        "app": ("app_id", "payments-api"),
        "repository": ("source_repository", "other/api"),
        "repository_id": ("source_repository_id", "999"),
        "source": ("source_commit", "f" * 40),
        "run": ("workflow_run_id", "124"),
        "attempt": ("run_attempt", "2"),
        "helper": ("platform_commit", "b" * 40),
        "platform": ("platform", "linux/amd64"),
        "tag": ("release_tag", "release-999-1"),
    }[mutation]
    if mutation == "tag":
        data[key] = value
    else:
        child[key] = value
    with pytest.raises(ValueError):
        ReleaseEvidence.model_validate(data)


@pytest.mark.parametrize(
    "mutation", ["root", "manifest", "config", "layer", "missing_layer", "unexpected_entry"]
)
def test_complete_oci_graph_is_checked(tmp_path, mutation):
    fixture = release_fixture(tmp_path)
    files = deepcopy(fixture["files"])
    prefix = "blobs/sha256/"
    index = fixture["index"]
    manifest_name = prefix + index["manifests"][0]["digest"].split(":")[1]
    manifest = json.loads(files[manifest_name])
    config_name = prefix + manifest["config"]["digest"].split(":")[1]
    layer_name = prefix + manifest["layers"][0]["digest"].split(":")[1]
    target = {
        "root": prefix + fixture["root"].split(":")[1],
        "manifest": manifest_name,
        "config": config_name,
        "layer": layer_name,
    }.get(mutation)
    if target:
        files[target] = b"corrupt"
    elif mutation == "missing_layer":
        files.pop(layer_name)
    else:
        files["../outside"] = b"unexpected"
    write_tar(fixture["bundle"], files)
    with pytest.raises((ValueError, KeyError)):
        verify_oci_bundle(fixture["bundle"], fixture["root"], fixture["children"])


def test_index_cannot_add_or_duplicate_untested_platforms(tmp_path):
    fixture = release_fixture(tmp_path)
    index = deepcopy(fixture["index"])
    index["manifests"][1] = index["manifests"][0]
    with pytest.raises(ValueError):
        validate_index(index, fixture["children"])


@pytest.mark.parametrize(
    "mutation",
    [None, "archive", "scan", "sbom", "app", "run", "helper", "metadata", "critical", "inventory"],
)
def test_candidate_verification_rechecks_bytes_context_and_policy(tmp_path, mutation):
    ctx, candidate, reports, receipt = candidate_fixture(tmp_path)
    if mutation in {"archive", "scan", "sbom"}:
        path = {
            "archive": candidate / "image.tar",
            "scan": reports / "image.json",
            "sbom": reports / "sbom.cdx.json",
        }[mutation]
        path.write_bytes(path.read_bytes() + b"changed")
    elif mutation in {"app", "run", "helper"}:
        field = {"app": "app_id", "run": "workflow_run_id", "helper": "platform_commit"}[mutation]
        receipt[field] = {"app": "payments-api", "run": "124", "helper": "b" * 40}[mutation]
        (candidate / "receipt.json").write_bytes(encoded(receipt))
    elif mutation == "metadata":
        meta = json.loads((candidate / "image-inspect.json").read_bytes())
        meta[0]["Config"]["Labels"]["io.aegis.app"] = "payments-api"
        (candidate / "image-inspect.json").write_bytes(encoded(meta))
    elif mutation in {"critical", "inventory"}:
        report = json.loads((reports / "image.json").read_bytes())
        if mutation == "critical":
            report["Results"][0]["Vulnerabilities"] = [{"Severity": "CRITICAL"}]
        else:
            report["Results"] = []
        (reports / "image.json").write_bytes(encoded(report))
        receipt["scan_report_sha256"] = file_hash(reports / "image.json").split(":")[1]
        (candidate / "receipt.json").write_bytes(encoded(receipt))
    if mutation:
        with pytest.raises((ValueError, KeyError)):
            verify_candidate(candidate, reports, ctx, "arm64")
    else:
        assert verify_candidate(candidate, reports, ctx, "arm64")["Architecture"] == "arm64"
