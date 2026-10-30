import hashlib
import json
from copy import deepcopy

import pytest

from aegis_platform.canonical import canonical
from tooling import stack_publish


@pytest.fixture
def registry(monkeypatch):
    config = canonical({"architecture": "arm64", "docker_version": "29.0", "config": {}})
    digest = "sha256:" + hashlib.sha256(config).hexdigest()
    docker_manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "digest": digest,
            "size": len(config),
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "digest": "sha256:" + "a" * 64,
                "size": 1024,
            }
        ],
    }
    state = {"source": docker_manifest, "uploaded": None, "wrong_registry_digest": False}

    def run(args, capture=False, **kwargs):
        if args[:2] == ["docker", "push"]:
            return None
        if args[:4] == ["docker", "buildx", "imagetools", "inspect"]:
            return json.dumps(state["source"])
        if args[:3] == ["regctl", "manifest", "put"]:
            state["uploaded"] = kwargs["input"]
            return None
        if args[:2] == ["skopeo", "inspect"]:
            return "sha256:" + (
                "b" * 64
                if state["wrong_registry_digest"]
                else hashlib.sha256(state["uploaded"]).hexdigest()
            )
        raise AssertionError("Unexpected publication transport: " + str(args[:3]))

    monkeypatch.setattr(stack_publish, "run", run)
    return digest, state


def test_oci_publication_preserves_tested_config_and_layer_blobs(registry):
    config_digest, state = registry
    before = deepcopy(state["source"])
    checksum = stack_publish.publish_oci("ghcr.io/demo/app:tested", config_digest)
    manifest = json.loads(state["uploaded"])
    assert checksum == "sha256:" + hashlib.sha256(state["uploaded"]).hexdigest()
    assert manifest["mediaType"] == "application/vnd.oci.image.manifest.v1+json"
    assert manifest["config"]["digest"] == config_digest
    assert manifest["config"]["size"] == before["config"]["size"]
    assert manifest["layers"][0]["digest"] == before["layers"][0]["digest"]
    assert manifest["layers"][0]["size"] == before["layers"][0]["size"]
    assert state["source"] == before


def test_publication_rejects_config_rewrite_before_oci_manifest_upload(registry):
    _digest, state = registry
    with pytest.raises(ValueError, match="tested candidate config"):
        stack_publish.publish_oci("ghcr.io/demo/app:tested", "sha256:" + "c" * 64)
    assert state["uploaded"] is None


def test_publication_rejects_registry_manifest_replacement(registry):
    digest, state = registry
    state["wrong_registry_digest"] = True
    with pytest.raises(ValueError, match="preserved candidate graph"):
        stack_publish.publish_oci("ghcr.io/demo/app:tested", digest)
