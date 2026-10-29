import hashlib
import io
import json
import tarfile

import pytest

from tooling.stack_ci import verify_archive_identity


def test_containerd_manifest_identity_is_bound_to_its_archived_config(tmp_path):
    config_id = "sha256:" + "a" * 64
    raw = json.dumps({"schemaVersion": 2, "config": {"digest": config_id}, "layers": []}).encode()
    image_id = "sha256:" + hashlib.sha256(raw).hexdigest()
    files = {
        "index.json": json.dumps(
            {"schemaVersion": 2, "manifests": [{"digest": image_id}]}
        ).encode(),
        "blobs/sha256/" + image_id.split(":")[1]: raw,
    }
    path = tmp_path / "candidate.tar"
    with tarfile.open(path, "w") as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    verify_archive_identity(path, image_id, config_id)
    with pytest.raises(ValueError, match="another image config"):
        verify_archive_identity(path, image_id, "sha256:" + "b" * 64)
    with pytest.raises(ValueError, match="archived manifest"):
        verify_archive_identity(path, "sha256:" + "c" * 64, config_id)


def test_classic_docker_config_identity_remains_supported(tmp_path):
    config_id = "sha256:" + "a" * 64
    verify_archive_identity(tmp_path / "not-an-oci-export.tar", config_id, config_id)
