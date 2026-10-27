import hashlib
import io
import json
import tarfile
from copy import deepcopy

import pytest

from tooling.candidate import config_digest, validate_identity


@pytest.fixture
def candidate():
    return {
        "Id": "sha256:" + "a" * 64,
        "Os": "linux",
        "Architecture": "arm64",
        "Config": {
            "Labels": {
                "io.aegis.app": "orders-api",
                "org.opencontainers.image.source": "https://github.com/example/orders-api",
                "org.opencontainers.image.revision": "b" * 40,
            }
        },
    }


def test_scan_binds_actual_config_bytes_from_single_exported_image(tmp_path):
    path = tmp_path / "image.tar"
    config = b'{"architecture":"arm64","os":"linux"}'
    with tarfile.open(path, "w") as archive:
        for name, data in [
            ("manifest.json", json.dumps([{"Config": "config.json"}]).encode()),
            ("config.json", config),
        ]:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    assert config_digest(path) == "sha256:" + hashlib.sha256(config).hexdigest()


@pytest.mark.parametrize("change", [None, "app", "source", "commit", "architecture", "scan"])
def test_wrong_app_source_architecture_or_scanned_content_cannot_pass(candidate, change):
    metadata = deepcopy(candidate)
    config = "sha256:" + "c" * 64
    scan = {"Metadata": {"ImageID": config}}
    labels = metadata["Config"]["Labels"]
    if change == "app":
        labels["io.aegis.app"] = "payments-api"
    elif change == "source":
        labels["org.opencontainers.image.source"] = "https://github.com/foreign/orders-api"
    elif change == "commit":
        labels["org.opencontainers.image.revision"] = "d" * 40
    elif change == "architecture":
        metadata["Architecture"] = "amd64"
    elif change == "scan":
        scan["Metadata"]["ImageID"] = "sha256:" + "e" * 64
    if change:
        with pytest.raises(ValueError):
            validate_identity(
                metadata, scan, config, "orders-api", "example/orders-api", "b" * 40, "arm64"
            )
    else:
        validate_identity(
            metadata, scan, config, "orders-api", "example/orders-api", "b" * 40, "arm64"
        )
