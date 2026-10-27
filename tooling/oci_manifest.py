"""Change descriptor media types without changing any scanned configuration/layer blob."""

import json
import sys
from copy import deepcopy


def normalize(manifest):
    result = deepcopy(manifest)
    if result.get("schemaVersion") != 2 or "config" not in result:
        raise ValueError("Expected a single Docker image manifest")
    result["mediaType"] = "application/vnd.oci.image.manifest.v1+json"
    result["config"]["mediaType"] = "application/vnd.oci.image.config.v1+json"
    mappings = {
        "application/vnd.docker.image.rootfs.diff.tar.gzip": (
            "application/vnd.oci.image.layer.v1.tar+gzip"
        ),
        "application/vnd.docker.image.rootfs.diff.tar": "application/vnd.oci.image.layer.v1.tar",
    }
    for layer in result["layers"]:
        if layer["mediaType"] in mappings:
            layer["mediaType"] = mappings[layer["mediaType"]]
        elif not layer["mediaType"].startswith("application/vnd.oci.image.layer."):
            raise ValueError("Unsupported image layer media type")
    return result


if __name__ == "__main__":
    print(json.dumps(normalize(json.load(sys.stdin)), separators=(",", ":")))
