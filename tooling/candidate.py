"""Bind a tested/scanned candidate archive to its app, source and pinned workflow helpers."""

import hashlib
import json
import os
import re
import tarfile
from pathlib import Path


def config_digest(archive_path: Path) -> str:
    with tarfile.open(archive_path) as archive:
        manifest_file = archive.extractfile("manifest.json")
        if manifest_file is None:
            raise ValueError("Candidate archive has no Docker manifest")
        raw = manifest_file.read(131073)
        if len(raw) > 131072:
            raise ValueError("Candidate manifest exceeds budget")
        manifests = json.loads(raw)
        if len(manifests) != 1:
            raise ValueError("Expected exactly one candidate image")
        config_file = archive.extractfile(manifests[0]["Config"])
        if config_file is None:
            raise ValueError("Candidate archive has no image configuration")
        config = config_file.read(2 * 1024 * 1024 + 1)
        if len(config) > 2 * 1024 * 1024:
            raise ValueError("Candidate configuration exceeds budget")
    return "sha256:" + hashlib.sha256(config).hexdigest()


def validate_identity(
    metadata: dict,
    scan: dict,
    config: str,
    app_id: str,
    repository: str,
    source_commit: str,
    architecture: str,
):
    labels = metadata.get("Config", {}).get("Labels") or {}
    if (
        not re.fullmatch(r"[0-9a-f]{40}", source_commit)
        or labels.get("io.aegis.app") != app_id
        or labels.get("org.opencontainers.image.revision") != source_commit
        or labels.get("org.opencontainers.image.source") != "https://github.com/" + repository
        or metadata.get("Os") != "linux"
        or metadata.get("Architecture") != architecture
        or architecture not in {"amd64", "arm64"}
    ):
        raise ValueError(
            "Candidate source, application or architecture does not match the workflow"
        )
    if scan.get("Metadata", {}).get("ImageID") != config:
        raise ValueError("Image scan does not describe the exported candidate configuration")


def file_hash(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def main():
    metadata = json.loads(Path("candidate/image-inspect.json").read_bytes())
    if len(metadata) != 1:
        raise ValueError("Expected one inspected image")
    config = config_digest(Path("candidate/image.tar"))
    validate_identity(
        metadata[0],
        json.loads(Path("reports/image.json").read_bytes()),
        config,
        os.environ["APP_ID"],
        os.environ["SOURCE_REPOSITORY"],
        os.environ["SOURCE_SHA"],
        os.environ["ARCH"],
    )
    receipt = {
        "schema_version": 1,
        "app_id": os.environ["APP_ID"],
        "source_repository": os.environ["SOURCE_REPOSITORY"],
        "source_commit": os.environ["SOURCE_SHA"],
        "platform": "linux/" + os.environ["ARCH"],
        "workflow_run_id": os.environ["GITHUB_RUN_ID"],
        "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "platform_commit": os.environ["PLATFORM_COMMIT"],
        "image_id": metadata[0]["Id"],
        "image_config_digest": config,
        "candidate_archive_sha256": file_hash(Path("candidate/image.tar")),
        "scan_report_sha256": file_hash(Path("reports/image.json")),
        "sbom_sha256": file_hash(Path("reports/sbom.cdx.json")),
        "provenance": (
            "Unsigned CI candidate evidence; not a published release or deployment approval"
        ),
    }
    Path("candidate/receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
