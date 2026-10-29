"""Validate source-bound candidate bytes and complete immutable multi-platform releases."""

import hashlib
import re
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator

from aegis_platform.canonical import strict_json
from aegis_platform.contracts import AppId, Commit, Contract, Digest, Identifier

PLATFORMS = {"linux/amd64", "linux/arm64"}


def validate_repository(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]+", value) or value.split(
        "/"
    )[1] in {".", ".."}:
        raise ValueError("Expected a GitHub owner/repository identity")
    return value


class ReleaseContext(Contract):
    app_id: AppId
    source_repository: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    source_repository_id: Identifier
    source_commit: Commit
    workflow_run_id: Identifier
    run_attempt: Identifier
    platform_commit: Commit

    @field_validator("source_repository")
    @classmethod
    def valid_repository(cls, value):
        return validate_repository(value)

    @property
    def image_name(self) -> str:
        return "ghcr.io/" + self.source_repository.lower()

    @property
    def tag(self) -> str:
        return f"release-{self.workflow_run_id}-{self.run_attempt}"


class PublishedPlatform(ReleaseContext):
    schema_version: Literal[1] = 1
    platform: Literal["linux/amd64", "linux/arm64"]
    image: str
    image_config_digest: Digest
    candidate_archive_sha256: Digest
    digest_pull_smoke_test: Literal["passed"]
    evidence_sha256: dict[str, Digest]

    @model_validator(mode="after")
    def scoped_image(self):
        if not re.fullmatch(re.escape(self.image_name) + r"@sha256:[0-9a-f]{64}", self.image):
            raise ValueError("Published platform must use an immutable source-scoped image")
        if set(self.evidence_sha256) != {"dependencies.json", "image.json", "sbom.cdx.json"}:
            raise ValueError("Published platform requires all scan/SBOM evidence hashes")
        return self


class ReleaseEvidence(ReleaseContext):
    schema_version: Literal[3] = 3
    release_tag: str
    verified_at: str
    image: str
    platforms: dict[str, PublishedPlatform]
    bundle_sha256: Digest
    provenance: Literal[
        "Unsigned workflow evidence; admission must verify GitHub source/run identity"
    ]

    @model_validator(mode="after")
    def bound_children(self):
        if self.release_tag != f"release-{self.workflow_run_id}-{self.run_attempt}":
            raise ValueError("Release tag does not match run identity")
        if not re.fullmatch(re.escape(self.image_name) + r"@sha256:[0-9a-f]{64}", self.image):
            raise ValueError("Release must use an immutable source-scoped root image")
        when = datetime.fromisoformat(self.verified_at.replace("Z", "+00:00"))
        if when.tzinfo is None:
            raise ValueError("Release observation requires a timezone")
        if set(self.platforms) != PLATFORMS:
            raise ValueError("Both supported platform receipts are required")
        for platform, child in self.platforms.items():
            if child.platform != platform:
                raise ValueError("Platform key and receipt disagree")
            for field in ReleaseContext.model_fields:
                if getattr(child, field) != getattr(self, field):
                    raise ValueError("Platform receipt belongs to another source, app or run")
        return self


def file_hash(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Evidence must be a regular file")
    with path.open("rb") as handle:
        return "sha256:" + hashlib.file_digest(handle, "sha256").hexdigest()


def candidate_config(path: Path) -> tuple[str, dict]:
    with tarfile.open(path) as archive:
        members = archive.getmembers()
        names = [m.name for m in members]
        if len(names) != len(set(names)) or any(m.issym() or m.islnk() for m in members):
            raise ValueError("Candidate archive contains ambiguous entries")

        def read(name, limit):
            member = archive.getmember(name)
            if not member.isfile() or member.size > limit:
                raise ValueError("Candidate metadata exceeds supported bounds")
            return archive.extractfile(member).read(limit + 1)

        manifest = strict_json(read("manifest.json", 131072))
        if not isinstance(manifest, list) or len(manifest) != 1:
            raise ValueError("Candidate must contain exactly one image")
        config = read(manifest[0]["Config"], 2 * 1024 * 1024)
    return "sha256:" + hashlib.sha256(config).hexdigest(), strict_json(config)


def validate_image(metadata: dict, context: ReleaseContext, architecture: str):
    labels = metadata.get("Config", {}).get("Labels") or {}
    if (
        architecture not in {"amd64", "arm64"}
        or metadata.get("Architecture") != architecture
        or metadata.get("Os") != "linux"
        or labels.get("io.aegis.app") != context.app_id
        or labels.get("org.opencontainers.image.source")
        != "https://github.com/" + context.source_repository
        or labels.get("org.opencontainers.image.revision") != context.source_commit
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", metadata.get("Id", ""))
    ):
        raise ValueError("Loaded image does not match the expected app/source/platform")
    if hasattr(context, "service_name") and labels.get("io.aegis.service") != context.service_name:
        raise ValueError("Loaded image belongs to a different stack service")


def verify_candidate(
    candidate: Path, reports: Path, context: ReleaseContext, architecture: str
) -> dict:
    receipt = strict_json((candidate / "receipt.json").read_bytes())
    expected_keys = {
        "schema_version",
        "app_id",
        "source_repository",
        "source_commit",
        "platform",
        "workflow_run_id",
        "run_attempt",
        "platform_commit",
        "image_id",
        "image_config_digest",
        "candidate_archive_sha256",
        "scan_report_sha256",
        "sbom_sha256",
        "provenance",
    }
    if (
        set(receipt) != expected_keys
        or type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != 1
    ):
        raise ValueError("Unsupported candidate evidence")
    for field in ReleaseContext.model_fields.keys() - {"source_repository_id"}:
        if receipt[field] != getattr(context, field):
            raise ValueError("Candidate evidence belongs to another app/source/run/helper version")
    if receipt["platform"] != "linux/" + architecture:
        raise ValueError("Candidate architecture differs from the selected job")
    for filename, field in [
        (candidate / "image.tar", "candidate_archive_sha256"),
        (reports / "image.json", "scan_report_sha256"),
        (reports / "sbom.cdx.json", "sbom_sha256"),
    ]:
        if file_hash(filename) != "sha256:" + receipt[field]:
            raise ValueError("Candidate evidence does not match retained bytes")
    config_digest, config = candidate_config(candidate / "image.tar")
    if config_digest != receipt["image_config_digest"]:
        raise ValueError("Candidate configuration differs from its receipt")
    metadata = strict_json((candidate / "image-inspect.json").read_bytes())
    if (
        not isinstance(metadata, list)
        or len(metadata) != 1
        or metadata[0]["Id"] != receipt["image_id"]
    ):
        raise ValueError("Inspected candidate identity differs from the receipt")
    validate_image(metadata[0], context, architecture)
    archived = {
        "Id": receipt["image_id"],
        "Os": config.get("os"),
        "Architecture": config.get("architecture"),
        "Config": {"Labels": config.get("config", {}).get("Labels", {})},
    }
    validate_image(archived, context, architecture)
    scan = strict_json((reports / "image.json").read_bytes())
    if scan.get("Metadata", {}).get("ImageID") != config_digest:
        raise ValueError("Scan describes another image configuration")
    for report in [scan, strict_json((reports / "dependencies.json").read_bytes())]:
        results = report.get("Results", [])
        if not any(r.get("Class") == "lang-pkgs" and r.get("Packages") for r in results):
            raise ValueError("Scan has no application inventory")
        if any(
            v.get("Severity") == "CRITICAL" for r in results for v in r.get("Vulnerabilities", [])
        ):
            raise ValueError("CRITICAL findings block publication")
    return metadata[0]


def validate_index(index: dict, children: dict[str, PublishedPlatform]) -> dict[str, str]:
    if (
        index.get("schemaVersion") != 2
        or index.get("mediaType") != "application/vnd.oci.image.index.v1+json"
    ):
        raise ValueError("Release root must be an OCI index")
    manifests = index.get("manifests", [])
    if len(manifests) != 2 or set(children) != PLATFORMS:
        raise ValueError("Expected exactly the two tested platform manifests")
    result = {}
    for manifest in manifests:
        platform = manifest.get("platform", {})
        key = platform.get("os", "") + "/" + platform.get("architecture", "")
        if (
            key not in children
            or key in result
            or manifest.get("mediaType") != "application/vnd.oci.image.manifest.v1+json"
            or manifest.get("digest") != children[key].image.rsplit("@", 1)[1]
        ):
            raise ValueError("Index does not preserve each tested platform image")
        result[key] = manifest["digest"]
    return result


def verify_oci_bundle(path: Path, root_digest: str, children: dict[str, PublishedPlatform]):
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", root_digest):
        raise ValueError("Invalid root digest")
    if path.stat().st_size > 4 * 1024**3:
        raise ValueError("OCI bundle exceeds 4 GiB")
    with tarfile.open(path) as archive:
        entries = archive.getmembers()
        if len(entries) > 100000 or len({m.name for m in entries}) != len(entries):
            raise ValueError("OCI archive has ambiguous or excessive entries")
        files = {}
        for member in entries:
            if member.isdir() and member.name in {"blobs", "blobs/sha256"}:
                continue
            if not member.isfile() or not (
                member.name in {"index.json", "oci-layout"}
                or re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", member.name)
            ):
                raise ValueError("Unexpected OCI archive entry")
            files[member.name] = member

        def read_json(name):
            member = files[name]
            if member.size > 4 * 1024 * 1024:
                raise ValueError("OCI metadata exceeds budget")
            return strict_json(archive.extractfile(member).read())

        if read_json("oci-layout") != {"imageLayoutVersion": "1.0.0"}:
            raise ValueError("Unsupported OCI layout")
        wrapper = read_json("index.json")
        roots = wrapper.get("manifests", [])
        if (
            wrapper.get("schemaVersion") != 2
            or len(roots) != 1
            or roots[0].get("digest") != root_digest
            or roots[0].get("mediaType") != "application/vnd.oci.image.index.v1+json"
        ):
            raise ValueError("OCI layout does not point at the selected root")

        def verify_blob(descriptor):
            digest = descriptor.get("digest", "")
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                raise ValueError("Unsupported OCI descriptor digest")
            member = files["blobs/sha256/" + digest.split(":")[1]]
            if type(descriptor.get("size")) is not int or descriptor["size"] != member.size:
                raise ValueError("OCI descriptor size does not match content")
            if (
                "sha256:" + hashlib.file_digest(archive.extractfile(member), "sha256").hexdigest()
                != digest
            ):
                raise ValueError("OCI descriptor content is corrupt")
            return member.name

        root_name = verify_blob(roots[0])
        index = read_json(root_name)
        validate_index(index, children)
        for descriptor in index["manifests"]:
            manifest = read_json(verify_blob(descriptor))
            if (
                manifest.get("schemaVersion") != 2
                or manifest.get("mediaType") != "application/vnd.oci.image.manifest.v1+json"
            ):
                raise ValueError("Unsupported child manifest")
            key = descriptor["platform"]["os"] + "/" + descriptor["platform"]["architecture"]
            if manifest["config"]["digest"] != children[key].image_config_digest:
                raise ValueError("OCI child config differs from tested image")
            if manifest["config"].get("mediaType") != "application/vnd.oci.image.config.v1+json":
                raise ValueError("Unsupported image config media type")
            verify_blob(manifest["config"])
            for layer in manifest["layers"]:
                if not layer.get("mediaType", "").startswith("application/vnd.oci.image.layer."):
                    raise ValueError("Unsupported OCI layer")
                verify_blob(layer)


def release_evidence(
    context: ReleaseContext, children: dict[str, PublishedPlatform], root: str, bundle: Path
) -> ReleaseEvidence:
    for child in children.values():
        for field in ReleaseContext.model_fields:
            if getattr(child, field) != getattr(context, field):
                raise ValueError("Child context differs from publication context")
    verify_oci_bundle(bundle, root, children)
    evidence_type = ReleaseEvidence
    if hasattr(context, "service_name"):
        from aegis_platform.stack_release import ComponentEvidence

        evidence_type = ComponentEvidence
    return evidence_type.model_validate(
        {
            **context.model_dump(),
            "schema_version": 3,
            "release_tag": context.tag,
            "verified_at": datetime.now(UTC).isoformat(),
            "image": context.image_name + "@" + root,
            "platforms": {k: v.model_dump() for k, v in children.items()},
            "bundle_sha256": file_hash(bundle),
            "provenance": (
                "Unsigned workflow evidence; admission must verify GitHub source/run identity"
            ),
        }
    )
