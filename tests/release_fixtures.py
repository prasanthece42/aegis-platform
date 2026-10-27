import hashlib
import io
import json
import tarfile

from aegis_platform.release import PublishedPlatform, ReleaseContext, file_hash, release_evidence

INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
CONFIG = "application/vnd.oci.image.config.v1+json"
LAYER = "application/vnd.oci.image.layer.v1.tar"


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


def sha(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def write_tar(path, files):
    with tarfile.open(path, "w") as archive:
        for name, raw in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))


def context():
    return ReleaseContext.model_validate(
        {
            "app_id": "orders-api",
            "source_repository": "example/orders-api",
            "source_repository_id": "101",
            "source_commit": "c" * 40,
            "workflow_run_id": "123",
            "run_attempt": "1",
            "platform_commit": "a" * 40,
        }
    )


def release_fixture(tmp_path):
    ctx, blobs, children, descriptors = context(), {}, {}, []

    def blob(raw, media_type):
        digest = sha(raw)
        blobs["blobs/sha256/" + digest.split(":")[1]] = raw
        return {"mediaType": media_type, "digest": digest, "size": len(raw)}

    for arch in ["amd64", "arm64"]:
        config = blob(encoded({"os": "linux", "architecture": arch}), CONFIG)
        layer = blob(("fixture-layer-" + arch).encode(), LAYER)
        child = blob(
            encoded(
                {"schemaVersion": 2, "mediaType": MANIFEST, "config": config, "layers": [layer]}
            ),
            MANIFEST,
        )
        descriptors.append({**child, "platform": {"os": "linux", "architecture": arch}})
        children["linux/" + arch] = PublishedPlatform.model_validate(
            {
                **ctx.model_dump(),
                "platform": "linux/" + arch,
                "image": ctx.image_name + "@" + child["digest"],
                "image_config_digest": config["digest"],
                "candidate_archive_sha256": "sha256:" + "d" * 64,
                "digest_pull_smoke_test": "passed",
                "evidence_sha256": {
                    name: "sha256:" + "e" * 64
                    for name in ["dependencies.json", "image.json", "sbom.cdx.json"]
                },
            }
        )
    index = {"schemaVersion": 2, "mediaType": INDEX, "manifests": descriptors}
    root = blob(encoded(index), INDEX)
    files = {
        **blobs,
        "oci-layout": encoded({"imageLayoutVersion": "1.0.0"}),
        "index.json": encoded({"schemaVersion": 2, "manifests": [root]}),
    }
    bundle = tmp_path / "image.oci.tar"
    write_tar(bundle, files)
    receipt = release_evidence(ctx, children, root["digest"], bundle)
    receipt_path = tmp_path / "release.json"
    receipt_path.write_text(json.dumps(receipt.model_dump(), indent=2) + "\n")
    return {
        "context": ctx,
        "children": children,
        "index": index,
        "root": root["digest"],
        "files": files,
        "bundle": bundle,
        "evidence": receipt,
        "receipt": receipt_path,
    }


def candidate_fixture(tmp_path):
    ctx = context()
    candidate, reports = tmp_path / "candidate", tmp_path / "reports"
    candidate.mkdir()
    reports.mkdir()
    labels = {
        "io.aegis.app": ctx.app_id,
        "org.opencontainers.image.source": "https://github.com/" + ctx.source_repository,
        "org.opencontainers.image.revision": ctx.source_commit,
    }
    config = encoded({"os": "linux", "architecture": "arm64", "config": {"Labels": labels}})
    config_digest = sha(config)
    write_tar(
        candidate / "image.tar",
        {
            "manifest.json": encoded([{"Config": "config.json", "Layers": []}]),
            "config.json": config,
        },
    )
    metadata = {
        "Id": config_digest,
        "Os": "linux",
        "Architecture": "arm64",
        "Config": {"Labels": labels},
    }
    (candidate / "image-inspect.json").write_bytes(encoded([metadata]))
    report = {
        "Metadata": {"ImageID": config_digest},
        "Results": [{"Class": "lang-pkgs", "Packages": [{"Name": "fastapi"}]}],
    }
    for name in ["image.json", "dependencies.json"]:
        (reports / name).write_bytes(encoded(report))
    (reports / "sbom.cdx.json").write_bytes(encoded({"bomFormat": "CycloneDX"}))
    receipt = {
        **ctx.model_dump(exclude={"source_repository_id"}),
        "schema_version": 1,
        "platform": "linux/arm64",
        "image_id": config_digest,
        "image_config_digest": config_digest,
        "candidate_archive_sha256": file_hash(candidate / "image.tar").split(":")[1],
        "scan_report_sha256": file_hash(reports / "image.json").split(":")[1],
        "sbom_sha256": file_hash(reports / "sbom.cdx.json").split(":")[1],
        "provenance": (
            "Unsigned CI candidate evidence; not a published release or deployment approval"
        ),
    }
    (candidate / "receipt.json").write_bytes(encoded(receipt))
    return ctx, candidate, reports, receipt
