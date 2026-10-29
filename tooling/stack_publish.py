"""Publish only validated stack candidates, then retain complete per-service OCI graphs."""

import argparse
import os
import re
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aegis_platform.canonical import canonical, digest, strict_json  # noqa: E402
from aegis_platform.publication import GitHubReleaseAPI, publish_release  # noqa: E402
from aegis_platform.release import (  # noqa: E402
    PublishedPlatform,
    file_hash,
    release_evidence,
    validate_image,
    validate_index,
)
from aegis_platform.stack import StackDefinition  # noqa: E402
from aegis_platform.stack_plan import DEPENDENCY_IMAGES  # noqa: E402
from aegis_platform.stack_release import (  # noqa: E402
    ComponentPlatform,
    StackReleaseEvidence,
    verify_stack_bundle,
)
from tooling.stack_ci import (  # noqa: E402
    context,
    inspect,
    pulled_config,
    run,
    service_context,
    smoke,
    verify_candidate,
)


def publish_platform(directory, destination, ctx, arch):
    candidate, stack = verify_candidate(directory, ctx, arch)
    published, references = {}, {}
    for name, service in candidate["services"].items():
        component = service_context(ctx, stack, name)
        run(["docker", "load", "--input", directory / name / "image.tar"])
        actual = inspect(service["image_id"])
        validate_image(actual, component, arch)
        tag = (
            f"{component.image_name}:sha-{ctx.source_commit}-"
            f"{ctx.workflow_run_id}-{ctx.run_attempt}-{arch}"
        )
        run(["docker", "tag", service["image_id"], tag])
        # Normalize transport media types to OCI while preserving config/layer content.
        run(["skopeo", "copy", "--format", "oci", "docker-daemon:" + tag, "docker://" + tag])
        checksum = run(
            ["skopeo", "inspect", "--format", "{{.Digest}}", "docker://" + tag], capture=True
        )
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", checksum):
            raise ValueError("Registry did not return a valid pushed digest")
        reference = component.image_name + "@" + checksum
        run(["docker", "pull", reference])
        pulled = inspect(reference)
        validate_image(pulled, component, arch)
        if pulled_config(reference) != service[
            "image_config_digest"
        ] or reference not in pulled.get("RepoDigests", []):
            raise ValueError("Digest-pulled service differs from the tested candidate")
        references[name] = reference
        model = PublishedPlatform if name == stack.primary_service else ComponentPlatform
        published[name] = model(
            **component.model_dump(),
            platform="linux/" + arch,
            image=reference,
            image_config_digest=service["image_config_digest"],
            candidate_archive_sha256=service["files"]["image.tar"],
            digest_pull_smoke_test="passed",
            evidence_sha256={
                "dependencies.json": service["files"]["image.json"],
                "image.json": service["files"]["image.json"],
                "sbom.cdx.json": service["files"]["sbom.cdx.json"],
            },
        )
    # Checks the immutable pulled services together, without executing any source-owned scripts.
    smoke(stack, references)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "platform.json").write_bytes(
        canonical(
            {
                "context": ctx.model_dump(),
                "architecture": arch,
                "stack": stack.model_dump(),
                "services": {k: v.model_dump() for k, v in published.items()},
            }
        )
    )


def assemble(platforms, output, ctx, verified_at):
    rows = [strict_json(p.read_bytes()) for p in sorted(platforms.glob("*/platform.json"))]
    if len(rows) != 2 or {r["architecture"] for r in rows} != {"amd64", "arm64"}:
        raise ValueError("Both independently tested native-platform receipts are required")
    stack = StackDefinition.model_validate(rows[0]["stack"])
    for row in rows:
        if (
            row["context"] != ctx.model_dump()
            or row["stack"] != stack.model_dump()
            or set(row["services"]) != set(stack.services)
        ):
            raise ValueError("Platform receipts differ in source, run, topology or service set")
    output.mkdir(parents=True, exist_ok=True)
    receipts, bundles = {}, {}
    for name in stack.services:
        component = service_context(ctx, stack, name)
        model = PublishedPlatform if name == stack.primary_service else ComponentPlatform
        children = {
            "linux/" + row["architecture"]: model.model_validate(row["services"][name])
            for row in rows
        }
        tag = (
            f"{component.image_name}:sha-{ctx.source_commit}-"
            f"{ctx.workflow_run_id}-{ctx.run_attempt}"
        )
        run(
            [
                "docker",
                "buildx",
                "imagetools",
                "create",
                "--tag",
                tag,
                *[children[p].image for p in sorted(children)],
            ]
        )
        root = run(
            ["skopeo", "inspect", "--format", "{{.Digest}}", "docker://" + tag], capture=True
        )
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", root):
            raise ValueError("Registry index digest is invalid")
        index = strict_json(
            run(["docker", "buildx", "imagetools", "inspect", tag, "--raw"], capture=True).encode()
        )
        validate_index(index, children)
        bundle = output / (name + ".oci.tar")
        run(
            [
                "skopeo",
                "copy",
                "--all",
                "--preserve-digests",
                "docker://" + component.image_name + "@" + root,
                "oci-archive:" + str(bundle) + ":" + ctx.tag,
            ]
        )
        evidence = release_evidence(component, children, root, bundle)
        evidence.verified_at = verified_at
        receipts[name], bundles[name] = evidence, bundle
    combined = output / "image.oci.tar"
    with tarfile.open(combined, "w") as archive:
        for name, path in sorted(bundles.items()):
            archive.add(path, arcname=f"services/{name}.oci.tar", recursive=False)
    primary = receipts.pop(stack.primary_service)
    evidence = StackReleaseEvidence.model_validate(
        {
            **primary.model_dump(),
            "schema_version": 4,
            "stack": stack.model_dump(),
            "stack_sha256": digest(stack.model_dump()),
            "primary_bundle_sha256": primary.bundle_sha256,
            "bundle_sha256": file_hash(combined),
            "components": {k: v.model_dump() for k, v in receipts.items()},
            "dependency_images": DEPENDENCY_IMAGES,
            "integration_tests": "passed",
        }
    )
    verify_stack_bundle(combined, evidence)
    receipt = output / "release.json"
    receipt.write_bytes(canonical(evidence.model_dump()))
    publish_release(
        GitHubReleaseAPI(ctx.source_repository, os.environ["GH_TOKEN"]), evidence, receipt, combined
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["platform", "assemble"])
    args = parser.parse_args()
    ctx = context()
    if args.command == "platform":
        arch = os.environ["ARCH"]
        if arch not in {"amd64", "arm64"}:
            raise ValueError("Unsupported platform")
        publish_platform(Path("candidate"), Path("published"), ctx, arch)
    else:
        assemble(Path("platform-evidence"), Path("reports"), ctx, os.environ["RUN_STARTED_AT"])
