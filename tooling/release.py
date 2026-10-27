"""Trusted release entry point. Each command validates context before using downloaded evidence."""

import argparse
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis_platform.canonical import strict_json  # noqa: E402
from aegis_platform.publication import GitHubReleaseAPI, publish_release  # noqa: E402
from aegis_platform.release import (  # noqa: E402
    PublishedPlatform,
    ReleaseContext,
    ReleaseEvidence,
    file_hash,
    release_evidence,
    validate_image,
    verify_candidate,
)


def context() -> ReleaseContext:
    return ReleaseContext.model_validate(
        {
            "app_id": os.environ["APP_ID"],
            "source_repository": os.environ["SOURCE_REPOSITORY"],
            "source_repository_id": os.environ["GITHUB_REPOSITORY_ID"],
            "source_commit": os.environ["SOURCE_SHA"],
            "workflow_run_id": os.environ["GITHUB_RUN_ID"],
            "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
            "platform_commit": os.environ["PLATFORM_COMMIT"],
        }
    )


def children(ctx: ReleaseContext) -> dict[str, PublishedPlatform]:
    result = {}
    for path in sorted(Path("platform-evidence").glob("*/published-platform.json")):
        child = PublishedPlatform.model_validate(strict_json(path.read_bytes()))
        if child.platform in result:
            raise ValueError("Duplicate published platform receipt")
        for key in ReleaseContext.model_fields:
            if getattr(child, key) != getattr(ctx, key):
                raise ValueError("Published platform belongs to another app/source/run")
        result[child.platform] = child
    if set(result) != {"linux/amd64", "linux/arm64"}:
        raise ValueError("Missing tested platform")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=[
            "verify-candidate",
            "verify-loaded",
            "write-platform",
            "index-inputs",
            "assemble",
            "publish",
        ],
    )
    args = parser.parse_args()
    ctx = context()
    reports = Path("reports")
    reports.mkdir(exist_ok=True)
    if args.command in {"verify-candidate", "verify-loaded", "write-platform"}:
        arch = os.environ["ARCH"]
        expected = verify_candidate(Path("candidate"), reports, ctx, arch)
        if args.command == "verify-candidate":
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected["Id"]):
                raise ValueError("Invalid candidate image ID")
            with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
                output.write("image_id=" + expected["Id"] + "\n")
        else:
            filename = (
                "loaded-image.json" if args.command == "verify-loaded" else "pulled-image.json"
            )
            actual = strict_json((reports / filename).read_bytes())
            if not isinstance(actual, list) or len(actual) != 1:
                raise ValueError("Expected one inspected image")
            validate_image(actual[0], ctx, arch)
            if actual[0]["Id"] != expected["Id"]:
                raise ValueError("Loaded/pulled image differs from tested candidate")
            if args.command == "write-platform":
                root = os.environ["PUBLISHED_DIGEST"]
                reference = ctx.image_name + "@" + root
                if not re.fullmatch(r"sha256:[0-9a-f]{64}", root) or reference not in actual[0].get(
                    "RepoDigests", []
                ):
                    raise ValueError("Digest-pulled image is not the selected registry image")
                receipt = strict_json(Path("candidate/receipt.json").read_bytes())
                evidence = PublishedPlatform.model_validate(
                    {
                        **ctx.model_dump(),
                        "platform": "linux/" + arch,
                        "image": reference,
                        "image_config_digest": receipt["image_config_digest"],
                        "candidate_archive_sha256": "sha256:" + receipt["candidate_archive_sha256"],
                        "digest_pull_smoke_test": "passed",
                        "evidence_sha256": {
                            name: file_hash(reports / name)
                            for name in ["dependencies.json", "image.json", "sbom.cdx.json"]
                        },
                    }
                )
                (reports / "published-platform.json").write_text(
                    json.dumps(evidence.model_dump(), indent=2) + "\n"
                )
    elif args.command == "index-inputs":
        tested = children(ctx)
        with Path(os.environ["GITHUB_ENV"]).open("a") as output:
            output.write(
                f"IMAGE_TAG={ctx.image_name}:sha-{ctx.source_commit}-{ctx.workflow_run_id}-{ctx.run_attempt}\n"
            )
            output.write("AMD64_REFERENCE=" + tested["linux/amd64"].image + "\n")
            output.write("ARM64_REFERENCE=" + tested["linux/arm64"].image + "\n")
    elif args.command == "assemble":
        root = os.environ["PUBLISHED_DIGEST"]
        receipt = release_evidence(ctx, children(ctx), root, reports / "image.oci.tar")
        previous = reports / "release.json"
        if previous.exists():
            old = ReleaseEvidence.model_validate(strict_json(previous.read_bytes()))
            if old.model_dump(exclude={"verified_at"}) != receipt.model_dump(
                exclude={"verified_at"}
            ):
                raise ValueError("Existing assembled receipt differs from this verified release")
            receipt = old
        previous.write_text(json.dumps(receipt.model_dump(), indent=2) + "\n")
    else:
        evidence = ReleaseEvidence.model_validate(
            strict_json((reports / "release.json").read_bytes())
        )
        for key in ReleaseContext.model_fields:
            if getattr(evidence, key) != getattr(ctx, key):
                raise ValueError("Publication context does not match the assembled release")
        # Recheck the OCI graph immediately before any external publication operation.
        verified = release_evidence(
            ctx, evidence.platforms, evidence.image.rsplit("@", 1)[1], reports / "image.oci.tar"
        )
        if verified.model_dump(exclude={"verified_at"}) != evidence.model_dump(
            exclude={"verified_at"}
        ):
            raise ValueError("Publication evidence changed after assembly")
        publish_release(
            GitHubReleaseAPI(ctx.source_repository, os.environ.get("GH_TOKEN", "")),
            evidence,
            reports / "release.json",
            reports / "image.oci.tar",
        )
    print("PASS:", args.command)


if __name__ == "__main__":
    main()
