"""Resume a source-scoped draft release, verify uploaded bytes, then publish once."""

import json
import os
import subprocess
import tempfile
from pathlib import Path

from aegis_platform.release import ReleaseEvidence, file_hash, validate_repository


class GitHubReleaseAPI:
    def __init__(self, repository: str, token: str):
        self.repository = validate_repository(repository)
        if not token:
            raise ValueError("Publication requires an explicit workflow-scoped token")
        self._environment = {**os.environ, "GH_TOKEN": token, "GH_HOST": "github.com"}

    def api(self, suffix: str, method="GET", payload=None, missing=False):
        command = [
            "gh",
            "api",
            f"repos/{self.repository}/{suffix}",
            "--method",
            method,
            "-H",
            "X-GitHub-Api-Version: 2026-03-10",
        ]
        if payload is not None:
            command += ["--input", "-"]
        result = subprocess.run(
            command,
            input=json.dumps(payload) if payload is not None else None,
            capture_output=True,
            text=True,
            check=False,
            env=self._environment,
        )
        if result.returncode:
            if missing and "HTTP 404" in result.stderr:
                return None
            raise ValueError("GitHub release operation failed; retry the same run/tag safely")
        return json.loads(result.stdout) if result.stdout.strip() else None

    def assets(self, release_id: int) -> list[dict]:
        result = []
        for page in range(1, 11):
            batch = self.api(f"releases/{release_id}/assets?per_page=100&page={page}")
            result.extend(batch)
            if len(batch) < 100:
                return result
        raise ValueError("Release asset listing exceeds the complete-discovery budget")

    def upload(self, tag: str, path: Path):
        result = subprocess.run(
            ["gh", "release", "upload", tag, str(path), "--repo", self.repository],
            capture_output=True,
            check=False,
            env=self._environment,
        )
        if result.returncode:
            raise ValueError(
                "Release asset upload interrupted; resume the same draft without overwriting"
            )

    def asset_hash(self, asset_id: int) -> str:
        import hashlib

        with tempfile.TemporaryFile() as stream:
            result = subprocess.run(
                [
                    "gh",
                    "api",
                    f"repos/{self.repository}/releases/assets/{asset_id}",
                    "-H",
                    "Accept: application/octet-stream",
                ],
                stdout=stream,
                stderr=subprocess.PIPE,
                check=False,
                env=self._environment,
            )
            if result.returncode:
                raise ValueError("Uploaded release asset could not be read back")
            stream.seek(0)
            return "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()


def publish_release(
    api: GitHubReleaseAPI, evidence: ReleaseEvidence, receipt: Path, bundle: Path
) -> dict:
    if api.repository.lower() != evidence.source_repository.lower():
        raise ValueError("Publication repository differs from verified source")
    if file_hash(bundle) != evidence.bundle_sha256:
        raise ValueError("Local bundle differs from the verified release")
    if json.loads(receipt.read_bytes()) != evidence.model_dump():
        raise ValueError("Local release receipt differs from verified intent")
    tag = evidence.release_tag
    reference = api.api(f"git/ref/tags/{tag}", missing=True)
    if reference is None:
        api.api("git/refs", "POST", {"ref": "refs/tags/" + tag, "sha": evidence.source_commit})
        reference = api.api(f"git/ref/tags/{tag}")
    if (
        reference["object"].get("type") != "commit"
        or reference["object"].get("sha") != evidence.source_commit
    ):
        raise ValueError("Release tag does not point directly at the selected source commit")
    release = api.api(f"releases/tags/{tag}", missing=True)
    if release is None:
        release = api.api(
            "releases",
            "POST",
            {
                "tag_name": tag,
                "target_commitish": evidence.source_commit,
                "name": f"Validated {evidence.app_id} {evidence.source_commit}",
                "body": (
                    f"App: {evidence.app_id}\nImage: {evidence.image}\n"
                    "Unsigned workflow evidence; not deployment approval."
                ),
                "draft": True,
                "prerelease": False,
                "make_latest": "false",
            },
        )
    if (
        release.get("tag_name") != tag
        or release.get("prerelease")
        or release.get("author", {}).get("login") != "github-actions[bot]"
        or release.get("author", {}).get("type") != "Bot"
    ):
        raise ValueError("Release issuer/tag does not match trusted workflow publication")
    expected = {"release.json": receipt, "image.oci.tar": bundle}
    assets = api.assets(release["id"])
    names = [asset["name"] for asset in assets]
    if len(names) != len(set(names)) or not set(names) <= expected.keys():
        raise ValueError("Release has duplicate or unexpected assets")
    for name, path in expected.items():
        asset = next((a for a in assets if a["name"] == name), None)
        if asset is None:
            if not release["draft"]:
                raise ValueError("Published release is incomplete; never overwrite it")
            api.upload(tag, path)
    assets = api.assets(release["id"])
    if len(assets) != 2 or {a["name"] for a in assets} != set(expected):
        raise ValueError("Release uploads are incomplete")
    for asset in assets:
        path = expected[asset["name"]]
        if (
            asset.get("state") != "uploaded"
            or asset.get("size") != path.stat().st_size
            or api.asset_hash(asset["id"]) != file_hash(path)
        ):
            raise ValueError(
                "Uploaded asset differs from verified local bytes; refusing publication"
            )
    if release["draft"]:
        release = api.api(
            f"releases/{release['id']}", "PATCH", {"draft": False, "make_latest": "false"}
        )
    if release.get("draft"):
        raise ValueError("Release publication is not confirmed")
    return release
