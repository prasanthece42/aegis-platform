"""Resolve reusable helpers from GitHub run metadata, never a caller-supplied helper ref."""

import hashlib
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit
from urllib.request import Request, urlopen

PLATFORM_REPOSITORY = "prasanthece42/aegis-platform"
WORKFLOW = "python-web-ci.yml"


def resolve_workflow_commit(run: dict, repository: str, workflow: str) -> str:
    prefix = repository + "/.github/workflows/" + workflow + "@"
    matches = [
        item for item in run.get("referenced_workflows", []) if item["path"].startswith(prefix)
    ]
    if not matches:
        raise ValueError("Run metadata does not identify the expected reusable workflow")
    commits = set()
    for item in matches:
        sha = item["sha"]
        if not re.fullmatch(r"[0-9a-f]{40}", sha) or item["path"] != prefix + sha:
            raise ValueError("Reusable workflows and their helpers must be pinned to a full commit")
        commits.add(sha)
    if len(commits) != 1:
        raise ValueError("Run metadata contains conflicting platform workflow versions")
    return commits.pop()


def validate_inputs(app_id: str, platforms: str, port: str, health_path: str) -> list[str]:
    if not re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", app_id) or not 3 <= len(app_id) <= 40:
        raise ValueError("Unsupported application ID")
    archs = json.loads(platforms)
    if (
        not isinstance(archs, list)
        or not 1 <= len(archs) <= 2
        or any(a not in {"amd64", "arm64"} for a in archs)
        or len(archs) != len(set(archs))
    ):
        raise ValueError("Select one or both supported CPU architectures without duplicates")
    if not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError("Invalid container port")
    decoded = unquote(health_path)
    parsed = urlsplit(decoded)
    if (
        not decoded.startswith("/")
        or decoded.startswith("//")
        or len(health_path) > 200
        or parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or "?" in decoded
        or "#" in decoded
        or "\\" in decoded
        or "%" in decoded
        or any(ord(c) < 33 or ord(c) == 127 for c in decoded)
        or any(part in {".", ".."} for part in decoded.split("/"))
    ):
        raise ValueError("Unsupported health path for the Python web CI profile")
    return archs


def main():
    if os.environ["GITHUB_SERVER_URL"] != "https://github.com":
        raise ValueError("This workflow supports github.com only")
    caller = os.environ["GITHUB_REPOSITORY"]
    run_id = os.environ["GITHUB_RUN_ID"]
    attempt = os.environ["GITHUB_RUN_ATTEMPT"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", caller) or not run_id.isdecimal():
        raise ValueError("Invalid GitHub workflow context")
    archs = validate_inputs(
        os.environ["AEGIS_APP_ID"],
        os.environ["AEGIS_PLATFORMS"],
        os.environ["AEGIS_PORT"],
        os.environ["AEGIS_HEALTH_PATH"],
    )
    request = Request(
        f"https://api.github.com/repos/{caller}/actions/runs/{run_id}",
        headers={
            "Authorization": "Bearer " + os.environ["GH_TOKEN"],
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
        },
    )
    with urlopen(request, timeout=20) as response:
        raw = response.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("Run metadata exceeds budget")
    run = json.loads(raw)
    if (
        str(run["id"]) != run_id
        or str(run["run_attempt"]) != attempt
        or str(run["repository"]["id"]) != os.environ["GITHUB_REPOSITORY_ID"]
    ):
        raise ValueError("Run metadata does not match this caller and attempt")
    sha = resolve_workflow_commit(run, PLATFORM_REPOSITORY, WORKFLOW)
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
    if os.environ["AEGIS_EXPORT_CANDIDATE"] == "true" and (
        os.environ["GITHUB_EVENT_NAME"] not in {"push", "workflow_dispatch"}
        or os.environ["GITHUB_REF"] != "refs/heads/" + event["repository"]["default_branch"]
    ):
        raise ValueError("Candidate export requires a trusted default-branch event")
    # Testable evidence linking this bootstrapped source to the resolved immutable workflow.
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        output.write(f"platform_repository={PLATFORM_REPOSITORY}\nplatform_commit={sha}\n")
        output.write("platforms=" + json.dumps(archs, separators=(",", ":")) + "\n")
        output.write(
            "bootstrap_sha256=" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest() + "\n"
        )


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, TypeError) as exc:
        print(f"Platform bootstrap refused: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
