"""Print a minimal source caller for review; never edit an application's workflow in place."""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis_platform.workflow import PLATFORM_REPOSITORY, validate_inputs  # noqa: E402


def make_caller(app_id: str, commit: str, branch: str = "main", release: bool = False) -> str:
    validate_inputs(app_id, '["amd64","arm64"]', "8000", "/health")
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or commit == "0" * 40:
        raise ValueError("Use the actual published platform commit SHA")
    if (
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", branch)
        or any(part in {"", ".", ".."} or part.endswith(".lock") for part in branch.split("/"))
        or ".." in branch
        or branch.endswith(".")
    ):
        raise ValueError("Unsupported default branch name")
    caller = f"""name: Aegis CI

on:
  pull_request:
  push:
    branches: [{json.dumps(branch)}]
  workflow_dispatch:

permissions:
  contents: read
  actions: read

concurrency:
  group: aegis-ci-${{{{ github.ref }}}}
  cancel-in-progress: false

jobs:
  validate:
    uses: {PLATFORM_REPOSITORY}/.github/workflows/python-web-ci.yml@{commit}
    with:
      app-id: {app_id}
      platforms: '["amd64","arm64"]'
"""
    if release:
        caller = caller.replace("name: Aegis CI", "name: Aegis release")
        caller = caller.replace("  pull_request:\n", "")
        caller = caller.replace("  contents: read", "  contents: write\n  packages: write")
        caller = caller.replace("group: aegis-ci-", "group: aegis-source-release-")
        caller = caller.replace("python-web-ci.yml@", "python-web-release.yml@")
        caller = caller.replace('      platforms: \'["amd64","arm64"]\'\n', "")
    return caller


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", required=True)
    parser.add_argument("--platform-commit", required=True)
    parser.add_argument("--default-branch", default="main")
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()
    print(make_caller(args.app, args.platform_commit, args.default_branch, args.release), end="")
