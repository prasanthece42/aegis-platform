"""Reject edits/deletion of chart version directories already present at the PR base."""

import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def assert_immutable(before: dict[str, bytes], after: dict[str, bytes]):
    versions = {
        (path.split("/")[1], path.split("/")[2])
        for path in before
        if path.startswith("charts/") and len(path.split("/")) >= 4
    }
    for family, version in versions:
        prefix = f"charts/{family}/{version}/"
        old = {p: value for p, value in before.items() if p.startswith(prefix)}
        new = {p: value for p, value in after.items() if p.startswith(prefix)}
        if old != new:
            raise ValueError(f"Existing chart version {version} changed; add a new version instead")


def main():
    base = os.getenv("CHART_BASE_SHA", "")
    if not base:
        parent = subprocess.run(
            ["git", "rev-parse", "HEAD^"], cwd=ROOT, capture_output=True, text=True, check=False
        )
        base = parent.stdout.strip() if parent.returncode == 0 else "0" * 40
    if not re.fullmatch(r"[0-9a-f]{40}", base):
        raise ValueError("Chart baseline must be a full commit SHA")
    before = {}
    if base != "0" * 40:
        paths = subprocess.check_output(
            ["git", "ls-tree", "-r", "--name-only", base, "--", "charts"],
            cwd=ROOT,
            text=True,
        ).splitlines()
        for path in paths:
            before[path] = subprocess.check_output(["git", "show", f"{base}:{path}"], cwd=ROOT)
    after = {
        str(p.relative_to(ROOT)): p.read_bytes()
        for p in (ROOT / "charts").rglob("*")
        if p.is_file()
    }
    assert_immutable(before, after)
    print("PASS: existing chart versions preserved; new version directories may be added")


if __name__ == "__main__":
    main()
