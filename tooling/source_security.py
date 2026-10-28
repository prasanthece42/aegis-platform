"""Scan a bounded tracked snapshot; publish finding locations, never matched source."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def tracked_snapshot(source: Path, destination: Path):
    paths = subprocess.run(
        ["git", "-C", str(source), "ls-files", "-z"],
        check=True,
        capture_output=True,
    ).stdout.split(b"\0")
    total = 0
    count = 0
    for raw in filter(None, paths):
        relative = Path(os.fsdecode(raw))
        target = source / relative
        if relative.is_absolute() or ".." in relative.parts or target.is_symlink():
            raise ValueError("Source snapshot contains an unsupported path or symlink")
        if not target.is_file() or not target.resolve().is_relative_to(source.resolve()):
            raise ValueError("Tracked source file is missing or outside the checkout")
        size = target.stat().st_size
        total += size
        count += 1
        if size > 20 * 1024 * 1024 or total > 100 * 1024 * 1024 or count > 10000:
            raise ValueError("Source security snapshot exceeds the supported profile budget")
        output = destination / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(target, output)
    if count == 0 or not any(destination.rglob("*.py")):
        raise ValueError("Python source security requires a nonempty tracked Python snapshot")


def evaluate(bandit: dict, secrets: dict):
    if bandit.get("errors") or not bandit.get("metrics", {}).get("_totals", {}).get("loc"):
        raise ValueError("SAST did not successfully inspect Python source")
    if (
        not isinstance(bandit.get("results"), list)
        or secrets.get("SchemaVersion") != 2
        or secrets.get("ArtifactType") != "filesystem"
        or secrets.get("Trivy", {}).get("Version") != "0.76.1"
        or not isinstance(secrets.get("Results", []), list)
    ):
        raise ValueError("Scanner report is incomplete")
    findings = []
    for item in bandit["results"]:
        findings.append(
            {
                "scanner": "bandit",
                "rule": item["test_id"],
                "file": item["filename"],
                "line": item["line_number"],
                "severity": item["issue_severity"],
            }
        )
    # Trivy omits Results entirely for a clean filesystem without package inventory.
    for result in secrets.get("Results", []):
        for item in result.get("Secrets", []):
            findings.append(
                {
                    "scanner": "trivy-secret",
                    "rule": item["RuleID"],
                    "file": result["Target"],
                    "line": item["StartLine"],
                    "severity": item["Severity"],
                }
            )
    return {"schema_version": 1, "status": "failed" if findings else "passed", "findings": findings}


def scan(source: Path, report: Path):
    report.parent.mkdir(parents=True, exist_ok=True)
    # A failed/missing scanner must never leave an older success report behind.
    report.write_text(
        json.dumps(
            {"schema_version": 1, "status": "failed", "error": "Source security did not complete"}
        )
        + "\n"
    )
    with tempfile.TemporaryDirectory(prefix="aegis-source-security-") as folder:
        root = Path(folder)
        snapshot = root / "source"
        snapshot.mkdir()
        tracked_snapshot(source, snapshot)
        config = root / "bandit.yaml"
        config.write_text("skips: []\n")
        empty = root / "empty"
        empty.write_text("")
        trivy_config = root / "trivy.yaml"
        trivy_config.write_text("{}\n")
        python = os.environ.get("AEGIS_BANDIT_PYTHON", sys.executable)
        commands = [
            [
                python,
                "-m",
                "bandit",
                "-r",
                str(snapshot),
                "--ignore-nosec",
                "--ini",
                str(empty),
                "-c",
                str(config),
                "--severity-level",
                "high",
                "--confidence-level",
                "medium",
                "-f",
                "json",
                "-o",
                str(root / "sast.json"),
            ],
            [
                "trivy",
                "fs",
                "--config",
                str(trivy_config),
                "--secret-config",
                str(trivy_config),
                "--ignorefile",
                str(empty),
                "--scanners",
                "secret",
                "--format",
                "json",
                "--timeout",
                "5m",
                "--output",
                str(root / "secrets.json"),
                str(snapshot),
            ],
        ]
        for command in commands:
            result = subprocess.run(command, cwd=root, capture_output=True, timeout=360)
            # Bandit returns 1 for findings. Trivy findings are evaluated from JSON.
            allowed = {0, 1} if "bandit" in command else {0}
            if result.returncode not in allowed:
                raise ValueError("Source security scanner failed; raw output withheld")
        result = evaluate(
            json.loads((root / "sast.json").read_bytes()),
            json.loads((root / "secrets.json").read_bytes()),
        )
        for finding in result["findings"]:
            path = Path(finding["file"])
            if path.is_absolute():
                finding["file"] = str(path.relative_to(snapshot))
        report.write_text(json.dumps(result, indent=2) + "\n")
        if result["status"] != "passed":
            raise ValueError("Source security findings block this candidate; see redacted report")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    try:
        scan(args.source.resolve(), args.report.resolve())
    except (ValueError, OSError, subprocess.SubprocessError, KeyError) as exc:
        print(type(exc).__name__ + ": source security failed; see redacted report", file=sys.stderr)
        raise SystemExit(1) from None
