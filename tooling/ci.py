"""Generic Python web CI from the pinned platform checkout, not app-owned scripts."""

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis_platform.contracts import Runtime  # noqa: E402


def run(arguments: list[str], *, cwd: Path | None = None, capture=False):
    return subprocess.run(
        arguments, cwd=cwd, check=True, text=True, stdout=subprocess.PIPE if capture else None
    ).stdout


def inventory_policy(report: dict):
    results = report.get("Results", [])
    if not any(r.get("Class") == "lang-pkgs" and r.get("Packages") for r in results):
        raise ValueError("Scanner detected no application dependency inventory")
    if any(v.get("Severity") == "CRITICAL" for r in results for v in r.get("Vulnerabilities", [])):
        raise ValueError("CRITICAL vulnerabilities block the candidate, including unfixed findings")


def source_environment(source: Path, venv: Path):
    if (
        not (source / "requirements.txt").is_file()
        or not (source / "requirements-prod.txt").is_file()
    ):
        raise ValueError(
            "Python web profile requires hash-locked development and production requirements"
        )
    run([sys.executable, "-m", "venv", str(venv)])
    python = str(venv / "bin/python")
    run([python, "-m", "pip", "install", "--require-hashes", "-r", "requirements.txt"], cwd=source)
    return python


def checks(source: Path, venv: Path, phase="all"):
    python = source_environment(source, venv)
    if phase in {"all", "quality"}:
        run([python, "-m", "ruff", "check", "."], cwd=source)
        run([python, "-m", "ruff", "format", "--check", "."], cwd=source)
    if phase in {"all", "tests"}:
        run([python, "-m", "pytest"], cwd=source)


def smoke(image: str, runtime: Runtime):
    container = run(
        [
            "docker",
            "run",
            "-d",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--publish",
            f"127.0.0.1::{runtime.container_port}",
            image,
        ],
        capture=True,
    ).strip()
    if not re.fullmatch(r"[0-9a-f]{64}", container):
        raise ValueError("Docker returned an invalid container identity")
    try:
        address = run(
            ["docker", "port", container, f"{runtime.container_port}/tcp"], capture=True
        ).strip()
        if not re.fullmatch(r"127\.0\.0\.1:[0-9]+", address):
            raise ValueError("Smoke test did not receive a loopback mapping")
        url = "http://" + address + runtime.health_path
        for _attempt in range(30):
            try:
                with urlopen(url, timeout=2) as response:
                    if response.url != url or response.status != 200:
                        raise ValueError("Health response was redirected or unsuccessful")
                    if json.load(response) != {"status": "ok"}:
                        raise ValueError("Health must return the supported JSON contract")
                break
            except (OSError, ValueError):
                time.sleep(1)
        else:
            raise ValueError("Candidate failed its runtime health contract")
        uid = run(["docker", "exec", container, "id", "-u"], capture=True).strip()
        if uid != "10001":
            raise ValueError("Candidate must run with the supported non-root UID 10001")
    finally:
        run(["docker", "rm", "-f", container], capture=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["checks", "quality", "tests", "scan-policy", "smoke"])
    parser.add_argument("--source", type=Path)
    parser.add_argument("--venv", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--image")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--health-path", default="/health")
    args = parser.parse_args()
    if args.command in {"checks", "quality", "tests"}:
        if args.source is None or args.venv is None:
            parser.error("checks requires --source and --venv")
        checks(
            args.source.resolve(),
            args.venv.resolve(),
            "all" if args.command == "checks" else args.command,
        )
    elif args.command == "scan-policy":
        if args.report is None:
            parser.error("scan-policy requires --report")
        inventory_policy(json.loads(args.report.read_bytes()))
    else:
        if not args.image:
            parser.error("smoke requires --image")
        runtime = Runtime(
            container_port=args.port, health_path=args.health_path, resource_profile_id="small"
        )
        smoke(args.image, runtime)


if __name__ == "__main__":
    main()
