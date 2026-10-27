"""Build a reproducible local platform wheel and record its source identity for the portal."""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--portal", type=Path, default=ROOT.parent / "aegis-portal")
    args = parser.parse_args()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    portal = args.portal.resolve()
    if tomllib.loads((portal / "pyproject.toml").read_text())["project"]["name"] != "aegis-portal":
        raise ValueError("Destination is not an Aegis portal project")
    subprocess.run(
        [sys.executable, "-m", "hatchling", "build", "-t", "wheel"], cwd=ROOT, check=True
    )
    wheel_name = f"aegis_platform-{project['version']}-py3-none-any.whl"
    wheel = ROOT / "dist" / wheel_name
    vendor = portal / "vendor"
    vendor.mkdir(exist_ok=True)
    shutil.copyfile(wheel, vendor / wheel_name)
    sources = [ROOT / "pyproject.toml", *sorted((ROOT / "src/aegis_platform").glob("*.py"))]
    manifest = {
        "schema_version": 1,
        "package": project["name"],
        "version": project["version"],
        "distribution": wheel_name,
        "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "provenance": "Local source snapshot; not a published or signed platform release",
        "source_sha256": {
            str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources
        },
    }
    (vendor / "aegis-platform.bundle.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(
        "Built local shared contract bundle; refresh and verify the portal dependency locks next."
    )


if __name__ == "__main__":
    main()
