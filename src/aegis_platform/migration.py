"""Read-only verification of the working sample before an explicitly reviewed cutover."""

import hashlib
from pathlib import Path

from aegis_platform.catalog import checked_path


def verify_baseline(snapshot: dict, workspace: Path) -> list[str]:
    if (
        snapshot.get("schema_version") != 1
        or snapshot.get("approved_catalog_enrollment") is not False
    ):
        raise ValueError("Expected a non-enrolled legacy baseline")
    changed = []
    for repository, data in snapshot["repositories"].items():
        if repository not in {"aegis-cicd", "aegis-gitops"}:
            raise ValueError("Unknown baseline repository")
        for relative, expected in data["files"].items():
            path = workspace / repository / checked_path(relative)
            if path.is_symlink() or not path.is_file():
                changed.append(f"{repository}/{relative}")
            elif hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                changed.append(f"{repository}/{relative}")
    return changed
