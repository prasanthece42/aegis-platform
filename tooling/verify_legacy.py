"""Verify the checked-in baseline without changing repositories or the cluster."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegis_platform.canonical import strict_json  # noqa: E402
from aegis_platform.migration import verify_baseline  # noqa: E402

if __name__ == "__main__":
    snapshot = strict_json((ROOT / "migrations/sample-api.baseline.json").read_bytes())
    changes = verify_baseline(snapshot, ROOT.parent)
    if changes:
        print("Baseline changed; inspect before cutover:\n" + "\n".join(changes), file=sys.stderr)
        raise SystemExit(1)
    print("PASS: legacy sample source, workflows, GitOps and Argo bindings are unchanged")
