"""Exercise actual pinned scanners against isolated positive/negative canaries."""

import json
import subprocess
import tempfile
from pathlib import Path

from tooling.source_security import scan


def main():
    with tempfile.TemporaryDirectory(prefix="aegis-security-check-") as folder:
        source = Path(folder) / "source"
        source.mkdir()
        subprocess.run(["git", "init", "-q", str(source)], check=True)
        report = Path(folder) / "report.json"
        (source / "app.py").write_text('def health():\n    return {"status": "ok"}\n')
        subprocess.run(["git", "-C", str(source), "add", "."], check=True)
        scan(source, report)
        assert json.loads(report.read_bytes())["status"] == "passed"
        # Deliberately synthetic: this disposable canary must never enter reports.
        canary = "AKIA" + "Q7MTJ2SP9K4Z8N6C"
        (source / "app.py").write_text(
            "import subprocess\nsubprocess.Popen(input(), shell=True)\n"
            + 'aws_access_key_id = "'
            + canary
            + '"\n'
        )
        (source / ".trivyignore").write_text("*\n")
        (source / "trivy.yaml").write_text("scan:\n  scanners: []\n")
        subprocess.run(["git", "-C", str(source), "add", "."], check=True)
        try:
            scan(source, report)
        except ValueError:
            pass
        else:
            raise ValueError("Synthetic source security findings were not blocked")
        result = json.loads(report.read_bytes())
        if (
            result["status"] != "failed"
            or canary in report.read_text()
            or {f["scanner"] for f in result["findings"]} != {"bandit", "trivy-secret"}
        ):
            raise ValueError("Security canary was not detected and safely redacted")
    print("Real source-security checks passed: clean source, SAST, secrets, overrides, redaction")


if __name__ == "__main__":
    main()
