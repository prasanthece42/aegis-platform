"""Keep the pre-checkout bootstrap identical to its tested stdlib implementation."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def render_ci() -> str:
    return render_workflow("ci")


def render_workflow(kind: str, family="python-web") -> str:
    if kind not in {"ci", "release"}:
        raise ValueError("Unknown workflow family")
    if family not in {"python-web", "python-stack"}:
        raise ValueError("Unknown workflow family")
    template = (ROOT / f".github/workflow-templates/{family}-{kind}.yml.in").read_text()
    bootstrap = (ROOT / "src/aegis_platform/workflow.py").read_text().rstrip()
    if kind == "release":
        bootstrap = bootstrap.replace(
            'WORKFLOW = "python-web-ci.yml"', 'WORKFLOW = "python-web-release.yml"'
        )
    if family == "python-stack":
        bootstrap = bootstrap.replace(
            f'WORKFLOW = "python-web-{kind}.yml"', f'WORKFLOW = "python-stack-{kind}.yml"'
        )
        line = 'output.write("platforms=" + json.dumps(archs, separators=(",", ":")) + "\\n")'
        bootstrap = bootstrap.replace(
            line, line + '\n        output.write("run_started_at=" + run["run_started_at"] + "\\n")'
        )
    return template.replace(
        "__AEGIS_BOOTSTRAP__",
        "\n".join("          " + line if line else "" for line in bootstrap.splitlines()),
    )


if __name__ == "__main__":
    for family in ["python-web", "python-stack"]:
        for kind in ["ci", "release"]:
            (ROOT / f".github/workflows/{family}-{kind}.yml").write_text(
                render_workflow(kind, family)
            )
