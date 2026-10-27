"""Keep the pre-checkout bootstrap identical to its tested stdlib implementation."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def render_ci() -> str:
    return render_workflow("ci")


def render_workflow(kind: str) -> str:
    if kind not in {"ci", "release"}:
        raise ValueError("Unknown workflow family")
    template = (ROOT / f".github/workflow-templates/python-web-{kind}.yml.in").read_text()
    bootstrap = (ROOT / "src/aegis_platform/workflow.py").read_text().rstrip()
    if kind == "release":
        bootstrap = bootstrap.replace(
            'WORKFLOW = "python-web-ci.yml"', 'WORKFLOW = "python-web-release.yml"'
        )
    return template.replace(
        "__AEGIS_BOOTSTRAP__",
        "\n".join("          " + line if line else "" for line in bootstrap.splitlines()),
    )


if __name__ == "__main__":
    for kind in ["ci", "release"]:
        (ROOT / f".github/workflows/python-web-{kind}.yml").write_text(render_workflow(kind))
