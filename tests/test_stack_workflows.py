import re
from pathlib import Path

import pytest
import yaml

from tooling.render_workflows import render_workflow

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("kind", ["ci", "release"])
def test_stack_workflows_are_generated_pinned_and_have_executable_bootstrap(kind):
    rendered = render_workflow(kind, "python-stack")
    assert rendered == (ROOT / f".github/workflows/python-stack-{kind}.yml").read_text()
    workflow = yaml.safe_load(rendered)
    prepare = workflow["jobs"]["prepare"]
    resolve = prepare["steps"][0]["run"]
    compile(resolve, "stack-bootstrap", "exec")
    assert f'WORKFLOW = "python-stack-{kind}.yml"' in resolve
    assert 'run["run_started_at"]' in resolve
    assert "persist-credentials: false" in rendered
    assert workflow["permissions"] == {"contents": "read", "actions": "read"}
    for job in workflow["jobs"].values():
        for step in job.get("steps", []):
            if "uses" in step:
                assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", step["uses"])
    if kind == "release":
        assert workflow["jobs"]["publish"]["permissions"]["contents"] == "read"
        assert workflow["jobs"]["validate"]["uses"] == "./.github/workflows/python-stack-ci.yml"
        assert workflow["jobs"]["assemble"]["needs"] == ["prepare", "publish"]
    else:
        assert workflow["jobs"]["candidate"]["needs"] == ["prepare", "checks", "security"]
        security = workflow["jobs"]["security"]
        assert any("stack_ci.py security" in s.get("run", "") for s in security["steps"])
        assert not any("stack_ci.py checks" in s.get("run", "") for s in security["steps"])
