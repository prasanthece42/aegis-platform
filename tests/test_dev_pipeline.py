from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from aegis_platform.local_agent import verify_dev_security
from aegis_platform.pipeline import dev_pipeline
from tooling.source_security import evaluate, tracked_snapshot


def jobs():
    root = Path(__file__).resolve().parents[1]
    result = []
    for family in ("ci", "release"):
        workflow = yaml.load(
            (root / f".github/workflows/python-web-{family}.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        for job in workflow["jobs"].values():
            if "name" not in job:
                continue
            for arch in ("amd64", "arm64") if "matrix" in job.get("strategy", {}) else (None,):
                result.append(
                    {
                        "name": "validate / "
                        + job["name"].replace("${{ matrix.arch }}", arch or ""),
                        "status": "completed",
                        "conclusion": "success",
                    }
                )
    return result


def test_nine_stages_require_both_architectures_and_fresh_runtime_security():
    result = dev_pipeline(jobs(), complete=True, delivery={"status": "healthy"})
    assert len(result["stages"]) == 9
    assert all(s["state"] == "passed" for s in result["stages"][:8])
    assert result["stages"][8]["state"] == "unknown"
    assert (
        dev_pipeline(jobs(), delivery={"status": "healthy", "security_verified": True})["stages"][
            8
        ]["state"]
        == "passed"
    )
    partial = [j for j in jobs() if j["name"] != "validate / 07 Container security (arm64)"]
    assert dev_pipeline(partial, complete=True)["stages"][6]["state"] == "unknown"
    legacy = [{"name": "checks", "status": "completed", "conclusion": "success"}]
    assert all(s["state"] == "unknown" for s in dev_pipeline(legacy, complete=True)["stages"][:8])


def test_failed_cancelled_duplicate_and_skipped_jobs_do_not_turn_green():
    for conclusion, expected in (
        ("failure", "failed"),
        ("timed_out", "failed"),
        ("cancelled", "cancelled"),
        ("skipped", "skipped"),
    ):
        items = jobs()
        next(j for j in items if "07 Container security (arm64)" in j["name"])["conclusion"] = (
            conclusion
        )
        assert dev_pipeline(items, complete=True)["stages"][6]["state"] == expected
    items = jobs()
    items.append(deepcopy(next(j for j in items if "04 Source security" in j["name"])))
    assert dev_pipeline(items, complete=True)["stages"][3]["state"] == "unknown"


def test_source_reports_never_export_matched_secrets_or_source_code():
    sast = {
        "errors": [],
        "metrics": {"_totals": {"loc": 10}},
        "results": [
            {
                "test_id": "B602",
                "filename": "app/main.py",
                "line_number": 3,
                "issue_severity": "HIGH",
                "code": "private-source",
            }
        ],
    }
    secrets = {
        "Results": [
            {
                "Target": "app/settings.py",
                "Secrets": [
                    {
                        "RuleID": "fixture",
                        "StartLine": 1,
                        "Severity": "HIGH",
                        "Match": "private-value",
                        "Code": {"Lines": ["private-value"]},
                    }
                ],
            }
        ]
    }
    secrets.update(SchemaVersion=2, ArtifactType="filesystem", Trivy={"Version": "0.76.1"})
    result = evaluate(sast, secrets)
    assert result["status"] == "failed"
    assert "private" not in str(result)
    with pytest.raises(ValueError):
        evaluate({**sast, "errors": ["parse error"]}, secrets)
    with pytest.raises(ValueError):
        evaluate({**sast, "metrics": {}}, secrets)
    assert (
        evaluate(
            {**sast, "results": []},
            {"SchemaVersion": 2, "ArtifactType": "filesystem", "Trivy": {"Version": "0.76.1"}},
        )["status"]
        == "passed"
    )
    with pytest.raises(ValueError):
        evaluate({**sast, "results": []}, {})


def test_tracked_snapshot_rejects_symlink_escape(tmp_path, monkeypatch):
    from types import SimpleNamespace

    source, output = tmp_path / "repo", tmp_path / "output"
    source.mkdir()
    output.mkdir()
    (source / "app.py").symlink_to(tmp_path / "outside")
    monkeypatch.setattr(
        "tooling.source_security.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=b"app.py\0"),
    )
    with pytest.raises(ValueError, match="symlink"):
        tracked_snapshot(source, output)


def runtime():
    spec = {
        "automountServiceAccountToken": False,
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": 10001,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "containers": [
            {
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]},
                }
            }
        ],
    }
    deployment = {
        "spec": {
            "selector": {"matchLabels": {"app": "fixture"}},
            "replicas": 1,
            "template": {"spec": spec},
        }
    }
    service = {"spec": {"type": "ClusterIP", "selector": {"app": "fixture"}}}
    pods = {"items": [{"metadata": {"labels": {"app": "fixture"}}, "spec": deepcopy(spec)}]}
    return deployment, service, pods


@pytest.mark.parametrize(
    "mutation",
    ["root", "token", "host", "writable", "privileged", "external", "missing_pod", "secret"],
)
def test_runtime_smoke_blocks_unsafe_live_pods_and_public_service(mutation):
    deployment, service, pods = runtime()
    verify_dev_security(deployment, service, pods)
    spec = pods["items"][0]["spec"]
    if mutation == "root":
        spec["securityContext"]["runAsUser"] = 0
    elif mutation == "token":
        spec["automountServiceAccountToken"] = True
    elif mutation == "host":
        spec["hostNetwork"] = True
    elif mutation == "writable":
        spec["containers"][0]["securityContext"]["readOnlyRootFilesystem"] = False
    elif mutation == "privileged":
        spec["containers"][0]["securityContext"]["privileged"] = True
    elif mutation == "external":
        service["spec"]["type"] = "LoadBalancer"
    elif mutation == "missing_pod":
        pods["items"] = []
    else:
        spec["volumes"] = [{"name": "secret", "secret": {"secretName": "private"}}]
    with pytest.raises(ValueError):
        verify_dev_security(deployment, service, pods)


def test_fresh_failed_rollout_is_visible_as_a_failed_ninth_stage():
    result = dev_pipeline(jobs(), delivery={"status": "reconciling", "health_check_failed": True})
    assert result["stages"][8]["state"] == "failed"
