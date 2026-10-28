import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from aegis_platform.canonical import canonical, digest
from aegis_platform.delivery import DeliveryPolicy
from aegis_platform.observability_policy import OBS_BASE, ObservabilityPolicy, password_fingerprint
from aegis_platform.observability_service import (
    CONTEXT,
    SUCCESS,
    ObservabilityServicePolicy,
    service_plan,
    verify_exact_tree,
    verify_operator_review,
    verify_proposal,
)
from tooling import observability_service as admission
from tooling.bootstrap_observability import (
    credential_secrets,
    prepare_credentials,
    verify_protection,
)


@pytest.fixture
def case():
    policy = ObservabilityPolicy.model_validate_json(
        Path("policies/observability.json").read_text()
    )
    access = ObservabilityServicePolicy(
        operator_user_ids=["301"],
        proposer_bot_user_id="902",
    )
    delivery = DeliveryPolicy.model_validate_json(Path("policies/delivery.json").read_text())
    expected = service_plan(policy, access, "a" * 40)
    repository = {"id": policy.gitops_repository_id, "full_name": policy.gitops_repository}
    pr = {
        "state": "open",
        "head": {"sha": "b" * 40, "repo": repository},
        "base": {"ref": access.branch, "repo": repository},
        "user": {"id": "902", "type": "Bot"},
        "changed_files": len(expected),
        "draft": False,
    }
    changed = [{"filename": p, "status": "added"} for p in expected]
    review = {
        "id": 1,
        "user": {"id": "301", "type": "User"},
        "state": "APPROVED",
        "commit_id": "b" * 40,
    }
    return policy, access, delivery, expected, pr, changed, review


def test_combined_plan_binds_config_and_includes_grafana_in_controller_path(case):
    policy, access, _, expected, *_ = case
    assert expected == service_plan(policy, access, "a" * 40)
    resources = {k: v for k, v in expected.items() if not k.endswith("review.json")}
    assert expected[OBS_BASE + "/review.json"]["resources_hash"] == digest(resources)
    assert OBS_BASE + "/manifests/deployment-grafana.json" in expected
    objects = list(expected.values())
    app = next(v for v in objects if v.get("kind") == "Application")
    assert app["spec"]["source"]["targetRevision"] == "platform-observability"
    assert app["spec"]["source"]["path"] == OBS_BASE + "/manifests"
    project = next(v for v in objects if v.get("kind") == "AppProject")
    assert {"group": "networking.k8s.io", "kind": "NetworkPolicy"} in project["spec"][
        "namespaceResourceWhitelist"
    ]
    assert all(v.get("kind") != "Secret" for v in objects)
    assert all(
        "aegis.io/config-hash" in v["spec"]["template"]["metadata"]["annotations"]
        for v in objects
        if v.get("kind") == "Deployment"
    )


@pytest.mark.parametrize("mutation", ["extra", "missing", "image", "secret", "private_key"])
def test_admission_rejects_unrendered_resource_changes(case, mutation):
    expected = case[3]
    actual = deepcopy(expected)
    if mutation == "extra":
        actual[OBS_BASE + "/manifests/extra.json"] = {"kind": "Deployment"}
    elif mutation == "missing":
        actual.pop(next(iter(actual)))
    elif mutation == "image":
        actual[OBS_BASE + "/manifests/deployment-grafana.json"]["spec"]["template"]["spec"][
            "containers"
        ][0]["image"] = "grafana/grafana:latest"
    elif mutation == "secret":
        actual[OBS_BASE + "/manifests/secret.json"] = {
            "kind": "Secret",
            "data": {"password": "forbidden"},
        }
    else:
        actual[OBS_BASE + "/review.json"]["private_key"] = "forbidden"
    with pytest.raises(ValueError):
        verify_exact_tree(actual, expected)


def test_exact_tree_accepts_json_whitespace_but_rejects_duplicate_keys(case):
    expected = case[3]
    verify_exact_tree({p: canonical(v) for p, v in expected.items()}, expected)
    actual = {p: canonical(v) for p, v in expected.items()}
    actual[next(iter(actual))] = b'{"kind":"ConfigMap","kind":"Secret"}'
    with pytest.raises(ValueError):
        verify_exact_tree(actual, expected)


@pytest.mark.parametrize(
    "mutation",
    ["fork", "wrong_branch", "human_author", "extra_path", "rename", "removed", "duplicate"],
)
def test_pr_scope_cannot_expand_authority(case, mutation):
    policy, access, _, expected, pr, changed, _ = case
    if mutation == "fork":
        pr["head"]["repo"] = {"id": "999", "full_name": "attacker/fork"}
    elif mutation == "wrong_branch":
        pr["base"]["ref"] = "main"
    elif mutation == "human_author":
        pr["user"]["type"] = "User"
    elif mutation == "extra_path":
        changed[0]["filename"] = ".github/workflows/override.yml"
    elif mutation == "rename":
        changed[0]["previous_filename"] = "outside.json"
    elif mutation == "removed":
        changed[0]["status"] = "removed"
    else:
        changed[1] = changed[0]
    with pytest.raises(ValueError):
        verify_proposal(pr, changed, policy, access, expected)


@pytest.mark.parametrize("mutation", ["stale", "self", "dismissed", "changes", "draft", "bot"])
def test_only_independent_current_human_review_authorizes(case, mutation):
    _, access, delivery, _, pr, _, review = case
    if mutation == "stale":
        review["commit_id"] = "c" * 40
    elif mutation == "self":
        pr["user"]["id"] = "301"
    elif mutation == "dismissed":
        review["state"] = "DISMISSED"
    elif mutation == "changes":
        review["state"] = "CHANGES_REQUESTED"
    elif mutation == "draft":
        pr["draft"] = True
    else:
        review["user"]["type"] = "Bot"
    with pytest.raises(ValueError):
        verify_operator_review(pr, [review], access, delivery)


@pytest.mark.parametrize("race", [False, True])
def test_admission_never_posts_success_to_changed_pr_head(case, monkeypatch, race):
    policy, access, delivery, expected, pr, changed, review = case
    posted = []
    calls = []

    def repo(method, path, body=None):
        if method == "POST":
            posted.append(body)
            return {}
        calls.append(path)
        value = deepcopy(pr)
        if len(calls) > 1 and race:
            value["head"]["sha"] = "c" * 40
        return value

    api = SimpleNamespace(repo=repo, pages=lambda p: changed if p.endswith("/files") else [review])
    engine = SimpleNamespace(gitops=api)
    monkeypatch.setattr(admission, "admitted_plan", lambda e: (expected, policy, access, delivery))
    monkeypatch.setattr(admission, "tree_files", lambda *args: expected)
    admission.check_pr(engine, 1)
    assert posted == (
        [] if race else [{"state": "success", "context": CONTEXT, "description": SUCCESS}]
    )


def test_generated_workflow_uses_trusted_pinned_code_only():
    parsed = yaml.safe_load(admission.workflow("a" * 40))
    steps = parsed["jobs"]["admission"]["steps"]
    checkout = steps[0]["with"]
    assert checkout["ref"] == "a" * 40
    assert checkout["repository"] == "prasanthece42/aegis-platform"
    assert checkout["persist-credentials"] is False
    assert "pull_request.head" not in json.dumps(steps)
    with pytest.raises(ValueError):
        admission.workflow("main")


def protection():
    return {
        "enforce_admins": {"enabled": True},
        "required_pull_request_reviews": {
            "required_approving_review_count": 1,
            "dismiss_stale_reviews": True,
        },
        "required_status_checks": {
            "strict": True,
            "checks": [{"context": CONTEXT, "app_id": 15368}],
        },
    }


@pytest.mark.parametrize(
    "mutation", ["admins", "review", "stale", "strict", "forged_status", "force", "bypass"]
)
def test_bootstrap_rejects_weakened_branch_protection(mutation):
    p = protection()
    verify_protection(p)
    if mutation == "admins":
        p["enforce_admins"]["enabled"] = False
    elif mutation == "review":
        p["required_pull_request_reviews"]["required_approving_review_count"] = 0
    elif mutation == "stale":
        p["required_pull_request_reviews"]["dismiss_stale_reviews"] = False
    elif mutation == "strict":
        p["required_status_checks"]["strict"] = False
    elif mutation == "forged_status":
        p["required_status_checks"]["checks"][0]["app_id"] = 99
    elif mutation == "force":
        p["allow_force_pushes"] = {"enabled": True}
    else:
        p["required_pull_request_reviews"]["bypass_pull_request_allowances"] = {"users": ["301"]}
    with pytest.raises(ValueError):
        verify_protection(p)


def test_credentials_are_private_fingerprint_bound_and_never_overwritten(case, tmp_path):
    from aegis_platform.observability_policy import query_password

    policy = case[0]
    oauth = tmp_path / "oauth.json"
    secret = "synthetic-test-oauth-capability-0123456789"
    oauth.write_text(json.dumps({"client_secret": secret}))
    oauth.chmod(0o600)
    policy = policy.model_copy(
        update={
            "query_password_sha256": password_fingerprint(
                query_password(secret, policy.cluster_uid)
            )
        }
    )
    directory = tmp_path / "private"
    prepare_credentials(directory, oauth, policy)
    assert directory.stat().st_mode & 0o077 == 0
    result = credential_secrets(directory, policy)
    assert set(result) == {"aegis-observability-auth", "aegis-grafana-auth"}
    assert result["aegis-observability-auth"]["query.htpasswd"].startswith(b"query:$apr1$")
    with pytest.raises(FileExistsError):
        prepare_credentials(directory, oauth, policy)
    (directory / "query-password").write_text("wrong-password" * 3)
    with pytest.raises(ValueError):
        credential_secrets(directory, policy)


@pytest.mark.parametrize("mutation", ["clean", "dirty", "stale_code", "cluster", "inactive_issuer"])
def test_trusted_renderer_binds_checkout_and_enrollment(case, monkeypatch, tmp_path, mutation):
    policy, access, delivery, *_ = case
    delivery = delivery.model_copy(update={"observer_user_ids": ["301"]})
    files = {
        "policies/observability.json": canonical(policy.model_dump()),
        "policies/observability-service.json": canonical(access.model_dump()),
    }
    cluster = SimpleNamespace(
        cluster_uid=policy.cluster_uid, gitops_repository_id=policy.gitops_repository_id
    )
    if mutation == "cluster":
        cluster.cluster_uid = "different-cluster"
    trust = SimpleNamespace(
        issuers=[SimpleNamespace(bot_user_id="902", active=mutation != "inactive_issuer")]
    )
    engine = SimpleNamespace(
        root=tmp_path,
        snapshot=lambda: (
            "a" * 40,
            SimpleNamespace(clusters={policy.cluster_id: cluster}),
            delivery,
            trust,
            {},
        ),
        platform=SimpleNamespace(file=lambda path, revision: files[path]),
    )

    def output(command, **kwargs):
        if "rev-parse" in command:
            return ("b" if mutation == "stale_code" else "a") * 40 + "\n"
        return " M tracked.py" if mutation == "dirty" else ""

    monkeypatch.setattr("subprocess.check_output", output)
    if mutation == "clean":
        assert admission.admitted_plan(engine)[0] == service_plan(policy, access, "a" * 40)
    else:
        with pytest.raises(ValueError):
            admission.admitted_plan(engine)


def test_alert_categories_and_backend_scrapes_use_existing_authenticated_gateways(case):
    from aegis_platform.observability_config import alert_rules, collector_config, prometheus_config

    policy = case[0]
    rules = alert_rules()["groups"][0]["rules"]
    assert {r["alert"] for r in rules} >= {
        "AegisApplicationUnavailable",
        "AegisPodCrashLoop",
        "AegisExcessiveRestarts",
        "AegisHighErrorRate",
        "AegisHighLatency",
        "AegisNodePressure",
        "AegisCollectorUnavailable",
        "AegisMonitoringBackendUnavailable",
    }
    assert all(
        r["annotations"]["grafana_url"].startswith("http://127.0.0.1:3000/d/aegis-") for r in rules
    )
    configs = prometheus_config(policy)["scrape_configs"]
    backends = next(c for c in configs if c["job_name"] == "aegis-monitoring-backends")
    assert backends["basic_auth"]["password_file"].endswith("/query-password")
    assert len(backends["static_configs"][0]["targets"]) == 4
    assert collector_config(policy)["receivers"]["k8s_cluster"]["metrics"][
        "k8s.container.status.reason"
    ]["enabled"]


def test_preflight_cannot_adopt_unrelated_resources(case, monkeypatch):
    from tooling.bootstrap_observability import preflight_resources

    expected = case[3]
    calls = []
    monkeypatch.setattr(
        "subprocess.check_output",
        lambda *args, **kwargs: canonical(
            {
                "metadata": {"labels": {"app.kubernetes.io/part-of": "another-platform"}},
            }
        ).decode(),
    )
    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError):
        preflight_resources(["kubectl", "--context", "kind-local"], expected)
    assert not calls


def test_preflight_only_uses_dry_run_on_public_plan_objects(case, monkeypatch):
    from tooling.bootstrap_observability import preflight_resources

    calls = []
    monkeypatch.setattr("subprocess.check_output", lambda *args, **kwargs: "")
    monkeypatch.setattr("subprocess.run", lambda command, **kwargs: calls.append((command, kwargs)))
    preflight_resources(["kubectl", "--context", "kind-local"], case[3])
    assert calls
    for command, kwargs in calls:
        assert "--dry-run=client" in command
        assert json.loads(kwargs["input"])["kind"] != "Secret"
