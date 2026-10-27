import json
import os
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from aegis_platform.bootstrap import (
    bootstrap_plan,
    chart_identity,
    release_values,
    validate_profile,
    write_plan,
)
from aegis_platform.catalog import Catalog, CatalogPolicy, Cluster
from aegis_platform.contracts import CatalogEntry
from tests.release_fixtures import release_fixture

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "charts/web-service/1.0.0"
POLICY = json.loads((ROOT / "policies/bootstrap.json").read_text())
CONTEXT = json.loads((ROOT / "examples/bootstrap-context.json").read_text())


def catalog(entries, cluster, policy):
    entries = deepcopy(entries)
    identity = chart_identity(CHART)
    for entry in entries:
        entry["versions"]["chart_sha256"] = identity["sha256"]
    return Catalog(
        [CatalogEntry.model_validate(e) for e in entries],
        [Cluster.model_validate(cluster)],
        CatalogPolicy.model_validate(policy),
    )


def test_two_apps_render_separate_targets_without_namespace_chart_ownership(
    example_entries, cluster_record, policy_record
):
    loaded = catalog(example_entries, cluster_record, policy_record)
    first = bootstrap_plan(loaded, "orders-api", "dev", CONTEXT, POLICY, CHART)
    second = bootstrap_plan(loaded, "payments-api", "dev", CONTEXT, POLICY, CHART)
    assert (
        first["argocd/projects/orders-api-dev.json"]["spec"]["destinations"]
        != second["argocd/projects/payments-api-dev.json"]["spec"]["destinations"]
    )
    app = first["argocd/applications/orders-api-dev.json"]
    assert app["spec"]["syncPolicy"]["automated"]["selfHeal"] is True
    assert "CreateNamespace=true" not in app["spec"]["syncPolicy"]["syncOptions"]
    project = first["argocd/projects/orders-api-dev.json"]
    assert all("kind" in content for path, content in first.items() if path.startswith("clusters/"))
    assert (
        first["reviews/bootstrap/example-kind/orders-api/dev.json"]["status"]
        == "review-only-not-applied"
    )
    assert project["spec"]["clusterResourceWhitelist"] == []
    assert {r["kind"] for r in project["spec"]["namespaceResourceWhitelist"]} == {
        "Deployment",
        "Service",
        "ServiceAccount",
    }
    assert not any(path in second for path in first if path.startswith(("argocd/", "clusters/")))


@pytest.mark.parametrize("environment,branch", [("staging", "staging"), ("prod", "prod")])
def test_protected_bootstrap_never_enables_automatic_sync(
    example_entries, cluster_record, policy_record, environment, branch
):
    entries = deepcopy(example_entries)
    entry = entries[0]
    target = deepcopy(entry["environments"]["dev"])
    target.update(
        namespace=f"aegis-orders-api-{environment}",
        argo_application=f"orders-api-{environment}",
        argo_project=f"orders-api-{environment}",
        gitops_branch=branch,
        values_path=f"applications/orders-api/environments/{environment}/values.yaml",
    )
    entry["environments"][environment] = target
    loaded = catalog(entries, cluster_record, policy_record)
    plan = bootstrap_plan(loaded, "orders-api", environment, CONTEXT, POLICY, CHART)
    app = plan[f"argocd/applications/orders-api-{environment}.json"]
    assert "automated" not in app["spec"]["syncPolicy"]
    assert app["spec"]["source"]["targetRevision"] == branch
    assert (
        app["metadata"]["annotations"]["aegis.io/human-review-required"]
        == str(environment == "prod").lower()
    )
    assert (
        plan[f"argocd/projects/orders-api-{environment}.json"]["spec"]["destinations"][0][
            "namespace"
        ]
        == target["namespace"]
    )


@pytest.mark.parametrize("mutation", ["uid", "repository_id", "chart", "quota", "resources"])
def test_bootstrap_rejects_wrong_identity_or_profile(
    example_entries, cluster_record, policy_record, mutation
):
    loaded = catalog(example_entries, cluster_record, policy_record)
    context, policy = deepcopy(CONTEXT), deepcopy(POLICY)
    if mutation == "uid":
        context["cluster_uid"] = "replacement-cluster"
    elif mutation == "repository_id":
        context["gitops_repository_id"] = "999"
    elif mutation == "chart":
        loaded.apps["orders-api"].versions.chart_sha256 = "sha256:" + "f" * 64
    elif mutation == "quota":
        policy["resource_profiles"]["small"]["quota"]["pods"] = "100"
    else:
        policy["resource_profiles"]["small"]["limits"]["cpu"] = "5000m"
    with pytest.raises(ValueError):
        bootstrap_plan(loaded, "orders-api", "dev", context, policy, CHART)


def test_quota_covers_rollout_and_default_service_account():
    profile = validate_profile(POLICY, "small")
    assert int(profile["quota"]["pods"]) == profile["max_replicas"] + 1
    assert profile["quota"]["count/serviceaccounts"] == "2"


def test_plan_writer_does_not_overwrite_existing_files(tmp_path):
    out = tmp_path / "review"
    write_plan({"app/test.json": {"status": "review-only"}}, out)
    with pytest.raises(ValueError):
        write_plan({"app/test.json": {"status": "changed"}}, out)
    assert json.loads((out / "app/test.json").read_text())["status"] == "review-only"
    with pytest.raises(ValueError):
        write_plan({"../outside.json": {}}, tmp_path / "new")


def helm(tmp_path, values, namespace="aegis-orders-api-dev"):
    path = tmp_path / "values.json"
    path.write_text(json.dumps(values))
    env = {
        **os.environ,
        "HELM_CACHE_HOME": str(tmp_path / "cache"),
        "HELM_CONFIG_HOME": str(tmp_path / "config"),
        "HELM_DATA_HOME": str(tmp_path / "data"),
    }
    return subprocess.run(
        [
            "helm",
            "template",
            "orders-api",
            str(CHART),
            "--namespace",
            namespace,
            "--kube-version",
            "1.35.8",
            "--values",
            str(path),
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def test_real_helm_render_uses_exact_digest_and_restricted_security(
    tmp_path, example_entries, cluster_record, policy_record
):
    loaded = catalog(example_entries, cluster_record, policy_record)
    evidence = release_fixture(tmp_path)["evidence"]
    values = release_values(loaded, "orders-api", "dev", evidence, POLICY)
    result = helm(tmp_path, values)
    assert result.returncode == 0, result.stderr
    manifests = list(yaml.safe_load_all(result.stdout))
    assert {m["kind"] for m in manifests} == {"Deployment", "Service", "ServiceAccount"}
    deployment = next(m for m in manifests if m["kind"] == "Deployment")
    pod = deployment["spec"]["template"]["spec"]
    container = pod["containers"][0]
    assert container["image"] == evidence.image
    assert pod["automountServiceAccountToken"] is False
    assert pod["securityContext"]["runAsUser"] == 10001
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
    assert deployment["metadata"]["namespace"] == "aegis-orders-api-dev"


@pytest.mark.parametrize(
    "mutation", ["namespace", "replicas", "digest", "privilege", "oversize", "path"]
)
def test_chart_rejects_invalid_or_unsafe_values(
    tmp_path, example_entries, cluster_record, policy_record, mutation
):
    loaded = catalog(example_entries, cluster_record, policy_record)
    values = release_values(
        loaded, "orders-api", "dev", release_fixture(tmp_path)["evidence"], POLICY
    )
    namespace = "aegis-orders-api-dev"
    if mutation == "namespace":
        namespace = "aegis-payments-api-dev"
    elif mutation == "replicas":
        values["replicaCount"] = 100
    elif mutation == "digest":
        values["image"]["digest"] = "latest"
    elif mutation == "privilege":
        values["securityContext"] = {"privileged": True}
    elif mutation == "oversize":
        values["resources"]["limits"]["cpu"] = "5000m"
    else:
        values["healthPath"] = "https://outside.example"
    assert helm(tmp_path, values, namespace).returncode != 0


def test_foreign_release_cannot_generate_values(
    tmp_path, example_entries, cluster_record, policy_record
):
    loaded = catalog(example_entries, cluster_record, policy_record)
    evidence = release_fixture(tmp_path)["evidence"]
    with pytest.raises(ValueError):
        release_values(loaded, "payments-api", "dev", evidence, POLICY)
    with pytest.raises(ValueError):
        release_values(loaded, "orders-api", "prod", evidence, POLICY)


def test_rendered_values_do_not_mutate_policy_or_other_apps(
    tmp_path, example_entries, cluster_record, policy_record
):
    loaded = catalog(example_entries, cluster_record, policy_record)
    original_policy = deepcopy(POLICY)
    evidence = release_fixture(tmp_path)["evidence"]
    before = bootstrap_plan(loaded, "payments-api", "dev", CONTEXT, POLICY, CHART)
    values = release_values(loaded, "orders-api", "dev", evidence, POLICY)
    values["resources"]["limits"]["cpu"] = "9999m"
    assert POLICY == original_policy
    assert bootstrap_plan(loaded, "payments-api", "dev", CONTEXT, POLICY, CHART) == before


def test_chart_lint_and_nontraversing_dotted_health_path(
    tmp_path, example_entries, cluster_record, policy_record
):
    loaded = catalog(example_entries, cluster_record, policy_record)
    values = release_values(
        loaded, "orders-api", "dev", release_fixture(tmp_path)["evidence"], POLICY
    )
    values["healthPath"] = "/health/live.v1"
    assert helm(tmp_path, values).returncode == 0
    result = subprocess.run(
        [
            "helm",
            "lint",
            str(CHART),
            "--strict",
            "--namespace",
            "aegis-orders-api-dev",
            "--values",
            str(tmp_path / "values.json"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
