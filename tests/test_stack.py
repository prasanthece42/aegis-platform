import io
import json
import subprocess
import tarfile
from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from aegis_platform.bootstrap import bootstrap_plan, chart_identity, release_values
from aegis_platform.canonical import canonical, digest
from aegis_platform.catalog import Catalog, CatalogPolicy, Cluster
from aegis_platform.contracts import CatalogEntry, StackRuntime
from aegis_platform.delivery import admit_release
from aegis_platform.release import file_hash
from aegis_platform.stack import StackDefinition
from aegis_platform.stack_plan import DEPENDENCY_IMAGES, budget
from aegis_platform.stack_release import StackReleaseEvidence, parse_release, verify_stack_bundle
from tests.release_fixtures import release_fixture
from tests.test_delivery import policy as policy
from tests.test_delivery import release_case as release_case

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "charts/multi-service/1.0.0"


def definition():
    return StackDefinition(
        primary_service="catalog",
        services={
            "catalog": {
                "env": {"CACHE_TTL_SECONDS": "30"},
                "secret_env": {"DATABASE_URL": "database-url"},
            },
            "orders": {
                "replicas": 2,
                "service_env": {"CATALOG_URL": "catalog"},
                "secret_env": {"DATABASE_URL": "database-url"},
            },
        },
    )


def test_stack_budget_accounts_for_rollout_surges_and_namespace_root_ca():
    profile = json.loads((ROOT / "policies/bootstrap.json").read_text())["resource_profiles"][
        "small"
    ]
    quota = budget(definition(), profile)
    assert quota["pods"] == "9"
    assert quota["count/configmaps"] == "2"
    assert quota["services"] == "5"
    assert quota["persistentvolumeclaims"] == "2"
    assert quota["requests.storage"] == "2Gi"


def stack_fixture(tmp_path):
    original = release_fixture(tmp_path)
    raw = original["evidence"].model_dump()
    component = deepcopy(raw)
    component["service_name"] = "orders"
    repository = original["context"].image_name + "/orders"
    component["image"] = repository + "@" + original["root"]
    for child in component["platforms"].values():
        child["service_name"] = "orders"
        child["image"] = repository + "@" + child["image"].split("@")[1]
    bundle = tmp_path / "stack.tar"
    with tarfile.open(bundle, "w") as archive:
        for name in ("catalog", "orders"):
            archive.add(original["bundle"], arcname=f"services/{name}.oci.tar")
    stack = definition()
    raw.update(
        schema_version=4,
        stack=stack.model_dump(),
        stack_sha256=digest(stack.model_dump()),
        primary_bundle_sha256=raw["bundle_sha256"],
        bundle_sha256=file_hash(bundle),
        components={"orders": component},
        dependency_images=DEPENDENCY_IMAGES,
        integration_tests="passed",
    )
    return StackReleaseEvidence.model_validate(raw), bundle


@pytest.mark.parametrize(
    "mutation",
    [
        "traversal",
        "reserved",
        "missing_url",
        "secret_literal",
        "duplicate_env",
        "too_many",
        "probe_escape",
    ],
)
def test_definition_rejects_unsafe_or_unbounded_topologies(mutation):
    raw = definition().model_dump()
    service = raw["services"]["catalog"]
    if mutation == "traversal":
        service["context"] = "../private"
    if mutation == "reserved":
        raw["services"]["postgres"] = service
    if mutation == "missing_url":
        service["service_env"] = {"OTHER_URL": "unknown"}
    if mutation == "secret_literal":
        service["env"]["API_KEY"] = "a-real-looking-value"
    if mutation == "duplicate_env":
        service["env"]["DATABASE_URL"] = "anything"
    if mutation == "too_many":
        raw["services"] = {f"service-{i}": service for i in range(9)}
    if mutation == "probe_escape":
        service["health_path"] = "/%2e%2e/config"
    with pytest.raises(ValidationError):
        StackDefinition.model_validate(raw)


def test_complete_archive_verified_before_any_consumer_mutation(tmp_path):
    evidence, bundle = stack_fixture(tmp_path)
    seen = []
    verify_stack_bundle(bundle, evidence, consume=lambda name, *_: seen.append(name))
    assert set(seen) == {"catalog", "orders"}
    assert parse_release(canonical(evidence.model_dump())) == evidence
    damaged = tmp_path / "damaged.tar"
    with tarfile.open(damaged, "w") as archive:
        for name in ("catalog", "orders"):
            raw = (tmp_path / "image.oci.tar").read_bytes() if name == "catalog" else b"corrupt"
            member = tarfile.TarInfo(f"services/{name}.oci.tar")
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    evidence.bundle_sha256 = file_hash(damaged)
    seen.clear()
    with pytest.raises(ValueError, match="checksum"):
        verify_stack_bundle(damaged, evidence, consume=lambda name, *_: seen.append(name))
    assert seen == []


@pytest.mark.parametrize("mutation", ["missing", "source", "service", "dependency", "topology"])
def test_stack_receipt_rejects_cross_source_or_incomplete_evidence(tmp_path, mutation):
    evidence, _ = stack_fixture(tmp_path)
    raw = evidence.model_dump()
    if mutation == "missing":
        raw["components"] = {}
    if mutation == "source":
        raw["components"]["orders"]["source_commit"] = "d" * 40
    if mutation == "service":
        raw["components"]["orders"]["service_name"] = "wrong"
    if mutation == "dependency":
        raw["dependency_images"]["redis"] = "redis:latest"
    if mutation == "topology":
        raw["stack"]["services"]["orders"]["replicas"] = 1
    with pytest.raises(ValueError):
        StackReleaseEvidence.model_validate(raw)


def test_stack_release_requires_distinct_workflows_and_matching_catalog(
    tmp_path,
    release_case,
    policy,
):
    evidence, _ = stack_fixture(tmp_path)
    entry, _, release, repository, run = release_case
    raw_entry = entry.model_dump()
    raw_entry["runtime"] = {
        "profile_id": "python312-multiservice",
        "container_port": 8080,
        "health_path": "/health",
        "resource_profile_id": "small",
        "stack": definition().model_dump(),
        "credentials_secret": entry.app_id + "-runtime",
    }
    entry = CatalogEntry.model_validate(raw_entry)
    with pytest.raises(ValueError, match="both approved"):
        admit_release(entry, canonical(evidence.model_dump()), release, repository, run, policy)
    for workflow in run["referenced_workflows"]:
        workflow["path"] = workflow["path"].replace("python-web-", "python-stack-")
    assert (
        admit_release(entry, canonical(evidence.model_dump()), release, repository, run, policy)
        == evidence
    )
    changed = entry.model_copy(deep=True)
    changed.runtime.stack.services["orders"].replicas = 1
    with pytest.raises(ValueError, match="topology"):
        admit_release(changed, canonical(evidence.model_dump()), release, repository, run, policy)


def test_helm_bootstrap_secret_environment_and_storage_boundaries(tmp_path, release_case, policy):
    evidence, _ = stack_fixture(tmp_path)
    original = release_case[0].model_dump()
    original["runtime"] = StackRuntime(
        container_port=8080,
        health_path="/health",
        resource_profile_id="small",
        stack=definition(),
        credentials_secret="orders-api-runtime",
        environment={"catalog": {"CACHE_TTL_SECONDS": "45"}},
    ).model_dump()
    original["versions"]["chart_sha256"] = chart_identity(CHART)["sha256"]
    entry = CatalogEntry.model_validate(original)
    target = entry.environments["dev"]
    loaded = Catalog(
        [entry],
        [
            Cluster(
                cluster_id=target.cluster_id,
                cluster_uid=target.cluster_uid,
                gitops_repository_id=target.gitops_repository_id,
                profile_id="small",
            )
        ],
        CatalogPolicy(
            schema_version=1,
            resource_profile_ids=["small"],
            runtime_profile_ids=["python312-multiservice"],
            environment_branches={"dev": "main", "staging": "staging", "prod": "prod"},
            production_human_review_required=True,
            protected_sync_mode="operator",
            max_applications=100,
        ),
    )
    bootstrap = json.loads((ROOT / "policies/bootstrap.json").read_text())
    values = release_values(loaded, entry.app_id, "dev", evidence, bootstrap)
    path = tmp_path / "values.json"
    path.write_text(json.dumps(values))
    rendered = subprocess.check_output(
        ["helm", "template", entry.app_id, CHART, "-f", path], text=True
    )
    objects = [o for o in yaml.safe_load_all(rendered) if o]
    assert len([o for o in objects if o["kind"] == "StatefulSet"]) == 2
    assert len([o for o in objects if o["kind"] == "PersistentVolumeClaim"]) == 2
    assert not any(o["kind"] in {"Secret", "Namespace", "ClusterRole"} for o in objects)
    catalog = next(
        o
        for o in objects
        if o["kind"] == "Deployment" and o["metadata"]["name"].endswith("-catalog")
    )
    env = catalog["spec"]["template"]["spec"]["containers"][0]["env"]
    assert {e["name"]: e.get("value") for e in env}["CACHE_TTL_SECONDS"] == "45"
    assert (
        next(e for e in env if e["name"] == "DATABASE_URL")["valueFrom"]["secretKeyRef"]["name"]
        == "orders-api-runtime"
    )
    assert all(o["metadata"]["namespace"] == target.namespace for o in objects)
    context = {
        "gitops_repository": "example/aegis-gitops",
        **{k: getattr(target, k) for k in ("gitops_repository_id", "cluster_id", "cluster_uid")},
    }
    plan = bootstrap_plan(loaded, entry.app_id, "dev", context, bootstrap, CHART)
    project = plan[f"argocd/projects/{target.argo_project}.json"]
    assert "Secret" not in {r["kind"] for r in project["spec"]["namespaceResourceWhitelist"]}
    assert (
        plan[f"argocd/applications/{target.argo_application}.json"]["spec"]["source"]["path"]
        == "charts/multi-service/1.0.0"
    )
    assert all(
        not s["spec"].get("externalIPs") and s["spec"]["type"] == "ClusterIP"
        for s in objects
        if s["kind"] == "Service"
    )


def test_public_override_cannot_select_secrets_or_unknown_services():
    base = {
        "container_port": 8080,
        "health_path": "/health",
        "resource_profile_id": "small",
        "stack": definition().model_dump(),
        "credentials_secret": "orders-api-runtime",
    }
    for overrides in (
        {"catalog": {"DATABASE_URL": "bad"}},
        {"unknown": {"CACHE_TTL_SECONDS": "2"}},
        {"catalog": {"CACHE_TTL_SECONDS": "redis://:private@cache:6379/0"}},
    ):
        with pytest.raises(ValidationError):
            StackRuntime.model_validate({**base, "environment": overrides})
