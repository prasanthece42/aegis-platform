from copy import deepcopy
from pathlib import Path

import pytest

from aegis_platform.catalog import Catalog, CatalogPolicy, Cluster, checked_path, load_catalog
from aegis_platform.contracts import CatalogEntry


def catalog(entries, cluster, policy):
    return Catalog(
        [CatalogEntry.model_validate(e) for e in entries],
        [Cluster.model_validate(cluster)],
        CatalogPolicy.model_validate(policy),
    )


def test_two_apps_have_independent_destinations(example_entries, cluster_record, policy_record):
    loaded = catalog(example_entries, cluster_record, policy_record)
    a = loaded.resolve("orders-api", "dev")
    b = loaded.resolve("payments-api", "dev")
    assert a["target"]["namespace"] != b["target"]["namespace"]
    changed = deepcopy(example_entries)
    changed[1]["runtime"]["container_port"] = 8080
    reloaded = catalog(changed, cluster_record, policy_record)
    assert a == reloaded.resolve("orders-api", "dev")
    assert b["catalog_entry_hash"] != reloaded.resolve("payments-api", "dev")["catalog_entry_hash"]


@pytest.mark.parametrize(
    "change",
    [
        "duplicate_app",
        "duplicate_source",
        "namespace",
        "path",
        "branch",
        "cluster_uid",
        "repository",
        "controller",
        "profile",
    ],
)
def test_catalog_rejects_foreign_or_ambiguous_bindings(
    example_entries, cluster_record, policy_record, change
):
    entries = deepcopy(example_entries)
    first, second = entries
    target = first["environments"]["dev"]
    if change == "duplicate_app":
        second["app_id"] = first["app_id"]
    elif change == "duplicate_source":
        second["source"]["repository_id"] = first["source"]["repository_id"]
    elif change == "namespace":
        target["namespace"] = "kube-system"
    elif change == "path":
        target["values_path"] = "applications/payments-api/environments/dev/values.yaml"
    elif change == "branch":
        target["gitops_branch"] = "prod"
    elif change == "cluster_uid":
        target["cluster_uid"] = "rebuilt-cluster"
    elif change == "repository":
        target["gitops_repository_id"] = "999"
    elif change == "controller":
        target["argo_application"] = "payments-api-dev"
    else:
        first["runtime"]["resource_profile_id"] = "unbounded"
    with pytest.raises(ValueError):
        catalog(entries, cluster_record, policy_record)


def test_delivery_diff_cannot_touch_another_app_or_protected_configuration(
    example_entries, cluster_record, policy_record
):
    loaded = catalog(example_entries, cluster_record, policy_record)
    loaded.check_delivery_paths(
        "orders-api",
        "dev",
        "release-123-1",
        [
            "applications/orders-api/environments/dev/values.yaml",
            "applications/orders-api/environments/dev/release.json",
            "applications/orders-api/releases/release-123-1.json",
        ],
    )
    for path in [
        "applications/payments-api/environments/dev/values.yaml",
        "applications/orders-api/environments/prod/values.yaml",
        "argocd/applications/orders-api-dev.yaml",
        "policies/catalog.json",
    ]:
        with pytest.raises(ValueError):
            loaded.check_delivery_paths("orders-api", "dev", "release-123-1", [path])


def test_unenabled_environment_and_production_policy_cannot_be_bypassed(
    example_entries, cluster_record, policy_record
):
    loaded = catalog(example_entries, cluster_record, policy_record)
    with pytest.raises(ValueError):
        loaded.resolve("orders-api", "prod")
    with pytest.raises(ValueError):
        CatalogPolicy.model_validate({**policy_record, "production_human_review_required": False})
    with pytest.raises(ValueError):
        CatalogPolicy.model_validate({**policy_record, "protected_sync_mode": "automatic"})


@pytest.mark.parametrize(
    "path", ["../foreign", "/absolute", "a//b", "a/./b", "a/../b", "a\\b", "a/%2f/b", "a\nb"]
)
def test_repository_paths_are_normalized(path):
    with pytest.raises(ValueError):
        checked_path(path)


def test_active_catalog_has_no_fabricated_enrollments():
    root = Path(__file__).resolve().parents[1]
    loaded = load_catalog(root / "catalog", root / "policies/catalog.json")
    assert all(
        not cluster.cluster_uid.startswith("EXAMPLE") for cluster in loaded.clusters.values()
    )
    assert all(
        cluster.cluster_uid != "demo-cluster-not-enrolled" for cluster in loaded.clusters.values()
    )


def test_loader_rejects_symlink_records(tmp_path, policy_record):
    import json

    root = tmp_path / "catalog"
    (root / "apps").mkdir(parents=True)
    (root / "clusters").mkdir()
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(policy_record))
    (root / "apps/foreign.json").symlink_to(policy)
    with pytest.raises(ValueError):
        load_catalog(root, policy)
