import json
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from aegis_platform.observability import AUTH_SECRET, observability_plan
from aegis_platform.observability_policy import (
    IMAGE_REPOSITORIES,
    OBS_NAMESPACE,
    ObservabilityPolicy,
    password_fingerprint,
    query_password,
)


@pytest.fixture
def telemetry_policy():
    return ObservabilityPolicy.model_validate(
        json.loads(Path("policies/observability.json").read_text())
    )


def test_query_capability_is_separate_from_oauth_and_bound_to_cluster():
    seed = "synthetic-test-oauth-secret-0123456789"
    first = query_password(seed, "cluster-one")
    assert len(first) == 64 and first != seed
    assert first != query_password(seed, "cluster-two")
    assert first != query_password(seed + "new", "cluster-one")
    assert password_fingerprint(first).startswith("sha256:")
    with pytest.raises(ValueError):
        query_password("short", "cluster-one")


@pytest.mark.parametrize(
    "mutation",
    ["tag", "unknown_image", "private_material", "node_name", "public_ip", "placeholder_digest"],
)
def test_public_policy_rejects_unreviewable_images_or_wrong_node_identity(
    telemetry_policy, mutation
):
    data = telemetry_policy.model_dump()
    if mutation == "tag":
        data["images"]["loki"] = IMAGE_REPOSITORIES["loki"] + ":latest"
    elif mutation == "unknown_image":
        data["images"]["loki"] = "attacker.example/loki@sha256:" + "a" * 64
    elif mutation == "private_material":
        data["kubelet_ca_pem"] += "\n-----BEGIN PRIVATE KEY-----\n"
    elif mutation == "node_name":
        data["node_name"] = "different-node"
    elif mutation == "public_ip":
        data["node_ip"] = "8.8.8.8"
    elif mutation == "placeholder_digest":
        data["images"]["loki"] = IMAGE_REPOSITORIES["loki"] + "@sha256:" + "0" * 64
    with pytest.raises((ValidationError, ValueError)):
        ObservabilityPolicy.model_validate(data)


def test_rendered_stack_has_no_credentials_or_workload_write_rbac(telemetry_policy):
    files = observability_plan(telemetry_policy, "a" * 40)
    objects = [r for r in files.values() if isinstance(r, dict) and "kind" in r]
    assert all(r["kind"] != "Secret" for r in objects)
    role = next(r for r in objects if r["kind"] == "ClusterRole")
    for rule in role["rules"]:
        assert set(rule["verbs"]) <= {"get", "list", "watch"}
        assert not set(rule["resources"]) & {"secrets", "pods/exec", "pods/attach", "nodes/proxy"}
    for obj in objects:
        if obj["kind"] == "Deployment":
            spec = obj["spec"]["template"]["spec"]
            assert not spec.get("hostNetwork") and not spec.get("hostPID")
            assert all("hostPath" not in volume for volume in spec["volumes"])
            assert spec["automountServiceAccountToken"] == (
                obj["metadata"]["name"] in {"collector", "container-log-reader"}
            )
            for container in spec["containers"]:
                assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
                assert container["securityContext"]["readOnlyRootFilesystem"]
                assert container["image"] in telemetry_policy.images.values()
        elif obj["kind"] == "Service":
            assert obj["spec"]["type"] == "ClusterIP"
        assert obj["metadata"].get("namespace") in {None, OBS_NAMESPACE, "argocd"}
    encoded = json.dumps(files)
    assert AUTH_SECRET in encoded
    assert (
        query_password("synthetic-test-oauth-secret-0123456789", telemetry_policy.cluster_uid)
        not in encoded
    )


def test_storage_queries_are_authenticated_even_without_network_policy(telemetry_policy):
    files = observability_plan(telemetry_policy, "a" * 40)
    maps = [
        v
        for v in files.values()
        if isinstance(v, dict) and v.get("kind") == "ConfigMap" and "nginx.conf" in v["data"]
    ]
    for config in maps:
        nginx = config["data"]["nginx.conf"]
        assert "auth_basic_user_file /run/telemetry-auth/query.htpasswd" in nginx
        assert "access_log off" in nginx
        for protocol in ["client_body", "proxy", "fastcgi", "uwsgi", "scgi"]:
            assert f"{protocol}_temp_path /tmp/" in nginx
        assert "$request_method != GET" in nginx
        assert "location / { return 404; }" in nginx
    for name in ["loki", "tempo", "prometheus", "alertmanager"]:
        config = next(c for c in maps if c["metadata"]["name"] == name + "-config")
        deployment = next(
            v
            for v in files.values()
            if isinstance(v, dict)
            and v.get("kind") == "Deployment"
            and v["metadata"]["name"] == name
        )
        if name in ["loki", "tempo"]:
            assert (
                json.loads(config["data"]["config.yaml"])["server"]["http_listen_address"]
                == "127.0.0.1"
            )
        else:
            assert any(
                "127.0.0.1:" in arg
                for arg in deployment["spec"]["template"]["spec"]["containers"][0]["command"]
            )


def test_app_namespace_identity_is_replaced_and_kubelet_tls_is_verified(telemetry_policy):
    from aegis_platform.observability_config import collector_config

    config = collector_config(telemetry_policy)
    app = config["service"]["pipelines"]["traces"]["processors"]
    assert (
        app.index("transform/identity") < app.index("k8s_attributes") < app.index("filter/unknown")
    )
    association = config["processors"]["k8s_attributes"]["pod_association"]
    assert association == [{"sources": [{"from": "connection"}]}]
    tls = config["receivers"]["kubelet_stats"]
    assert tls["insecure_skip_verify"] is False and tls["ca_file"] == "/etc/aegis/kubelet-ca.pem"
    assert "${env:K8S_NODE_NAME}" in tls["endpoint"]
    assert "debug" not in config["exporters"]


def test_operator_review_retains_exact_policy_and_revision(telemetry_policy):
    from aegis_platform.canonical import digest

    files = observability_plan(telemetry_policy, "a" * 40)
    record = next(v for path, v in files.items() if path.endswith("/review.json"))
    assert record["requires_independent_operator_review"] is True
    assert record["platform_revision"] == "a" * 40
    assert record["policy_hash"] == digest(telemetry_policy.model_dump())
    changed = deepcopy(telemetry_policy)
    changed.retention_hours = 24
    assert observability_plan(changed, "a" * 40) == files
    with pytest.raises(ValueError):
        observability_plan(telemetry_policy, "main")
