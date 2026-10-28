import json

import pytest

from aegis_platform.canonical import digest
from aegis_platform.grafana import ASSETS, BASE, dashboards, grafana_plan
from aegis_platform.observability_policy import ObservabilityPolicy


def policy():
    from pathlib import Path

    return ObservabilityPolicy.model_validate_json(Path("policies/observability.json").read_text())


def test_candidate_is_separate_deterministic_and_requires_review():
    p = policy()
    first = grafana_plan(p, "a" * 40)
    assert first == grafana_plan(p, "a" * 40)
    review = first[BASE + "/review.json"]
    assert review["requires_independent_operator_review"]
    assert not review["developer_access"] and not review["production_ready"]
    resources = {k: v for k, v in first.items() if not k.endswith("review.json")}
    assert review["resources_hash"] == digest(resources)
    with pytest.raises(ValueError):
        grafana_plan(p, "main")
    assert all(v.get("kind") != "Secret" for v in first.values())
    assert all("argoproj.io" not in str(v.get("apiVersion")) for v in first.values())


def test_runtime_never_exposes_admin_or_query_credentials_to_browser():
    objects = list(grafana_plan(policy(), "a" * 40).values())
    deployment = next(o for o in objects if o.get("kind") == "Deployment")
    spec = deployment["spec"]["template"]["spec"]
    assert not spec["automountServiceAccountToken"]
    container = spec["containers"][0]
    env = {e["name"]: e for e in container["env"]}
    assert env["AEGIS_QUERY_PASSWORD"]["valueFrom"]["secretKeyRef"]["key"] == "query-password"
    for key in [
        "GF_AUTH_ANONYMOUS_ENABLED",
        "GF_SECURITY_ALLOW_EMBEDDING",
        "GF_USERS_ALLOW_SIGN_UP",
        "GF_UNIFIED_ALERTING_ENABLED",
    ]:
        assert env[key]["value"] == "false"
    assert container["securityContext"]["readOnlyRootFilesystem"]
    assert next(o for o in objects if o.get("kind") == "Service")["spec"]["type"] == "ClusterIP"
    assert next(o for o in objects if o.get("kind") == "NetworkPolicy")["spec"]["ingress"] == []


def test_provisioning_uses_authenticated_gateways_and_bounded_correlation():
    sources = json.loads((ASSETS / "datasources.yaml").read_text())["datasources"]
    assert len(sources) == 3
    for ds in sources:
        assert ds["access"] == "proxy" and ds["basicAuth"] and not ds["editable"]
        assert ds["url"].endswith(".svc.cluster.local:8080")
        assert ds["secureJsonData"]["basicAuthPassword"] == "$AEGIS_QUERY_PASSWORD"
    assert sources[1]["jsonData"]["maxLines"] == 200
    derived = sources[1]["jsonData"]["derivedFields"][0]
    assert derived["datasourceUid"] == "aegis-tempo"
    assert derived["url"] == "$${__value.raw}"


def test_dashboards_are_scoped_with_no_fabricated_future_metrics():
    boards = dashboards("actual-cluster-uid")
    assert len(boards) == 6
    uids = set()
    for board in boards.values():
        uids.add(board["uid"])
        assert not board["editable"]
        assert board["templating"]["list"][0]["query"] == "actual-cluster-uid"
        ids = [p["id"] for p in board["panels"]]
        assert len(ids) == len(set(ids))
        for panel in board["panels"]:
            if panel["type"] == "text":
                continue
            for target in panel["targets"]:
                assert 'aegis_cluster_uid="$cluster"' in target["expr"]
    assert len(uids) == 6
    assert all(p["type"] == "text" for p in boards["agentops.json"]["panels"])
    assert "Future instrumentation" in json.dumps(boards["delivery.json"])
