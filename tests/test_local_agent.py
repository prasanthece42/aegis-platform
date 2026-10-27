from copy import deepcopy

import pytest

from aegis_platform.local_agent import LocalAgent, LocalConfig, normalize_bundle
from aegis_platform.release import verify_oci_bundle
from tests.release_fixtures import release_fixture


def test_kind_transport_annotations_preserve_the_complete_registry_graph(tmp_path):
    fixture = release_fixture(tmp_path)
    output = tmp_path / "import.tar"
    normalize_bundle(fixture["bundle"], output, fixture["evidence"])
    verify_oci_bundle(output, fixture["root"], fixture["children"])


def test_wrong_cluster_uid_stops_before_operator_or_docker_access(monkeypatch):
    from types import SimpleNamespace

    from aegis_platform import local_agent

    config = LocalConfig(
        kubeconfig="/explicit/config",
        context="kind-aegis-dev",
        cluster_id="kind-local",
        cluster_uid="enrolled-uid",
        kind_binary="/explicit/kind",
        kind_cluster="aegis-dev",
        kind_node="aegis-dev-control-plane",
    )
    target = SimpleNamespace(cluster_id="kind-local", cluster_uid="enrolled-uid")
    entry = SimpleNamespace(environments={"dev": target})
    agent = LocalAgent(config, None)
    monkeypatch.setattr(
        local_agent,
        "command",
        lambda *_: '{"clusters":[{"cluster":{"server":"https://127.0.0.1:1234"}}]}',
    )
    monkeypatch.setattr(agent, "get", lambda *_: {"metadata": {"uid": "different-cluster"}})
    with pytest.raises(ValueError, match="namespace UID"):
        agent.enroll(entry, "dev", None)
    foreign = deepcopy(entry)
    foreign.environments["dev"].cluster_uid = "other"
    with pytest.raises(ValueError, match="target differs"):
        agent.enroll(foreign, "dev", None)
