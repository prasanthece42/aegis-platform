import base64
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from aegis_platform.canonical import canonical, digest
from aegis_platform.contracts import CatalogEntry
from aegis_platform.delivery import DeliveryPolicy
from aegis_platform.portal_system import BASE, PortalSystemPolicy, system_plan, validate_credentials
from aegis_platform.release import ReleaseContext
from aegis_platform.request import Issuer, RequestTrust
from tests import release_fixtures
from tooling import portal_system


@pytest.fixture
def system_case(tmp_path, monkeypatch):
    ctx = ReleaseContext(
        app_id="aegis-portal",
        source_repository="example/aegis-portal",
        source_repository_id="101",
        source_commit="d" * 40,
        workflow_run_id="123",
        run_attempt="1",
        platform_commit="a" * 40,
    )
    monkeypatch.setattr(release_fixtures, "context", lambda: ctx)
    evidence = release_fixtures.release_fixture(tmp_path)["evidence"]
    data = json.loads(Path("examples/catalog/apps/orders-api.json").read_text())
    data.update(app_id="aegis-portal", display_name="Portal")
    data["source"].update(name="aegis-portal")
    entry = CatalogEntry.model_validate(data)
    configuration = json.loads(Path("policies/portal-system.json").read_text())["configuration"]
    configuration.update(
        public_origin="https://portal.example.invalid",
        app_id="99",
        client_id="fixture",
        platform_repository="example/aegis-platform",
        platform_repository_id="400",
        platform_installation_id="201",
        platform_bot_user_id="902",
        source_installation_ids=["201"],
        onboarding_user_ids=["301"],
        allowed_owner_user_ids=["301"],
        cluster_id=entry.environments["dev"].cluster_id,
        cluster_uid=entry.environments["dev"].cluster_uid,
        gitops_repository="example/aegis-gitops",
        gitops_repository_id="401",
        gitops_installation_id="202",
        issuer_id="fixture-portal",
        signing_key_id="fixture-key",
    )
    policy = PortalSystemPolicy(
        source_repository_id="101",
        operator_user_ids=["301"],
        configuration=configuration,
        signing_public_key_base64="a" * 43 + "=",
    )
    bootstrap = json.loads(Path("policies/bootstrap.json").read_text())
    delivery = DeliveryPolicy(
        platform_repository="example/aegis-platform",
        platform_repository_id="400",
        gitops_repository="example/aegis-gitops",
        gitops_repository_id="401",
        bootstrap_policy_hash=digest(bootstrap),
        workflow_bot_user_ids=["41898282"],
        observer_user_ids=["301"],
        production_reviewer_user_ids=["301"],
    )
    return entry, policy, delivery, bootstrap, canonical(evidence.model_dump()), "700"


def test_portal_system_has_no_kubernetes_credential_or_secret_values_in_git(system_case):
    files = system_plan(*system_case)
    assert len(files) == 11
    assert all(
        not isinstance(value, dict) or value.get("kind") != "Secret" for value in files.values()
    )
    deployment = files[BASE + "/manifests/deployment.json"]
    pod = deployment["spec"]["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False
    assert pod["securityContext"]["runAsUser"] == pod["securityContext"]["fsGroup"] == 10001
    assert deployment["spec"]["replicas"] == 1
    assert deployment["spec"]["strategy"]["type"] == "Recreate"
    container = pod["containers"][0]
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["readinessProbe"]["httpGet"]["path"] == "/ready"
    assert container["livenessProbe"]["httpGet"]["path"] == "/health"
    assert container["env"][-1]["valueFrom"]["secretKeyRef"] == {
        "name": "aegis-portal-runtime",
        "key": "client-secret",
    }
    credentials = next(
        volume["secret"] for volume in pod["volumes"] if volume["name"] == "credentials"
    )
    assert credentials["defaultMode"] == 0o440
    assert {item["key"] for item in credentials["items"]} == {
        "github-app.pem",
        "request-signing.pem",
    }
    app = files[BASE + "/bootstrap/application.json"]
    assert app["spec"]["source"]["targetRevision"] == "platform-system"
    assert "CreateNamespace=true" not in app["spec"]["syncPolicy"]["syncOptions"]
    assert files[BASE + "/bootstrap/project.json"]["spec"]["clusterResourceWhitelist"] == []


@pytest.mark.parametrize("mutation", ["source", "cluster", "port", "policy"])
def test_portal_system_rejects_unapproved_bindings(system_case, mutation):
    entry, policy, delivery, bootstrap, raw, release_id = system_case
    if mutation == "source":
        policy.source_repository_id = "999"
    elif mutation == "cluster":
        policy.configuration.cluster_uid = "another-cluster"
    elif mutation == "port":
        entry.runtime.container_port = 8080
    else:
        bootstrap["pod_security_version"] = "v1.34"
    with pytest.raises(ValueError):
        system_plan(entry, policy, delivery, bootstrap, raw, release_id)


def test_operator_private_keys_must_match_the_reviewed_public_issuer(system_case):
    policy = system_case[1]
    app = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signing = ed25519.Ed25519PrivateKey.generate()

    def private(key):
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    public = base64.b64encode(
        signing.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode()
    policy.signing_public_key_base64 = public
    trust = RequestTrust(
        platform_repository_id="400",
        issuers=[
            Issuer(
                issuer_id="fixture-portal",
                key_id="fixture-key",
                public_key_base64=public,
                bot_user_id="902",
                active=True,
            )
        ],
    )
    validate_credentials(
        private(app), private(signing), "fixture-private-client-secret", policy, trust
    )
    with pytest.raises(ValueError):
        validate_credentials(
            private(app),
            private(ed25519.Ed25519PrivateKey.generate()),
            "fixture-private-client-secret",
            policy,
            trust,
        )
    with pytest.raises(ValueError):
        validate_credentials(
            private(signing), private(signing), "fixture-private-client-secret", policy, trust
        )


@pytest.mark.parametrize("review", ["missing", "human", "bot", "tampered"])
def test_system_gate_requires_exact_manifests_and_current_head_human_review(
    system_case, monkeypatch, review
):
    expected = system_plan(*system_case)
    policy, delivery = system_case[1:3]
    actual = {
        path: value if isinstance(value, bytes) else canonical(value)
        for path, value in expected.items()
    }
    if review == "tampered":
        resource = deepcopy(expected[BASE + "/manifests/deployment.json"])
        resource["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"] = (
            True
        )
        actual[BASE + "/manifests/deployment.json"] = canonical(resource)
    pr = {
        "state": "open",
        "merged_at": None,
        "draft": False,
        "head": {"sha": "a" * 40, "repo": {"id": 401}},
        "base": {"sha": "b" * 40, "ref": "platform-system", "repo": {"id": 401}},
        "user": {"id": 902, "type": "Bot"},
        "changed_files": len(expected),
    }
    observations = []

    def repo(method, _path, payload=None):
        if method == "POST":
            observations.append(payload)
            return {}
        return pr

    def pages(path):
        if path.endswith("/reviews"):
            if review in {"human", "bot"}:
                return [
                    {
                        "id": 1,
                        "state": "APPROVED",
                        "commit_id": "a" * 40,
                        "user": {"id": 301, "type": "User" if review == "human" else "Bot"},
                    }
                ]
            return []
        return [{"filename": path, "status": "added"} for path in expected]

    engine = SimpleNamespace(
        gitops=SimpleNamespace(repo=repo, pages=pages, file=lambda path, _ref: actual[path])
    )
    monkeypatch.setattr(portal_system, "admitted_plan", lambda *_: (expected, policy, delivery))
    monkeypatch.setattr(portal_system, "tree_files", lambda *_: actual)
    if review == "tampered":
        with pytest.raises(ValueError):
            portal_system.check_pr(engine, 1)
        assert observations[-1]["state"] == "failure"
    else:
        portal_system.check_pr(engine, 1)
        assert observations[-1]["state"] == ("success" if review == "human" else "pending")


def test_upload_storage_is_explicit_and_persistent(system_case):
    from aegis_platform.portal_system import PortalUploadPolicy

    entry, policy, delivery, bootstrap, raw, release_id = system_case
    baseline = system_plan(*system_case)
    assert not any("pvc" in path for path in baseline)
    policy.uploads = PortalUploadPolicy(
        owner="prasanthece42", owner_type="User", storage_class="standard"
    )
    files = system_plan(entry, policy, delivery, bootstrap, raw, release_id)
    claim = files[BASE + "/manifests/uploads-pvc.json"]
    assert claim["spec"]["accessModes"] == ["ReadWriteOnce"]
    assert claim["spec"]["resources"]["requests"]["storage"] == "1Gi"
    assert claim["metadata"]["annotations"]["argocd.argoproj.io/sync-options"] == "Prune=false"
    pod = files[BASE + "/manifests/deployment.json"]["spec"]["template"]["spec"]
    assert pod["containers"][0]["securityContext"]["readOnlyRootFilesystem"]
    env = {item["name"]: item.get("value") for item in pod["containers"][0]["env"]}
    assert env["AEGIS_UPLOAD_OWNER"] == "prasanthece42"
    assert env["AEGIS_UPLOAD_OWNER_TYPE"] == "User"
    assert env["AEGIS_UPLOAD_DATA"] == "/var/lib/aegis/uploads/uploads.sqlite3"
    volume = next(v for v in pod["volumes"] if v["name"] == "uploads")
    assert volume["persistentVolumeClaim"]["claimName"] == "aegis-portal-uploads"
    whitelist = files[BASE + "/bootstrap/project.json"]["spec"]["namespaceResourceWhitelist"]
    assert {"group": "", "kind": "PersistentVolumeClaim"} in whitelist
    assert files[BASE + "/bootstrap/quota.json"]["spec"]["hard"]["requests.storage"] == "1Gi"


def test_separate_upload_policy_keeps_legacy_system_configuration_compatible(system_case):
    from aegis_platform.portal_system import PortalSystemPolicy

    policy = system_case[1]
    original = policy.model_dump()
    original.pop("uploads")
    upload = {"owner": "prasanthece42", "owner_type": "User", "storage_class": "standard"}

    class Platform:
        def file(self, path, revision):
            assert revision == "a" * 40
            return canonical(upload if path.endswith("portal-uploads.json") else original)

        def repo(self, method, path):
            assert method == "GET" and path == "contents/policies?ref=" + "a" * 40
            return [{"path": "policies/portal-uploads.json"}]

    parsed = portal_system.reviewed_system_policy(Platform(), "a" * 40)
    assert parsed.uploads.owner == "prasanthece42"
    assert PortalSystemPolicy.model_validate(original).uploads is None
    files = system_plan(*system_case)
    assert files[BASE + "/review.json"]["policy_hash"] == digest(original)
