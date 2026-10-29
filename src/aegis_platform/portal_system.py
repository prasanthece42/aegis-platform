"""Operator-controlled portal service, independently recoverable from the portal UI.

Only public configuration and Secret references enter Git. Secret values are supplied
by the enrolled local operator, never by a portal request or a hosted workflow.
"""

import base64
import json
from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from pydantic import Field, model_validator

from aegis_platform.bootstrap import validate_profile
from aegis_platform.canonical import digest, strict_json
from aegis_platform.contracts import CatalogEntry, Contract, Identifier
from aegis_platform.delivery import DeliveryPolicy, receipt_hash
from aegis_platform.portal_config import LiveConfig
from aegis_platform.release import ReleaseEvidence
from aegis_platform.request import RequestTrust

NAMESPACE = "aegis-portal-system"
BASE = "platform-services/aegis-portal"
RUNTIME_CONTRACT = {
    "schema_version": 1,
    "readiness_path": "/ready",
    "liveness_path": "/health",
    "signing_key_binding": "Ed25519 public key",
    "kubernetes_credentials": False,
}


UPLOAD_RUNTIME_CONTRACT = {**RUNTIME_CONTRACT, "zip_uploads": 1}


class PortalUploadPolicy(Contract):
    owner: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")
    owner_type: Literal["User", "Organization"]
    visibility: Literal["public"] = "public"
    storage_class: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]{0,62}$")
    storage_size: Literal["1Gi"] = "1Gi"


class PortalSystemPolicy(Contract):
    schema_version: Literal[1] = 1
    branch: Literal["platform-system"] = "platform-system"
    namespace: Literal["aegis-portal-system"] = NAMESPACE
    operator_user_ids: list[Identifier] = Field(min_length=1)
    source_repository_id: Identifier
    signing_public_key_base64: str = Field(min_length=44, max_length=44)
    configuration: LiveConfig
    uploads: PortalUploadPolicy | None = None

    @model_validator(mode="after")
    def delivery_is_bound(self):
        if not self.configuration.delivery_workflow_commit:
            raise ValueError("The system portal requires an explicitly bound delivery workflow")
        return self


def validate_credentials(
    app_key: bytes,
    signing_key: bytes,
    client_secret: str,
    policy: PortalSystemPolicy,
    trust: RequestTrust,
):
    app = serialization.load_pem_private_key(app_key, password=None)
    signing = serialization.load_pem_private_key(signing_key, password=None)
    if not isinstance(app, RSAPrivateKey) or app.key_size < 2048:
        raise ValueError("Expected a GitHub App RSA key of at least 2048 bits")
    if not isinstance(signing, Ed25519PrivateKey) or not client_secret.strip():
        raise ValueError("Expected a separate Ed25519 signing key and OAuth client secret")
    public = base64.b64encode(
        signing.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode()
    config = policy.configuration
    matching = [
        issuer
        for issuer in trust.issuers
        if (
            issuer.active
            and issuer.issuer_id == config.issuer_id
            and issuer.key_id == config.signing_key_id
            and issuer.public_key_base64 == public
            and issuer.bot_user_id == config.platform_bot_user_id
        )
    ]
    if (
        len(matching) != 1
        or trust.platform_repository_id != config.platform_repository_id
        or public != policy.signing_public_key_base64
    ):
        raise ValueError("Runtime signing key does not match the active reviewed issuer registry")


def system_plan(
    entry: CatalogEntry,
    policy: PortalSystemPolicy,
    delivery: DeliveryPolicy,
    bootstrap: dict,
    raw_receipt: bytes,
    release_id: str,
) -> dict[str, dict | bytes]:
    """Render the operator review plan after the caller performs live release admission."""
    release = ReleaseEvidence.model_validate(strict_json(raw_receipt))
    config = policy.configuration
    target = entry.environments["dev"]
    if (
        entry.app_id != "aegis-portal"
        or entry.source.repository_id != policy.source_repository_id
        or release.app_id != entry.app_id
        or release.source_repository_id != entry.source.repository_id
        or release.source_repository.lower()
        != (entry.source.owner + "/" + entry.source.name).lower()
        or release.platform_commit != entry.versions.workflow_commit
        or entry.runtime.container_port != 8000
        or entry.runtime.health_path != "/health"
        or config.platform_repository_id != delivery.platform_repository_id
        or config.gitops_repository_id != delivery.gitops_repository_id
        or config.gitops_repository != delivery.gitops_repository
        or config.cluster_id != target.cluster_id
        or config.cluster_uid != target.cluster_uid
        or digest(bootstrap) != delivery.bootstrap_policy_hash
        or not release_id.isdigit()
        or release_id.startswith("0")
    ):
        raise ValueError("Portal system configuration/release differs from reviewed identities")
    profile = validate_profile(bootstrap, "small")
    labels = {"app.kubernetes.io/name": "aegis-portal", "aegis.io/component": "portal-system"}

    def metadata(name):
        return {"name": name, "namespace": NAMESPACE, "labels": labels}

    public_config = json.dumps(config.model_dump(), indent=2) + "\n"
    config_hash = digest(config.model_dump())
    environment = {
        "AEGIS_MODE": "live",
        "AEGIS_CONFIG": "/run/aegis/config/config.json",
        "AEGIS_APP_PRIVATE_KEY_FILE": "/run/aegis/credentials/github-app.pem",
        "AEGIS_SIGNING_KEY_FILE": "/run/aegis/credentials/request-signing.pem",
        "AEGIS_SIGNING_PUBLIC_KEY_B64": policy.signing_public_key_base64,
    }
    service_account = {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": metadata("aegis-portal"),
        "automountServiceAccountToken": False,
    }
    configmap = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": metadata("aegis-portal-config"),
        "data": {"config.json": public_config},
    }
    deployment = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": metadata("aegis-portal"),
        "spec": {
            "replicas": 1,
            "strategy": {"type": "Recreate"},
            "selector": {"matchLabels": labels},
            "template": {
                "metadata": {
                    "labels": labels,
                    "annotations": {"aegis.io/config-sha256": config_hash},
                },
                "spec": {
                    "serviceAccountName": "aegis-portal",
                    "automountServiceAccountToken": False,
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 10001,
                        "runAsGroup": 10001,
                        "fsGroup": 10001,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [
                        {
                            "name": "portal",
                            "image": release.image,
                            "imagePullPolicy": "Never",
                            "ports": [{"name": "http", "containerPort": 8000}],
                            "resources": {
                                "requests": profile["requests"],
                                "limits": profile["limits"],
                            },
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                            "env": [
                                {"name": key, "value": value} for key, value in environment.items()
                            ]
                            + [
                                {
                                    "name": "AEGIS_GITHUB_CLIENT_SECRET",
                                    "valueFrom": {
                                        "secretKeyRef": {
                                            "name": "aegis-portal-runtime",
                                            "key": "client-secret",
                                        }
                                    },
                                }
                            ],
                            "volumeMounts": [
                                {"name": name, "mountPath": path, "readOnly": readonly}
                                for name, path, readonly in [
                                    ("config", "/run/aegis/config", True),
                                    ("credentials", "/run/aegis/credentials", True),
                                    ("tmp", "/tmp", False),
                                ]
                            ],
                            "readinessProbe": {
                                "httpGet": {"path": "/ready", "port": "http"},
                                "periodSeconds": 5,
                                "failureThreshold": 3,
                            },
                            "livenessProbe": {
                                "httpGet": {"path": "/health", "port": "http"},
                                "periodSeconds": 10,
                                "failureThreshold": 3,
                            },
                            "startupProbe": {
                                "httpGet": {"path": "/health", "port": "http"},
                                "periodSeconds": 2,
                                "failureThreshold": 30,
                            },
                        }
                    ],
                    "volumes": [
                        {
                            "name": "config",
                            "configMap": {"name": "aegis-portal-config", "defaultMode": 0o444},
                        },
                        {
                            "name": "credentials",
                            "secret": {
                                "secretName": "aegis-portal-runtime",
                                "defaultMode": 0o440,
                                "items": [
                                    {"key": key, "path": key}
                                    for key in ["github-app.pem", "request-signing.pem"]
                                ],
                            },
                        },
                        {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}},
                    ],
                },
            },
        },
    }
    if policy.uploads:
        upload = policy.uploads
        container = deployment["spec"]["template"]["spec"]["containers"][0]
        container["env"].extend(
            [
                {"name": "AEGIS_UPLOAD_OWNER", "value": upload.owner},
                {"name": "AEGIS_UPLOAD_OWNER_TYPE", "value": upload.owner_type},
                {"name": "AEGIS_UPLOAD_DATA", "value": "/var/lib/aegis/uploads/uploads.sqlite3"},
            ]
        )
        container["volumeMounts"].append(
            {"name": "uploads", "mountPath": "/var/lib/aegis/uploads", "readOnly": False}
        )
        deployment["spec"]["template"]["spec"]["volumes"].append(
            {"name": "uploads", "persistentVolumeClaim": {"claimName": "aegis-portal-uploads"}}
        )
    service = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": metadata("aegis-portal"),
        "spec": {
            "type": "ClusterIP",
            "selector": labels,
            "ports": [{"name": "http", "port": 80, "targetPort": "http"}],
        },
    }
    namespace_labels = {**labels}
    for mode in ["enforce", "audit", "warn"]:
        namespace_labels[f"pod-security.kubernetes.io/{mode}"] = "restricted"
        namespace_labels[f"pod-security.kubernetes.io/{mode}-version"] = bootstrap[
            "pod_security_version"
        ]
    namespace = {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {"name": NAMESPACE, "labels": namespace_labels},
    }
    quota = {
        "apiVersion": "v1",
        "kind": "ResourceQuota",
        "metadata": metadata("aegis-budget"),
        "spec": {"hard": {**profile["quota"], "configmaps": "2", "secrets": "1"}},
    }
    limits = {
        "apiVersion": "v1",
        "kind": "LimitRange",
        "metadata": metadata("aegis-container-limits"),
        "spec": {
            "limits": [
                {
                    "type": "Container",
                    "defaultRequest": profile["requests"],
                    "default": profile["limits"],
                    "max": profile["limits"],
                }
            ]
        },
    }
    repo = "https://github.com/" + delivery.gitops_repository + ".git"
    project = {
        "apiVersion": "argoproj.io/v1alpha1",
        "kind": "AppProject",
        "metadata": {"name": NAMESPACE, "namespace": "argocd", "labels": labels},
        "spec": {
            "sourceRepos": [repo],
            "destinations": [{"server": "https://kubernetes.default.svc", "namespace": NAMESPACE}],
            "clusterResourceWhitelist": [],
            "namespaceResourceWhitelist": [
                {"group": group, "kind": kind}
                for group, kind in [
                    ("apps", "Deployment"),
                    ("", "Service"),
                    ("", "ServiceAccount"),
                    ("", "ConfigMap"),
                ]
            ],
        },
    }
    application = {
        "apiVersion": "argoproj.io/v1alpha1",
        "kind": "Application",
        "metadata": {"name": NAMESPACE, "namespace": "argocd", "labels": labels},
        "spec": {
            "project": NAMESPACE,
            "source": {
                "repoURL": repo,
                "targetRevision": policy.branch,
                "path": BASE + "/manifests",
                "directory": {"recurse": False},
            },
            "destination": {"server": "https://kubernetes.default.svc", "namespace": NAMESPACE},
            "syncPolicy": {
                "automated": {"prune": True, "selfHeal": True, "allowEmpty": False},
                "syncOptions": ["ServerSideApply=true", "FailOnSharedResource=true"],
            },
        },
    }
    files = {
        f"{BASE}/manifests/{name}.json": resource
        for name, resource in [
            ("deployment", deployment),
            ("service", service),
            ("serviceaccount", service_account),
            ("configmap", configmap),
        ]
    }
    if policy.uploads:
        files[f"{BASE}/manifests/uploads-pvc.json"] = {
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {
                **metadata("aegis-portal-uploads"),
                "annotations": {"argocd.argoproj.io/sync-options": "Prune=false"},
            },
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "storageClassName": policy.uploads.storage_class,
                "resources": {"requests": {"storage": policy.uploads.storage_size}},
            },
        }
        project["spec"]["namespaceResourceWhitelist"].append(
            {"group": "", "kind": "PersistentVolumeClaim"}
        )
        quota["spec"]["hard"].update({"persistentvolumeclaims": "1", "requests.storage": "1Gi"})
    files.update(
        {
            f"{BASE}/bootstrap/{name}.json": resource
            for name, resource in [
                ("namespace", namespace),
                ("quota", quota),
                ("limits", limits),
                ("project", project),
                ("application", application),
            ]
        }
    )
    files[f"{BASE}/releases/{release.release_tag}.json"] = raw_receipt
    policy_data = policy.model_dump()
    if policy.uploads is None:
        policy_data.pop("uploads")
    files[f"{BASE}/review.json"] = {
        "schema_version": 1,
        "app_id": entry.app_id,
        "release_id": release_id,
        "release_tag": release.release_tag,
        "release_evidence_hash": receipt_hash(raw_receipt),
        "image": release.image,
        "configuration_hash": config_hash,
        "policy_hash": digest(policy_data),
        "cluster_uid": config.cluster_uid,
        "namespace": NAMESPACE,
        "requires_maintainer_review": True,
        "requires_operator_secret_injection": True,
    }
    return files
