"""Local operator-only Grafana add-on. Rendering never applies cluster resources."""

import argparse
import json
import re
from pathlib import Path

from aegis_platform.canonical import digest
from aegis_platform.observability import AUTH_SECRET, metadata, security
from aegis_platform.observability_policy import OBS_BASE, ObservabilityPolicy

ASSETS = Path(__file__).with_suffix("")
# Cached image for local compatibility checks. Production needs upgrade/security review.
IMAGE = (
    "docker.io/grafana/grafana@sha256:"
    "8b37a2f028f164ce7b9889e1765b9d6ee23fec80f871d156fbf436d6198d32b7"
)
BASE = OBS_BASE + "/grafana"


def dashboards(cluster_uid):
    result = {}
    for path in sorted((ASSETS / "dashboards").glob("*.json")):
        board = json.loads(path.read_text())
        cluster = board["templating"]["list"][0]
        cluster.update(query=cluster_uid, current={"text": cluster_uid, "value": cluster_uid})
        result[path.name] = board
    return result


def grafana_plan(policy: ObservabilityPolicy, revision: str):
    """Keep separate from the seven-component policy and its existing approval hash."""
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("A full reviewed platform revision is required")
    files = {}

    def add(obj):
        files[f"{BASE}/manifests/{obj['kind'].lower()}-{obj['metadata']['name']}.json"] = obj

    for name, data in [
        (
            "grafana-provisioning",
            {
                filename: (ASSETS / filename).read_text()
                for filename in ["datasources.yaml", "dashboards.yaml"]
            },
        ),
        (
            "grafana-dashboards",
            {
                name: json.dumps(board, indent=2) + "\n"
                for name, board in dashboards(policy.cluster_uid).items()
            },
        ),
    ]:
        add({"apiVersion": "v1", "kind": "ConfigMap", "metadata": metadata(name), "data": data})
    env = {
        "GF_AUTH_ANONYMOUS_ENABLED": "false",
        "GF_USERS_ALLOW_SIGN_UP": "false",
        "GF_USERS_ALLOW_ORG_CREATE": "false",
        "GF_SECURITY_ALLOW_EMBEDDING": "false",
        "GF_SECURITY_ADMIN_USER": "operator",
        "GF_SECURITY_ADMIN_PASSWORD__FILE": "/run/grafana-auth/admin-password",
        "GF_SECURITY_SECRET_KEY__FILE": "/run/grafana-auth/secret-key",
        "GF_ANALYTICS_REPORTING_ENABLED": "false",
        "GF_ANALYTICS_CHECK_FOR_UPDATES": "false",
        "GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES": "false",
        "GF_UNIFIED_ALERTING_ENABLED": "false",
        "GF_ALERTING_ENABLED": "false",
        "GF_LOG_LEVEL": "warn",
    }
    mounts = [
        {
            "name": "provisioning",
            "mountPath": "/etc/grafana/provisioning/datasources/aegis.yaml",
            "subPath": "datasources.yaml",
            "readOnly": True,
        },
        {
            "name": "provisioning",
            "mountPath": "/etc/grafana/provisioning/dashboards/aegis.yaml",
            "subPath": "dashboards.yaml",
            "readOnly": True,
        },
        {"name": "dashboards", "mountPath": "/etc/grafana/dashboards", "readOnly": True},
        {"name": "auth", "mountPath": "/run/grafana-auth", "readOnly": True},
        {"name": "data", "mountPath": "/var/lib/grafana"},
        {"name": "tmp", "mountPath": "/tmp"},
    ]
    add(
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": metadata("grafana"),
            "spec": {
                "replicas": 1,
                "strategy": {"type": "Recreate"},
                "selector": {"matchLabels": {"app.kubernetes.io/name": "grafana"}},
                "template": {
                    "metadata": {"labels": metadata("grafana")["labels"]},
                    "spec": {
                        "serviceAccountName": "telemetry-runtime",
                        "automountServiceAccountToken": False,
                        "securityContext": {
                            "runAsNonRoot": True,
                            "runAsUser": 472,
                            "runAsGroup": 472,
                            "fsGroup": 472,
                            "seccompProfile": {"type": "RuntimeDefault"},
                        },
                        "containers": [
                            {
                                "name": "grafana",
                                "image": IMAGE,
                                "imagePullPolicy": "IfNotPresent",
                                "securityContext": security(),
                                "resources": {
                                    "requests": {"cpu": "100m", "memory": "128Mi"},
                                    "limits": {"cpu": "500m", "memory": "512Mi"},
                                },
                                "env": [{"name": k, "value": v} for k, v in env.items()]
                                + [
                                    {
                                        "name": "AEGIS_QUERY_PASSWORD",
                                        "valueFrom": {
                                            "secretKeyRef": {
                                                "name": AUTH_SECRET,
                                                "key": "query-password",
                                            }
                                        },
                                    }
                                ],
                                "ports": [{"name": "http", "containerPort": 3000}],
                                "readinessProbe": {
                                    "httpGet": {"path": "/api/health", "port": "http"}
                                },
                                "startupProbe": {
                                    "httpGet": {"path": "/api/health", "port": "http"},
                                    "periodSeconds": 3,
                                    "failureThreshold": 60,
                                },
                                "volumeMounts": mounts,
                            }
                        ],
                        "volumes": [
                            {"name": "provisioning", "configMap": {"name": "grafana-provisioning"}},
                            {"name": "dashboards", "configMap": {"name": "grafana-dashboards"}},
                            {
                                "name": "auth",
                                "secret": {
                                    "secretName": "aegis-grafana-auth",
                                    "defaultMode": 0o440,
                                },
                            },
                            {"name": "data", "emptyDir": {"sizeLimit": "512Mi"}},
                            {"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}},
                        ],
                    },
                },
            },
        }
    )
    add(
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": metadata("grafana"),
            "spec": {
                "type": "ClusterIP",
                "selector": {"app.kubernetes.io/name": "grafana"},
                "ports": [{"name": "http", "port": 3000, "targetPort": "http"}],
            },
        }
    )
    # Operator port-forward only; ingress denial requires a policy-enforcing CNI.
    add(
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": metadata("grafana-operator-only"),
            "spec": {
                "podSelector": {"matchLabels": {"app.kubernetes.io/name": "grafana"}},
                "policyTypes": ["Ingress"],
                "ingress": [],
            },
        }
    )
    files[BASE + "/review.json"] = {
        "platform_revision": revision,
        "policy_hash": digest(policy.model_dump()),
        "profile": "local-operator-only",
        "requires_independent_operator_review": True,
        "image": IMAGE,
        "resources_hash": digest(files),
        "prerequisites": ["reviewed shared observability stack", AUTH_SECRET, "aegis-grafana-auth"],
        "developer_access": False,
        "production_ready": False,
    }
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=Path("policies/observability.json"))
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    policy = ObservabilityPolicy.model_validate_json(args.policy.read_text())
    for path, data in grafana_plan(policy, args.revision).items():
        target = args.output / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(data, indent=2) + "\n")
    print("Rendered local operator candidate; independent GitOps review required.")


if __name__ == "__main__":
    main()
