"""Deterministic, operator-reviewed telemetry plan. No credentials or cluster writes."""

import json
import re
from pathlib import Path

from aegis_platform.canonical import digest
from aegis_platform.observability_config import (
    alert_rules,
    collector_config,
    loki_config,
    prometheus_config,
    proxy_config,
    tempo_config,
)
from aegis_platform.observability_policy import OBS_BASE, OBS_NAMESPACE, ObservabilityPolicy

AUTH_SECRET = "aegis-observability-auth"
SIZES = {"prometheus": "2Gi", "loki": "3Gi", "tempo": "3Gi", "alertmanager": "1Gi"}
RESOURCES = {
    "prometheus": ("100m", "128Mi", "500m", "512Mi"),
    "loki": ("100m", "128Mi", "500m", "512Mi"),
    "tempo": ("100m", "256Mi", "700m", "1Gi"),
    "alertmanager": ("25m", "32Mi", "100m", "128Mi"),
    "collector": ("100m", "128Mi", "500m", "384Mi"),
    "proxy": ("10m", "16Mi", "100m", "32Mi"),
}


def resources(name):
    cpu, mem, limit_cpu, limit_mem = RESOURCES[name]
    return {
        "requests": {"cpu": cpu, "memory": mem},
        "limits": {"cpu": limit_cpu, "memory": limit_mem},
    }


def metadata(name, namespace=OBS_NAMESPACE):
    return {
        "name": name,
        **({"namespace": namespace} if namespace else {}),
        "labels": {
            "app.kubernetes.io/part-of": "aegis-observability",
            "app.kubernetes.io/name": name,
        },
    }


def security():
    return {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
    }


def configmap(component, policy):
    configs = {
        "prometheus": lambda: prometheus_config(policy),
        "loki": loki_config,
        "tempo": tempo_config,
        "alertmanager": lambda: {
            "global": {"resolve_timeout": "1m"},
            "route": {
                "receiver": "portal",
                "group_by": ["alertname", "k8s_namespace_name"],
                "group_wait": "5s",
                "group_interval": "30s",
                "repeat_interval": "4h",
            },
            "receivers": [{"name": "portal"}],
        },
        "collector": lambda: collector_config(policy),
    }
    data = {
        "config.yaml": json.dumps(configs[component](), indent=2) + "\n",
        "nginx.conf": proxy_config(component),
    }
    if component == "prometheus":
        data["rules.json"] = json.dumps(alert_rules(), indent=2) + "\n"
    if component == "collector":
        data["kubelet-ca.pem"] = policy.kubelet_ca_pem
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": metadata(component + "-config"),
        "data": data,
    }


def deployment(component, policy):
    commands = {
        "prometheus": [
            "/bin/prometheus",
            "--config.file=/etc/aegis/config.yaml",
            "--web.listen-address=127.0.0.1:9090",
            "--storage.tsdb.path=/data",
            "--storage.tsdb.retention.time=24h",
            "--storage.tsdb.retention.size=1GB",
        ],
        "loki": ["/usr/bin/loki", "-config.file=/etc/aegis/config.yaml"],
        "tempo": ["/tempo", "-config.file=/etc/aegis/config.yaml"],
        "alertmanager": [
            "/bin/alertmanager",
            "--config.file=/etc/aegis/config.yaml",
            "--web.listen-address=127.0.0.1:9093",
            "--cluster.listen-address=",
            "--storage.path=/data",
        ],
        "collector": ["/otelcol-contrib", "--config=/etc/aegis/config.yaml"],
    }
    common = [
        {"name": "config", "mountPath": "/etc/aegis", "readOnly": True},
        {"name": "tmp", "mountPath": "/tmp"},
    ]
    app = {
        "name": component,
        "image": policy.images[component],
        "imagePullPolicy": "IfNotPresent",
        "command": commands[component],
        "securityContext": security(),
        "resources": resources(component),
        "volumeMounts": list(common),
    }
    if component in SIZES:
        app["volumeMounts"].append(
            {"name": "data", "mountPath": "/var/tempo" if component == "tempo" else "/data"}
        )
    if component in {"prometheus", "collector"}:
        app["volumeMounts"].append(
            {"name": "auth-client", "mountPath": "/run/telemetry-auth", "readOnly": True}
        )
    if component == "collector":
        app["env"] = [
            {"name": "K8S_NODE_NAME", "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}}},
            {"name": "K8S_NODE_IP", "valueFrom": {"fieldRef": {"fieldPath": "status.hostIP"}}},
        ]
        app["ports"] = [{"name": "otlp-http", "containerPort": 4318}]
    proxy = {
        "name": "query-gateway",
        "image": policy.images["proxy"],
        "imagePullPolicy": "IfNotPresent",
        "command": ["nginx", "-c", "/etc/aegis/nginx.conf", "-g", "daemon off;"],
        "ports": [{"name": "query", "containerPort": 8080}],
        "resources": resources("proxy"),
        "securityContext": security(),
        "volumeMounts": list(common)
        + [{"name": "auth", "mountPath": "/run/telemetry-auth", "readOnly": True}],
        "readinessProbe": {
            "httpGet": {"path": "/ready", "port": "query"},
            "periodSeconds": 5,
            "timeoutSeconds": 3,
            "failureThreshold": 12,
        },
        "startupProbe": {
            "httpGet": {"path": "/ready", "port": "query"},
            "periodSeconds": 3,
            "timeoutSeconds": 3,
            "failureThreshold": 60,
        },
    }
    if component in {"loki", "tempo", "alertmanager", "collector"}:
        proxy["ports"].append({"name": "ingest", "containerPort": 8081})
    volumes = [
        {"name": "config", "configMap": {"name": component + "-config"}},
        {
            "name": "auth",
            "secret": {
                "secretName": AUTH_SECRET,
                "defaultMode": 0o440,
                "items": [
                    {"key": key, "path": key}
                    for key in ["query.htpasswd", "ingest.htpasswd", "agent.htpasswd"]
                ],
            },
        },
        {"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}},
    ]
    if component in {"prometheus", "collector"}:
        keys = ["ingest-password"] + (["query-password"] if component == "prometheus" else [])
        volumes.append(
            {
                "name": "auth-client",
                "secret": {
                    "secretName": AUTH_SECRET,
                    "defaultMode": 0o440,
                    "items": [{"key": key, "path": key} for key in keys],
                },
            }
        )
    if component in SIZES:
        volumes.append(
            {"name": "data", "persistentVolumeClaim": {"claimName": component + "-data"}}
        )
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": metadata(component),
        "spec": {
            "replicas": 1,
            "revisionHistoryLimit": 2,
            "strategy": {"type": "Recreate"},
            "selector": {"matchLabels": {"app.kubernetes.io/name": component}},
            "template": {
                "metadata": {"labels": metadata(component)["labels"]},
                "spec": {
                    "nodeSelector": {"kubernetes.io/hostname": policy.node_name},
                    "hostAliases": [{"ip": policy.node_ip, "hostnames": [policy.node_name]}]
                    if component == "collector"
                    else [],
                    "serviceAccountName": "collector"
                    if component == "collector"
                    else "telemetry-runtime",
                    "automountServiceAccountToken": component == "collector",
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 10001,
                        "runAsGroup": 10001,
                        "fsGroup": 10001,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [app, proxy],
                    "volumes": volumes,
                },
            },
        },
    }


def service(component):
    ports = [{"name": "query", "port": 8080, "targetPort": "query"}]
    if component in {"loki", "tempo", "alertmanager", "collector"}:
        ports.append({"name": "ingest", "port": 8081, "targetPort": "ingest"})
    if component == "collector":
        ports.append({"name": "otlp-http", "port": 4318, "targetPort": "otlp-http"})
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": metadata(component),
        "spec": {
            "type": "ClusterIP",
            "selector": {"app.kubernetes.io/name": component},
            "ports": ports,
        },
    }


def observability_plan(policy: ObservabilityPolicy, platform_revision: str):
    if not re.fullmatch(r"[0-9a-f]{40}", platform_revision):
        raise ValueError("A full reviewed platform revision is required")
    files = {}

    def add(resource, folder="manifests"):
        key = resource["kind"].lower() + "-" + resource["metadata"]["name"] + ".json"
        files[f"{OBS_BASE}/{folder}/{key}"] = resource

    for component in ["prometheus", "loki", "tempo", "alertmanager", "collector"]:
        add(configmap(component, policy))
        add(deployment(component, policy))
        add(service(component))
        if component in SIZES:
            add(
                {
                    "apiVersion": "v1",
                    "kind": "PersistentVolumeClaim",
                    "metadata": metadata(component + "-data"),
                    "spec": {
                        "accessModes": ["ReadWriteOnce"],
                        "storageClassName": "standard",
                        "resources": {"requests": {"storage": SIZES[component]}},
                    },
                }
            )
    script = Path(__file__).with_name("observability_log_agent.py").read_text()
    add(
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": metadata("container-log-reader"),
            "data": {"log-agent.py": script},
        }
    )
    add(
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": metadata("container-log-reader"),
            "spec": {
                "replicas": 1,
                "strategy": {"type": "Recreate"},
                "selector": {"matchLabels": {"app.kubernetes.io/name": "container-log-reader"}},
                "template": {
                    "metadata": {"labels": metadata("container-log-reader")["labels"]},
                    "spec": {
                        "serviceAccountName": "log-reader",
                        "automountServiceAccountToken": True,
                        "nodeSelector": {"kubernetes.io/hostname": policy.node_name},
                        "securityContext": {
                            "runAsNonRoot": True,
                            "runAsUser": 10001,
                            "runAsGroup": 10001,
                            "fsGroup": 10001,
                            "seccompProfile": {"type": "RuntimeDefault"},
                        },
                        "containers": [
                            {
                                "name": "reader",
                                "image": policy.images["log_agent"],
                                "imagePullPolicy": "IfNotPresent",
                                "command": ["python", "/etc/aegis/log-agent.py"],
                                "securityContext": security(),
                                "env": [
                                    {"name": "AEGIS_CLUSTER_UID", "value": policy.cluster_uid},
                                    {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
                                ],
                                "resources": {
                                    "requests": {"cpu": "25m", "memory": "64Mi"},
                                    "limits": {"cpu": "100m", "memory": "128Mi"},
                                },
                                "volumeMounts": [
                                    {"name": "code", "mountPath": "/etc/aegis", "readOnly": True},
                                    {
                                        "name": "auth",
                                        "mountPath": "/run/log-agent",
                                        "readOnly": True,
                                    },
                                    {"name": "tmp", "mountPath": "/tmp"},
                                ],
                            }
                        ],
                        "volumes": [
                            {"name": "code", "configMap": {"name": "container-log-reader"}},
                            {
                                "name": "auth",
                                "secret": {
                                    "secretName": AUTH_SECRET,
                                    "defaultMode": 0o440,
                                    "items": [{"key": "agent-password", "path": "agent-password"}],
                                },
                            },
                            {"name": "tmp", "emptyDir": {"sizeLimit": "16Mi"}},
                        ],
                    },
                },
            },
        }
    )
    add(
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": metadata("aegis-container-log-reader", None),
            "rules": [
                {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]},
                {"apiGroups": [""], "resources": ["pods/log"], "verbs": ["get"]},
                {"apiGroups": [""], "resources": ["namespaces"], "verbs": ["get", "list"]},
            ],
        }
    )
    add(
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": metadata("aegis-container-log-reader", None),
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "aegis-container-log-reader",
            },
            "subjects": [
                {"kind": "ServiceAccount", "name": "log-reader", "namespace": OBS_NAMESPACE}
            ],
        }
    )
    for name in ["telemetry-runtime", "collector", "log-reader"]:
        add(
            {
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": metadata(name),
                "automountServiceAccountToken": name in {"collector", "log-reader"},
            }
        )
    add(
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": metadata("aegis-telemetry-collector", None),
            "rules": [
                {
                    "apiGroups": [""],
                    "resources": [
                        "nodes",
                        "namespaces",
                        "pods",
                        "services",
                        "replicationcontrollers",
                        "resourcequotas",
                        "limitranges",
                        "persistentvolumeclaims",
                    ],
                    "verbs": ["get", "list", "watch"],
                },
                {
                    "apiGroups": ["apps"],
                    "resources": ["deployments", "daemonsets", "replicasets", "statefulsets"],
                    "verbs": ["get", "list", "watch"],
                },
                {
                    "apiGroups": ["batch"],
                    "resources": ["jobs", "cronjobs"],
                    "verbs": ["get", "list", "watch"],
                },
                {
                    "apiGroups": [""],
                    "resources": ["nodes/stats"],
                    "resourceNames": [policy.node_name],
                    "verbs": ["get"],
                },
            ],
        }
    )
    add(
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": metadata("aegis-telemetry-collector", None),
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "aegis-telemetry-collector",
            },
            "subjects": [
                {"kind": "ServiceAccount", "name": "collector", "namespace": OBS_NAMESPACE}
            ],
        }
    )
    ns = metadata(OBS_NAMESPACE, None)
    ns["labels"].update(
        {
            "pod-security.kubernetes.io/enforce": "restricted",
            "pod-security.kubernetes.io/enforce-version": "v1.35",
        }
    )
    add({"apiVersion": "v1", "kind": "Namespace", "metadata": ns}, "bootstrap")
    add(
        {
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": metadata("telemetry-budget"),
            "spec": {
                "hard": {
                    "requests.cpu": "2",
                    "limits.cpu": "4",
                    "requests.memory": "2Gi",
                    "limits.memory": "4Gi",
                    "requests.storage": "12Gi",
                    "persistentvolumeclaims": "4",
                    "pods": "8",
                }
            },
        },
        "bootstrap",
    )
    add(
        {
            "apiVersion": "v1",
            "kind": "LimitRange",
            "metadata": metadata("telemetry-limits"),
            "spec": {
                "limits": [
                    {
                        "type": "Container",
                        "defaultRequest": {"cpu": "50m", "memory": "64Mi"},
                        "default": {"cpu": "500m", "memory": "512Mi"},
                    }
                ]
            },
        },
        "bootstrap",
    )
    cluster_kinds = ["ClusterRole", "ClusterRoleBinding"]
    namespaced = ["ConfigMap", "Deployment", "PersistentVolumeClaim", "Service", "ServiceAccount"]
    add(
        {
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "AppProject",
            "metadata": metadata("aegis-observability", "argocd"),
            "spec": {
                "sourceRepos": ["https://github.com/" + policy.gitops_repository + ".git"],
                "destinations": [
                    {"namespace": OBS_NAMESPACE, "server": "https://kubernetes.default.svc"}
                ],
                "clusterResourceWhitelist": [
                    {"group": "rbac.authorization.k8s.io", "kind": kind} for kind in cluster_kinds
                ],
                "namespaceResourceWhitelist": [
                    {"group": "apps" if k == "Deployment" else "", "kind": k} for k in namespaced
                ],
            },
        },
        "bootstrap",
    )
    add(
        {
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "Application",
            "metadata": metadata("aegis-observability", "argocd"),
            "spec": {
                "project": "aegis-observability",
                "source": {
                    "repoURL": "https://github.com/" + policy.gitops_repository + ".git",
                    "targetRevision": "main",
                    "path": OBS_BASE + "/manifests",
                },
                "destination": {
                    "server": "https://kubernetes.default.svc",
                    "namespace": OBS_NAMESPACE,
                },
                "syncPolicy": {
                    "automated": {"prune": True, "selfHeal": True, "allowEmpty": False},
                    "syncOptions": ["ServerSideApply=true", "FailOnSharedResource=true"],
                },
            },
        },
        "bootstrap",
    )
    files[OBS_BASE + "/review.json"] = {
        "schema_version": 1,
        "platform_revision": platform_revision,
        "policy_hash": digest(policy.model_dump()),
        "cluster_uid": policy.cluster_uid,
        "namespace": OBS_NAMESPACE,
        "requires_independent_operator_review": True,
        "private_auth_secret": AUTH_SECRET,
        "retention_hours": 24,
    }
    return files
