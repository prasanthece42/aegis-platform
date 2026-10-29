"""Platform-owned multi-service rendering, quotas and image/environment bindings."""

import re

from aegis_platform.canonical import digest
from aegis_platform.stack import PROFILE

DEPENDENCY_IMAGES = {
    "postgres": (
        "docker.io/library/postgres@sha256:"
        "b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24"
    ),
    "redis": (
        "docker.io/library/redis@sha256:"
        "57e4255cc971b1c8d6f8a6ca283ac01bc3ecdd914273ef6bfaede87aaecd6541"
    ),
    "gateway": (
        "docker.io/nginxinc/nginx-unprivileged@sha256:"
        "a6c4f61f456b85b8fdf7ec7ab28cc3e299440e6fb4a9dea520e5fd8fd440025e"
    ),
}


def budget(stack, profile):
    # Every deployment may surge once; two stateful dependencies do not surge.
    pods = sum(s.replicas for s in stack.services.values()) + len(stack.services) + 4
    quota = {
        "pods": str(pods),
        "services": str(len(stack.services) + 3),
        "count/deployments.apps": str(len(stack.services) + 1),
        "count/statefulsets.apps": "2",
        "count/serviceaccounts": "2",
        "count/configmaps": "2",  # Gateway configuration plus Kubernetes' root-CA ConfigMap.
        "count/secrets": "1",
        "persistentvolumeclaims": "2",
        "requests.storage": "2Gi",
    }
    for group in ("requests", "limits"):
        for key, unit in (("cpu", "m"), ("memory", "Mi")):
            quota[f"{group}.{key}"] = str(int(profile[group][key].removesuffix(unit)) * pods) + unit
    return quota


def nginx_config(app_id, stack, resolver="kube-dns.kube-system.svc.cluster.local", namespace=None):
    # Kubernetes supplies the resolver's IP through resolv.conf at gateway startup.
    suffix = "." + namespace + ".svc.cluster.local" if namespace else ""
    routes = "\n".join(
        f"location /api/{name}/ {{ set $upstream {app_id}-{name}{suffix}; "
        f"rewrite ^/api/{name}/(.*)$ /$1 break; proxy_pass http://$upstream:{s.port}; }}"
        for name, s in sorted(stack.services.items())
    )
    return (
        """pid /tmp/nginx.pid;
events { worker_connections 1024; }
http {
  access_log off;
  error_log /dev/stderr warn;
  client_body_temp_path /tmp/client;
  proxy_temp_path /tmp/proxy;
  fastcgi_temp_path /tmp/fastcgi;
  uwsgi_temp_path /tmp/uwsgi;
  scgi_temp_path /tmp/scgi;
  resolver RESOLVER valid=5s;
  server {
    listen 8080;
    client_max_body_size 32k;
    proxy_connect_timeout 2s;
    proxy_read_timeout 30s;
    proxy_next_upstream off;
    location = /health { default_type application/json; return 200 '{"status":"ok"}'; }
    location = / {
      default_type application/json;
      return 200 '{"application":"APP_ID","profile":"python312-multiservice"}';
    }
    ROUTES
  }
}
""".replace("RESOLVER", resolver)
        .replace("APP_ID", app_id)
        .replace("ROUTES", routes)
    )


def manifests(runtime, app_id, environment, images, profile):
    """Inputs are strict source contracts and admitted immutable images, never raw YAML."""
    stack = runtime.stack
    namespace = f"aegis-{app_id}-{environment}"
    if set(images) != set(stack.services) | set(DEPENDENCY_IMAGES):
        raise ValueError("Every service and dependency image is required")
    objects = []
    labels = {"aegis.io/app": app_id, "aegis.io/environment": environment}

    def add(kind, name, **fields):
        obj = {
            "apiVersion": "apps/v1" if kind in {"Deployment", "StatefulSet"} else "v1",
            "kind": kind,
            "metadata": {"name": name, "namespace": namespace, "labels": labels},
            **fields,
        }
        objects.append(obj)
        return obj

    def secret(key):
        return {"secretKeyRef": {"name": runtime.credentials_secret, "key": key}}

    add("ServiceAccount", app_id, automountServiceAccountToken=False)

    def workload(name, container, port, replicas=1, volumes=None, stateful=False, uid=10001):
        full = app_id if name == "gateway" else f"{app_id}-{name}"
        selector = {**labels, "aegis.io/component": name}
        security = {
            "runAsNonRoot": True,
            "runAsUser": uid,
            "runAsGroup": uid,
            "fsGroup": uid,
            "seccompProfile": {"type": "RuntimeDefault"},
        }
        container.update(
            name=name,
            image=images[name],
            imagePullPolicy="Never",
            resources={k: profile[k] for k in ("requests", "limits")},
            securityContext={
                "allowPrivilegeEscalation": False,
                "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]},
            },
            ports=[{"name": "http" if port not in {5432, 6379} else "tcp", "containerPort": port}],
        )
        pod = {
            "serviceAccountName": app_id,
            "automountServiceAccountToken": False,
            "securityContext": security,
            "terminationGracePeriodSeconds": 20,
            "containers": [container],
            "volumes": [{"name": "tmp", "emptyDir": {"sizeLimit": "32Mi"}}, *(volumes or [])],
        }
        container.setdefault("volumeMounts", []).append({"name": "tmp", "mountPath": "/tmp"})
        spec = {
            "replicas": replicas,
            "selector": {"matchLabels": selector},
            "template": {
                "metadata": {
                    "labels": selector,
                    "annotations": {"aegis.io/config-hash": digest(container)},
                },
                "spec": pod,
            },
        }
        if stateful:
            spec["serviceName"] = full
        else:
            spec["strategy"] = {
                "type": "RollingUpdate",
                "rollingUpdate": {"maxSurge": 1, "maxUnavailable": 0},
            }
        add("StatefulSet" if stateful else "Deployment", full, spec=spec)
        add(
            "Service",
            full,
            spec={
                "type": "ClusterIP",
                "selector": selector,
                "ports": [
                    {
                        "name": "http" if name == "gateway" else "tcp",
                        "port": 80 if name == "gateway" else port,
                        "targetPort": port,
                    }
                ],
            },
        )

    for name, service in sorted(stack.services.items()):
        configured = {**service.env, **runtime.environment.get(name, {})}
        env = [{"name": k, "value": v} for k, v in sorted(configured.items())]
        env += [
            {"name": k, "value": f"http://{app_id}-{v}:{stack.services[v].port}"}
            for k, v in sorted(service.service_env.items())
        ]
        env += [{"name": k, "valueFrom": secret(v)} for k, v in sorted(service.secret_env.items())]
        probe = {
            "httpGet": {"path": service.health_path, "port": service.port},
            "timeoutSeconds": 2,
            "periodSeconds": 3,
        }
        workload(
            name,
            {
                "env": env,
                "readinessProbe": probe,
                "startupProbe": {**probe, "failureThreshold": 40},
                "livenessProbe": {**probe, "periodSeconds": 15, "failureThreshold": 5},
            },
            service.port,
            replicas=service.replicas,
        )

    for name in ("postgres", "redis"):
        add(
            "PersistentVolumeClaim",
            f"{app_id}-{name}",
            metadata={
                "name": f"{app_id}-{name}",
                "namespace": namespace,
                "labels": labels,
                "annotations": {
                    "helm.sh/resource-policy": "keep",
                    "argocd.argoproj.io/sync-options": "Prune=false",
                },
            },
            spec={"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Gi"}}},
        )
    workload(
        "postgres",
        {
            "env": [
                {"name": "POSTGRES_USER", "value": "commerce"},
                {"name": "POSTGRES_DB", "value": "commerce"},
                {"name": "PGDATA", "value": "/var/lib/postgresql/data/pgdata"},
                {"name": "POSTGRES_PASSWORD", "valueFrom": secret("postgres-password")},
            ],
            "volumeMounts": [
                {"name": "data", "mountPath": "/var/lib/postgresql/data"},
                {"name": "socket", "mountPath": "/var/run/postgresql"},
            ],
            "readinessProbe": {
                "exec": {"command": ["pg_isready", "-U", "commerce", "-d", "commerce"]},
                "periodSeconds": 3,
            },
        },
        5432,
        stateful=True,
        uid=70,
        volumes=[
            {"name": "data", "persistentVolumeClaim": {"claimName": f"{app_id}-postgres"}},
            {"name": "socket", "emptyDir": {"sizeLimit": "16Mi"}},
        ],
    )
    workload(
        "redis",
        {
            "env": [{"name": "REDIS_PASSWORD", "valueFrom": secret("redis-password")}],
            "command": [
                "/bin/sh",
                "-ec",
                'umask 077; printf "requirepass %s\\nappendonly yes\\nmaxmemory 96mb\\nmaxmemory-policy noeviction\\n" "$REDIS_PASSWORD" > /data/redis.conf; exec redis-server /data/redis.conf',  # noqa: E501
            ],
            "volumeMounts": [{"name": "data", "mountPath": "/data"}],
            "readinessProbe": {
                "exec": {
                    "command": [
                        "/bin/sh",
                        "-ec",
                        'REDISCLI_AUTH="$REDIS_PASSWORD" redis-cli ping | grep -q PONG',
                    ]
                },
                "periodSeconds": 3,
            },
        },
        6379,
        stateful=True,
        uid=999,
        volumes=[{"name": "data", "persistentVolumeClaim": {"claimName": f"{app_id}-redis"}}],
    )
    config = nginx_config(app_id, stack, namespace=namespace)
    add("ConfigMap", f"{app_id}-gateway", data={"nginx.conf": config})
    gateway = {
        "command": [
            "/bin/sh",
            "-ec",
            "dns=$(awk '/^nameserver/{print $2;exit}' /etc/resolv.conf); "
            'sed "s/kube-dns.kube-system.svc.cluster.local/$dns/" '
            "/config/nginx.conf > /tmp/nginx.conf; "
            "exec nginx -c /tmp/nginx.conf -g 'daemon off;'",
        ],
        "volumeMounts": [{"name": "config", "mountPath": "/config", "readOnly": True}],
        "readinessProbe": {"httpGet": {"path": "/health", "port": 8080}, "periodSeconds": 3},
    }
    workload(
        "gateway",
        gateway,
        8080,
        uid=101,
        volumes=[{"name": "config", "configMap": {"name": f"{app_id}-gateway"}}],
    )
    objects[-2]["spec"]["template"]["metadata"]["annotations"]["aegis.io/gateway-config"] = digest(
        config
    )
    return objects


def release_values(catalog, app_id, environment, evidence, policy):
    from aegis_platform.bootstrap import validate_profile

    entry = catalog.apps[app_id]
    runtime = entry.runtime
    if runtime.profile_id != PROFILE or evidence.stack.model_dump() != runtime.stack.model_dump():
        raise ValueError("Release stack differs from the reviewed catalog topology/configuration")
    if (
        evidence.app_id != app_id
        or evidence.source_repository_id != entry.source.repository_id
        or evidence.source_repository.lower() != f"{entry.source.owner}/{entry.source.name}".lower()
        or evidence.platform_commit != entry.versions.workflow_commit
    ):
        raise ValueError("Stack release differs from approved source/workflow")
    profile = validate_profile(policy, runtime.resource_profile_id)
    images = {name: child.image for name, child in evidence.service_receipts().items()}
    images.update(DEPENDENCY_IMAGES)
    if any(
        not re.fullmatch(r"[a-z0-9./_-]+@sha256:[0-9a-f]{64}", value) for value in images.values()
    ):
        raise ValueError("All stack images must be immutable")
    repository, checksum = evidence.image.split("@")
    return {
        "appId": app_id,
        "environment": environment,
        "sourceCommit": evidence.source_commit,
        "image": {"repository": repository, "digest": checksum, "pullPolicy": "Never"},
        "stackSha256": evidence.stack_sha256,
        "images": images,
        "plan": manifests(runtime, app_id, environment, images, profile),
    }
