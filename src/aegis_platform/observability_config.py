"""Bounded local telemetry configuration; credentials are mounted references only."""

from aegis_platform.observability_policy import OBS_NAMESPACE

CREDS = "/run/telemetry-auth"


def proxy_config(component):
    ports = {
        "prometheus": 9090,
        "loki": 3100,
        "tempo": 3200,
        "alertmanager": 9093,
        "collector": 8889,
    }
    ready = {
        "prometheus": "/-/ready",
        "loki": "/ready",
        "tempo": "/ready",
        "alertmanager": "/-/ready",
        "collector": "/",
    }
    reads = {
        "prometheus": (
            r"/api/v1/(query|query_range|alerts|rules|targets|labels|series|"
            r"label/[a-zA-Z_][a-zA-Z0-9_]*/values|status/buildinfo)"
        ),
        "loki": r"/loki/api/v1/(query|query_range|labels|label/[a-zA-Z_][a-zA-Z0-9_]*/values)",
        "tempo": r"/api/(echo|search|traces/[a-fA-F0-9]+)",
        "alertmanager": r"/api/v2/alerts",
        "collector": r"/metrics",
    }
    port = ports[component]
    health_port = 13133 if component == "collector" else port
    config = """pid /tmp/nginx.pid;
error_log /dev/stderr warn;
worker_processes 1;
events { worker_connections 128; }
http {
 access_log off;
 client_max_body_size 2m;
 client_body_temp_path /tmp/client_temp;
 proxy_temp_path /tmp/proxy_temp;
 fastcgi_temp_path /tmp/fastcgi_temp;
 uwsgi_temp_path /tmp/uwsgi_temp;
 scgi_temp_path /tmp/scgi_temp;
 proxy_connect_timeout 3s;
 proxy_read_timeout 10s;
 server {
  listen 8080;
"""
    config += (
        f"  location = /ready {{ proxy_pass http://127.0.0.1:{health_port}{ready[component]}; }}\n"
    )
    config += f"""  location ~ ^({reads[component]}|/metrics)$ {{
   if ($request_method != GET) {{ return 405; }}
   auth_basic "Aegis telemetry";
   auth_basic_user_file {CREDS}/query.htpasswd;
   proxy_pass http://127.0.0.1:{port};
  }}
"""
    if component == "collector":
        config += f"""  location = /internal-metrics {{
   auth_basic "Aegis telemetry";
   auth_basic_user_file {CREDS}/query.htpasswd;
   proxy_pass http://127.0.0.1:8888/metrics;
  }}
"""
    config += "  location / { return 404; }\n }\n"
    write = {
        "loki": ("/otlp/v1/logs", 3100),
        "tempo": ("/v1/traces", 4318),
        "alertmanager": ("/api/v2/alerts", 9093),
        "collector": ("/v1/logs", 4320),
    }
    if component in write:
        path, dest = write[component]
        auth_file = "agent.htpasswd" if component == "collector" else "ingest.htpasswd"
        config += f""" server {{
  listen 8081;
  location = {path} {{
   if ($request_method != POST) {{ return 405; }}
   auth_basic "Aegis ingest";
   auth_basic_user_file {CREDS}/{auth_file};
   proxy_pass http://127.0.0.1:{dest};
  }}
  location / {{ return 404; }}
 }}
"""
    return config + "}\n"


def alert_rules():
    scope = 'k8s_namespace_name=~"aegis-.*"'
    config = {
        "groups": [
            {
                "name": "aegis-applications",
                "interval": "15s",
                "rules": [
                    {
                        "alert": "AegisHighErrorRate",
                        "expr": (
                            "sum by (k8s_namespace_name, aegis_cluster_uid) "
                            "(rate(http_server_requests_total{"
                            + scope
                            + ',http_response_status_code=~"5.."}[1m])) / '
                            "clamp_min(sum by (k8s_namespace_name, aegis_cluster_uid) "
                            "(rate(http_server_requests_total{" + scope + "}[1m])), 0.001) > 0.05"
                        ),
                        "for": "30s",
                        "labels": {"severity": "warning"},
                        "annotations": {"summary": "Application HTTP errors exceed 5%"},
                    },
                    {
                        "alert": "AegisPodNotReady",
                        "expr": (
                            "min by (k8s_namespace_name, k8s_pod_name, aegis_cluster_uid) "
                            f"(k8s_container_ready{{{scope}}}) == 0"
                        ),
                        "for": "2m",
                        "labels": {"severity": "warning"},
                        "annotations": {"summary": "Application pod has an unready container"},
                    },
                    {
                        "alert": "AegisTelemetryScrapeUnavailable",
                        "expr": 'up{job="aegis-telemetry"} == 0',
                        "for": "1m",
                        "labels": {"severity": "critical"},
                        "annotations": {"summary": "Telemetry collection is unavailable"},
                    },
                ],
            }
        ]
    }

    rules = config["groups"][0]["rules"]
    for name, expr, duration, severity, summary in [
        (
            "AegisApplicationUnavailable",
            f"k8s_deployment_available{{{scope}}} == 0",
            "2m",
            "critical",
            "Application deployment has no available replicas",
        ),
        (
            "AegisPodCrashLoop",
            f"k8s_container_status_reason{{{scope},"
            'k8s_container_status_reason="CrashLoopBackOff"} > 0',
            "2m",
            "warning",
            "Application container is in CrashLoopBackOff",
        ),
        (
            "AegisExcessiveRestarts",
            f"k8s_container_restarts{{{scope}}} > 5",
            "2m",
            "warning",
            "Application container reports more than five recent restarts",
        ),
        (
            "AegisHighLatency",
            "histogram_quantile(0.95, sum by (le, k8s_namespace_name, aegis_cluster_uid) "
            f"(rate(http_server_request_duration_seconds_bucket{{{scope}}}[5m]))) > 1 "
            "and on(k8s_namespace_name, aegis_cluster_uid) "
            "sum by (k8s_namespace_name, aegis_cluster_uid) "
            f"(rate(http_server_requests_total{{{scope}}}[5m])) > 1",
            "5m",
            "warning",
            "Application p95 latency exceeds one second with sustained traffic",
        ),
        (
            "AegisNodePressure",
            "(k8s_node_condition_memory_pressure == 1) or (k8s_node_condition_disk_pressure == 1)",
            "2m",
            "critical",
            "Kubernetes node has memory or disk pressure",
        ),
        (
            "AegisCollectorUnavailable",
            'up{job="aegis-collector-internal"} == 0',
            "1m",
            "critical",
            "Collector internal metrics are unavailable",
        ),
        (
            "AegisMonitoringBackendUnavailable",
            'up{job="aegis-monitoring-backends"} == 0',
            "1m",
            "critical",
            "Monitoring backend scrape is unavailable",
        ),
    ]:
        rules.append(
            {
                "alert": name,
                "expr": expr,
                "for": duration,
                "labels": {"severity": severity},
                "annotations": {"summary": summary},
            }
        )
    for rule in rules:
        app_scoped = "k8s_namespace_name" in rule["expr"]
        dashboard = "application" if app_scoped else "platform"
        link = "http://127.0.0.1:3000/d/aegis-" + dashboard
        link += "?var-cluster={{ $labels.aegis_cluster_uid }}"
        if app_scoped:
            link += "&var-namespace={{ $labels.k8s_namespace_name }}"
        rule["annotations"]["grafana_url"] = link
    return config


def prometheus_config(policy):
    basic = {"username": "query", "password_file": CREDS + "/query-password"}
    return {
        "global": {"scrape_interval": "15s", "evaluation_interval": "15s"},
        "rule_files": ["/etc/aegis/rules.json"],
        "alerting": {
            "alertmanagers": [
                {
                    "static_configs": [
                        {"targets": [f"alertmanager.{OBS_NAMESPACE}.svc.cluster.local:8081"]}
                    ],
                    "basic_auth": {
                        "username": "ingest",
                        "password_file": CREDS + "/ingest-password",
                    },
                }
            ]
        },
        "scrape_configs": [
            {
                "job_name": "aegis-monitoring-backends",
                "basic_auth": basic,
                "static_configs": [
                    {
                        "targets": [
                            f"{name}.{OBS_NAMESPACE}.svc.cluster.local:8080"
                            for name in ["prometheus", "loki", "tempo", "alertmanager"]
                        ],
                        "labels": {"aegis_cluster_uid": policy.cluster_uid},
                    }
                ],
            },
            {
                "job_name": "aegis-telemetry",
                "basic_auth": basic,
                "static_configs": [
                    {
                        "targets": [f"collector.{OBS_NAMESPACE}.svc.cluster.local:8080"],
                        "labels": {"aegis_cluster_uid": policy.cluster_uid},
                    }
                ],
            },
            {
                "job_name": "aegis-collector-internal",
                "metrics_path": "/internal-metrics",
                "basic_auth": basic,
                "static_configs": [
                    {
                        "targets": [f"collector.{OBS_NAMESPACE}.svc.cluster.local:8080"],
                        "labels": {"aegis_cluster_uid": policy.cluster_uid},
                    }
                ],
            },
        ],
    }


def loki_config():
    return {
        "auth_enabled": False,
        "server": {
            "http_listen_address": "127.0.0.1",
            "http_listen_port": 3100,
            "grpc_listen_address": "127.0.0.1",
        },
        "common": {
            # Single-binary components dial their advertised ring address. It must
            # match the private gRPC listener rather than the externally assigned pod IP.
            "instance_addr": "127.0.0.1",
            "path_prefix": "/data",
            "replication_factor": 1,
            "ring": {"kvstore": {"store": "inmemory"}},
            "storage": {
                "filesystem": {"chunks_directory": "/data/chunks", "rules_directory": "/data/rules"}
            },
        },
        "schema_config": {
            "configs": [
                {
                    "from": "2026-01-01",
                    "store": "tsdb",
                    "object_store": "filesystem",
                    "schema": "v13",
                    "index": {"prefix": "index_", "period": "24h"},
                }
            ]
        },
        "storage_config": {
            "tsdb_shipper": {
                "active_index_directory": "/data/index",
                "cache_location": "/data/cache",
            }
        },
        "compactor": {
            "working_directory": "/data/compactor",
            "retention_enabled": True,
            "delete_request_store": "filesystem",
            "compaction_interval": "5m",
        },
        "limits_config": {
            "retention_period": "24h",
            "allow_structured_metadata": True,
            "otlp_config": {
                "resource_attributes": {
                    "attributes_config": [
                        {"action": "index_label", "attributes": ["aegis.cluster.uid"]}
                    ]
                }
            },
            "max_entries_limit_per_query": 1000,
            "max_query_length": "1h",
            "ingestion_rate_mb": 2,
            "ingestion_burst_size_mb": 4,
        },
        "analytics": {"reporting_enabled": False},
    }


def tempo_config():
    return {
        "target": "all",
        "server": {
            "http_listen_address": "127.0.0.1",
            "http_listen_port": 3200,
            "grpc_listen_address": "127.0.0.1",
        },
        "distributor": {
            "receivers": {"otlp": {"protocols": {"http": {"endpoint": "127.0.0.1:4318"}}}}
        },
        "live_store": {
            "max_trace_idle": "10s",
            "max_block_duration": "2m",
            "max_block_bytes": 1000000,
        },
        "backend_scheduler": {
            "provider": {
                "compaction": {
                    "compaction": {
                        "compaction_window": "1h",
                        "block_retention": "24h",
                        "compacted_block_retention": "10m",
                        "max_block_bytes": 10000000,
                    }
                }
            }
        },
        "storage": {
            "trace": {
                "backend": "local",
                "wal": {"path": "/var/tempo/trace-wal"},
                "local": {"path": "/var/tempo/blocks"},
                "pool": {"max_workers": 4, "queue_depth": 256},
            }
        },
        "querier": {"max_concurrent_queries": 2},
        "usage_report": {"reporting_enabled": False},
    }


def collector_config(policy):
    # App identity comes from the pod connection, not untrusted OTLP resource attributes.
    statements = [
        'delete_matching_keys(resource.attributes, "^k8s\\\\.")',
        'delete_key(resource.attributes, "aegis.cluster.uid")',
    ]
    transform = {
        key: [{"context": context, "statements": statements}]
        for key, context in [
            ("trace_statements", "span"),
            ("metric_statements", "datapoint"),
            ("log_statements", "log"),
        ]
    }
    unknown = [
        'resource.attributes["k8s.namespace.name"] == nil',
        'not IsMatch(resource.attributes["k8s.namespace.name"], "^aegis-")',
    ]
    processors = {
        "memory_limiter": {"check_interval": "1s", "limit_mib": 256, "spike_limit_mib": 64},
        "transform/identity": transform,
        "k8s_attributes": {
            "auth_type": "serviceAccount",
            "passthrough": False,
            "filter": {"node_from_env_var": "K8S_NODE_NAME"},
            "extract": {
                "metadata": ["k8s.namespace.name", "k8s.pod.name", "k8s.pod.uid", "k8s.node.name"]
            },
            "pod_association": [{"sources": [{"from": "connection"}]}],
        },
        "filter/unknown": {
            "error_mode": "ignore",
            "traces": {"span": unknown},
            "metrics": {"datapoint": unknown},
            "logs": {"log_record": unknown},
        },
        "resource/cluster": {
            "attributes": [
                {"key": "aegis.cluster.uid", "value": policy.cluster_uid, "action": "upsert"}
            ]
        },
        "batch": {"timeout": "5s", "send_batch_size": 256, "send_batch_max_size": 512},
    }
    pipeline = [
        "memory_limiter",
        "transform/identity",
        "k8s_attributes",
        "filter/unknown",
        "resource/cluster",
        "batch",
    ]
    return {
        "extensions": {
            "health_check": {"endpoint": "127.0.0.1:13133"},
            "basicauth/ingest": {
                "client_auth": {"username": "ingest", "password_file": CREDS + "/ingest-password"}
            },
        },
        "receivers": {
            "otlp/agent": {
                "protocols": {
                    "http": {"endpoint": "127.0.0.1:4320", "max_request_body_size": 1048576}
                }
            },
            "otlp": {
                "protocols": {
                    "http": {"endpoint": "0.0.0.0:4318", "max_request_body_size": 1048576}
                }
            },
            "k8s_cluster": {
                "auth_type": "serviceAccount",
                "collection_interval": "15s",
                "node_conditions_to_report": ["Ready", "MemoryPressure", "DiskPressure"],
                "allocatable_types_to_report": ["cpu", "memory"],
                "metrics": {"k8s.container.status.reason": {"enabled": True}},
            },
            "kubelet_stats": {
                "collection_interval": "15s",
                "auth_type": "serviceAccount",
                "endpoint": "https://${env:K8S_NODE_NAME}:10250",
                "ca_file": "/etc/aegis/kubelet-ca.pem",
                "insecure_skip_verify": False,
                "metric_groups": ["node", "pod", "container"],
            },
        },
        "processors": processors,
        "exporters": {
            "prometheus": {
                "endpoint": "127.0.0.1:8889",
                "resource_to_telemetry_conversion": {"enabled": True},
                "metric_expiration": "90s",
                "send_timestamps": True,
            },
            "otlp_http/loki": {
                "endpoint": f"http://loki.{OBS_NAMESPACE}.svc.cluster.local:8081/otlp",
                "auth": {"authenticator": "basicauth/ingest"},
                "timeout": "5s",
            },
            "otlp_http/tempo": {
                "endpoint": f"http://tempo.{OBS_NAMESPACE}.svc.cluster.local:8081",
                "auth": {"authenticator": "basicauth/ingest"},
                "timeout": "5s",
            },
        },
        "service": {
            "extensions": ["health_check", "basicauth/ingest"],
            "telemetry": {
                "logs": {"level": "warn"},
                "metrics": {
                    "level": "basic",
                    "readers": [
                        {"pull": {"exporter": {"prometheus": {"host": "127.0.0.1", "port": 8888}}}}
                    ],
                },
            },
            "pipelines": {
                "metrics/apps": {
                    "receivers": ["otlp"],
                    "processors": pipeline,
                    "exporters": ["prometheus"],
                },
                "metrics/cluster": {
                    "receivers": ["k8s_cluster", "kubelet_stats"],
                    "processors": ["memory_limiter", "resource/cluster", "batch"],
                    "exporters": ["prometheus"],
                },
                "logs/containers": {
                    "receivers": ["otlp/agent"],
                    "processors": ["memory_limiter", "filter/unknown", "resource/cluster", "batch"],
                    "exporters": ["otlp_http/loki"],
                },
                "logs": {
                    "receivers": ["otlp"],
                    "processors": pipeline,
                    "exporters": ["otlp_http/loki"],
                },
                "traces": {
                    "receivers": ["otlp"],
                    "processors": pipeline,
                    "exporters": ["otlp_http/tempo"],
                },
            },
        },
    }
