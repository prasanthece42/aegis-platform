# First live activation: findings and runtime corrections

The approved source at `86e4b2836c5172200914eb42535605d9045fe6f6` was admitted through
GitOps workflow #28 and exact-plan PR #29, after actual human approvals and trusted
checks. The reviewed local bootstrap verified enrollment/review/credentials and created
only bootstrap/controllers and private Secrets. Argo deployed the workload manifests.
No AWS resources were changed.

## Observed on the deployed local stack

- All seven workloads are ready; Argo reports Synced/Healthy; all four PVCs are Bound.
- All six configured Prometheus scrape targets report `up=1`.
- Actual kubelet CPU/memory/network series, portal HTTP counters/histograms and heartbeat
  are present. Cluster-state metrics are missing because the cluster receiver cannot sync
  its HPA informer with the original RBAC.
- All six dashboards are provisioned in real Grafana. Prometheus data source health passes.
- Five real portal requests with a recorded trace context produced five spans in Tempo;
  trace-by-ID returns HTTP 200 and namespace `aegis-portal-system`.
- Grafana 11.5.2's Tempo health endpoint returns `plugin.notImplemented`. The real trace
  query above establishes ingestion/query connectivity; the missing health method is not
  evidence that Tempo is unreachable.
- Loki readiness passes, but ingestion returns 503 and queries time out. Logs show Loki's
  internal components trying the pod IP on gRPC port 9095 while the listener is bound to
  loopback. Some queued logs were dropped during this failure. Pod readiness alone did
  not establish usable ingestion/query paths.
- The running pilot remains the previously deployed release; its new immutable telemetry
  release is published/cached and still needs promotion through the existing delivery path.

## Corrections in this candidate

Set Loki's single-binary `common.instance_addr` to `127.0.0.1`, matching the existing private
HTTP/gRPC listeners. This retains the authenticated gateway boundary. The setting also
appears in the [upstream local configuration](https://github.com/grafana/loki/blob/main/cmd/loki/loki-local-config.yaml).

Add only `get`, `list`, `watch` for `autoscaling/horizontalpodautoscalers` to the collector
ClusterRole. The pinned receiver's default HPA informer requires these permissions; see
[receiver RBAC documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/k8sclusterreceiver/README.md).
The role still grants no workload writes, Secrets, exec or attach access.

`tooling/check_loki_runtime.py` starts the actual pinned Loki image in a network-disabled,
read-only container, with a pinned Python utility container sharing only its isolated
loopback namespace. It verifies readiness, Grafana's exact health query, a synthetic
native push and subsequent query. It uses no real credentials, cluster data, published
ports or external network. CI runs it after caching the reviewed images. This extends
native syntax validation with a real ingestion/query regression check.

These are source corrections requiring the normal source and exact-plan GitOps reviews.
They were not hot-patched onto the approved running configuration. After source merge,
repin the admission workflow to reviewed main, regenerate the exact plan, and obtain the
configuration approvals. Then confirm the live Loki data source, fresh logs, cluster-state
series, alerts and portal views. Isolated regression success does not establish that the
live correction is installed.
