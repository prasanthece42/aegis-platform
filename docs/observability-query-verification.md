# Query alignment after live rollout

The reviewed Loki/HPA corrections are active through GitOps PRs #30/#31. All seven
monitoring workloads are ready and Argo is Synced/Healthy. Live verification established:

- Six Prometheus scrape targets are up; cluster-state series now include node conditions,
  deployment availability, container readiness/restarts, and quota/statefulset metrics.
- Loki bounded queries return streams; Grafana's Loki and Prometheus health checks pass.
- Eight new portal requests produce eight Tempo spans and eight matching structured logs.
  Both are retrievable through Grafana's authenticated server-side data source proxy.
- Tempo's Grafana health method is unimplemented in this local Grafana version, while
  the actual trace query through Grafana returns HTTP 200 with eight spans.

A final query audit found that the pinned collector exports `k8s_container_ready`, not
`k8s_pod_condition_ready`. The latter returned no namespace values; using the collected
`k8s_pod_cpu_usage` returned ten namespaces. This candidate corrects namespace discovery,
labels readiness panels as container readiness, and evaluates the pod alert from the
minimum container readiness per pod. It does not claim to measure custom readiness gates.

The collector already emits node network byte counters; the Kubernetes network panel now
uses their measured rate instead of an obsolete future-instrumentation note. Fixture
`tests/fixtures/observed-observability-metrics.json` records only verified metric names and
binds them to the exact collector image. Tests reject dashboard references outside that
inventory, except Prometheus's conditional `ALERTS` series.

Grafana 11.5.2 can use its authenticated GET `/api/v1/series` fallback for metric-filtered
namespace discovery; see the [pinned upstream implementation](https://github.com/grafana/grafana/blob/v11.5.2/packages/grafana-prometheus/src/metric_find_query.ts).
The read-only proxy now permits that metadata endpoint. The native auth test proves valid
GETs reach the upstream and POSTs remain denied. No write endpoint or credential exposure
is introduced. The standalone Grafana check's report now explicitly describes its isolated
scope rather than claiming the real cluster has no deployed backends.

These are a separate query/provisioning source candidate. They are not hot-patched onto
provisioned dashboards. They need normal source and exact-plan GitOps review; the live
backend connectivity corrections are already deployed and working independently.

The hello-aegis 1.1.0 release is published and cached, but the running pilot still needs
promotion through its existing signed delivery path. Its application HTTP signals must
not be inferred from the portal's verified telemetry. The operator CLI identity is not a
substitute for the portal's GitHub App user authorization flow; a read-only CLI preview
failed safely without submitting any deployment request.

Validation of this candidate: 279 platform tests pass; native backend/gateway/auth/alert
checks and real isolated Grafana provisioning pass. Fifteen distinct proposed Prometheus
expressions were executed against the live backend; all returned successful responses,
and readiness/network queries returned real samples. Empty conditional alert series were
accepted as zero active alert samples, not replaced with fabricated values.
