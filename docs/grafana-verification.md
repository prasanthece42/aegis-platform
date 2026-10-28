# Grafana verification record

Evidence from this implementation session. These results describe the current local
source tree, including pre-existing uncommitted monitoring work. No changes were pushed,
cloud resources created or Kubernetes workloads modified.

| Check | Actual result | Boundary |
| --- | --- | --- |
| Local runtime inventory | Kind control-plane container running; hello-aegis healthy; no monitoring namespace/services/pods | Read-only kubectl inside local node; EKS untouched |
| Platform pytest | 236 passed | Includes 4 new Grafana contract/security/dashboard tests |
| Ruff lint / format | Passed | Entire platform source and tooling |
| Grafana native startup | Passed, database healthy | Real cached Grafana 11.5.2, disposable Docker container, network none |
| Data source provisioning | Three expected UIDs loaded, read-only, password reported as secure and omitted from API | Real Grafana API; no backend connectivity |
| Dashboard provisioning | All six dashboard UIDs loaded and marked provisioned | Real Grafana provisioning; no live panel data |
| Anonymous access | Data source API denied | Real Grafana HTTP check |
| Effective Grafana settings | Anonymous access, signup, embedding and Grafana Alerting disabled | Real authenticated admin settings API |
| Existing backend validation | All 12 pinned-image checks passed | Five backend native config validators, five nginx validators, synthetic alert fire/clear, query authentication |
| Asset syntax | Provisioning, CI YAML and six dashboard JSON files parse | Offline structural check |
| Package | Platform wheel includes Grafana module and all eight asset files | Wheel archive inspection |
| Review candidate | Renderer completed with local placeholder revision | Not admitted; regenerate from exact reviewed clean source |
| AWS changes | None | No AWS calls, Terraform or context switching |

The first Grafana smoke attempt exposed a test assumption: the data source list API
omits `secureJsonFields`. The test now checks each data source detail API and passes.
A package inspection initially selected an older wheel from `dist`; the exact current
0.4.6 wheel was then verified. No forced asset inclusion is needed.

Reproduce from `aegis-platform`:

```sh
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/python -m pytest -q
PYTHONPATH=src .venv/bin/python -m tooling.check_grafana
PYTHONPATH=src .venv/bin/python -m tooling.check_observability
.venv/bin/python -m hatchling build -t wheel
```

Docker checks require the reviewed images cached locally and Docker socket access.
They create temporary isolated containers, publish no ports, never query Kubernetes,
use synthetic credentials and remove those containers/credential files afterwards.
Machine-readable results are ignored artifacts at `.local/grafana-validation/results.json`
and `.local/observability-validation/results.json`. CI now pulls the pinned Grafana image
and executes the real provisioning/authentication check; remote CI has not run in this session.

## Checks not established

- Prometheus/Loki/Tempo deployed connectivity, exact live metric names/units and dashboard data.
- Actual hello-aegis requests producing metrics, logs, spans or working correlation links.
- Browser portal-to-Grafana navigation or developer SSO; no shared developer link was enabled.
- Cross-tenant data denial. Shared cluster-wide credentials are intentionally operator-only.
- Deployed collector/backend failure behavior, alert notifications or incident acknowledgement.
- Kubernetes admission/schema validation, policy-enforcing CNI behavior or network/TLS security.
- Patched image support/CVE assessment, production HA, durable Grafana state or disaster recovery.
- EKS authenticated collection and private cross-cluster query/ingestion.

The shared monitoring stack is an unapproved source candidate and is absent from the
local cluster. Its trusted exact-plan admission/bootstrap controls remain prerequisites.
Activating that stack outside the existing review controls would bypass the requested
GitOps approval boundary. The implementation therefore stops at verifiable local source
and isolated runtime checks. [The runbook](grafana-observability.md) describes review,
activation prerequisites and subsequent live checks. This is not production-ready.
