# Aegis platform

Shared contracts, reusable Python web CI/release, signed delivery admission and local
Kind observation for Aegis. The portal authorizes requests, GitOps records approved
configuration, and Argo deploys it. PROD requires independent human approval and an
explicit authorized operator sync.

## Verified live path

The public `prasanthece42/aegis-portal` repository is enrolled in the active catalog.
Its published amd64/arm64 releases use the pinned reusable workflow, immutable OCI
images and source-bound schema-3 receipts. The configured GitHub App signs portal
requests; the GitOps worker creates App-authored PRs and checks current grants,
source lineage, app-specific state and fresh cache/health evidence.

Two real DEV requests reached Argo Synced/Healthy. GitOps PR #18 exercised native CI
and automatic DEV merge without execution approval. The sample application's DEV,
STAGING and PROD pod identities and images stayed unchanged during that update.
Those observations establish this integration path; they do not establish legacy
catalog enrollment, protected-environment delivery or rollback support.

The existing sample retains its original controllers, namespaces and pipeline.
`migrations/sample-api.baseline.json` and `tooling/verify_legacy.py` protect the recorded
70-file baseline. Example catalog entries are synthetic and are never active enrollments.

## Local checks

Requires Python 3.12, uv and Helm for chart tests:

```sh
uv sync --locked
uv run --locked aegis-platform validate
uv run --locked aegis-platform --catalog examples/catalog validate
uv run --locked pytest -q
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked python tooling/verify_legacy.py
```

`aegis-platform export-schemas` regenerates the public contracts. CI also checks the
reusable workflow generator, versioned chart identity and historical chart immutability.
`tooling/make_caller.py` prints opt-in callers pinned to an actual platform commit.
The existing consumer's workflow/helper pin remains independent of package versions.

## Delivery boundaries

* Repository-scoped App tokens create signed, idempotent journal records and proposals.
  They have no Kubernetes credentials, Administration permission or branch bypass.
* Source publication runs trusted pinned helpers in fresh checkouts and reads uploaded
  release assets back. Unsigned receipts are validated against live GitHub run metadata;
  they are not cryptographic attestations.
* The worker verifies the complete PR diff, exact desired files, current source access,
  app-specific fingerprints, source ancestry and trusted fresh observer statuses.
* DEV permits auto-merge/Argo auto-sync after checks. Protected targets retain review
  and operator sync. Successful submission or schema validation is never deployment health.
* `local_agent.py` uses an explicit enrolled loopback cluster UID and operator identity
  to verify/import OCI graphs and observe Argo, replicas, image and Service health.
  It does not apply workloads or approve PROD.

`charts/web-service/1.0.0` fixes non-root/read-only pods, disabled service-account tokens,
immutable image digests and bounded resources. New namespaces/controller bindings are
rendered for review separately; existing sample bindings are preserved.

## Configured portal service

Version 0.4.4 adds an operator-owned runtime plan for the configured front door in
`aegis-portal-system`, separate from the managed `aegis-portal-dev` release-validation app.
The plan is not installed merely by publishing this package.

`policies/portal-system.json` contains public configuration and the expected signing
public key. `python -m tooling.portal_system render` generates exact public manifests,
bootstrap resources and retained release evidence after live release/cache admission.
The selected source must declare the supported portal runtime contract.

The dedicated GitOps branch `platform-system` must enforce the
`aegis/platform-service-policy` check and an independent human operator review of the
current PR head. The validator checks every rendered file, trusted App authorship,
immutable source/run metadata and fresh cache evidence. It never accepts Secret objects
or private material in Git. The workload is a singleton with `/ready` readiness and no
Kubernetes credentials. A signing-key mismatch prevents live startup.

After the branch/CI are installed and the exact runtime plan is reviewed and merged:

```sh
PYTHONPATH=src:. .venv/bin/python -m tooling.bootstrap_portal \
  --agent-config .local/agent.json \
  --credentials '../aegis-portal/.local/github-app' --operator-from-gh
```

The enrolled operator rechecks branch protection, actual exact-head human approval,
required CI, release/cache evidence, active signing registry and cluster identity. It
creates only namespace/budget, a private runtime Secret and Argo controller bindings.
Argo reconciles the public ConfigMap, ServiceAccount, Deployment and Service. Credentials
enter Kubernetes through stdin and are never committed or stored in last-applied metadata.
An existing different Secret blocks bootstrap and requires an explicit rotation procedure.

The portal repository supplies a loopback HTTPS gateway with a fixed Service forward,
cluster-UID checks and reconnection after pod replacement. The gateway holds operator
cluster access; the portal pod does not. A host-run portal remains an independent
operator recovery path while the same reviewed configuration and keys remain valid.

## Shared package and remaining integration

Version 0.4.5 adds the `PortalOwnerPolicy` contract and optional reviewed
`policies/portal-owner.json`. Its numeric repository binding and explicit GitHub user
IDs grant read-only access to the portal's Platform owner console. This role is separate
from application ownership, onboarding and deployment grants. An empty owner list
disables access. The CLI validates the policy against the delivery repository identity
and exports `schemas/portal-owner-policy.v1.json`. Role changes use the protected main
branch's independent maintainer review; the portal rechecks the current grant on each
owner request. No Kubernetes credentials, branch bypass or write capability is added.

The portal carries a hash-pinned local wheel and source manifest, built by
`tooling/refresh_portal_vendor.py`. This is a local distribution snapshot, not a signed
package release. Bump versions before changing published content, refresh the wheel,
then refresh portal locks and requirement exports and run its checks.

The configured system runtime and separate `hello-aegis` DEV application have completed
live integration. Remaining work includes reviewing and activating the owner console,
explicit legacy sample enrollment, protected-target end-to-end evidence, rollback and
advance controls, and credential rotation/recovery procedures. Keep these separate from
the already verified DEV request path. Design references are in the sample repository's
`DOCS/22`–`28` documents.


## Shared monitoring candidate (0.4.6)

`policies/observability.json` binds the enrolled cluster, public kubelet certificate chain,
private query capability fingerprint and seven immutable component images. The pure
`observability_plan` renderer produces public manifests for Prometheus, Alertmanager, Loki,
Tempo, the OpenTelemetry Collector and a bounded container-log reader. It emits no Secret
values and performs no cluster writes. The plan includes an independent operator review
record; a rendered candidate is not evidence of approval or installation.

Backends bind to pod loopback behind authenticated Nginx query/ingest proxies. This provides
query authentication independently of local CNI NetworkPolicy support. Read-only proxy pods
place all temporary paths under `/tmp`. The collector replaces application-supplied Kubernetes
identity using connection metadata. The log reader uses bounded read-only Kubernetes access,
excludes its own namespace, scrubs common credentials and advances cursors only after full
OTLP acceptance. Log collection continues when another application namespace is unavailable.
Retention is bounded to 24 hours and PVC capacity; alerts have no external notification target.

Run the ordinary unit suite and then, with all seven reviewed images cached in Docker:

```sh
.venv/bin/python -m tooling.check_observability
```

This check runs five native backend validators, all five proxy validators, query authentication
checks and a simulated hello-aegis alert firing/clearing test in disposable containers. Every
container has networking disabled, no published ports, a read-only filesystem and synthetic
credentials. It never pulls images, contacts Kubernetes or changes deployments. Evidence is
saved in `.local/observability-validation/results.json`. The checker requires local OpenSSL.

Live installation, trusted GitOps admission/bootstrap tooling and an instrumented request
through deployed hello-aegis and the configured portal still require reviewed activation.
Passing offline checks does not establish live ingestion, readiness or deployment health.

## Central Grafana local candidate

The [Grafana architecture and runbook](docs/grafana-observability.md) records discovery,
placement/security decisions, six dashboards, private prerequisites, GitOps review,
alert ownership and EKS/hardening gaps. The [verification record](docs/grafana-verification.md)
separates actual container checks from blocked deployed telemetry checks.

`python -m aegis_platform.grafana --policy policies/observability.json --revision
FULL_REVIEWED_SHA --output .local/grafana-candidate` renders a separate operator-only
add-on without changing the existing seven-component policy or applying anything.
With the pinned Grafana image cached, run `PYTHONPATH=src .venv/bin/python -m
tooling.check_grafana` for actual isolated provisioning/authentication verification.
Developer Grafana access is disabled until backend tenant isolation is established.

The [reviewed activation path](docs/observability-activation.md) now provides combined
exact-plan rendering, pinned GitOps admission workflow generation, independent-current-head
review checks, and a local bootstrap that defaults to verification only. It preserves
existing deployment approval requirements and never creates AWS resources.
