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
