# Multi-service applications — 0.5.0 source candidate

This adds the opt-in `python312-multiservice` runtime and the new immutable
`charts/multi-service/1.0.0` chart. Existing `python312-web` callers, receipts and
chart directories retain their behavior. Implementation and local checks do not
publish these helpers, update the configured portal or deploy the commerce app.

## Application contract

The source repository supplies `aegis-stack.json`, validated against
`schemas/stack-definition.v1.json`. It declares 2–8 Python web services, normalized
Docker build paths/arguments, non-privileged ports, readiness paths, 1–2 replicas,
public environment defaults, internal service URL references and database/cache
Secret key references. There may be at most twelve application replicas.
Service names leave room for the application's prefix in Kubernetes DNS names.
Unknown fields, path traversal, undefined service references, literal sensitive
environment keys, overlapping environment sources and reserved dependency names
fail validation. Compose files are never interpreted by the portal or GitOps worker.

The first dependency profile, `postgres17-redis7-nginx`, pins three platform-owned
images. These profile pins are immutable compatibility inputs; a future dependency
upgrade needs a separately versioned profile/chart and reviewed migration. All
application Services and dependencies remain private. The Nginx entry Service is
port 80 and forwards `/api/{service}/...` to each component's configured port.
The gateway container listens on 8080. Public cloud load balancers are outside this
profile. The initial profile has one PostgreSQL database shared by the app's
services; it is not a managed or highly available database offering.

## Registration and configuration

ZIP inspection detects and validates the source contract without executing it.
After upload, the developer reviews services and changes only declared public
environment defaults. Existing repositories have a **Load services from selected
repository** action. The backend independently fetches the contract at the exact
selected source commit and rechecks it during submission. It never trusts the
browser's topology. Public overrides and the runtime Secret name enter the reviewed
catalog entry and its signed registration payload.

The runtime Secret must be named `{app_id}-runtime` in the application's namespace.
Service references are limited to its `database-url` and `redis-url` keys. The
dependency containers use `postgres-password` and `redis-password`. No Secret values
enter registration payloads, public Git, generated chart values or hosted release CI.
API/worker processes still have no Kubernetes access. A developer sees reference
names, not secret-entry fields. Credentials are an operator target-setup step.

## Release and admission

`python-stack-ci.yml` resolves its helper checkout from immutable GitHub workflow
metadata, runs hash-locked quality/tests and source scans, then builds/scans every
service on native amd64 and arm64 runners. The pinned helper creates a disposable
network, starts dependencies and all services, verifies readiness and generated
gateway routes, and runs application integration tests inside an unprivileged
container. Test containers receive only synthetic database credentials, no GitHub
credentials or Docker socket. Cleanup runs on success and failure.

Publication jobs execute only pinned helpers against downloaded candidates. They
verify source/run/profile, image archive hashes, config/manifest bindings, inventory,
scan policy and SBOM hashes before loading images. Docker manifest IDs and config
digests are distinct: both classic and containerd stores are supported. Transport
is normalized to OCI before publication, then pulled configs and the complete stack
are tested again. Source-owned test scripts never execute in publication jobs.

Schema-4 `release.json` retains the primary service's existing source-scoped image
identity, the other service receipts, complete topology hash and fixed dependency
images. One `image.oci.tar` contains exactly one verified multi-platform OCI graph
per application service. Receipt children must agree on source repository ID,
commit, run, attempt and helper pin. No partial stack release is admitted. Scan
reports and SBOMs are retained separately for fourteen days.

Delivery independently requires the approved stack CI/release workflows and exact
catalog topology. Source/default-branch/bot identity, current grants, source lineage,
signed request journals, native GitOps checks and fresh observer evidence remain
mandatory. Promotions require the exact complete prior-environment release receipt,
in addition to the prior environment's fresh health evidence. PROD retains its
independent human approval and operator sync gates.

Source security runs in a separate fresh job that never executes application
tests or installs application dependencies. It uses the existing pinned Bandit
and redacted Trivy secret-scanning policy, plus the dependency vulnerability gate.

## GitOps and observation

Bootstrap derives bounded namespace quotas for every replica, rollout surge,
dependency, Service and PVC. The AppProject adds only ConfigMap, StatefulSet and PVC
to the existing namespace whitelist. It never allows Secret creation or cluster
resources through application delivery. The chart renders only the platform's
exact admitted plan; it is not an arbitrary-manifest application API.

Every workload disables service-account token mounts, uses bounded resources and a
restricted security context. PostgreSQL/Redis use image-compatible non-root users
and persistent volumes; Nginx and Python services use read-only root filesystems.
PVCs have explicit retention annotations. GitOps/Helm deletion is not a database
backup strategy; operators own backup, restore and namespace deletion procedures.

The local observer verifies every application OCI graph before importing any graph,
caches fixed dependency images by digest, and checks Argo's exact app-scoped Git
revision. It verifies every component's image/configuration/generation/replicas,
private Service, serving pods, restricted security, gateway config and bound PVCs,
then probes every service and the gateway. A ready gateway alone cannot establish
whole-app health. Component observations use current intent anchors and fingerprints;
the portal labels missing or stale measurements. Existing namespace-scoped monitoring
remains available; this feature does not install a new telemetry stack or per-service
instrumentation automatically.

## Activation order — operator work, not performed by local implementation

1. Publish and review a new immutable platform commit containing these contracts,
   helpers, workflows, schemas and chart. Do not point consumers at a branch name.
2. Review updates to the GitOps delivery-request and delivery-policy workflow helper
   pins. The current published pins do not understand schema-4 receipts. Keep the
   existing metadata-only checks and protected-branch approvals. Review the portal
   system validator pin separately when upgrading the configured front door.
   Install `validate-stacks.yml` and add its `stack-chart` check to the protected
   environment branches. It renders only managed stack pointers and runs strict
   Kubernetes schema validation. The historical sample workflow remains unchanged.
3. Update the reviewed public portal configuration with `multiservice_versions`:
   matching published workflow/helper SHA, chart version `1.0.0` and the output of
   `python -m aegis_platform chart-identity --chart charts/multi-service/1.0.0`.
   Update its `delivery_workflow_commit` to the reviewed GitOps workflow commit.
   Publishing source alone does not install the configured portal. Its new immutable
   release, exact system plan and operator bootstrap still need their existing review.
4. Run the updated local observer from the reviewed platform revision. Preserve its
   explicit loopback cluster context and UID. Do not switch the global kubeconfig.
5. The developer uploads `commerce-demo.zip`, reviews defaults/Secret references,
   installs the proposed source callers through an authorized workflow-writing
   maintainer and submits registration. Review/merge its catalog and exact bootstrap
   plan using the ordinary protected workflow. Bootstrap the app namespace/budget.
6. Verify operator credential provisioning, then explicitly create it when reviewed:

   ```sh
   PYTHONPATH=src:. .venv/bin/python -m tooling.stack_credentials \
     --agent-config .local/agent.json --app commerce-demo
   # Repeat with --apply only after reviewing this app's exact target setup.
   ```

   This uses the existing explicitly injected operator/App credentials. It checks
   repository identities, current observer identity, enrolled cluster UID and exact
   merged bootstrap bytes. Values are generated in memory and sent to Kubernetes
   stdin. Existing Secrets are preserved; rotation is separate work. No secret
   values are printed or persisted to a local file.
7. After both native CI paths publish a validated release and the observer caches it,
   the developer selects that release and confirms DEV deployment **in the portal**.
   The platform worker proposes the exact multi-service values; Argo reconciles them.

Until step 3 is installed, the running portal cannot offer this new profile. An
absent `multiservice_versions` field disables it; an attempted API registration fails
with `STACK_SETUP_REQUIRED`. This avoids proposing callers with fabricated pins.

## Validation

Run platform pytest/Ruff, generated workflow/schema checks and chart identity checks.
`tests/test_stack*.py` cover invalid manifests, cross-source/incomplete receipts,
complete-bundle validation before cache mutation, real Helm rendering, environment/
Secret boundaries, runtime drift and executable pinned workflow bootstraps.
The portal adds API and desktop/mobile browser walkthroughs. Local native CI evidence
is not a GitHub publication, amd64 execution, portal activation or deployed health claim.
