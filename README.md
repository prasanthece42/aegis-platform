# Aegis platform foundation

Shared contracts, catalog validation, reusable Python web CI/release and review-only
workload/bootstrap rendering. This is not yet an active multi-app delivery engine. The platform and portal are published separately. Consumer caller migration and live
namespace/controller changes require explicit enrollment and integration validation.

The sibling portal consumes `aegis-platform==0.3.0`. The existing sample keeps its
current CI/release/GitOps behavior.

## Local use

Requires Python 3.12 and uv:

```sh
uv sync --locked
uv run --locked aegis-platform validate
uv run --locked aegis-platform --catalog examples/catalog validate
uv run --locked aegis-platform --catalog examples/catalog resolve --app orders-api --environment dev
uv run --locked pytest -q
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked python tooling/verify_legacy.py
```

The **active catalog is empty**. `examples/catalog` contains two synthetic apps and a
synthetic cluster enrollment for isolated validation. These example IDs/pins must not
be copied into an approved live catalog. Real GitHub IDs, template pins and the enrolled
cluster UID remain setup inputs.

## Shared contracts and catalog

`src/aegis_platform/contracts.py` owns registration, catalog, deployment intent and
desired-state contracts. `canonical.py` owns strict JSON/JCS hashing; `fingerprint.py`
owns app-scoped desired-state identity. The portal uses compatibility imports, preserving
its API schemas and fingerprint fixture. Twelve generated schemas live in `schemas/`;
refresh with `uv run --locked aegis-platform export-schemas`.

The catalog checks filenames, unique app/repository identities, enabled environments,
approved runtime/resource profile IDs and enrolled cluster UID/repository bindings.
New app namespaces, Argo identities and GitOps paths resolve from the app ID. Workflow
and helper pins must match; placeholder zero pins are rejected. Resource profile IDs
are validated here. Bootstrap renders quotas/limits from `policies/bootstrap.json`;
actual capacity measurement and operator application remain setup work.

`check-diff` accepts a complete JSON array of paths and checks app/environment scope.
It is a path predicate only. A future trusted PR adapter must fetch the complete diff,
account for renames/deletions and validate exact values, release evidence, lineage,
approval and concurrency before merge. Schema/path validity grants no deployment or
deletion authority. Tests prove another app's changes leave this app's resolved hash
and desired-state fingerprint unchanged.

The policy fixes DEV/main, STAGING/staging and PROD/prod. It requires human PROD review
and operator sync for protected targets. No controller or namespace is created by validation.

## Reusable Python web CI

`.github/workflows/python-web-ci.yml` implements `workflow_call` for Python 3.12 web apps:

1. Validate app ID, bounded amd64/arm64 matrix, port and supported health path.
2. Resolve the immutable reusable-workflow commit from GitHub run metadata.
3. Check out helpers and source separately, with checkout credentials disabled.
4. Install hash-locked app dependencies in a separate venv; run Ruff/Pytest.
5. Scan dependency inventory and reject every CRITICAL finding, including unfixed ones.
6. Build source/app-labelled images, verify HTTP health and UID 10001 with a read-only
   filesystem, export exact candidate bytes, scan them and generate an SBOM.
7. Bind archive/config/scan identity to app, source, architecture and helper commit in
   unsigned candidate evidence. Optional export is restricted to trusted default-branch
   push/dispatch runs; PR exports fail before source execution.

The health contract is HTTP 200 with `{"status":"ok"}`. This profile requires hash-locked
`requirements.txt` and `requirements-prod.txt`, Ruff and Pytest. It accepts no arbitrary
commands or Kubernetes inputs. Permissions are Contents read and Actions read; no
deployment secrets, image/release publication, GitOps merge or PROD approval capability.
App tests/Dockerfiles run under the existing trusted source-maintainer assumption.
Future privileged publication/admission jobs need fresh trusted checkouts and independent
evidence validation rather than trusting app CI text.

The generated stdlib bootstrap reads GitHub's documented
[`referenced_workflows` metadata](https://docs.github.com/en/rest/actions/workflow-runs#get-a-workflow-run).
It requires one matching SHA-pinned workflow in the proposed `prasanthece42/aegis-platform`
repository, and checks out helpers at that same SHA. The caller cannot provide a separate
helper repository/ref. See GitHub's [reusable workflow model](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows).
If the eventual owner/name changes, update the constant and regenerate before publication.
No OIDC/cloud role or inherited account token is required.

`tooling/render_workflows.py` embeds the tested bootstrap from its template; tests verify
exact agreement. Actionlint validation is not a real GitHub execution, which remains pending.

After an actual reviewed platform commit is published, print a caller for review:

```sh
uv run --locked python tooling/make_caller.py --app orders-api --platform-commit ACTUAL_40_CHARACTER_COMMIT
```

The generator edits no app files and rejects mutable refs/zero placeholders. Tests show
two app callers use the same pinned family with distinct app IDs. It generates CI by
default; `--release` selects the separate default-branch-only release caller described below.

## Release publication

`.github/workflows/python-web-release.yml` calls the same pinned CI family for both CPU
architectures. Fresh publication jobs check out only the resolved platform helpers,
verify downloaded candidate hashes/context and actual loaded image identity, then
publish using the caller repository's short-lived GitHub token. They normalize OCI
descriptor media types without rebuilding config/layers, pull exact digests, rerun
runtime health and record platform receipts. No app-owned Python/shell helper is run
on the host in jobs holding publication credentials.

The index job combines tested immutable child references, exports the complete OCI
graph with preserved digests, and verifies its root, manifests, configs, layers and
descriptor sizes. New release evidence is **schema 3**, with app/repository IDs and
workflow/helper/run bindings; legacy schema-2 sample delivery remains unchanged.
Unsigned receipts are not attestations. Live admission still needs GitHub source/run
verification, approved catalog pins, ancestry, cache proof and current policy.

Source release publication creates or resumes a bot-authored draft, reads uploaded
asset bytes back and compares hashes, then publishes. Matching completed releases are
reused; wrong authors/tags, modified bytes, unexpected assets and incomplete published
releases fail without overwriting. Assets are `release.json` and `image.oci.tar`.
The helper never uses `--clobber` or treats publication as deployment/PROD approval.

Generate an opt-in caller with `tooling/make_caller.py ... --release`. That caller grants
Contents write/Packages write/Actions read; CI/prepare jobs explicitly reduce permissions
to read. No GitOps credential is accepted. Source releases are serialized per repository;
versioned run/attempt tags do not replace older releases. For a GitHub rerun, rerun all
jobs to regenerate current-attempt artifacts; failed-job-only reruns must not consume
receipts from another attempt. Partial images/drafts may require reviewed cleanup.

The publication API is tested with a fake provider. No real GHCR/GitHub release or hosted
workflow run has occurred in this increment. Actual permissions, nested workflow metadata,
registry tooling and live draft recovery remain integration checks before enabling it.

## Workload chart and operator bootstrap

`charts/web-service/1.0.0` renders only Deployment, Service and ServiceAccount. It fixes
UID 10001, dropped capabilities, read-only root filesystem, disabled token mounting,
bounded replicas/resources and immutable image references. Namespace ownership stays
with operator bootstrap. Helm values reject unknown/privileged inputs and mutable tags.
Chart content has a canonical file-hash identity in `charts/web-service/manifest.v1.json`;
CI rejects edits/deletion of a version directory already present at the PR base.

`render-bootstrap` emits namespace, ResourceQuota, LimitRange and one Argo Application
and AppProject per **app/environment**. Projects allow only that namespace/repository
and the three workload kinds, with no cluster resources. DEV gets auto-sync; STAGING
and PROD do not. There is no `CreateNamespace` option or cascading-deletion finalizer.
PROD review metadata is informational; actual human approval and authorized sync remain
separate controls. No apply/sync command or Kubernetes credential is present in this CLI.

```sh
uv run --locked aegis-platform --catalog examples/catalog render-bootstrap \
  --app orders-api --environment dev --context examples/bootstrap-context.json \
  --output .local/orders-bootstrap-review
```

Outputs must go to a new/empty directory. The example context is synthetic, not live
enrollment. `reviews/bootstrap/` holds review metadata separately from Kubernetes files.
Review and commit chart/values/controller definitions to the intended GitOps branch
before any operator applies bindings. Existing sample namespaces/controllers are not
accepted as new naming defaults and are never renamed by this generator.

The initial `small` profile proposes 100m/128Mi requests and 500m/256Mi limits, at most
two replicas plus one rollout surge. Quota permits the default and app service accounts.
The Pod Security policy is pinned to v1.35 to match the existing local profile; operators
must validate enrollment/version/capacity before use. This is not a measured capacity claim.

`render-release --app ... --release ... --output ...` writes source-bound DEV values and
receipt/pointer files for review. It does not assert live release eligibility or cache
availability, merge Git or deploy. Protected value planning remains blocked until promotion
admission exists. Bootstrap for protected targets can be reviewed independently.

## Portal contract bundle

Before a remote package release exists, the portal carries a wheel in `vendor/`, with
distribution checksum and source-file manifest. Its requirement exports pin the hash;
the Docker build copies the wheel before dependency installation. The portal build
therefore needs no sibling checkout. This is a local source snapshot, not a signed or
published platform release or proof of deployed workflow identity.

After deliberate shared-package changes, run:

```sh
uv run --locked python tooling/refresh_portal_vendor.py
```

Then run `uv lock --refresh-package aegis-platform` and `uv sync` in the portal,
regenerate both requirement exports, and run the portal's API,
contract and container checks. Bump the package version for changed published content;
do not replace a released artifact under the same version.

## Sample migration and remaining work

`migrations/sample-api.baseline.json` records 70 source/workflow/GitOps files and the
sample's existing namespace, Argo Application/project and branch bindings. Its checker
is read-only. This snapshot is not enrollment or a claim of current runtime health.
Legacy namespaces do not follow the new naming rule; a later explicit compatibility
and cutover design must preserve or deliberately migrate those bindings. No replacement
namespaces, changed namespace ownership or chart cutover are implied here.

Live publication/bootstrap integration, App/repository/cluster setup, legacy enrollment,
a second real app, cache/health adapters and scoped deployment
requests/GitOps checks remain. Example catalog and local container tests do not prove
independent Argo rollout/failure/rollback. Portal deployment remains disabled. PROD
retains human review and authorized operator sync.

## Delivery admission implementation

`delivery.py` verifies schema-3 receipts against independently fetched GitHub repository,
release and successful default-branch run metadata, including both immutable reusable
workflow pins. It checks current grants, app-scoped desired-state preconditions, fresh
observer evidence, and exact-head independent human PROD review. This pure admission
module is tested locally; a hosted GitOps request worker and local multi-app observer
are still required before live deployment requests are enabled.
