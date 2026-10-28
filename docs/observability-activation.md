# Reviewed local observability activation

The implementation now includes the previously missing exact-plan admission and scoped
bootstrap tools. Source review, immutable publication and actual operator approval remain
required. This document describes the implemented path; it is not evidence of activation.

## What changes

`service_plan()` combines the existing monitoring renderer with Grafana under one
`platform-services/aegis-observability/manifests` directory. The controller tracks only
`platform-observability`. The Argo project permits the Grafana NetworkPolicy; all existing
read-only RBAC, storage and resource restrictions remain. Configuration hashes on pod
annotations trigger rollouts when ConfigMaps change. The public review record binds the
platform revision, telemetry/access policies, exact resources and operator-only Grafana
profile. No secret values are rendered.

`ObservabilityServicePolicy` enrolls the existing platform App bot and human local
operators. Normal catalog validation checks operator enrollment and exports a JSON schema.
Admission checks additionally require an active proposer issuer, matching repository IDs,
cluster UID, clean current trusted source checkout and exact JSON equality for every path.
Extra files, missing files, credentials, changed images, renames, deletions and fork PRs
fail. Review must be by an independent enrolled human on the current head. Drafts,
dismissals and outstanding change requests block success. A changed/closed PR receives
no stale success status. No proposed source is checked out or executed.

The generated workflow uses the existing pinned Actions and a full trusted platform SHA.
The dedicated status is `aegis/observability-policy`. Updating platform main requires
repinning/reviewing the workflow; stale renderer code is intentionally rejected.

Bootstrap defaults to **verification only**. It verifies the authoritative merged PR
identity with the existing GraphQL/REST helper, fresh trusted status, current-head human
review and branch protection. Protection must enforce admins, approving/stale-dismissed
reviews, strict checks bound to GitHub Actions, no force pushes/deletion or review bypass.
The local agent requires an explicit kubeconfig/context, loopback API, enrolled cluster
UID and approved node/IP. Existing unrelated resources cannot be adopted. Public resources
receive client dry-run validation before any mutation. It rechecks review and source state
immediately before applying. Credential changes require an explicit rotation procedure.

With `--apply`, the tool installs only Namespace, quota, limits, AppProject, Application
and the two private Secrets. Secrets use `create`, not last-applied annotations. Argo
owns all workload manifests. This tool does not update running portal or hello-aegis
releases and cannot authorize AWS changes.

## Review and promotion order

1. Review and merge the platform source candidate, including the new public policies,
   schema, renderers, native config checks and admission tests. Native CI pulls immutable
   images and validates Grafana, all backends/gateways and synthetic alert transitions.
2. From that exact clean platform main checkout, generate the pinned workflow and render
   the combined plan. The workflow belongs in the GitOps default branch through its normal
   reviewed PR. Never use the placeholder SHA in local test artifacts.
3. Establish the dedicated branch/protection under independent repository administration;
   use the requirements above. This implementation changes no repository protection.
4. Have the enrolled App propose the rendered files into `platform-observability`. The
   validator must post a successful dedicated status only after independent human review.
   Merge through the protected branch. Human-authored substitutes fail the bot identity
   check; do not weaken that check or use an administrator bypass.
5. Prepare private credentials, verify bootstrap, then apply the reviewed controller plan.
6. Release and promote the instrumented hello-aegis and portal candidates through their
   existing source/release/cache/deployment controls. They cannot be replaced with mutable
   local images. Verify live telemetry, alert routes and tenant restrictions before enabling
   developer Grafana links.

Commands from the reviewed platform checkout (rendering/admission uses existing scoped
GitHub App environment variables, as in `tooling.portal_system`):

```sh
PYTHONPATH=src .venv/bin/python -m tooling.observability_service workflow \
  --revision FULL_REVIEWED_MAIN_SHA --output .local/observability-admission.yml
PYTHONPATH=src .venv/bin/python -m tooling.observability_service render \
  --output .local/observability-service-plan
PYTHONPATH=src .venv/bin/python -m tooling.observability_service check-pr --number PR_NUMBER
```

One-time secret preparation accepts the existing protected OAuth credential JSON. It
reuses the domain-separated query derivation and verifies the public policy fingerprint;
other capabilities and Grafana keys are independently generated. Files are operator-owned
mode 0600 in an exclusively created 0700 directory. Existing directories are never overwritten.
Use the actual protected file path; never paste secrets into CLI arguments or Git.

```sh
PYTHONPATH=src .venv/bin/python -m tooling.bootstrap_observability \
  --credentials .local/observability-credentials \
  --prepare-from-oauth PATH_TO_PROTECTED_OAUTH_JSON
PYTHONPATH=src .venv/bin/python -m tooling.bootstrap_observability \
  --credentials .local/observability-credentials --agent-config .local/agent.json
PYTHONPATH=src .venv/bin/python -m tooling.bootstrap_observability \
  --credentials .local/observability-credentials --agent-config .local/agent.json --apply
```

These commands are deliberately ineffective before actual trusted source publication,
protected branch merge, exact status/review and cluster checks. Chat approval is not a
substitute for the configured GitOps review record.

## Pilot fix and measured runtime

The pilot source now calls the portal Service on HTTP port 80 and supplies its reviewed
public Host authority (`localhost:8443` locally; `AEGIS_PORTAL_HOST` for a reviewed alternate
deployment). Only that authority and generated traceparent are sent; browser credentials
and query strings are excluded. It does not send a privileged portal session.

A read-only request from the **running** hello-aegis pod to that Service/Host returned
HTTP 200 and portal version 0.3.1. This verifies private DNS/networking and Host handling;
it does not prove the new instrumented image has been deployed. The running hello-aegis
is still 1.0.0. Pilot source tests validate trace propagation and the corrected request.

The existing HTTPS listener at `https://localhost:8443` now returns a healthy response
when verified against `.local/tls/localhost.crt`. A gateway start attempt found the port
already occupied; that existing process was preserved. No live application deployment,
cloud API, source merge or approval bypass was performed by these checks.

## Verification boundaries

Platform tests cover exact-tree mutations, forks, wrong issuers/branches, self/stale/bot
reviews, changed PR heads, stale/dirty trusted code, cluster mismatch, inactive issuers,
weakened protection, private credential fingerprints/overwrite refusal and unrelated
resource adoption. Native backend validators accept ten rules and the enabled crash-loop
receiver metric. Deployed cross-tenant tests, live failure injection, notification delivery,
SSO and patched production Grafana remain outstanding as described in the HLD.
