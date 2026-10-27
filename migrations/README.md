# Preserved sample enrollment review

The configured portal's Kubernetes runtime and real browser GitHub sign-in are verified.
The existing sample still uses its original pipeline and schema-2 release evidence. The
new generic catalog/delivery engine admits schema-3 evidence and new per-app bindings;
copying the sample into that catalog would misrepresent its namespace/controller and
release contract.

`sample-api.baseline.json` freezes 70 source/workflow/GitOps files and original bindings.
`sample-api.enrollment-review.json` describes those actual identities and destinations
for the next compatibility review. Its stage is explicitly `review-only-not-enrolled`.
It enables no portal delivery or resource creation/rename and retains human PROD review
and operator sync. It is outside the active catalog.

From the platform checkout, run the read-only audit with the existing enrolled operator:

```sh
PYTHONPATH=src:. .venv/bin/python -m tooling.audit_legacy_enrollment \
  --agent-config .local/agent.json --operator-from-gh
```

The audit checks local and remote baseline file identity, real repository IDs, the
explicit loopback cluster UID, and all three environments' repository/live Argo bindings,
project definitions, values/pointer/retained receipt/live image consistency and enforced
branch protection. It issues only metadata reads. It never creates a token for the portal,
proposes a deployment, changes credentials, applies resources or syncs Argo.

The timestamped report is ignored `.local/legacy-enrollment-audit.json`. It records the
observed Git revisions and Argo states. It explicitly does not establish fresh release
eligibility, trusted promotion health, catalog enrollment or completion of a cutover.
Schema-2 evidence is never relabelled schema 3.

The live initial audit passed for:

| Environment | Namespace | Argo Application | Branch |
| --- | --- | --- | --- |
| DEV | aegis-dev | sample-api-local | main |
| STAGING | aegis-staging | sample-api-staging-local | staging |
| PROD | aegis-prod | sample-api-prod-local | prod |

The next implementation must provide an explicit legacy catalog/evidence adapter and
portal capability display, prevent duplicate source enrollment, preserve the existing
writer identity until reviewed cutover, and prove app-specific update/failure/rollback
isolation. Review controller/policy/chart propagation per target branch before changing
writers or enabling new portal operations. This audit grants no deployment authority.
