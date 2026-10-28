# Nine-stage DEV DevSecOps pipeline

This change implements a read-only portal projection and stricter shared CI. It does
not turn on automatic delivery, waive approvals, update existing consumer pins, or
claim that historical releases passed the new checks. STAGING/PROD controls are unchanged.

| Stage | Execution and evidence |
| --- | --- |
| 1 Validate source | Existing immutable workflow/helper resolution and bounded profile inputs |
| 2 Code quality | Ruff lint and formatting in an isolated application environment |
| 3 Application tests | Pytest in a separate application environment; no new coverage threshold |
| 4 Source security | Bandit 1.8.6 HIGH severity / MEDIUM-or-higher confidence, and Trivy 0.76.1 built-in secret rules |
| 5 Dependency security | Existing dependency inventory requirement and CRITICAL vulnerability gate |
| 6 Build image | Source-labelled image, one build per architecture, exact archive transfer |
| 7 Container security | Restricted runtime HTTP/UID smoke, image scan, CRITICAL gate, SBOM and identity-bound candidate receipt |
| 8 Publish and verify release | Exact tested image publication, digest pull/smoke, multi-platform index and retained release evidence |
| 9 DEV deployment verification | Existing GitOps admission, Argo/image/replica/HTTP checks plus restricted live pod/Service verification |

Stages 2–5 run in parallel after stage 1; stage 6 requires all four to pass.
Stage 7 consumes stage 6's exact archived image, and release publication requires the
entire reusable CI workflow to succeed. Write-bearing publication jobs never check out
or execute application scripts. This retains existing unsigned evidence; no claim of
cryptographic image signing or full dynamic application security testing is made.

## Source security

Scanner dependencies have a separate hash lock and isolated environment. Only tracked
files are copied into a bounded snapshot, without executing repository code. Symlinks,
missing files, oversized files/trees and a missing Python inventory fail closed.
Scanner configuration and working directory are platform-controlled; repository
`.bandit`, `nosec`, Trivy configuration and ignore files cannot disable these gates.
Reports contain finding rule, file, line and severity only. Matched secret values,
source excerpts and raw scanner stdout/stderr are never uploaded or printed.
Scanner errors, parse failures and incomplete reports fail the stage.

Bandit is a Python-specific baseline, not a complete code audit. The secret scan covers
the checked-out tracked snapshot, not the repository's full history. Vulnerability
thresholds remain unchanged; dependency/image HIGH findings are not newly blocking.

## DEV runtime check

The enrolled local observer uses its existing explicit cluster identity and credentials.
It checks the converged Deployment template and actual selected pods: non-root UID,
RuntimeDefault seccomp, no privilege escalation, read-only root filesystem, dropped
capabilities, no host namespaces/ports or credential-bearing volumes, and no unexpected
init/ephemeral containers. Service exposure must remain ClusterIP with the approved
selector. The health request is bounded and rejects redirects before following them.
No penetration scan, new network exposure or workload mutation is performed.

Successful DEV checks post `aegis/APP/dev-security` against the same app-specific intent
anchor and fingerprint as health. The portal requires trusted, matching evidence no
older than five minutes to pass stage 9. Missing/stale/untrusted evidence remains
unverified. A fresh trusted failed health check makes stage 9 failed. This display does
not replace delivery admission or grant deployment permission.

## Activation

1. Review and merge this platform source through the existing portal owner review.
2. Update a pilot's caller pins and its reviewed catalog workflow/helper pins together
   to the exact approved platform commit. Never move consumer pins silently.
3. Publish a fresh pilot release and exercise the existing signed DEV delivery flow.
4. Upgrade the enrolled observer to this approved source and keep it running.
5. Publish the portal update and approve its exact system runtime plan through the
   existing service controls. Until then, the running portal remains unchanged.
6. Verify all nine stages against the same new release/deployment request. Expand to
   other applications only after the pilot passes.

A registration or resource/access approval is still performed by a human in the portal.
Ordinary DEV delivery retains existing check-gated merge and Argo auto-sync behavior.
Automatic release-to-request submission is a separate integration, not implemented here.

## Verification

Local regression tests cover missing architecture evidence, legacy runs, duplicate and
failed/skipped jobs, unsafe live pod/Service configurations and redacted security reports.
Real pinned Bandit/Trivy scans pass on hello-aegis; a disposable synthetic fixture fails
both scanners even with repository ignore overrides, without publishing the canary.
The runtime check was exercised read-only against live hello-aegis in local Kind.
