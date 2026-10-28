"""Trusted metadata-only telemetry PR admission; never executes proposed repository code."""

import argparse
import os
import re
from pathlib import Path

from aegis_platform.bootstrap import write_plan
from aegis_platform.canonical import strict_json
from aegis_platform.observability_policy import OBS_BASE, ObservabilityPolicy
from aegis_platform.observability_service import (
    CONTEXT,
    SUCCESS,
    ObservabilityServicePolicy,
    service_plan,
    verify_exact_tree,
    verify_operator_review,
    verify_proposal,
)
from aegis_platform.worker import tree_files
from tooling.delivery import worker


def admitted_plan(engine):
    revision, catalog, delivery, trust, _bootstrap = engine.snapshot()
    policy = ObservabilityPolicy.model_validate(
        strict_json(engine.platform.file("policies/observability.json", revision))
    )
    access = ObservabilityServicePolicy.model_validate(
        strict_json(engine.platform.file("policies/observability-service.json", revision))
    )
    cluster = catalog.clusters[policy.cluster_id]
    if (
        policy.platform_repository_id != delivery.platform_repository_id
        or policy.gitops_repository_id != delivery.gitops_repository_id
        or policy.gitops_repository != delivery.gitops_repository
        or cluster.cluster_uid != policy.cluster_uid
        or cluster.gitops_repository_id != policy.gitops_repository_id
        or not set(access.operator_user_ids) <= set(delivery.observer_user_ids)
        or access.proposer_bot_user_id
        not in {issuer.bot_user_id for issuer in trust.issuers if issuer.active}
    ):
        raise ValueError("Telemetry identity differs from trusted catalog/delivery enrollment")
    # Never render current policy using stale or locally modified trusted code/assets.
    # Hosted workflows check out this immutable SHA; local bootstrap must do the same.
    import subprocess

    root = engine.root
    current = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    dirty = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"], cwd=root, text=True
    ).strip()
    if current != revision or dirty:
        raise ValueError(
            "Use the clean trusted platform main revision, including assets and policies"
        )
    return service_plan(policy, access, revision), policy, access, delivery


def check_pr(engine, number):
    pr = engine.gitops.repo("GET", f"pulls/{number}")
    if pr.get("merged_at") or pr["state"] != "open":
        return
    sha = pr["head"]["sha"]
    state, description = "failure", "Observability manifest admission failed"
    try:
        expected, policy, access, delivery = admitted_plan(engine)
        verify_proposal(pr, engine.gitops.pages(f"pulls/{number}/files"), policy, access, expected)
        verify_exact_tree(
            tree_files(engine.gitops, sha, lambda path: path.startswith(OBS_BASE + "/")),
            expected,
        )
        try:
            verify_operator_review(
                pr, engine.gitops.pages(f"pulls/{number}/reviews"), access, delivery
            )
        except ValueError:
            state, description = (
                "pending",
                "Exact telemetry plan; independent operator review required",
            )
        else:
            state, description = "success", SUCCESS
    finally:
        latest = engine.gitops.repo("GET", f"pulls/{number}")
        if (
            latest["state"] == "open"
            and not latest.get("merged_at")
            and latest["head"]["sha"] == sha
        ):
            engine.gitops.repo(
                "POST",
                "statuses/" + sha,
                {
                    "state": state,
                    "context": CONTEXT,
                    "description": description,
                },
            )
    print(description)


def workflow(revision):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Pin a full reviewed platform revision")
    return f"""name: Observability operator admission
on:
  pull_request_target:
    branches: [platform-observability]
    types: [opened, synchronize, reopened, edited]
  pull_request_review:
    types: [submitted, dismissed]
  workflow_dispatch:
    inputs:
      pr_number:
        type: string
        required: true
permissions:
  contents: read
concurrency:
  group: aegis-observability-${{{{ github.event.pull_request.number || inputs.pr_number }}}}
  cancel-in-progress: false
jobs:
  admission:
    if: >-
      (github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main') ||
      github.event.pull_request.base.ref == 'platform-observability'
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    permissions:
      contents: read
      pull-requests: read
      statuses: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          repository: prasanthece42/aegis-platform
          ref: {revision}
          persist-credentials: false
      - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0
        with:
          python-version: '3.12'
      - run: python -m pip install --require-hashes -r requirements.txt
      - name: Verify exact plan and independent current-head review
        env:
          PYTHONPATH: src:.
          GH_TOKEN: ${{{{ secrets.GITHUB_TOKEN }}}}
          AEGIS_APP_ID: '5488289'
          AEGIS_PLATFORM_INSTALLATION_ID: '175648688'
          AEGIS_APP_PRIVATE_KEY: ${{{{ secrets.AEGIS_APP_PRIVATE_KEY }}}}
          PR_NUMBER: ${{{{ github.event.pull_request.number || inputs.pr_number }}}}
        run: python -m tooling.observability_service check-pr
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    render = commands.add_parser("render")
    render.add_argument("--output", type=Path, required=True)
    check = commands.add_parser("check-pr")
    check.add_argument("--number", type=int)
    wf = commands.add_parser("workflow")
    wf.add_argument("--revision", required=True)
    wf.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "workflow":
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(workflow(args.revision))
    elif args.command == "render":
        write_plan(admitted_plan(worker())[0], args.output)
    else:
        number = str(args.number or os.environ.get("PR_NUMBER", ""))
        if not re.fullmatch(r"[1-9][0-9]*", number):
            parser.error("Positive PR number required")
        check_pr(worker(), int(number))


if __name__ == "__main__":
    main()
