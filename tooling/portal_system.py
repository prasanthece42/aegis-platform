"""Render or validate the independently recoverable, operator-owned portal service."""

import argparse
import os
import re
import sys
from pathlib import Path

from aegis_platform.bootstrap import write_plan
from aegis_platform.canonical import canonical, strict_json
from aegis_platform.delivery import (
    admit_release,
    cache_fingerprint,
    verify_production_approval,
    verify_status,
)
from aegis_platform.portal_system import BASE, RUNTIME_CONTRACT, PortalSystemPolicy, system_plan
from aegis_platform.release import ReleaseEvidence
from aegis_platform.worker import tree_files
from tooling.delivery import worker


def admitted_plan(engine, release_id):
    from datetime import UTC, datetime

    revision, catalog, delivery, trust, bootstrap = engine.snapshot()
    policy = PortalSystemPolicy.model_validate(
        strict_json(engine.platform.file("policies/portal-system.json", revision))
    )
    entry = catalog.apps["aegis-portal"]
    source = engine.source_factory(entry)
    release = source.repo("GET", "releases/" + str(int(release_id)))
    assets = [asset for asset in release["assets"] if asset["name"] == "release.json"]
    if len(assets) != 1:
        raise ValueError("Portal release receipt is missing or ambiguous")
    raw = source.repo("GET", "releases/assets/" + str(assets[0]["id"]), raw=True)
    evidence = ReleaseEvidence.model_validate(strict_json(raw))
    contract = strict_json(source.file("app/portal-profile.json", evidence.source_commit))
    if canonical(contract) != canonical(RUNTIME_CONTRACT):
        raise ValueError(
            "Selected image source does not declare the required portal runtime contract"
        )
    if not any(
        issuer.active
        and issuer.issuer_id == policy.configuration.issuer_id
        and issuer.key_id == policy.configuration.signing_key_id
        and issuer.public_key_base64 == policy.signing_public_key_base64
        and issuer.bot_user_id == policy.configuration.platform_bot_user_id
        for issuer in trust.issuers
    ):
        raise ValueError("System signing-key binding differs from the active reviewed registry")
    run = source.repo(
        "GET", f"actions/runs/{evidence.workflow_run_id}/attempts/{evidence.run_attempt}"
    )
    admit_release(entry, raw, release, source.repo("GET", ""), run, delivery)
    verify_status(
        source.pages(f"commits/{evidence.source_commit}/statuses"),
        f"aegis/{entry.app_id}/{entry.environments['dev'].cluster_id}-cache",
        "cachefp:" + cache_fingerprint(entry, "dev", evidence).split(":")[1],
        evidence.source_commit,
        delivery,
        datetime.now(UTC),
    )
    return system_plan(entry, policy, delivery, bootstrap, raw, str(release_id)), policy, delivery


def check_pr(engine, number):
    pr = engine.gitops.repo("GET", "pulls/" + str(number))
    if pr.get("merged_at") or pr["state"] != "open":
        print("Completed/closed system PR; no new status is issued")
        return
    sha = pr["head"]["sha"]
    state, description = "failure", "Portal system manifest admission failed"
    try:
        review = strict_json(engine.gitops.file(BASE + "/review.json", sha))
        if not re.fullmatch(r"[1-9][0-9]*", str(review["release_id"])):
            raise ValueError("Invalid system release ID")
        expected, policy, delivery = admitted_plan(engine, review["release_id"])
        if (
            pr["base"]["ref"] != policy.branch
            or str(pr["head"]["repo"]["id"]) != delivery.gitops_repository_id
            or str(pr["base"]["repo"]["id"]) != delivery.gitops_repository_id
            or str(pr["user"]["id"]) != policy.configuration.platform_bot_user_id
            or pr["user"].get("type") != "Bot"
        ):
            raise ValueError("System proposal differs from operator-owned repository/issuer scope")
        changed = engine.gitops.pages(f"pulls/{number}/files")
        if (
            len(changed) != pr["changed_files"]
            or len(changed) > 100
            or any(
                file["filename"] not in expected
                or file["status"] not in {"added", "modified"}
                or "previous_filename" in file
                for file in changed
            )
        ):
            raise ValueError("System PR changes paths outside the exact rendered review plan")
        actual = tree_files(engine.gitops, sha, lambda path: path.startswith(BASE + "/"))
        for path, value in expected.items():
            if path not in actual or (
                actual[path] != value
                if isinstance(value, bytes)
                else canonical(strict_json(actual[path])) != canonical(value)
            ):
                raise ValueError("System manifest differs from reviewed policy/release: " + path)
        # Older immutable receipts may remain, but cannot be changed or introduced as extras.
        for path in actual.keys() - expected.keys():
            if not re.fullmatch(
                re.escape(BASE) + r"/releases/release-[1-9][0-9]*-[1-9][0-9]*\.json", path
            ):
                raise ValueError("Unexpected system resource or private material in Git")
            if actual[path] != engine.gitops.file(path, pr["base"]["sha"]):
                raise ValueError("Retained system release receipt changed")
        try:
            review_policy = delivery.model_copy(
                update={"production_reviewer_user_ids": policy.operator_user_ids}
            )
            verify_production_approval(
                pr, engine.gitops.pages(f"pulls/{number}/reviews"), review_policy
            )
        except ValueError:
            state, description = (
                "pending",
                "Manifests verified; independent human operator review required",
            )
        else:
            state, description = (
                "success",
                "Exact system manifests, release/cache and operator review verified",
            )
    finally:
        latest = engine.gitops.repo("GET", "pulls/" + str(number))
        if (
            not latest.get("merged_at")
            and latest["state"] == "open"
            and latest["head"]["sha"] == sha
        ):
            engine.gitops.repo(
                "POST",
                "statuses/" + sha,
                {
                    "state": state,
                    "context": "aegis/platform-service-policy",
                    "description": description,
                },
            )
    print(description)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    render = commands.add_parser("render")
    render.add_argument("--release-id", required=True)
    render.add_argument("--output", type=Path, required=True)
    check = commands.add_parser("check-pr")
    check.add_argument("--number", type=int)
    args = parser.parse_args()
    engine = worker()
    if args.command == "render":
        files, _policy, _delivery = admitted_plan(engine, args.release_id)
        write_plan(files, args.output)
        print(
            "Rendered operator review files; no Secrets, workloads or controller bindings applied"
        )
    else:
        number = str(args.number or os.environ.get("PR_NUMBER", ""))
        if not re.fullmatch(r"[1-9][0-9]*", number):
            parser.error("A positive PR number is required")
        check_pr(engine, int(number))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError) as exc:
        print("Portal system admission blocked: " + str(exc), file=sys.stderr)
        raise SystemExit(1) from None
