"""Entry point for the pinned, trusted GitOps request workflows."""

import argparse
import base64
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from aegis_platform.canonical import canonical
from aegis_platform.github_api import GitHubAPI
from aegis_platform.worker import DeliveryWorker

ROOT = Path(__file__).resolve().parents[1]


def encoded(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def app_token(installation, repository_id, permissions):
    pem = os.environ.get("AEGIS_APP_PRIVATE_KEY")
    if pem is None:
        pem = Path(os.environ["AEGIS_APP_PRIVATE_KEY_FILE"]).read_text()
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("Expected an RSA GitHub App key")
    now = int(time.time())
    unsigned = (
        encoded(canonical({"alg": "RS256", "typ": "JWT"}))
        + "."
        + encoded(
            canonical(
                {
                    "iat": now - 60,
                    "exp": now + 540,
                    "iss": os.environ["AEGIS_APP_ID"],
                }
            )
        )
    )
    jwt = unsigned + "." + encoded(key.sign(unsigned.encode(), padding.PKCS1v15(), hashes.SHA256()))
    from aegis_platform.canonical import strict_json

    request = urllib.request.Request(
        f"https://api.github.com/app/installations/{int(installation)}/access_tokens",
        data=canonical(
            {
                "repository_ids": [int(repository_id)],
                "permissions": permissions,
            }
        ),
        headers={
            "Authorization": "Bearer " + jwt,
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return strict_json(response.read(65536))["token"]
    except urllib.error.HTTPError as exc:
        raise ValueError(f"App token minting failed HTTP {exc.code}") from None


def worker(*, propose=False):
    # Bind bootstrap discovery to the expected public control-plane identity. Reviewed
    # policy independently checks numeric IDs after discovery.
    token = app_token(
        os.environ["AEGIS_PLATFORM_INSTALLATION_ID"],
        "1435080811",
        {"contents": "read", "issues": "read"},
    )
    platform = GitHubAPI(token, "prasanthece42/aegis-platform")
    gitops_token = os.environ["GH_TOKEN"]
    if propose:
        gitops_token = app_token(
            os.environ["AEGIS_GITOPS_INSTALLATION_ID"],
            "1433742863",
            {"contents": "write", "pull_requests": "write", "actions": "write", "statuses": "read"},
        )
    gitops = GitHubAPI(gitops_token, "prasanthece42/aegis-gitops")

    def source(entry):
        scoped = app_token(
            entry.source.installation_id,
            entry.source.repository_id,
            {
                "contents": "read",
                "actions": "read",
                "statuses": "read",
            },
        )
        return GitHubAPI(scoped, entry.source.owner + "/" + entry.source.name)

    return DeliveryWorker(platform, gitops, source, ROOT)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["propose", "check-pr", "check-event", "check-run"])
    parser.add_argument("--request-id")
    parser.add_argument("--issue-number", type=int)
    parser.add_argument("--pr-number", type=int)
    args = parser.parse_args()
    engine = worker(propose=args.command == "propose")
    if args.command == "check-run":
        sha = os.environ.get("RUN_HEAD_SHA", "")
        branch = os.environ.get("RUN_HEAD_BRANCH", "")
        if not re.fullmatch(r"[0-9a-f]{40}", sha) or not branch:
            raise ValueError("Invalid completed-run identity")
        prs = engine.gitops.pages("pulls", state="open", head="prasanthece42:" + branch)
        matches = [pr for pr in prs if pr["head"]["sha"] == sha]
        if not matches:
            print("Completed run has no current open PR")
            return
        if len(matches) != 1:
            raise ValueError("Ambiguous completed-run PR binding")
        args.pr_number = matches[0]["number"]
        args.command = "check-event"
    if args.command == "check-event":
        number = str(args.pr_number or os.environ.get("PR_NUMBER", ""))
        if not re.fullmatch(r"[1-9][0-9]*", number):
            parser.error("PR number is required")
        args.pr_number = int(number)
        pr = engine.gitops.repo("GET", "pulls/" + number)
        if pr.get("merged_at") or pr["state"] != "open":
            print("Completed/closed PR: no new admission status is issued")
            return
        files = engine.gitops.pages(f"pulls/{number}/files")
        if len(files) != pr["changed_files"]:
            raise ValueError("Incomplete PR file list")
        if not any(file["filename"].startswith("applications/") for file in files):
            engine.gitops.repo(
                "POST",
                "statuses/" + pr["head"]["sha"],
                {
                    "state": "success",
                    "context": "aegis/delivery-policy",
                    "description": "No app delivery paths changed; other checks still apply",
                },
            )
            return
        rid = re.search(r"^Aegis request: (req-[0-9a-f]{64})$", pr.get("body") or "", re.M)
        issue = re.search(r"^Platform issue: ([1-9][0-9]*)$", pr.get("body") or "", re.M)
        if not rid or not issue:
            engine.gitops.repo(
                "POST",
                "statuses/" + pr["head"]["sha"],
                {
                    "state": "failure",
                    "context": "aegis/delivery-policy",
                    "description": "App delivery changes require a canonical signed request",
                },
            )
            raise ValueError("Missing canonical delivery request binding")
        args.request_id, args.issue_number = rid[1], int(issue[1])
        args.command = "check-pr"
    if (
        not re.fullmatch(r"req-[0-9a-f]{64}", args.request_id or "")
        or not args.issue_number
        or args.issue_number < 1
    ):
        parser.error("Invalid request identity")
    if args.command == "propose":
        pr = engine.propose(args.request_id, args.issue_number)
        # The existing chart/promotion checks run at the PR head. Their workflow bytes
        # cannot have changed: the admitted diff contains only exact app delivery files.
        engine.gitops.repo(
            "POST",
            "actions/workflows/validate.yml/dispatches",
            {
                "ref": pr["head"]["ref"],
                "inputs": {"pr_number": str(pr["number"])},
            },
        )
        engine.gitops.repo(
            "POST",
            "actions/workflows/delivery-policy.yml/dispatches",
            {
                "ref": "main",
                "inputs": {
                    "request_id": args.request_id,
                    "issue_number": str(args.issue_number),
                    "pr_number": str(pr["number"]),
                },
            },
        )
        # Auto-merge only DEV, and only through enforced required checks. Protected
        # branches receive an ordinary PR; this process never submits a review or sync.
        if pr["base"]["ref"] == "main" and not pr.get("auto_merge"):
            merged = engine.gitops.call(
                "POST",
                "/graphql",
                {
                    "query": """
                mutation($id: ID!) { enablePullRequestAutoMerge(input: {
                  pullRequestId: $id, mergeMethod: SQUASH
                }) { pullRequest { number } } }
                """,
                    "variables": {"id": pr["node_id"]},
                },
            )
            if merged.get("errors"):
                raise ValueError("DEV auto-merge could not be enabled; required checks still apply")
        print("Delivery PR: " + pr["html_url"])
    else:
        if not args.pr_number or args.pr_number < 1:
            parser.error("check-pr requires a PR number")
        pr = engine.gitops.repo("GET", "pulls/" + str(args.pr_number))
        if pr.get("merged_at") or pr["state"] != "open":
            print("Completed/closed PR: no new admission status is issued")
            return
        sha = pr["head"]["sha"]
        try:
            verified, _intent = engine.check_pr(args.pr_number, args.request_id, args.issue_number)
            if verified["head"]["sha"] != sha:
                raise ValueError("PR head changed while checking")
        except (ValueError, KeyError, OSError):
            latest = engine.gitops.repo("GET", "pulls/" + str(args.pr_number))
            if latest.get("merged_at") or latest["state"] != "open":
                print("PR completed while checking; no retrospective status change is issued")
                return
            if latest["head"]["sha"] != sha:
                print("PR head changed while checking; current-head validation must run again")
                return
            engine.gitops.repo(
                "POST",
                f"statuses/{sha}",
                {
                    "state": "failure",
                    "context": "aegis/delivery-policy",
                    "description": "Delivery admission failed; inspect the trusted workflow run",
                },
            )
            raise
        engine.gitops.repo(
            "POST",
            f"statuses/{sha}",
            {
                "state": "success",
                "context": "aegis/delivery-policy",
                "description": "Request, authority, release, cache and lineage verified",
            },
        )
        print("PASS: current-head delivery admission")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError) as exc:
        print("Delivery blocked: " + str(exc), file=sys.stderr)
        raise SystemExit(1) from None
