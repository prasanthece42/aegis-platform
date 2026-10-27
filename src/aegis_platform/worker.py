"""Trusted GitOps request processing. Never checks out or executes application code."""

import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from aegis_platform.canonical import digest, strict_json
from aegis_platform.catalog import Catalog, CatalogPolicy, Cluster
from aegis_platform.contracts import CatalogEntry
from aegis_platform.delivery import DeliveryPolicy, verify_production_approval
from aegis_platform.proposal import current_state, proposal
from aegis_platform.release import ReleaseEvidence
from aegis_platform.request import RequestTrust, verify_request


def tree_files(api, revision, select):
    tree = api.repo("GET", "git/trees/" + revision + "?recursive=1")
    if tree.get("truncated") or len(tree["tree"]) > 10000:
        raise ValueError("Repository tree exceeds supported bounds")
    result = {}
    for item in tree["tree"]:
        if item["type"] == "blob" and select(item["path"]):
            if item.get("mode") != "100644":
                raise ValueError("Symlinks and executable configuration files are unsupported")
            result[item["path"]] = api.file(item["path"], revision)
    return result


def proposal_issuers(policy, trust, issuer_id):
    """PR writers are distinct from the immutable release publisher trust set."""
    return set(policy.workflow_bot_user_ids) | {
        issuer.bot_user_id
        for issuer in trust.issuers
        if issuer.active and issuer.issuer_id == issuer_id
    }


class DeliveryWorker:
    def __init__(self, platform, gitops, source_factory, root: Path):
        self.platform, self.gitops, self.source_factory, self.root = (
            platform,
            gitops,
            source_factory,
            root,
        )

    def snapshot(self):
        revision = self.platform.repo("GET", "commits/main")["sha"]
        files = tree_files(
            self.platform,
            revision,
            lambda p: (
                p.startswith("catalog/apps/")
                and p.endswith(".json")
                or p.startswith("catalog/clusters/")
                and p.endswith(".json")
                or p
                in {
                    "policies/catalog.json",
                    "policies/bootstrap.json",
                    "policies/delivery.json",
                    "policies/request-trust.json",
                }
            ),
        )
        catalog = Catalog(
            [
                CatalogEntry.model_validate(strict_json(value))
                for path, value in files.items()
                if path.startswith("catalog/apps/")
            ],
            [
                Cluster.model_validate(strict_json(value))
                for path, value in files.items()
                if path.startswith("catalog/clusters/")
            ],
            CatalogPolicy.model_validate(strict_json(files["policies/catalog.json"])),
        )
        policy = DeliveryPolicy.model_validate(strict_json(files["policies/delivery.json"]))
        trust = RequestTrust.model_validate(strict_json(files["policies/request-trust.json"]))
        if (
            self.platform.repository != policy.platform_repository
            or self.gitops.repository != policy.gitops_repository
            or str(self.platform.repo("GET", "")["id"]) != policy.platform_repository_id
            or str(self.gitops.repo("GET", "")["id"]) != policy.gitops_repository_id
            or trust.platform_repository_id != policy.platform_repository_id
        ):
            raise ValueError("Worker repository identity differs from reviewed policy")
        return revision, catalog, policy, trust, strict_json(files["policies/bootstrap.json"])

    def request(self, rid, number, trust):
        if not re.fullmatch(r"req-[0-9a-f]{64}", rid) or not re.fullmatch(
            r"[1-9][0-9]*", str(number)
        ):
            raise ValueError("Expected canonical request ID and issue number")
        ref = self.platform.repo("GET", "git/ref/heads/portal-requests/" + rid)["object"]["sha"]
        record = strict_json(self.platform.file("record.json", ref))
        issue = self.platform.repo("GET", "issues/" + str(number))
        return verify_request(record, issue, trust, rid, datetime.now(UTC))

    def target_files(self, entry, environment):
        target = entry.environments[environment]
        head = self.gitops.repo("GET", "commits/" + quote(target.gitops_branch, safe=""))["sha"]
        prefixes = (
            f"applications/{entry.app_id}/",
            f"charts/web-service/{entry.versions.chart_version}/",
            f"clusters/{target.cluster_id}/bootstrap/{entry.app_id}/{environment}/",
        )
        exact = {
            f"argocd/projects/{target.argo_project}.json",
            f"argocd/applications/{target.argo_application}.json",
        }
        files = tree_files(self.gitops, head, lambda p: p.startswith(prefixes) or p in exact)
        pointer = target.values_path.rsplit("/", 1)[0] + "/release.json"
        anchor = None
        if pointer in files:
            commits = self.gitops.repo(
                "GET", "commits?sha=" + head + "&path=" + quote(pointer, safe="") + "&per_page=1"
            )
            if not commits:
                raise ValueError("Existing intent has no app-scoped anchor")
            anchor = commits[0]["sha"]
        return head, files, anchor

    def plan(self, rid, number):
        revision, catalog, policy, trust, bootstrap = self.snapshot()
        intent = self.request(rid, number, trust)
        entry = catalog.apps[intent.app_id]
        # Signed previews remain valid across unrelated catalog changes. Their original
        # snapshot must be on main's history and still have identical app/policy inputs.
        comparison = self.platform.repo("GET", f"compare/{intent.catalog_revision}...{revision}")
        if comparison.get("status") not in {"ahead", "identical"}:
            raise ValueError("Intent catalog snapshot is not an approved main ancestor")
        if (
            digest(
                strict_json(
                    self.platform.file(f"catalog/apps/{entry.app_id}.json", intent.catalog_revision)
                )
            )
            != intent.catalog_entry_hash
            or digest(
                strict_json(self.platform.file("policies/delivery.json", intent.catalog_revision))
            )
            != intent.resolved_policy_hash
        ):
            raise ValueError("Intent differs from its original approved catalog snapshot")
        source = self.source_factory(entry)
        repository = source.repo("GET", "")
        collaborators = source.pages("collaborators")
        source_push = any(
            str(user["id"]) == intent.requester_user_id
            and user.get("permissions", {}).get("push") is True
            for user in collaborators
        )
        release = source.repo("GET", "releases/" + intent.release_id)
        assets = [asset for asset in release["assets"] if asset["name"] == "release.json"]
        if len(assets) != 1:
            raise ValueError("Release receipt is missing or ambiguous")
        raw = source.repo("GET", "releases/assets/" + str(assets[0]["id"]), raw=True)
        evidence = ReleaseEvidence.model_validate(strict_json(raw))
        run = source.repo(
            "GET", f"actions/runs/{evidence.workflow_run_id}/attempts/{evidence.run_attempt}"
        )
        head, files, anchor = self.target_files(entry, intent.environment)
        current = current_state(
            entry, intent.environment, files, anchor, digest(policy.model_dump())
        )
        lineage = None
        if current:
            lineage = source.repo(
                "GET", f"compare/{current.source_commit}...{evidence.source_commit}"
            )["status"]
        prior, prior_statuses = None, None
        if intent.environment != "dev":
            prior_env = {"staging": "dev", "prod": "staging"}[intent.environment]
            _head, prior_files, prior_anchor = self.target_files(entry, prior_env)
            prior = current_state(
                entry, prior_env, prior_files, prior_anchor, digest(policy.model_dump())
            )
            if not prior:
                raise ValueError("No prior-environment intent")
            prior_statuses = self.gitops.pages(f"commits/{prior.intent_anchor}/statuses")
        plan = proposal(
            intent=intent,
            catalog=catalog,
            catalog_revision=intent.catalog_revision,
            policy=policy,
            bootstrap_policy=bootstrap,
            chart=self.root / f"charts/web-service/{entry.versions.chart_version}",
            raw_receipt=raw,
            release=release,
            repository=repository,
            run=run,
            source_push=source_push,
            source_comparison=lineage,
            git_files=files,
            current_anchor=anchor,
            cache_statuses=source.pages(f"commits/{evidence.source_commit}/statuses"),
            prior=prior,
            prior_statuses=prior_statuses,
        )
        proposal_bots = proposal_issuers(policy, trust, intent.issuer_id)
        return intent, policy, head, files, plan, proposal_bots

    def propose(self, rid, number):
        intent, policy, head, files, plan, _proposal_bots = self.plan(rid, number)
        branch = "aegis-requests/" + rid
        prs = self.gitops.pages(
            "pulls", state="all", head=policy.gitops_repository.split("/")[0] + ":" + branch
        )
        if prs:
            if len(prs) != 1:
                raise ValueError("Ambiguous request PR")
            self.check_pr(prs[0]["number"], rid, number, require_approval=False)
            return prs[0]
        refs = self.gitops.pages("git/matching-refs/heads/" + branch)
        if refs:
            if len(refs) != 1 or refs[0]["ref"] != "refs/heads/" + branch:
                raise ValueError("Unexpected request branch")
            existing_head = refs[0]["object"]["sha"]
            for path, expected in plan.items():
                if self.gitops.file(path, existing_head) != expected:
                    raise ValueError("Existing branch differs from admitted request")
            changed = self.gitops.repo("GET", f"compare/{head}...{existing_head}")
            self.verify_diff(changed, {p for p, data in plan.items() if files.get(p) != data})
        else:
            self.gitops.commit_files(
                branch, head, plan, f"Request {intent.app_id} {intent.environment}: {rid}"
            )
        pr = self.gitops.repo(
            "POST",
            "pulls",
            {
                "head": branch,
                "base": {"dev": "main", "staging": "staging", "prod": "prod"}[intent.environment],
                "title": f"Deploy {intent.app_id} to {intent.environment}",
                "body": (
                    f"Aegis request: {rid}\nPlatform issue: {number}\n\n"
                    f"Immutable source: {intent.source_commit}\nImage: {intent.image_root_digest}\n"
                    "PROD requires human approval; protected environments require operator sync."
                ),
            },
        )
        self.check_pr(pr["number"], rid, number, require_approval=False)
        return pr

    @staticmethod
    def verify_diff(comparison, expected):
        changed = comparison.get("files", [])
        if (
            not changed
            or len(changed) >= 300
            or {file["filename"] for file in changed} != expected
            or len(changed) != len(expected)
            or any(
                file["status"] not in {"added", "modified"} or "previous_filename" in file
                for file in changed
            )
        ):
            raise ValueError("Complete PR diff differs from the exact admitted app request")

    def check_pr(self, pr_number, rid, issue_number, *, require_approval=True):
        intent, policy, base, files, plan, proposal_bots = self.plan(rid, issue_number)
        pr = self.gitops.repo("GET", "pulls/" + str(int(pr_number)))
        expected_branch = {"dev": "main", "staging": "staging", "prod": "prod"}[intent.environment]
        if (
            pr["base"]["ref"] != expected_branch
            or str(pr["base"]["repo"]["id"]) != policy.gitops_repository_id
            or str(pr["head"]["repo"]["id"]) != policy.gitops_repository_id
            or pr["head"]["ref"] != "aegis-requests/" + rid
            or str(pr["user"]["id"]) not in proposal_bots
            or pr["user"]["type"] != "Bot"
            or pr.get("draft")
            or pr["state"] != "open"
        ):
            raise ValueError("PR scope or workflow issuer differs from approved request")
        sha = pr["head"]["sha"]
        for path, expected in plan.items():
            if self.gitops.file(path, sha) != expected:
                raise ValueError("PR contents differ from exact admitted values/evidence")
        changed = self.gitops.repo("GET", f"compare/{base}...{sha}")
        actual_files = self.gitops.pages(f"pulls/{pr_number}/files")
        if len(actual_files) != pr["changed_files"]:
            raise ValueError("Incomplete PR file list")
        self.verify_diff(
            {"files": actual_files}, {p for p, value in plan.items() if files.get(p) != value}
        )
        self.verify_diff(changed, {p for p, value in plan.items() if files.get(p) != value})
        if intent.environment == "prod" and require_approval:
            verify_production_approval(pr, self.gitops.pages(f"pulls/{pr_number}/reviews"), policy)
        return pr, intent
