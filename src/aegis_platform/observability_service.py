"""Exact, independently reviewed local telemetry service plan and admission boundary."""

from copy import deepcopy
from typing import Literal

from pydantic import Field, model_validator

from aegis_platform.canonical import canonical, digest, strict_json
from aegis_platform.contracts import Contract, Identifier
from aegis_platform.delivery import verify_production_approval
from aegis_platform.grafana import BASE as GRAFANA_BASE
from aegis_platform.grafana import grafana_plan
from aegis_platform.observability import observability_plan
from aegis_platform.observability_policy import OBS_BASE, ObservabilityPolicy

CONTEXT = "aegis/observability-policy"
SUCCESS = "Exact observability plan and independent operator review verified"


class ObservabilityServicePolicy(Contract):
    schema_version: Literal[1] = 1
    branch: Literal["platform-observability"] = "platform-observability"
    operator_user_ids: list[Identifier] = Field(min_length=1, max_length=20)
    proposer_bot_user_id: Identifier

    @model_validator(mode="after")
    def independent_operators(self):
        if self.proposer_bot_user_id in self.operator_user_ids:
            raise ValueError("Proposer and human operators must be independent")
        if len(set(self.operator_user_ids)) != len(self.operator_user_ids):
            raise ValueError("Duplicate operators")
        return self


def service_plan(policy: ObservabilityPolicy, access: ObservabilityServicePolicy, revision: str):
    files = deepcopy(observability_plan(policy, revision))
    grafana = grafana_plan(policy, revision)
    for path, resource in grafana.items():
        if "/manifests/" in path:
            files[OBS_BASE + "/manifests/" + path.rsplit("/", 1)[1]] = resource
    for value in files.values():
        if value.get("kind") == "Application":
            value["spec"]["source"]["targetRevision"] = access.branch
        if value.get("kind") == "AppProject":
            value["spec"]["namespaceResourceWhitelist"].append(
                {"group": "networking.k8s.io", "kind": "NetworkPolicy"}
            )
        if value.get("kind") == "Deployment":
            # subPath provisioning/config mounts require a rollout when source config changes.
            value["spec"]["template"]["metadata"].setdefault("annotations", {})[
                "aegis.io/config-hash"
            ] = digest({k: v for k, v in files.items() if v.get("kind") == "ConfigMap"})
    files.pop(OBS_BASE + "/review.json")
    files[OBS_BASE + "/review.json"] = {
        "schema_version": 1,
        "platform_revision": revision,
        "policy_hash": digest(policy.model_dump()),
        "access_policy_hash": digest(access.model_dump()),
        "resources_hash": digest(files),
        "grafana_review": grafana[GRAFANA_BASE + "/review.json"],
        "requires_independent_operator_review": True,
        "profile": "local-operator-only",
        "production_ready": False,
    }
    return files


def verify_exact_tree(actual, expected):
    if set(actual) != set(expected):
        raise ValueError("Telemetry tree must contain exactly the rendered paths")
    for path, value in expected.items():
        raw = actual[path]
        decoded = strict_json(raw) if isinstance(raw, (str, bytes)) else raw
        if canonical(decoded) != canonical(value):
            raise ValueError("Telemetry resource differs from trusted plan: " + path)


def verify_proposal(pr, changed, policy, access, expected):
    if (
        pr["base"]["ref"] != access.branch
        or str(pr["head"]["repo"]["id"]) != policy.gitops_repository_id
        or str(pr["base"]["repo"]["id"]) != policy.gitops_repository_id
        or pr["head"]["repo"]["full_name"] != policy.gitops_repository
        or pr["base"]["repo"]["full_name"] != policy.gitops_repository
        or str(pr["user"]["id"]) != access.proposer_bot_user_id
        or pr["user"].get("type") != "Bot"
    ):
        raise ValueError("Telemetry PR repository, branch or proposer differs from trusted policy")
    if (
        not changed
        or len(changed) != pr["changed_files"]
        or len(changed) > 100
        or len({f["filename"] for f in changed}) != len(changed)
        or any(
            f["filename"] not in expected
            or f["status"] not in {"added", "modified"}
            or "previous_filename" in f
            for f in changed
        )
    ):
        raise ValueError("Telemetry PR changes files outside the exact plan")


def verify_operator_review(pr, reviews, access, delivery):
    return verify_production_approval(
        pr,
        reviews,
        delivery.model_copy(update={"production_reviewer_user_ids": access.operator_user_ids}),
    )
