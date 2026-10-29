"""Strict contracts shared by registration, journals and generated JSON schemas."""

from typing import Annotated, Literal
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from aegis_platform.stack import EnvName, Name, StackDefinition, public_setting

Identifier = Annotated[str, Field(pattern=r"^[1-9][0-9]*$", max_length=24)]
AppId = Annotated[
    str, Field(min_length=3, max_length=40, pattern=r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
]
Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
Commit = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
Environment = Literal["dev", "staging", "prod"]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Runtime(Contract):
    profile_id: Literal["python312-web"] = "python312-web"
    container_port: int = Field(ge=1, le=65535)
    health_path: str = Field(min_length=1, max_length=200)
    resource_profile_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,39}$")

    @field_validator("health_path")
    @classmethod
    def safe_health_path(cls, value: str) -> str:
        # Decode once and reject remaining escapes, preventing double-encoded traversal.
        decoded = unquote(value)
        parsed = urlsplit(decoded)
        if (
            not decoded.startswith("/")
            or decoded.startswith("//")
            or parsed.scheme
            or parsed.netloc
            or parsed.query
            or parsed.fragment
            or "?" in decoded
            or "#" in decoded
            or "\\" in decoded
            or "%" in decoded
            or any(ord(c) < 33 or ord(c) == 127 for c in decoded)
            or any(part in {".", ".."} for part in decoded.split("/"))
        ):
            raise ValueError("Use an application path without query, authority or traversal")
        return decoded


class StackRuntime(Runtime):
    profile_id: Literal["python312-multiservice"] = "python312-multiservice"
    stack: StackDefinition
    credentials_secret: str = Field(pattern=r"^[a-z][a-z0-9-]{0,62}$")
    environment: dict[Name, dict[EnvName, str]] = Field(default_factory=dict, max_length=8)

    @model_validator(mode="after")
    def gateway(self):
        if self.container_port != 8080 or self.health_path != "/health":
            raise ValueError("Multi-service entrypoint uses port 8080 and /health")
        for name, values in self.environment.items():
            if (
                name not in self.stack.services
                or not set(values) <= self.stack.services[name].env.keys()
            ):
                raise ValueError("Only declared non-secret environment values can be overridden")
            if any(not public_setting(k, v) for k, v in values.items()):
                raise ValueError("Use bounded non-secret environment values")
        return self


class RegistrationFields(Contract):
    repository_id: Identifier
    app_id: AppId
    display_name: str = Field(min_length=1, max_length=80)
    owner_user_ids: list[Identifier] = Field(min_length=1, max_length=20)
    runtime: Runtime | StackRuntime

    @model_validator(mode="after")
    def owned_secret(self):
        if (
            isinstance(self.runtime, StackRuntime)
            and self.runtime.credentials_secret != self.app_id + "-runtime"
        ):
            raise ValueError(
                "Credentials must use the application's namespace-local runtime Secret"
            )
        return self

    @field_validator("display_name")
    @classmethod
    def printable_name(cls, value: str) -> str:
        if not value.strip() or not value.isprintable():
            raise ValueError("Use a nonempty printable application name")
        return value.strip()

    @field_validator("owner_user_ids")
    @classmethod
    def distinct_owners(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("Owners must be distinct")
        return sorted(value, key=int)


class RegistrationSubmission(RegistrationFields):
    review_token: str = Field(min_length=20, max_length=16384)


class Source(Contract):
    repository_id: Identifier
    installation_id: Identifier
    owner: str
    name: str
    default_branch: str


class Access(Contract):
    owner_user_ids: list[Identifier] = Field(min_length=1)
    viewer_user_ids: list[Identifier]
    deployer_user_ids_by_environment: dict[Environment, list[Identifier]]


class Versions(Contract):
    workflow_commit: Commit
    helper_commit: Commit
    chart_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    chart_sha256: Digest


class Target(Contract):
    delivery_mode: Literal["manual", "automatic"]
    cluster_id: str
    cluster_uid: str
    namespace: str
    argo_application: str
    argo_project: str
    gitops_repository_id: Identifier
    gitops_branch: str
    values_path: str
    access_mapping_id: str | None


class CatalogEntry(Contract):
    schema_version: Literal[1] = 1
    app_id: AppId
    display_name: str
    source: Source
    access: Access
    runtime: Runtime | StackRuntime

    @model_validator(mode="after")
    def owned_secret(self):
        if (
            isinstance(self.runtime, StackRuntime)
            and self.runtime.credentials_secret != self.app_id + "-runtime"
        ):
            raise ValueError(
                "Credentials must use the application's namespace-local runtime Secret"
            )
        return self

    versions: Versions
    environments: dict[Environment, Target]


class PriorEvidence(Contract):
    environment: Literal["dev", "staging"]
    intent_anchor: str
    fingerprint: Digest
    observed_at: str
    evidence_reference: str


class DeploymentIntent(Contract):
    schema_version: Literal[1] = 1
    request_id: str = Field(pattern=r"^req-[0-9a-f]{64}$")
    issuer_id: str
    platform_repository_id: Identifier
    requester_user_id: Identifier
    created_at: str
    idempotency_key_hash: Digest
    payload_hash: Digest
    app_id: AppId
    environment: Environment
    operation: Literal["deploy", "promote"]
    origin: Literal["portal"]
    catalog_revision: Commit
    catalog_entry_hash: Digest
    resolved_policy_hash: Digest
    source_repository_id: Identifier
    source_commit: Commit
    release_id: Identifier
    release_workflow_run_id: Identifier
    release_evidence_hash: Digest
    image_root_digest: Digest
    platform_digests: dict[str, Digest] = Field(min_length=1)
    expected_desired_fingerprint: Digest | None
    expected_intent_anchor: str | None
    prior_environment_evidence: PriorEvidence | None

    @model_validator(mode="after")
    def promotion_evidence(self):
        expected_prior = {"staging": "dev", "prod": "staging"}
        if self.environment == "dev":
            if self.operation != "deploy" or self.prior_environment_evidence is not None:
                raise ValueError("DEV deployment does not use promotion evidence")
        elif (
            self.operation != "promote"
            or self.prior_environment_evidence is None
            or self.prior_environment_evidence.environment != expected_prior[self.environment]
        ):
            raise ValueError("Promotion requires matching prior-environment evidence")
        if (self.expected_desired_fingerprint is None) != (self.expected_intent_anchor is None):
            raise ValueError("Desired fingerprint and intent anchor must be present together")
        return self


class DesiredState(Contract):
    """Resolved trusted inputs for one app/environment; no global branch HEAD or timestamps."""

    schema_version: Literal[1] = 1
    app_id: AppId
    environment: Environment
    cluster_id: str = Field(min_length=1)
    cluster_uid: str = Field(min_length=1)
    namespace: str = Field(max_length=63, pattern=r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
    source_repository_id: Identifier
    source_commit: Commit
    image_root_digest: Digest
    platform_digests: dict[str, Digest] = Field(min_length=1)
    chart_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    chart_sha256: Digest
    effective_values: dict[str, JsonValue]
    resolved_cluster_profile: dict[str, JsonValue]
    controller_bindings: dict[str, JsonValue]
