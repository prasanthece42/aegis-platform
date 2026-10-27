"""Public portal configuration shared with operator bootstrap validation."""

from urllib.parse import urlsplit

from pydantic import Field, model_validator

from aegis_platform.contracts import Commit, Contract, Identifier, Versions


class Profile(Contract):
    cpu_request: str
    memory_request: str
    cpu_limit: str
    memory_limit: str


class LiveConfig(Contract):
    public_origin: str
    app_id: Identifier
    client_id: str
    platform_repository: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    platform_repository_id: Identifier
    platform_installation_id: Identifier
    platform_bot_user_id: Identifier
    platform_branch: str = "main"
    source_installation_ids: list[Identifier]
    onboarding_user_ids: list[Identifier]
    allowed_owner_user_ids: list[Identifier]
    resource_profiles: dict[str, Profile]
    versions: Versions
    cluster_id: str
    cluster_uid: str
    gitops_repository_id: Identifier
    issuer_id: str
    signing_key_id: str
    gitops_repository: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
    )
    gitops_installation_id: Identifier | None = None
    delivery_workflow_commit: Commit | None = None

    @model_validator(mode="after")
    def require_tls(self):
        if self.delivery_workflow_commit and not (
            self.gitops_repository and self.gitops_installation_id
        ):
            raise ValueError("Delivery requires an explicit GitOps repository and installation")
        url = urlsplit(self.public_origin)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.path
            or url.query
            or url.fragment
            or url.username
            or url.password
        ):
            raise ValueError("Live public_origin must be an HTTPS origin without path")
        return self
