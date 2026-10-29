"""Bounded multi-service source contract. No Compose execution or arbitrary manifests."""

import re
from pathlib import PurePosixPath
from typing import Annotated, Literal
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Name = Annotated[str, Field(pattern=r"^[a-z](?:[a-z0-9-]{0,20}[a-z0-9])?$")]
EnvName = Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")]
SecretKey = Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")]
SENSITIVE = re.compile(
    r"(?:PASSWORD|SECRET|TOKEN|PRIVATE_KEY|API_KEY|ACCESS_KEY|CREDENTIAL|AUTHORIZATION|DATABASE_URL|REDIS_URL)"
)
PROFILE = "python312-multiservice"
CHART = "multi-service"


def public_setting(key, value):
    if SENSITIVE.search(key) or len(value) > 512 or not value.isprintable():
        return False
    if re.search(r"[A-Za-z][A-Za-z0-9+.-]*://[^/\s]*@", value):
        return False
    pattern = (
        r"-----BEGIN .*PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{20,}|"
        r"github_pat_[A-Za-z0-9_]{20,}|(?:AKIA|ASIA)[A-Z0-9]{16}"
    )
    return not re.search(pattern, value)


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def source_path(value: str) -> str:
    if value == ".":
        return value
    if (
        not value
        or PurePosixPath(value).is_absolute()
        or not re.fullmatch(r"[A-Za-z0-9_./-]+", value)
        or any(p in {"", ".", ".."} for p in value.split("/"))
    ):
        raise ValueError("Use a normalized source-relative path")
    return value


def validate_health_path(value: str) -> str:
    parsed = urlsplit(value)
    if (
        not value.startswith("/")
        or value.startswith("//")
        or unquote(value) != value
        or parsed.query
        or parsed.fragment
        or "?" in value
        or "#" in value
        or "\\" in value
        or any(ord(c) < 33 or ord(c) > 126 for c in value)
        or any(p in {".", ".."} for p in value.split("/"))
    ):
        raise ValueError("Use a plain HTTP probe path")
    return value


class StackService(Strict):
    context: str = "."
    dockerfile: str = "Dockerfile"
    build_args: dict[EnvName, str] = Field(default_factory=dict, max_length=8)
    port: int = Field(default=8000, ge=1024, le=65535)
    health_path: str = "/ready"
    replicas: int = Field(default=1, ge=1, le=2)
    env: dict[EnvName, str] = Field(default_factory=dict, max_length=32)
    service_env: dict[EnvName, Name] = Field(default_factory=dict, max_length=8)
    secret_env: dict[EnvName, SecretKey] = Field(default_factory=dict, max_length=8)

    _paths = field_validator("context", "dockerfile")(source_path)
    _health = field_validator("health_path")(validate_health_path)

    @model_validator(mode="after")
    def bounded_environment(self):
        groups = [set(self.env), set(self.service_env), set(self.secret_env)]
        if not set(self.secret_env.values()) <= {"database-url", "redis-url"}:
            raise ValueError(
                "This dependency profile supports database-url and redis-url service Secret keys"
            )
        if sum(map(len, groups)) != len(set().union(*groups)):
            raise ValueError("Environment names must have one source")
        for group in (self.env, self.build_args):
            if any(not public_setting(k, v) for k, v in group.items()):
                raise ValueError("Use bounded public values; credentials require Secret references")
        return self


class StackDefinition(Strict):
    schema_version: Literal[1] = 1
    profile_id: Literal["python312-multiservice"] = PROFILE
    primary_service: Name
    services: dict[Name, StackService] = Field(min_length=2, max_length=8)
    dependencies: Literal["postgres17-redis7-nginx"] = "postgres17-redis7-nginx"

    @model_validator(mode="after")
    def topology(self):
        if self.primary_service not in self.services:
            raise ValueError("Primary release anchor must identify an application service")
        if set(self.services) & {"gateway", "postgres", "redis"}:
            raise ValueError("Dependency service names are reserved")
        if sum(s.replicas for s in self.services.values()) > 12:
            raise ValueError("Stack exceeds twelve application replicas")
        for service in self.services.values():
            if not set(service.service_env.values()) <= self.services.keys():
                raise ValueError("Internal URLs must refer to declared services")
        return self


def chart_family(runtime) -> str:
    return CHART if runtime.profile_id == PROFILE else "web-service"
