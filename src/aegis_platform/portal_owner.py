"""Explicit read-only platform-owner grants, separate from application ownership."""

from typing import Literal

from pydantic import Field, field_validator

from aegis_platform.contracts import Contract, Identifier


class PortalOwnerPolicy(Contract):
    schema_version: Literal[1] = 1
    platform_repository_id: Identifier
    mode: Literal["read_only"]
    owner_user_ids: list[Identifier] = Field(max_length=20)

    @field_validator("owner_user_ids")
    @classmethod
    def distinct_owners(cls, value):
        if len(value) != len(set(value)):
            raise ValueError("Platform owner grants must be distinct")
        return sorted(value, key=int)
