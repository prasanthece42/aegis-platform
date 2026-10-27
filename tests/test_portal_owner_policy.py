import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from aegis_platform.portal_owner import PortalOwnerPolicy


def policy(**changes):
    return PortalOwnerPolicy.model_validate(
        {"platform_repository_id": "400", "mode": "read_only", "owner_user_ids": ["301"], **changes}
    )


def test_platform_owner_requires_an_explicit_distinct_grant():
    assert policy().owner_user_ids == ["301"]
    assert policy(owner_user_ids=[]).owner_user_ids == []
    with pytest.raises(ValidationError, match="distinct"):
        policy(owner_user_ids=["301", "301"])


@pytest.mark.parametrize(
    "changes", [{"mode": "admin"}, {"owner_user_ids": ["0"]}, {"allow_sync": True}]
)
def test_policy_cannot_introduce_write_sync_or_malformed_grants(changes):
    with pytest.raises(ValidationError):
        policy(**changes)


def test_live_owner_policy_is_bound_to_the_delivery_control_repository():
    owner = PortalOwnerPolicy.model_validate(
        json.loads(Path("policies/portal-owner.json").read_text())
    )
    delivery = json.loads(Path("policies/delivery.json").read_text())
    assert owner.platform_repository_id == delivery["platform_repository_id"]
