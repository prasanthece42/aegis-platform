import base64
from copy import deepcopy
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis_platform.canonical import canonical, digest
from aegis_platform.request import Issuer, RequestTrust, verify_record, verify_request
from tests.test_proposal import admitted as admitted
from tests.test_proposal import policy as policy
from tests.test_proposal import release_case as release_case


@pytest.fixture
def signed(admitted):
    key = Ed25519PrivateKey.generate()
    trust = RequestTrust(
        platform_repository_id="400",
        issuers=[
            Issuer(
                issuer_id="test",
                key_id="test-key",
                bot_user_id="902",
                active=True,
                public_key_base64=base64.b64encode(
                    key.public_key().public_bytes(
                        serialization.Encoding.Raw, serialization.PublicFormat.Raw
                    )
                ).decode(),
            )
        ],
    )

    def sign(payload):
        return {
            "payload": payload,
            "envelope": {
                "algorithm": "Ed25519",
                "key_id": "test-key",
                "payload_sha256": digest(payload),
                "signature": base64.urlsafe_b64encode(key.sign(canonical(payload)))
                .rstrip(b"=")
                .decode(),
            },
        }

    intent = admitted["intent"].model_dump()
    issue = {
        "id": 800,
        "number": 1,
        "html_url": "https://github.com/example/aegis-platform/issues/1",
        "user": {"id": 902, "type": "Bot"},
        "state": "open",
        "body": canonical(sign({"kind": "deployment_intent", "intent": intent})).decode(),
    }
    record = sign(
        {
            "kind": "deployment_request",
            "intent": intent,
            "binding": {"id": "800", "number": 1, "url": issue["html_url"]},
        }
    )
    return record, issue, trust, intent["request_id"], admitted["now"]


def test_exact_signed_issue_and_canonical_journal_are_required(signed):
    assert verify_request(*signed).request_id == signed[3]


@pytest.mark.parametrize(
    "mutation", ["body", "author", "closed", "id", "payload", "expiry", "revoked"]
)
def test_forged_revoked_or_rebound_requests_fail_closed(signed, mutation):
    record, issue, trust, rid, now = deepcopy(signed)
    if mutation == "body":
        issue["body"] = "untrusted labels are not signed requests"
    elif mutation == "author":
        issue["user"]["id"] = 999
    elif mutation == "closed":
        issue["state"] = "closed"
    elif mutation == "id":
        issue["id"] = 801
    elif mutation == "payload":
        record["payload"]["intent"]["requester_user_id"] = "999"
    elif mutation == "expiry":
        now += timedelta(days=2)
    else:
        trust.issuers[0].active = False
        assert verify_record(record, trust, admission=False)
    with pytest.raises(ValueError):
        verify_request(record, issue, trust, rid, now)
