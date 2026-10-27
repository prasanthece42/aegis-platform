"""Public-key verification of durable portal requests and their canonical issue binding."""

import base64
from datetime import datetime, timedelta
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field

from aegis_platform.canonical import canonical, digest
from aegis_platform.contracts import Contract, DeploymentIntent, Identifier
from aegis_platform.delivery import timestamp


class Issuer(Contract):
    issuer_id: str = Field(min_length=1, max_length=100)
    key_id: str = Field(min_length=1, max_length=100)
    public_key_base64: str = Field(min_length=43, max_length=44)
    bot_user_id: Identifier
    active: bool


class RequestTrust(Contract):
    schema_version: Literal[1] = 1
    platform_repository_id: Identifier
    issuers: list[Issuer] = Field(min_length=1, max_length=20)
    maximum_request_age_seconds: int = Field(default=86400, ge=300, le=86400)


def verify_record(
    record: dict, trust: RequestTrust, *, admission: bool = True
) -> tuple[dict, Issuer]:
    if set(record) != {"payload", "envelope"}:
        raise ValueError("Invalid signed record fields")
    envelope, payload = record["envelope"], record["payload"]
    if (
        not isinstance(envelope, dict)
        or set(envelope) != {"algorithm", "key_id", "payload_sha256", "signature"}
        or envelope["algorithm"] != "Ed25519"
        or envelope["payload_sha256"] != digest(payload)
    ):
        raise ValueError("Invalid signature envelope")
    intent = DeploymentIntent.model_validate(payload["intent"])
    matches = [
        issuer
        for issuer in trust.issuers
        if (issuer.key_id == envelope["key_id"] and issuer.issuer_id == intent.issuer_id)
    ]
    if (
        len(matches) != 1
        or intent.platform_repository_id != trust.platform_repository_id
        or (admission and not matches[0].active)
    ):
        raise ValueError("Request issuer is unknown, revoked or bound to another repository")
    issuer = matches[0]
    try:
        public = base64.b64decode(issuer.public_key_base64, validate=True)
        encoded = envelope["signature"]
        signature = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
        )
        Ed25519PublicKey.from_public_bytes(public).verify(signature, canonical(payload))
    except (ValueError, InvalidSignature) as exc:
        raise ValueError("Invalid request signature") from exc
    return payload, issuer


def verify_request(record: dict, issue: dict, trust: RequestTrust, request_id: str, now: datetime):
    from aegis_platform.canonical import strict_json

    payload, issuer = verify_record(record, trust)
    if set(payload) != {"kind", "intent", "binding"} or payload["kind"] != "deployment_request":
        raise ValueError("Not a canonical deployment request")
    intent = DeploymentIntent.model_validate(payload["intent"])
    binding = payload["binding"]
    if (
        not isinstance(binding, dict)
        or set(binding) != {"id", "number", "url"}
        or intent.request_id != request_id
        or binding["id"] != str(issue.get("id"))
        or binding["number"] != issue.get("number")
        or binding["url"] != issue.get("html_url")
        or str(issue.get("user", {}).get("id")) != issuer.bot_user_id
        or issue.get("user", {}).get("type") != "Bot"
        or "pull_request" in issue
        or issue.get("state") != "open"
    ):
        raise ValueError("Request is not bound to its exact bot-authored open issue")
    body, issue_issuer = verify_record(strict_json(issue["body"]), trust)
    if (
        set(body) != {"kind", "intent"}
        or body["kind"] != "deployment_intent"
        or body["intent"] != payload["intent"]
        or issue_issuer != issuer
    ):
        raise ValueError("Issue differs from the canonical journal")
    created = timestamp(intent.created_at)
    if created > now + timedelta(seconds=300) or now - created > timedelta(
        seconds=trust.maximum_request_age_seconds
    ):
        raise ValueError("Request is expired or future-dated")
    return intent
