"""Reviewed local telemetry identity and immutable component inventory."""

import hashlib
import hmac
import ipaddress
from typing import Literal

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from pydantic import Field, model_validator

from aegis_platform.contracts import Contract, Digest, Identifier

OBS_NAMESPACE = "aegis-observability"
OBS_BASE = "platform-services/aegis-observability"
COLLECTOR_ENDPOINT = "http://collector.aegis-observability.svc.cluster.local:4318"
IMAGE_REPOSITORIES = {
    "prometheus": "quay.io/prometheus/prometheus",
    "alertmanager": "quay.io/prometheus/alertmanager",
    "loki": "docker.io/grafana/loki",
    "tempo": "docker.io/grafana/tempo",
    "collector": (
        "ghcr.io/open-telemetry/opentelemetry-collector-releases/opentelemetry-collector-contrib"
    ),
    "proxy": "docker.io/nginxinc/nginx-unprivileged",
    "log_agent": "docker.io/library/python",
}


def query_password(client_secret: str, cluster_uid: str) -> str:
    """Domain-separated read capability; never transmit the OAuth secret to telemetry."""
    if len(client_secret) < 20 or not cluster_uid:
        raise ValueError("Protected OAuth secret and enrolled cluster identity required")
    return hmac.new(
        client_secret.encode(),
        ("aegis/observability/query/v1/" + cluster_uid).encode(),
        hashlib.sha256,
    ).hexdigest()


def password_fingerprint(password: str) -> str:
    return "sha256:" + hashlib.sha256(password.encode()).hexdigest()


class ObservabilityPolicy(Contract):
    schema_version: Literal[1] = 1
    platform_repository_id: Identifier
    gitops_repository_id: Identifier
    gitops_repository: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    cluster_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,39}$")
    cluster_uid: str = Field(min_length=1, max_length=100)
    node_name: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]{0,252}$")
    node_ip: str
    namespace: Literal["aegis-observability"] = OBS_NAMESPACE
    retention_hours: Literal[24] = 24
    query_password_sha256: Digest
    images: dict[str, str]
    kubelet_ca_pem: str = Field(min_length=128, max_length=16384)

    @model_validator(mode="after")
    def fixed_components_and_public_trust(self):
        address = ipaddress.ip_address(self.node_ip)
        if not address.is_private or address.is_loopback or address.is_unspecified:
            raise ValueError("Collector requires the enrolled node's private internal IP")
        if set(self.images) != set(IMAGE_REPOSITORIES):
            raise ValueError("Exactly the reviewed seven telemetry components are required")
        for name, repo in IMAGE_REPOSITORIES.items():
            image = self.images[name]
            prefix = repo + "@sha256:"
            if not image.startswith(prefix):
                raise ValueError("Component repository or immutable identity differs")
            digest = image[len(prefix) :]
            if (
                len(digest) != 64
                or digest == "0" * 64
                or any(c not in "0123456789abcdef" for c in digest)
            ):
                raise ValueError("Component must use a full immutable SHA-256 digest")
        if "PRIVATE KEY" in self.kubelet_ca_pem:
            raise ValueError("Only public kubelet certificates may enter policy")
        chain = x509.load_pem_x509_certificates(self.kubelet_ca_pem.encode())
        if len(chain) != 2:
            raise ValueError("Expected the enrolled kubelet leaf and public CA")
        leaf, ca = chain
        try:
            leaf.verify_directly_issued_by(ca)
            ca.verify_directly_issued_by(ca)
        except InvalidSignature as exc:
            raise ValueError("Kubelet public certificate chain is invalid") from exc
        if not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("Kubelet trust anchor must be a CA")
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if self.node_name not in names.get_values_for_type(x509.DNSName):
            raise ValueError("Kubelet public certificate differs from the enrolled node name")
        return self
