"""Source-bound six/many-image receipts and a bounded archive of verified OCI graphs."""

import tarfile
import tempfile
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from aegis_platform.canonical import digest, strict_json
from aegis_platform.release import (
    PublishedPlatform,
    ReleaseContext,
    ReleaseEvidence,
    file_hash,
    verify_oci_bundle,
)
from aegis_platform.stack import Name, StackDefinition


class ComponentContext(ReleaseContext):
    service_name: Name

    @property
    def image_name(self):
        return super().image_name + "/" + self.service_name


class ComponentPlatform(PublishedPlatform):
    service_name: Name

    @property
    def image_name(self):
        return super().image_name + "/" + self.service_name


class ComponentEvidence(ReleaseEvidence):
    service_name: Name
    platforms: dict[str, ComponentPlatform]

    @property
    def image_name(self):
        return super().image_name + "/" + self.service_name

    @model_validator(mode="after")
    def component_children(self):
        if any(c.service_name != self.service_name for c in self.platforms.values()):
            raise ValueError("Component receipt mixes service identities")
        return self


class StackReleaseEvidence(ReleaseEvidence):
    schema_version: Literal[4] = 4
    stack: StackDefinition
    stack_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    primary_bundle_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    components: dict[Name, ComponentEvidence] = Field(min_length=1, max_length=7)
    dependency_images: dict[str, str]
    integration_tests: Literal["passed"]

    @model_validator(mode="after")
    def complete_stack(self):
        from aegis_platform.stack_plan import DEPENDENCY_IMAGES

        if self.stack_sha256 != digest(self.stack.model_dump()):
            raise ValueError("Stack receipt topology hash differs")
        if set(self.components) != set(self.stack.services) - {self.stack.primary_service}:
            raise ValueError("Release must contain every declared service exactly once")
        if self.dependency_images != DEPENDENCY_IMAGES:
            raise ValueError("Dependency images differ from the reviewed platform profile")
        for name, component in self.components.items():
            if component.service_name != name:
                raise ValueError("Component key and service identity differ")
            for field in ReleaseContext.model_fields:
                if getattr(component, field) != getattr(self, field):
                    raise ValueError(
                        "Stack components must share the same source, run and helper pin"
                    )
        return self

    def service_receipts(self):
        return {self.stack.primary_service: self, **self.components}


def parse_release(raw):
    data = strict_json(raw) if isinstance(raw, bytes) else raw
    cls = StackReleaseEvidence if data.get("schema_version") == 4 else ReleaseEvidence
    return cls.model_validate(data)


def verify_stack_bundle(path: Path, evidence: StackReleaseEvidence, consume=None):
    """Never extract member paths; verify the exact bytes of each nested graph first."""
    if file_hash(path) != evidence.bundle_sha256 or path.stat().st_size > 4 * 1024**3:
        raise ValueError("Stack bundle checksum/size differs")
    receipts = evidence.service_receipts()
    expected = {f"services/{name}.oci.tar": name for name in receipts}
    with tarfile.open(path) as archive, tempfile.TemporaryDirectory(prefix="aegis-stack-") as temp:
        members = archive.getmembers()
        if len(members) != len(expected) or {m.name for m in members} != set(expected):
            raise ValueError("Stack archive must contain exactly its declared service graphs")
        verified = []
        for member in members:
            if not member.isfile() or member.size > 1024**3:
                raise ValueError("Stack graph must be a bounded regular file")
            name = expected[member.name]
            target = Path(temp) / (name + ".tar")
            with target.open("wb") as output, archive.extractfile(member) as source:
                import shutil

                shutil.copyfileobj(source, output)
            child = receipts[name]
            checksum = (
                evidence.primary_bundle_sha256
                if name == evidence.stack.primary_service
                else child.bundle_sha256
            )
            if file_hash(target) != checksum:
                raise ValueError("Service graph checksum differs")
            verify_oci_bundle(target, child.image.rsplit("@", 1)[1], child.platforms)
            verified.append((name, target, child))
        # No cache mutation occurs until every graph has passed verification.
        if consume:
            for name, target, child in verified:
                consume(name, target, child)
