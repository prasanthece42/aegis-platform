from aegis_platform.canonical import digest
from aegis_platform.contracts import DesiredState


def desired_fingerprint(state: DesiredState) -> str:
    return digest(state.model_dump())
