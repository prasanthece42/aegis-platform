from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from tooling.stack_credentials import credential_material


def test_generated_credentials_bind_only_the_app_namespace_and_dependencies(capsys):
    entry = SimpleNamespace(
        app_id="commerce-demo",
        runtime=SimpleNamespace(
            profile_id="python312-multiservice", credentials_secret="commerce-demo-runtime"
        ),
        environments={"dev": SimpleNamespace(namespace="aegis-commerce-demo-dev")},
    )
    material = credential_material(entry, "dev")
    assert capsys.readouterr().out == ""
    assert material["metadata"]["namespace"] == "aegis-commerce-demo-dev"
    values = material["stringData"]
    database, redis = urlsplit(values["database-url"]), urlsplit(values["redis-url"])
    assert database.password == values["postgres-password"]
    assert redis.password == values["redis-password"]
    assert database.hostname == "commerce-demo-postgres"
    assert redis.hostname == "commerce-demo-redis"
    assert len(values["postgres-password"]) == 64
    entry.runtime.credentials_secret = "other-app-runtime"
    with pytest.raises(ValueError, match="belong"):
        credential_material(entry, "dev")
