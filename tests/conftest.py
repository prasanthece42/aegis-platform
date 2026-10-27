from pathlib import Path

import pytest

from aegis_platform.canonical import strict_json

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def fields():
    return {
        "repository_id": "101",
        "app_id": "orders-api",
        "display_name": "Orders API",
        "owner_user_ids": ["301"],
        "runtime": {
            "profile_id": "python312-web",
            "container_port": 8000,
            "health_path": "/health",
            "resource_profile_id": "small",
        },
    }


@pytest.fixture
def example_entries():
    return [
        strict_json(p.read_bytes()) for p in sorted((ROOT / "examples/catalog/apps").glob("*.json"))
    ]


@pytest.fixture
def cluster_record():
    return strict_json((ROOT / "examples/catalog/clusters/example-kind.json").read_bytes())


@pytest.fixture
def policy_record():
    return strict_json((ROOT / "policies/catalog.json").read_bytes())
