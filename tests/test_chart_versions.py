import pytest

from tooling.check_chart_versions import assert_immutable


def test_existing_versions_are_immutable_and_new_versions_are_allowed():
    original = {"charts/web-service/1.0.0/Chart.yaml": b"version: 1.0.0"}
    assert_immutable(
        original, {**original, "charts/web-service/1.0.1/Chart.yaml": b"version: 1.0.1"}
    )
    for changed in [
        {},
        {"charts/web-service/1.0.0/Chart.yaml": b"changed"},
        {**original, "charts/web-service/1.0.0/templates/new.yaml": b"new resource"},
    ]:
        with pytest.raises(ValueError):
            assert_immutable(original, changed)
