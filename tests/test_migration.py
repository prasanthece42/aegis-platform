import hashlib

from aegis_platform.migration import verify_baseline


def test_legacy_check_is_read_only_and_detects_changes(tmp_path):
    path = tmp_path / "aegis-cicd/app/main.py"
    path.parent.mkdir(parents=True)
    original = b"working application\n"
    path.write_bytes(original)
    snapshot = {
        "schema_version": 1,
        "approved_catalog_enrollment": False,
        "repositories": {
            "aegis-cicd": {"files": {"app/main.py": hashlib.sha256(original).hexdigest()}}
        },
    }
    assert verify_baseline(snapshot, tmp_path) == []
    assert path.read_bytes() == original
    path.write_text("unexpected change")
    assert verify_baseline(snapshot, tmp_path) == ["aegis-cicd/app/main.py"]
