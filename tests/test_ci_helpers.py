import pytest

from tooling.ci import checks, inventory_policy


def test_scan_requires_application_inventory_and_blocks_unfixed_critical():
    with pytest.raises(ValueError):
        inventory_policy({"Results": []})
    valid = {"Results": [{"Class": "lang-pkgs", "Packages": [{"Name": "fastapi"}]}]}
    inventory_policy(valid)
    valid["Results"][0]["Vulnerabilities"] = [{"Severity": "CRITICAL", "FixedVersion": ""}]
    with pytest.raises(ValueError):
        inventory_policy(valid)


def test_generic_checks_use_platform_logic_and_a_separate_application_environment(
    tmp_path, monkeypatch
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "requirements.txt").write_text("hash-locked development dependencies")
    (source / "requirements-prod.txt").write_text("hash-locked runtime dependencies")
    calls = []
    monkeypatch.setattr("tooling.ci.run", lambda args, **kwargs: calls.append((args, kwargs)))
    venv = tmp_path / "source-venv"
    checks(source, venv)
    assert calls[1][0][0] == str(venv / "bin/python")
    assert "--require-hashes" in calls[1][0]
    assert calls[-1][0][-2:] == ["-m", "pytest"]
    assert all("source/scripts/" not in " ".join(command) for command, _kwargs in calls)
