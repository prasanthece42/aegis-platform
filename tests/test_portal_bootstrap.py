import os

import pytest

from tooling.bootstrap_portal import private_file


def test_bootstrap_accepts_only_private_regular_credential_files(tmp_path):
    path = tmp_path / "key.pem"
    path.write_bytes(b"fixture only")
    path.chmod(0o600)
    assert private_file(path) == b"fixture only"
    path.chmod(0o640)
    with pytest.raises(ValueError, match="private regular"):
        private_file(path)


def test_bootstrap_refuses_credential_symlinks_and_foreign_ownership(tmp_path, monkeypatch):
    path = tmp_path / "key.pem"
    path.write_bytes(b"fixture only")
    path.chmod(0o600)
    link = tmp_path / "linked.pem"
    link.symlink_to(path)
    with pytest.raises(ValueError, match="private regular"):
        private_file(link)
    owner = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: owner + 1)
    with pytest.raises(ValueError, match="owned by the operator"):
        private_file(path)
