from copy import deepcopy

import pytest

from aegis_platform.publication import GitHubReleaseAPI, publish_release
from tests.release_fixtures import release_fixture, sha


class FakeAPI:
    repository = "example/orders-api"

    def __init__(self):
        self.reference = None
        self.release = None
        self.uploaded = {}
        self.mutations = []
        self.fail_upload_once = False

    def api(self, suffix, method="GET", payload=None, missing=False):
        if method != "GET":
            self.mutations.append((suffix, method))
        if suffix.startswith("git/ref/tags/"):
            return deepcopy(self.reference)
        if suffix == "git/refs":
            self.reference = {"object": {"type": "commit", "sha": payload["sha"]}}
            return deepcopy(self.reference)
        if suffix.startswith("releases/tags/"):
            return deepcopy(self.release)
        if suffix == "releases":
            self.release = {
                **payload,
                "id": 7,
                "author": {"login": "github-actions[bot]", "type": "Bot"},
            }
            return deepcopy(self.release)
        if suffix == "releases/7" and method == "PATCH":
            self.release.update(payload)
            return deepcopy(self.release)
        raise AssertionError(suffix)

    def assets(self, _release_id):
        return [
            {"name": name, "id": i, "size": len(data), "state": "uploaded"}
            for i, (name, data) in enumerate(self.uploaded.items(), 1)
        ]

    def upload(self, _tag, path):
        if self.fail_upload_once and path.name == "image.oci.tar":
            self.fail_upload_once = False
            raise ValueError("simulated interrupted upload")
        assert path.name not in self.uploaded
        self.uploaded[path.name] = path.read_bytes()

    def asset_hash(self, asset_id):
        return sha(list(self.uploaded.values())[asset_id - 1])


def test_draft_publication_verifies_assets_then_reuses_published_release(tmp_path):
    fixture = release_fixture(tmp_path)
    api = FakeAPI()
    first = publish_release(api, fixture["evidence"], fixture["receipt"], fixture["bundle"])
    assert first["draft"] is False
    mutations = len(api.mutations)
    second = publish_release(api, fixture["evidence"], fixture["receipt"], fixture["bundle"])
    assert second["id"] == first["id"]
    assert len(api.mutations) == mutations


def test_partial_upload_resumes_the_same_draft_without_overwriting(tmp_path):
    fixture = release_fixture(tmp_path)
    api = FakeAPI()
    api.fail_upload_once = True
    with pytest.raises(ValueError):
        publish_release(api, fixture["evidence"], fixture["receipt"], fixture["bundle"])
    original = api.uploaded["release.json"]
    assert api.release["draft"] is True
    result = publish_release(api, fixture["evidence"], fixture["receipt"], fixture["bundle"])
    assert result["draft"] is False and api.uploaded["release.json"] == original


@pytest.mark.parametrize(
    "mutation",
    ["tag", "author", "asset", "missing_published_asset", "unexpected_asset", "repository"],
)
def test_wrong_issuer_tag_or_bytes_cannot_be_replaced(tmp_path, mutation):
    fixture = release_fixture(tmp_path)
    api = FakeAPI()
    publish_release(api, fixture["evidence"], fixture["receipt"], fixture["bundle"])
    if mutation == "tag":
        api.reference["object"]["sha"] = "f" * 40
    elif mutation == "author":
        api.release["author"] = {"login": "human", "type": "User"}
    elif mutation == "asset":
        api.uploaded["release.json"] = b"changed"
    elif mutation == "missing_published_asset":
        api.uploaded.pop("image.oci.tar")
    elif mutation == "unexpected_asset":
        api.uploaded["extra.txt"] = b"unexpected"
    else:
        api.repository = "other/repository"
    mutations = len(api.mutations)
    with pytest.raises(ValueError):
        publish_release(api, fixture["evidence"], fixture["receipt"], fixture["bundle"])
    assert len(api.mutations) == mutations


def test_transport_requires_an_explicit_token_and_never_uses_ambient_login(monkeypatch, tmp_path):
    from types import SimpleNamespace

    with pytest.raises(ValueError):
        GitHubReleaseAPI("example/orders-api", "")
    with pytest.raises(ValueError):
        GitHubReleaseAPI("example/..", "synthetic")
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        if "stdout" in kwargs:
            kwargs["stdout"].write(b"asset")
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr("aegis_platform.publication.subprocess.run", run)
    api = GitHubReleaseAPI("example/orders-api", "explicit-test-token")
    api.api("releases")
    api.upload("release-123-1", tmp_path / "release.json")
    assert api.asset_hash(1) == sha(b"asset")
    assert all(call[1]["env"]["GH_TOKEN"] == "explicit-test-token" for call in calls)
    assert all(call[1]["env"]["GH_HOST"] == "github.com" for call in calls)
    assert all("explicit-test-token" not in " ".join(call[0]) for call in calls)
