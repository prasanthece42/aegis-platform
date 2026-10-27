import os
from types import SimpleNamespace

import pytest

from tooling.bootstrap_portal import merged_branch_pr, private_file


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


def merge_api(prs, *, graphql_changes=None, errors=False):
    def pages(path, **params):
        assert path == "pulls" and params == {"state": "closed", "base": "platform-system"}
        return [{"number": number, "merged_at": pr["merged_at"]} for number, pr in prs.items()]

    def repo(method, path):
        assert method == "GET"
        return prs[int(path.removeprefix("pulls/"))]

    def call(method, path, payload):
        assert (method, path) == ("POST", "/graphql")
        assert payload["variables"]["owner"] == "example"
        assert payload["variables"]["name"] == "gitops"
        number = payload["variables"]["number"]
        merged = {
            "number": number,
            "state": "MERGED",
            "merged": True,
            "baseRefName": "platform-system",
            "headRefOid": "b" * 40,
            "mergeCommit": {"oid": "a" * 40},
            **(graphql_changes or {}),
        }
        return (
            {"errors": [{"message": "provider failure"}]}
            if errors
            else {"data": {"repository": {"pullRequest": merged}}}
        )

    return SimpleNamespace(repository="example/gitops", pages=pages, repo=repo, call=call)


def merged_pr(**changes):
    return {
        "number": 20,
        "state": "closed",
        "merged_at": "2026-10-27T13:50:18Z",
        "base": {"ref": "platform-system"},
        "head": {"sha": "b" * 40},
        **changes,
    }


def test_bootstrap_binds_graphql_merge_when_rest_omits_merge_sha():
    pr = merged_pr()
    assert "merge_commit_sha" not in pr
    assert merged_branch_pr(merge_api({20: pr}), "platform-system", "a" * 40) == pr


@pytest.mark.parametrize(
    "changes",
    [{"base": {"ref": "main"}}, {"merged_at": None}, {"state": "open"}],
)
def test_bootstrap_still_rejects_wrong_branch_or_unmerged_rest_pr(changes):
    with pytest.raises(ValueError, match="reviewed merged PR"):
        merged_branch_pr(merge_api({20: merged_pr(**changes)}), "platform-system", "a" * 40)


@pytest.mark.parametrize(
    "changes",
    [
        {"mergeCommit": {"oid": "c" * 40}},
        {"mergeCommit": None},
        {"headRefOid": "c" * 40},
        {"baseRefName": "main"},
        {"number": 99},
        {"state": "CLOSED"},
        {"merged": False},
    ],
)
def test_bootstrap_rejects_mismatched_graphql_identity(changes):
    with pytest.raises(ValueError, match="reviewed merged PR"):
        merged_branch_pr(
            merge_api({20: merged_pr()}, graphql_changes=changes), "platform-system", "a" * 40
        )


def test_bootstrap_rejects_graphql_errors():
    with pytest.raises(ValueError, match="authoritative PR"):
        merged_branch_pr(merge_api({20: merged_pr()}, errors=True), "platform-system", "a" * 40)


def test_bootstrap_rejects_ambiguous_merge_bindings():
    with pytest.raises(ValueError, match="reviewed merged PR"):
        merged_branch_pr(
            merge_api({20: merged_pr(), 21: merged_pr(number=21)}), "platform-system", "a" * 40
        )
