from types import SimpleNamespace

from aegis_platform.github_api import GitHubAPI


def test_repository_root_has_no_trailing_slash_and_token_stays_out_of_argv(monkeypatch):
    import aegis_platform.github_api as module

    seen = []

    def run(args, **kwargs):
        seen.append(args)
        assert "fixture-token" not in " ".join(args)
        assert kwargs["env"]["GH_TOKEN"] == "fixture-token"
        return SimpleNamespace(returncode=0, stdout=b'{"id":123}', stderr=b"")

    monkeypatch.setattr(module.subprocess, "run", run)
    assert GitHubAPI("fixture-token", "example/repository").repo("GET", "")["id"] == 123
    assert seen[0][2] == "/repos/example/repository"
