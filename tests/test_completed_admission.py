from types import SimpleNamespace

import pytest

from tooling import delivery


def test_completed_event_does_not_reissue_a_status(monkeypatch):
    def repo(method, _path, *_args):
        assert method == "GET"
        return {"state": "closed", "merged_at": "2026-10-27T00:00:00Z"}

    monkeypatch.setattr(
        delivery, "worker", lambda **_: SimpleNamespace(gitops=SimpleNamespace(repo=repo))
    )
    monkeypatch.setattr(delivery.sys, "argv", ["delivery.py", "check-event", "--pr-number", "16"])
    delivery.main()


@pytest.mark.parametrize("completion", ["merged", "new_head", "still_open"])
def test_merge_race_never_writes_a_retrospective_failure(monkeypatch, completion):
    calls = []

    def repo(method, path, *args):
        calls.append((method, path))
        if method == "POST":
            assert completion == "still_open"
            return {}
        return {
            "state": "closed" if len(calls) > 1 and completion == "merged" else "open",
            "merged_at": "2026-10-27T00:00:00Z"
            if len(calls) > 1 and completion == "merged"
            else None,
            "head": {"sha": "b" * 40 if len(calls) > 1 and completion == "new_head" else "a" * 40},
        }

    def checking(*_):
        raise ValueError("Desired state changed during merge")

    monkeypatch.setattr(
        delivery,
        "worker",
        lambda **_: SimpleNamespace(gitops=SimpleNamespace(repo=repo), check_pr=checking),
    )
    monkeypatch.setattr(
        delivery.sys,
        "argv",
        [
            "delivery.py",
            "check-pr",
            "--pr-number",
            "16",
            "--request-id",
            "req-" + "a" * 64,
            "--issue-number",
            "4",
        ],
    )
    if completion == "still_open":
        with pytest.raises(ValueError):
            delivery.main()
        assert calls[-1][0] == "POST"
    else:
        delivery.main()
        assert all(method == "GET" for method, _ in calls)
