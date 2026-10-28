import collections
import io
import json
from urllib.parse import urlparse

import pytest

from aegis_platform.observability_log_agent import LogAgent, safe_line, timestamp_ns


@pytest.mark.parametrize(
    "line,private",
    [
        ("Authorization: Basic cHJpdmF0ZTpwYXNz", "cHJpdmF0ZTpwYXNz"),
        ("Cookie: session=private-value; other=also-private", "private"),
        ('{"cookie":"session=private-value; another=private"}', "private"),
        ("Set-Cookie: session=private-value; Secure; HttpOnly", "private"),
        ("Bearer private-bearer-value", "private"),
        ('{"client_secret":"private-value"}', "private"),
        ("/callback?code=private-value&state=private-state", "private"),
    ],
)
def test_container_log_scrubbing_covers_credentials_and_cookie_headers(line, private):
    assert private not in safe_line(line)
    assert "[redacted]" in safe_line(line)
    assert len(safe_line("x" * 10000)) == 4096
    assert "\x00" not in safe_line("hello\x00")


def agent_fixture():
    # No Kubernetes credentials, DNS, CA or cluster connection in these tests.
    agent = LogAgent.__new__(LogAgent)
    agent.namespaces = ["aegis-deleted", "aegis-hello-aegis-dev"]
    agent.cluster_uid = "test-cluster"
    agent.password = "synthetic-agent-password"
    agent.namespace_cursor = 0
    agent.cursors = {}
    agent.seen = collections.deque(maxlen=2000)
    return agent


def test_namespace_failure_isolated_and_cursors_only_advance_after_full_acceptance():
    agent = agent_fixture()
    paths = []

    def request(path):
        paths.append(path)
        if "aegis-deleted" in path:
            raise OSError("Namespace deleted")
        if urlparse(path).path.endswith("/log"):
            return b"2026-10-27T18:30:10.123456789Z Hello Aegis\n"
        return json.dumps(
            {
                "items": [
                    {
                        "metadata": {
                            "name": "hello-123",
                            "uid": "pod-uid",
                            "namespace": "aegis-hello-aegis-dev",
                        },
                        "status": {
                            "containerStatuses": [
                                {
                                    "name": "web",
                                    "restartCount": 0,
                                    "state": {"running": {"startedAt": "now"}},
                                }
                            ]
                        },
                    }
                ]
            }
        ).encode()

    class Opener:
        result = {"partialSuccess": {"rejectedLogRecords": 1}}

        def open(self, request, timeout):
            assert request.method == "POST"
            assert request.headers["Authorization"].startswith("Basic ")
            assert timeout == 5
            self.payload = json.loads(request.data)
            return io.BytesIO(json.dumps(self.result).encode())

    agent.request, agent.opener = request, Opener()
    batches, updates = agent.collect()
    assert len(batches) == len(updates) == 1
    assert not agent.cursors and not agent.seen
    with pytest.raises(ValueError, match="not fully accepted"):
        agent.publish(batches, updates)
    assert not agent.cursors and not agent.seen
    agent.opener.result = {}
    agent.publish(batches, updates)
    assert len(agent.cursors) == len(agent.seen) == 1
    assert agent.collect() == ([], [])
    assert "sinceTime=" in next(path for path in reversed(paths) if "/log?" in path)
    attrs = {
        row["key"]: row["value"]["stringValue"] for row in batches[0]["resource"]["attributes"]
    }
    assert attrs["k8s.namespace.name"] == "aegis-hello-aegis-dev"
    assert attrs["aegis.cluster.uid"] == "test-cluster"
    assert attrs["aegis.log_source"] == "container"


def test_cluster_mismatch_and_paginated_discovery_fail_closed():
    agent = agent_fixture()
    agent.request = lambda _: b'{"metadata":{"uid":"another-cluster"}}'
    with pytest.raises(ValueError, match="Cluster identity differs"):
        agent.verify_cluster()
    agent.namespaces = None
    agent.request = lambda _: b'{"metadata":{"continue":"next-page"},"items":[]}'
    with pytest.raises(ValueError, match="discovery exceeds budget"):
        agent.collect()


def test_nanosecond_timestamps_are_exact_and_invalid_timestamps_fail():
    assert timestamp_ns("2026-10-27T18:30:10.123456789Z") % 1000000000 == 123456789
    with pytest.raises(ValueError):
        timestamp_ns("2026-10-27T18:30:10.1234567899Z")
