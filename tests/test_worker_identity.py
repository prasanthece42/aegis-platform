from aegis_platform.request import Issuer, RequestTrust
from aegis_platform.worker import proposal_issuers
from tests.test_delivery import policy as policy
from tooling import delivery


def test_only_active_matching_request_issuer_can_author_a_proposal(policy):
    trust = RequestTrust(
        platform_repository_id="400",
        issuers=[
            Issuer(
                issuer_id=issuer,
                key_id="key-" + bot,
                public_key_base64="a" * 43 + "=",
                bot_user_id=bot,
                active=active,
            )
            for issuer, bot, active in [
                ("portal", "902", True),
                ("other", "903", True),
                ("portal", "904", False),
            ]
        ],
    )
    assert proposal_issuers(policy, trust, "portal") == {"41898282", "902"}
    assert policy.workflow_bot_user_ids == ["41898282"]


def test_proposal_app_token_has_one_repository_and_no_status_write_authority(monkeypatch):
    tokens = []

    def mint(installation, repository_id, permissions):
        tokens.append((installation, repository_id, permissions))
        return "scoped-app-" + repository_id

    monkeypatch.setattr(delivery, "app_token", mint)
    monkeypatch.setenv("AEGIS_PLATFORM_INSTALLATION_ID", "201")
    monkeypatch.setenv("AEGIS_GITOPS_INSTALLATION_ID", "202")
    monkeypatch.setenv("GH_TOKEN", "hosted-check-token")
    proposal = delivery.worker(propose=True)
    assert proposal.gitops.token == "scoped-app-1433742863"
    assert tokens[-1] == (
        "202",
        "1433742863",
        {
            "contents": "write",
            "pull_requests": "write",
            "actions": "write",
            "statuses": "read",
        },
    )
    assert delivery.worker().gitops.token == "hosted-check-token"
