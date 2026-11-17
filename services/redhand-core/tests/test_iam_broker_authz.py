"""
The credential broker (`/v1/iam/mint/*`) is called with an organization's SDK key, which is a telemetry credential: it proves an organization, not an agent.
Found by the route sweep: the endpoint minted for whatever agent and tool the request named, so any holder of the key could ask for cloud credentials for
an agent that does not exist, that another organization owns, that is frozen or revoked or only "reported", or for a tool its passport does not allow.
Now the request must name an active passport of the key's own organization, and a tool that passport's scopes cover.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest

from redhand_core.services.local_store import DEFAULT_ORG_ID, DEV_OPERATORS, DEFAULT_DEV_API_KEY, LocalSupabaseAdapter

from core_helpers import make_client, operator_headers

OTHER_ORG = "00000000-0000-0000-0000-0000000000c0"


class Env:
    def __init__(self) -> None:
        self.store = LocalSupabaseAdapter()
        self.client, self.settings = make_client(self.store, ENVIRONMENT="development")

    def h(self, user: str = "operator") -> dict[str, str]:
        return operator_headers(user, settings=self.settings)

    def register(self, scopes: list[dict[str, str]] | None = None, name: str = "broker-bot") -> dict[str, Any]:
        body = {"name": name, "framework": "custom", "scopes": scopes if scopes is not None else [{"server": "gcs", "tool": "read_object"}]}
        response = self.client.post("/v1/passports", json=body, headers=self.h("admin"))
        assert response.status_code == 201, response.text
        passport: dict[str, Any] = response.json()["passport"]
        return passport

    def gcp(self, agent: dict[str, Any] | str, tool: str = "read_object", key: str = DEFAULT_DEV_API_KEY) -> Any:
        external = agent if isinstance(agent, str) else agent["external_agent_id"]
        body = {"trace_id": uuid4().hex, "span_id": uuid4().hex[:16], "external_agent_id": external, "tool_name": tool,
                "target_resource": "//storage.googleapis.com/projects/_/buckets/example-bucket", "permissions": ["storage.objects.get"]}
        return self.client.post("/v1/iam/mint/gcp", json=body, headers={"X-RedHand-API-Key": key})

    def aws(self, agent: dict[str, Any] | str, tool: str = "read_object") -> Any:
        external = agent if isinstance(agent, str) else agent["external_agent_id"]
        body = {"trace_id": uuid4().hex, "span_id": uuid4().hex[:16], "external_agent_id": external, "tool_name": tool,
                "role_arn": "arn:aws:iam::123456789012:role/redhand-test", "target_resource_arn": "arn:aws:s3:::example-bucket/*", "actions": ["s3:GetObject"]}
        return self.client.post("/v1/iam/mint/aws", json=body, headers={"X-RedHand-API-Key": DEFAULT_DEV_API_KEY})

    def set_status(self, agent: dict[str, Any], **changes: Any) -> None:
        row = next(a for a in self.store.tables["agents"] if str(a["id"]) == str(agent["id"]))
        row.update(changes)


@pytest.fixture
def env() -> Env:
    return Env()


def test_an_active_passport_of_the_organization_with_a_covering_scope_can_mint(env: Env) -> None:
    agent = env.register()
    response = env.gcp(agent)
    assert response.status_code == 200, response.text
    assert env.aws(agent).status_code in (200, 403), "the AWS route reaches its own checks (a deployment with no AWS source is refused there)"


def test_an_agent_that_does_not_exist_gets_nothing(env: Env) -> None:
    response = env.gcp("no-such-agent")
    assert response.status_code == 403 and "passport" in response.json()["detail"].lower()
    assert env.aws("no-such-agent").status_code == 403


def test_another_organizations_agent_gets_nothing(env: Env) -> None:
    env.store.tables["organizations"].append({"id": OTHER_ORG, "name": "Other", "slug": "other", "safe_mode": False})
    env.store.tables["agents"].append({
        "id": str(uuid4()), "organization_id": OTHER_ORG, "external_agent_id": "theirs", "name": "Theirs", "framework": "n8n", "environment": "production",
        "scopes": [{"server": "gcs", "tool": "*", "access": "write"}], "status": "active", "expires_at": "2099-01-01T00:00:00+00:00", "version": 1,
        "reported_only": False})
    assert env.gcp("theirs").status_code == 403
    assert env.aws("theirs").status_code == 403


@pytest.mark.parametrize("changes", [{"status": "frozen"}, {"status": "revoked"}, {"expires_at": "2000-01-01T00:00:00+00:00"}, {"reported_only": True}],
                         ids=["frozen", "revoked", "expired", "reported-only"])
def test_an_agent_that_may_not_act_gets_nothing(env: Env, changes: dict[str, Any]) -> None:
    agent = env.register()
    env.set_status(agent, **changes)
    assert env.gcp(agent).status_code == 403
    assert env.aws(agent).status_code == 403


def test_a_tool_outside_the_passport_scopes_gets_nothing(env: Env) -> None:
    agent = env.register([{"server": "gcs", "tool": "read_object"}])
    assert env.gcp(agent, tool="delete_bucket").status_code == 403
    assert env.aws(agent, tool="delete_bucket").status_code == 403


def test_a_wildcard_scope_covers_any_tool_and_no_scope_covers_none(env: Env) -> None:
    wide = env.register([{"server": "gcs", "tool": "*"}], name="wide-bot")
    assert env.gcp(wide, tool="anything").status_code == 200
    none = env.register([], name="empty-bot")
    assert env.gcp(none, tool="anything").status_code == 403


def test_a_refused_request_changes_nothing(env: Env) -> None:
    import copy

    before = copy.deepcopy(env.store.tables)
    env.gcp("no-such-agent")
    assert env.store.tables == before


def test_the_operators_exist_for_this_test() -> None:
    assert DEV_OPERATORS["operator"]["role"] == "security_operator" and DEFAULT_ORG_ID
