"""
Unit tests for the Ephemeral IAM Token Broker, STS providers, and WORM audit logger.
"""

import time
import pytest
from agentwall.src.broker.providers.aws_sts import AWSSTSProvider
from agentwall.src.broker.providers.azure_sts import AzureSTSProvider
from agentwall.src.broker.providers.gcp_sts import GCPSTSProvider
from agentwall.src.broker.providers.local_mock import LocalMockSTSProvider
from agentwall.src.broker.providers.saas_token import SaaSTokenProvider
from agentwall.src.broker.providers.vault import VaultSTSProvider
from agentwall.src.broker.token_manager import EphemeralTokenBroker


@pytest.mark.asyncio
async def test_local_sts_token_minting_and_validation() -> None:
    provider = LocalMockSTSProvider()
    token = await provider.mint_token(
        agent_id="agent-finops-01",
        tool_name="execute_sql",
        target_audience="https://warehouse.data.internal",
        ttl_seconds=30,
    )

    assert token.bound_agent_id == "agent-finops-01"
    assert token.bound_tool_name == "execute_sql"
    assert token.target_audience == "https://warehouse.data.internal"
    assert token.ttl_seconds == 30
    assert token.is_expired() is False
    assert token.is_valid_for("https://warehouse.data.internal", "execute_sql") is True
    assert token.is_valid_for("https://other.data.internal", "execute_sql") is False

    is_valid = await provider.validate_token(token)
    assert is_valid is True


@pytest.mark.asyncio
async def test_token_broker_enforces_60_second_max_ttl() -> None:
    broker = EphemeralTokenBroker()
    # Attempt to request an overprivileged 1-hour token
    token = await broker.mint_ephemeral_token(
        agent_id="agent-sre",
        tool_name="run_shell_cmd",
        target_audience="https://node-diagnostics.internal",
        ttl_seconds=3600,
    )

    # Must be strictly clamped to <= 60 seconds
    assert token.ttl_seconds <= 60
    assert token.expires_at <= time.time() + 61


@pytest.mark.asyncio
async def test_gcp_and_vault_providers() -> None:
    gcp_provider = GCPSTSProvider()
    vault_provider = VaultSTSProvider()

    gcp_token = await gcp_provider.mint_token(
        agent_id="agent-gcp",
        tool_name="fetch_customer_record",
        target_audience="//crm.googleapis.com/customers",
        ttl_seconds=45,
    )
    assert gcp_token.access_token.startswith("ya29.c.agentwall_")
    assert await gcp_provider.validate_token(gcp_token) is True

    vault_token = await vault_provider.mint_token(
        agent_id="agent-vault",
        tool_name="run_shell_cmd",
        target_audience="https://vault.internal",
        ttl_seconds=15,
    )
    assert vault_token.access_token.startswith("hvs.CAES")
    assert await vault_provider.validate_token(vault_token) is True


@pytest.mark.asyncio
async def test_aws_azure_and_saas_providers_with_delegated_identity() -> None:
    aws_prov = AWSSTSProvider(account_id="999888777666")
    azure_prov = AzureSTSProvider(tenant_id="contoso-corp")
    saas_prov = SaaSTokenProvider()

    # 1. AWS STS
    aws_token = await aws_prov.mint_token(
        agent_id="agent-aws-s3",
        tool_name="read_s3_bucket",
        target_audience="arn:aws:s3:::customer-data",
        ttl_seconds=45,
        user_id="user-123",
        user_roles=["cloud_operator"],
    )
    assert aws_token.access_token.startswith("ASIA")
    assert aws_token.user_id == "user-123"
    assert "cloud_operator" in aws_token.user_roles
    assert await aws_prov.validate_token(aws_token) is True

    # 2. Azure Entra ID / Managed Identity
    az_token = await azure_prov.mint_token(
        agent_id="agent-az-data",
        tool_name="azure_blob_inspect",
        target_audience="https://management.azure.com",
        ttl_seconds=30,
        user_id="alice@contoso.com",
        user_roles=["cloud_operator", "admin"],
    )
    assert "agentwall_az_" in az_token.access_token
    assert az_token.user_id == "alice@contoso.com"
    assert await azure_prov.validate_token(az_token) is True

    # 3. SaaS Tokens (GitHub, Slack, Google Workspace)
    gh_token = await saas_prov.mint_token(
        agent_id="agent-coder",
        tool_name="github_read_issue",
        target_audience="https://api.github.com/repos/org/repo",
        ttl_seconds=30,
    )
    assert gh_token.access_token.startswith("ghs_")
    assert await saas_prov.validate_token(gh_token) is True

    slack_token = await saas_prov.mint_token(
        agent_id="agent-notify",
        tool_name="send_slack_message",
        target_audience="https://slack.com/api",
        ttl_seconds=30,
    )
    assert slack_token.access_token.startswith("xoxb-ephemeral-")
    assert await saas_prov.validate_token(slack_token) is True

    gsuite_token = await saas_prov.mint_token(
        agent_id="agent-mailer",
        tool_name="read_email",
        target_audience="https://gmail.googleapis.com",
        ttl_seconds=30,
    )
    assert gsuite_token.access_token.startswith("ya29.gsuite_obo_")
    assert await saas_prov.validate_token(gsuite_token) is True


@pytest.mark.asyncio
async def test_local_sts_has_no_shared_default_secret() -> None:
    """Two providers without an explicit secret must not accept each other's tokens."""
    minting = LocalMockSTSProvider()
    verifying = LocalMockSTSProvider()
    token = await minting.mint_token(agent_id="a", tool_name="t", target_audience="aud")
    assert await minting.validate_token(token) is True
    assert await verifying.validate_token(token) is False


@pytest.mark.asyncio
async def test_local_sts_explicit_secret_verifies_across_instances() -> None:
    token = await LocalMockSTSProvider(signing_secret=b"s" * 32).mint_token(
        agent_id="a", tool_name="t", target_audience="aud"
    )
    assert await LocalMockSTSProvider(signing_secret=b"s" * 32).validate_token(token) is True
