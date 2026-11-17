"""
The tables that hold tenant data and the columns an export leaves out, as the in-memory twin sees them.

The database function `tenant_data_manifest()` (supabase/migrations/20261130000000_tenant_lifecycle.sql) is the real list. This copy exists only so the
development twin can export the same way; a test compares the two so they cannot drift.
"""

from __future__ import annotations

from typing import Final, Literal

Scope = Literal["org", "agent", "self", "members"]

MANIFEST: Final[tuple[tuple[str, Scope, tuple[str, ...]], ...]] = (
    ("organizations", "self", ("siem_webhook_url",)),
    ("organization_members", "members", ()),
    ("agents", "org", ()),
    ("agent_keys", "org", ("key_hash",)),
    ("agent_destinations", "org", ()),
    ("agent_budget_state", "agent", ()),
    ("agent_usage_daily", "org", ()),
    ("agent_model_daily", "org", ()),
    ("agent_tool_hourly", "org", ()),
    ("agent_events", "org", ()),
    ("event_batches", "org", ()),
    ("event_chain_heads", "org", ()),
    ("execution_traces", "org", ("ephemeral_token_jti",)),
    ("hitl_interventions", "org", ("notification_webhook_url", "resume_webhook_url")),
    ("security_events", "org", ()),
    ("security_findings", "org", ()),
    ("radar_suppressions", "org", ()),
    ("radar_rule_counts", "org", ()),
    ("radar_scan_counts", "org", ()),
    ("honeytokens", "org", ()),
    ("honey_tools", "org", ()),
    ("honeytrips", "org", ()),
    ("mcp_servers", "org", ()),
    ("mcp_tool_pins", "org", ()),
    ("approved_models", "org", ()),
    ("sdk_api_keys", "org", ("key_hash",)),
    ("telegram_links", "org", ()),
    ("telegram_link_codes", "org", ("code_hash",)),
    ("member_invites", "org", ("token_hash",)),
    ("control_audit_log", "org", ()),
)
