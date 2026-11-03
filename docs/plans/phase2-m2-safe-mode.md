# Phase 2 M2 plan: Safe Mode

**Status:** Approved 2026-11-03 (all three open decisions approved as recommended).
Design and rationale: `docs/adr/0009-safe-mode.md`.

**Goal:** an operator can put one agent, or the whole organization, into Safe Mode; the gateway then
allows only tools declared read. Phase 2 done test 2.

**Decisions taken:** new scopes default to write in the dashboard form (the API default is unchanged);
Safe Mode also filters `tools/list`; turning it off needs an admin and confirmation.

**Delivered:** migration `20261104000000_safe_mode` with rollback and SQL tests; core endpoints
(`POST /v1/passports/{id}/safe-mode`, `GET` and `POST /v1/organization/safe-mode`); the gateway check;
`/safemode on` in Telegram; dashboard controls; end-to-end test; benchmark.

**Evidence (local, 2026-11-03):** full suite and end-to-end tests pass; every protection was broken in
turn and made tests fail; benchmark warm p50 0.82 ms / p99 1.80 ms, cold p50 1.15 ms / p99 2.77 ms
(budget 10 ms / 50 ms), revocation 2.03 s.

**Not yet verified:** the migration and the new code on staging, the dashboard controls in a browser, a
real agent in Safe Mode against a real MCP server.
