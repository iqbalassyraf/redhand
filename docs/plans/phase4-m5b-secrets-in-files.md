# Plan: Phase 4 M5b, `redhand scan` finds secrets in prompt and config files

**Status:** APPROVED by the owner (2026-11-12) with both recommended answers (scan `.py` files too; skip only the AWS documentation example). **BUILT** on branch `feat/phase4-m5b-secrets-in-files` (PR pending). Differences from this plan: section 10. Part of `docs/plans/phase4-finish-plan.md` (milestone M5b, done test 8). Local-only: no staging test, no deploy, no gateway or core change.

## 1. Goal
A developer runs `redhand scan <folder>` and is told **which file and line** holds a credential pasted into a prompt or config file (an API key in a `.env`, a key in a system-prompt text file, a private key in a YAML), and **what kind** it is, without the tool ever printing, storing or exporting the value.

## 2. Current state (checked 2026-11-12)
- `redhand scan` (`packages/redhand-sdk/src/redhand_sdk/cli.py`, `scanner/ast_checker.py`) reads **Python files only** and reports three agent-code rules (`RH-SEC-001` to `003`) as `ScanFinding(rule_id, rule_name, severity, file_path, line_number, tool_name, message)`. It prints each finding, can export SARIF 2.1.0 (`scanner/sarif.py`), and with `--strict` exits 1 on any `error`.
- The gateway already finds secrets in **tool results**: `EgressTaintGuardrail.PATTERNS` in `agentwall/src/firewall/ast_guardrails.py` has seven patterns (OpenAI key `sk-...`, Anthropic key `sk-ant-...`, AWS key id, GCP bearer `ya29.`, private key header, the cloud metadata address, three exfiltration webhook hosts). `agentwall/bench/corpus/secret_leak.jsonl` is the labelled corpus for it, with a baseline in `agentwall/bench/baseline.json`.
- The SDK is installed on its own by customers (`pip install redhand-sdk`), so it **must not import `agentwall`** (decided in the finish plan).
- Gap: nothing looks for a credential sitting in a prompt or config file **before** it is deployed. Done test 8 asks for exactly that.

## 3. Approach
- **New module** `packages/redhand-sdk/src/redhand_sdk/scanner/secrets.py`: a small pattern table (name, regex) copied from `EgressTaintGuardrail.PATTERNS` for the secret kinds (OpenAI key, Anthropic key, AWS key id, GCP bearer, private key header). The metadata address and the webhook hosts are exfiltration targets, not secrets, so they stay in the gateway's list and are not reported as secrets here. Matching is line by line.
- **The value is never held in a finding.** A new `SecretFinding` has **no field for the matched text**: only file, line, secret type and a fixed message per type ("A private key appears in this file."). It cannot leak a value by accident, because there is nowhere to put it. Console output, SARIF `message`, exceptions and logs are built only from those fields. SARIF gets no snippet and no hash of the value.
- **Rule id:** `RH-SEC-004` ("Secret in a prompt or config file"), severity `error` so `--strict` fails a CI job that finds one. The type name goes in the message.
- **Which files:** `.env` and `.env.*`, `.yaml`, `.yml`, `.json`, `.toml`, `.md`, `.txt` (the plan's list). Python files keep the existing AST scan only (see open question 1).
- **Bounds (all new, all stated in the help text):**
  - a file over **1 MiB** is skipped and counted ("1 file skipped: too large"), never partly read;
  - **symlinks are not followed** (a link out of the folder could read anything on the machine);
  - the directories `.git`, `node_modules` and `.venv` are skipped (plus `__pycache__`);
  - a file with a NUL byte in its first 8 KiB is treated as binary and skipped;
  - at most **5,000 files** per run and **50 findings per file**, with a visible "stopped at the limit" line, so work and output are bounded.
- **`redhand scan` flow:** the existing Python scan is unchanged. The secrets pass runs after it on the same folder (or on one file if a file path is given) and its findings are added to the same list, printing and SARIF. A summary line says how many files were read, skipped and why.
- **Patterns stay in step with the gateway:** a test in `agentwall/tests` (the only place both packages are visible) compares the SDK table's names and regexes with `EgressTaintGuardrail.PATTERNS` for the shared kinds and fails if they differ. The SDK itself still imports nothing from `agentwall`.
- **Measured on the corpus:** a test runs the SDK matcher over the positive and negative samples of `secret_leak.jsonl` and reports found and false-alarm counts next to the gateway guardrail's, so any difference is visible. No figure is claimed beyond that corpus.

**Alternatives considered**
1. *Import the guardrail from `agentwall`.* Makes the SDK unusable on its own. Rejected (already decided).
2. *Entropy-based detection (flag any long random string).* Many false alarms on hashes, ids and lockfiles, and no clear "type" to report. Rejected for now; limits are stated instead.
3. *Run a third-party scanner (gitleaks, trufflehog).* New dependency or tool with its own rules and licence, and we could not guarantee it never prints the value. Rejected.
4. *Print a masked value (first and last characters).* Even a fragment helps an attacker who sees a CI log. Rejected: no part of the value is ever printed.

## 4. Changes
- New: `scanner/secrets.py`, tests in `packages/redhand-sdk/tests/test_secrets_scan.py`, `agentwall/tests/test_sdk_secret_patterns_in_sync.py`.
- Modified: `scanner/ast_checker.py` or `cli.py` (call the secrets pass, add the rule to the rule list), `scanner/sarif.py` (the new rule's name; no new fields), the CLI help text.
- Docs: `docs/runbooks/` (a short "scan for secrets in prompts and config files" runbook), `docs/security/threat-model.md` (one row), `docs/security/coverage-matrix.md` wording only if the Coverage page lists secrets in prompts (LLM02/LLM07), `CHANGELOG.md`, `docs/handoff.md`.
- **No change** to the gateway, core, the database, the API, the dashboard or any dependency.

## 5. Security impact
- **New data handled:** the content of local files, in memory, line by line, on the developer's machine. Nothing is sent anywhere: the scan makes no network call.
- **Secrets never leave the scanner:** the value is not in the finding type, the console, the SARIF file, exceptions or logs. Errors name the file and the reason only (for example "could not read this file: permission denied"). A test searches every output (stdout, stderr, SARIF, exception text) for a planted value and fails if any part of it appears.
- **Fails safe:** an unreadable or oversize file is reported as skipped, never silently ignored, and the exit code with `--strict` does not hide it (skipped files are listed; a finding still returns 1).
- **Hostile folders:** a repository can contain symlinks to `/etc` or huge files. Symlinks are not followed, files are capped at 1 MiB, the number of files and findings is capped, and the regexes are linear (no nested quantifiers; a test runs them on a 1 MiB line of repeated characters inside a time limit).
- **Claims discipline:** the help text and the runbook say what it cannot do: it finds only the listed formats, not passwords, database URLs or custom tokens; it reads only the listed file types; and a clean result does not prove the repository has no secret. It does not say anything about protection outside the files it read.
- **A found secret is still a real secret:** the output tells the developer to rotate it. The runbook says so, because deleting the line does not remove it from git history.

## 6. Data and migrations
None.

## 7. Tests
- **Failing first:** one planted secret of each kind in each file type is found at the right line and type.
- **Value never printed:** for each kind, a planted value is searched for in stdout, stderr, the SARIF text and any exception raised. None of it appears, not even a few characters.
- **Negative and abuse cases:** a symlink to a file with a secret is not followed; a 1 MiB + 1 byte file is skipped and counted; a binary file is skipped; `.git`, `node_modules` and `.venv` are not read; 5,001 files stop at the limit with the message; 51 secrets in one file report 50 and say so; a file with no read permission is reported, not crashed on; a 1 MiB single line of repeated characters finishes inside a time limit.
- **No false alarm on documented examples we choose to allow:** the corpus negatives and ordinary text (a UUID, a git hash, a base64 image) do not match. The AWS documentation example key is a known question (open question 2).
- **`--strict`:** exit 1 with a secret, 0 without, and unchanged for the Python findings.
- **Pattern sync test** (section 3) and the **corpus measurement**.
- **Mutation checks:** put the value into the finding message, follow symlinks, remove the size cap, remove the finding cap, drop one pattern from the table. Each must be caught.
- **Full suite, ruff 0.17.3, mypy 2.4.1** as in CI. Existing scanner tests stay unchanged and green.

## 8. Cost and performance
No hot path, no network, no running cost, no dependency. A scan reads at most 5,000 files of at most 1 MiB each (about 5 GB in the extreme, so the file cap is the real limit); a normal repository takes a moment. Measured once on this repository and reported.

## 9. Risks and open questions
1. **Python files (owner).** System prompts often live in Python strings. Recommendation: also run the secrets pass over `.py` files (read as text, not parsed), because that is where many prompts are, and say so. Cost: more flags from test fixtures and examples. If you prefer, keep it to the listed file types for now.
2. **Documented example keys.** Our own tests and many docs use fake keys such as the AWS documentation example. Recommendation: skip a short list of well-known documentation examples (AWS `AKIAIOSFODNN7EXAMPLE` only), no other exemptions, and no inline "ignore" comment yet (an ignore marker would let a real secret be hidden). Agree?
3. **The SARIF `helpUri`** in `scanner/sarif.py` points at `https://docs.redhand.security/rules/...`. I have not checked that this address exists. If it does not, a claim in our own output is wrong. Not part of this change; it should be checked and fixed separately.
4. **Not measured:** how common the listed formats are in real prompt files. The corpus measurement only shows the pattern behaviour, not real-world recall.
5. **Size:** medium. One PR, branch `feat/phase4-m5b-secrets-in-files`.

## 10. Differences from the plan, found while building
- **The SDK patterns are not exact copies of the gateway's.** The gateway's `sk-` pattern matches anywhere, so "risk-assessment-and-mitigation" looks like an OpenAI key and would flag ordinary Markdown and YAML. The SDK adds a word-boundary guard in front of the OpenAI, Anthropic and Google patterns, and its AWS pattern needs a whole 20-character key id (the gateway's has an alternative, `A3T` plus one character, that matches only four characters). `agentwall/tests/test_sdk_secret_patterns_in_sync.py` states exactly this (the guarded patterns must equal the guard plus the gateway's pattern; the others must be identical).
- **Found, not fixed (out of scope): the gateway's AWS pattern** (`EgressTaintGuardrail`, `agentwall/src/firewall/ast_guardrails.py`) has that four-character alternative, so it can redact harmless text such as `A3TX` in a tool result. It needs its own small fix and test.
- **An Anthropic key is labelled `ANTHROPIC_KEY` by the SDK and `OPENAI_KEY` by the gateway** (the gateway's OpenAI pattern runs first and consumes it). The verdict, found or not, is the same on every corpus sample.
- **The old clean-scan message was replaced.** "Zero vulnerabilities found! All agent tools guarded..." would now also imply "no secrets", so it says what was checked and that it is not a guarantee.
- **`secrets.py` is added to the strict mypy list** in `pyproject.toml`.
- **Measured on the corpus:** the SDK finds 8 of the 20 malicious `secret_leak` samples and flags 0 of 20 harmless ones; the gateway guardrail finds 9 (the extra one is the AWS documentation example the SDK skips on purpose). The other 12 malicious samples are not in a secret format either matcher knows (addresses, webhook hosts, other credential forms).
- **Measured on this repository:** `redhand scan .` read 413 files in about 1.4 s and skipped one (a 2 MiB model file). It flagged 17 lines, all in tests, mock token generators, a demo script and the `battleground` demo database. One in `battleground/database/db.py` (an OpenAI-style value) could not be confirmed fake from here; the owner should look at it.
