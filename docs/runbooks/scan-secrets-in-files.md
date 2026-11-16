# Runbook: find secrets pasted into prompt and config files (`redhand scan`)

**Product truth:** this is a local check on files you point it at, before they are deployed. It makes no network call and sends nothing to RedHand.
It says nothing about secrets anywhere else (chat, a database, a running agent, a file type it does not read).

## Use it
1. Install the SDK (`pip install redhand-sdk`) and run `redhand scan <folder>` (or one file). Add `--strict` in CI to fail the job when a secret is found,
   and `--sarif <path>` to export the report for GitHub or GitLab code scanning.
2. Read the report. For each secret it prints the **file, the line and the kind** (Anthropic key, OpenAI-style key, AWS access key id, Google Cloud token,
   private key). **It never prints the value**, not even part of it, and neither does the SARIF file.
3. **Rotate the secret.** Deleting the line is not enough: git history and any copy of the file keep it.
4. The summary line says how many files were read and how many were skipped and why. Check it: a skipped file was not scanned.

## What it reads and finds
- Reads `.env`, `.env.*`, `.yaml`, `.yml`, `.json`, `.toml`, `.md`, `.txt` and `.py` files (a single file you name is read whatever its type).
- Finds only these formats: Anthropic keys, OpenAI-style keys (`sk-...`), AWS access key ids (the whole 20-character id), Google Cloud access tokens
  (`ya29.`), and private key headers. They are matched at a word boundary, so a word like "risk-assessment-and-mitigation" is not a key.
- Skips the AWS documentation example key (`AKIAIOSFODNN7EXAMPLE`) and nothing else. There is no inline "ignore" comment on purpose: it would let a real
  secret be hidden. If a test file holds a fake key that is flagged, build the fake from pieces in the test, or keep it out of the scanned folder.

## Limits worth knowing
- **A clean result is not a guarantee.** It does not find passwords, database URLs, custom tokens, keys in other formats, or secrets that are encoded,
  split over lines or kept in a file type it does not read.
- Bounded on purpose: files over 1 MiB, binary files, symlinks and the folders `.git`, `node_modules`, `.venv` and `__pycache__` are skipped; at most
  5,000 files are read per run (the report says "Stopped at the limit" if it hit that); at most 50 findings are reported per file.
- The patterns are copies of the gateway's secret patterns (`EgressTaintGuardrail`), kept in step by a test. They are not the same: the SDK matches at a
  word boundary and needs a whole AWS key id.
- Measured only on our own labelled `secret_leak` samples (`agentwall/bench/corpus/secret_leak.jsonl`): the SDK finds the same samples as the gateway
  guardrail, except the AWS documentation example it skips on purpose. Nothing is measured on real prompt files.

## If it flags something that is not a secret
A test fixture, a mock token generator or a demo seed will be flagged if its value looks like a real format. Check the line. If it is a fake, build it from
pieces (`"sk-" + "x" * 24`) so the file no longer holds a literal key, or keep that file out of the scanned folder. Do not paste the value into a ticket or chat.

## The baseline and the CI gate
CI runs `redhand scan . --strict --baseline .redhand-scan-baseline.json` on every push and pull request. The repository holds deliberate fake keys (test fixtures, demos),
and the scanner has no inline "ignore" marker, so the accepted findings live in one reviewed file instead.
- **An entry** is a file, a rule (`RH-SEC-004` secrets, `RH-SEC-003` Python tool rule), the SHA-256 of the offending line (trimmed), a count and a **reason** (10 to 300
  characters, never a TODO). It never holds the secret text. The line number is not part of it, so moving code is fine; changing the line is not.
- **A new finding fails the job.** So does an entry that no longer matches anything (the code changed or was deleted): remove or reduce it, so the list only shrinks.
- **A missing, oversized or invalid baseline exits 2** (fail closed). `redhand scan` run from the repository root with path `.` is what the entries are written for.
- **Adding an entry** is a reviewed change: `redhand scan . --emit-baseline new.json` writes entries (never overwriting a file) with a TODO reason the loader refuses; replace each
  reason with why the value is safe, then merge them into `.redhand-scan-baseline.json`. **Never baseline a real secret: rotate it.**
- **Limits:** the scan finds only the formats listed above, in the file types listed above. The baseline hash proves a line is unchanged, not that it is harmless: the reason is
  a person's statement. A clean gate is not proof that no secret exists, and git history is not scanned here (see `docs/release-readiness.md`, section 3.1).
