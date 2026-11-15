# M4.7b: baseline on the tuning set (before any rule change)

Measured 2026-11-13 with `scripts/radar_real_documents_fetch.py` against the rules whose fingerprint is `a7818a78351aa02e` (the rules as they were before M4.7b). Plan: `docs/plans/phase4-m4-7b-quieter-rules.md`. Split: `docs/security/m4-7b-split.md` (committed before this file and before any rule change).

Only names and counts are recorded here. The documents themselves live in an untracked folder outside the repository (decision P4-D10).

## What was measured
- The tuning set only (60 repositories). The text is each repository's DeepWiki answer from the public DeepWiki server, the same text the gateway sees through `read_wiki_contents`.
- **58 documents scanned, 2 unavailable** (`apple/swift`, `tensorflow/tensorflow`: DeepWiki did not return a document). An unavailable document is never counted as clean.
- Every document is assumed harmless, so any strong finding counts as a false alarm. All 58 are longer than 2 KiB.
- The Radar reads at most 16 KiB of a result: 8 KiB from the start and 8 KiB from the end when it is longer (`_collect` in `agentwall/src/firewall/radar.py`, tested by `test_a_huge_value_is_read_at_both_ends_but_not_in_the_middle`). The plan's step 4 ("replace the first 16 KiB with both ends") described a change that was already made; it is dropped from the scope of M4.7b.

## Result
| | flagged | strong | strong rate | 95% upper bound |
|---|---|---|---|---|
| hidden instructions (injection) | 26 | 16 | 27.6% | 40.2% |
| risky output | 4 | 3 | 5.2% | 14.1% |

17 of 58 documents (29.3%) had at least one strong finding.

Strong findings, by rule, as a number of documents:

| rule | documents | what it is |
|---|---|---|
| `RAD-INJ-003` | 13 | fake system or role marker |
| `RAD-INJ-005` | 5 | tells the agent to run a command |
| `RAD-OUT-007` | 3 | sensitive file or path escape |
| `RAD-INJ-002` | 2 | persona or mode change |
| `RAD-INJ-007` | 1 | asks to reveal something |

Repositories with a strong finding: TanStack/query, ansible/ansible, django/django, dotnet/aspnetcore, encode/httpx, flutter/flutter, gin-gonic/gin, git/git, home-assistant/core, moment/moment, ohmyzsh/ohmyzsh, openai/openai-python, prometheus/prometheus, tmux/tmux, traefik/traefik, vercel/next.js, vim/vim.

## What the tuning documents show (classes, not text)
- **`RAD-INJ-003`**: a plain documentation heading that starts with `system`, `admin`, `instruction` or `directive` (for example an architecture or overview section) is read as a marker, and the wrapper pattern fires on markdown links and diagram node labels because its keyword has no word boundary.
- **`RAD-INJ-005`**: diagram node labels that contain a function call, and a code-fence language tag after the word "run".
- **`RAD-OUT-007`**: `/root/` in the middle of a relative path, a bare prose mention of `.git/config`, and JavaScript relative imports counted as path traversal because depth was counted across the whole document.
- **Not in M4.7b's scope** (listed, not changed): `RAD-INJ-002` on the phrases "debug mode" and "maintenance mode" (2 documents) and `RAD-INJ-007` on a sentence about environment variables (1 document).

## Not yet measured
The frozen set. It is measured once, after the rules are final, by `count --set frozen --final`.
