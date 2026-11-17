# Security policy

RedHand is a security product, so we want to hear about weaknesses in it.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Use GitHub's private vulnerability reporting: on the repository page choose **Security**, then **Report a vulnerability**. If that option is not available to you, open an issue that says only that you have a security report and how to reach you, with no details, and we will reply with a private channel.

Please include: what you found, where (file, route or component), the steps to reproduce, and what an attacker gains. A proof of concept is welcome; please keep it to your own test data.

What to expect: an acknowledgement within a few working days, a fix or a clear answer on whether we consider it in scope, and credit in the changelog if you want it. This is a young project run by a small team: there is no bug bounty.

## In scope
- The code in this repository: the gateway (`agentwall/`), the control plane (`services/redhand-core/`), the SDK and sidecar (`packages/`), the dashboard (`apps/redhand-ui/`) and the database migrations (`supabase/`).
- Authentication, authorization, tenant isolation, secret handling, the credential broker, the Prompt Injection Radar, and the revoke/freeze path.

## Out of scope, please do not test
- **Any hosted environment.** RedHand's staging services are private test systems; do not scan, probe or attack them. Run the code locally instead (see the README: core and gateway start in development mode with an in-memory store on your own machine).
- Social engineering, physical attacks, denial-of-service load tests, and anything that needs access to someone else's account.
- Findings that need a malicious operator who already holds the owner role, or a compromised deployment secret.

## Things that look like secrets but are not
This repository contains deliberately fake keys in tests, demos and the `battleground/` simulation (for example `sk_live_DEMODEMO…`, AWS's documented example key). They are listed, with a reason for each, in `.redhand-scan-baseline.json`, and CI fails on any new secret-looking value that is not on that list. Old commits contain earlier decoy values that looked like real keys; they are being treated as exposed and rotated regardless.

## Supported versions
There are no tagged releases yet; fixes go to `main`.

## How we check ourselves
Every build runs the test suite, a secret scan, a dependency audit, a sweep that attacks every route for missing authentication, wrong roles and other tenants' ids, and a revocation drill on real processes. See `docs/release-readiness.md` and `docs/security/threat-model.md`.
