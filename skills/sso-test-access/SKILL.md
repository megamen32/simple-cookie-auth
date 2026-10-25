---
name: sso-test-access
description: Safely sign in to authorized bezrabotnyi.com QA browser checks using the existing shared SSO test account and vaulted password, without exposing credentials.
---

Read the canonical [SSO QA runbook](../../docs/SSO-QA-ACCESS.md).
Use existing `testlogin` with SSS reference `sso.qa.admin-equivalent` and the
fixed stdin consumer at `../../scripts/sso-qa-fill.py`; never retrieve the
password into model context. The runbook contains the exact command and
browser ownership, verification and cleanup steps. Reuse this account; do not
create accounts, change roles or restart authentication for a login check.
This skill grants no additional authority for application actions.
