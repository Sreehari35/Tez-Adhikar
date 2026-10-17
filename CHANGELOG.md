# Security remediation changelog

- Direct role creation bypass: `AccessService.create_role` now authorizes the caller and validates role names, descriptions, and permission lists.
- Malformed grant scopes: `AccessService.create_grant` validates effect, dimensions, values, target user, and active role.
- Reusable credentials: `app.seed` requires `NAGARKOT_DEMO_PASSWORD` and `NAGARKOT_PARSER_API_KEY`; no sample password/API key is embedded in source.
- Login abuse: `app.auth` applies a five-attempt, 60-second per-username in-memory rate limiter.
- Filing evidence loss: `filed_job_seals` now records immutable cycles and filing code no longer uses `INSERT OR REPLACE`.
- Packaging hygiene: `.gitignore` excludes SQLite state, signing key files, Python caches, logs, and submission ZIPs.

See `ACCEPTANCE_REPORT.md` for unresolved critical controls.
