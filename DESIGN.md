# Tez Adhikar — Access Control & Audit Service
**Nagarkot Forwarders Pvt. Ltd. (NFPL)**  
*Design document | “Right Access. Right Authority.”*

## 1. Purpose and design principles

Tez Adhikar centralizes authorization for shipment-processing jobs. A job belongs to one client, branch, direction (import/export), and mode (air, FCL, or LCL), and normally moves through **Confirmed → Prepared → Checked → Filed**. It may also enter controlled exception states such as Cancelled or Reopened.

The design follows **least privilege, deny by default, separation of duties (SoD), explicit scope, auditable changes, and revalidation at the time of action**. Reading a job and changing it are separate permissions. A role describes allowed actions; a grant assigns a role to a person for a defined scope and period. An administrator does not automatically receive shipment-processing authority.

The service is intended for Python 3.10+ with the standard library and SQLite. SQLite is suitable for this single-service assessment and its 500-user/200,000-job target when queries are indexed and paginated. It is not a substitute for a multi-writer distributed database or independently protected audit storage. Performance claims should be based on repeatable benchmarks rather than assumptions.

## 2. Model and key decisions

### Identity, roles, and grants
A user has an active/inactive status. A role contains named permissions such as `view_job`, `prepare`, `check`, `file`, `cancel_filed`, `reopen`, and `manage_access`. A grant connects a user to a role and records its scope, start/end validity, creator, and lifecycle. Scope dimensions are client, branch, direction, and mode. Use an explicit `ALL` value for an intentional wildcard; a missing or malformed dimension is not silently interpreted as unrestricted access. Explicit deny rules, where supported, take precedence over matching allows.

Typical roles include Maker, Checker, Filer, Supervisor, ClientViewer, AccessAdmin, Auditor, and a restricted parser service identity. These are policy examples; the effective permissions must come from the configured role and grant records.

### Authorization and workflow
For every protected request, validate the authenticated actor, active status, permission, grant validity, target-job scope, workflow transition, and applicable SoD restrictions. Re-check these conditions inside the transaction that performs the mutation so a stale earlier decision cannot authorize a later change. Return a structured decision with an allow/deny result and reason code; do not expose another client’s records through explanations, counts, or error messages.

The normal workflow permits only defined transitions. The preparer must not check or file the same job, even if they also hold a Checker or Supervisor role or act as a delegate. A filed job must not be edited through ordinary update paths. Cancelling or reopening a filed job is an exceptional workflow: require a scoped Supervisor request, a business reason, approval by a different eligible Supervisor, and a re-check of the job state and approval immediately before committing the transition. The approval must be authenticated and bound to the exact job, action, reason, requester, expected state, and expiry—not inferred from a caller-supplied approver ID.

### Persistence, audit, and history
Use SQLite transactions and foreign keys for related changes, with indexes on job scope/stage, grant lookup fields, and audit sequence. Use bounded pagination for large lists. Keep audit events append-only at the application layer and record actor, action, target, timestamp, reason, outcome, and relevant before/after identifiers without unnecessarily copying sensitive payloads.

A hash- or HMAC-chained audit ledger can reveal alteration of recorded events if verification is correct and the key is protected separately. It does not prevent a privileged attacker from deleting the database and key together, nor prove that every real-world event was recorded. Production deployment should back up the ledger, restrict key access, and export or replicate audit evidence to a separately controlled destination. Filing seals should cover a canonical representation of the filed data and be verified on read or before exceptional operations.

Historical queries must distinguish **who had authority** from **who actually acted**. Reconstructing past authority requires retained historical versions of users, roles, grants, delegations, and relevant job attributes. If the evidence is incomplete, report that limitation instead of presenting a definitive answer.

## 3. Answers to the design questions

**Q1. Should everyone see everything? How does visibility differ from authority?**  
No. Internal staff see jobs within their permitted client/branch scope; auditors may receive broader read-only access when justified. A ClientViewer sees only their own client’s approved shipment fields. `view_job` permits reading but never implies permission to prepare, check, file, cancel, or reopen.

**Q2. Maker for every client but Checker for a few; Checker limited to one branch and imports?**  
Represent each responsibility as a separate grant. For example, a Maker grant can explicitly cover all clients while a Checker grant covers only C01 and C02. Another Checker grant can be restricted to client C03, the Mumbai branch, and imports. Wildcards must be explicit, and each dimension must be checked against the job.

**Q3. What if the preparer is also qualified to approve?**  
Deny checking or filing when the authenticated actor is the recorded preparer. A second role or delegated permission does not override SoD. Record the denial with a clear reason code.

**Q4. What if the responsible person is absent?**  
An authorized Supervisor may delegate eligible authority to a qualified colleague for a defined scope and time window. A delegation cannot exceed the delegator’s authority, must be auditable, and must not permit sub-delegation unless policy explicitly allows it. The delegate remains subject to scope, expiry, workflow, explicit denies, and SoD.

**Q5. What happens to in-progress jobs when responsibilities change?**  
Re-evaluate access on every action. Close or expire superseded grants, invalidate affected credentials/sessions, and reassign outstanding work through an audited process. Preserve completed actions and their original actor attribution; do not rewrite history to make the new assignee appear to have performed earlier work.

**Q6. Who can cancel a filed job or reopen a closed one?**  
Only a scoped Supervisor may request the exception, with a meaningful reason and independent approval from another eligible Supervisor. Bind approval to the specific request and expire it. Re-check permissions and state in the same transaction as the transition. Preserve the original filing and record the exception as a new event.

**Q7. What if a client employee wants to follow shipments?**  
Give them a client-scoped, read-only role. Enforce the client boundary on details, lists, counts, audit views, and historical endpoints. Return only fields approved for client viewing; redact internal notes, margins, tariff commentary, and staff details where policy requires it.

**Q8. What if an admin must fix a stuck job or tries to escalate their own privileges?**  
Separate `manage_access` from shipment permissions. Do not let an AccessAdmin grant themselves authority or approve their own privilege increase. For emergencies, use a narrowly scoped, short-lived break-glass workflow with a reason, independent review, and complete audit. If those controls are unavailable, deny the exceptional mutation and use a documented manual recovery process.

**Q9. How should the overnight parser be treated?**  
Use a dedicated service identity and secret, not a shared human account. Limit it to required ingestion operations and permitted fields/stages. It must not manage users or grants, check/file jobs, reopen filed jobs, or alter audit records. Authenticate requests, validate input, rate-limit where appropriate, and audit its actions separately.

**Q10. How do you explain “why can she do this and he can’t?”**  
Evaluate both users against the same job and action, then return a side-by-side explanation: active grants, scope matches/mismatches, stage rule, explicit deny, SoD result, and final reason code. Apply the same visibility policy to the explanation so it cannot reveal a job or client to an unauthorized caller.

**Q11. How do you answer “who could have changed this job on the 3rd?”**  
Resolve the date, time, and timezone. Report separately (1) users whose historically recorded grants and role definitions permitted the action at that time and (2) audited events showing who actually performed recorded actions. Exclude events recorded after the historical cutoff when reconstructing what the system knew then. State when retained evidence is insufficient.

**Q12. How can a new role be introduced while engineering is busy?**  
Store role definitions as validated data, with a fixed vocabulary of supported permissions. An authorized administrator proposes the role, reviews its scope and impact, obtains required approval, and activates it through a controlled workflow. Do not allow arbitrary permission strings or use “no-code” role creation to bypass privilege checks. Changes should be audited and covered by regression tests.

**Q13. How can “jobs waiting for me” match what a person can actually do?**  
Use the same policy semantics for authorization, queues, and counts. If SQL is used to filter lists, test it against the authorization evaluator for scope, grant validity, stage, denies, and SoD. Apply pagination after policy filtering or prove the filtering order is equivalent. Test parity with deterministic edge cases and randomized comparisons.

**Q14. What should happen when the system is unsure?**  
Fail closed for protected actions. Missing identity, invalid policy, unavailable database, missing audit key, or indeterminate state must never become an allow. Return a safe error/denial and log it where possible. If a required audit write cannot be committed, do not commit the sensitive mutation unless a documented policy explicitly defines a safe alternative.

**Q15. How should access be revoked when an employee leaves or changes roles?**  
Deactivate the account, revoke grants and delegations, invalidate credentials/sessions, and prevent new actions immediately. Reassign open work through an audited process while preserving past actor attribution. Make offboarding idempotent and test retries, partial failures, and stale sessions.

**Q16. What if a delegate is also the preparer?**  
Evaluate SoD against the real authenticated actor, not the delegator’s identity. If the delegate prepared the job, deny their check/file action even when the delegation otherwise grants the necessary role. Delegation never overrides SoD or explicit denies.

**Q17. What if two people act at the same time or a request uses stale state?**  
Perform the final authorization and state-transition check within a database transaction. Use a conditional update or version/state check so only one valid transition wins. If another request changes the job first, reject the stale request and require the caller to refresh; never silently apply an action to a different state.

**Q18. What if someone tampers with or deletes audit records, replays a request, or the key is lost?**  
Verify the ledger chain and filing seal, alert on sequence gaps or mismatches, and keep protected backups or an independently controlled audit copy. Use unique request/approval identifiers and expiry to prevent replay of sensitive approvals. Rotate and back up keys under controlled access. If a required verification key is unavailable, report verification as unavailable and deny operations that depend on it; do not claim the ledger is verified.

**Q19. What if authorization, the database, or audit storage fails?**  
Fail closed for protected operations and return a clear operational error without exposing secrets. Use transactions so a state change and its required audit event either both commit or neither commits. Provide health checks and recovery procedures; do not fall back to permissive cached decisions or unaudited writes.

**Q20. How will correctness and performance be maintained as the system grows?**  
Add indexes based on measured query plans, use bounded/keyset pagination, and avoid loading all jobs into memory. Benchmark realistic datasets near 500 users and 200,000 jobs, including worst-case scope filters and counts. Test access boundaries, transition invariants, SoD, offboarding, audit verification, concurrency, and list/count parity. Treat performance numbers as measured results tied to the test environment, not universal guarantees.

## 4. Trade-offs and scope

- **SQLite and a single service:** simple to run and inspect for this assessment; concurrency and deployment needs should be reassessed before multi-instance production use.
- **Data-driven roles:** faster to extend, but role edits require validation, approval, audit, and tests.
- **HMAC-chained audit:** efficient tamper evidence when the secret is protected; it is not a digital signature and cannot independently prove completeness.
- **Fail-closed behavior:** protects integrity but may temporarily block work during an outage; documented recovery and monitoring are therefore necessary.
- **Historical reconstruction:** useful only to the extent that versions and events were retained accurately.
- **Security boundary:** authorization must be enforced server-side on every endpoint; hiding UI controls is not an access-control mechanism.

The implementation should be judged against automated tests and the actual running service. Features described here are design requirements unless verified in code; do not represent a control as implemented merely because it is documented.
