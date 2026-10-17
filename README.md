# Tez Adhikar --- Access Control & Audit Service

**Right Access. Right Authority.**

A centralized authorization service that ensures every user can perform
only the actions permitted by their role, scope, and a shipment's
current state.

-   **Live demo:** https://tez-adhikar.onrender.com/
-   **Source code:** https://github.com/Sreehari35/Tez-Adhikar
-   **Runtime:** Python 3.10+; Python standard library only
-   **Storage:** SQLite in WAL mode
-   **Dependencies:** No third-party pip packages required for the core
    service


## Quick start

Run these commands from the repository root in **PowerShell**.

### 1. Configure demo secrets

Use unique local demo values. Do not reuse personal passwords or
production secrets.

``` powershell
$env:NAGARKOT_DEMO_PASSWORD = 'choose-a-unique-demo-password'
$env:NAGARKOT_PARSER_API_KEY = 'replace-with-a-long-random-parser-key'
```

### 2. Initialize the demo database

``` powershell
python -m app.seed
```

This initializes the SQLite database and seeds sample branches, clients,
staff, jobs, and initial HMAC ledger events.

### 3. Start the HTTP service

``` powershell
python -m app.cli serve --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000/ in your browser.

To start the server using the module entry point instead, check the
current `app.server` configuration and use `python -m app.server`.

## Architecture at a glance

``` mermaid
flowchart TD
    U[User / Client / Service] --> API[HTTP API]
    API --> AUTH[Authentication and identity checks]
    AUTH --> POLICY[Authorization engine]
    POLICY --> SCOPE[Role, scope, workflow state and SoD checks]
    SCOPE --> DECISION{Allow or deny}
    DECISION -->|Allow| ACTION[Execute permitted operation]
    DECISION -->|Deny| REJECT[Reject request]
    ACTION --> DB[(SQLite database)]
    ACTION --> LEDGER[HMAC audit ledger]
    DB --> VERIFY[Ledger and filed-job integrity verification]
    LEDGER --> VERIFY
    POLICY --> EXPLAIN[Authorization explanation]
```

The authorization decision should be enforced by the server on every
protected operation. Hiding a button in the browser is not an
authorization control.

## Core capabilities

-   **Role- and scope-based authorization:** permissions can be
    constrained by client, branch, direction, mode, and action.
-   **Workflow-state enforcement:** actions are checked against a
    shipment's current lifecycle stage.
-   **Separation of duties (SoD):** a user cannot approve or file work
    they prepared where the rule prohibits it.
-   **Delegation:** time-bounded supervisor delegation with no
    delegation chaining.
-   **Two-person administrative approval:** grant changes are proposed
    by one AccessAdmin and approved by a distinct AccessAdmin.
-   **Sensitive filed-job operations:** cancellation or reopening
    requires a persisted request and a distinct eligible Supervisor's
    approval.
-   **HMAC audit ledger:** chained event authentication supports tamper
    detection.
-   **Filed-job seals:** detects out-of-band edits to filed shipment
    records.
-   **Authorization explainer:** compares why one user is allowed and
    another is denied.
-   **Forensic replay:** reconstructs authority at a historical point in
    time.
-   **Fail-closed behavior:** indeterminate authorization outcomes
    should be denied.

## Sample data

The standard seed is documented to create:

-   5 branches: Mumbai, Delhi, Chennai, Kolkata, Ahmedabad
-   10 corporate clients
-   20 sample staff identities
-   Approximately 300 customs jobs

These are demonstration records, not real customer data. Demo identities
and credentials must be treated as non-production.

## API quick reference

The following endpoints are documented by the project. Use the exact
authentication/session requirements implemented by the current server;
do not assume an endpoint is safe to expose anonymously.

  ------------------------------------------------------------------------------------------
  Method                  Endpoint                                   Purpose
  ----------------------- ------------------------------------------ -----------------------
  `POST`                  `/authorize`                               Evaluate an
                                                                     authorization request
                                                                     and return a decision
                                                                     receipt

  `GET`                   `/explain?user=A&other=B&action=X&job=J`   Compare two users'
                                                                     authorization outcomes

  `GET`                   `/jobs/waiting?user=U`                     List jobs awaiting a
                                                                     user's action

  `GET`                   `/jobs?limit=50&after=ID`                  Paginated shipment
                                                                     listing

  `POST`                  `/jobs`                                    Create a job in the
                                                                     Confirmed stage

  `POST`                  `/jobs/{id}/action`                        Request a workflow
                                                                     transition

  `POST`                  `/grants`                                  Submit an
                                                                     administrative grant
                                                                     proposal

  `POST`                  `/grant-proposals/{proposal_id}/approve`   Approve a grant
                                                                     proposal as a distinct
                                                                     AccessAdmin

  `POST`                  `/grants/{id}/revoke`                      Revoke a grant

  `POST`                  `/delegations`                             Create a time-bounded
                                                                     supervisor delegation

  `POST`                  `/jobs/{id}/sensitive-requests`            Request a sensitive
                                                                     operation on a Filed
                                                                     job

  `POST`                  `/sensitive-requests/{id}/approve`         Approve a sensitive
                                                                     request

  `POST`                  `/sensitive-requests/{id}/execute`         Execute an approved
                                                                     sensitive request

  `POST`                  `/breakglass`                              Initiate emergency
                                                                     break-glass access

  `GET`                   `/audit/job/{id}`                          Retrieve a job's audit
                                                                     history

  `GET`                   `/audit/verify`                            Verify the HMAC audit
                                                                     ledger
  ------------------------------------------------------------------------------------------

### Example: authorization request

For a local server, the documented request shape is:

``` bash
curl -X POST http://127.0.0.1:8000/authorize \
  -H "Content-Type: application/json" \
  -d '{"actor_id":"u_asha","action":"prepare","job_id":"JOB_0001"}'
```

If authentication is required by the deployed configuration, include the
required session or authorization credentials. Do not add credentials to
source code or publish them in examples.

### Sensitive approval workflows

Administrative grant changes are asynchronous:

1.  An authenticated AccessAdmin submits `POST /grants`.
2.  A different authenticated AccessAdmin approves through
    `POST /grant-proposals/{proposal_id}/approve`.
3.  The approval identity is derived from the authenticated request, not
    from a caller-supplied approver ID.

For cancellation or reopening of a Filed job:

1.  Request the action at `POST /jobs/{id}/sensitive-requests` with an
    action and reason.
2.  A distinct eligible Supervisor approves it.
3.  The original requester executes the approved request.

The persisted request is documented to bind the job, action, requester,
expected stage, reason, expiry, and approval.

## Test and verification commands

Run these commands from the repository root.

### Automated tests

``` powershell
python -m unittest discover -s tests
```

The README describes tests for SoD, delegation, responsibility changes,
sensitive filed-job operations, administrative self-escalation, parser
restrictions, client-field redaction, ledger tampering, job-seal
tampering, historical replay, predicate equivalence, and fail-closed
behavior.

**Report the actual result from your current checkout.** Do not claim
that tests pass unless you ran them successfully.

### Verify the audit ledger

``` powershell
python -m app.cli verify
```

### Verify filed-job seals

``` powershell
python -m app.cli verify-jobs
```

### Explain an authorization decision

``` powershell
python -m app.cli explain --user u_asha --other u_ravi --action check --job JOB_0051
```

### Replay historical authority

``` powershell
python -m app.cli who-could-change --job JOB_0051 --at 2026-03-01T00:00:00Z
```

### Generate scale data and benchmark

Configure the two environment variables shown in Quick Start, then run:

``` powershell
python -m app.seed --scale
python -m app.bench
```

The scale seed is documented for 500 users and 200,000 jobs. Benchmark
results depend on the host; use only the measurements emitted by the
machine on which you ran the benchmark.

## Render deployment notes

The live demo is at https://tez-adhikar.onrender.com/.

For a Render Python Web Service, the service must bind to `0.0.0.0` and
use Render's assigned `$PORT`. The CLI supports `--host` and `--port`,
so the intended start command is:

``` bash
python -m app.seed && python -m app.cli serve --host 0.0.0.0 --port $PORT
```

Configure these environment variables in Render's Environment settings:

-   `NAGARKOT_DEMO_PASSWORD`
-   `NAGARKOT_PARSER_API_KEY`

Generate separate, strong values and keep them out of Git. The seed
command intentionally refuses to run when these variables are missing.

**Persistence warning:** Render free web services do not provide
persistent disks. SQLite data stored on the instance filesystem can be
lost on restart or redeploy. Do not rely on this free deployment for
durable records. Also verify that seeding on each start will not
overwrite or reset important data before using the command in a live
service.

## Security and submission checklist

-   [ ] Replace unsafe dynamic `innerHTML` rendering with safe DOM APIs
    or context-aware sanitization.
-   [ ] Complete and test the authenticated browser login/logout
    workflow.
-   [ ] Verify authorization server-side on every protected endpoint.
-   [ ] Confirm unauthenticated and insufficiently privileged requests
    are denied.
-   [ ] Confirm secrets, generated databases, caches, and private key
    files are excluded from Git.
-   [ ] Verify demo credentials and parser API keys are not exposed in
    public files, browser responses, or logs.
-   [ ] Run the automated test suite and record the real result.
-   [ ] Test persistence and restart behavior on the target hosting
    platform.
-   [ ] Document any known limitations honestly before submission.

## Repository layout

``` text
Tez-Adhikar/
├── app/        # Service, authorization logic, CLI, seed and benchmark modules
├── tests/      # Automated tests
├── README.md   # Project documentation
├── DESIGN.md   # Design decisions and architecture details
└── CHANGELOG.md
```

See the source repository for the current implementation:
https://github.com/Sreehari35/Tez-Adhikar.
