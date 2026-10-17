# Tez Adhikar — Access Control & Audit Service
> **Tagline**: Right Access. Right Authority.  
> **Full Title**: Tez Adhikar — Access Control & Audit Service  
> **Short Description**: A centralized authorization service that ensures every user can perform only the actions permitted by their role, scope, and the shipment's current state.


---

## 1. Quick Start

Run this single command from the project root:

```bash
$env:NAGARKOT_DEMO_PASSWORD='<Enter a demo password>'
$env:NAGARKOT_PARSER_API_KEY='choose-a-long-random-parser-key'
python -m app.seed
python -m app.server
```

The service will:
1. Initialize the SQLite database in WAL mode with tuned composite indexes.
2. Seed the 5 branches, 10 corporate clients, 20 deliberate staff members, and ~300 customs jobs with HMAC ledger events.
3. Launch the HTTP service daemon at **`http://127.0.0.1:8000/`**.

The seed command deliberately refuses to run without both variables. They are
demo inputs, not bundled credentials; do not reuse them in production.

Open `http://127.0.0.1:8000/shipments` and sign in with a seeded username and
the demo password supplied to `NAGARKOT_DEMO_PASSWORD`. Shipment data is
permission-scoped; client accounts see only their own client data.

## Submission status

**NOT READY FOR SUBMISSION.** The implementation has authenticated API routes,
session revocation, scoped job reads, and tamper checks, but the browser console
still has dynamic `innerHTML` paths and lacks a completed authenticated browser
workflow. Those are critical requirements and must be completed before
production or assignment submission.

## Sensitive approval API

Administrative grants are now intentionally asynchronous. An authenticated
AccessAdmin submits `POST /grants`; it creates a pending proposal and **does not
change effective access**. A different authenticated AccessAdmin then calls
`POST /grant-proposals/{proposal_id}/approve`. The request body never supplies
an approver identity.

For a Filed job, direct `POST /jobs/{id}/action` cancellation/reopening is
rejected even if it contains `second_approver_id`. Use these authenticated
operations instead:

1. `POST /jobs/{id}/sensitive-requests` with `action` and `reason`.
2. A distinct eligible Supervisor calls `POST /sensitive-requests/{id}/approve`.
3. The original requester calls `POST /sensitive-requests/{id}/execute`.

The persisted request binds the job, action, requester, expected `Filed`
stage, reason, expiry, and approval. Execution consumes it atomically.

---

## 2. Multi-Page Web Console (Easy to Understand)

Tez Adhikar features a modern, clean light-theme multi-page web console designed with the corporate color palette of [Nagarkot Forwarders](https://nagarkot.co.in/) (`#0B3056` Navy, `#00A3E0` Ocean Blue, `#F8FAFC` Light Slate).

Navigate across dedicated pages via the sticky top bar:

| Page | Route | What You Can Do Here |
| :--- | :--- | :--- |
| **Home / Overview** | `/` | High-level system KPIs, overview cards, and the **Real-Time Authorization Engine & Simulator** with 4 one-click preset scenarios (Asha vs Ravi, Client User restrictions, Admin SoD). |
| **Shipments Explorer** | `/shipments` | Search and browse all customs clearance shipments with stage filters, branch slices, client toggles, and keyset pagination. Includes direct links to each shipment's audit log. |
| **"Jobs Waiting for Me"** | `/waiting` | Select any employee from a dropdown to immediately see the shipments awaiting their action. Advance workflow stages (`PREPARE`, `CHECK`, `FILE`) with **1-click execution** that updates the job and appends to the audit ledger. |
| **Job Audit & Lifecycle Log** | `/logs` | **Complete timeline for any job** (`JOB_0051`, `JOB_0001`, etc.). Shows who created it, who accessed it, who modified it, all reason codes, and highlighted security incidents. Includes live access testing directly on the job! |
| **Staff Access Directory** | `/staff` | Plain-English access rules for all 20 employees across 5 branches, plus the interactive **"Why A Can & B Can't"** side-by-side comparative explainer. |

---

## 3. Key Constraints & Design Principles

- **Python Standard Library ONLY**: Built entirely with Python 3.10+ standard libraries (`http.server`, `sqlite3`, `hmac`, `hashlib`, `json`, `argparse`, `unittest`, `ctypes`). **Zero pip packages, zero Docker required**.
- **Scale target**: 500 users and 200,000 jobs. Run `python -m app.bench` on the target machine and retain its emitted report; no machine-specific performance result is claimed in this repository.
- **SQLite in WAL Mode**: Concurrency and durability via Write-Ahead Logging (`PRAGMA journal_mode = WAL`, `PRAGMA synchronous = NORMAL`).
- **Sub-50 ms waiting-query target**: keyset pagination and the waiting count/list queries are indexed and benchmarked by `app.bench`; performance must be measured in the intended deployment environment.
- **Unified Predicate Compiler**: A single compiler engine compiles grants into both the Python in-memory boolean check and the parameterized SQL `WHERE` clause.

---

## 4. Sample Dataset & Plain-English Access Summary

### 4.1 Assumptions
- **5 Branches**: **Mumbai** (Headquarters / Major Port), **Delhi** (Inland Container Depot), **Chennai** (Southern Seaport), **Kolkata** (Eastern Gateway), and **Ahmedabad** (Western ICD).
- **10 Corporate Clients**: C01 (Acme Corp), C02 (Zenith Global), C03 (Tata Logistics), C04 (Reliance Retail), C05 (Infosys Hardware), C06 (Sun Pharma), C07 (Bajaj Auto), C08 (L&T Heavy), C09 (Mahindra Impex), C10 (Adani Ports Client Group).

### 4.2 Plain-English Staff Access Listing (20 Users)

Every staff member's access is formatted as: `"Person A has role B for client C, branch D, direction E, mode F"`:

1. **Asha Sharma** (`u_asha`) has role **Maker** for ALL clients, ALL branches, ALL directions, ALL modes; and role **Checker** for clients C01, C02, C03, ALL branches, ALL directions, ALL modes.  
   *Constraint*: Separation of Duties (SoD) blocks Asha from checking or filing any job she prepared.
2. **Ravi Verma** (`u_ravi`) has role **Checker** for client C03, branch Mumbai, direction import, ALL modes.  
   *Constraint*: Scoped strictly to Mumbai imports for Tata Logistics (C03).
3. **Meera Nair** (`u_meera`) has role **Supervisor** for ALL clients, branch Mumbai, ALL directions, ALL modes.  
   *Constraint*: Currently absent on parental leave; active delegation granted to Karan.
4. **Karan Joshi** (`u_karan`) has role **Delegate (Supervisor)** for ALL clients, branch Mumbai, ALL directions, ALL modes.  
   *Constraint*: Acts under Meera's authority. Real-actor SoD applies: if Karan prepared a job, he cannot check it. Delegation cannot be chained.
5. **Priya Shah** (`u_priya`) has role **ClientViewer** for client C02 (Zenith Global), ALL branches, ALL directions, ALL modes.  
   *Constraint*: External corporate client user: view-only. Internal fields (`prepared_by`, `checked_by`, margin, internal notes) are strictly redacted.
6. **Devendra Patel** (`u_dev`) has role **AccessAdmin** for ALL clients, ALL branches, ALL directions, ALL modes.  
   *Constraint*: Manages access grants. Strictly prohibited from pipeline job actions (`prepare`, `check`, `file`). Cannot elevate own privileges.
7. **Arun Mukherjee** (`u_arun`) has role **AccessAdmin** for ALL clients, ALL branches, ALL directions, ALL modes.  
   *Constraint*: Second security administrator required to co-approve administrative grant modifications.
8. **Overnight Parser** (`svc_parser`) has role **Service** for ALL clients, ALL branches, ALL directions, ALL modes.  
   *Constraint*: Automated service account authenticated via hashed API key. Restricted strictly to creating and updating jobs in **Confirmed** stage. Cannot touch later stages or manage access.
9. **Arjun Kapoor** (`u_arjun`) has role **Auditor** for ALL clients, ALL branches, ALL directions, ALL modes.  
   *Constraint*: Cross-branch compliance and audit read-only visibility.
10. **Vikram Singh** (`u_vikram`) has role **Supervisor** for ALL clients, branch Delhi, ALL directions, ALL modes.
11. **Ananya Iyer** (`u_ananya`) has role **Supervisor** for ALL clients, branch Chennai, ALL directions, ALL modes.
12. **Rajesh Ghosh** (`u_rajesh`) has role **Supervisor** for ALL clients, branch Kolkata, ALL directions, ALL modes.
13. **Sneha Mehta** (`u_sneha`) has role **Supervisor** for ALL clients, branch Ahmedabad, ALL directions, ALL modes.
14. **Suresh Kumar** (`u_suresh`) has role **Maker** for ALL clients, branches Delhi and Kolkata, ALL directions, ALL modes.
15. **Deepa Reddy** (`u_deepa`) has role **Checker** for ALL clients, branches Delhi and Kolkata, ALL directions, ALL modes.
16. **Manoj Tiwari** (`u_manoj`) has role **Filer** for ALL clients, branch Mumbai, ALL directions, ALL modes.
17. **Pooja Hegde** (`u_pooja`) has role **Filer** for ALL clients, branch Delhi, ALL directions, ALL modes.
18. **Rahul Sen** (`u_rahul`) has role **Viewer** for ALL clients, branch Mumbai, ALL directions, ALL modes.
19. **Rohit Deshmukh** (`u_rohit`) has role **Maker** for ALL clients, branches Chennai and Ahmedabad, ALL directions, ALL modes.
20. **Neha Kulkarni** (`u_neha`) has role **Checker** for ALL clients, branches Chennai and Ahmedabad, ALL directions, ALL modes.

---

## 5. How to Run, Test, and Scale

### 5.1 Load Standard Sample Dataset (~300 Jobs, 20 Users)
```bash
$env:NAGARKOT_DEMO_PASSWORD='choose-a-demo-password'
$env:NAGARKOT_PARSER_API_KEY='choose-a-long-random-parser-key'
python -m app.seed
```
Seeds 5 branches, 10 clients, 20 users, and 300 jobs with full initial lifecycle events in the cryptographic ledger.

### 5.2 Run Automated Test Suite (30 Comprehensive Tests)
```bash
python -m unittest discover -s tests
```
*Coverage*: Maker/checker SoD conflicts, absent owner + delegation (no chaining), changed responsibility and pool reassignment, filed-job cancel/reopen requiring second approver, admin self-escalation blocked, parser stage limits, client-user field redaction, chained HMAC ledger tamper detection, job-seal tamper detection, forensic time-machine replay, predicate compiler dual-execution equivalence over 1,200+ random pairs, and INDETERMINATE fail-closed error handling.

### 5.3 Generate Scale Dataset (500 Users + 200,000 Jobs)
```bash
$env:NAGARKOT_DEMO_PASSWORD='choose-a-demo-password'
$env:NAGARKOT_PARSER_API_KEY='choose-a-long-random-parser-key'
python -m app.seed --scale
```
Generation time depends on the host; the command prints the measured duration.

### 5.4 Run Scale Benchmarks
```bash
python -m app.bench
```
Measures real performance across 200,000 jobs, 50 iterations per user, reporting mean, median, p95, min latencies, and process RSS memory.

---

## 6. Security Differentiators & CLI Commands

### 6.1 Cryptographic Audit Ledger (`cli verify`)
Append-only tamper-evident ledger where each event's hash is computed as `HMAC(K, prev_hash + canonical_event)`.
```bash
python -m app.cli verify
```
*Reports `[OK]` if valid, or identifies the exact sequence number if tampered.*

### 6.2 Job Seals on Filed Shipments (`cli verify-jobs`)
When a customs job reaches `Filed`, an HMAC seal of its canonical content is computed and locked. Detects out-of-band direct database edits:
```bash
python -m app.cli verify-jobs
```

### 6.3 Forensic Time Machine (`cli who-could-change`)
Replays bitemporal grants as they existed at a historical date and correlates with actual audit events:
```bash
python -m app.cli who-could-change --job JOB_0000051 --at 2026-03-01T00:00:00Z
```

### 6.4 Side-by-Side Explainer (`cli explain`)
Answers *"Why can Person A do this and Person B cannot?"*:
```bash
python -m app.cli explain --user u_asha --other u_ravi --action check --job JOB_0000051
```

### 6.5 Blast-Radius Simulator (`cli simulate-grant`)
Dry-run simulator that computes jobs gained, SoD conflicts created, and grantor self-escalation warnings with zero changes committed:
```bash
python -m app.cli simulate-grant --grantor u_dev --user u_suresh --role Checker --scope "{}"
```

### 6.6 Probe Detection & Alerts (MITRE ATT&CK Mapping)
- Rapid authorization denials within a sliding window trigger an `anomaly` event mapped to **MITRE ATT&CK T1078** (Valid Accounts scanning) and **T1087** (Account/Permission Discovery).
- Any write attempt on a `Filed` job triggers an immediate `alert` event.

---

## 7. HTTP REST API Reference

Start server: `python -m app.server` (or `python -m app.cli serve --port 8000`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/authorize` | Evaluates authorization request and returns signed HMAC decision receipt. |
| `GET` | `/explain?user=A&other=B&action=X&job=J` | Side-by-side comparison explaining why A is allowed and B is denied. |
| `GET` | `/jobs/waiting?user=U` | Lists jobs awaiting user action and returns total count using compiled SQL. |
| `GET` | `/jobs?limit=50&after=ID` | Keyset-paginated job listing with client-side field redaction. |
| `POST` | `/jobs` | Creates a new customs job in `Confirmed` stage. |
| `POST` | `/jobs/{id}/action` | Executes a state transition (`prepare`, `check`, `file`, `cancel`, `reopen`). |
| `POST` | `/grants` | Creates a bitemporal grant (admin self-escalation blocked). |
| `POST` | `/grants/{id}/revoke` | Revokes grant, triggers responsibility change, and reassigns claimed jobs. |
| `POST` | `/delegations` | Creates time-bounded supervisor delegation (no chaining). |
| `POST` | `/breakglass` | Initiates 30-minute emergency break-glass with immediate security alert. |
| `GET` | `/audit/job/{id}` | Fetches chronological audit trail, job record, and incidents for a specific job. |
| `GET` | `/audit/verify` | Runs full cryptographic verification of the audit ledger. |
| `GET` | `/logo.jpg` | Serves official Tez Adhikar brand logo. |

---

## 8. Benchmark procedure

Run `python -m app.bench` only after generating the scale database with the
same environment variables shown above. The command emits the actual host,
database size, RSS, and latency distribution. Do not reuse figures from a
different machine or run as evidence for this submission.
