# SecureScan AI

Enterprise vulnerability assessment platform, built from the BRD and FRS
documents in this repo. This pass implements a working, end-to-end slice of
the platform: authentication, company/user management, a real (bounded)
web scanner with a plugin framework, findings storage, and PDF reporting —
plus a React dashboard to drive it.

## What's implemented

**Backend** (`apps/backend`, FastAPI + MongoDB, DDD-lite architecture)

- JWT authentication: register (creates a company + Company Admin on the
  first user), login, `GET /auth/me`, logout (audit-only, JWTs are
  stateless), forgot/reset password (30-minute token, FR-003).
- Company & user management (`/companies`, `/users`) with role-based access
  (`platform_admin`, `company_admin`, `security_analyst`, `developer`,
  `auditor`).
- Scan orchestration (`/scans`): create/queue a scan, list, get detail,
  cancel, delete (completed/cancelled only, FR-019), re-run with the same
  configuration (FR-019), list findings, update a finding's status/
  assignment, download a PDF report. Scans run as a FastAPI background
  task (see **Known simplifications** below).
- Audit logging (`/audit-logs`, Section 13): every critical action
  (register, login success/failure, logout, password reset, user/company
  changes, scan submit/cancel/delete/re-run, settings changes) is recorded
  with timestamp, user, action, target, IP address, and result. Visible to
  company admins, platform admins, and auditors.
- In-app notifications (`/notifications`, Section 12): scan started/
  completed/failed/cancelled, report ready, finding assigned, finding
  updated. Unread count + mark-as-read/mark-all-read.
- Company settings (`/settings`, Section 14): theme, SMTP (config only —
  no email actually sends yet, see below), password policy, session
  timeout, scanner defaults, report branding. Company-admin editable.
- Rate limiting (Section 15): Redis-backed fixed-window limiter on every
  API route (configurable requests/window), fails open if Redis is down
  so the platform stays available.

**Active testing (narrow, opt-in by nature of what it targets)**
- Reflected XSS: injects a unique marker into each discovered query
  parameter, flags it if it comes back unescaped in the HTML.
- Error-based SQL injection: appends a single quote to each parameter,
  greps the response for known DB error signatures (MySQL/Postgres/
  MSSQL/Oracle/SQLite).
- Open redirect: tests parameters named like `redirect`/`next`/`url`/etc.
  with an external test URL, checks whether the `Location` header
  reflects it unvalidated.
- Capped at 40 parameter tests per scan; every probe is a single request,
  nothing here does iterative fuzzing or multi-step exploitation.

**Crawler/engine improvements**
- `scanner_defaults.request_delay_ms` (Settings) is now actually
  honored by the crawler between requests - previously persisted but
  unused.
- **Form and parameter cataloging**: every form (action, method, field
  names) and every unique query parameter seen during crawl is stored
  and exposed via `GET /scans/{id}/attack-surface`, independent of
  whether a finding was raised against it.
- **Authenticated scanning** (FRS Section 29): scans can carry a
  `bearer`, `cookie`, or `form`-login auth profile; the crawler and
  active-testing client authenticate once at scan start and reuse that
  session for every subsequent request. Credentials are currently
  stored in cleartext on the scan document - see Known simplifications.
- **Optional JS-rendered link discovery** via Playwright
  (`scanner_defaults.enable_js_rendering`, off by default). Discovers
  links a single-page app would inject client-side that a plain HTTP
  GET never sees. Requires `pip install playwright && playwright
  install chromium` on the backend host - not installed by default, and
  this code path has not been exercised against a live browser in the
  environment this was built in. It degrades gracefully (logs a warning
  and continues with HTTP-only results) if Playwright isn't present.

**More passive checks**
- Subresource Integrity, cookie prefix hygiene (`__Secure-`/`__Host-`),
  insecure form action on HTTPS pages, CSRF token presence (structural
  check only), sitemap.xml discovery, favicon fingerprinting (MD5/
  SHA-256, plus a Shodan-style hash if the optional `mmh3` package is
  installed), passive JWT inspection (alg=none, arbitrary jku/x5u -
  decodes the header only, never attempts to verify or crack a
  signature).

**Reporting & business value**
- **CVSS scoring**: every finding now carries an estimated CVSS 3.1
  score and vector, derived from its severity band - see the
  disclaimer in `cvss_service.py`. This is explicitly an approximation,
  not a per-finding calculated score, and is labeled as such in the PDF
  report and API response.
- **Scan-to-scan comparison**: `GET /scans/{id}/compare/{baseline_id}`
  returns new/fixed/persistent findings between two scans of the same
  target, matched by (plugin, category, URL) rather than exact
  fingerprint so cosmetic evidence changes (like "days until cert
  expiry") don't register as a different issue.
- **Excel and JSON export**: `GET /scans/{id}/export/excel` and
  `/export/json`, alongside the existing PDF report - Section 11 lists
  all of Executive PDF, Technical PDF, Excel, JSON, and HTML; HTML
  export is still outstanding.
- **Compliance mapping**: `GET /scans/{id}/compliance-mapping` groups
  findings under PCI-DSS v4.0 / SOC 2 / ISO 27001 controls via each
  finding's OWASP Top 10 category. This is a general reference mapping
  to help prioritize remediation, not a certified compliance
  assessment - see the disclaimer returned alongside the mapping.

**API Scan** (new screen: sidebar → "API Scan")

Paste a curl command (as copied from browser DevTools or Postman) and
the platform will:

- Parse it (`curl_parser.py`) - handles `-X`, `-H`, `-d`/`--data`/
  `--data-raw`/`--data-urlencode`, `-u` (Basic auth), `-b`/`--cookie`,
  `-A`, `-e`, `-G`, `--url`, and a bare positional URL. Unrecognized
  flags are ignored rather than rejected, since real DevTools/Postman
  exports include flags (`--compressed`, `-k`, `--location`) that don't
  affect how the request is built.
- Execute the parsed request once, plus a small number of variants:
  the same request with `Authorization`/`Cookie` stripped (to check
  whether auth is actually enforced), an `OPTIONS` probe (risky HTTP
  methods), and a CORS probe with a synthetic `Origin` header.
- Run the same header/transport/cookie/JWT/sensitive-data plugins the
  web scanner uses (most already guard on content-type, so HTML-only
  checks harmlessly no-op against JSON), plus three API-specific
  checks: verbose error/stack-trace disclosure, missing
  `X-Content-Type-Options` / mismatched `Content-Type`, and broken
  auth enforcement (the stripped-credentials probe above).
- Flag Indian personal-data patterns in the response (Aadhaar-shaped
  numbers, PAN, Indian mobile numbers, IFSC codes, passport-shaped
  numbers, email) via `DpdpPersonalDataExposurePlugin` - pattern
  matching only, explicitly low-confidence, meant to prompt manual
  review rather than assert a confirmed data type or breach.
- Map findings to **India's Digital Personal Data Protection Act,
  2023** via `GET /scans/{id}/dpdp-mapping` - primarily Section 8(5)
  ("reasonable security safeguards"), with personal-data-exposure
  findings also flagged against Section 8(1) (purpose limitation/data
  minimization). Like the PCI/SOC 2/ISO mapping, this is a reference
  mapping to prioritize remediation, not a legal opinion - the
  disclaimer is returned alongside every response.

Findings from an API scan flow through the exact same pipeline as web
scans - same PDF/Excel/JSON export, same Compliance tab, same
scan-to-scan comparison. `ScanDetail` shows a DPDP tab instead of
Attack Surface for API-type scans (a single-request scan has no crawl
surface to show).
- A real Discovery + Crawl Engine: bounded, same-host, breadth-first crawl
  (configurable max depth / max pages), using `httpx`.
- A real Vulnerability Plugin Framework (`app/domains/scan/services/`):
  independent plugins with metadata, isolated execution (one plugin's
  failure never stops the others), fingerprint-based deduplication.
  Page-level plugins: HTTPS Enforcement, HSTS, Security Headers (X-Frame-
  Options, CSP presence, X-Content-Type-Options, Referrer-Policy,
  Permissions-Policy), **CSP directive analysis** (unsafe-inline/eval,
  wildcard sources, missing object-src/frame-ancestors), Cookie Security,
  **Cookie parent-domain scoping**, Server Header Disclosure,
  Cache-Control, Mixed Content, **password-field autocomplete**,
  **file-upload field detection**, **sensitive data exposure** (private
  keys, DB connection strings, AWS keys, emails), **X-XSS-Protection**,
  **vulnerable JS library fingerprinting** (jQuery/Bootstrap/Angular.js/
  Lodash/Moment.js by version). Site-level checks: robots.txt,
  security.txt, `.git` exposure, risky HTTP methods, TLS configuration,
  technology fingerprinting, directory listing, backup file exposure,
  **CORS misconfiguration** (reflected-origin test), **OpenAPI/Swagger/
  GraphQL discovery** (+ GraphQL introspection probe), **ASP.NET tracing/
  debugging** diagnostics.
- PDF report generation with ReportLab (executive summary + technical
  findings, grouped by severity).

**Frontend** (`apps/frontend`, React + MUI + React Router + Axios + Recharts)

- Login / Register, JWT stored client-side, auto-redirect on 401.
- Dashboard: KPI cards, severity distribution donut, recent activity.
- New Scan form, Scan History table, Scan Detail (live-ish polling while
  running, findings table, report download).
- Users page (list + invite, company-admin only), Settings stub.

## Known simplifications vs. the full FRS

The FRS documents (Parts 2, 3, 5) describe a distributed orchestration
layer with a persistent job queue, multiple worker processes, pause/resume
with saved crawler state, retries with backoff, and a full notification/
audit-log system. This pass implements the **single-process** version of
that pipeline (FastAPI `BackgroundTasks`) so a scan genuinely runs and
produces real findings end-to-end, but it does not yet include: a durable
queue (Kafka is wired for connectivity but unused), multi-worker scaling,
pause/resume, or scheduled (future-dated) scans.

Audit logging and in-app notifications are now real (see above). What's
still simulated:

- **Forgot password emails**: the reset link is logged server-side and
  (in non-production only) returned directly in the API response so the
  flow can be tested without SMTP. Company Settings has SMTP fields, but
  nothing actually sends mail through them yet — that's the next piece
  to wire up (`smtplib`/an email provider, using the per-company SMTP
  settings already being persisted).
- **Password policy from Settings**: the company-level password policy
  is persisted and editable, but registration/user-creation still
  enforce the fixed FR-001 policy (12+ chars, mixed case, number,
  special char) rather than reading the company's configured policy.
- **Scan credentials stored in cleartext**: `auth_config` (bearer
  tokens, cookies, login passwords) is persisted as-is in the scan
  document. Fine for a dev/demo pass; move this to an encrypted-at-rest
  secret store before using this against anything real.
- **CVSS scores are estimated, not calculated**: derived from severity
  band only (see `cvss_service.py`), not the 8-metric CVSS 3.1
  calculation a real assessment requires. Labeled as an estimate
  everywhere it's shown.
- **Active testing is intentionally narrow**: reflected XSS, error-based
  SQLi, and open redirect only, capped at 40 parameter tests per scan.
  This is not a fuzzing engine - no blind/boolean-based injection, no
  DOM-based testing, no out-of-band confirmation. See the plugin
  coverage discussion earlier in this project's history for what a
  fuller active scanner would need.
- **HTML report export** (the 5th format FRS Section 11 lists alongside
  Executive/Technical PDF, Excel, and JSON) is not implemented.
- **DPDP and compliance mappings are reference mappings, not legal
  assessments** - both say so in their API responses, but worth
  repeating: mapping a finding to Section 8(5) or a PCI-DSS control
  doesn't mean an actual compliance gap exists, only that it's worth a
  human looking at.
- **API scan credentials**: like the web scanner's `auth_config`, the
  full curl command (including any `Authorization`/cookie/password
  values it contains) is stored as-is on the scan document.

## Running locally

### Option A — Docker Compose (MongoDB + Redis + backend)

```bash
docker compose up --build
```

Then run the frontend separately (see below). The backend will be at
`http://localhost:8000`.

### Option B — Manual

**Backend**

```bash
cd apps/backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env   # edit JWT_SECRET at minimum
# Make sure MongoDB is running locally on 27017 (or update MONGODB_URI)
# Redis is used for rate limiting; if it's unreachable the API still
# works, rate limiting just fails open (see README "Known simplifications")
uvicorn app.main:app --reload
```

API docs: `http://localhost:8000/docs`

**Frontend**

```bash
cd apps/frontend
npm install
cp .env.example .env   # VITE_API_BASE_URL defaults to http://localhost:8000/api/v1
npm run dev
```

App: `http://localhost:5173`

## Project layout

```
apps/
  backend/
    app/
      api/v1/routes/         # HTTP routes
      domains/
        identity/            # User aggregate, auth service
        organization/        # Company aggregate
        scan/                # Scan aggregate, crawler, plugin framework
        finding/              # Finding aggregate
        report/               # PDF generation
      platform/               # bootstrap, security, persistence, errors, etc.
  frontend/
    src/
      pages/                  # Login, Dashboard, NewScan, ScanDetail, ...
      components/             # Layout, ProtectedRoute, SeverityBadge
      context/AuthContext.jsx
      api/client.js
docker-compose.yml
docker/backend.Dockerfile
```

## Trying it out

1. Start Mongo (`docker compose up mongodb -d`) and the backend.
2. Start the frontend, open `http://localhost:5173`, register an account.
3. Create a scan against a site you're authorized to test — your own app,
   or a deliberately-vulnerable target like `http://testphp.vulnweb.com`.
4. Watch the scan complete, review findings, and download the PDF report.
