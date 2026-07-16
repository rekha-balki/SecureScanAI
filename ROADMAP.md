# SecureScan AI Engineering Roadmap

## Version 0.1.0-alpha

### SCAN-1
- [x] Repository initialization
- [x] Git workflow
- [x] Branch strategy

### SCAN-2.1
- [x] FastAPI bootstrap
- [x] Swagger
- [x] Health endpoint

### SCAN-2.2.1
- [x] Configuration framework
- [x] Environment management
- [x] Application settings

---

## Version 0.2.0-alpha

### SCAN-2.2.2
- [x] Logging Framework

### SCAN-2.2.3
- [x] Global Exception Handling

### SCAN-2.2.4
- [x] Standard API Response Model

### SCAN-2.2.5
- [x] Middleware

### SCAN-2.3
- [x] Shared Kernel

### SCAN-2.4
- [x] MongoDB Infrastructure

### SCAN-2.5
- [ ] Kafka Infrastructure (client wired, not yet used by orchestration)

### SCAN-2.6
- [ ] Redis Infrastructure (client wired, not yet used)

---

## Version 0.3.0-alpha

### Identity Domain

- [x] User
- [x] Company
- [x] Roles
- [ ] Permissions (role check only; no granular permission model yet)
- [x] JWT Authentication

---

## Version 0.4.0-alpha

### Scan Management

- [x] Scan CRUD (create, list, get, cancel)
- [ ] Scheduling (run immediately only; no future/recurring schedule)
- [x] Status Tracking

---

## Version 0.5.0-alpha

### Web Scanner

- [x] Crawler (bounded, same-host, breadth-first)
- [x] Plugin Engine (isolated execution, fingerprint dedupe)
- [x] Vulnerability Detection (9 built-in plugins + 4 site-level checks)

---

## Version 0.6.0-alpha

### Reporting

- [x] PDF Reports
- [x] Executive Summary
- [ ] CVSS Scoring (severity is plugin-assigned; no numeric CVSS calc yet)

---

## Version 1.0.0

### Production MVP

- [ ] Multi-tenancy hardening (data isolation exists via company_id; no
      platform-admin cross-tenant console yet)
- [x] RBAC (role-gated endpoints)
- [x] Dashboard
- [x] Notifications (scan started/completed/failed/cancelled, report
      ready, finding assigned/updated)
- [x] Audit Logs (register, login, logout, password reset, user/company
      changes, scan submit/cancel/delete/rerun, settings changes)
- [x] Forgot / reset password (FR-003) — dev-mode token exposure until
      SMTP sending is wired up
- [x] Scan delete / re-run (FR-019)
- [x] Company settings persistence (FR Section 14) — theme, password
      policy, session timeout, scanner defaults, report branding, SMTP
      config fields (not yet used to actually send mail)
- [x] Rate limiting (FR Section 15) — Redis-backed, fails open
- [ ] Durable job queue / multi-worker orchestration (currently in-process
      background tasks; see README "Known simplifications")
- [ ] Pause / resume scans
- [ ] Actually send email (password reset, notifications) via the
      persisted SMTP settings
- [ ] Company-configurable password policy enforced at registration
      (currently the fixed FR-001 policy is hardcoded)

- [ ] API Documentation
- [ ] Production Deployment