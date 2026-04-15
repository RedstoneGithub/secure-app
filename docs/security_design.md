# Security Design Document

**CS 419 - Secure Web Application Project**  
Secure Document Sharing System  
Spring 2026

---

## Table of Contents

1. Architecture Overview
2. Threat Model
3. Security Controls
4. Data Protection

## 1. Architecture Overview

### 1.1 System Architecture

The Secure Document Sharing System is a web application built using the Python/Flask framework. It follows a single-server architecture with file-based storage, eliminating the need for a database while maintaining structured data organization.

```text
┌─────────────────────────────────────────────────────┐
│                    CLIENT BROWSER                   │
│         (HTML5 / CSS3 / JavaScript)                 │
└────────────────────┬────────────────────────────────┘
                     │ HTTPS (TLS)  Port 5000
┌────────────────────▼────────────────────────────────┐
│                  FLASK APPLICATION                  │
│                                                     │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────┐  │
│  │    Routes   │  │  Decorators  │  │  Logging  │  │
│  │  /login     │  │ require_auth │  │ Security  │  │
│  │  /register  │  │ require_role │  │  Logger   │  │
│  │  /documents │  └──────────────┘  └───────────┘  │
│  │  /admin     │                                    │
│  └─────────────┘                                    │
│                                                     │
│  ┌─────────────────────────────────────────────┐    │
│  │           Security Middleware               │    │
│  │  - Security Headers (@after_request)        │    │
│  │  - HTTPS Redirect (@before_request)         │    │
│  │  - Session Validation                       │    │
│  │  - Rate Limiting                            │    │
│  └─────────────────────────────────────────────┘    │
└────────────────────┬────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────┐
│                FILE-BASED STORAGE                   │
│                                                     │
│  data/                                              │
│  ├── users.json          (plaintext JSON)           │
│  ├── sessions.json       (plaintext JSON)           │
│  └── uuid.enc            (Fernet encrypted)         │
│                                                     │
│  logs/                                              │
│  └── security.log        (append-only log)          │
└─────────────────────────────────────────────────────┘
```

### 1.2 Data Flow Diagrams

#### User Authentication Flow

```text
User → POST /login
     → Rate limit check (10 req/min per IP)
     → Load user from users.json
     → Check account lock status
     → bcrypt.checkpw(password, hash)
     → On success: create session token → sessions.json
     → Set secure cookie (HttpOnly, Secure, SameSite=Strict)
     → Log event to security.log
     → Redirect to /dashboard
```

#### Document Upload Flow

```text
User → POST /documents/upload
     → require_auth (session validation)
     → Guest role check (blocked if guest)
     → File extension + MIME type validation
     → File size check (max 10 MB)
     → Check for existing filename (versioning)
     → base64 encode binary data
     → Fernet encrypt JSON payload
     → Write uuid.enc to data/
     → Log FILE_UPLOADED to security.log
```

#### Document Download Flow

```text
User → GET /documents/download/<doc_id>
     → require_auth (session validation)
     → Guest role check (blocked if guest)
     → UUID format validation (regex)
     → Path traversal check (os.path.abspath)
     → Load + decrypt .enc file
     → Check owner/editor access role
     → Log FILE_DOWNLOADED to security.log
     → Stream file to browser
```

#### Document Sharing Flow

```text
Owner → POST /documents/share/<doc_id>
      → require_auth (session validation)
      → UUID format validation
      → Verify requester is document owner
      → Validate target username exists
      → Validate role (editor or viewer)
      → Update shared_with in .enc file
      → Log DOCUMENT_SHARED to security.log
```

### 1.3 Component Descriptions

| Component | Description |
| --- | --- |
| Flask Application | Core web framework handling routing, request processing, and template rendering |
| EncryptedStorage | Fernet-based symmetric encryption class for document files |
| SecurityLogger | Structured JSON event logger writing to `logs/security.log` |
| SessionManager | File-backed session management with 30-minute timeout |
| RBAC Decorators | `require_auth` and `require_role` function decorators for access control |
| Security Headers | `@app.after_request` middleware applying all required HTTP security headers |
| Rate Limiter | In-memory IP-based rate limiting (10 login attempts per minute) |

### 1.4 Technology Stack Justification

| Technology | Justification |
| --- | --- |
| Python 3 / Flask | Lightweight, readable, strong security library ecosystem |
| bcrypt (rounds=12) | Industry-standard password hashing with configurable work factor |
| cryptography (Fernet) | Authenticated symmetric encryption - prevents tampering as well as reading |
| secrets module | Cryptographically secure token generation for sessions |
| File-based JSON storage | No database setup required per project spec; simple and auditable |
| Jinja2 templates | Auto-escaping by default prevents XSS in rendered output |
| TLS (self-signed cert) | Encrypts data in transit for development environment |

## 2. Threat Model

### 2.1 Asset Identification

| Asset | Classification | Description |
| --- | --- | --- |
| User credentials | Critical | Usernames, emails, bcrypt password hashes |
| Document contents | High | Encrypted files stored as `.enc` |
| Session tokens | High | 32-byte URL-safe tokens in `sessions.json` |
| Encryption key | Critical | Fernet key stored in `secret.key` |
| Security logs | Medium | Event logs containing IP addresses and usernames |
| User metadata | Medium | Registration timestamps, roles, lock status |

### 2.2 Threat Enumeration (STRIDE Model)

| Threat | Category | Description |
| --- | --- | --- |
| Brute force login | Spoofing | Attacker repeatedly guesses passwords |
| Session hijacking | Spoofing | Attacker steals session cookie to impersonate user |
| Privilege escalation | Elevation of Privilege | User accesses admin or other user's resources |
| Path traversal | Tampering | Attacker manipulates `doc_id` to read arbitrary files |
| XSS injection | Tampering | Attacker injects scripts via filenames or usernames |
| File upload abuse | Tampering | Attacker uploads malicious or oversized files |
| Man-in-the-middle | Information Disclosure | Attacker intercepts HTTP traffic |
| Direct file access | Information Disclosure | Attacker reads `.enc` files from disk |
| Log tampering | Repudiation | Attacker modifies or deletes security logs |
| Denial of Service | Denial of Service | Attacker floods login endpoint |

### 2.3 Vulnerability Assessment

| Vulnerability | Likelihood | Impact | Risk Level |
| --- | --- | --- | --- |
| Weak password accepted | Low | High | Medium |
| Session fixation | Low | High | Medium |
| Path traversal on download | Medium | Critical | High |
| Unvalidated file upload | Medium | High | High |
| Hardcoded `SECRET_KEY` | Low | Critical | High |
| Plaintext key storage (`secret.key`) | Medium | Critical | High |
| No CSRF token on forms | Medium | Medium | Medium |
| Debug mode enabled | Low | High | Medium |

### 2.4 Attack Scenarios

#### Scenario 1: Brute Force Login

An attacker attempts to guess a user's password by sending repeated POST requests to `/login`.

**Mitigation:** Account lockout after 5 failed attempts (15 min), rate limit of 10 requests/min per IP, bcrypt with cost factor 12 slows offline guessing.

#### Scenario 2: Path Traversal on Download

An attacker sends a request to `/documents/download/../data/users` to read the users file.

**Mitigation:** UUID regex validation rejects non-UUID `doc_id`s; `os.path.abspath` comparison ensures path stays within `data/`.

#### Scenario 3: Privilege Escalation

A standard user manually crafts a request to `/admin/dashboard`.

**Mitigation:** `@require_role('admin')` decorator checks session role and returns 403 with an `ACCESS_DENIED` log event.

#### Scenario 4: Malicious File Upload

An attacker uploads a `.php` or `.exe` file disguised with a fake extension.

**Mitigation:** Both file extension and MIME type are validated against an allowlist before the file is processed.

#### Scenario 5: Man-in-the-Middle

An attacker intercepts traffic on an HTTP connection to steal session cookies.

**Mitigation:** HTTPS enforced via TLS; `Strict-Transport-Security` header set; session cookie has `Secure=True` flag.

### 2.5 Risk Prioritization

| Priority | Risk | Status |
| --- | --- | --- |
| 1 | Path traversal | Mitigated |
| 2 | Unvalidated file uploads | Mitigated |
| 3 | Brute force / credential stuffing | Mitigated |
| 4 | Session hijacking | Mitigated (secure cookies + HTTPS) |
| 5 | Privilege escalation | Mitigated (RBAC decorators) |
| 6 | Plaintext key storage (`secret.key`) | Partially mitigated |
| 7 | CSRF on state-changing forms | Partially mitigated (SameSite=Strict) |

## 3. Security Controls

### A. User Authentication (15 points)

**Control Description:** Secure user registration and login with strong password requirements and account protection mechanisms.

**Implementation:**

- Passwords hashed with bcrypt (cost factor 12) - never stored in plaintext
- Password requirements: minimum 12 characters, uppercase, lowercase, number, special character
- Account lockout after 5 failed attempts for 15 minutes
- Rate limiting: maximum 10 login attempts per IP per minute
- Session token generated with `secrets.token_urlsafe(32)`

**Testing Methodology:** Attempt login with wrong password 5 times - verify account locks. Send 11 rapid requests - verify rate limit. Check `users.json` for bcrypt hash format (`$2b$12$...`).

**Known Limitations:** Rate limiting is in-memory and resets on server restart. No multi-factor authentication.

**Mitigation Strategies:** Persist rate limit data to file. Add TOTP-based MFA for high-security accounts.

### B. Access Control (15 points)

**Control Description:** Role-based access control (RBAC) with three roles: Admin, User, and Guest.

**Implementation:**

- `require_auth` decorator validates active session before any protected route
- `require_role(role)` decorator checks session role against required role
- Admin: full access including user management and all documents
- User: upload, download own/shared docs, share documents
- Guest: read-only - can view document list but cannot upload or download

**Testing Methodology:** Log in as guest and attempt upload - expect redirect. Log in as user and attempt `/admin/dashboard` - expect 403. Attempt to download a viewer-only shared document - expect access denied.

**Known Limitations:** `require_role` checks exact role match - admin cannot use user-level decorators without modification.

**Mitigation Strategies:** Extend `require_role` to accept a list of allowed roles.

### C. Input Validation & Injection Prevention (20 points)

**Control Description:** Whitelist-based validation of all user inputs and uploaded files to prevent injection attacks.

**Implementation:**

- Username: regex `^\w{3,20}$` (alphanumeric + underscore, 3-20 chars)
- Email: regex format validation
- Password: length + complexity requirements enforced server-side
- File uploads: allowlist of extensions (`pdf`, `txt`, `docx`, `png`, `jpg`, `jpeg`) and MIME types
- File size: maximum 10 MB enforced before processing
- Document IDs: UUID regex rejects path traversal attempts
- XSS: Jinja2 auto-escaping enabled on all template variables
- Path traversal: `os.path.abspath` comparison keeps file access within `data/`

**Testing Methodology:** Upload `.exe` and `.php` files - verify rejection. Submit `<script>alert(1)</script>` as username - verify escaped output. Request `/documents/download/../data/users` - verify 400.

**Known Limitations:** MIME type can be spoofed. No magic byte checking or malware scanning.

**Mitigation Strategies:** Use `python-magic` for magic byte validation. Integrate ClamAV for malware scanning.

### D. Encryption (15 points)

**Control Description:** Encryption of data in transit (TLS) and data at rest (Fernet symmetric encryption).

**Implementation:**

- Transport: TLS via self-signed certificate, Flask `ssl_context`
- HTTPS redirect via `@app.before_request`
- HSTS header: `max-age=31536000; includeSubDomains`
- Data at rest: Fernet (AES-128-CBC + HMAC-SHA256) for all document files
- Encryption key stored in `secret.key`, generated on first run
- Binary data base64-encoded before encryption

**Testing Methodology:** Open a `.enc` file in a text editor - verify unreadable ciphertext. Send HTTP request - verify redirect to HTTPS. Check response headers for `Strict-Transport-Security`.

**Known Limitations:** Self-signed certificate generates browser warnings. Encryption key stored in plaintext on disk.

**Mitigation Strategies:** Use a CA-signed certificate for production. Store key in environment variable or HSM.

### E. Session Management (15 points)

**Control Description:** Secure file-backed session management with timeout and secure cookie configuration.

**Implementation:**

- Session tokens: `secrets.token_urlsafe(32)` - 256-bit cryptographically secure
- Sessions stored in `data/sessions.json` with user ID, role, timestamps
- 30-minute inactivity timeout
- Session destroyed on logout
- Cookie flags: `HttpOnly=True`, `Secure=True`, `SameSite=Strict`
- Flask `SECRET_KEY` loaded from environment variable

**Testing Methodology:** Log in, wait 31 minutes, attempt dashboard access - verify redirect to login. Log out and reuse old token - verify invalid. Check cookie flags in browser DevTools.

**Known Limitations:** No concurrent session detection. Sessions file grows without cleanup.

**Mitigation Strategies:** Add periodic cleanup of expired sessions. Implement single active session per user.

### F. Security Headers (10 points)

**Control Description:** HTTP response headers instructing the browser to apply additional security policies.

| Header | Value | Purpose |
| --- | --- | --- |
| Content-Security-Policy | `default-src 'self'` | Restricts resource loading to same origin |
| X-Frame-Options | `DENY` | Prevents clickjacking via iframes |
| X-Content-Type-Options | `nosniff` | Prevents MIME type sniffing |
| X-XSS-Protection | `1; mode=block` | Legacy XSS filter for older browsers |
| Referrer-Policy | `strict-origin-when-cross-origin` | Limits referrer information leakage |
| Permissions-Policy | `geolocation=(), microphone=(), camera=()` | Disables sensitive browser APIs |
| Strict-Transport-Security | `max-age=31536000; includeSubDomains` | Enforces HTTPS for 1 year |

**Testing Methodology:** Use browser DevTools -> Network -> Response Headers to verify all headers. Use `securityheaders.com` to scan.

**Known Limitations:** CSP uses `unsafe-inline` for scripts and styles - acceptable for development.

### G. Logging & Monitoring (10 points)

**Control Description:** Structured JSON security event logging for audit trail and incident response.

**Implementation:** `SecurityLogger` class writes JSON entries to `logs/security.log`. Each entry includes timestamp (UTC ISO), event type, user ID, IP address, details, and severity.

**Events Logged:** `LOGIN_SUCCESS`, `LOGIN_FAILED`, `LOGIN_BLOCKED`, `ACCOUNT_LOCKED`, `RATE_LIMITED`, `FILE_UPLOADED`, `FILE_DOWNLOADED`, `FILE_VERSION_UPLOADED`, `UPLOAD_REJECTED`, `DOCUMENT_SHARED`, `ACCESS_DENIED`, `PATH_TRAVERSAL_ATTEMPT`, `ADMIN_DASHBOARD_ACCESS`, `ADMIN_USER_LOCKED`, `ADMIN_USER_UNLOCKED`, `FILE_LOAD_ERROR`.

**Testing Methodology:** Trigger a failed login - verify `WARNING` entry in `security.log`. Upload a file - verify `FILE_UPLOADED` entry. Attempt path traversal - verify `PATH_TRAVERSAL_ATTEMPT` entry.

**Known Limitations:** Logs stored on same server. No real-time alerting.

**Mitigation Strategies:** Ship logs to remote syslog or SIEM. Add alerting for `CRITICAL` events.

## 4. Data Protection

### 4.1 Data Classification

| Data | Classification | Storage Location | Encrypted |
| --- | --- | --- | --- |
| Password hashes | Confidential | `data/users.json` | bcrypt hashed |
| Document contents | Confidential | `data/uuid.enc` | Yes (Fernet) |
| Session tokens | Confidential | `data/sessions.json` | No |
| Encryption key | Secret | `secret.key` | No |
| User metadata | Internal | `data/users.json` | No |
| Security logs | Internal | `logs/security.log` | No |

### 4.2 Encryption Methods

**Password Hashing:** bcrypt with cost factor 12. Each password has a unique random salt. Output is a 60-character hash stored in `users.json`.

**Document Encryption:** Fernet (AES-128-CBC with PKCS7 padding + HMAC-SHA256 authentication). Provides both confidentiality and integrity - tampering with a `.enc` file is detected on decryption. Binary document data is base64-encoded before encryption to handle all file types.

**Transport Encryption:** TLS via HTTPS. Self-signed RSA-4096 certificate for development. HSTS enforced to prevent downgrade attacks.

### 4.3 Key Management

**Fernet Encryption Key:** Generated once using `Fernet.generate_key()` on first startup. Stored in `secret.key` in the project root. All documents share the same key. Key loss means all encrypted documents are permanently unrecoverable.

**Flask Secret Key:** Loaded from the `SECRET_KEY` environment variable at startup. Falls back to a randomly generated key if not set. Used for Flask session signing.

**Recommended Production Improvements:**

- Store Fernet key in an environment variable or secrets manager
- Rotate keys periodically with re-encryption of existing documents
- Use per-document encryption keys derived from a master key

### 4.4 Secure Deletion Procedures

Document deletion is not currently implemented. When implemented, the following procedures should be followed:

1. **Overwrite before delete:** Overwrite the `.enc` file with random bytes before removing it from disk
2. **Remove sharing references:** Remove the document ID from any `shared_with` entries
3. **Audit log:** Log the deletion event with user ID, document ID, and timestamp
4. **Version cleanup:** All stored versions within the `.enc` file are deleted together with the document

---

CS 419 - Secure Web Application Project | Spring 2026
