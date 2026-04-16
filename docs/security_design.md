# Security Design

## Design Goals

The project needed a security design that was realistic enough to defend the obvious web-app attacks, but still small enough to build and test quickly. The main goals were:

- require authentication for anything sensitive
- separate admin, user, and guest behavior clearly
- keep uploaded documents unreadable on disk
- make suspicious activity visible in logs
- avoid security features that only look good on paper and never got tested

Because of that, the final design is intentionally simple: one Flask app, local file-based storage, and a handful of controls that we could actually verify end to end.

## System Layout

At a high level, the app looks like this:

```text
Browser
  |
  | HTTPS
  v
Flask application
  |- routes and templates
  |- auth and role decorators
  |- session validation
  |- upload / download / sharing logic
  |- security headers and HTTPS redirect
  |
  +--> data/users.json
  +--> data/sessions.json
  +--> data/<uuid>.enc
  +--> logs/security.log
  +--> secret.key
```

Everything runs in a single application process, which makes the trust boundaries easier to reason about:

- the browser talks to Flask over HTTPS
- Flask decides whether a request is allowed
- the filesystem holds users, sessions, encrypted documents, logs, and the Fernet key

## Core Security Decisions

### Authentication

Passwords are hashed with bcrypt before they are stored. The password policy is enforced on the server side, not just in the browser, so weak passwords are rejected even if someone edits the form manually.

To slow down guessing attacks, the app uses two controls together:

- account lockout after 5 failed login attempts
- IP-based rate limiting at 10 login attempts per minute

Successful logins create a random session token with `secrets.token_urlsafe(32)`. Session cookies are configured with `HttpOnly`, `Secure`, and `SameSite=Strict`.

### Authorization

The first layer is route-level protection. `require_auth` blocks unauthenticated access, and `require_role("admin")` protects admin-only pages.

The second layer is document-level protection. Even after a user is authenticated, the app still checks whether that user is allowed to access the specific file they asked for.

The access model is:

- admins can reach admin routes and can delete documents when needed
- normal users can upload their own files and share them
- guests can sign in, but they cannot upload or download documents
- shared viewers can open a document in the app, but they cannot download it
- shared editors can view and download the file
- only the owner can share a document with someone else

### File Handling and Input Validation

Uploads are restricted by both extension and MIME type. The allowlist is intentionally small: `pdf`, `txt`, `docx`, `png`, `jpg`, and `jpeg`. Files larger than 10 MB are rejected before they are processed.

Document routes also validate the `doc_id` format before touching the filesystem. The app expects a UUID-looking value, and it also checks that the resolved path stays inside the `data/` directory.

For user input, the app keeps things fairly conservative:

- usernames are limited to letters, numbers, and underscores
- email addresses get basic format validation
- Jinja auto-escaping is relied on for rendered output

### Encryption and Transport Security

Documents are encrypted before they are written to disk. The application uses Fernet from the `cryptography` package, which gives us both confidentiality and integrity checking. In plain terms, someone who opens a `.enc` file directly should not be able to read the document, and tampering with the ciphertext should break decryption.

The app also enforces HTTPS outside test and debug mode. If a request comes in over HTTP, it is redirected to HTTPS. Responses include common hardening headers like CSP, HSTS, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.

### Session Handling

Sessions are stored in `data/sessions.json` with the user ID, username, role, and timestamps. The app treats 30 minutes of inactivity as expired and deletes old sessions when they are encountered.

Logout destroys the server-side session record and clears the client-side session. That means reusing an old cookie after logout should fail, which matched what we saw in testing.

### Logging and Monitoring

The app writes security-relevant events to `logs/security.log`, including failed logins, lockouts, rate-limit hits, denied access, rejected uploads, and path traversal attempts. There is also an access log for normal document actions.

The logging is intentionally plain. It is there so we can answer questions like:

- who tried to access what?
- was a failure caused by bad credentials or a lockout?
- did the app reject the request because of permissions, input validation, or file rules?

## Threats We Designed For

These were the main attack paths we cared about while building the app:

| Threat | What we did about it |
| --- | --- |
| Brute-force login | bcrypt, failed-login lockout, IP rate limiting |
| Privilege escalation | route decorators plus per-document ownership checks |
| IDOR / direct file access | UUID validation, path checks, server-side authorization |
| Malicious file upload | extension allowlist, MIME allowlist, file-size cap |
| Session theft | HTTPS, secure cookie flags, logout invalidation, timeout |
| XSS in rendered pages | Jinja auto-escaping and conservative username validation |
| Tampering with stored files | Fernet authentication detects invalid ciphertext |
| Suspicious or abusive behavior | structured security logging |

This is not a full formal threat model, but it reflects the actual design choices in the code.

## Data Protection

The app stores a small number of sensitive files, and each one is protected differently:

| Data | Location | Protection |
| --- | --- | --- |
| Password hashes | `data/users.json` | bcrypt hashing |
| Session records | `data/sessions.json` | server-side storage, secure cookie transport |
| Document contents | `data/<uuid>.enc` | Fernet encryption |
| Security logs | `logs/security.log` | file permissions and append-only usage pattern |
| Fernet key | `secret.key` | local file only; no extra protection yet |

Even if someone reads the raw stored file, they should only get ciphertext. The weaker part is secret management: once the host is compromised, a key stored on disk is much easier to steal.

## Known Gaps and Tradeoffs

The current design is solid for the class project, but a few compromises are still worth being honest about:

- the Fernet key is stored on disk in `secret.key`
- login rate limiting is in memory, so it resets if the server restarts
- forms do not use dedicated CSRF tokens; protection is mostly coming from session handling and `SameSite=Strict`
- the CSP still allows `unsafe-inline` for scripts and styles
- the password change endpoint does not currently have its own rate limiting
- secure deletion is best effort only on modern storage hardware

None of these issues cancel out the rest of the design, but they are the first places we would revisit if this project moved beyond a classroom environment.

## Why This Design Works for the Project

The biggest strength of the design is that it stays close to the code. We did not add security mechanisms just to list them in a report. The controls in this document are the ones that were actually implemented and exercised during testing.

That makes the system easier to explain and easier to trust. It is a small Flask app with a small set of well-understood controls: strong password handling, role checks, encrypted document storage, secure session settings, HTTPS enforcement, and useful logging. For the scope of this project, that is the right level of complexity.
