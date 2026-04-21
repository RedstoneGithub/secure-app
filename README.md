# Secure Document Sharing System
CS 419 — Spring 2026

A Flask-based web application for securely uploading, encrypting, and sharing confidential documents between users with role-based access control and a full audit trail.

## Features

- User registration and authentication with bcrypt password hashing
- AES-128 (Fernet) encryption for all documents at rest
- Document sharing with owner / editor / viewer roles
- Document versioning and version history
- Admin dashboard for user and document management
- Security headers, HTTPS enforcement, and structured security logging

## Requirements

- Python 3.10+
- OpenSSL (for generating the self-signed certificate)

## Setup

### 1. Clone the repository

```bash
git clone <repo-url>
cd CS419-FinalProj
```

### 2. Create and activate a virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. TLS certificate

A self-signed `cert.pem` and `key.pem` are included in the repository for convenience. You can use them directly , no extra steps needed.

If you prefer to generate your own:

```bash
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```

When prompted, fill in any values (or press Enter to accept defaults).

### 5. Set the secret key (recommended)

```bash
# Windows
set SECRET_KEY=your-random-secret-here

# macOS / Linux
export SECRET_KEY=your-random-secret-here
```

If omitted, a random key is generated each run (sessions will not survive restarts).

### 6. Create an admin user

On first run the `data/` directory is created automatically. To create an admin account, register normally through the UI, then manually edit `data/users.json` and change `"role": "user"` to `"role": "admin"` for that entry.

### 7. Run the application

```bash
python app.py
```

The app starts on `https://0.0.0.0:5000`. Open `https://localhost:5000` in your browser.

> Your browser will show a certificate warning because the cert is self-signed. Click "Advanced" and proceed to continue.

## Project Structure

```
CS419-FinalProj/
├── app.py              # Main application — routes, auth, encryption, logging
├── config.py           # All configuration constants
├── requirements.txt    # Python dependencies
├── cert.pem            # TLS certificate (self-signed)
├── key.pem             # TLS private key
├── secret.key          # Fernet encryption key
├── data/               # JSON data store (auto-created on first run)
│   ├── users.json      # User accounts
│   ├── sessions.json   # Active sessions
│   └── *.enc           # Encrypted documents
├── logs/
│   ├── security.log    # Security events and warnings
│   └── access.log      # Authentication and document activity log
├── templates/          # Jinja2 HTML templates
├── docs/               # Security design document and pentest report PDFs
├── tests/              # Automated test suite and manual verification guide
└── presentation/       # Presentation slides
```

## Testing

- Automated coverage: `140` passing tests in `tests/test_app.py`
- Manual verification guide: `tests/MANUAL_TESTING.md`
- Run the suite with `python -m pytest tests/test_app.py -v`

The automated suite covers registration, login, password changes, RBAC, upload validation, encryption, session handling, security headers, audit logging, sharing, deletion, viewing, version restore/download, and editor-upload flows.

## User Roles

| Role  | Upload | Download | Share | View All | Manage Users |
|-------|--------|----------|-------|----------|--------------|
| Admin | Yes    | Yes      | Yes   | Yes      | Yes          |
| User  | Yes    | Yes*     | Yes   | No       | No           |
| Guest | No     | No       | No    | No       | No           |

\* Users can download documents they own or are shared with them as editor. Editors can also upload a new version of a document shared with them (the replacement must keep the original file extension); viewers cannot.

## Security Controls Summary

| Control | Implementation |
|---------|---------------|
| Password hashing | bcrypt, cost factor 12 |
| Session tokens | `secrets.token_urlsafe(32)`, 30-min timeout |
| Data-at-rest encryption | Fernet (AES-128-CBC + HMAC-SHA256) |
| Transport encryption | TLS 1.2+ via self-signed certificate |
| Account lockout | 5 failed attempts → locked 15 minutes |
| Rate limiting | Max 10 login attempts per IP per minute |
| Security headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| Input validation | Whitelist regex on usernames, MIME + extension checks on uploads |
| Path traversal prevention | UUID regex validation + `os.path.abspath` boundary check |
| Audit logging | Structured JSON log for all security events |
