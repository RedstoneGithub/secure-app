# Manual Testing Guide — CS 419 Secure Document Sharing System

This guide covers how to manually verify every security requirement from the rubric.
Run these tests in a browser and terminal after starting the app.

---

## Setup

```bash
# 1. Activate virtual environment
venv\Scripts\activate          # Windows
source venv/bin/activate       # Mac/Linux

# 2. Start the server
python app.py

# 3. Open browser and accept the self-signed cert warning
https://localhost:5000
```

> All tests below assume the server is running at `https://localhost:5000`.
> Accept the self-signed certificate warning in your browser when prompted.

---

## A. User Authentication (15 points)

### A1. Registration — input validation

Go to `https://localhost:5000/register` and try each of these. Each should show
an error message and create no account.

| Input to test | What to enter | Expected result |
|---|---|---|
| Username too short | `ab` | Error: username invalid |
| Username too long | 21 `a` characters | Error: username invalid |
| Username with hyphen | `bad-user` | Error: username invalid |
| Invalid email | `notanemail` | Error: email invalid |
| Password too short | `Short1!` | Error: password requirements |
| Password no uppercase | `alllower123!` | Error: password requirements |
| Password no lowercase | `ALLUPPER123!` | Error: password requirements |
| Password no number | `NoNumbers!!!A` | Error: password requirements |
| Password no special char | `NoSpecialABC123` | Error: password requirements |
| Passwords don't match | `AlicePass12!` / `Different12!` | Error: passwords do not match |

Then register a valid account:
- Username: `alice` (3–20 chars, letters/numbers/underscore only)
- Email: `alice@test.com`
- Password: `AlicePass12!` (12+ chars, upper, lower, number, special)
- Confirm password: same

**Expected:** Redirect to home page, success message.

Verify the password is hashed in `data/users.json`:
```bash
cat data/users.json
# password_hash should start with $2b$12$ — never the raw password
```

### A2. Duplicate username/email

Register a second account with the same username or email as above.

**Expected:** Error message, no second account created.

### A3. Login — wrong credentials

Go to `https://localhost:5000/login`:
- Enter a username that does not exist → error message
- Enter correct username, wrong password → error message

### A4. Account lockout after 5 failures

Enter the wrong password **5 times** for the same account.

**Expected:** "Account locked" message on the 5th attempt. Correct password should
also be rejected while locked. Check `data/users.json` — `locked_until` should be
set to a future timestamp.

**Wait 15 minutes** (or set `locked_until` to `null` in `data/users.json` manually)
to verify the account unlocks.

### A5. Rate limiting (10 attempts per IP per minute)

Submit the login form **11 times** rapidly (wrong password is fine).

**Expected:** "Too many login attempts. Please wait a minute." on the 11th attempt.

### A6. Verify security log

```bash
cat logs/security.log
# Look for LOGIN_SUCCESS, LOGIN_FAILED, ACCOUNT_LOCKED, RATE_LIMITED events
```

---

## B. Access Control (15 points)

### B1. Unauthenticated access — redirect to login

While logged out, visit each of these directly:
- `https://localhost:5000/dashboard`
- `https://localhost:5000/documents`
- `https://localhost:5000/admin/dashboard`

**Expected:** All redirect to the login page.

### B2. Regular user cannot access admin

Log in as a regular `user` role account, then visit:

```
https://localhost:5000/admin/dashboard
```

**Expected:** `403 Forbidden`

Check the log:
```bash
cat logs/security.log
# Look for ACCESS_DENIED event
```

### B3. Guest role restrictions

Register an account and select **Guest** as the role. Log in with that account.

- Try to upload a file → **Expected:** "Guest accounts cannot upload documents."
- Try to visit a download URL → **Expected:** Blocked/redirected

### B4. Viewer cannot download

1. Log in as a regular user (User A), upload a document.
2. Share it with another user (User B) as **Viewer**.
3. Log out, log in as User B.
4. Try to click download on the shared document.

**Expected:** Access denied — viewers can only see the file listed, not download it.

### B5. Editor can download

Repeat B4 but share as **Editor** instead of Viewer.

**Expected:** Download succeeds.

### B6. Non-owner cannot share

Log in as User B (who had a document shared with them), try to share that
document with someone else.

**Expected:** "Only the document owner can share it."

### B7. Admin user management

Create an admin account by editing `data/users.json` and setting `"role": "admin"`.
Log in as admin and visit `https://localhost:5000/admin/dashboard`.

**Expected:** Admin dashboard shows all users and documents.

Try locking and unlocking a user account from the dashboard.

---

## C. Input Validation & Injection Prevention (20 points)

### C1. File upload — rejected extensions

Log in as a regular user, go to `https://localhost:5000/documents`, and try
uploading each of these files:

| Filename | MIME type | Expected |
|---|---|---|
| `malware.exe` | application/octet-stream | Rejected |
| `shell.php` | text/plain | Rejected |
| `xss.html` | text/html | Rejected |
| `script.js` | application/javascript | Rejected |

**Expected:** Error message "File type not allowed."
Verify: no new `.enc` files appear in `data/`.

### C2. File upload — allowed types

Try uploading these (should succeed):

| Filename | MIME type |
|---|---|
| `document.pdf` | application/pdf |
| `notes.txt` | text/plain |
| `report.docx` | application/vnd.openxmlformats-officedocument.wordprocessingml.document |
| `photo.png` | image/png |
| `photo.jpg` | image/jpeg |

**Expected:** "File uploaded and encrypted successfully."

### C3. File upload — oversized file

Create a file larger than 10 MB and try to upload it.

```bash
# Create a 11 MB test file
python -c "open('bigfile.txt','wb').write(b'x'*(11*1024*1024))"
```

**Expected:** "File too large. Maximum size is 10 MB."

### C4. Path traversal on download

While logged in, visit these URLs directly in the browser:

```
https://localhost:5000/documents/download/not-a-valid-uuid!!!
https://localhost:5000/documents/download/../../etc/passwd
```

**Expected:** `400 Bad Request` or `404 Not Found` — never file contents.

### C5. XSS prevention

Try submitting `<script>alert(1)</script>` as a username during registration.

**Expected:** The validation regex rejects it (only alphanumeric + underscore allowed),
so no account is created. Even if it were stored, Jinja2 auto-escaping would prevent
it from executing.

---

## D. Encryption (15 points)

### D1. Data at rest — files are encrypted

Upload a text file with obvious content (e.g., content = `TOP SECRET`).
Then open the `.enc` file on disk directly:

```bash
# Find the file
ls data/*.enc

# Try to read it
cat data/<uuid>.enc
# Should be unreadable ciphertext, not "TOP SECRET"
```

### D2. Download decrypts correctly

Download the file you just uploaded through the browser.

**Expected:** The downloaded file matches the original content exactly.

### D3. HTTPS enforcement

Visit the site over plain HTTP:

```
http://localhost:5000
```

**Expected:** Browser is redirected to `https://localhost:5000` (301 redirect).

```bash
# Verify via curl
curl -k -I http://localhost:5000
# Look for: Location: https://localhost:5000
```

---

## E. Session Management (15 points)

### E1. Session cookie flags

Log in, then open browser **DevTools → Application → Cookies → localhost**.

Verify the session cookie has:
- `HttpOnly` ✅ (prevents JavaScript access)
- `Secure` ✅ (HTTPS only)
- `SameSite: Strict` ✅ (CSRF protection)

### E2. Logout destroys session

1. Log in.
2. Copy your session cookie value from DevTools.
3. Click Logout.
4. Try to visit `https://localhost:5000/dashboard`.

**Expected:** Redirected to login. The old cookie no longer works.

Verify session was removed:
```bash
cat data/sessions.json
# Should be empty {} after logout
```

### E3. Session timeout

1. Log in.
2. Manually edit `data/sessions.json` — set `last_activity` to a timestamp
   30+ minutes in the past (subtract 1900 from the current Unix timestamp).
3. Try to visit `https://localhost:5000/dashboard`.

**Expected:** Redirected to login (session expired).

```bash
# Get current Unix timestamp minus 1900 seconds
python -c "import time; print(time.time() - 1900)"
```

---

## F. Security Headers (10 points)

### F1. Verify all required headers are present

```bash
curl -k -I https://localhost:5000/
```

You should see all 7 of these headers:

| Header | Expected value |
|---|---|
| `Content-Security-Policy` | `default-src 'self'; ...` |
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `X-XSS-Protection` | `1; mode=block` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |

### F2. Verify headers appear on all routes (not just home)

```bash
# Check an authenticated route too
curl -k -I https://localhost:5000/login
```

---

## G. Logging & Monitoring (10 points)

### G1. Watch the log in real time

```bash
# PowerShell
Get-Content logs/security.log -Wait

# Git Bash / WSL
tail -f logs/security.log
```

### G2. Trigger and verify each event type

Perform these actions and confirm the matching event appears in the log:

| Action | Expected log event |
|---|---|
| Successful login | `LOGIN_SUCCESS` |
| Wrong password | `LOGIN_FAILED` |
| 5 wrong passwords | `ACCOUNT_LOCKED` |
| 11 rapid login attempts | `RATE_LIMITED` |
| Upload a file | `FILE_UPLOADED` |
| Download a file | `FILE_DOWNLOADED` |
| Upload a second version | `FILE_VERSION_UPLOADED` |
| Upload a `.exe` file | `UPLOAD_REJECTED` |
| Share a document | `DOCUMENT_SHARED` |
| User visits `/admin/dashboard` without admin role | `ACCESS_DENIED` |
| Path traversal URL attempt | `PATH_TRAVERSAL_ATTEMPT` |
| Admin views dashboard | `ADMIN_DASHBOARD_ACCESS` |
| Admin locks a user | `ADMIN_USER_LOCKED` |

### G3. Verify log entry structure

Each log entry should be a JSON object with:
- `timestamp` — UTC ISO format
- `event_type` — e.g. `LOGIN_SUCCESS`
- `user_id` — the user's ID (or `null` for anonymous)
- `ip_address` — e.g. `127.0.0.1`
- `details` — event-specific context

```bash
# Pretty-print the last log entry
python -c "
import json
lines = open('logs/security.log').readlines()
for line in lines[-3:]:
    try:
        entry = json.loads(line.split(' - ', 2)[2])
        print(json.dumps(entry, indent=2))
    except: pass
"
```

---

## H. Core Features — Documents

### H1. Upload and download

1. Upload any allowed file.
2. Find it in **My Documents** on `https://localhost:5000/documents`.
3. Click Download — file should match the original.

### H2. Document versioning

1. Upload a file named `report.txt` with content "Version 1".
2. Upload another file with the **same filename** `report.txt` with content "Version 2".

**Expected:**
- Only one document row appears (same filename = new version)
- Version counter increments to `v2`
- Click **Version History** — should show `v1` in the history

### H3. Sharing

1. Upload a document as User A.
2. Enter User B's username in the Share form, select **Viewer**, submit.
3. Log out and log in as User B.

**Expected:**
- Document appears under **Shared With Me**
- User B's role shows as "Viewer"
- Download button is replaced with "View only"

Repeat with **Editor** role — User B should be able to download.

### H4. Sharing restrictions

Try to:
- Share a document with yourself → should be blocked
- Share using an invalid role (edit the form with DevTools to send `role=admin`) → should be blocked
- As a non-owner, POST to `/documents/share/<doc_id>` → should be blocked

---

## Running the Automated Tests

```bash
# Run all 103 automated tests (covers all sections above)
python -m pytest tests/test_app.py -v

# Run a specific section
python -m pytest tests/test_app.py::TestSecurityHeaders -v
python -m pytest tests/test_app.py::TestLogin -v
python -m pytest tests/test_app.py::TestAccessControl -v

# Stop on first failure
python -m pytest tests/test_app.py -x -v
```

All 103 tests should pass.
