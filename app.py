from flask import (
    Flask,
    render_template,
    request,
    redirect,
    send_file,
    url_for,
    flash,
    session,
)
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import base64
import ipaddress
import json
import os
import time
import re
import uuid
import bcrypt
import secrets
import logging
from datetime import datetime, timedelta, timezone


import config

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = config.SESSION_COOKIE_HTTPONLY
app.config["SESSION_COOKIE_SECURE"] = config.SESSION_COOKIE_SECURE
app.config["SESSION_COOKIE_SAMESITE"] = config.SESSION_COOKIE_SAMESITE
USERS_FILE = config.USERS_FILE


class EncryptedStorage:
    def __init__(self, key_file="secret.key"):
        # Load or generate encryption key
        try:
            with open(key_file, "rb") as f:
                self.key = f.read()
        except FileNotFoundError:
            self.key = Fernet.generate_key()
            with open(key_file, "wb") as f:
                f.write(self.key)

        self.cipher = Fernet(self.key)

    def save_encrypted(self, filename, data):
        """Save encrypted JSON data"""
        json_data = json.dumps(data)
        encrypted = self.cipher.encrypt(json_data.encode())

        with open(filename, "wb") as f:
            f.write(encrypted)

    def load_encrypted(self, filename):
        """Load and decrypt JSON data"""
        with open(filename, "rb") as f:
            encrypted = f.read()
            decrypted = self.cipher.decrypt(encrypted)
            return json.loads(decrypted.decode())


class StructuredLogger:
    def __init__(self, name, log_file):
        os.makedirs("logs", exist_ok=True)
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.FileHandler(log_file)
            handler.setFormatter(
                logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            )
            self.logger.addHandler(handler)

    def log_event(self, event_type, user_id, details, severity="INFO"):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "ip_address": request.remote_addr,
            "details": details,
        }
        msg = json.dumps(entry)
        if severity == "CRITICAL":
            self.logger.critical(msg)
        elif severity == "ERROR":
            self.logger.error(msg)
        elif severity == "WARNING":
            self.logger.warning(msg)
        else:
            self.logger.info(msg)


class SecurityLogger(StructuredLogger):
    def __init__(self, log_file="logs/security.log"):
        super().__init__("security", log_file)


class AccessLogger(StructuredLogger):
    def __init__(self, log_file="logs/access.log"):
        super().__init__("access", log_file)


security_log = SecurityLogger()
access_log = AccessLogger()
encrypted_storage = EncryptedStorage()

# Tracks login attempts per IP: {ip: [timestamp, ...]}
login_attempts = {}


def is_rate_limited(ip):
    now = time.time()
    attempts = login_attempts.get(ip, [])
    # Keep only attempts within the last 60 seconds
    attempts = [t for t in attempts if now - t < config.RATE_LIMIT_WINDOW]
    login_attempts[ip] = attempts
    if len(attempts) >= config.RATE_LIMIT_MAX:
        return True
    attempts.append(now)
    login_attempts[ip] = attempts
    return False


def decode_document_bytes(file_record, fallback_record=None):
    """Support binary-safe storage while remaining compatible with older text-only records."""
    encoding = file_record.get("content_encoding")
    if encoding is None and fallback_record is not None:
        encoding = fallback_record.get("content_encoding")
    if encoding == "base64":
        return base64.b64decode(file_record["data"])
    return file_record["data"].encode("utf-8")


def build_version_filename(filename, version_number):
    stem, ext = os.path.splitext(filename)
    return f"{stem}_v{version_number}{ext}"


def get_version_record(file_data, version_number):
    for version in file_data.get("versions", []):
        if version.get("version") == version_number:
            version_record = dict(version)
            version_record.setdefault(
                "content_encoding", file_data.get("content_encoding")
            )
            version_record.setdefault(
                "content_type",
                file_data.get("content_type", "application/octet-stream"),
            )
            return version_record
    return None


# --- RBAC decorators ---
from functools import wraps


def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not get_current_session():
            flash("Please log in first.")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


def require_role(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current = get_current_session()
            if not current or current["role"] != role:
                security_log.log_event(
                    "ACCESS_DENIED",
                    current["user_id"] if current else None,
                    {"resource": request.path, "required_role": role},
                    "WARNING",
                )
                return "Forbidden", 403
            return f(*args, **kwargs)

        return decorated_function

    return decorator


# --- end RBAC decorators ---


def load_users():
    if not os.path.exists(USERS_FILE):
        return []

    with open(USERS_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []


def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)


def validate_username(username):
    return re.fullmatch(r"^\w{3,20}$", username) is not None


def validate_email(email):
    return re.fullmatch(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email) is not None


def validate_password(password):
    if len(password) < 12:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*]", password):
        return False
    return True


def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode(
        "utf-8"
    )


def find_user_by_username(username):
    users = load_users()
    for user in users:
        if user["username"].lower() == username.lower():
            return user
    return None


SESSIONS_FILE = config.SESSIONS_FILE


def load_sessions():
    if not os.path.exists(SESSIONS_FILE):
        return {}

    with open(SESSIONS_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def save_sessions(sessions):
    with open(SESSIONS_FILE, "w") as f:
        json.dump(sessions, f, indent=4)


def update_user(updated_user):
    users = load_users()
    for i, user in enumerate(users):
        if user["id"] == updated_user["id"]:
            users[i] = updated_user
            break
    save_users(users)


def securely_delete_file(path):
    if not os.path.exists(path):
        return

    size = os.path.getsize(path)
    with open(path, "r+b") as f:
        f.write(os.urandom(size))
        f.flush()
        os.fsync(f.fileno())
    os.remove(path)


def ensure_tls_certificates(cert_path="cert.pem", key_path="key.pem"):
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CS 419 Secure App"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    with open(key_path, "wb") as key_file:
        key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(cert_path, "wb") as cert_file:
        cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))


def create_session(user):
    sessions = load_sessions()
    token = secrets.token_urlsafe(32)

    sessions[token] = {
        "user_id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "created_at": time.time(),
        "last_activity": time.time(),
    }

    save_sessions(sessions)
    return token


def destroy_session(token):
    sessions = load_sessions()
    if token in sessions:
        del sessions[token]
        save_sessions(sessions)


def get_current_session():
    token = session.get("session_token")
    if not token:
        return None

    sessions = load_sessions()
    session_data = sessions.get(token)

    if not session_data:
        return None

    # 30 minute timeout
    if time.time() - session_data["last_activity"] > config.SESSION_TIMEOUT:
        destroy_session(token)
        session.clear()
        return None

    session_data["last_activity"] = time.time()
    sessions[token] = session_data
    save_sessions(sessions)

    return session_data


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr
        if is_rate_limited(ip):
            security_log.log_event("RATE_LIMITED", None, {"ip": ip}, "WARNING")
            flash("Too many login attempts. Please wait a minute.")
            return redirect(url_for("login"))

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = find_user_by_username(username)

        if not user:
            security_log.log_event(
                "LOGIN_FAILED",
                None,
                {"username": username, "reason": "User not found"},
                "WARNING",
            )
            flash("Invalid username or password.")
            return redirect(url_for("login"))

        # Check if account is locked
        if user["locked_until"] is not None and time.time() < user["locked_until"]:
            security_log.log_event(
                "LOGIN_BLOCKED",
                user["id"],
                {"username": username, "reason": "Account locked"},
                "WARNING",
            )
            flash("Account is locked. Try again later.")
            return redirect(url_for("login"))

        if bcrypt.checkpw(
            password.encode("utf-8"), user["password_hash"].encode("utf-8")
        ):
            user["failed_attempts"] = 0
            user["locked_until"] = None
            update_user(user)

            token = create_session(user)
            session["session_token"] = token

            security_log.log_event("SESSION_CREATED", user["id"], {"username": username})
            access_log.log_event("LOGIN_SUCCESS", user["id"], {"username": username})
            flash("Login successful.")
            return redirect(url_for("dashboard"))

        else:
            user["failed_attempts"] += 1

            if user["failed_attempts"] >= config.MAX_FAILED_ATTEMPTS:
                user["locked_until"] = time.time() + config.LOCKOUT_DURATION
                security_log.log_event(
                    "ACCOUNT_LOCKED",
                    user["id"],
                    {"username": username, "reason": "5 failed login attempts"},
                    "ERROR",
                )
                flash("Account locked due to too many failed login attempts.")
            else:
                security_log.log_event(
                    "LOGIN_FAILED",
                    user["id"],
                    {"username": username, "reason": "Invalid password"},
                    "WARNING",
                )
                flash("Invalid username or password.")

            update_user(user)
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Validation checks
        if not validate_username(username):
            flash(
                "Username must be 3-20 characters and contain only letters, numbers, or underscores."
            )
            return redirect(url_for("register"))

        if not validate_email(email):
            flash("Please enter a valid email address.")
            return redirect(url_for("register"))

        if not validate_password(password):
            flash(
                "Password must be at least 12 characters and include uppercase, lowercase, number, and special character."
            )
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for("register"))

        users = load_users()

        # Duplicate checks
        for user in users:
            if user["username"].lower() == username.lower():
                flash("Username already exists.")
                return redirect(url_for("register"))
            if user["email"].lower() == email.lower():
                flash("Email already exists.")
                return redirect(url_for("register"))

        # Hash password
        hashed_password = hash_password(password)

        # Allow guest registration — guests get read-only access
        requested_role = request.form.get("role", "user")
        role = "guest" if requested_role == "guest" else "user"

        new_user = {
            "id": f"u{len(users) + 1}",
            "username": username,
            "email": email,
            "password_hash": hashed_password,
            "role": role,
            "failed_attempts": 0,
            "locked_until": None,
            "created_at": time.time(),
        }

        users.append(new_user)
        save_users(users)

        flash("Registration successful. You can now log in.")
        return redirect(url_for("home"))

    return render_template("register.html")


def get_user_documents(user_id):
    # Returns all docs the user owns or has been shared with
    documents = []
    for filename in os.listdir("data"):
        if filename.endswith(".enc"):
            try:
                file_data = encrypted_storage.load_encrypted(f"data/{filename}")
                is_owner = file_data.get("user_id") == user_id
                is_shared = user_id in file_data.get("shared_with", {})
                if is_owner or is_shared:
                    if "id" not in file_data:
                        file_data["id"] = filename.replace(".enc", "")
                    # Attach the user's role for use in templates
                    file_data["user_role"] = (
                        "owner" if is_owner else file_data["shared_with"][user_id]
                    )
                    documents.append(file_data)
            except Exception as e:
                security_log.log_event(
                    "FILE_LOAD_ERROR",
                    user_id,
                    {"filename": filename, "error": str(e)},
                    "ERROR",
                )
    return documents


def allowed_file(filename, mimetype):
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in config.ALLOWED_EXTENSIONS and mimetype in config.ALLOWED_MIME_TYPES


@app.route("/documents/upload", methods=["GET", "POST"])
@require_auth  # added: require login
def upload_document():
    current_session = get_current_session()

    if not current_session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    # Guests cannot upload documents
    if current_session["role"] == "guest":
        security_log.log_event(
            "ACCESS_DENIED",
            current_session["user_id"],
            {"resource": "/documents/upload", "reason": "Guest role cannot upload"},
            "WARNING",
        )
        flash("Guest accounts cannot upload documents.")
        return redirect(url_for("documents"))

    if request.method == "POST":
        # Encrypt and store the files
        file = request.files.get("file")
        target_doc_id = request.form.get("doc_id", "").strip()
        if file:
            # Validate extension and MIME type
            if not allowed_file(file.filename, file.mimetype):
                security_log.log_event(
                    "UPLOAD_REJECTED",
                    current_session["user_id"],
                    {
                        "filename": file.filename,
                        "mimetype": file.mimetype,
                        "reason": "Invalid file type",
                    },
                    "WARNING",
                )
                flash(
                    "File type not allowed. Allowed types: pdf, txt, docx, png, jpg, jpeg."
                )
                return redirect(url_for("upload_document"))
            # Validate file size
            file_data = file.read()
            if len(file_data) > config.MAX_FILE_SIZE:
                security_log.log_event(
                    "UPLOAD_REJECTED",
                    current_session["user_id"],
                    {"filename": file.filename, "reason": "File too large"},
                    "WARNING",
                )
                flash("File too large. Maximum size is 10 MB.")
                return redirect(url_for("upload_document"))
            # Check if a doc with the same filename already exists (for versioning)
            existing_doc = None
            existing_enc_path = None
            if target_doc_id:
                if not re.match(r"^[a-f0-9\-]{36}$", target_doc_id):
                    security_log.log_event(
                        "PATH_TRAVERSAL_ATTEMPT",
                        current_session["user_id"],
                        {"doc_id": target_doc_id},
                        "WARNING",
                    )
                    return "Bad request", 400

                base_dir = os.path.abspath("data")
                existing_enc_path = os.path.abspath(
                    os.path.join(base_dir, f"{target_doc_id}.enc")
                )
                if (
                    not existing_enc_path.startswith(base_dir)
                    or not os.path.exists(existing_enc_path)
                ):
                    flash("Document not found.")
                    return redirect(url_for("documents"))

                existing_doc = encrypted_storage.load_encrypted(existing_enc_path)
                user_id = current_session["user_id"]
                is_owner = existing_doc.get("user_id") == user_id
                is_admin = current_session["role"] == "admin"
                shared_role = existing_doc.get("shared_with", {}).get(user_id)
                if not is_owner and not is_admin and shared_role != "editor":
                    security_log.log_event(
                        "ACCESS_DENIED",
                        user_id,
                        {
                            "doc_id": target_doc_id,
                            "reason": "Insufficient document role for upload",
                        },
                        "WARNING",
                    )
                    flash("You do not have permission to upload a new version of this file.")
                    return redirect(url_for("documents"))

                current_ext = os.path.splitext(existing_doc["filename"])[1].lower()
                uploaded_ext = os.path.splitext(file.filename)[1].lower()
                if current_ext != uploaded_ext:
                    security_log.log_event(
                        "UPLOAD_REJECTED",
                        user_id,
                        {
                            "filename": file.filename,
                            "doc_id": target_doc_id,
                            "reason": "Replacement extension mismatch",
                        },
                        "WARNING",
                    )
                    flash(
                        f"Replacement uploads must use the same file type ({current_ext})."
                    )
                    return redirect(url_for("documents"))
            else:
                for fname in os.listdir("data"):
                    if fname.endswith(".enc"):
                        try:
                            d = encrypted_storage.load_encrypted(f"data/{fname}")
                            if (
                                d.get("user_id") == current_session["user_id"]
                                and d.get("filename") == file.filename
                            ):
                                existing_doc = d
                                existing_enc_path = f"data/{fname}"
                                break
                        except Exception:
                            pass

            if existing_doc:
                # Add current data as a previous version
                versions = existing_doc.get("versions", [])
                versions.append(
                    {
                        "version": existing_doc.get("version", 1),
                        "data": existing_doc["data"],
                        "content_encoding": existing_doc.get("content_encoding"),
                        "content_type": existing_doc.get(
                            "content_type", "application/octet-stream"
                        ),
                        "uploaded_at": existing_doc["uploaded_at"],
                        "uploaded_by": existing_doc.get(
                            "uploaded_by", existing_doc["user_id"]
                        ),
                    }
                )
                existing_doc["data"] = base64.b64encode(file_data).decode("ascii")
                existing_doc["uploaded_at"] = datetime.now().isoformat()
                existing_doc["uploaded_by"] = current_session["user_id"]
                existing_doc["version"] = existing_doc.get("version", 1) + 1
                existing_doc["versions"] = versions
                encrypted_storage.save_encrypted(existing_enc_path, existing_doc)
                doc_id = existing_doc["id"]
                access_log.log_event(
                    "FILE_VERSION_UPLOADED",
                    current_session["user_id"],
                    {
                        "filename": existing_doc["filename"],
                        "doc_id": doc_id,
                        "version": existing_doc["version"],
                    },
                )
                flash(
                    f"New version (v{existing_doc['version']}) uploaded successfully."
                )
            else:
                # Brand new document
                doc_id = str(uuid.uuid4())
                enc_filename = f"data/{doc_id}.enc"
                encrypted_storage.save_encrypted(
                    enc_filename,
                    {
                        "id": doc_id,
                        "filename": file.filename,
                        "data": base64.b64encode(file_data).decode("ascii"),
                        "content_encoding": "base64",
                        "content_type": file.mimetype or "application/octet-stream",
                        "user_id": current_session["user_id"],
                        "uploaded_at": datetime.now().isoformat(),
                        "uploaded_by": current_session["user_id"],
                        "shared_with": {},  # {user_id: "editor" or "viewer"}
                        "version": 1,
                        "versions": [],  # stores previous versions
                    },
                )
                access_log.log_event(
                    "FILE_UPLOADED",
                    current_session["user_id"],
                    {"filename": file.filename, "doc_id": doc_id},
                )
                flash("File uploaded and encrypted successfully.")

    return redirect(url_for("documents"))


@app.route("/documents/download/<doc_id>")
@require_auth  # added: require login
def download_document(doc_id):
    current_session = get_current_session()

    if not current_session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    # Guests cannot download documents
    if current_session["role"] == "guest":
        security_log.log_event(
            "ACCESS_DENIED",
            current_session["user_id"],
            {
                "resource": f"/documents/download/{doc_id}",
                "reason": "Guest role cannot download",
            },
            "WARNING",
        )
        flash("Guest accounts cannot download documents.")
        return redirect(url_for("documents"))

    # Path traversal prevention — ensure doc_id is a plain UUID with no path characters
    if not re.match(r"^[a-f0-9\-]{36}$", doc_id):
        security_log.log_event(
            "PATH_TRAVERSAL_ATTEMPT",
            current_session["user_id"],
            {"doc_id": doc_id},
            "WARNING",
        )
        return "Bad request", 400

    # Retrieve the encrypted file by document ID
    base_dir = os.path.abspath("data")
    enc_path = os.path.abspath(os.path.join(base_dir, f"{doc_id}.enc"))
    if not enc_path.startswith(base_dir):
        security_log.log_event(
            "PATH_TRAVERSAL_ATTEMPT",
            current_session["user_id"],
            {"doc_id": doc_id},
            "WARNING",
        )
        return "Bad request", 400

    if not os.path.exists(enc_path):
        flash("File not found.")
        return redirect(url_for("documents"))

    file_data = encrypted_storage.load_encrypted(enc_path)
    if not file_data:
        flash("File not found.")
        return redirect(url_for("documents"))

    # Check access — must be owner, editor, or admin (viewers cannot download)
    user_id = current_session["user_id"]
    is_owner = file_data.get("user_id") == user_id
    is_admin = current_session["role"] == "admin"
    shared_role = file_data.get("shared_with", {}).get(user_id)
    if not is_owner and not is_admin and shared_role != "editor":
        security_log.log_event(
            "ACCESS_DENIED",
            user_id,
            {"doc_id": doc_id, "reason": "Insufficient document role"},
            "WARNING",
        )
        flash("You do not have permission to download this file.")
        return redirect(url_for("documents"))

    # Return the file for download
    access_log.log_event(
        "FILE_DOWNLOADED",
        user_id,
        {"filename": file_data["filename"], "doc_id": doc_id},
    )
    from io import BytesIO

    return send_file(
        BytesIO(decode_document_bytes(file_data)),
        as_attachment=True,
        download_name=file_data["filename"],
        mimetype=file_data.get("content_type", "application/octet-stream"),
    )


@app.route("/documents/view/<doc_id>")
@require_auth
def view_document(doc_id):
    current_session = get_current_session()

    if not re.match(r"^[a-f0-9\-]{36}$", doc_id):
        security_log.log_event(
            "PATH_TRAVERSAL_ATTEMPT",
            current_session["user_id"],
            {"doc_id": doc_id},
            "WARNING",
        )
        return "Bad request", 400

    base_dir = os.path.abspath("data")
    enc_path = os.path.abspath(os.path.join(base_dir, f"{doc_id}.enc"))
    if not enc_path.startswith(base_dir):
        security_log.log_event(
            "PATH_TRAVERSAL_ATTEMPT",
            current_session["user_id"],
            {"doc_id": doc_id},
            "WARNING",
        )
        return "Bad request", 400

    if not os.path.exists(enc_path):
        flash("File not found.")
        return redirect(url_for("documents"))

    file_data = encrypted_storage.load_encrypted(enc_path)
    user_id = current_session["user_id"]
    is_owner = file_data.get("user_id") == user_id
    is_admin = current_session["role"] == "admin"
    is_shared = user_id in file_data.get("shared_with", {})
    if not is_owner and not is_admin and not is_shared:
        security_log.log_event(
            "ACCESS_DENIED",
            user_id,
            {"doc_id": doc_id, "reason": "Not authorized to view document"},
            "WARNING",
        )
        flash("You do not have access to this document.")
        return redirect(url_for("documents"))

    access_log.log_event(
        "FILE_VIEWED", user_id, {"filename": file_data["filename"], "doc_id": doc_id}
    )
    from io import BytesIO

    return send_file(
        BytesIO(decode_document_bytes(file_data)),
        as_attachment=False,
        download_name=file_data["filename"],
        mimetype=file_data.get("content_type", "application/octet-stream"),
    )


@app.route("/documents/share/<doc_id>", methods=["POST"])
@require_auth  # added: require login — share a document with another user
def share_document(doc_id):
    current_session = get_current_session()

    # Validate doc_id format
    if not re.match(r"^[a-f0-9\-]{36}$", doc_id):
        return "Bad request", 400

    base_dir = os.path.abspath("data")
    enc_path = os.path.abspath(os.path.join(base_dir, f"{doc_id}.enc"))
    if not enc_path.startswith(base_dir) or not os.path.exists(enc_path):
        flash("Document not found.")
        return redirect(url_for("documents"))

    file_data = encrypted_storage.load_encrypted(enc_path)

    # Only the owner can share
    if file_data.get("user_id") != current_session["user_id"]:
        security_log.log_event(
            "ACCESS_DENIED",
            current_session["user_id"],
            {"doc_id": doc_id, "reason": "Only owner can share"},
            "WARNING",
        )
        flash("Only the document owner can share it.")
        return redirect(url_for("documents"))

    target_username = request.form.get("username", "").strip()
    role = request.form.get("role", "viewer")

    if role not in ("editor", "viewer"):
        flash("Invalid role. Choose editor or viewer.")
        return redirect(url_for("documents"))

    target_user = find_user_by_username(target_username)
    if not target_user:
        flash(f"User '{target_username}' not found.")
        return redirect(url_for("documents"))

    if target_user["id"] == current_session["user_id"]:
        flash("You cannot share a document with yourself.")
        return redirect(url_for("documents"))

    # Update shared_with and save
    if "shared_with" not in file_data:
        file_data["shared_with"] = {}
    file_data["shared_with"][target_user["id"]] = role
    encrypted_storage.save_encrypted(enc_path, file_data)

    access_log.log_event(
        "DOCUMENT_SHARED",
        current_session["user_id"],
        {"doc_id": doc_id, "shared_with": target_user["id"], "role": role},
    )
    flash(f"Document shared with {target_username} as {role}.")
    return redirect(url_for("documents"))


@app.route("/documents/delete/<doc_id>", methods=["POST"])
@require_auth
def delete_document(doc_id):
    current_session = get_current_session()

    if not re.match(r"^[a-f0-9\-]{36}$", doc_id):
        security_log.log_event(
            "PATH_TRAVERSAL_ATTEMPT",
            current_session["user_id"],
            {"doc_id": doc_id},
            "WARNING",
        )
        return "Bad request", 400

    base_dir = os.path.abspath("data")
    enc_path = os.path.abspath(os.path.join(base_dir, f"{doc_id}.enc"))
    if not enc_path.startswith(base_dir):
        security_log.log_event(
            "PATH_TRAVERSAL_ATTEMPT",
            current_session["user_id"],
            {"doc_id": doc_id},
            "WARNING",
        )
        return "Bad request", 400

    if not os.path.exists(enc_path):
        flash("Document not found.")
        return redirect(url_for("documents"))

    file_data = encrypted_storage.load_encrypted(enc_path)
    is_owner = file_data.get("user_id") == current_session["user_id"]
    is_admin = current_session["role"] == "admin"
    if not is_owner and not is_admin:
        security_log.log_event(
            "ACCESS_DENIED",
            current_session["user_id"],
            {"doc_id": doc_id, "reason": "Only owner or admin can delete"},
            "WARNING",
        )
        flash("Only the document owner can delete it.")
        return redirect(url_for("documents"))

    securely_delete_file(enc_path)
    access_log.log_event(
        "DOCUMENT_DELETED",
        current_session["user_id"],
        {"doc_id": doc_id, "filename": file_data["filename"]},
    )
    flash("Document deleted successfully.")
    return redirect(url_for("documents"))


# --- Version history route added here ---
@app.route("/documents/versions/<doc_id>")
@require_auth
def document_versions(doc_id):
    current_session = get_current_session()

    if not re.match(r"^[a-f0-9\-]{36}$", doc_id):
        return "Bad request", 400

    base_dir = os.path.abspath("data")
    enc_path = os.path.abspath(os.path.join(base_dir, f"{doc_id}.enc"))
    if not enc_path.startswith(base_dir) or not os.path.exists(enc_path):
        flash("Document not found.")
        return redirect(url_for("documents"))

    file_data = encrypted_storage.load_encrypted(enc_path)

    # Must be owner, shared user, or admin to view versions
    user_id = current_session["user_id"]
    is_owner = file_data.get("user_id") == user_id
    is_admin = current_session["role"] == "admin"
    shared_role = file_data.get("shared_with", {}).get(user_id)
    is_shared = shared_role is not None
    if not is_owner and not is_admin and not is_shared:
        security_log.log_event(
            "ACCESS_DENIED",
            user_id,
            {"doc_id": doc_id, "reason": "Not authorized to view versions"},
            "WARNING",
        )
        flash("You do not have access to this document.")
        return redirect(url_for("documents"))

    access_log.log_event("DOCUMENT_VERSIONS_ACCESSED", user_id, {"doc_id": doc_id})
    versions = file_data.get("versions", [])
    return render_template(
        "versions.html",
        filename=file_data["filename"],
        current_version=file_data.get("version", 1),
        current_uploaded_at=file_data["uploaded_at"],
        versions=versions,
        doc_id=doc_id,
        can_download=is_owner or shared_role == "editor",
        can_restore=is_owner,
    )


# --- end version history route ---


@app.route("/documents/versions/<doc_id>/download/<int:version_number>")
@require_auth
def download_document_version(doc_id, version_number):
    current_session = get_current_session()

    if not re.match(r"^[a-f0-9\-]{36}$", doc_id):
        security_log.log_event(
            "PATH_TRAVERSAL_ATTEMPT",
            current_session["user_id"],
            {"doc_id": doc_id},
            "WARNING",
        )
        return "Bad request", 400

    base_dir = os.path.abspath("data")
    enc_path = os.path.abspath(os.path.join(base_dir, f"{doc_id}.enc"))
    if not enc_path.startswith(base_dir) or not os.path.exists(enc_path):
        flash("Document not found.")
        return redirect(url_for("documents"))

    file_data = encrypted_storage.load_encrypted(enc_path)
    user_id = current_session["user_id"]
    is_owner = file_data.get("user_id") == user_id
    is_admin = current_session["role"] == "admin"
    shared_role = file_data.get("shared_with", {}).get(user_id)
    if not is_owner and not is_admin and shared_role != "editor":
        security_log.log_event(
            "ACCESS_DENIED",
            user_id,
            {"doc_id": doc_id, "reason": "Not authorized to download previous version"},
            "WARNING",
        )
        flash("You do not have permission to download this version.")
        return redirect(url_for("document_versions", doc_id=doc_id))

    version_record = get_version_record(file_data, version_number)
    if not version_record:
        flash("Version not found.")
        return redirect(url_for("document_versions", doc_id=doc_id))

    access_log.log_event(
        "FILE_VERSION_DOWNLOADED",
        user_id,
        {
            "filename": file_data["filename"],
            "doc_id": doc_id,
            "version": version_number,
        },
    )
    from io import BytesIO

    return send_file(
        BytesIO(decode_document_bytes(version_record, file_data)),
        as_attachment=True,
        download_name=build_version_filename(file_data["filename"], version_number),
        mimetype=version_record.get(
            "content_type", file_data.get("content_type", "application/octet-stream")
        ),
    )


@app.route(
    "/documents/versions/<doc_id>/restore/<int:version_number>", methods=["POST"]
)
@require_auth
def restore_document_version(doc_id, version_number):
    current_session = get_current_session()

    if not re.match(r"^[a-f0-9\-]{36}$", doc_id):
        security_log.log_event(
            "PATH_TRAVERSAL_ATTEMPT",
            current_session["user_id"],
            {"doc_id": doc_id},
            "WARNING",
        )
        return "Bad request", 400

    base_dir = os.path.abspath("data")
    enc_path = os.path.abspath(os.path.join(base_dir, f"{doc_id}.enc"))
    if not enc_path.startswith(base_dir) or not os.path.exists(enc_path):
        flash("Document not found.")
        return redirect(url_for("documents"))

    file_data = encrypted_storage.load_encrypted(enc_path)
    user_id = current_session["user_id"]
    if file_data.get("user_id") != user_id:
        security_log.log_event(
            "ACCESS_DENIED",
            user_id,
            {"doc_id": doc_id, "reason": "Only owner can restore version"},
            "WARNING",
        )
        flash("Only the document owner can restore previous versions.")
        return redirect(url_for("document_versions", doc_id=doc_id))

    version_record = get_version_record(file_data, version_number)
    if not version_record:
        flash("Version not found.")
        return redirect(url_for("document_versions", doc_id=doc_id))

    current_version = file_data.get("version", 1)
    versions = file_data.get("versions", [])
    versions.append(
        {
            "version": current_version,
            "data": file_data["data"],
            "content_encoding": file_data.get("content_encoding"),
            "content_type": file_data.get("content_type", "application/octet-stream"),
            "uploaded_at": file_data["uploaded_at"],
            "uploaded_by": file_data.get("uploaded_by", file_data["user_id"]),
        }
    )

    file_data["data"] = version_record["data"]
    file_data["content_encoding"] = version_record.get("content_encoding")
    file_data["content_type"] = version_record.get(
        "content_type", file_data.get("content_type", "application/octet-stream")
    )
    file_data["uploaded_at"] = datetime.now().isoformat()
    file_data["uploaded_by"] = user_id
    file_data["version"] = current_version + 1
    file_data["versions"] = versions

    encrypted_storage.save_encrypted(enc_path, file_data)
    access_log.log_event(
        "FILE_VERSION_RESTORED",
        user_id,
        {
            "filename": file_data["filename"],
            "doc_id": doc_id,
            "restored_from": version_number,
            "version": file_data["version"],
        },
    )
    flash(f"Version v{version_number} restored as the current document.")
    return redirect(url_for("document_versions", doc_id=doc_id))


@app.route("/documents")
@require_auth  # added: require login
def documents():
    current_session = get_current_session()

    if not current_session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    access_log.log_event("DOCUMENTS_ACCESSED", current_session["user_id"], {})
    return render_template(
        "documents.html",
        username=current_session["username"],
        documents=get_user_documents(current_session["user_id"]),
        role=current_session["role"],
    )


# --- Admin routes added here ---
@app.route("/admin/dashboard")
@require_auth
@require_role("admin")
def admin_dashboard():
    current_session = get_current_session()
    all_users = load_users()

    # Load all documents across all users
    all_documents = []
    for filename in os.listdir("data"):
        if filename.endswith(".enc"):
            try:
                doc = encrypted_storage.load_encrypted(f"data/{filename}")
                all_documents.append(doc)
            except Exception as e:
                security_log.log_event(
                    "FILE_LOAD_ERROR",
                    current_session["user_id"],
                    {"filename": filename, "error": str(e)},
                    "ERROR",
                )

    access_log.log_event("ADMIN_DASHBOARD_ACCESS", current_session["user_id"], {})
    return render_template(
        "admin.html",
        username=current_session["username"],
        users=all_users,
        documents=all_documents,
        now=time.time(),
    )


@app.route("/admin/users/<user_id>/lock", methods=["POST"])
@require_auth
@require_role("admin")
def admin_lock_user(user_id):
    current_session = get_current_session()
    users = load_users()

    target = next((u for u in users if u["id"] == user_id), None)
    if not target:
        flash("User not found.")
        return redirect(url_for("admin_dashboard"))

    action = request.form.get("action")
    if action == "lock":
        target["locked_until"] = time.time() + config.LOCKOUT_DURATION
        security_log.log_event(
            "ADMIN_USER_LOCKED",
            current_session["user_id"],
            {"target_user": user_id},
            "WARNING",
        )
        flash(f"User {target['username']} has been locked.")
    elif action == "unlock":
        target["locked_until"] = None
        target["failed_attempts"] = 0
        security_log.log_event(
            "ADMIN_USER_UNLOCKED", current_session["user_id"], {"target_user": user_id}
        )
        flash(f"User {target['username']} has been unlocked.")

    save_users(users)
    return redirect(url_for("admin_dashboard"))


# --- end admin routes ---


@app.route("/dashboard")
@require_auth  # added: require login
def dashboard():
    current_session = get_current_session()

    if not current_session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    access_log.log_event("DASHBOARD_ACCESSED", current_session["user_id"], {})
    return render_template(
        "dashboard.html",
        username=current_session["username"],
        role=current_session["role"],
    )


@app.route("/change-password", methods=["POST"])
@require_auth
def change_password():
    current_session = get_current_session()
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    user = find_user_by_username(current_session["username"])
    if not user:
        flash("User not found.")
        return redirect(url_for("dashboard"))

    if not bcrypt.checkpw(
        current_password.encode("utf-8"), user["password_hash"].encode("utf-8")
    ):
        security_log.log_event(
            "PASSWORD_CHANGE_FAILED",
            user["id"],
            {"reason": "Invalid current password"},
            "WARNING",
        )
        flash("Current password is incorrect.")
        return redirect(url_for("dashboard"))

    if not validate_password(new_password):
        security_log.log_event(
            "PASSWORD_CHANGE_FAILED",
            user["id"],
            {"reason": "Password policy validation failed"},
            "WARNING",
        )
        flash(
            "New password must be at least 12 characters and include uppercase, lowercase, number, and special character."
        )
        return redirect(url_for("dashboard"))

    if new_password != confirm_password:
        security_log.log_event(
            "PASSWORD_CHANGE_FAILED",
            user["id"],
            {"reason": "Passwords do not match"},
            "WARNING",
        )
        flash("New passwords do not match.")
        return redirect(url_for("dashboard"))

    if bcrypt.checkpw(
        new_password.encode("utf-8"), user["password_hash"].encode("utf-8")
    ):
        security_log.log_event(
            "PASSWORD_CHANGE_FAILED",
            user["id"],
            {"reason": "New password matches current password"},
            "WARNING",
        )
        flash("New password must be different from the current password.")
        return redirect(url_for("dashboard"))

    user["password_hash"] = hash_password(new_password)
    update_user(user)
    security_log.log_event("PASSWORD_CHANGED", user["id"], {})
    flash("Password changed successfully.")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    current_session = get_current_session()
    token = session.get("session_token")
    if token:
        destroy_session(token)

    if current_session:
        security_log.log_event("SESSION_DESTROYED", current_session["user_id"], {})
        access_log.log_event("LOGOUT", current_session["user_id"], {})

    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("home"))


@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    return response


@app.before_request
def require_https():
    forwarded_proto = request.headers.get("X-Forwarded-Proto", "")
    is_https = request.is_secure or forwarded_proto == "https"
    if not is_https and not app.debug and not app.testing:
        url = request.url.replace("http://", "https://", 1)
        return redirect(url, code=301)


os.makedirs("data", exist_ok=True)
os.makedirs("logs", exist_ok=True)

if __name__ == "__main__":
    ensure_tls_certificates()
    app.run(ssl_context=("cert.pem", "key.pem"), host="0.0.0.0", port=5000)
