import os
import secrets

# Flask secret key — loaded from environment, falls back to a random key per process
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Session cookie security flags
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = "Strict"

# File storage paths
USERS_FILE = "data/users.json"
SESSIONS_FILE = "data/sessions.json"

# File upload restrictions
ALLOWED_EXTENSIONS = {'pdf', 'txt', 'docx', 'png', 'jpg', 'jpeg'}
ALLOWED_MIME_TYPES = {
    'application/pdf',
    'text/plain',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'image/png',
    'image/jpeg',
}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# Session timeout in seconds (30 minutes)
SESSION_TIMEOUT = 1800

# Account lockout settings
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 15 * 60  # 15 minutes

# Rate limiting: max login attempts per IP per window
RATE_LIMIT_MAX = 10
RATE_LIMIT_WINDOW = 60  # seconds
