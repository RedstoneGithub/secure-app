from flask import Flask, render_template, request, redirect, url_for, flash, session
import json
import os
import time
import re
import bcrypt
import secrets


app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-change-this-later"
USERS_FILE = "data/users.json"


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


def find_user_by_username(username):
    users = load_users()
    for user in users:
        if user["username"].lower() == username.lower():
            return user
    return None

SESSIONS_FILE = "data/sessions.json"


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
    
def create_session(user):
    sessions = load_sessions()
    token = secrets.token_urlsafe(32)

    sessions[token] = {
        "user_id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "created_at": time.time(),
        "last_activity": time.time()
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
    if time.time() - session_data["last_activity"] > 1800:
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
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = find_user_by_username(username)

        if not user:
            flash("Invalid username or password.")
            return redirect(url_for("login"))

        # Check if account is locked
        if user["locked_until"] is not None and time.time() < user["locked_until"]:
            flash("Account is locked. Try again later.")
            return redirect(url_for("login"))

        if bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
            # Reset failed attempts
            user["failed_attempts"] = 0
            user["locked_until"] = None
            update_user(user)

            # Create JSON-backed session
            token = create_session(user)
            session["session_token"] = token

            flash("Login successful.")
            return redirect(url_for("dashboard"))

        else:
            user["failed_attempts"] += 1

            if user["failed_attempts"] >= 5:
                user["locked_until"] = time.time() + (15 * 60)
                flash("Account locked due to too many failed login attempts.")
            else:
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
            flash("Username must be 3-20 characters and contain only letters, numbers, or underscores.")
            return redirect(url_for("register"))

        if not validate_email(email):
            flash("Please enter a valid email address.")
            return redirect(url_for("register"))

        if not validate_password(password):
            flash("Password must be at least 12 characters and include uppercase, lowercase, number, and special character.")
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
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")

        new_user = {
            "id": f"u{len(users) + 1}",
            "username": username,
            "email": email,
            "password_hash": hashed_password,
            "role": "user",
            "failed_attempts": 0,
            "locked_until": None,
            "created_at": time.time()
        }

        users.append(new_user)
        save_users(users)

        flash("Registration successful. You can now log in.")
        return redirect(url_for("home"))

    return render_template("register.html")


@app.route("/dashboard")
def dashboard():
    current_session = get_current_session()

    if not current_session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    return render_template("dashboard.html", username=current_session["username"])

@app.route("/logout")
def logout():
    token = session.get("session_token")
    if token:
        destroy_session(token)

    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)