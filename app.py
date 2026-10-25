import os
import re
import sqlite3
from pathlib import Path

from dotenv import load_dotenv
from flask import (
    Flask, abort, flash, g, redirect, render_template,
    request, session, url_for
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR / "auth_lab.db"


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.getenv("SECRET_KEY", ""),
        DATABASE=os.getenv("DATABASE_PATH", str(DEFAULT_DB)),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",
        PERMANENT_SESSION_LIFETIME=1800,
        MAX_CONTENT_LENGTH=16 * 1024,
        WTF_CSRF_TIME_LIMIT=3600,
        RATELIMIT_STORAGE_URI=os.getenv(
            "RATELIMIT_STORAGE_URI", "memory://"
        ),
    )
    if test_config:
        app.config.update(test_config)

    if not app.config["SECRET_KEY"]:
        raise RuntimeError(
            "SECRET_KEY is missing. Copy .env.example to .env and set "
            "a random secret, or export SECRET_KEY in your environment."
        )

    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)

    CSRFProtect(app)
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=[],
        storage_uri=app.config["RATELIMIT_STORAGE_URI"],
    )

    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
        return g.db

    @app.teardown_appcontext
    def close_db(_error=None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def init_db():
        db = get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.commit()

    with app.app_context():
        init_db()

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; "
            "img-src 'self' data:; form-action 'self'; "
            "frame-ancestors 'none'; base-uri 'self'"
        )
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.get("/")
    def index():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    @limiter.limit("5 per minute", methods=["POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
                flash(
                    "Use 3–32 characters: letters, numbers, dot, underscore, or hyphen.",
                    "error",
                )
            elif len(password) < 12:
                flash("Password must be at least 12 characters.", "error")
            elif len(password) > 1024:
                flash("Password is too long.", "error")
            elif password != confirm_password:
                flash("Passwords do not match.", "error")
            else:
                password_hash = generate_password_hash(password)
                try:
                    db = get_db()
                    db.execute(
                        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                        (username, password_hash),
                    )
                    db.commit()
                except sqlite3.IntegrityError:
                    flash("That username is already registered.", "error")
                else:
                    flash("Account created. You can now sign in.", "success")
                    return redirect(url_for("login"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("5 per minute", methods=["POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            db = get_db()
            user = db.execute(
                "SELECT id, username, password_hash FROM users "
                "WHERE username = ? COLLATE NOCASE",
                (username,),
            ).fetchone()

            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session.permanent = True
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                flash("Signed in successfully.", "success")
                return redirect(url_for("dashboard"))

            # Same response for unknown username and wrong password.
            flash("Invalid username or password.", "error")

        return render_template("login.html")

    @app.get("/dashboard")
    def dashboard():
        if not session.get("user_id"):
            abort(401)
        return render_template(
            "dashboard.html", username=session.get("username", "User")
        )

    @app.post("/logout")
    def logout():
        session.clear()
        flash("You have been signed out.", "success")
        return redirect(url_for("login"))

    @app.errorhandler(401)
    def unauthorized(_error):
        return render_template("401.html"), 401

    @app.errorhandler(413)
    def request_too_large(_error):
        return render_template("error.html", code=413,
                               message="Request payload is too large."), 413

    @app.errorhandler(429)
    def rate_limited(_error):
        return render_template("error.html", code=429,
                               message="Too many attempts. Wait a minute and try again."), 429

    return app


app = create_app()

if __name__ == "__main__":
    # Local-only development server. Do not use Flask's dev server in production.
    app.run(host="127.0.0.1", port=5000, debug=False)
