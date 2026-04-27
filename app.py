import hashlib
import sqlite3
import time
import re
from datetime import datetime
from functools import wraps
from pathlib import Path
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature


from cryptography.fernet import Fernet, InvalidToken
from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "security_app.db"
UPLOAD_DIR = BASE_DIR / "uploads"
ENCRYPTED_DIR = BASE_DIR / "encrypted"

for folder in (UPLOAD_DIR, ENCRYPTED_DIR):
    folder.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-secret-key"
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])





SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    phone TEXT,
    organization TEXT,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    document_title TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    encrypted_path TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    aes_key TEXT NOT NULL,
    blockchain_tx_hash TEXT NOT NULL,
    uploaded_at TEXT NOT NULL,
    key_generation_time REAL NOT NULL,
    encryption_time REAL NOT NULL,
    decryption_time REAL NOT NULL,
    response_time REAL NOT NULL,
    computational_overhead REAL NOT NULL,
    total_change_rate REAL NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS training_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    epoch INTEGER NOT NULL,
    accuracy REAL NOT NULL,
    loss REAL NOT NULL,
    precision_score REAL NOT NULL,
    recall_score REAL NOT NULL,
    f1_score REAL NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decryption_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    file_id INTEGER NOT NULL,
    request_message TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    admin_response TEXT,
    decryption_key TEXT,
    created_at TEXT NOT NULL,
    reviewed_at TEXT,
    reviewed_by INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(file_id) REFERENCES uploads(id),
    FOREIGN KEY(reviewed_by) REFERENCES users(id)
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(SCHEMA_SQL)

    admin = db.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()
    if admin is None:
        db.execute(
            """
            INSERT INTO users (full_name, email, username, password_hash, phone, organization, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "System Admin",
                "admin@example.com",
                "admin",
                generate_password_hash("admin123"),
                "0000000000",
                "Security Lab",
                "admin",
                datetime.utcnow().isoformat(),
            ),
        )

    metrics_count = db.execute("SELECT COUNT(*) AS c FROM training_metrics").fetchone()[0]
    if metrics_count == 0:
        rows = [
            (1, 0.71, 1.12, 0.70, 0.68, 0.69),
            (2, 0.75, 0.97, 0.74, 0.72, 0.73),
            (3, 0.80, 0.84, 0.79, 0.77, 0.78),
            (4, 0.84, 0.71, 0.83, 0.82, 0.82),
            (5, 0.88, 0.59, 0.87, 0.85, 0.86),
            (6, 0.91, 0.48, 0.90, 0.89, 0.89),
        ]
        for epoch, acc, loss, prec, rec, f1 in rows:
            db.execute(
                """
                INSERT INTO training_metrics (epoch, accuracy, loss, precision_score, recall_score, f1_score, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (epoch, acc, loss, prec, rec, f1, datetime.utcnow().isoformat()),
            )

    db.commit()
    db.close()


def log_action(actor, action, details):
    db = get_db()
    db.execute(
        "INSERT INTO logs (actor, action, details, created_at) VALUES (?, ?, ?, ?)",
        (actor, action, details, datetime.utcnow().isoformat()),
    )
    db.commit()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def role_required(role):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if session.get("role") != role:
                flash("Access denied.", "danger")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)

        return wrapped

    return decorator


def calculate_blockchain_hash(filename, encrypted_bytes, user_id):
    payload = f"{filename}|{user_id}|{time.time()}".encode("utf-8") + encrypted_bytes
    return hashlib.sha256(payload).hexdigest()


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form["full_name"].strip()
        email = request.form["email"].strip()
        username = request.form["username"].strip()
        password = request.form["password"]
        phone = request.form["phone"].strip()
        organization = request.form["organization"].strip()

        # Check all fields
        if not all([full_name, email, username, password, phone, organization]):
            flash("All 6 fields are required.", "danger")
            return render_template("register.html")

        # Phone validation (exactly 10 digits)
        if not re.fullmatch(r"\d{10}", phone):
            flash("Phone number must be exactly 10 digits.", "danger")
            return render_template("register.html")

        db = get_db()

        # Check if username or email already exists
        exists = db.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, email)
        ).fetchone()

        if exists:
            flash("Username or Email already exists.", "danger")
            return render_template("register.html")

        # Insert new user
        db.execute(
            """INSERT INTO users
            (full_name, email, username, password_hash, phone, organization, role, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
           (
                full_name,
                email,
                username,
                generate_password_hash(password),
                phone,
                organization,
                "user",
                 datetime.utcnow().isoformat(),
            ),
        )
        db.commit()

        flash("Registration successful. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user is None or not check_password_hash(user['password_hash'], password):
            flash("Invalid credentials.", "danger")
            return render_template("login.html")

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        log_action(user["username"], "login", f"Role: {user['role']}")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    username = session.get("username", "anonymous")
    session.clear()
    db = get_db()
    db.execute(
        "INSERT INTO logs (actor, action, details, created_at) VALUES (?, ?, ?, ?)",
        (username, "logout", "Session ended", datetime.utcnow().isoformat()),
    )
    db.commit()
    flash("Logged out.", "success")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user_count = db.execute("SELECT COUNT(*) AS c FROM users WHERE role = 'user'").fetchone()["c"]
    upload_count = db.execute("SELECT COUNT(*) AS c FROM uploads").fetchone()["c"]
    metric_count = db.execute("SELECT COUNT(*) AS c FROM training_metrics").fetchone()["c"]
    latest_logs = db.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 8").fetchall()

    if session["role"] == "admin":
        uploads = db.execute(
            """
            SELECT uploads.*, users.username
            FROM uploads
            JOIN users ON users.id = uploads.user_id
            ORDER BY uploads.id DESC
            LIMIT 10
            """
        ).fetchall()
        return render_template(
            "admin_dashboard.html",
            user_count=user_count,
            upload_count=upload_count,
            metric_count=metric_count,
            uploads=uploads,
            logs=latest_logs,
        )

    my_uploads = db.execute(
        "SELECT * FROM uploads WHERE user_id = ? ORDER BY id DESC LIMIT 10", (session["user_id"],)
    ).fetchall()
    profile = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    return render_template(
        "user_dashboard.html",
        upload_count=upload_count,
        metric_count=metric_count,
        my_uploads=my_uploads,
        profile=profile,
        logs=latest_logs,
    )


@app.route("/admin/upload", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_upload():
    if request.method == "POST":
        title = request.form.get("document_title", "").strip()
        file = request.files.get("document")

        if not title or file is None or file.filename == "":
            flash("Document title and file are required.", "danger")
            return render_template("admin_upload.html")

        filename = secure_filename(file.filename)
        raw_bytes = file.read()
        if not raw_bytes:
            flash("Empty file is not allowed.", "danger")
            return render_template("admin_upload.html")

        start = time.perf_counter()
        key_start = time.perf_counter()
        fernet_key = Fernet.generate_key()
        key_generation_time = time.perf_counter() - key_start

        enc_start = time.perf_counter()
        cipher = Fernet(fernet_key)
        encrypted_bytes = cipher.encrypt(raw_bytes)
        encryption_time = time.perf_counter() - enc_start

        dec_start = time.perf_counter()
        _ = cipher.decrypt(encrypted_bytes)
        decryption_time = time.perf_counter() - dec_start

        file_hash = hashlib.sha256(raw_bytes).hexdigest()
        tx_hash = calculate_blockchain_hash(filename, encrypted_bytes, session["user_id"])
        encrypted_name = f"{int(time.time())}_{filename}.enc"
        encrypted_path = ENCRYPTED_DIR / encrypted_name
        encrypted_path.write_bytes(encrypted_bytes)

        response_time = time.perf_counter() - start
        computational_overhead = key_generation_time + encryption_time + decryption_time
        total_change_rate = (len(encrypted_bytes) - len(raw_bytes)) / max(len(raw_bytes), 1)

        db = get_db()
        db.execute(
            """
            INSERT INTO uploads (
                user_id, document_title, original_filename, encrypted_path, file_hash,
                file_size, aes_key, blockchain_tx_hash, uploaded_at,
                key_generation_time, encryption_time, decryption_time,
                response_time, computational_overhead, total_change_rate
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session["user_id"],
                title,
                filename,
                str(encrypted_path),
                file_hash,
                len(raw_bytes),
                fernet_key.decode("utf-8"),
                tx_hash,
                datetime.utcnow().isoformat(),
                key_generation_time,
                encryption_time,
                decryption_time,
                response_time,
                computational_overhead,
                total_change_rate,
            ),
        )
        db.commit()
        log_action(session["username"], "upload", f"Uploaded '{title}' as encrypted object")
        flash("File uploaded, encrypted (AES/Fernet), and blockchain hash recorded.", "success")
        return redirect(url_for("admin_files"))

    return render_template("admin_upload.html")


@app.route("/admin/files")
@login_required
@role_required("admin")
def admin_files():
    db = get_db()
    rows = db.execute(
        """
        SELECT uploads.*, users.username
        FROM uploads
        JOIN users ON users.id = uploads.user_id
        ORDER BY uploads.id DESC
        """
    ).fetchall()
    return render_template("admin_files.html", rows=rows)


@app.route("/admin/reports")
@login_required
@role_required("admin")
def admin_reports():
    db = get_db()
    metrics = db.execute("SELECT * FROM training_metrics ORDER BY epoch ASC").fetchall()
    perf = db.execute(
        """
        SELECT id, document_title, uploaded_at, file_size,
               key_generation_time, encryption_time, decryption_time,
               response_time, computational_overhead, total_change_rate
        FROM uploads
        ORDER BY id DESC
        """
    ).fetchall()
    return render_template("reports.html", metrics=metrics, perf=perf, page_title="Admin Performance Reports")


@app.route("/admin/logs")
@login_required
@role_required("admin")
def admin_logs():
    db = get_db()
    rows = db.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 200").fetchall()
    return render_template("logs.html", rows=rows, page_title="Distributed Training Logs")


@app.route("/admin/requests")
@login_required
@role_required("admin")
def admin_requests():
    db = get_db()
    rows = db.execute(
        """
        SELECT dr.*, u.username AS requester_name, up.document_title, up.original_filename
        FROM decryption_requests dr
        JOIN users u ON u.id = dr.user_id
        JOIN uploads up ON up.id = dr.file_id
        ORDER BY
            CASE dr.status
                WHEN 'pending' THEN 0
                WHEN 'approved' THEN 1
                ELSE 2
            END,
            dr.id DESC
        """
    ).fetchall()
    return render_template("admin_requests.html", rows=rows)


@app.route("/admin/requests/<int:request_id>/action", methods=["POST"])
@login_required
@role_required("admin")
def admin_request_action(request_id):
    decision = request.form.get("decision", "").strip().lower()
    admin_response = request.form.get("admin_response", "").strip()
    if decision not in {"approve", "reject"}:
        flash("Invalid action.", "danger")
        return redirect(url_for("admin_requests"))

    db = get_db()
    req = db.execute("SELECT * FROM decryption_requests WHERE id = ?", (request_id,)).fetchone()
    if req is None:
        flash("Request not found.", "danger")
        return redirect(url_for("admin_requests"))

    if req["status"] != "pending":
        flash("This request was already reviewed.", "danger")
        return redirect(url_for("admin_requests"))

    now = datetime.utcnow().isoformat()
    if decision == "approve":
        upload = db.execute("SELECT aes_key FROM uploads WHERE id = ?", (req["file_id"],)).fetchone()
        if upload is None:
            flash("Linked file not found.", "danger")
            return redirect(url_for("admin_requests"))
        db.execute(
            """
            UPDATE decryption_requests
            SET status = 'approved',
                admin_response = ?,
                decryption_key = ?,
                reviewed_at = ?,
                reviewed_by = ?
            WHERE id = ?
            """,
            (admin_response or "Approved by admin.", upload["aes_key"], now, session["user_id"], request_id),
        )
        db.commit()
        log_action(session["username"], "request_approved", f"Approved key request id {request_id}")
        flash("Request approved and decryption key shared.", "success")
    else:
        db.execute(
            """
            UPDATE decryption_requests
            SET status = 'rejected',
                admin_response = ?,
                decryption_key = NULL,
                reviewed_at = ?,
                reviewed_by = ?
            WHERE id = ?
            """,
            (admin_response or "Rejected by admin.", now, session["user_id"], request_id),
        )
        db.commit()
        log_action(session["username"], "request_rejected", f"Rejected key request id {request_id}")
        flash("Request rejected.", "success")

    return redirect(url_for("admin_requests"))


@app.route("/user/search", methods=["GET", "POST"])
@login_required
def user_search():
    db = get_db()
    results = []
    if request.method == "POST":
        q = request.form.get("query", "").strip()
        rows = db.execute(
            """
            SELECT id, document_title, original_filename, uploaded_at, file_size
            FROM uploads
            WHERE document_title LIKE ? OR original_filename LIKE ?
            ORDER BY id DESC
            """,
            (f"%{q}%", f"%{q}%"),
        ).fetchall()
        results = rows
        log_action(session["username"], "search", f"Query: {q}")

    return render_template("user_search.html", results=results)
@app.route('/search', methods=['GET', 'POST'])
def search():
    results = []  # always initialize as empty list

    if request.method == 'POST':
        query = request.form['query']
        results = db.search_files(query)  # should return [] if no match

    return render_template('user_search.html', results=results)


@app.route("/user/request-key/<int:file_id>", methods=["POST"])
@login_required
def user_request_key(file_id):
    db = get_db()
    upload = db.execute(
        "SELECT id, document_title, original_filename FROM uploads WHERE id = ?",
        (file_id,),
    ).fetchone()
    if upload is None:
        flash("File not found.", "danger")
        return redirect(url_for("user_search"))

    existing_pending = db.execute(
        """
        SELECT id FROM decryption_requests
        WHERE user_id = ? AND file_id = ? AND status = 'pending'
        """,
        (session["user_id"], file_id),
    ).fetchone()
    if existing_pending:
        flash("You already have a pending request for this file.", "danger")
        return redirect(url_for("user_requests"))

    db.execute(
        """
        INSERT INTO decryption_requests (user_id, file_id, request_message, status, created_at)
        VALUES (?, ?, ?, 'pending', ?)
        """,
        (
            session["user_id"],
            file_id,
            f"Request decryption key for {upload['document_title']} ({upload['original_filename']})",
            datetime.utcnow().isoformat(),
        ),
    )
    db.commit()
    log_action(session["username"], "request_key", f"Requested key for file id {file_id}")
    flash("Decryption key request sent to admin.", "success")
    return redirect(url_for("user_requests"))


@app.route("/user/requests")
@login_required
def user_requests():
    db = get_db()
    rows = db.execute(
        """
        SELECT dr.*, up.document_title, up.original_filename
        FROM decryption_requests dr
        JOIN uploads up ON up.id = dr.file_id
        WHERE dr.user_id = ?
        ORDER BY dr.id DESC
        """,
        (session["user_id"],),
    ).fetchall()
    return render_template("user_requests.html", rows=rows)


@app.route("/user/download/<int:file_id>", methods=["GET", "POST"])
@login_required
def user_download(file_id):
    db = get_db()
    row = db.execute("SELECT * FROM uploads WHERE id = ?", (file_id,)).fetchone()
    if row is None:
        flash("File not found.", "danger")
        return redirect(url_for("user_search"))

    approved_req = db.execute(
        """
        SELECT decryption_key FROM decryption_requests
        WHERE user_id = ? AND file_id = ? AND status = 'approved'
        ORDER BY id DESC LIMIT 1
        """,
        (session["user_id"], file_id),
    ).fetchone()

    if request.method == "POST":
        key = request.form.get("decryption_key", "").strip()
        if not key and approved_req is not None:
            key = approved_req["decryption_key"]
        if key != row["aes_key"]:
            log_action(session["username"], "download_failed", f"Wrong key for file id {file_id}")
            flash("Invalid decryption key.", "danger")
            return render_template("user_download.html", item=row, approved_req=approved_req)

        try:
            encrypted_bytes = Path(row["encrypted_path"]).read_bytes()
            cipher = Fernet(key.encode("utf-8"))
            plain_bytes = cipher.decrypt(encrypted_bytes)
        except (OSError, InvalidToken, ValueError):
            flash("Unable to decrypt file.", "danger")
            return render_template("user_download.html", item=row)

        temp_path = UPLOAD_DIR / f"tmp_{row['id']}_{row['original_filename']}"
        temp_path.write_bytes(plain_bytes)
        log_action(session["username"], "download_success", f"Downloaded file id {file_id}")
        return send_file(temp_path, as_attachment=True, download_name=row["original_filename"])

    return render_template("user_download.html", item=row, approved_req=approved_req)


@app.route("/user/results")
@login_required
def user_results():
    db = get_db()
    metrics = db.execute("SELECT * FROM training_metrics ORDER BY epoch ASC").fetchall()
    perf = db.execute(
        """
        SELECT id, document_title, uploaded_at, file_size,
               key_generation_time, encryption_time, decryption_time,
               response_time, computational_overhead, total_change_rate
        FROM uploads
        ORDER BY id DESC
        """
    ).fetchall()
    return render_template("reports.html", metrics=metrics, perf=perf, page_title="User Results & Graphs")


@app.route("/user/logs")
@login_required
def user_logs():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM logs WHERE actor = ? ORDER BY id DESC LIMIT 120", (session["username"],)
    ).fetchall()
    return render_template("logs.html", rows=rows, page_title="Test Log History")


@app.context_processor
def inject_now():
    return {"now_year": datetime.utcnow().year}


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user is None:
            flash("Email not found.", "danger")
            return render_template("forgot_password.html")

        token = serializer.dumps(email, salt="password-reset-salt")
        reset_url = url_for("reset_password", token=token, _external=True)

        # In real application, send this link via email
        flash("Password reset link generated.", "success")
        return render_template("reset_link.html", reset_url=reset_url)

    return render_template("forgot_password.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = serializer.loads(token, salt="password-reset-salt", max_age=600)
    except SignatureExpired:
        flash("Reset link expired. Try again.", "danger")
        return redirect(url_for("forgot_password"))
    except BadSignature:
        flash("Invalid reset link.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("password", "")
        if not new_password:
            flash("Password cannot be empty.", "danger")
            return render_template("reset_password.html")

        db = get_db()
        db.execute(
            "UPDATE users SET password_hash = ? WHERE email = ?",
            (generate_password_hash(new_password), email),
        )
        db.commit()

        log_action(email, "password_reset", "User reset password")
        flash("Password updated successfully. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html")


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
