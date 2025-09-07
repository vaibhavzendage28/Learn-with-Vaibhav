# app.py
import os
import io
import glob
import logging
import base64
import json
import mysql.connector
# new imports for OAuth flow
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from mysql.connector import Error

# --- Ensure service account file is available BEFORE importing google libs ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

def ensure_service_account_file():
    """
    Writes service account JSON from environment into /tmp/service-account.json
    and sets GOOGLE_APPLICATION_CREDENTIALS so google libraries can find it.
    Looks for either:
      - GCP_SERVICE_ACCOUNT_JSON (raw JSON)
      - GCP_SERVICE_ACCOUNT_JSON_B64 (base64-encoded JSON)
    Returns the path (or None).
    """
    sa_json = os.environ.get("GCP_SERVICE_ACCOUNT_JSON")
    sa_b64 = os.environ.get("GCP_SERVICE_ACCOUNT_JSON_B64")
    path = "/tmp/service-account.json"

    if sa_json:
        try:
            parsed = json.loads(sa_json)  # sanity check
            with open(path, "w", encoding="utf-8") as f:
                f.write(json.dumps(parsed))
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = path
            logging.info("Wrote service account JSON from GCP_SERVICE_ACCOUNT_JSON to %s", path)
            return path
        except Exception:
            logging.exception("GCP_SERVICE_ACCOUNT_JSON present but invalid JSON")
            return None

    if sa_b64:
        try:
            data = base64.b64decode(sa_b64)
            parsed = json.loads(data)
            with open(path, "w", encoding="utf-8") as f:
                f.write(json.dumps(parsed))
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = path
            logging.info("Wrote service account JSON from GCP_SERVICE_ACCOUNT_JSON_B64 to %s", path)
            return path
        except Exception:
            logging.exception("Failed to decode/parse GCP_SERVICE_ACCOUNT_JSON_B64")
            return None

    # Nothing in env; leave it to file discovery below
    logging.warning("No service account JSON found in environment. Set GCP_SERVICE_ACCOUNT_JSON or GCP_SERVICE_ACCOUNT_JSON_B64.")
    return None

# run this early
ensure_service_account_file()

# --- Now import Google libs (safe because credentials path may exist now) ---
# pip install google-api-python-client google-auth google-auth-httplib2
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload

# --- Flask app and config ---
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "supersecretkey")

LOCAL_UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(LOCAL_UPLOAD_FOLDER, exist_ok=True)

# Load .env locally if present
if os.environ.get("RENDER") is None:
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except Exception:
        pass

# MySQL config
db_config = {
    "host": os.getenv("DB_HOST"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME"),
    "port": int(os.getenv("DB_PORT", 3306)),
}

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")  # override via env

SERVICE_ACCOUNT_CANDIDATES = [
    "service-account.json",
    "service_account.json",
    "service-account-key.json",
    "service-account-key.json",
    "credentials.json",
    "drive-service-account.json",
]

# ---------- OAuth helper routes (one-time use to get refresh token) ----------
OAUTH_CLIENT_ID = os.getenv("GOOGLE_OAUTH_CLIENT_ID")
OAUTH_CLIENT_SECRET = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET")
OAUTH_REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI")  # must match Google Console

def _client_config():
    """Build client config dict used by google_auth_oauthlib.flow.Flow"""
    return {
        "web": {
            "client_id": OAUTH_CLIENT_ID,
            "client_secret": OAUTH_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [OAUTH_REDIRECT_URI],
        }
    }

@app.route("/oauth2authorize")
def oauth2authorize():
    """Redirect user to Google consent screen to obtain refresh token (one-time)."""
    if not (OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET and OAUTH_REDIRECT_URI):
        return "Missing OAuth client config in environment variables.", 500

    flow = Flow.from_client_config(
        _client_config(),
        scopes=DRIVE_SCOPES,
        redirect_uri=OAUTH_REDIRECT_URI,
    )
    auth_url, state = flow.authorization_url(
        access_type="offline",       # IMPORTANT: offline gives refresh token
        include_granted_scopes="true",
        prompt="consent"            # force showing consent to get refresh token
    )
    session["oauth_state"] = state
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    """Exchange code for tokens and show the refresh token (copy it to Render secrets)."""
    state = session.get("oauth_state", None)
    if not state:
        return "Missing OAuth state in session. Start at /oauth2authorize", 400

    flow = Flow.from_client_config(
        _client_config(),
        scopes=DRIVE_SCOPES,
        state=state,
        redirect_uri=OAUTH_REDIRECT_URI,
    )

    # Exchange the authorization code for credentials
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials

    refresh_token = getattr(creds, "refresh_token", None)
    access_token = getattr(creds, "token", None)

    if not refresh_token:
        return (
            "No refresh token returned. Make sure you used 'prompt=consent' "
            "and that you authorized with the same account. If you previously "
            "authorized, revoke and try again.",
            400,
        )

    # IMPORTANT: show the refresh token so you can copy it into Render Secrets
    # DO NOT keep this page public — once saved in Render, remove these routes or protect them.
    return (
        f"<h3>OAuth completed ✅</h3>"
        f"<p>Copy this refresh token and paste into Render as <b>DRIVE_REFRESH_TOKEN</b> (secret):</p>"
        f"<pre>{refresh_token}</pre>"
        f"<p>Then restart your service.</p>"
    )

def get_drive_service_oauth():
    """Build a Drive service using saved refresh token (preferred for user Drive uploads)."""
    refresh_token = os.getenv("DRIVE_REFRESH_TOKEN")
    client_id = os.getenv("GOOGLE_OAUTH_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET")
    if not (refresh_token and client_id and client_secret):
        app.logger.info("OAuth refresh token or client config missing.")
        return None

    creds = Credentials(
        token=None,
        refresh_token=refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=client_id,
        client_secret=client_secret,
        scopes=DRIVE_SCOPES,
    )
    try:
        creds.refresh(Request())  # obtains access token using refresh token
    except Exception as e:
        app.logger.exception("Failed to refresh OAuth credentials: %s", e)
        return None

    try:
        service = build("drive", "v3", credentials=creds, cache_discovery=False)
        return service
    except Exception as e:
        app.logger.exception("Failed to build Drive service with OAuth credentials: %s", e)
        return None


def find_service_account_file():
    """
    Search for a service-account JSON file:
      1) If GOOGLE_APPLICATION_CREDENTIALS is set and exists -> use it
      2) If /tmp/service-account.json exists (written from env) -> use it
      3) Look for common filenames in project root
      4) Inspect any .json in project root for service_account/type marker
    """
    # 1) explicit env var path
    env_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    if env_path and os.path.isfile(env_path):
        return env_path

    # 2) /tmp path (written by ensure_service_account_file)
    tmp_path = "/tmp/service-account.json"
    if os.path.isfile(tmp_path):
        return tmp_path

    # 3) common candidate names in project root
    for name in SERVICE_ACCOUNT_CANDIDATES:
        path = os.path.join(BASE_DIR, name)
        if os.path.isfile(path):
            return path

    # 4) inspect other json files for a service_account marker
    for path in glob.glob(os.path.join(BASE_DIR, "*.json")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read(2000)
                if '"type": "service_account"' in content or '"client_email"' in content:
                    return path
        except Exception:
            continue

    return None

SERVICE_ACCOUNT_FILE = find_service_account_file()
DRIVE_SCOPES = ["https://www.googleapis.com/auth/drive"]
_drive_service = None

def init_drive_service():
    global _drive_service
    if _drive_service is not None:
        return _drive_service

    # prefer explicit env-provided credentials file
    sa_file = SERVICE_ACCOUNT_FILE or os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    if not sa_file or not os.path.isfile(sa_file):
        app.logger.warning("No service account JSON file found in project directory or environment.")
        return None

    try:
        creds = service_account.Credentials.from_service_account_file(sa_file, scopes=DRIVE_SCOPES)
        service = build("drive", "v3", credentials=creds, cache_discovery=False)
        _drive_service = service
        app.logger.info("Google Drive service initialized with %s", sa_file)
        return _drive_service
    except Exception as e:
        app.logger.exception("Failed to initialize Google Drive service: %s", e)
        return None

# attempt init early (harmless if fails)
init_drive_service()

def get_db_connection():
    try:
        return mysql.connector.connect(**db_config)
    except Error as e:
        app.logger.error("Database connection error: %s", e)
        return None

def upload_file_to_drive(file_storage, filename=None, folder_id=None):
    # prefer OAuth (uploads into the user Drive)
    drive = get_drive_service_oauth() or init_drive_service()
    if not drive:
        return None

    if not filename:
        filename = secure_filename(file_storage.filename or "unnamed")
    file_metadata = {"name": filename}
    if folder_id:
        file_metadata["parents"] = [folder_id]

    try:
        file_storage.stream.seek(0)
    except Exception:
        pass

    media = MediaIoBaseUpload(
        file_storage.stream,
        mimetype=(file_storage.mimetype or "application/octet-stream"),
        resumable=True,
    )

    created = drive.files().create(
        body=file_metadata,
        media_body=media,
        supportsAllDrives=True,   # safe for both My Drive & Shared Drives
        fields="id,webViewLink,webContentLink"
    ).execute()

    file_id = created.get("id")
    try:
        drive.permissions().create(
            fileId=file_id,
            body={"type": "anyone", "role": "reader"},
            supportsAllDrives=True
        ).execute()
    except Exception as perm_exc:
        app.logger.warning("Failed to set public permission on Drive file %s: %s", file_id, perm_exc)

    return {
        "id": file_id,
        "webViewLink": created.get("webViewLink"),
        "webContentLink": created.get("webContentLink"),
    }

@app.route("/_drive_test")
def drive_test():
    """
    Quick test endpoint to verify Drive API access after deployment.
    Returns a small list of files (or an error).
    """
    try:
        service = init_drive_service()
        if not service:
            return {"ok": False, "error": "Drive service not initialized (no credentials found)."}, 500
        files = service.files().list(pageSize=5, fields="files(id, name)").execute().get("files", [])
        return {"ok": True, "sample_files": files}
    except Exception as e:
        app.logger.exception("Drive test failed")
        return {"ok": False, "error": str(e)}, 500

@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin"] = True
            flash("Welcome Admin ✅", "dashboard")
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Invalid Credentials ❌", "login")
    return render_template("admin_login.html")

@app.route("/admin_dashboard")
def admin_dashboard():
    if not session.get("admin"):
        flash("Please login as Admin first ⚠️", "login")
        return redirect(url_for("admin_login"))
    conn = get_db_connection()
    stats = {"total_students": 0, "total_notes": 0, "total_assignments": 0, "downloads": 0}
    if conn:
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT COUNT(*) AS count FROM users")
            stats["total_students"] = cursor.fetchone()["count"]
            cursor.execute("SELECT COUNT(*) AS count FROM materials WHERE type='notes'")
            stats["total_notes"] = cursor.fetchone()["count"]
            cursor.execute("SELECT COUNT(*) AS count FROM materials WHERE type='assignment'")
            stats["total_assignments"] = cursor.fetchone()["count"]
            try:
                cursor.execute("SELECT SUM(download_count) AS total FROM materials")
                result = cursor.fetchone()
                stats["downloads"] = result["total"] if result and result["total"] else 0
            except Exception:
                stats["downloads"] = 0
        except Exception as e:
            app.logger.error("Error fetching stats: %s", e)
        finally:
            cursor.close()
            conn.close()
    return render_template("admin_dashboard.html", stats=stats)

@app.route("/admin_logout")
def admin_logout():
    session.pop("admin", None)
    flash("You have been logged out 👋", "login")
    return redirect(url_for("home"))

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if not session.get("admin"):
        flash("Please login as Admin first ⚠️", "login")
        return redirect(url_for("admin_login"))
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        file = request.files.get("file")
        class_name = request.form.get("class", "").strip()
        subject = request.form.get("subject", "").strip()
        file_type = request.form.get("type", "").strip()
        if not title or not file or file.filename == "":
            flash("Title and file are required ❌", "upload")
            return redirect(url_for("upload"))
        filename = secure_filename(file.filename)
        drive_result = None
        try:
            drive_result = upload_file_to_drive(file, filename=filename, folder_id=os.getenv("DRIVE_FOLDER_ID"))
        except Exception as e:
            app.logger.error("Drive upload failed: %s", e)
            drive_result = None
        if not drive_result:
            local_path = os.path.join(LOCAL_UPLOAD_FOLDER, filename)
            try:
                file.stream.seek(0)
            except Exception:
                pass
            file.save(local_path)
            flash("Uploaded locally (Drive unavailable).", "dashboard")
        else:
            local_path = None
            flash("✅ File uploaded to Google Drive successfully!", "dashboard")
        conn = get_db_connection()
        if conn:
            try:
                cur = conn.cursor()
                try:
                    cur.execute(
                        """
                        INSERT INTO materials
                        (title, file_name, class, subject, type, drive_file_id, web_view_link, web_content_link, uploaded_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
                        """,
                        (
                            title,
                            filename,
                            class_name,
                            subject,
                            file_type,
                            drive_result["id"] if drive_result else None,
                            drive_result.get("webViewLink") if drive_result else None,
                            drive_result.get("webContentLink") if drive_result else None,
                        ),
                    )
                except mysql.connector.Error:
                    cur.execute(
                        "INSERT INTO materials (title, file_name, class, subject, type, uploaded_at) VALUES (%s, %s, %s, %s, %s, NOW())",
                        (title, filename, class_name, subject, file_type),
                    )
                conn.commit()
            except Exception as e:
                app.logger.error("Failed to save material record: %s", e)
            finally:
                cur.close()
                conn.close()
        return redirect(url_for("admin_dashboard"))
    return render_template("upload.html")

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if "user" in session:
        return redirect(url_for("home"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("All fields are required ❌", "register")
            return redirect(url_for("register"))
        hashed_pw = generate_password_hash(password)
        conn = get_db_connection()
        if conn:
            try:
                cur = conn.cursor()
                cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_pw))
                conn.commit()
                flash("Registration successful 🎉 Please login.", "login")
                return redirect(url_for("login"))
            except mysql.connector.IntegrityError:
                flash("Username already exists ❌", "register")
            except Exception as e:
                app.logger.error("Registration error: %s", e)
                flash("Registration failed ❌", "register")
            finally:
                cur.close()
                conn.close()
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("home"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db_connection()
        if conn:
            cur = conn.cursor(dictionary=True)
            try:
                cur.execute("SELECT * FROM users WHERE username=%s", (username,))
                user = cur.fetchone()
            except Exception as e:
                app.logger.error("Login DB error: %s", e)
                user = None
            finally:
                cur.close()
                conn.close()
            if user and check_password_hash(user["password"], password):
                session["user"] = user["username"]
                flash("Login successful ✅", "home")
                return redirect(url_for("home"))
            else:
                flash("Invalid username or password ❌", "login")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("You have been logged out 👋", "login")
    return redirect(url_for("home"))

@app.route("/resources")
def resources():
    if "user" not in session:
        flash("Please login to access resources ⚠️", "login")
        return redirect(url_for("login"))
    conn = get_db_connection()
    files = []
    if conn:
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute("SELECT * FROM resources ORDER BY uploaded_at DESC")
            files = cur.fetchall()
        except Exception as e:
            app.logger.error("Failed to fetch resources: %s", e)
            files = []
        finally:
            cur.close()
            conn.close()
    return render_template("resources.html", files=files)

@app.route("/notes")
def notes():
    if "user" not in session:
        flash("Please login to access notes ⚠️", "login")
        return redirect(url_for("login"))
    conn = get_db_connection()
    notes_list = []
    if conn:
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM materials WHERE type='notes' ORDER BY class, subject")
            notes_list = cursor.fetchall()
        except Exception as e:
            app.logger.error("Failed to fetch notes: %s", e)
            notes_list = []
        finally:
            cursor.close()
            conn.close()
    return render_template("notes.html", notes=notes_list)

@app.route("/assignments")
def assignments():
    if "user" not in session:
        flash("Please login to access assignments ⚠️", "login")
        return redirect(url_for("login"))
    conn = get_db_connection()
    assignments_list = []
    if conn:
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM materials WHERE type='assignment' ORDER BY class, subject")
            assignments_list = cursor.fetchall()
        except Exception as e:
            app.logger.error("Failed to fetch assignments: %s", e)
            assignments_list = []
        finally:
            cursor.close()
            conn.close()
    return render_template("assignments.html", assignments=assignments_list)

@app.route("/download/<filename>")
def download(filename):
    conn = get_db_connection()
    drive_file_id = None
    if conn:
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute("SELECT drive_file_id FROM materials WHERE file_name = %s LIMIT 1", (filename,))
            row = cur.fetchone()
            if row:
                drive_file_id = row.get("drive_file_id")
            try:
                cur.execute("UPDATE materials SET download_count = COALESCE(download_count,0) + 1 WHERE file_name = %s", (filename,))
                conn.commit()
            except Exception:
                pass
        except Exception as e:
            app.logger.error("Download DB error: %s", e)
        finally:
            cur.close()
            conn.close()
    if drive_file_id:
        direct_download = f"https://drive.google.com/uc?export=download&id={drive_file_id}"
        return redirect(direct_download)
    local_path = os.path.join(LOCAL_UPLOAD_FOLDER, filename)
    if os.path.isfile(local_path):
        from flask import send_from_directory
        return send_from_directory(LOCAL_UPLOAD_FOLDER, filename, as_attachment=True)
    else:
        flash("❌ File not found!", "home")
        return redirect(url_for("home"))

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    conn = get_db_connection()
    web_view_link = None
    if conn:
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute("SELECT web_view_link FROM materials WHERE file_name = %s LIMIT 1", (filename,))
            row = cur.fetchone()
            if row:
                web_view_link = row.get("web_view_link")
        except Exception as e:
            app.logger.error("Preview DB error: %s", e)
        finally:
            cur.close()
            conn.close()
    if web_view_link:
        return redirect(web_view_link)
    local_path = os.path.join(LOCAL_UPLOAD_FOLDER, filename)
    if os.path.isfile(local_path):
        from flask import send_from_directory
        return send_from_directory(LOCAL_UPLOAD_FOLDER, filename)
    else:
        flash("❌ File not found on server!", "home")
        return redirect(url_for("home"))

@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "-1"
    return response

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=os.getenv("FLASK_DEBUG", "true").lower() in ("1", "true"))
