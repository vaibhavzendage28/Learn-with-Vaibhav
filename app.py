# app.py
import os
import io
import glob
import mysql.connector
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

# Google Drive API imports
# pip install google-api-python-client google-auth
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "supersecretkey")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

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

def find_service_account_file():
    for name in SERVICE_ACCOUNT_CANDIDATES:
        path = os.path.join(BASE_DIR, name)
        if os.path.isfile(path):
            return path
    for path in glob.glob(os.path.join(BASE_DIR, "*.json")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read(2000)
                if '"service_account"' in content or '"type": "service_account"' in content:
                    return path
        except Exception:
            continue
    env_path = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
    if env_path and os.path.isfile(env_path):
        return env_path
    return None

SERVICE_ACCOUNT_FILE = find_service_account_file()
DRIVE_SCOPES = ["https://www.googleapis.com/auth/drive"]
_drive_service = None

def init_drive_service():
    global _drive_service
    if _drive_service is not None:
        return _drive_service
    if not SERVICE_ACCOUNT_FILE:
        app.logger.warning("No service account JSON file found in project directory.")
        return None
    try:
        creds = service_account.Credentials.from_service_account_file(
            SERVICE_ACCOUNT_FILE, scopes=DRIVE_SCOPES
        )
        service = build("drive", "v3", credentials=creds, cache_discovery=False)
        _drive_service = service
        app.logger.info("Google Drive service initialized.")
        return _drive_service
    except Exception as e:
        app.logger.error("Failed to initialize Google Drive service: %s", e)
        return None

init_drive_service()

def get_db_connection():
    try:
        return mysql.connector.connect(**db_config)
    except Error as e:
        app.logger.error("Database connection error: %s", e)
        return None

def upload_file_to_drive(file_storage, filename=None, folder_id=None):
    drive = init_drive_service()
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
    created = drive.files().create(body=file_metadata, media_body=media, fields="id,webViewLink,webContentLink").execute()
    file_id = created.get("id")
    try:
        drive.permissions().create(fileId=file_id, body={"type": "anyone", "role": "reader"}).execute()
    except Exception as perm_exc:
        app.logger.warning("Failed to set public permission on Drive file %s: %s", file_id, perm_exc)
    return {
        "id": file_id,
        "webViewLink": created.get("webViewLink"),
        "webContentLink": created.get("webContentLink"),
    }

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
