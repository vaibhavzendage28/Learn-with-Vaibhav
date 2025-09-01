import os
import mysql.connector
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from mysql.connector import Error

# Only load .env locally (not on Render)
if os.environ.get("RENDER") is None:  
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

# ---------- Flask Setup ----------
app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config["UPLOAD_FOLDER"] = os.path.join(os.getcwd(), "uploads")

# ---------- MySQL CONFIG ----------
db_config = {
    "host": os.getenv("DB_HOST"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME"),
    "port": os.getenv("DB_PORT", 3306)
}

# ---------- Utility: Database Connection ----------
def get_db_connection():
    try:
        return mysql.connector.connect(**db_config)
    except Error as e:
        print("Database connection error:", e)
        return None

# ---------- Admin Credentials ----------
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"   # better: load from .env later

# ---------- Routes ----------

# --- Admin Login ---
@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin"] = True
            flash("Welcome Admin ✅", "dashboard")
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Invalid Credentials ❌", "login")

    return render_template("admin_login.html")

# --- Admin Dashboard ---
@app.route("/admin_dashboard")
def admin_dashboard():
    if not session.get("admin"):
        flash("Please login as Admin first ⚠️", "login")
        return redirect(url_for("admin_login"))

    conn = get_db_connection()
    stats = {
        "total_students": 0,
        "total_notes": 0,
        "total_assignments": 0,
        "downloads": 0   # needs tracking
    }

    if conn:
        cursor = conn.cursor(dictionary=True)

        # Count students
        cursor.execute("SELECT COUNT(*) AS count FROM users")
        stats["total_students"] = cursor.fetchone()["count"]

        # Count notes
        cursor.execute("SELECT COUNT(*) AS count FROM materials WHERE type='notes'")
        stats["total_notes"] = cursor.fetchone()["count"]

        # Count assignments
        cursor.execute("SELECT COUNT(*) AS count FROM materials WHERE type='assignment'")
        stats["total_assignments"] = cursor.fetchone()["count"]

        # Count downloads (optional: requires downloads table)
        try:
            cursor.execute("SELECT SUM(download_count) AS total FROM materials")
            result = cursor.fetchone()
            stats["downloads"] = result["total"] if result["total"] else 0
        except:
            stats["downloads"] = 0

        cursor.close()
        conn.close()

    return render_template("admin_dashboard.html", stats=stats)

# --- Admin Logout ---
@app.route("/admin_logout")
def admin_logout():
    session.pop("admin", None)
    flash("You have been logged out 👋", "login")
    return redirect(url_for("home"))

# --- Upload Materials (Admin) ---
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if not session.get("admin"):
        flash("Please login as Admin first ⚠️", "login")
        return redirect(url_for("home"))

    if request.method == "POST":
        title = request.form["title"]
        file = request.files["file"]
        class_name = request.form["class"]
        subject = request.form["subject"]
        file_type = request.form["type"]

        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)

            conn = get_db_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO materials (title, file_name, class, subject, type) VALUES (%s, %s, %s, %s, %s)",
                    (title, filename, class_name, subject, file_type),
                )
                conn.commit()
                cursor.close()
                conn.close()

            flash("✅ File uploaded successfully!", "dashboard")
            return redirect(url_for("admin_dashboard"))

    return render_template("upload.html")

# --- Home ---
@app.route("/")
def home():
    return render_template("index.html")

# --- Register ---
@app.route("/register", methods=["GET", "POST"])
def register():
    if "user" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

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
            finally:
                cur.close()
                conn.close()

    return render_template("register.html")

# --- Login ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        conn = get_db_connection()
        if conn:
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT * FROM users WHERE username=%s", (username,))
            user = cur.fetchone()
            cur.close()
            conn.close()

            if user and check_password_hash(user["password"], password):
                session["user"] = user["username"]
                flash("Login successful ✅", "home")
                return redirect(url_for("home"))
            else:
                flash("Invalid username or password ❌", "login")

    return render_template("login.html")

# --- Logout ---
@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("You have been logged out 👋", "login")
    return redirect(url_for("home"))

# --- Resources Page ---
@app.route("/resources")
def resources():
    if "user" not in session:
        flash("Please login to access resources ⚠️", "login")
        return redirect(url_for("login"))

    conn = get_db_connection()
    files = []
    if conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM resources ORDER BY uploaded_at DESC")
        files = cur.fetchall()
        cur.close()
        conn.close()

    return render_template("resources.html", files=files)

# --- Notes Page ---
@app.route("/notes")
def notes():
    if "user" not in session:
        flash("Please login to access notes ⚠️", "login")
        return redirect(url_for("login"))

    conn = get_db_connection()
    notes_list = []
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM materials WHERE type='notes' ORDER BY class, subject")
        notes_list = cursor.fetchall()
        cursor.close()
        conn.close()

    return render_template("notes.html", notes=notes_list)

# --- Assignments Page ---
@app.route("/assignments")
def assignments():
    if "user" not in session:
        flash("Please login to access assignments ⚠️", "login")
        return redirect(url_for("login"))

    conn = get_db_connection()
    assignments_list = []
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM materials WHERE type='assignment' ORDER BY class, subject")
        assignments_list = cursor.fetchall()
        cursor.close()
        conn.close()

    return render_template("assignments.html", assignments=assignments_list)

# --- Serve Uploaded Files ---
@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# --- Download Files ---
@app.route("/download/<filename>")
def download(filename):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE materials SET download_count = download_count + 1 WHERE file_name = %s", (filename,))
        conn.commit()
        cursor.close()
        conn.close()

    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)

# ---------- No Cache ----------
@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "-1"
    return response

# ---------- Main ----------
# if __name__ == "__main__":
#     if not os.path.exists(app.config["UPLOAD_FOLDER"]):
#         os.makedirs(app.config["UPLOAD_FOLDER"])
#     app.run(debug=True)
