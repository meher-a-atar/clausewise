from dotenv import load_dotenv
import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from groq import Groq
import fitz  # PyMuPDF
from docx import Document


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersecretkey")

DB_FILE = "users.db"
load_dotenv() 
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")  # keep keys out of code
MODEL_NAME = os.environ.get("GROQ_MODEL", "llama3-8b-8192")
client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None

# -------- DB --------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT,
            clause TEXT,
            risks TEXT,
            summary TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()
init_db()

# -------- Helpers --------
def extract_text_from_file(path: str) -> str:
    if path.lower().endswith(".pdf"):
        doc = fitz.open(path)
        return "\n".join(p.get_text() for p in doc).strip()
    if path.lower().endswith(".docx"):
        d = Document(path)
        return "\n".join(p.text for p in d.paragraphs if p.text.strip())
    raise ValueError("Unsupported file type (.pdf or .docx only)")

def groq_analyze(prompt: str) -> str:
    if not client:
        return "(Groq API key not set)"
    r = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": "You are a legal document analysis assistant."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.3,
        max_tokens=500,
    )
    return r.choices[0].message.content

def analyze_document(text: str) -> tuple[str, str, str]:
    clause_prompt = "Provide a concise clause-by-clause explanation (max 3 sentences per clause):\n" + text
    risk_prompt = "Identify potential legal risks and compliance issues concisely (max 5 points):\n" + text
    summary_prompt = "Summarize the document in under 100 words:\n" + text
    return groq_analyze(clause_prompt), groq_analyze(risk_prompt), groq_analyze(summary_prompt)

# -------- Routes --------
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session.get("username"))

# ---- Signup (session-based app) ----
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if password != confirm:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("signup"))
        if not username or not email:
            flash("Username and Email are required.", "danger")
            return redirect(url_for("signup"))

        hashed = generate_password_hash(password)
        try:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (username, email, hashed),
            )
            conn.commit()
            conn.close()
            flash("✅ Signup successful! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("⚠️ Username or Email already exists.", "danger")
    return render_template("signup.html")

# ---- Login (fixes `identity` bug) ----
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # user can type either username OR email in the same field
        identity = (request.form.get("username") or request.form.get("email") or "").strip().lower()
        password = request.form.get("password", "")

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute(
            "SELECT id, username, email, password FROM users WHERE lower(email) = ? OR lower(username) = ?",
            (identity, identity),
        )
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session["user_id"] = user[0]
            session["username"] = user[1] or user[2]
            flash("✅ Logged in successfully!", "success")
            return redirect(url_for("dashboard"))
        flash("❌ Invalid credentials.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("✅ Logged out successfully.", "success")
    return redirect(url_for("home"))

# ---- Upload & Analyze ----
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files.get("document")
        if not file or not file.filename:
            flash("Please choose a file.", "warning")
            return redirect(url_for("upload"))
        os.makedirs("uploads", exist_ok=True)
        path = os.path.join("uploads", file.filename)
        file.save(path)
        try:
            text = extract_text_from_file(path)
            clause, risks, summary = analyze_document(text)
            with sqlite3.connect(DB_FILE) as conn:
                c = conn.cursor()
                c.execute(
                    "INSERT INTO history (user_id, filename, clause, risks, summary) VALUES (?, ?, ?, ?, ?)",
                    (session["user_id"], file.filename, clause, risks, summary),
                )
                hid = c.lastrowid
                conn.commit()
            return redirect(url_for("history_detail", history_id=hid))
        except Exception as e:
            flash(f"Error: {e}", "danger")

    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute(
            "SELECT id, filename, created_at FROM history WHERE user_id = ? ORDER BY created_at DESC",
            (session["user_id"],),
        )
        rows = c.fetchall()
    history = [{"id": r[0], "filename": r[1], "created_at": r[2]} for r in rows]
    return render_template("upload.html", history=history)

# ---- History ----
@app.route("/history")
def history_list():
    if "user_id" not in session:
        return redirect(url_for("login"))
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute(
            "SELECT id, filename, created_at FROM history WHERE user_id = ? ORDER BY created_at DESC",
            (session["user_id"],),
        )
        rows = c.fetchall()
    history = [{"id": r[0], "filename": r[1], "created_at": r[2]} for r in rows]
    return render_template("history.html", history=history)

@app.route("/history/<int:history_id>")
def history_detail(history_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute(
            "SELECT filename, clause, risks, summary, created_at FROM history WHERE id = ? AND user_id = ?",
            (history_id, session["user_id"]),
        )
        row = c.fetchone()
    if not row:
        return "Record not found", 404
    filename, clause, risks, summary, created_at = row
    return render_template(
        "result.html",
        filename=filename,
        clause_result=clause,
        risk_result=risks,
        summary_result=summary,
        uploaded_at=created_at,
    )

@app.route("/history/delete/<int:history_id>", methods=["POST"])
def delete_history(history_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("DELETE FROM history WHERE id = ? AND user_id = ?", (history_id, session["user_id"]))
        conn.commit()
    flash("🗑️ Analysis deleted.", "success")
    return redirect(url_for("history_list"))

if __name__ == "__main__":
    app.run(debug=True)

