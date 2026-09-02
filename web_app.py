from dotenv import load_dotenv
load_dotenv(".env")
import os
from flask import Flask, request, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("HACKPROOF_SECRET_KEY")
from auth import db, User, Report, login_manager
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///hackproof.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)
login_manager.init_app(app)
from google import genai
import markdown
import os
import time
import re
import requests
from pathlib import Path

from analysis_router import handle_analysis_request
from tools import run_safe_tool, SAFE_COMMANDS, TOOL_DESCRIPTIONS
from phishing_detector import analyze_url, format_result
from scam_detector import analyze_scam, format_scam_result


def load_knowledge():
    knowledge_dir = Path("knowledge")

    if not knowledge_dir.exists():
        return ""

    sections = []

    for filename in sorted(knowledge_dir.iterdir()):
        if filename.suffix.lower() != ".txt":
            continue

        content = filename.read_text(encoding="utf-8").strip()

        if content:
            sections.append(
                f"--- {filename.name} ---\n{content}"
            )

    return "\n\n".join(sections)


def retrieve_knowledge(question):
    knowledge = load_knowledge()

    if not knowledge.strip():
        return "No local knowledge available."

    q = question.lower().strip()
    q = re.sub(r"[^a-z0-9\s]", " ", q)

    stop_words = {
        "what", "is", "a", "an", "the",
        "explain", "tell", "me", "about",
        "define", "please", "can", "you", "of"
    }

    keywords = set(q.split()) - stop_words

    if not keywords:
        return "Please provide a more specific question."

    lines = [line.strip() for line in knowledge.splitlines()]

    best_start = None
    best_score = -1
    best_is_heading = False

    for i, line in enumerate(lines):
        if not line:
            continue

        line_lower = line.lower()

        # Ignore port-list entries such as "53 - DNS"
        is_port_entry = bool(re.match(r"^\d+\s*-\s*", line))

        score = sum(
            1 for keyword in keywords
            if keyword == line_lower or keyword in line_lower.split()
        )

        if score == 0:
            continue

        # Prefer a real topic heading over a port entry.
        is_heading = (
            line.isupper()
            and len(line.split()) <= 5
            and not is_port_entry
        )

        if is_heading and score > 0:
            score += 5

        if score > best_score:
            best_score = score
            best_start = i
            best_is_heading = is_heading

    if best_start is None:
        return "No directly relevant information found."

    result = [lines[best_start]]

    for line in lines[best_start + 1:]:
        if not line:
            break

        if line.startswith("---"):
            break

        # Stop when the next major topic heading begins.
        if (
            line.isupper()
            and len(line.split()) <= 5
            and line.lower() not in keywords
            and not re.match(r"^\d+\s*-\s*", line)
        ):
            break

        result.append(line)

    return "\n".join(result)


def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()
client = genai.Client()

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HackProof AI</title>

<style>
* {
    box-sizing: border-box;
}

:root {
    --bg: #07111f;
    --panel: #0d1a2b;
    --panel2: #111f33;
    --border: #243852;
    --text: #e8f0fa;
    --muted: #8fa5bd;
    --accent: #39d9ff;
    --accent2: #4d7cff;
    --danger: #ff5364;
    --success: #38d39f;
}

body {
    margin: 0;
    min-height: 100vh;
    font-family: Inter, Arial, sans-serif;
    background:
        radial-gradient(circle at 80% 10%, rgba(57,217,255,.10), transparent 30%),
        radial-gradient(circle at 10% 90%, rgba(77,124,255,.10), transparent 30%),
        var(--bg);
    color: var(--text);
}

header {
    height: 68px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 28px;
    border-bottom: 1px solid var(--border);
    background: rgba(7,17,31,.88);
    backdrop-filter: blur(12px);
    position: sticky;
    top: 0;
    z-index: 10;
}

.brand {
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: 20px;
    font-weight: 800;
}

.logo {
    width: 38px;
    height: 38px;
    display: grid;
    place-items: center;
    border: 1px solid rgba(57,217,255,.4);
    border-radius: 10px;
    background: rgba(57,217,255,.08);
    font-size: 20px;
}

.status {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--muted);
    font-size: 13px;
}

.status-dot {
    width: 9px;
    height: 9px;
    border-radius: 50%;
    background: var(--success);
    box-shadow: 0 0 12px rgba(56,211,159,.8);
}

.layout {
    display: grid;
    grid-template-columns: 230px 1fr;
    min-height: calc(100vh - 68px);
}

.sidebar {
    border-right: 1px solid var(--border);
    padding: 22px 14px;
    background: rgba(9,20,35,.72);
}

.section-title {
    color: #637b96;
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 1.4px;
    margin: 8px 12px 12px;
    text-transform: uppercase;
}

.nav {
    display: flex;
    flex-direction: column;
    gap: 6px;
}

.nav a {
    color: var(--muted);
    text-decoration: none;
    padding: 12px 14px;
    border-radius: 9px;
    display: flex;
    align-items: center;
    gap: 11px;
    transition: .2s;
}

.nav a:hover,
.nav a.active {
    color: var(--text);
    background: rgba(57,217,255,.08);
    border: 1px solid rgba(57,217,255,.14);
}

.main {
    width: min(1200px, 100%);
    margin: auto;
    padding: 30px;
}

.hero {
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    margin-bottom: 24px;
}

.hero h1 {
    margin: 0 0 7px;
    font-size: clamp(25px, 4vw, 36px);
}

.hero p {
    margin: 0;
    color: var(--muted);
}

.badge {
    border: 1px solid rgba(57,217,255,.25);
    color: var(--accent);
    padding: 7px 11px;
    border-radius: 999px;
    font-size: 12px;
    background: rgba(57,217,255,.06);
}

.metrics {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 14px;
    margin-bottom: 18px;
}

.metric {
    background: linear-gradient(145deg, var(--panel2), var(--panel));
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 18px;
}

.metric-label {
    color: var(--muted);
    font-size: 12px;
}

.metric-value {
    font-size: 22px;
    font-weight: 800;
    margin-top: 7px;
}

.chat-card {
    border: 1px solid var(--border);
    border-radius: 16px;
    background: rgba(13,26,43,.9);
    overflow: hidden;
    box-shadow: 0 20px 60px rgba(0,0,0,.22);
}

.chat-header {
    padding: 17px 20px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
}

.chat-title {
    display: flex;
    gap: 11px;
    align-items: center;
    font-weight: 750;
}

.ai-icon {
    width: 34px;
    height: 34px;
    display: grid;
    place-items: center;
    border-radius: 9px;
    background: rgba(57,217,255,.10);
    border: 1px solid rgba(57,217,255,.25);
}

#chat {
    height: 55vh;
    min-height: 430px;
    overflow-y: auto;
    padding: 22px;
    scroll-behavior: smooth;
}

.message {
    max-width: 82%;
    margin: 0 0 16px;
    padding: 14px 16px;
    border-radius: 13px;
    line-height: 1.6;
    white-space: normal;
    word-wrap: break-word;
}

.message.user {
    margin-left: auto;
    background: linear-gradient(135deg, #15508a, #17406f);
    border: 1px solid rgba(57,217,255,.15);
}

.message.bot {
    margin-right: auto;
    background: #17263b;
    border: 1px solid var(--border);
}

.message-label {
    font-size: 11px;
    font-weight: 800;
    color: var(--accent);
    margin-bottom: 5px;
}

.message.user .message-label {
    color: #b9eaff;
}

.input-area {
    padding: 15px;
    border-top: 1px solid var(--border);
    display: flex;
    gap: 10px;
    background: rgba(7,17,31,.45);
}

#question {
    flex: 1;
    min-width: 0;
    padding: 14px 16px;
    border-radius: 10px;
    border: 1px solid #314965;
    background: #0b1728;
    color: var(--text);
    outline: none;
    font-size: 14px;
}

#question:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(57,217,255,.08);
}

button {
    border: 0;
    border-radius: 10px;
    padding: 0 20px;
    font-weight: 800;
    cursor: pointer;
    transition: .2s;
}

.send {
    color: #04101b;
    background: var(--accent);
}

.send:hover {
    transform: translateY(-1px);
    box-shadow: 0 8px 25px rgba(57,217,255,.2);
}

.clear {
    color: var(--text);
    background: #26364c;
}

.clear:hover {
    background: #31445e;
}

.quick-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    padding: 0 22px 18px;
}

.quick {
    padding: 8px 12px;
    color: var(--muted);
    background: #101e31;
    border: 1px solid var(--border);
    border-radius: 8px;
    font-size: 12px;
}

.quick:hover {
    color: var(--accent);
    border-color: rgba(57,217,255,.35);
}

.footer-note {
    color: #60758d;
    text-align: center;
    font-size: 11px;
    margin-top: 18px;
}

@media (max-width: 850px) {
    .layout {
        grid-template-columns: 1fr;
    }

    .sidebar {
        display: none;
    }

    .main {
        padding: 18px;
    }

    .metrics {
        grid-template-columns: 1fr;
    }

    .hero {
        align-items: flex-start;
        gap: 12px;
        flex-direction: column;
    }

    .message {
        max-width: 94%;
    }
}

@media (max-width: 600px) {
    header {
        padding: 0 16px;
    }

    .status {
        display: none;
    }

    #chat {
        min-height: 400px;
    }

    .input-area {
        flex-wrap: wrap;
    }

    #question {
        flex-basis: 100%;
    }

    button {
        height: 44px;
    }
}
</style>
</head>

<body>

<header>
    <div class="brand">
        <div class="logo">🛡️</div>
        <span>HACKPROOF AI</span>
    </div>

    <div class="status">
        <span class="status-dot"></span>
        Local Security Assistant
    </div>
</header>

<div class="layout">

<aside class="sidebar">
    <div class="section-title">Command Center</div>

    <nav class="nav">
        <a href="/dashboard">📊 Dashboard</a>
        <a href="/" class="active">🤖 AI Assistant</a>
        <a href="/analysis">🔍 Security Analysis</a>
        <a href="/tools">🧰 Safe Tools</a>
    </nav>

    <div class="section-title" style="margin-top:28px;">
        Learning
    </div>

    <nav class="nav">
        <a href="#" onclick="quickQuestion('Explain DNS enumeration'); return false;">🌐 DNS Enumeration</a>
        <a href="#" onclick="quickQuestion('Explain the CIA Triad'); return false;">🔐 CIA Triad</a>
        <a href="#" onclick="quickQuestion('Explain SSH security'); return false;">🔑 SSH Security</a>
    </nav>
</aside>

<main class="main">

    <section class="hero">
        <div>
            <h1>Cybersecurity Command Center</h1>
            <p>Analyze, learn and investigate with HackProof AI.</p>
        </div>

        <div class="badge">AUTHORIZED LAB USE</div>
    </section>

    <section class="metrics">
        <div class="metric">
            <div class="metric-label">AI Assistant</div>
            <div class="metric-value">ONLINE</div>
        </div>

        <div class="metric">
            <div class="metric-label">Security Mode</div>
            <div class="metric-value">DEFENSIVE</div>
        </div>

        <div class="metric">
            <div class="metric-label">Safe Tools</div>
            <div class="metric-value">ENABLED</div>
        </div>
    </section>

    <section class="chat-card">

        <div class="chat-header">
            <div class="chat-title">
                <div class="ai-icon">🤖</div>
                <div>
                    <div>HackProof AI Assistant</div>
                    <small style="color:#8095ad;font-weight:400;">
                        Cybersecurity learning & authorized analysis
                    </small>
                </div>
            </div>
        </div>

        <div id="chat">

            <div class="message bot">
                <div class="message-label">HACKPROOF AI</div>
                Hello! I am HackProof AI. Ask me a cybersecurity question.
            </div>

        </div>

        <div class="quick-actions">
            <button class="quick" onclick="quickQuestion('What is the CIA Triad?')">
                CIA Triad
            </button>

            <button class="quick" onclick="quickQuestion('What is DNS enumeration?')">
                DNS Enumeration
            </button>

            <button class="quick" onclick="quickQuestion('Explain SSH security')">
                SSH Security
            </button>

            <button class="quick" onclick="quickQuestion('What is a SOC?')">
                SOC
            </button>
        </div>

        <div class="input-area">
            <input
                id="question"
                type="text"
                placeholder="Ask HackProof about cybersecurity..."
                autocomplete="off"
                onkeydown="if(event.key === 'Enter') sendMessage()"
            >

            <button class="send" onclick="sendMessage()">Send</button>
            <button class="clear" onclick="clearChat()">Clear</button>
        </div>

    </section>

    <div class="footer-note">
        HackProof AI • Cybersecurity learning platform • Use tools only on systems you are authorized to test.
    </div>

</main>
</div>

<script>

async function sendMessage() {

    const input = document.getElementById("question");
    const chat = document.getElementById("chat");
    const question = input.value.trim();

    if (!question) return;

    chat.innerHTML += `
        <div class="message user">
            <div class="message-label">YOU</div>
            ${escapeHTML(question)}
        </div>
    `;

    input.value = "";

    const loading = document.createElement("div");
    loading.className = "message bot";
    loading.id = "loading-message";
    loading.innerHTML = `
        <div class="message-label">HACKPROOF AI</div>
        Analyzing your request...
    `;

    chat.appendChild(loading);
    chat.scrollTop = chat.scrollHeight;

    try {

        const response = await fetch("/chat", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                question: question
            })
        });

        const data = await response.json();

        loading.remove();

        chat.innerHTML += `
            <div class="message bot">
                <div class="message-label">HACKPROOF AI</div>
                ${data.answer || "No response received."}
            </div>
        `;

    } catch (error) {

        loading.remove();

        chat.innerHTML += `
            <div class="message bot">
                <div class="message-label">SYSTEM</div>
                Error connecting to HackProof server.
            </div>
        `;
    }

    chat.scrollTop = chat.scrollHeight;
}

function quickQuestion(question) {
    document.getElementById("question").value = question;
    sendMessage();
}

function clearChat() {

    const chat = document.getElementById("chat");

    chat.innerHTML = `
        <div class="message bot">
            <div class="message-label">HACKPROOF AI</div>
            Hello! I am HackProof AI. Ask me a cybersecurity question.
        </div>
    `;
}

function escapeHTML(text) {

    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}

</script>

</body>
</html>
"""


MEMORY_FILE = Path("memory.txt")

def load_memory():
    if not MEMORY_FILE.exists():
        return ""
    return MEMORY_FILE.read_text(encoding="utf-8")[-12000:]

def retrieve_memory_answer(question):
    if not MEMORY_FILE.exists():
        return None

    memory = MEMORY_FILE.read_text(encoding="utf-8").strip()
    if not memory:
        return None

    q_words = set(
        word.lower()
        for word in re.findall(r"[a-zA-Z0-9]+", question)
        if len(word) > 2
    )

    entries = memory.split("\nUser: ")
    best = None
    best_score = 0

    for entry in entries:
        text = entry.strip()
        if not text:
            continue

        words = set(
            word.lower()
            for word in re.findall(r"[a-zA-Z0-9]+", text)
            if len(word) > 2
        )

        score = len(q_words & words)

        if score > best_score:
            best_score = score
            best = text

    if best_score == 0 or not best:
        return None

    return best


def save_memory(question, answer):
    entry = f"\nUser: {question}\nHackProof: {answer}\n"
    with MEMORY_FILE.open("a", encoding="utf-8") as f:
        f.write(entry)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            return "Username and password are required.", 400

        if User.query.filter_by(username=username).first():
            return "Username already exists.", 400

        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        login_user(user)
        return "Registration successful. You can now use HackProof."



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            return "Login successful. <a href='/'>Open HackProof</a>"

        return "Invalid username or password.", 401

    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>HackProof AI - Login</title>
        <style>
            * { box-sizing: border-box; }
            body {
                margin: 0;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                background: #0f172a;
                color: #e5e7eb;
                font-family: Arial, sans-serif;
            }
            .card {
                width: 400px;
                padding: 32px;
                background: #111827;
                border: 1px solid #334155;
                border-radius: 14px;
            }
            h1 { margin-top: 0; }
            input {
                width: 100%;
                padding: 13px;
                margin: 8px 0;
                border: 1px solid #475569;
                border-radius: 8px;
                background: #1e293b;
                color: white;
            }
            button {
                width: 100%;
                padding: 13px;
                margin-top: 12px;
                border: 0;
                border-radius: 8px;
                font-weight: bold;
                cursor: pointer;
            }
            a { color: #93c5fd; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>🛡️ HackProof AI</h1>
            <h2>Login</h2>
            <form method="POST">
                <input name="username" placeholder="Username" required>
                <input name="password" type="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
            <p>New to HackProof? <a href="/register">Create an account</a></p>
        </div>
    </body>
    </html>
    """


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return "Logged out. <a href='/login'>Login again</a>"


@app.route("/dashboard")
@login_required
def dashboard():
    reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.created_at.desc()).all()
    report_html = "".join(f'<div class="report-item"><strong>{r.analysis_type}</strong> — {r.target}<br><small>{r.created_at}</small><br><pre>{r.result}</pre><p><a href="/reports/{r.id}">🔎 View Details</a></p></div>' for r in reports)
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>HackProof AI - Dashboard</title>
        <style>
            * {{ box-sizing: border-box; }}

            body {{
                margin: 0;
                min-height: 100vh;
                background: #0f172a;
                color: #e5e7eb;
                font-family: Arial, sans-serif;
            }}

            .sidebar {{
                position: fixed;
                left: 0;
                top: 0;
                bottom: 0;
                width: 240px;
                padding: 28px 18px;
                background: #111827;
                border-right: 1px solid #334155;
            }}

            .logo {{
                font-size: 24px;
                font-weight: bold;
                margin-bottom: 35px;
                padding: 0 10px;
            }}

            .sidebar a {{
                display: block;
                padding: 13px 14px;
                margin: 6px 0;
                border-radius: 8px;
                color: #e5e7eb;
                text-decoration: none;
            }}

            .sidebar a:hover {{
                background: #1e293b;
            }}

            .user {{
                position: absolute;
                bottom: 25px;
                left: 18px;
                right: 18px;
                padding: 14px;
                border-top: 1px solid #334155;
            }}

            .user a {{
                display: block;
                margin-top: 10px;
                color: #93c5fd;
                text-decoration: none;
            }}

            .main {{
                margin-left: 240px;
                padding: 40px;
                max-width: 1250px;
            }}

            .welcome {{
                margin-bottom: 30px;
            }}

            .welcome h1 {{
                margin: 0 0 8px;
                font-size: 32px;
            }}

            .grid {{
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 20px;
            }}

            .card {{
                background: #111827;
                border: 1px solid #334155;
                border-radius: 12px;
                padding: 24px;
                min-height: 170px;
            }}

            .card h2 {{
                margin-top: 0;
                font-size: 21px;
            }}

            .card p {{
                line-height: 1.5;
            }}

            .card a {{
                color: #93c5fd;
                text-decoration: none;
            }}

            .status {{
                color: #86efac;
                font-weight: bold;
            }}

            @media (max-width: 850px) {{
                .sidebar {{
                    width: 190px;
                }}

                .main {{
                    margin-left: 190px;
                    padding: 25px;
                }}

                .grid {{
                    grid-template-columns: 1fr;
                }}
            }}
        </style>
    </head>

    <body>

        <aside class="sidebar">
            <div class="logo">🛡️ HackProof AI</div>

            <a href="/dashboard">🏠 Dashboard</a>
            <a href="/">🤖 AI Chat</a>
            <a href="/analysis">🔎 Security Analysis</a>
        <a href="/phishing">🛡️ Phishing Scanner</a>
        <a href="/scam">🛡️ Scam Detector</a>
            <a href="/tools">🛠️ Safe Tools</a>
            <a href="/knowledge">📚 Knowledge Base</a>
            <a href="/reports">📝 Reports</a>

            <div class="user">
                👤 {current_user.username}
                <a href="/logout">🚪 Logout</a>
            </div>
        </aside>

        <main class="main">
            <div class="welcome">
                <h1>Security Dashboard</h1>
                <p>Welcome back, {current_user.username}.</p>
            </div>

            <div class="grid">

                <div class="card">
                    <h2>🤖 AI Assistant</h2>
                    <p>Ask HackProof cybersecurity questions.</p>
                    <a href="/">Open AI Chat →</a>
                </div>

                <div class="card">
                    <h2><a href="/analysis">🔍 Security Analysis</a></h2>
                    <p>Analyze authorized security data and requests.</p>
                    <span class="status">Available</span>
                </div>

                <div class="card">
                    <h2>🛠️ Safe Tools</h2>
                    <p>Access approved cybersecurity tools.</p>
                    <span class="status">Available</span>
                </div>

                <div class="card">
                    <h2>📚 Knowledge Base</h2>
                    <p>Use HackProof's local cybersecurity knowledge.</p>
                    <span class="status">Available</span>
                </div>

        <h2>📑 Reports</h2>
        <p>Saved security reports: <strong>{len(reports)}</strong></p>
            <p><a href="/reports">📄 View All Reports →</a></p>
        {report_html}
                </div>

                <div class="card">
                    <h2>🔐 Account</h2>
                    <p>Authenticated as <strong>{current_user.username}</strong>.</p>
                    <a href="/logout">Sign out →</a>
                </div>

            </div>
        </main>

    </body>
    </html>
    """


@app.route("/analysis", methods=["GET", "POST"])
@login_required
def analysis():
    result = None

    if request.method == "POST":
        question = request.form.get("question", "").strip()

        if question:
            result = handle_analysis_request(question)

            if result:
                try:
                    parts = question.split(maxsplit=2)

                    if len(parts) > 2:
                        analysis_type = parts[1].lower()
                        target = parts[2]
                    else:
                        analysis_type = "analysis"
                        target = question

                    report = Report(
                        user_id=current_user.id,
                        analysis_type=analysis_type,
                        target=target,
                        result=result
                    )

                    db.session.add(report)
                    db.session.commit()

                    print("REPORT SAVED:", analysis_type, target)

                except Exception as e:
                    if getattr(e, "response", None) is not None and e.response.status_code == 429:
                        return jsonify({
                            "answer": "HackProof AI has reached the Gemini free-tier limit. Please try again later."
                        })

        local_answer = retrieve_knowledge(question)
        if local_answer and local_answer != "No directly relevant information found.":
            return jsonify({
                "answer": markdown.markdown(local_answer, extensions=["tables", "fenced_code"])
            })

        return jsonify({
            "answer": "Gemini is temporarily unavailable. Please try again shortly."
        })

    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>HackProof AI - Security Analysis</title>

    <style>
        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            background: #0f172a;
            color: #e5e7eb;
            font-family: Arial, sans-serif;
        }}

        .page {{
            max-width: 900px;
            margin: 50px auto;
            padding: 30px;
        }}

        .card {{
            background: #111827;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 25px;
        }}

        input {{
            width: 100%;
            padding: 13px;
            margin: 12px 0;
            border: 1px solid #475569;
            border-radius: 8px;
            background: #1e293b;
            color: white;
        }}

        button {{
            padding: 12px 22px;
            border: 0;
            border-radius: 8px;
            font-weight: bold;
            cursor: pointer;
        }}

        .result {{
            margin-top: 20px;
            padding: 18px;
            background: #1e293b;
            border-radius: 8px;
            white-space: pre-wrap;
        }}

        a {{
            color: #93c5fd;
        }}
    </style>
</head>

<body>

<div class="page">

    <p>
        <a href="/dashboard">← Back to Dashboard</a>
    </p>

    <div class="card">

        <h1>🔎 Security Analysis</h1>

        <p>
            Use HackProof for authorized security analysis.
        </p>

        <form method="POST">

            <input
                name="question"
                placeholder="Example: analyze port 22"
                required
            >

            <button type="submit">
                Analyze
            </button>

        </form>

        {"<div class='result'>" + result + "</div>" if result else ""}

        <p>
            <a href="/reports">📄 View Reports</a>
        </p>

    </div>

</div>

</body>
</html>
"""
    result = None

    if request.method == "POST":
        question = request.form.get("question", "").strip()

        if question:
            result = handle_analysis_request(question)

            # Save successful analysis as a security report
            if result:
                try:
                    parts = question.split(maxsplit=2)
                    analysis_type = parts[1] if len(parts) > 1 else "analysis"
                    target = parts[2] if len(parts) > 2 else question

                    report = Report(
                        user_id=current_user.id,
                        analysis_type=analysis_type,
                        target=target,
                        result=result
                    )

                    db.session.add(report)
                    db.session.commit()

                    print("[+] Security report saved successfully.")

                except Exception as e:
                    db.session.rollback()
                    print(f"[!] Report save failed: {e}")

    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>HackProof AI - Security Analysis</title>
    <style>
        * {{ box-sizing: border-box; }}

        body {{
            margin: 0;
            background: #0f172a;
            color: #e5e7eb;
            font-family: Arial, sans-serif;
        }}

        .page {{
            max-width: 900px;
            margin: 50px auto;
            padding: 30px;
        }}

        .card {{
            background: #111827;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 25px;
        }}

        input {{
            width: 100%;
            padding: 13px;
            margin: 12px 0;
            border: 1px solid #475569;
            border-radius: 8px;
            background: #1e293b;
            color: white;
        }}

        button {{
            padding: 12px 22px;
            border: 0;
            border-radius: 8px;
            font-weight: bold;
            cursor: pointer;
        }}

        .result {{
            margin-top: 20px;
            padding: 18px;
            background: #1e293b;
            border-radius: 8px;
            white-space: pre-wrap;
        }}

        a {{
            color: #93c5fd;
        }}
    </style>
</head>

<body>
<div class="page">

    <p><a href="/dashboard">← Back to Dashboard</a></p>

    <div class="card">

        <h1>🔎 Security Analysis</h1>

        <p>
            Use HackProof for authorized security analysis.
        </p>

        <form method="POST">
            <input
                name="question"
                placeholder="Example: analyze port 22"
                required
            >

            <button type="submit">Analyze</button>
        </form>

        {f'<div class="result">{result}</div>' if result else ''}

    </div>

</div>
</body>
</html>
"""

@app.route("/tools")
@login_required
def tools_page():
    tool_list = "".join(
        f"<li><strong>{name}</strong> — {description}</li>"
        for name, description in TOOL_DESCRIPTIONS.items()
    )

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>HackProof AI - Safe Tools</title>
        <style>
            * {{ box-sizing: border-box; }}
            body {{
                margin: 0;
                background: #0f172a;
                color: #e5e7eb;
                font-family: Arial, sans-serif;
            }}
            .page {{
                max-width: 900px;
                margin: 50px auto;
                padding: 30px;
            }}
            .card {{
                background: #111827;
                border: 1px solid #334155;
                border-radius: 12px;
                padding: 25px;
            }}
            li {{
                margin: 15px 0;
            }}
            a {{
                color: #93c5fd;
            }}
        </style>
    </head>
    <body>
        <div class="page">
            <p><a href="/dashboard">← Back to Dashboard</a></p>

            <div class="card">
                <h1>🛠️ Safe Tools</h1>
                <p>Approved read-only cybersecurity tools:</p>
                <ul>
                    {tool_list}
                </ul>
            </div>
        </div>
    </body>
    </html>
    """


@app.route("/api/phishing", methods=["POST"])
@login_required
def phishing_api():
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", "")).strip()

    if not url:
        return jsonify({"error": "Please provide a URL."}), 400

    result = analyze_url(url)

    return jsonify({
        "url": result["url"],
        "risk": result["risk"],
        "score": result["score"],
        "indicators": result["indicators"],
        "recommendation": result["recommendation"],
        "report": format_result(result),
    })


@app.route("/")
@login_required
def home():
    return HTML


@app.route("/chat", methods=["POST"])
@login_required
def chat():

    data = request.get_json() or {}
    question = data.get("question", "").strip()
    if "project name" in question.lower():
        return jsonify({"answer": "Your project name is <b>HackProof AI</b>."})

    if not question:
        return jsonify({
            "answer": "Please enter a question."
        })

    if question.lower() == "list tools":
        return jsonify({
            "answer": "<b>Available safe tools:</b><br>" + "<br>".join(SAFE_COMMANDS.keys())
        })

    if question.lower().startswith("run tool ") or question.lower().startswith("run tool:"):
        tool_name = question[9:].lstrip(": ").strip()

        if tool_name not in SAFE_COMMANDS:
            return jsonify({
                "answer": "Tool not allowed."
            })

        tool_result = run_safe_tool(tool_name)

        return jsonify({
            "answer": tool_result.replace("\n", "<br>")
        })

    result = handle_analysis_request(question)

    if result is not None:

        return jsonify({
            "answer": result.replace("\n", "<br>")
        })

    try:
        relevant_knowledge = retrieve_knowledge(question)

        if relevant_knowledge and relevant_knowledge != "No directly relevant information found.":
            save_memory(question, relevant_knowledge)
            return jsonify({
                "answer": markdown.markdown(
                    relevant_knowledge,
                    extensions=["tables", "fenced_code"]
                )
            })

        conversation_memory = load_memory()

        prompt = (
            "You are HackProof AI, a cybersecurity learning assistant.\n\n"
            "Use the retrieved local knowledge when relevant.\n"
            "Only provide cybersecurity guidance for authorized systems, "
            "labs, and learning environments.\n\n"
            "RETRIEVED KNOWLEDGE:\n"
            + relevant_knowledge
            + "\n\nCONVERSATION MEMORY:\n"
        + conversation_memory
+ "\n\nUSER QUESTION:\n"
            + question
            + "\n\nAnswer clearly for the user."
        )

        response = None
        for attempt in range(3):
            try:
                api_key = os.getenv("GEMINI_API_KEY")
                api_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent"
                api_response = requests.post(api_url, headers={"Content-Type": "application/json", "x-goog-api-key": api_key}, json={"contents": [{"parts": [{"text": prompt}]}]}, timeout=30)
                api_response.raise_for_status()
                response_data = api_response.json()
                response_text = response_data["candidates"][0]["content"]["parts"][0]["text"]
                response = type("GeminiResponse", (), {"text": response_text})()
                break
            except Exception as e:
                if attempt == 2:
                    raise
                time.sleep(2 ** attempt)

        answer_html = markdown.markdown(
            response.text,
            extensions=["tables", "fenced_code"]
        )

        save_memory(question, response.text)

        return jsonify({
            "answer": answer_html
        })

    except Exception as e:
        memory_answer = retrieve_memory_answer(question)
        if memory_answer:
            return jsonify({
                "answer": markdown.markdown(memory_answer, extensions=["tables", "fenced_code"])
            })
        local_answer = retrieve_knowledge(question)
        if local_answer and local_answer != "No directly relevant information found.":
            return jsonify({
                "answer": markdown.markdown(local_answer, extensions=["tables", "fenced_code"])
            })
        return jsonify({
            "answer": "Gemini is temporarily unavailable. Please try again shortly."
        })


    
@app.route("/knowledge", methods=["GET"])
@login_required
def knowledge_page():
    query = request.args.get("q", "").strip()

    if query:
        knowledge_text = retrieve_knowledge(query)
    else:
        knowledge_text = load_knowledge()

    if not knowledge_text:
        knowledge_text = "No local cybersecurity knowledge is available yet."

    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>HackProof AI - Knowledge Base</title>
    <style>
        body {{
            margin: 0;
            padding: 40px;
            background: #0f172a;
            color: #e5e7eb;
            font-family: Arial, sans-serif;
        }}
        .container {{
            max-width: 1200px;
            margin: auto;
        }}
        .card {{
            background: #111827;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 28px;
        }}
        input {{
            width: 100%;
            box-sizing: border-box;
            padding: 12px;
            margin: 15px 0;
            background: #1e293b;
            color: white;
            border: 1px solid #475569;
            border-radius: 6px;
        }}
        button {{
            padding: 10px 18px;
            border: 0;
            border-radius: 6px;
            cursor: pointer;
        }}
        pre {{
            white-space: pre-wrap;
            line-height: 1.6;
            background: #1e293b;
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
        }}
        a {{
            color: #60a5fa;
        }}
    </style>
</head>
<body>
<div class="container">
    <p><a href="/dashboard">← Back to Dashboard</a></p>

    <div class="card">
        <h1>📚 HackProof Knowledge Base</h1>
        <p>Search HackProof's local cybersecurity knowledge.</p>

        <form method="GET" action="/knowledge">
            <input
                type="text"
                name="q"
                placeholder="Example: What is the CIA Triad?"
                value="{query}"
            >
            <button type="submit">Search</button>
        </form>

        <h2>Knowledge</h2>
        <pre>{knowledge_text}</pre>
    </div>
</div>
</body>
</html>
"""


@app.route("/reports")
@login_required
def reports_page():
    reports = Report.query.filter_by(
        user_id=current_user.id
    ).order_by(Report.created_at.desc()).all()

    report_count = len(reports)

    report_html = ""

    for r in reports:
        report_html += f"""
        <div class="report-card">
            <h3>{r.analysis_type} — {r.target}</h3>
            <small>{r.created_at}</small>
            <pre>{r.result}</pre>
        <p><a href="/reports/{r.id}">🔎 View Details</a></p>
        </div>
        """

    if not report_html:
        report_html = """
        <div class="empty">
            No security reports have been generated yet.
        </div>
        """

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>HackProof AI - Reports</title>
        <style>
            * {{ box-sizing: border-box; }}

            body {{
                margin: 0;
                min-height: 100vh;
                background: #0f172a;
                color: #e5e7eb;
                font-family: Arial, sans-serif;
            }}

            .container {{
                max-width: 1000px;
                margin: 40px auto;
                padding: 20px;
            }}

            a {{
                color: #7dd3fc;
                text-decoration: none;
            }}

            .card {{
                background: #111827;
                border: 1px solid #334155;
                border-radius: 14px;
                padding: 30px;
            }}

            .report-card {{
                background: #1e293b;
                border: 1px solid #334155;
                border-radius: 10px;
                padding: 20px;
                margin-top: 16px;
            }}

            .report-card h3 {{
                margin-top: 0;
                color: #f1f5f9;
            }}

            .report-card small {{
                color: #94a3b8;
            }}

            pre {{
                white-space: pre-wrap;
                background: #0f172a;
                padding: 15px;
                border-radius: 8px;
                margin-top: 15px;
                overflow-x: auto;
            }}

            .empty {{
                padding: 30px;
                text-align: center;
                color: #94a3b8;
            }}
        </style>
    </head>

    <body>
        <div class="container">
            <p><a href="/dashboard">← Back to Dashboard</a></p>

            <div class="card">
                <h1>📄 HackProof Security Reports</h1>
                <p>Saved security analysis reports — <strong>{report_count} reports</strong>.</p>

                {report_html}
            </div>
        </div>
    </body>
    </html>
    """


@app.route("/reports/<int:report_id>")
@login_required
def report_detail(report_id):
    report = Report.query.filter_by(
        id=report_id,
        user_id=current_user.id
    ).first_or_404()

    return f"""
    <html>
    <head>
        <title>HackProof - Report Detail</title>
        <style>
            body {{
                background: #0f172a;
                color: #e5e7eb;
                font-family: Arial, sans-serif;
                padding: 40px;
            }}
            .card {{
                max-width: 900px;
                margin: auto;
                background: #1e293b;
                padding: 30px;
                border-radius: 14px;
            }}
            a {{
                color: #7dd3fc;
            }}
            pre {{
                background: #0f172a;
                padding: 20px;
                border-radius: 8px;
                white-space: pre-wrap;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <p><a href="/reports">← Back to Reports</a></p>
            <h1>🔍 Security Report</h1>
            <h2>{report.analysis_type} — {report.target}</h2>
            <p>Report ID: {report.id}</p>
            <p>Created: {report.created_at}</p>
            <h3>Analysis Result</h3>
            <pre>{report.result}</pre>
        </div>
    </body>
    </html>
    """




@app.route("/scam", methods=["GET", "POST"])
@login_required
def scam_page():
    result = None
    message = ""

    if request.method == "POST":
        message = request.form.get("message", "").strip()
        if message:
            result = analyze_scam(message)

    return f'''
<!DOCTYPE html>
<html>
<head>
    <title>HackProof AI - Scam Detector</title>
    <style>
        body {{
            margin: 0;
            background: #0f172a;
            color: #e5e7eb;
            font-family: Arial, sans-serif;
        }}
        .page {{
            max-width: 900px;
            margin: 40px auto;
            padding: 25px;
        }}
        .card {{
            background: #111827;
            border: 1px solid #334155;
            border-radius: 14px;
            padding: 30px;
        }}
        textarea {{
            width: 100%;
            min-height: 180px;
            padding: 14px;
            margin: 15px 0;
            box-sizing: border-box;
            background: #1e293b;
            color: white;
            border: 1px solid #475569;
            border-radius: 8px;
            font-size: 15px;
        }}
        button {{
            padding: 12px 22px;
            background: #0ea5e9;
            color: white;
            border: 0;
            border-radius: 8px;
            font-weight: bold;
            cursor: pointer;
        }}
        .result {{
            margin-top: 25px;
            padding: 20px;
            background: #1e293b;
            border-radius: 10px;
            white-space: pre-wrap;
        }}
        a {{
            color: #7dd3fc;
        }}
    </style>
</head>
<body>
<div class="page">
    <p><a href="/dashboard">← Back to Dashboard</a></p>

    <div class="card">
        <h1>🛡️ Scam Message Detector</h1>
        <p>Analyze SMS, email, or other messages for common scam indicators.</p>

        <form method="POST">
            <textarea name="message" placeholder="Paste a suspicious message here..." required>{message}</textarea>
            <br>
            <button type="submit">Analyze Message</button>
        </form>

        {('<div class="result">' + format_scam_result(result) + '</div>') if result else ''}
    </div>
</div>
</body>
</html>
'''

@app.route("/phishing", methods=["GET", "POST"])
@login_required
def phishing_page():
    result = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()

        if url:
            result = analyze_url(url)
        else:
            result = {
                "url": "",
                "risk": "UNKNOWN",
                "score": 0,
                "indicators": [],
                "recommendation": "Please enter a URL to analyze."
            }

    risk = result.get("risk", "UNKNOWN") if result else ""
    score = result.get("score", 0) if result else 0
    indicators = result.get("indicators", []) if result else []
    recommendation = result.get("recommendation", "") if result else ""

    indicator_html = ""

    if indicators:
        indicator_html = "".join(
            f'<div class="indicator">⚠️ {indicator}</div>'
            for indicator in indicators
        )
    elif result:
        indicator_html = '<div class="safe-indicator">✓ No strong phishing indicators detected</div>'

    result_html = ""

    if result:
        result_html = f"""
        <section class="results">

            <div class="result-header">
                <div>
                    <div class="eyebrow">SECURITY ANALYSIS</div>
                    <h2>Scan Result</h2>
                </div>

                <div class="risk risk-{risk.lower()}">
                    {risk}
                </div>
            </div>

            <div class="score-card">
                <div class="score-number">{score}</div>
                <div>
                    <div class="score-title">Risk Score</div>
                    <div class="score-scale">0 — 100</div>
                </div>
            </div>

            <div class="target-card">
                <div class="label">ANALYZED URL</div>
                <div class="target">{result.get("url", "")}</div>
            </div>

            <div class="section">
                <h3>🔍 Detected Indicators</h3>
                <div class="indicators">
                    {indicator_html}
                </div>
            </div>

            <div class="recommendation">
                <div class="label">🛡️ RECOMMENDATION</div>
                <p>{recommendation}</p>
            </div>

        </section>
        """

    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>HackProof AI - Phishing Scanner</title>

    <style>
        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            background: #0b1220;
            color: #e5e7eb;
            font-family: Arial, sans-serif;
        }}

        .page {{
            max-width: 1050px;
            margin: 0 auto;
            padding: 45px 28px;
        }}

        a {{
            color: #7dd3fc;
        }}

        .back {{
            margin-bottom: 22px;
        }}

        .card {{
            background: #111827;
            border: 1px solid #334155;
            border-radius: 16px;
            padding: 32px;
            box-shadow: 0 15px 40px rgba(0,0,0,.25);
        }}

        .top {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 20px;
        }}

        h1 {{
            margin: 0;
            font-size: 32px;
        }}

        .subtitle {{
            color: #94a3b8;
            margin: 10px 0 30px;
        }}

        .badge {{
            border: 1px solid #0ea5e9;
            color: #7dd3fc;
            padding: 8px 12px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: bold;
        }}

        form {{
            display: flex;
            gap: 12px;
        }}

        input {{
            flex: 1;
            padding: 15px;
            border: 1px solid #475569;
            border-radius: 9px;
            background: #1e293b;
            color: white;
            font-size: 16px;
        }}

        button {{
            padding: 15px 24px;
            border: 0;
            border-radius: 9px;
            background: #0ea5e9;
            color: white;
            font-weight: bold;
            cursor: pointer;
        }}

        button:hover {{
            opacity: .9;
        }}

        .results {{
            margin-top: 28px;
            border-top: 1px solid #334155;
            padding-top: 28px;
        }}

        .result-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .eyebrow,
        .label {{
            font-size: 11px;
            letter-spacing: 1px;
            color: #94a3b8;
            font-weight: bold;
        }}

        h2 {{
            margin: 5px 0 0;
        }}

        .risk {{
            padding: 10px 18px;
            border-radius: 999px;
            font-weight: bold;
            font-size: 13px;
        }}

        .risk-low {{
            background: #123524;
            color: #86efac;
            border: 1px solid #166534;
        }}

        .risk-medium {{
            background: #3b2f0b;
            color: #fde68a;
            border: 1px solid #a16207;
        }}

        .risk-high {{
            background: #3f1219;
            color: #fca5a5;
            border: 1px solid #b91c1c;
        }}

        .risk-unknown {{
            background: #1e293b;
            color: #cbd5e1;
            border: 1px solid #475569;
        }}

        .score-card {{
            display: flex;
            align-items: center;
            gap: 18px;
            margin-top: 22px;
            padding: 22px;
            background: #172235;
            border-radius: 12px;
        }}

        .score-number {{
            font-size: 48px;
            font-weight: bold;
        }}

        .score-title {{
            font-size: 17px;
            font-weight: bold;
        }}

        .score-scale {{
            color: #94a3b8;
            margin-top: 5px;
        }}

        .target-card {{
            margin-top: 16px;
            padding: 18px;
            background: #172235;
            border-radius: 12px;
        }}

        .target {{
            margin-top: 8px;
            word-break: break-all;
            color: #dbeafe;
        }}

        .section {{
            margin-top: 24px;
        }}

        h3 {{
            font-size: 16px;
        }}

        .indicator {{
            padding: 12px 14px;
            margin-top: 8px;
            background: #251b1e;
            border: 1px solid #4b2930;
            border-radius: 8px;
            color: #fecaca;
        }}

        .safe-indicator {{
            padding: 12px 14px;
            background: #123524;
            border: 1px solid #166534;
            border-radius: 8px;
            color: #bbf7d0;
        }}

        .recommendation {{
            margin-top: 24px;
            padding: 18px;
            background: #172235;
            border-left: 4px solid #0ea5e9;
            border-radius: 8px;
        }}

        .recommendation p {{
            margin-bottom: 0;
            color: #cbd5e1;
            line-height: 1.5;
        }}

        @media (max-width: 700px) {{
            form {{
                flex-direction: column;
            }}

            .top {{
                flex-direction: column;
            }}

            .result-header {{
                align-items: flex-start;
                gap: 15px;
                flex-direction: column;
            }}
        }}
    </style>
</head>

<body>

<div class="page">

    <div class="back">
        <a href="/dashboard">← Back to Dashboard</a>
    </div>

    <div class="card">

        <div class="top">
            <div>
                <h1>🔎 Phishing URL Scanner</h1>
                <p class="subtitle">
                    Analyze a URL locally for common phishing indicators.
                </p>
            </div>

            <div class="badge">
                LOCAL ANALYSIS
            </div>
        </div>

        <form method="POST">
            <input
                type="url"
                name="url"
                placeholder="https://example.com"
                required
            >

            <button type="submit">
                Analyze URL
            </button>
        </form>

        {result_html}

    </div>

</div>

</body>
</html>
"""


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
