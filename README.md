# 🛡️ HackProof AI

HackProof AI is a cybersecurity learning and authorized security-analysis platform designed to help users understand cybersecurity concepts, analyze security-related data, work with a local cybersecurity knowledge base, and generate security reports.

> **Authorized-use only:** Use HackProof only on systems, networks, URLs, domains, IP addresses, and data that you own or are explicitly authorized to test.

---

## 🚀 Features

### 🤖 AI Cybersecurity Assistant
- Ask cybersecurity questions through a ChatGPT-style interface
- Receive cybersecurity explanations and guidance
- Conversation memory support
- Local cybersecurity knowledge retrieval

### 🔎 Security Analysis
- Authorized security analysis workflow
- Security intelligence analysis
- Threat correlation
- Phishing URL analysis
- Scam detection
- Unified threat analysis

### 📚 Cybersecurity Knowledge Base
HackProof includes a local knowledge base covering areas such as:
- Cybersecurity fundamentals
- Networking
- Security concepts

### 🛠️ Security Tools
HackProof provides controlled cybersecurity tooling designed for authorized environments.

### 📊 Security Reports
- Save security-analysis results
- View generated reports
- Review previous security reports

### 🔐 Security
- Authentication-protected dashboard and analysis routes
- Authentication-protected security APIs
- Environment-based secret configuration
- HTTP-only session cookies
- SameSite session protection
- Debug mode disabled by default
- Production Gunicorn configuration

### 📱 Responsive Interface
The dashboard has been tested at:

- Desktop layout
- Mobile layout: **390 × 844**

Mobile improvements include:
- Responsive metric cards
- Responsive content grids
- Responsive risk sections
- Hidden sidebar on small screens
- Mobile-friendly AI assistant

---

## 🏗️ Project Structure

```text
hackproof/
├── web_app.py
├── main.py
├── auth.py
├── connect_tools.py
├── analysis_router.py
├── security_analysis.py
├── security_intelligence.py
├── threat_correlation.py
├── tools.py
├── scam_detector.py
├── phishing_detector.py
├── unified_threat_analyzer.py
├── init_db.py
│
├── knowledge/
│   ├── cybersecurity_basics.txt
│   ├── linux.txt
│   └── networking.txt
│
├── instance/
│   └── hackproof.db
│
├── memory.txt
├── requirements.txt
├── start_production.sh
└── .gitignore
