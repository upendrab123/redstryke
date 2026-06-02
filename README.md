# REDSTRYKE - Autonomous AI Red Teamer

**Find security vulnerabilities in AI chatbots automatically.**

---

## What is REDSTRYKE?

FORGE is an automated security testing tool that finds weaknesses in AI chatbots (LLMs). You give it a target URL, and it automatically runs attack tests, evaluates the results, learns from each test, and creates professional PDF reports.

Think of it like a security camera that watches your AI chatbot 24/7 and alerts you when someone tries to break in.

---

## Who is this for?

- **Security Teams** - Test AI applications before release
- **Developers** - Find vulnerabilities in chatbots you've built
- **Red Teamers** - Evaluate AI safety for clients
- **Researchers** - Study AI security vulnerabilities
- **Companies** - Audit AI vendors they're considering

---

## What can REDSTRYKE find?

- 🔓 **Jailbreaks** - Tricks that make AI ignore safety rules
- 💉 **Prompt Injection** - Hidden commands inside normal messages
- 📊 **Data Leaks** - Accidental exposure of private information
- 🎭 **Persona Hijacking** - Making AI pretend to be someone else
- ⚖️ **Authority Impersonation** - AI pretending to be an expert

---

## 📺 How to View the Dashboard

After installing FORGE, you have two ways to use it:

### Option 1: Web Dashboard (Recommended) ⭐

The dashboard shows a visual interface where you can:
- Start scans with a click
- Watch progress in real-time
- View all findings and reports

**Start the dashboard:**
```bash
cd redstryke
python -m uvicorn dashboard.app:app --host 0.0.0.0 --port 7860
```

**Then open in your browser:**
```
http://localhost:7860
```

You'll see:
- 📊 **Dashboard** - Stats, severity bars, recent activity
- 🎯 **New Scan** - Start a scan with easy form
- 📁 **Engagements** - All your scan history
- 🐞 **Findings** - All vulnerabilities found
- 📄 **Reports** - Download PDF reports

### Option 2: Command Line (Advanced)

Run scans directly without the web interface:

```bash
python main.py --target "https://api.openai.com/v1/chat/completions" --description "My AI chatbot"
```

Results are saved to:
- **Reports:** `data/reports/`
- **Database:** `data/memory.db`

---

## Quick Start (5 minutes)

### 1. Get a Groq API Key (Free)

1. Go to [console.groq.com](https://console.groq.com)
2. Create an account
3. Click "Create API Key"
4. Copy the key (you'll paste it in step 3)

### 2. Install FORGE

```bash
# Clone the project
git clone https://github.com/YOUR_USERNAME/redstryke.git
cd redstryke

# Create environment file
copy .env.template .env

# Edit .env and paste your Groq API key
# (Open .env in a text editor, replace the placeholder key)

# Install dependencies
pip install -r requirements.txt
```

### 3. Run Your First Scan

**Option A - Using the Dashboard (Recommended)**

```bash
python -m uvicorn dashboard.app:app --host 0.0.0.0 --port 7860
```

Then open http://localhost:7860 in your browser!

**Option B - Command Line**

```bash
python main.py --target "https://api.openai.com/v1/chat/completions" --description "My AI chatbot"
```

---

## How to Use FORGE

### Using the Dashboard

1. Open http://localhost:7860
2. Click **New Scan** in the sidebar
3. Enter your target URL (e.g., your chatbot's API endpoint)
4. Give it a description (e.g., "Customer service bot for a bank")
5. Choose scan depth:
   - **Quick** - ~30 minutes (basic tests)
   - **Standard** - ~2 hours (recommended)
   - **Deep** - ~8 hours (comprehensive)
6. Click **Start Scan**
7. Watch real-time progress in the **Live Scan** tab
8. When complete, click **Generate Report** to download PDF

### Command Line Options

```bash
# Basic scan
python main.py --target "https://api.example.com/chat" --description "My bot"

# Scan with Groq API key
python main.py --target "URL" --description "Bot" --api-key "gsk_..."

# Deep scan
python main.py --target "URL" --description "Bot" --depth deep

# Skip vector memory (faster on slow computers)
python main.py --target "URL" --description "Bot" --no-vector-memory
```

---

## Features

### ✅ Working Now

- **Automated Attack Testing** - Runs security tests without manual intervention
- **Multiple Attack Types** - Jailbreaks, prompt injection, data leakage, and more
- **Real-time Progress** - Watch scans happen live in the dashboard
- **Learning Memory** - Gets smarter by remembering successful attacks
- **Professional Reports** - PDF reports with findings, severity, and recommendations
- **SQLite Database** - All scan history stored locally
- **Web Dashboard** - Easy-to-use interface with FastAPI

### ⚠️ Known Limitations

- **PyRIT not compatible with Python 3.14** - Uses Garak only for now
- **Requires internet** - Needs Groq API to plan attacks
- **No macOS/Linux GPU acceleration** - CPU only for embeddings
- **Limited to HTTP endpoints** - Doesn't test web UIs

---

## Understanding Scan Results

When FORGE finds a vulnerability, it categorizes by severity:

| Severity | Meaning | Action Needed |
|----------|---------|---------------|
| 🔴 **Critical** | AI completely bypassed safety | Urgent fix required |
| 🟠 **High** | Significant bypass achieved | Priority fix needed |
| 🔵 **Medium** | Partial bypass | Review recommended |
| 🟢 **Low** | Minor issue | Consider fixing |

Each finding includes:
- What the attack was
- How to reproduce it
- Which regulations apply (OWASP, EU AI Act, NIST)
- Recommendations for fixing

---

## Project Structure

```
redstryke/
├── main.py              # Command-line interface
├── dashboard/           # Web dashboard
│   ├── app.py         # FastAPI backend
│   └── static/        # HTML/CSS/JS
├── core/              # Core engine
│   ├── planner/      # Attack planning (Groq)
│   ├── executor/      # Attack runners (Garak/PyRIT)
│   ├── evaluator/     # Finding evaluation
│   ├── memory/       # SQLite + ChromaDB
│   └── reporter/     # PDF report generator
├── data/              # Scan results and reports
├── config/            # Configuration files
└── tests/             # Unit tests
```

---

## Troubleshooting

### "GROQ_API_KEY not found" error
- Make sure you created a `.env` file
- Paste your Groq API key in the .env file

### "No module named 'something'" error
- Run: `pip install -r requirements.txt`
- Make sure you installed all dependencies

### Scan runs forever with no results
- Check your target URL is correct
- Verify the API accepts connections
- Try a smaller scan (--depth quick)

### Dashboard won't load
- Make sure port 7860 isn't in use
- Try: `python -m uvicorn dashboard.app:app --port 8080`

---

## Getting Help

- **Report bugs**: Open an issue on GitHub
- **Ask questions**: Use GitHub Discussions
- **Contribute**: See CONTRIBUTING.md

---

## License

See LICENSE file. This is an open-source security tool intended for authorized testing only. Always get permission before testing systems you don't own.

---

## Credits

- Built with [Garak](https://github.com/NVIDIA/garak) for attack probes
- Uses [Groq](https://groq.com) for AI planning
- PDF generation with [xhtml2pdf](https://github.com/xhtml2pdf/xhtml2pdf)