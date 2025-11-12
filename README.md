# 🕵️‍♂️ NewProxyAgent

**Proxy Agent (Dual Mode + Duplicate Mode)** — a unified input/output proxy resolver with IPQS integration.

---

## 🚀 Features
- Input supports: `HOST:PORT`, `USER:PASS@HOST:PORT`, `HOST:PORT:USER:PASS`, `socks5://...`
- Automatically normalizes to `socks5h://user:pass@host:port`
- Duplicate handling:
  - `drop_all` — removes all duplicate IPs  
  - `keep_one` — keeps one and shows duplication count  
  - `keep_all` — keeps every entry
- Two proxy modes:
  - **Resolve Only**
  - **Resolve + IPQS**
- Built-in caching, retries, and multithreading  
- Web interface powered by Flask  
- Auto environment setup for any new user (cross-platform)
- Python-version aware setup — automatically installs compatible dependencies

---

## ⚙️ Installation
Clone the repository:
```bash
git clone https://github.com/ydeyeq/NewProxyAgent.git
cd NewProxyAgent
Run the setup script (this auto-creates a virtual environment and installs dependencies):

macOS / Linux

bash
Copy code
./setup_env.sh
Windows (PowerShell or Git Bash)

bash
Copy code
python setup_env.py
🧠 Usage
After setup, start the agent:

bash
Copy code
source venv/bin/activate        # macOS / Linux
# or
venv\Scripts\activate           # Windows

python web_agent.py
Then open your browser and go to:
👉 http://127.0.0.1:5000

Paste proxies, choose your mode, and process.

📦 Dependencies
Listed in requirements.txt but automatically managed by the setup script.

Flask (2.3+ / 3.x depending on Python version)

requests

urllib3

PySocks

blinker

certifi

charset-normalizer

idna

🧰 Folder Structure
bash
Copy code
NewProxyAgent/
├── venv/                # auto-created virtual environment
├── web_agent.py         # main Flask app
├── requirements.txt     # dependency list (universal ranges)
├── setup_env.py         # smart Python-version aware setup
├── setup_env.sh         # shell wrapper for macOS/Linux
├── setup_env.bat        # optional Windows wrapper
└── .gitignore
��‍💻 Contributing
Pull requests and issues are welcome!
If you’d like to add new features or improve duplicate-handling logic, fork the repo and open a PR.

📄 License
MIT License © 2025 ydeyeq
