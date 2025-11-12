# 🕵️‍♂️ NewProxyAgent

**Proxy Agent (Dual Mode + Duplicate Mode)** — unified input/output proxy resolver with IPQS integration.

---

## 🚀 Features
- Input supports: `HOST:PORT`, `USER:PASS@HOST:PORT`, `HOST:PORT:USER:PASS`, `socks5://...`
- Normalizes to `socks5h://user:pass@host:port`
- Duplicate handling:
  - `drop_all` — removes all duplicate IPs  
  - `keep_one` — keeps one and shows duplication count  
  - `keep_all` — keeps every entry
- Two proxy modes:
  - **Resolve Only**
  - **Resolve + IPQS**
- Built-in caching, retries, and multithreading  
- Web interface powered by Flask  
- Auto environment setup for any new user

---

## ⚙️ Installation

Clone the repository:
<pre><code>bash
git clone https://github.com/ydeyeq/NewProxyAgent.git
cd NewProxyAgent
</code></pre>

Run the setup script (this auto-creates a virtual environment and installs dependencies):

**macOS / Linux**
<pre><code>bash
./setup_env.sh
</code></pre>

**Windows**
<pre><code>bat
setup_env.bat
</code></pre>

---

## 🧠 Usage
After setup, start the agent:
<pre><code>bash
python web_agent.py
</code></pre>

Then open your browser and go to:  
👉 [http://127.0.0.1:5000](http://127.0.0.1:5000)

Paste proxies, choose your mode, and process.

---

## 📦 Dependencies
Listed in [`requirements.txt`](./requirements.txt)

- Flask  
- requests  
- urllib3  
- pysocks  
- ipaddress  

---

## 🧰 Folder Structure
<pre><code>
NewProxyAgent/
├── venv/                # auto-created virtual environment
├── web_agent.py         # main app
├── requirements.txt     # dependencies
├── setup_env.sh         # setup script (Mac/Linux)
├── setup_env.bat        # setup script (Windows)
└── .gitignore
</code></pre>

---

## 🧑‍💻 Contributing
Pull requests and issues are welcome!  
If you’d like to add new features or improve duplicate-detection logic, fork the repo and open a PR.

---

## 📄 License
MIT License © 2025 [ydeyeq](https://github.com/ydeyeq)
