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
```bash
git clone https://github.com/ydeyeq/NewProxyAgent.git
cd NewProxyAgent

