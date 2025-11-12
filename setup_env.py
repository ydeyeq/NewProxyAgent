#!/usr/bin/env python3
"""
Smart environment setup for Proxy Agent
- Detects Python version
- Creates virtual environment if needed
- Installs compatible dependencies automatically
"""

import sys
import subprocess
import os
from pathlib import Path

# --- Python version check ---
py_version = sys.version_info
print(f"🔍 Detected Python {py_version.major}.{py_version.minor}")

if py_version < (3, 9):
    print("❌ Python 3.9 or higher is required to run this project.")
    sys.exit(1)

# --- Ensure virtual environment ---
venv_dir = Path("venv")
if not venv_dir.exists():
    print("🧱 Creating virtual environment...")
    subprocess.run([sys.executable, "-m", "venv", "venv"], check=True)
else:
    print("🔹 Virtual environment already exists.")

# --- Activate virtual environment programmatically ---
if os.name == "nt":
    activate_path = venv_dir / "Scripts" / "python.exe"
else:
    activate_path = venv_dir / "bin" / "python"

# --- Upgrade pip ---
print("⬆️  Upgrading pip...")
subprocess.run([activate_path, "-m", "pip", "install", "--upgrade", "pip"], check=True)

# --- Base dependencies ---
base_reqs = [
    "blinker>=1.6",
    "certifi>=2023.0.0",
    "charset-normalizer>=3.2",
    "urllib3>=2.0.0",
    "idna>=3.0",
    "requests>=2.31.0",
]

# --- Flask and Click based on Python version ---
if py_version >= (3, 10):
    flask_reqs = ["Flask>=3.0.0", "click>=8.1.7"]
else:
    flask_reqs = ["Flask>=2.3.3,<3.0", "click>=8.1.7,<8.3"]

all_reqs = base_reqs + flask_reqs

print("📦 Installing dependencies:")
for pkg in all_reqs:
    print("  -", pkg)
    subprocess.run([activate_path, "-m", "pip", "install", "--upgrade", pkg], check=True)

print("✅ Environment setup complete!")
print("🎉 To run the app:")
if os.name == "nt":
    print("venv\\Scripts\\activate && python web_agent.py")
else:
    print("source venv/bin/activate && python web_agent.py")
