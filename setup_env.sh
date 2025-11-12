#!/bin/bash
echo "🚀 Proxy Agent smart setup starting..."

# Detect Python 3.x
PYTHON=$(command -v python3 || command -v python)
if [ -z "$PYTHON" ]; then
  echo "❌ Python 3 not found. Please install Python 3.9 or higher."
  exit 1
fi

echo "🧠 Using $($PYTHON --version)"

# Run Python setup script
$PYTHON setup_env.py
