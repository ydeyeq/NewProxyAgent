#!/bin/bash
echo "🔧 Setting up environment..."

# Create virtual environment if not exists
if [ ! -d "venv" ]; then
  python3 -m venv venv
  echo "✅ Virtual environment created."
else
  echo "🔹 Virtual environment already exists."
fi

# Activate it
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies
if [ -f "requirements.txt" ]; then
  pip install -r requirements.txt
  echo "✅ Dependencies installed."
else
  echo "⚠️ requirements.txt not found!"
fi

echo "🎉 Setup complete! To run:"
echo "source venv/bin/activate && python web_agent.py"