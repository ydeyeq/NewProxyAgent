@echo off
echo Setting up environment...

if not exist venv (
    python -m venv venv
    echo Virtual environment created.
) else (
    echo Virtual environment already exists.
)

call venv\Scripts\activate
python -m pip install --upgrade pip

if exist requirements.txt (
    pip install -r requirements.txt
    echo Dependencies installed.
) else (
    echo requirements.txt not found!
)

echo Setup complete! To run:
echo venv\Scripts\activate && python web_agent.py
pause
