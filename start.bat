@echo off
echo Starting AI Security Agent...
cd /d "%~dp0backend"
pip install -r ../requirements.txt -q
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
pause
