@echo off
cd /d "%~dp0"
python -m uvicorn dashboard.app:app --host 0.0.0.0 --port 7860