@echo off
setlocal
cd /d "%~dp0"
title PatchPilot

if not exist ".venv\Scripts\python.exe" (
  echo [PatchPilot] Creating virtual environment...
  python -m venv .venv || (echo Python 3.10+ is required & pause & exit /b 1)
)

echo [PatchPilot] Installing dependencies...
".venv\Scripts\python.exe" -m pip install -q --disable-pip-version-check -r requirements.txt || (pause & exit /b 1)

if not exist ".env" (
  copy ".env.example" ".env" >nul
  echo [PatchPilot] Created .env - add NEBIUS_API_KEY and TAVILY_API_KEY, then run again.
  notepad ".env"
  pause
  exit /b 0
)

if "%PORT%"=="" set PORT=8000
echo [PatchPilot] Starting on http://localhost:%PORT%
start "" "http://localhost:%PORT%"
".venv\Scripts\python.exe" -m uvicorn patchpilot.app.server:app --host 127.0.0.1 --port %PORT%
pause
