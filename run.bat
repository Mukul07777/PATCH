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

rem Already running? Then just open it instead of failing with "address already in use".
powershell -NoProfile -Command "try { $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 http://127.0.0.1:%PORT%/api/health; if ($r.Content -match 'nebius|status|ok') { exit 0 } } catch {}; exit 1" >nul 2>&1
if not errorlevel 1 (
  echo [PatchPilot] Already running on http://localhost:%PORT% - opening it.
  start "" "http://localhost:%PORT%"
  timeout /t 3 >nul
  exit /b 0
)

rem Port taken by some other program? Use the next free one.
:findport
powershell -NoProfile -Command "if (Get-NetTCPConnection -LocalPort %PORT% -State Listen -ErrorAction SilentlyContinue) { exit 1 } else { exit 0 }" >nul 2>&1
if errorlevel 1 (
  echo [PatchPilot] Port %PORT% is used by another program, trying the next one...
  set /a PORT=%PORT%+1
  goto findport
)

echo [PatchPilot] Starting on http://localhost:%PORT%  (keep this window open; close it to stop PatchPilot)
start "" "http://localhost:%PORT%"
".venv\Scripts\python.exe" -m uvicorn patchpilot.app.server:app --host 127.0.0.1 --port %PORT%
echo.
echo [PatchPilot] The server stopped. Scroll up to see why, then press a key to close this window.
pause
