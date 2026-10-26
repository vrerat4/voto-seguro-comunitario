@echo off
cd /d "%~dp0"
set PY=py
where py >nul 2>nul || set PY=python
%PY% -m pip install -q -r requirements.txt
%PY% server.py
pause
