@echo off
cd /d "%~dp0"
title CP-DFIR Investigation Console (web application)
set PY=
where python >nul 2>&1 && set PY=python
if "%PY%"=="" where py >nul 2>&1 && set PY=py
if "%PY%"=="" goto nopython
%PY% -c "import networkx, Evtx, boto3, psutil, flask, waitress" >nul 2>&1
if errorlevel 1 (
  echo Zaroori packages install ho rahe hain. Ye sirf ek baar hoga, internet chahiye.
  %PY% -m pip install -r requirements.txt
)
echo.
echo  ==========================================================
echo     CP-DFIR Investigation Console
echo     Browser apne aap khulega:  http://127.0.0.1:5000
echo     Band karne ke liye ye window close karo (ya Ctrl+C)
echo  ----------------------------------------------------------
echo     Live triage me Windows Security log bhi chahiye to
echo     is file par Right-click -^> "Run as administrator"
echo  ==========================================================
echo.
%PY% webapp\app.py
pause
goto :eof
:nopython
echo Python nahi mila. python.org/downloads se install karo aur "Add python.exe to PATH" tick karna.
pause
