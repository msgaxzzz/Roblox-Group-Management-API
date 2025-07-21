@echo off
setlocal enabledelayedexpansion

where python >nul 2>&1
if %errorlevel%==0 (
    set PYTHON_CMD=python
) else (
    where python3 >nul 2>&1
    if %errorlevel%==0 (
        set PYTHON_CMD=python3
    ) else (
        echo Neither python nor python3 found. Exiting.
        pause
        exit /b
    )
)

:loop
echo [%date% %time%] Restarting Main.py

for /f "tokens=2" %%a in ('tasklist ^| findstr /i Main.py') do (
    echo Killing process %%a
    taskkill /PID %%a /F
)

start "" %PYTHON_CMD% Main.py

echo [%date% %time%] Started new Main.py
timeout /t 700 /nobreak >nul
goto loop