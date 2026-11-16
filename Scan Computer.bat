@echo off
rem System Scanner - normal scan (no admin prompt). Read-only.
cd /d "%~dp0"
where pyw >nul 2>nul && (start "" pyw -3 "%~dp0system_scanner.py" %* & exit /b 0)
where pythonw >nul 2>nul && (start "" pythonw "%~dp0system_scanner.py" %* & exit /b 0)
echo Python 3 was not found. Install it from https://www.python.org/downloads/
echo (tick "Add python.exe to PATH" during setup), then run this again.
pause
