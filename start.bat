@echo off
setlocal
cd /d "%~dp0"
chcp 65001 >nul

where python >nul 2>nul
if errorlevel 1 goto no_python

python -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"
if errorlevel 1 goto old_python

if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 goto venv_failed
)

call ".venv\Scripts\activate.bat"
python -m pip install --disable-pip-version-check -q -r requirements.txt
if errorlevel 1 goto pip_failed

python main.py
goto end

:no_python
echo [ERROR] Python was not found in PATH. Install Python 3.11 or newer from python.org.
goto end

:old_python
echo [ERROR] Python 3.11 or newer is required.
goto end

:venv_failed
echo [ERROR] Could not create the virtual environment.
goto end

:pip_failed
echo [ERROR] Could not install dependencies. Check your internet connection.
goto end

:end
pause
endlocal
