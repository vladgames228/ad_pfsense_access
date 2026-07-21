@echo off
setlocal enabledelayedexpansion

net session >nul 2>&1
if %errorlevel% neq 0 (powershell -Command "Start-Process '%~f0' -Verb RunAs"&exit /b)
cd /d "%~dp0"
set "SERVICE_NAME=AD_Pfsense_Access"
set "APP_DIR=C:\Windows\ad_pfsense_access"

echo [INFO] Checking for Python...
where python >nul 2>&1
if %errorlevel% neq 0 (echo [ERROR] No python binary found&pause&exit /b 1)

echo [INFO] Checking and cleaning previous installation...
sc query "%SERVICE_NAME%" >nul 2>&1
if %errorlevel% equ 0 (
    .\nssm.exe stop "%SERVICE_NAME%" >nul 2>&1
    .\nssm.exe remove "%SERVICE_NAME%" confirm >nul 2>&1
    timeout /t 2 /nobreak >nul
)
if exist "%APP_DIR%" rmdir /s /q "%APP_DIR%"

echo [INFO] Creating app directory...
mkdir "%APP_DIR%"

echo [INFO] Copying files...
copy /y ".\main.py" "%APP_DIR%\" >nul
copy /y ".\config.json" "%APP_DIR%\" >nul
copy /y ".\requirements.txt" "%APP_DIR%\" >nul
copy /y ".\nssm.exe" "%APP_DIR%\" >nul
copy /y ".\.env" "%APP_DIR%\" >nul
if %errorlevel% neq 0 (echo [ERROR] Failed to copy files!&pause&exit /b 1)

echo [INFO] Creating Python venv...
python -m venv "%APP_DIR%\venv"
if !errorlevel! neq 0 (echo [ERROR] Failed to create venv!&pause&exit /b 1)

echo [INFO] Installing required libraries...
"%APP_DIR%\venv\Scripts\pip.exe" install -r "%APP_DIR%\requirements.txt" >nul
if %errorlevel% neq 0 (echo [ERROR] Failed to install libraries!&pause&exit /b 1)

echo [INFO] Installing and configuring service...
set "NSSM_EXE=%APP_DIR%\nssm.exe"
"%NSSM_EXE%" install "%SERVICE_NAME%" "%APP_DIR%\venv\Scripts\python.exe" "%APP_DIR%\main.py" >nul
"%NSSM_EXE%" set "%SERVICE_NAME%" AppDirectory "%APP_DIR%" >nul
"%NSSM_EXE%" set "%SERVICE_NAME%" AppStdout "%APP_DIR%\service_out.log" >nul
"%NSSM_EXE%" set "%SERVICE_NAME%" AppStderr "%APP_DIR%\service_err.log" >nul
"%NSSM_EXE%" set "%SERVICE_NAME%" Start SERVICE_AUTO_START >nul
"%NSSM_EXE%" set "%SERVICE_NAME%" AppRestartDelay 5000 >nul

echo [INFO] Starting service...
"%NSSM_EXE%" start "%SERVICE_NAME%" >nul

echo [INFO] Verifying service status...
sc query "%SERVICE_NAME%" | find "RUNNING" >nul
if %errorlevel% equ 0 (echo [OK] Service successfully installed. Logs: %APP_DIR%) else (echo [ERROR] Something went wrong :()

pause