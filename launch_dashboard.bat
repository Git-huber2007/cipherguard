@echo off
setlocal enabledelayedexpansion
title CipherGuard - Dual-Layer Wireless and VPN Security Platform
cls

:: Ensure we are running from the directory where this script is located
cd /d "%~dp0"

echo ======================================================================
echo   CIPHERGUARD - DUAL-LAYER SECURITY PLATFORM (Wi-Fi + IPsec/VPN)
echo   SIH26160 / NTRO Compliance - NIST SP 800-77 and RFC 8247 Hardening
echo ======================================================================
echo.

set "PY_EXE="

:: 1. Check Python 3.12 default install path
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
    set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
)

:: 2. Check py launcher
if not defined PY_EXE (
    where py >nul 2>nul
    if !errorlevel! equ 0 (
        set "PY_EXE=py -3"
    )
)

:: 3. Check python on PATH
if not defined PY_EXE (
    where python >nul 2>nul
    if !errorlevel! equ 0 (
        set "PY_EXE=python"
    )
)

:: 4. Verify python is available
if not defined PY_EXE (
    echo [ERROR] Python 3.10+ was not found on your system.
    echo Please install Python from https://www.python.org/downloads/
    echo and ensure "Add Python to PATH" is checked during installation.
    echo.
    pause
    exit /b 1
)

echo [*] Project Directory: %CD%
echo [*] Python Interpreter: !PY_EXE!
echo [*] Launching CipherGuard Dashboard on http://127.0.0.1:8000/ ...
echo [*] Opening your default web browser...
echo [*] (Keep this window open. Press Ctrl+C anytime to stop the server.)
echo ======================================================================
echo.

:: Open browser after 2 seconds in background
start "" "http://127.0.0.1:8000/"

:: Start dashboard server
!PY_EXE! -m cipherguard.cli serve --port 8000

if !errorlevel! neq 0 (
    echo.
    echo [!] Server exited with an error code.
    pause
)
