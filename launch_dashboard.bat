@echo off
title CipherGuard - Dual-Layer Wireless & VPN Security Assessment Platform
cls
echo ======================================================================
echo   CIPHERGUARD - DUAL-LAYER SECURITY PLATFORM (Wi-Fi + IPsec/VPN)
echo   SIH26160 / NTRO Compliance - NIST SP 800-77 & RFC 8247 Hardening
echo ======================================================================
echo.

set PY_EXE=
if exist %LOCALAPPDATA%\Programs\Python\Python312\python.exe (
    set PY_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe
) else (
    where python >nul 2>nul
    if %errorlevel% equ 0 (
        set PY_EXE=python
    ) else (
        where py >nul 2>nul
        if %errorlevel% equ 0 (
            set PY_EXE=py
        )
    )
)

if %PY_EXE%==" (
 echo [ERROR] Python 3.10+ could not be located.
 echo Please install Python 3.10+ and add it to PATH.
 pause
 exit /b 1
)

echo [*] Python Interpreter: %PY_EXE%
echo [*] Launching CipherGuard Dashboard on http://127.0.0.1:8000/ ...
echo [*] Press Ctrl+C anytime to stop the server.
echo.

timeout /t 2 >nul
start  http://127.0.0.1:8000/
%PY_EXE% -m cipherguard.cli serve --port 8000
pause
