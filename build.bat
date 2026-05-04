@echo off
title SecureWatch — Build
color 0B

echo.
echo  ================================================
echo   SecureWatch v1.0 — Build Tool
echo   Author: Abdulelah Mutlaq Alotaibe
echo  ================================================
echo.

:: Check Python
python --version > nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Python not installed!
    echo  Download: https://www.python.org/downloads/
    pause & exit
)
echo  [OK] Python found

:: Install requirements
echo  [*] Installing requirements...
pip install customtkinter pyinstaller pillow -q
echo  [OK] Done

:: Generate Icon
echo  [*] Creating icon...
python make_icon.py
echo  [OK] SecureWatch.ico created

:: Build EXE
echo  [*] Building SecureWatch.exe ...
echo      Please wait 2-3 minutes...
echo.
:: Clean old build files first
if exist SecureWatch.spec del SecureWatch.spec
if exist dist rmdir /s /q dist
if exist build rmdir /s /q build

:: Build with UAC Admin request
pyinstaller --onefile --windowed --name "SecureWatch" --icon "SecureWatch.ico" --uac-admin SecureWatch.py

:: Copy EXE out of dist
echo.
echo  [*] Copying SecureWatch.exe to this folder...
copy /Y dist\SecureWatch.exe SecureWatch.exe

echo.
echo  ================================================
echo   DONE!
echo   SecureWatch.exe is ready in this folder.
echo   You can delete: dist, build, __pycache__
echo  ================================================
echo.
pause
