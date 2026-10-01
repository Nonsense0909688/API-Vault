@echo off
title API-Vault Builder

cd /d "%~dp0.."

echo [1/3] Cleaning old build...

if not exist output mkdir output

if exist output\api-vault.exe del /q output\api-vault.exe

echo [2/3] Building...

go build -o output\api-vault.exe .

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed!
    pause
    exit /b 1
)

echo.
echo [3/3] Build successful!
echo.
echo Output: %cd%\output\api-vault.exe
echo.

pause