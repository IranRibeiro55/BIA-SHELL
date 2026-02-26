@echo off
title BIA Shell - Launcher
:: BIA Shell (c) 2024-2025 Iran Ribeiro - https://github.com/IranRibeiro55/BIA-SHELL
:: Executa BIA Shell em PowerShell 5.1+ (Bypass para scripts)
set "SCRIPT=%~dp0BIA-Shell.ps1"
if not exist "%SCRIPT%" (
    echo [ERRO] Nao encontrado: %SCRIPT%
    pause
    exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"
if errorlevel 1 pause
