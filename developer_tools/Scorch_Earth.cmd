@echo off
setlocal EnableDelayedExpansion
set "SCRIPT_DIR=%~dp0"

net session >nul 2>&1
if %ERRORLEVEL% equ 0 (
    goto :elevated
)

echo Requesting Administrator privileges for FreeEDR Scorch-Earth cleanup...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd.exe -ArgumentList '/c \"\"%~dp0Scorch_Earth.cmd\" %*\"' -Verb RunAs"
exit /b %ERRORLEVEL%

:elevated
pushd "%SCRIPT_DIR%" >nul
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%Scorch_Earth.ps1" %*
set "EXIT_CODE=%ERRORLEVEL%"
popd >nul
exit /b %EXIT_CODE%
