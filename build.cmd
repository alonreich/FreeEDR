@echo off
setlocal EnableDelayedExpansion
set "DOTNET_CLI_FORCE_UTF8_ENCODING=false"
set "DOTNET_CLI_UI_LANGUAGE=en-US"
set "VSCONSOLEOUTPUT=1"
set "SCRIPT_DIR=%~dp0"
pushd "%SCRIPT_DIR%" >nul || exit /b 1

call "%SCRIPT_DIR%build\env.cmd"
set "RC=0"

where dotnet >nul 2>&1
if errorlevel 1 (
  echo ERROR: the "dotnet" command was not found.
  echo Install the free .NET 10 SDK:  winget install Microsoft.DotNet.SDK.10
  set "RC=1"
  goto :finish
)
dotnet --list-sdks 2>nul | findstr /r /b /c:"10\." >nul
if errorlevel 1 (
  echo ERROR: no .NET 10 SDK is installed. FreeEDR targets net10.0-windows.
  echo Installed SDKs:
  dotnet --list-sdks
  echo Install the free .NET 10 SDK:  winget install Microsoft.DotNet.SDK.10
  set "RC=1"
  goto :finish
)

dotnet build "%SCRIPT_DIR%build\EdrBuild\EdrBuild.csproj" -c Release --nologo -v quiet -tl:off
set "RC=%ERRORLEVEL%"
if "%RC%"=="0" (
  dotnet "%SCRIPT_DIR%build\EdrBuild\bin\Release\net10.0-windows\EdrBuild.dll" %*
  set "RC=!ERRORLEVEL!"
)

:finish
if not "%RC%"=="0" (
  echo.
  echo ###########################################################
  echo  BUILD / RELEASE FAILED ^(exit code %RC%^).
  echo  See .\build.log for full diagnostic output.
  echo ###########################################################
)

popd >nul
if exist "%SCRIPT_DIR%developer_tools\SetConsoleFont.ps1" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%developer_tools\SetConsoleFont.ps1" <nul
)
exit /b %RC%
