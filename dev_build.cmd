@echo off
rem FreeEDR local dev build - same checks as build.cmd, but .\compiled is not wiped first
rem (only FreeEDR-Setup.exe is replaced) and the version says "dev build". The pipeline lives in build\EdrBuild.
call "%~dp0build\env.cmd"
dotnet run --project "%~dp0build\EdrBuild\EdrBuild.csproj" -c Release -- --dev %*
exit /b %ERRORLEVEL%
