@echo off
rem FreeEDR release build. The whole pipeline (checks, C# tests incl. tray parity, NativeAOT tray publish,
rem live self-test, staging, Inno Setup installer, single-file validation) lives in build\EdrBuild.
rem .\compiled is wiped first and then holds exactly one file, FreeEDR-Setup.exe.
rem Usage: build.cmd [--skip-live]     Exit codes: 0 = OK, 1 = build failed.  Nothing is installed or published.
call "%~dp0build\env.cmd"
dotnet run --project "%~dp0build\EdrBuild\EdrBuild.csproj" -c Release -- %*
exit /b %ERRORLEVEL%
