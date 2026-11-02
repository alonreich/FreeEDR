@echo off
rem Keeps every file a build writes inside this dev folder (.\obj): temp files, the NuGet package cache,
rem the .NET CLI home. Called by build.cmd and dev_build.cmd. (nuget.config does the same for plain dotnet commands.)
set "FREEEDR_DEV=%~dp0.."
set "TEMP=%FREEEDR_DEV%\obj\tmp"
set "TMP=%FREEEDR_DEV%\obj\tmp"
set "NUGET_PACKAGES=%FREEEDR_DEV%\obj\nuget\packages"
set "NUGET_HTTP_CACHE_PATH=%FREEEDR_DEV%\obj\nuget\http-cache"
set "NUGET_PLUGINS_CACHE_PATH=%FREEEDR_DEV%\obj\nuget\plugins-cache"
set "DOTNET_CLI_HOME=%FREEEDR_DEV%\obj\dotnet-home"
set "DOTNET_CLI_TELEMETRY_OPTOUT=1"
set "DOTNET_NOLOGO=1"
set "DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1"
if not exist "%TEMP%" mkdir "%TEMP%"
