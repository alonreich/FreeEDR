; ================================================================================================
; FreeEDR-Setup.exe - the single-file installer of FreeEDR (Inno Setup 6.3 or newer).
; Compiled by build\EdrBuild (build.cmd / dev_build.cmd), which passes the defines below; never compile by hand.
;
; WHAT IT DOES
;   * Asks for administrator rights once (FreeEDR runs as SYSTEM and lives in admin-only C:\Program Files\FreeEDR).
;   * Unpacks the project files (exactly Install-EDR.ps1's $ProjectFiles) into Inno's private temporary folder,
;     which Inno removes when it exits. Every file stays visible to antivirus with its real name (no dropper).
;   * Runs that copy of Install-EDR.ps1 in 64-bit Windows PowerShell 5.1, in a visible window, and waits.
;     Install-EDR does everything else (backup, move from C:\EDR, tools, Sysmon, ACLs, Defender, task, tray,
;     verify, roll back) and returns 0 = SUCCESS, 3 = ROLLED BACK, 1 = FAILED. Setup reports that result.
;   * Writes nothing itself: no program folder, no registry, no uninstaller (uninstall: Installation_Process.md §7).
;   Silent:  FreeEDR-Setup.exe /VERYSILENT  (no prompts; Install-EDR runs with -NoPause; exit code 0 / 1).
; ================================================================================================

#if Ver < EncodeVer(6, 3, 0)
  #error Inno Setup 6.3 or newer is required (winget install JRSoftware.InnoSetup).
#endif
#ifndef AppVersion
  #error AppVersion is missing. Build with build.cmd / dev_build.cmd (build\EdrBuild), not by hand.
#endif
#ifndef AppVersionText
  #define AppVersionText AppVersion
#endif
#ifndef StagingDir
  #error StagingDir is missing. Build with build.cmd / dev_build.cmd (build\EdrBuild), not by hand.
#endif
#ifndef OutputDir
  #error OutputDir is missing. Build with build.cmd / dev_build.cmd (build\EdrBuild), not by hand.
#endif

[Setup]
AppId={{6F0E2C1A-4B7D-4E59-9A33-0E2D5C8B7A41}
AppName=FreeEDR
AppVersion={#AppVersionText}
AppVerName=FreeEDR {#AppVersionText}
AppPublisher=FreeEDR Project
VersionInfoVersion={#AppVersion}
VersionInfoTextVersion={#AppVersion}
VersionInfoProductVersion={#AppVersion}
VersionInfoProductTextVersion={#AppVersionText}
VersionInfoCompany=FreeEDR Project
VersionInfoDescription=FreeEDR Setup (home EDR + Wail2Ban)
VersionInfoProductName=FreeEDR
VersionInfoOriginalFileName=FreeEDR-Setup.exe
OutputDir={#OutputDir}
OutputBaseFilename=FreeEDR-Setup
PrivilegesRequired=admin
CreateAppDir=no
Uninstallable=no
DisableWelcomePage=no
DisableReadyPage=no
DisableFinishedPage=yes
DisableProgramGroupPage=yes
ShowLanguageDialog=no
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
Compression=lzma2/max
SolidCompression=yes
SetupLogging=no

[Messages]
WelcomeLabel2=This installs or upgrades FreeEDR in C:\Program Files\FreeEDR: real-time detection (Sysmon), malware hash and YARA checks, Sigma event-log scans, Wail2Ban and the tray dashboard.%n%nAn upgrade backs up the current version first and rolls back by itself if the new one does not start. Your events, bans and allow-lists are kept (an install in the old C:\EDR folder is moved here).
ReadyLabel1=Ready to install FreeEDR {#AppVersionText}.
ReadyLabel2b=Click Install. A PowerShell window shows every step; it ends with INSTALL RESULT.

[Files]
Source: "{#StagingDir}\*"; DestDir: "{tmp}\FreeEDR-src"; Flags: recursesubdirs createallsubdirs ignoreversion

[Code]
var
  InstallResult: Integer;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Src, Params, Log: String;
begin
  if CurStep <> ssPostInstall then Exit;
  Src := ExpandConstant('{tmp}\FreeEDR-src');
  Log := ExpandConstant('{commonpf64}\FreeEDR\install.log');
  Params := '-NoProfile -ExecutionPolicy Bypass -File "' + Src + '\Install-EDR.ps1"';
  if WizardSilent then Params := Params + ' -NoPause';
  WizardForm.StatusLabel.Caption := 'Running Install-EDR.ps1 (see the PowerShell window)...';
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), Params, Src, SW_SHOWNORMAL, ewWaitUntilTerminated, InstallResult) then
  begin
    SuppressibleMsgBox('Could not start Windows PowerShell: ' + SysErrorMessage(InstallResult), mbCriticalError, MB_OK, IDOK);
    InstallResult := -1;
    Exit;
  end;
  case InstallResult of
    0: SuppressibleMsgBox('FreeEDR installed successfully.' + #13#10#13#10 + 'The tray shield is in the notification area. Details: ' + Log, mbInformation, MB_OK, IDOK);
    3: SuppressibleMsgBox('The new version did not start, so the previous version was restored (ROLLED BACK).' + #13#10#13#10 + 'Details: ' + Log, mbError, MB_OK, IDOK);
  else
    SuppressibleMsgBox('FreeEDR installation FAILED (exit code ' + IntToStr(InstallResult) + ').' + #13#10#13#10 + 'Details: ' + Log, mbCriticalError, MB_OK, IDOK);
  end;
end;

function GetCustomSetupExitCode: Integer;
begin
  { 0 only when Install-EDR.ps1 reported SUCCESS }
  if InstallResult = 0 then Result := 0 else Result := 1;
end;
