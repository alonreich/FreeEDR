; ================================================================================================
; FreeEDR-Setup.exe - the single-file installer of FreeEDR (Inno Setup 6.3 or newer).
; Compiled by build\EdrBuild (build.cmd / dev_build.cmd), which passes the defines below; never compile by hand.
;
; WHAT IT DOES
;   * Asks for administrator rights once (FreeEDR runs as SYSTEM and lives in admin-only C:\Program Files\FreeEDR).
;   * Refuses non-x64 Windows (the tools and the Sysmon driver are x64-only).
;   * Unpacks the staged files (bin\ NativeAOT programs, config\, rules\, docs) into C:\Program Files\FreeEDR\setup-src,
;     which only administrators can write, and deletes them again at the end. Every file stays visible to antivirus.
;   * Runs setup-src\bin\FreeEDR-Installer.exe install in a visible console and waits. The installer does everything
;     else (backup, tools, Sysmon, ACLs, Defender audit mode, the "FreeEDR" service, tray, shortcuts, verify, roll back)
;     and returns 0 = SUCCESS, 3 = ROLLED BACK, 1 = FAILED. Setup reports that result.
;   * Registers FreeEDR in Settings > Apps / appwiz.cpl. Uninstall runs FreeEDR-Installer.exe uninstall, which puts the
;     Windows settings back, then removes the folder.
;   Silent:  FreeEDR-Setup.exe /VERYSILENT [/TASKS="!desktopicon"] [/ReplaceSysmonConfig=1]   (exit code 0 / 1)
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
VersionInfoDescription=FreeEDR Setup (detect-only EDR + Wail2Ban)
VersionInfoProductName=FreeEDR
VersionInfoOriginalFileName=FreeEDR-Setup.exe
OutputDir={#OutputDir}
OutputBaseFilename=FreeEDR-Setup
PrivilegesRequired=admin
; The folder is fixed (EdrPaths.DefaultRoot); Setup's uninstaller lives in it
CreateAppDir=yes
DefaultDirName={commonpf64}\FreeEDR
DisableDirPage=yes
UsePreviousAppDir=no
DirExistsWarning=no
Uninstallable=yes
UninstallDisplayName=FreeEDR
UninstallDisplayIcon={app}\bin\tray\FreeEDR-Tray.exe
; Tools and data are downloaded by the installer, so Setup cannot count them: about 250 MB
UninstallDisplaySize=262144000
CloseApplications=no
RestartApplications=no
DisableWelcomePage=no
DisableReadyPage=no
DisableFinishedPage=yes
DisableProgramGroupPage=yes
ShowLanguageDialog=no
WizardStyle=modern
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0.17763
Compression=lzma2/max
SolidCompression=yes
SetupLogging=no

[Messages]
WelcomeLabel2=This installs or upgrades FreeEDR in C:\Program Files\FreeEDR: real-time detection (Sysmon), malware hash and YARA checks, Sigma event-log scans, vulnerability checks, Wail2Ban and the dashboard, for every account on this PC.%n%nFreeEDR detects and explains; it never stops or removes anything. Only Wail2Ban acts: it blocks computers that keep failing to sign in over the network.%n%nAn upgrade backs up the current version first and rolls back by itself if the new one does not start. Your events, bans and allow-lists are kept.%n%nFreeEDR installs Microsoft Sysinternals Sysmon and accepts its license for you: https://learn.microsoft.com/sysinternals/license-terms
ReadyLabel1=Ready to install FreeEDR {#AppVersionText}.
ReadyLabel2b=Click Install. A console window shows every step; it ends with INSTALL RESULT.

[Tasks]
Name: "desktopicon"; Description: "Create a FreeEDR icon on the desktop (all users)"

[Files]
; Admin-only location (not the user's %TEMP%), so nothing unelevated can swap the files before they run elevated
Source: "{#StagingDir}\*"; DestDir: "{app}\setup-src"; Flags: recursesubdirs createallsubdirs ignoreversion deleteafterinstall

[UninstallRun]
Filename: "{app}\bin\FreeEDR-Installer.exe"; Parameters: "uninstall --from-setup"; WorkingDir: "{sys}"; Flags: waituntilterminated; RunOnceId: "FreeEDRUninstall"; StatusMsg: "Removing FreeEDR and restoring the Windows settings it changed..."

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
var
  InstallResult: Integer;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Src, Params, Log: String;
begin
  if CurStep = ssDone then DelTree(ExpandConstant('{app}\setup-src'), True, True, True);   { the unpacked copy, files and folders }
  if CurStep <> ssPostInstall then Exit;
  Src := ExpandConstant('{app}\setup-src');
  Log := ExpandConstant('{app}\install.log');
  { Setup shows the result itself, so the console window never waits for Enter }
  Params := 'install --source "' + Src + '" --no-pause --version "{#AppVersionText}"';
  if WizardSilent then Params := Params + ' --silent';
  if not WizardIsTaskSelected('desktopicon') then Params := Params + ' --no-desktop-icon';
  if ExpandConstant('{param:ReplaceSysmonConfig|0}') = '1' then Params := Params + ' --replace-sysmon-config';
  WizardForm.StatusLabel.Caption := 'Installing FreeEDR (see the console window)...';
  if not Exec(Src + '\bin\FreeEDR-Installer.exe', Params, Src, SW_SHOWNORMAL, ewWaitUntilTerminated, InstallResult) then
  begin
    SuppressibleMsgBox('Could not start the FreeEDR installer: ' + SysErrorMessage(InstallResult), mbCriticalError, MB_OK, IDOK);
    InstallResult := -1;
    Exit;
  end;
  case InstallResult of
    0: SuppressibleMsgBox('FreeEDR {#AppVersionText} installed successfully.' + #13#10#13#10 + 'The shield is in the notification area; "FreeEDR" is in the Start menu. Details: ' + Log, mbInformation, MB_OK, IDOK);
    3: SuppressibleMsgBox('The new version did not start, so the previous version was restored (ROLLED BACK).' + #13#10#13#10 + 'Details: ' + Log, mbError, MB_OK, IDOK);
  else
    SuppressibleMsgBox('FreeEDR installation FAILED (exit code ' + IntToStr(InstallResult) + ').' + #13#10#13#10 + 'Details: ' + Log + ' (and %TEMP%\FreeEDR-install.log)' + #13#10#13#10 + 'To remove what was set up: Settings > Apps > FreeEDR > Uninstall.', mbCriticalError, MB_OK, IDOK);
  end;
end;

function GetCustomSetupExitCode: Integer;
begin
  { 0 only when the installer reported SUCCESS }
  if InstallResult = 0 then Result := 0 else Result := 1;
end;
