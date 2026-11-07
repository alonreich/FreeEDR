; ================================================================================================
; FreeEDR-Setup.exe - the single-file installer of FreeEDR (Inno Setup 6.3 or newer).
; Compiled by build\EdrBuild (build.cmd / dev_build.cmd), which passes the defines below; never compile by hand.
;
; WHAT IT DOES
;   * Asks for administrator rights once (FreeEDR runs as SYSTEM and lives in admin-only C:\Program Files\FreeEDR).
;   * Refuses non-x64 Windows (the tools and the Sysmon driver are x64-only).
;   * Unpacks the staged files (bin\ NativeAOT programs, config\, rules\, docs) into C:\Program Files\FreeEDR\setup-src,
;     which only administrators can write, and deletes them again at the end. Every file stays visible to antivirus.
;   * Shows no wizard pages of its own: it runs setup-src\bin\FreeEDR-Installer.exe install, whose window (the
;     dashboard's look) asks upgrade vs clean install, shows every step and the result. The installer does everything
;     else (backup, tools, Sysmon, ACLs, Defender audit mode, the "FreeEDR" service, tray, shortcuts, verify, roll back)
;     and returns 0 = SUCCESS, 3 = ROLLED BACK, 1 = FAILED, 4 = cancelled in its window.
;   * Registers FreeEDR in Settings > Apps / appwiz.cpl. Uninstall runs FreeEDR-Installer.exe uninstall, which puts the
;     Windows settings back, then removes the folder.
;   Silent:  FreeEDR-Setup.exe /VERYSILENT [/NoDesktopIcon=1] [/Clean=1] [/ReplaceSysmonConfig=1]   (exit code 0 / 1)
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
; Program, tools (embedded), rules and the event archive: about 1.3 GB at most
UninstallDisplaySize=1395864371
CloseApplications=no
RestartApplications=no
DisableWelcomePage=yes
DisableReadyPage=yes
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
  Upgrade: Boolean;
begin
  if CurStep = ssDone then DelTree(ExpandConstant('{app}\setup-src'), True, True, True);   { the unpacked copy, files and folders }
  if CurStep <> ssPostInstall then Exit;
  Src := ExpandConstant('{app}\setup-src');
  Log := ExpandConstant('{app}\install.log');
  Upgrade := FileExists(ExpandConstant('{app}\bin\FreeEDR-Engine.exe'));
  { Without /SILENT the installer shows its own window (choices, steps, result); Setup's wizard stays out of the way }
  Params := 'install --source "' + Src + '" --version "{#AppVersionText}"';
  if WizardSilent then Params := Params + ' --silent';
  if ExpandConstant('{param:NoDesktopIcon|0}') = '1' then Params := Params + ' --no-desktop-icon';
  if ExpandConstant('{param:Clean|0}') = '1' then Params := Params + ' --clean';
  if ExpandConstant('{param:ReplaceSysmonConfig|0}') = '1' then Params := Params + ' --replace-sysmon-config';
  WizardForm.StatusLabel.Caption := 'FreeEDR Setup is running in its own window...';
  WizardForm.Hide;
  try
    if not Exec(Src + '\bin\FreeEDR-Installer.exe', Params, Src, SW_SHOWNORMAL, ewWaitUntilTerminated, InstallResult) then
    begin
      SuppressibleMsgBox('Could not start the FreeEDR installer: ' + SysErrorMessage(InstallResult), mbCriticalError, MB_OK, IDOK);
      InstallResult := -1;
      Exit;
    end;
  finally
    WizardForm.Show;
  end;
  { The window already showed the result; only a silent run or a cancel needs a word here }
  if InstallResult = 4 then
  begin
    if Upgrade then
      SuppressibleMsgBox('Setup was cancelled. The installed version of FreeEDR was not changed.', mbInformation, MB_OK, IDOK)
    else
      SuppressibleMsgBox('Setup was cancelled before anything was set up.' + #13#10#13#10 + 'To remove the leftover entry: Settings > Apps > FreeEDR > Uninstall (it changes no Windows setting, since none was changed).', mbInformation, MB_OK, IDOK);
  end
  else if WizardSilent and (InstallResult <> 0) then
    SuppressibleMsgBox('FreeEDR installation did not succeed (exit code ' + IntToStr(InstallResult) + '). Details: ' + Log, mbCriticalError, MB_OK, IDOK);
end;

function GetCustomSetupExitCode: Integer;
begin
  { 0 only when the installer reported SUCCESS }
  if InstallResult = 0 then Result := 0 else Result := 1;
end;
