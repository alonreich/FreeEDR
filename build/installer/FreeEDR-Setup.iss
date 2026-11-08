
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
#ifndef OutputName
  #define OutputName "FreeEDR-Setup"
#endif
#define UninstallKey "Software\Microsoft\Windows\CurrentVersion\Uninstall\{6F0E2C1A-4B7D-4E59-9A33-0E2D5C8B7A41}_is1"
#define FinishKey "Software\Microsoft\Windows\CurrentVersion\Uninstall\FreeEDR-FinishRemoval"

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
VersionInfoOriginalFileName={#OutputName}.exe
OutputDir={#OutputDir}
OutputBaseFilename={#OutputName}
PrivilegesRequired=admin
CreateAppDir=yes
DefaultDirName={commonpf64}\FreeEDR
DisableDirPage=yes
UsePreviousAppDir=no
DirExistsWarning=no
Uninstallable=yes
UninstallDisplayName=FreeEDR
UninstallDisplayIcon={app}\bin\tray\FreeEDR-Tray.exe
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
Source: "{#StagingDir}\*"; DestDir: "{app}\setup-src"; Flags: recursesubdirs createallsubdirs ignoreversion deleteafterinstall

[Code]
var
  InstallResult: Integer;
  UninstallResult: Integer;
  Downgrade: Boolean;

function VersionPart(const S: String; Index: Integer): Integer;
var
  I, Part, Value: Integer;
  C: Char;
begin
  Result := 0;
  Part := 0;
  Value := 0;
  for I := 1 to Length(S) do
  begin
    C := S[I];
    if (C >= '0') and (C <= '9') then
    begin
      if Value < 100000 then Value := Value * 10 + (Ord(C) - Ord('0'));
    end
    else if C = '.' then
    begin
      if Part = Index then begin Result := Value; Exit; end;
      Part := Part + 1;
      Value := 0;
    end
    else Break;
  end;
  if Part = Index then Result := Value;
end;

function CompareVersions(const A, B: String): Integer;
var
  I, X, Y: Integer;
begin
  Result := 0;
  for I := 0 to 3 do
  begin
    X := VersionPart(A, I);
    Y := VersionPart(B, I);
    if X < Y then begin Result := -1; Exit; end;
    if X > Y then begin Result := 1; Exit; end;
  end;
end;

function InstalledVersion: String;
var
  S: AnsiString;
begin
  Result := '';
  if LoadStringFromFile(ExpandConstant('{commonpf64}\FreeEDR\version.txt'), S) then Result := Trim(String(S));
  if Result = '' then
    if not RegQueryStringValue(HKLM64, '{#UninstallKey}', 'DisplayVersion', Result) then Result := '';
end;

function InitializeSetup: Boolean;
var
  Installed: String;
begin
  Result := True;
  Downgrade := False;
  Installed := InstalledVersion;
  if (Installed = '') or (CompareVersions(Installed, '{#AppVersion}') <= 0) then Exit;
  Downgrade := True;
  if ExpandConstant('{param:AllowDowngrade|0}') = '1' then Exit;
  if SuppressibleMsgBox('The installed FreeEDR (' + Installed + ') is newer than this Setup ({#AppVersionText}).' + #13#10#13#10 +
       'Installing it goes back to an older version: fixes and detection rules made since then are lost, and settings saved by the newer version may not load.' + #13#10#13#10 +
       'Install the older version anyway?', mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) <> IDYES then
  begin
    Log('Downgrade from ' + Installed + ' to {#AppVersionText} declined; nothing was changed.');
    Result := False;
  end;
end;

procedure SyncDisplayVersion;
var
  S: AnsiString;
begin
  if LoadStringFromFile(ExpandConstant('{app}\version.txt'), S) and (Trim(String(S)) <> '') then
    RegWriteStringValue(HKLM64, '{#UninstallKey}', 'DisplayVersion', Trim(String(S)));
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Src, Params, LogFile: String;
  Upgrade: Boolean;
begin
  if CurStep = ssDone then DelTree(ExpandConstant('{app}\setup-src'), True, True, True);
  if CurStep <> ssPostInstall then Exit;
  Src := ExpandConstant('{app}\setup-src');
  LogFile := ExpandConstant('{app}\install.log');
  Upgrade := FileExists(ExpandConstant('{app}\bin\FreeEDR-Engine.exe'));
  Params := 'install --source "' + Src + '" --version "{#AppVersionText}"';
  if WizardSilent then Params := Params + ' --silent';
  if ExpandConstant('{param:NoDesktopIcon|0}') = '1' then Params := Params + ' --no-desktop-icon';
  if ExpandConstant('{param:Clean|0}') = '1' then Params := Params + ' --clean';
  if ExpandConstant('{param:ReplaceSysmonConfig|0}') = '1' then Params := Params + ' --replace-sysmon-config';
  if Downgrade then Params := Params + ' --allow-downgrade';
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
    if Upgrade and (InstallResult <> 0) then SyncDisplayVersion;
  end;
  if InstallResult = 4 then
  begin
    if Upgrade then
      SuppressibleMsgBox('Setup was cancelled. The installed version of FreeEDR was not changed.', mbInformation, MB_OK, IDOK)
    else
      SuppressibleMsgBox('Setup was cancelled before anything was set up.' + #13#10#13#10 + 'To remove the leftover entry: Settings > Apps > FreeEDR > Uninstall (it changes no Windows setting, since none was changed).', mbInformation, MB_OK, IDOK);
  end
  else if WizardSilent and (InstallResult <> 0) then
    SuppressibleMsgBox('FreeEDR installation did not succeed (exit code ' + IntToStr(InstallResult) + '). Details: ' + LogFile, mbCriticalError, MB_OK, IDOK);
end;

function GetCustomSetupExitCode: Integer;
begin
  if InstallResult = 0 then Result := 0 else Result := 1;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Helper: String;
begin
  Helper := ExpandConstant('{app}\bin\FreeEDR-Installer.exe');
  if CurUninstallStep = usUninstall then
  begin
    UninstallResult := -1;
    UninstallProgressForm.StatusLabel.Caption := 'Removing FreeEDR and restoring the Windows settings it changed...';
    if FileExists(Helper) then
      if not Exec(Helper, 'uninstall --from-setup', ExpandConstant('{sys}'), SW_SHOWNORMAL, ewWaitUntilTerminated, UninstallResult) then UninstallResult := -1;
  end
  else if CurUninstallStep = usPostUninstall then
  begin
    if (UninstallResult = 0) or (UninstallResult = 1) then
      DelTree(ExpandConstant('{app}'), True, True, True)
    else
    begin
      if FileExists(Helper) then
      begin
        RegWriteStringValue(HKLM64, '{#FinishKey}', 'DisplayName', 'FreeEDR (finish removal)');
        RegWriteStringValue(HKLM64, '{#FinishKey}', 'UninstallString', '"' + Helper + '" uninstall');
        RegWriteStringValue(HKLM64, '{#FinishKey}', 'DisplayIcon', Helper);
        RegWriteStringValue(HKLM64, '{#FinishKey}', 'Publisher', 'FreeEDR Project');
        RegWriteDWordValue(HKLM64, '{#FinishKey}', 'NoModify', 1);
        RegWriteDWordValue(HKLM64, '{#FinishKey}', 'NoRepair', 1);
      end;
      SuppressibleMsgBox('FreeEDR could not put back every Windows setting it changed (code ' + IntToStr(UninstallResult) + '), so its folder and the record of your original settings were kept.' + #13#10#13#10 +
        'Restart the PC, then finish with Settings > Apps > "FreeEDR (finish removal)". Details: FreeEDR-uninstall.log in %TEMP%.', mbError, MB_OK, IDOK);
    end;
  end;
end;
