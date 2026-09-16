; VortexSSH Windows installer (Inno Setup 6).
;
; Build on Windows (native or CI):
;   ISCC.exe installer\windows\vortexssh.iss
;
; The binaries are expected under `..\..\target\release` (a native Windows
; build). To package a Linux cross-compiled build instead, override:
;   ISCC.exe /DVortexDist=..\..\target\x86_64-pc-windows-gnu\release installer\windows\vortexssh.iss

#ifndef VortexDist
  #define VortexDist "..\..\target\release"
#endif

#define MyAppName "VortexSSH"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "VortexSSH"
#define MyAppExeName "vortexssh-gui.exe"

[Setup]
AppId={{8D2E6B4A-1C7F-4E3A-9B5D-2A0F7C1E4D96}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\VortexSSH
DefaultGroupName=VortexSSH
DisableProgramGroupPage=yes
OutputDir=Output
OutputBaseFilename=vortexssh-setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
SetupIconFile=..\..\assets\icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"
Name: "modifypath"; Description: "Add VortexSSH to the &PATH"; GroupDescription: "Other tasks:"

[Files]
Source: "{#VortexDist}\vortexssh.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#VortexDist}\vortexssh-tui.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#VortexDist}\vortexssh-gui.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\assets\icon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\VortexSSH"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"
Name: "{group}\VortexSSH (Terminal)"; Filename: "{app}\vortexssh-tui.exe"; IconFilename: "{app}\icon.ico"
Name: "{group}\VortexSSH (CLI)"; Filename: "{app}\vortexssh.exe"; IconFilename: "{app}\icon.ico"
Name: "{group}\Uninstall VortexSSH"; Filename: "{uninstallexe}"
Name: "{autodesktop}\VortexSSH"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch VortexSSH"; Flags: nowait postinstall skipifsilent

[Code]
const
  EnvironmentKey = 'Environment';

procedure EnvAddPath(Path: string);
var
  Paths: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, EnvironmentKey, 'Path', Paths) then
    Paths := '';
  if Paths = '' then
    Paths := Path
  else
    Paths := Paths + ';' + Path;
  RegWriteStringValue(HKEY_CURRENT_USER, EnvironmentKey, 'Path', Paths);
end;

procedure EnvRemovePath(Path: string);
var
  Paths: string;
  P: Integer;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, EnvironmentKey, 'Path', Paths) then
    Paths := '';
  P := Pos(';' + Path + ';', ';' + Paths + ';');
  if P > 0 then
  begin
    Delete(Paths, P - 1, Length(Path) + 1);
    Paths := Trim(Paths);
    if Paths = '' then
      RegDeleteValue(HKEY_CURRENT_USER, EnvironmentKey, 'Path')
    else
      RegWriteStringValue(HKEY_CURRENT_USER, EnvironmentKey, 'Path', Paths);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    if WizardIsTaskSelected('modifypath') then
      EnvAddPath(ExpandConstant('{app}'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    EnvRemovePath(ExpandConstant('{app}'));
end;
