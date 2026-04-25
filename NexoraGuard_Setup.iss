; NexoraGuard Inno Setup Script v2.0
; Nexora Cyber Tech
;
; PREREQUISITES (install on the build machine):
;   1. Inno Setup 6.x  —  https://jrsoftware.org/isinfo.php
;   2. Run PyInstaller first:  pyinstaller nexoraguard.spec --clean
;      This produces:  dist\NexoraGuard\NexoraGuard.exe  (+ all support files)
;
; BUILD COMMAND (after Inno Setup is installed):
;   iscc NexoraGuard_Setup.iss
;   Output:  installer\NexoraGuard_Setup.exe

; ── App identity ──────────────────────────────────────────────────────────────
#define AppName      "NexoraGuard"
#define AppVersion   "2.0.0"
#define AppPublisher "Nexora Cyber Tech"
#define AppURL       "https://nexoracybertech.com"
#define AppExe       "NexoraGuard.exe"
#define AppGuid      "{{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"

[Setup]
AppId={#AppGuid}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
DefaultDirName={autopf}\{#AppPublisher}\{#AppName}
DefaultGroupName={#AppPublisher}\{#AppName}
OutputDir=installer
OutputBaseFilename=NexoraGuard_Setup
SetupIconFile=logo.ico
LicenseFile=LICENSE.txt
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
; Uninstaller
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\{#AppExe}
; Show "This will install..." description
WizardStyle=modern
DisableProgramGroupPage=no
DisableWelcomePage=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

; ── Custom wizard pages ───────────────────────────────────────────────────────
[Messages]
WelcomeLabel2=This will install [name/ver] on your computer.%n%nNexoraGuard is an AI-powered security monitoring platform that protects your PC in real-time.%n%nIt is recommended that you close all other applications before continuing.

; ── Installation tasks ────────────────────────────────────────────────────────
[Tasks]
Name: "desktopicon"; Description: "Create a &Desktop shortcut";                         GroupDescription: "Shortcuts:"
Name: "startup";     Description: "Start NexoraGuard when &Windows starts (recommended)"; GroupDescription: "Autostart:"

; ── Files to bundle ───────────────────────────────────────────────────────────
[Files]
; All PyInstaller onedir output — the entire dist\NexoraGuard\ folder
Source: "dist\NexoraGuard\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; Shortcut icon
Source: "logo.ico"; DestDir: "{app}"; Flags: ignoreversion

; License / readme
Source: "LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion

; ── Shortcuts ─────────────────────────────────────────────────────────────────
[Icons]
; Start Menu
Name: "{group}\NexoraGuard";            Filename: "{app}\{#AppExe}"; IconFilename: "{app}\logo.ico"; Comment: "NexoraGuard Security Platform"
Name: "{group}\Uninstall NexoraGuard";  Filename: "{uninstallexe}"

; Desktop (optional task)
Name: "{commondesktop}\NexoraGuard"; Filename: "{app}\{#AppExe}"; IconFilename: "{app}\logo.ico"; Tasks: desktopicon; Comment: "NexoraGuard Security Platform"

; ── Registry ──────────────────────────────────────────────────────────────────
[Registry]
; Windows Startup — HKCU Run key (per-user, no extra UAC prompt; EXE itself has uac_admin manifest)
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "{#AppName}"; ValueData: """{app}\{#AppExe}"""; Flags: uninsdeletevalue; Tasks: startup

; App Paths — lets Windows find NexoraGuard.exe from the Run dialog / shell
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{#AppExe}"; ValueType: string; ValueName: ""; ValueData: "{app}\{#AppExe}"; Flags: uninsdeletekey

; Uninstall metadata (shown in Programs & Features)
Root: HKLM; Subkey: "SOFTWARE\{#AppPublisher}\{#AppName}"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey

; ── Post-install run ──────────────────────────────────────────────────────────
[Run]
; Launch NexoraGuard after install (optional checkbox)
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName} now"; Flags: postinstall nowait skipifsilent

; ── Uninstall cleanup ─────────────────────────────────────────────────────────
[UninstallDelete]
; Remove AppData config/logs folder on uninstall (optional — comment out to preserve logs)
; Type: filesandordirs; Name: "{userappdata}\NexoraCyberTech\NexoraGuard"

; ── Code section — pre/post install logic ────────────────────────────────────
[Code]

// Stop any running NexoraGuard process before installing (avoid file-lock errors)
function InitializeSetup(): Boolean;
var
  ResultCode: Integer;
begin
  Exec('taskkill.exe', '/F /IM NexoraGuard.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := True;
end;

// Confirm uninstall
function InitializeUninstall(): Boolean;
begin
  Result := MsgBox(
    'Are you sure you want to completely remove NexoraGuard from this computer?',
    mbConfirmation,
    MB_YESNO
  ) = IDYES;
end;
