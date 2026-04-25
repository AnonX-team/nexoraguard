; NexoraGuard Agent Installer
; Nexora Cyber Tech
;
; BUILD STEPS:
;   1. pyinstaller nexoraguard_agent.spec --clean
;      (produces: dist\NexoraGuard-Agent.exe)
;   2. iscc NexoraGuard_Agent_Setup.iss
;      (produces: installer\NexoraGuard_Agent_Setup.exe)

#define AgentName      "NexoraGuard Agent"
#define AgentVersion   "2.0.0"
#define AgentPublisher "Nexora Cyber Tech"
#define AgentExe       "NexoraGuard-Agent.exe"
#define AgentGuid      "{B9C8D7E6-F5A4-3210-FEDC-BA9876543210}"

[Setup]
AppId={#AgentGuid}
AppName={#AgentName}
AppVersion={#AgentVersion}
AppVerName={#AgentName} {#AgentVersion}
AppPublisher={#AgentPublisher}
AppPublisherURL=https://anonx-team.github.io/nexoraguard/
AppSupportURL=https://anonx-team.github.io/nexoraguard/
DefaultDirName={autopf}\{#AgentPublisher}\{#AgentName}
DefaultGroupName={#AgentPublisher}\{#AgentName}
OutputDir=installer
OutputBaseFilename=NexoraGuard_Agent_Setup
SetupIconFile=logo.ico
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
DisableProgramGroupPage=yes
DisableWelcomePage=no
WizardStyle=modern

; Show a clean, modern wizard
WizardImageFile=compiler:WizModernImage-IS.bmp
WizardSmallImageFile=compiler:WizModernSmallImage-IS.bmp

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon";   Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"
Name: "startupentry";  Description: "Start agent automatically when Windows &boots"; GroupDescription: "Startup:"; Flags: unchecked

[Files]
Source: "dist\NexoraGuard-Agent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "logo.ico";                   DestDir: "{app}"; Flags: ignoreversion
Source: "LICENSE.txt";                DestDir: "{app}"; Flags: ignoreversion isreadme

[Icons]
Name: "{group}\{#AgentName}";          Filename: "{app}\{#AgentExe}"; IconFilename: "{app}\logo.ico"
Name: "{group}\Uninstall {#AgentName}"; Filename: "{uninstallexe}"
Name: "{commondesktop}\{#AgentName}";  Filename: "{app}\{#AgentExe}"; IconFilename: "{app}\logo.ico"; Tasks: desktopicon

[Registry]
; Auto-start on boot (if task selected)
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run";
  ValueType: string; ValueName: "NexoraGuardAgent";
  ValueData: """{app}\{#AgentExe}"""; Tasks: startupentry

[Run]
; Launch agent after install — will show setup wizard on first run
Filename: "{app}\{#AgentExe}"; Description: "Launch {#AgentName}";
  Flags: nowait postinstall skipifsilent

[UninstallRun]
; Kill agent before uninstall
Filename: "taskkill.exe"; Parameters: "/f /im {#AgentExe}"; Flags: runhidden; RunOnceId: "KillAgent"

[UninstallDelete]
; Clean up config files
Type: filesandordirs; Name: "{userappdata}\NexoraGuard"

[Messages]
WelcomeLabel1=Welcome to NexoraGuard Agent Setup
WelcomeLabel2=This will install the NexoraGuard monitoring agent on your computer.%n%nThe agent runs silently in the background and reports system data to your NexoraGuard server.%n%nClick Next to continue.
FinishedHeadingLabel=NexoraGuard Agent Installed
FinishedLabel=The agent has been installed. It will launch now and ask for your server details.%n%nYou can find the agent in your system tray (bottom-right corner).
