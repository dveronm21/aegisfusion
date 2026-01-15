[Setup]
AppName=Aegis Fusion Core
AppVersion=1.0.0
AppPublisher=Aegis Fusion
DefaultDirName={pf}\Aegis Fusion
DefaultGroupName=Aegis Fusion
PrivilegesRequired=admin
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
OutputBaseFilename=AegisFusionCoreSetup

[Files]
Source: "..\..\core\target\release\aegis-fusion-core.exe"; DestDir: "{app}\core"; Flags: ignoreversion
Source: "install_service.ps1"; DestDir: "{app}\installer"; Flags: ignoreversion
Source: "uninstall_service.ps1"; DestDir: "{app}\installer"; Flags: ignoreversion

[Run]
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\installer\install_service.ps1"" -BinaryPath ""{app}\core\aegis-fusion-core.exe"""; Flags: runhidden

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\installer\uninstall_service.ps1"""; Flags: runhidden
