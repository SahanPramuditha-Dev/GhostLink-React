; Inno Setup script for GHOSTLINK
[Setup]
AppName=GHOSTLINK
AppVersion=1.0
DefaultDirName={pf}\GHOSTLINK
DefaultGroupName=GHOSTLINK
OutputBaseFilename=GHOSTLINK_Installer
Compression=lzma
SolidCompression=yes

[Files]
Source: "dist\\ghostlink.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\\ghostlink-launcher.exe"; DestDir: "{app}"; Flags: ignoreversion
; Optional icon
Source: "scripts\\ghostlink.ico"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\GHOSTLINK"; Filename: "{app}\ghostlink-launcher.exe"; IconFilename: "{app}\\ghostlink.ico"
Name: "{commondesktop}\GHOSTLINK"; Filename: "{app}\ghostlink-launcher.exe"; Tasks: desktopicon; IconFilename: "{app}\\ghostlink.ico"
Name: "{userstartup}\GHOSTLINK"; Filename: "{app}\ghostlink-launcher.exe"; Tasks: autostart; IconFilename: "{app}\\ghostlink.ico"

[Tasks]
Name: desktopicon; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"; Flags: unchecked
Name: autostart; Description: "Start GHOSTLINK automatically on login"; GroupDescription: "Startup options:"; Flags: unchecked

[Run]
Filename: "{app}\ghostlink.exe"; Description: "Launch GHOSTLINK"; Flags: nowait postinstall skipifsilent
