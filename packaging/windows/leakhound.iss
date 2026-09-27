; Instalador de Windows, con Inno Setup 6. Lo compila la CI después de PyInstaller:
;     iscc packaging\windows\leakhound.iss
; La versión llega en la variable de entorno LEAKHOUND_VERSION.

#define AppVersion GetEnv("LEAKHOUND_VERSION")

[Setup]
; Este identificador no se cambia nunca: es lo que hace que una versión nueva se instale
; encima de la anterior en vez de al lado.
AppId={{7FD0C84B-FC1B-451C-9E09-EDC325AE09ED}
AppName=leakhound
AppVersion={#AppVersion}
AppVerName=leakhound {#AppVersion}
AppPublisher=espi0207
AppPublisherURL=https://github.com/espi0207/leakhound
AppSupportURL=https://github.com/espi0207/leakhound/issues
DefaultDirName={autopf}\leakhound
DisableProgramGroupPage=yes
; Sin permisos de administrador se instala solo para quien lo instala (y no sale el aviso
; de "¿Quieres permitir que esta aplicación haga cambios?").
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\..\dist
OutputBaseFilename=leakhound-windows
SetupIconFile=..\icon.ico
UninstallDisplayIcon={app}\leakhound.exe
WizardStyle=modern
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "contextmenu"; Description: "Añadir «Buscar secretos con leakhound» al menú de las carpetas (clic derecho)"
Name: "desktopicon"; Description: "Crear un acceso directo en el escritorio"; Flags: unchecked

[Files]
Source: "..\..\dist\leakhound\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\leakhound"; Filename: "{app}\leakhound.exe"
Name: "{autodesktop}\leakhound"; Filename: "{app}\leakhound.exe"; Tasks: desktopicon

[Registry]
; Clic derecho sobre una carpeta, y clic derecho en el fondo de una carpeta abierta.
; En Windows 11 salen dentro de "Mostrar más opciones".
Root: HKA; Subkey: "Software\Classes\Directory\shell\leakhound"; ValueType: string; ValueName: ""; ValueData: "Buscar secretos con leakhound"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\shell\leakhound"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\leakhound.exe"; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\shell\leakhound\command"; ValueType: string; ValueName: ""; ValueData: """{app}\leakhound.exe"" ""%1"""; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\Background\shell\leakhound"; ValueType: string; ValueName: ""; ValueData: "Buscar secretos aquí con leakhound"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\Background\shell\leakhound"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\leakhound.exe"; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\Background\shell\leakhound\command"; ValueType: string; ValueName: ""; ValueData: """{app}\leakhound.exe"" ""%V"""; Tasks: contextmenu

[Run]
Filename: "{app}\leakhound.exe"; Description: "Abrir leakhound"; Flags: nowait postinstall skipifsilent
