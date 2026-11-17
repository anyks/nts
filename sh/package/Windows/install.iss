; Установщик библиотеки nts (Network Transport Security) для Windows.
; Поля @version@/@pwd@/@installerDir@/@arch@/@suffix@ подставляет сценарий
; sh/dist/windows_make_installer.sh перед компиляцией утилитой iscc.

#define MyAppName "NTS (Network Transport Security)"
#define MyAppVersion "@version@"
#define MyAppPublisher "ANYKS"
#define MyAppURL "https://anyks.com"
#define MyDir "@pwd@"
#define MyResaultDir "@installerDir@"

[Code]
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
  ParamExpanded: string;
begin
  //expand the setup constants like {app} from Param
  ParamExpanded := ExpandConstant(Param);
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  // look for the path with leading and trailing semicolon and with or without \ ending
  // Pos() returns 0 if not found
  Result := Pos(';' + UpperCase(ParamExpanded) + ';', ';' + UpperCase(OrigPath) + ';') = 0;
  if Result = True then
     Result := Pos(';' + UpperCase(ParamExpanded) + '\;', ';' + UpperCase(OrigPath) + ';') = 0;
end;

[Setup]
; NOTE: The value of AppId uniquely identifies this application. Do not use the same AppId value in installers for other applications.
AppId={{8F2C5B1A-6D47-4E5A-9C3B-2A1D0E7F4B58}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName="{autopf}\anyks\nts"
DisableDirPage=yes
ChangesEnvironment=yes
DisableProgramGroupPage=yes
; Архитектура подставляется сценарием сборки: x64compatible или arm64
ArchitecturesAllowed=@arch@
ArchitecturesInstallIn64BitMode=@arch@
OutputDir="{#MyResaultDir}"
OutputBaseFilename=SetupNts-{#MyAppVersion}@suffix@
Compression=lzma
SolidCompression=yes
WizardStyle=modern
; Окно принятия условий лицензии
LicenseFile="{#MyDir}\LICENSE.txt"

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; Заголовки библиотеки: include\anyks\nts\**
Source: "{#MyDir}\stage\include\*"; DestDir: "{app}\include"; Flags: ignoreversion recursesubdirs createallsubdirs
; Обе библиотеки и cmake-файлы: lib\anyks\*.{a,dll.a}, lib\cmake\{anyks\nts, nts}
Source: "{#MyDir}\stage\lib\*"; DestDir: "{app}\lib"; Flags: ignoreversion recursesubdirs createallsubdirs
; Динамическая библиотека и библиотеки времени исполнения собирателя
Source: "{#MyDir}\stage\bin\*"; DestDir: "{app}\bin"; Flags: ignoreversion recursesubdirs createallsubdirs
; Текст лицензии
Source: "{#MyDir}\LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion

[Registry]
; Каталог dll добавляется в PATH системы и пользователя
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}\bin"; Check: NeedsAddPath('{app}\bin')
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}\bin"; Check: NeedsAddPath('{app}\bin')

[Messages]
WelcomeLabel2=This will install [name/ver] on your computer.%n%nThe library, headers and CMake package files are placed into {app}; the DLL directory {app}\bin is added to PATH.
