; Nova EDR Agent Installer Script

#define MyAppName "Nova EDR"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "N0vaSky"
#define MyAppURL "github.com/n0vasky" // CHANGE ME
#define MyAppExeName "Nova EDR.exe"
#define SourcePath "C:\Users\nova\source\repos\NovaEDR\bin\Debug" // CHANGE ME
#define IconPath "C:\Users\nova\Downloads\novaedr.ico" // CHANGE ME
#define ServerURL "https://raw.githubusercontent.com/N0vaSky/NovaEDR-deploy/" // CHANGE ME
#define UpdateIntervalMinutes "60" // CHANGE ME IF YOU FEEL LIKE IT

[Setup]
; Basic setup information
AppId={{38D8AC11-6B1F-4E15-8842-D12A1C84A5A6}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={pf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=.
OutputBaseFilename=Nova EDR Setup
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
SetupIconFile={#IconPath}
UninstallDisplayName={#MyAppName}
UninstallDisplayIcon={app}\novaedr.ico

; Enable command line parameter processing
SetupLogging=yes
AllowNoIcons=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; Include all files from the Release directory
Source: "{#SourcePath}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; Include the icon
Source: "{#IconPath}"; DestDir: "{app}"; Flags: ignoreversion

; Create directories
[Dirs]
Name: "{commonappdata}\NovaEDR\Config"; Permissions: everyone-full
Name: "{commonappdata}\NovaEDR\Logs"; Permissions: everyone-full
Name: "{commonappdata}\NovaEDR\Temp"; Permissions: everyone-full

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\novaedr.ico"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"; IconFilename: "{app}\novaedr.ico"

[Code]
var
  ClientIDPage: TInputQueryWizardPage;
  WazuhGroupsPage: TInputQueryWizardPage;
  ClientIDValue: String;
  WazuhGroupsValue: String;
  IsClientIDFromParam: Boolean;
  IsWazuhGroupsFromParam: Boolean;

// Check for admin rights during initialization
function InitializeSetup(): Boolean;
begin
  if not IsAdminLoggedOn then
  begin
    MsgBox('This installer requires administrator privileges. Please run as an administrator.', mbError, MB_OK);
    Result := False;
  end
  else
    Result := True;
end;

// Parse command line parameters
function GetCommandLineParam(const ParamName: String): String;
var
  I: Integer;
  Param: String;
begin
  Result := '';
  for I := 1 to ParamCount do
  begin
    Param := ParamStr(I);
    if Pos('/' + ParamName + '=', Param) = 1 then
    begin
      Delete(Param, 1, Length('/' + ParamName + '='));
      Result := Param;
      Break;
    end;
  end;
end;

// Initialize the wizard
procedure InitializeWizard;
begin
  // Create Client ID page
  ClientIDPage := CreateInputQueryPage(wpWelcome,
    'Client ID', 'Please enter your Client ID',
    'This ID is used to identify which client this installation belongs to.');
  ClientIDPage.Add('Client ID:', False);
  
  // Create Wazuh Groups page
  WazuhGroupsPage := CreateInputQueryPage(ClientIDPage.ID,
    'Wazuh Agent Groups', 'Please enter your Wazuh Agent Groups',
    'Multiple groups should be comma-separated (e.g., "group1,group2,group3"). Leave empty if not needed.');
  WazuhGroupsPage.Add('Wazuh Agent Groups:', False);
  
  // Check for command-line parameters
  ClientIDValue := GetCommandLineParam('CLIENT_ID');
  if ClientIDValue <> '' then
  begin
    ClientIDPage.Values[0] := ClientIDValue;
    IsClientIDFromParam := True;
  end
  else
  begin
    ClientIDPage.Values[0] := 'nhpdriXRA3M9Fs7rKkaAtG2lI'; // CHANGE ME
    IsClientIDFromParam := False;
  end;
  
  WazuhGroupsValue := GetCommandLineParam('WAZUH_GROUPS');
  if WazuhGroupsValue <> '' then
  begin
    WazuhGroupsPage.Values[0] := WazuhGroupsValue;
    IsWazuhGroupsFromParam := True;
  end
  else
  begin
    WazuhGroupsPage.Values[0] := '';
    IsWazuhGroupsFromParam := False;
  end;
end;

// Validate next button click
function NextButtonClick(CurPageID: Integer): Boolean;
begin
  if CurPageID = ClientIDPage.ID then
  begin
    // Validate Client ID
    ClientIDValue := ClientIDPage.Values[0];
    if ClientIDValue = '' then
    begin
      MsgBox('Please enter a valid Client ID.', mbError, MB_OK);
      Result := False;
    end
    else
      Result := True;
  end
  else if CurPageID = WazuhGroupsPage.ID then
  begin
    // No validation needed for Wazuh Groups as it can be empty
    WazuhGroupsValue := WazuhGroupsPage.Values[0];
    Result := True;
  end
  else
    Result := True;
end;

// Skip pages if values were provided as parameters
function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  
  if (PageID = ClientIDPage.ID) and IsClientIDFromParam then
    Result := True;
    
  if (PageID = WazuhGroupsPage.ID) and IsWazuhGroupsFromParam then
    Result := True;
end;

// Create configuration file
procedure CreateConfigFile;
var
  ConfigDir, ConfigFile, ConfigContent: String;
begin
  ConfigDir := ExpandConstant('{commonappdata}\NovaEDR\Config');
  ConfigFile := ConfigDir + '\config.json';
  
  // Create the configuration content with proper JSON escaping
  ConfigContent := '{' + #13#10 +
    '  "ServerUrl": "{#ServerURL}",' + #13#10 +
    '  "ClientId": "' + ClientIDValue + '",' + #13#10;
    
  // Add Wazuh Groups if specified
  if WazuhGroupsValue <> '' then
    ConfigContent := ConfigContent + '  "WazuhGroups": "' + WazuhGroupsValue + '",' + #13#10;
    
  ConfigContent := ConfigContent +
    '  "UpdateIntervalMinutes": {#UpdateIntervalMinutes},' + #13#10 +
    '  "LogLevel": "Info",' + #13#10 +
    '  "LogPath": "C:\\ProgramData\\NovaEDR\\Logs",' + #13#10 +
    '  "ConfigPath": "C:\\ProgramData\\NovaEDR\\Config",' + #13#10 +
    '  "TempPath": "C:\\ProgramData\\NovaEDR\\Temp"' + #13#10 +
    '}';
  
  // Write to file
  if FileExists(ConfigFile) then
    DeleteFile(ConfigFile);
    
  if not ForceDirectories(ConfigDir) then
    MsgBox('Failed to create directory: ' + ConfigDir, mbError, MB_OK);
    
  if SaveStringToFile(ConfigFile, ConfigContent, False) then
    Log('Created configuration file: ' + ConfigFile)
  else
    MsgBox('Failed to create configuration file: ' + ConfigFile, mbError, MB_OK);
end;

// Return the Client ID to use in the run section
function GetClientID(Param: String): String;
begin
  Result := ClientIDValue;
end;

// Return the Wazuh Groups to use in the run section
function GetWazuhGroups(Param: String): String;
begin
  Result := WazuhGroupsValue;
end;

// Handle uninstallation steps with proper dependency removal
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    // Ensure dependencies are uninstalled first
    if Exec(ExpandConstant('{app}\{#MyAppExeName}'), '--uninstall', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    begin
      // Agent uninstall executed successfully
      Log('Successfully executed agent uninstall with result code: ' + IntToStr(ResultCode));
    end
    else
    begin
      // Agent uninstall failed
      Log('Failed to execute agent uninstall: ' + SysErrorMessage(ResultCode));
    end;
  end
  else if CurUninstallStep = usPostUninstall then
  begin
    // Clean up configuration files
    DelTree(ExpandConstant('{commonappdata}\NovaEDR'), True, True, True);
  end;
end;

[Run]
; Create config file and install service
Filename: "{cmd}"; WorkingDir: "{app}"; Parameters: "/c echo Creating configuration file..."; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "--install CLIENT_ID=""{code:GetClientID}"" WAZUH_GROUPS=""{code:GetWazuhGroups}"""; WorkingDir: "{app}"; StatusMsg: "Installing Nova EDR service..."; Flags: runhidden; BeforeInstall: CreateConfigFile

[UninstallRun]
; First run the agent's uninstall function to remove dependencies
Filename: "{app}\{#MyAppExeName}"; Parameters: "--uninstall"; WorkingDir: "{app}"; StatusMsg: "Removing Nova EDR components..."; Flags: runhidden; RunOnceId: "UninstallComponents"
