@echo off

set "params=%*"
cd /d "%~dp0" && (if exist "%temp%\getadmin.vbs" del "%temp%\getadmin.vbs") && fsutil dirty query %systemdrive% 1>nul 2>nul || (echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "cmd.exe", "/k cd ""%~sdp0"" && %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs" && "%temp%\getadmin.vbs" && exit /B)

powershell -command (Get-Item 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe').VersionInfo.FileVersion > %TMP%\edge_version.txt

set file="%TMP%\edge_version.txt"
set maxbytesize=15
FOR /F "usebackq" %%A IN ('%file%') DO set size=%%~zA

if %size% LSS %maxbytesize% (
	echo.I have found the Microsoft Edge ^(NEW^) version^:
) ELSE (
	echo.Please check if Microsoft Edge ^(NEW^) is installed in your system...
	timeout 8 >nul
	exit
)

powershell -command (Get-Command 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe').Version
timeout 4 >nul
echo.Uninstalling Microsoft Edge ^(NEW^)...
set /p EDGE=<%TMP%\edge_version.txt
"C:\Program Files (x86)\Microsoft\Edge\Application\%EDGE%\Installer\setup.exe" -uninstall -system-level -verbose-logging -force-uninstall
echo.To complete the uninstallation of Microsoft Edge ^(NEW^) please restart Windows...
timeout 8 >nul
exit
