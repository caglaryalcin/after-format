:: Uninstall - Edge
if exist "C:\Program Files (x86)\Microsoft\Edge\Application\" (
for /f "delims=" %%a in ('dir /b "C:\Program Files (x86)\Microsoft\Edge\Application\"') do (
cd /d "C:\Program Files (x86)\Microsoft\Edge\Application\%%a\Installer\" >nul 2>&1
if exist "setup.exe" (
set "EXIST=1"
echo - Removing Microsoft Edge
start /w setup.exe --uninstall --system-level --force-uninstall)
))

:: Uninstall - EdgeWebView
if exist "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\" (
for /f "delims=" %%a in ('dir /b "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\"') do (
cd /d "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\%%a\Installer\" >nul 2>&1
if exist "setup.exe" (
echo - Removing EdgeWebView
start /w setup.exe --uninstall --msedgewebview --system-level --force-uninstall)
))


:: Delete additional files
if exist "C:\Windows\System32\MicrosoftEdgeCP.exe" (
for /f "delims=" %%a in ('dir /b "C:\Windows\System32\MicrosoftEdge*"') do (
takeown /f "C:\Windows\System32\%%a" > NUL 2>&1
icacls "C:\Windows\System32\%%a" /inheritance:e /grant "%UserName%:(OI)(CI)F" /T /C > NUL 2>&1
del /S /Q "C:\Windows\System32\%%a" > NUL 2>&1))