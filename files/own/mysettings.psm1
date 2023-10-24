##########
#region My Custom Drivers
##########
$myText = @"
###############################
######## DO NOT ACCEPT ########
###############################
"@

Write-Host `n$myText -ForegroundColor Red -BackgroundColor Black

Write-Host `n"Do you " -NoNewline
Write-Host "own this script?" -NoNewline -ForegroundColor Red -BackgroundColor Black
Write-Host "(Settings, downloads and installations of the script owner will be made):" -NoNewline -ForegroundColor Red -BackgroundColor Black
Write-Host "(y/n): " -NoNewline
$response = Read-Host

if ($response -eq 'y' -or $response -eq 'Y') {

    Function Own {
        Function SetPins {
            ##Create Icons folder
            New-Item -Path 'C:\icons' -ItemType Directory *>$null

            #Opera
            $WScriptShell = New-Object -ComObject WScript.Shell
            $Opera = "C:\Program Files\Opera\Launcher.exe"
            $OperaDirectory = "C:\Program Files\Opera\"
            $ShortcutFile = "C:\icons\Opera Browser.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $Opera
            $Shortcut.WorkingDirectory = $OperaDirectory
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\Opera Browser.lnk" *>$null

            #Chrome
            $WScriptShell = New-Object -ComObject WScript.Shell
            $Chrome = "C:\Program Files\Google\Chrome\Application\chrome.exe"
            $Shortcut.WorkingDirectory = "C:\Program Files\Google\Chrome\Application\"
            $ShortcutFile = "C:\icons\Google Chrome.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $Chrome
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\Google Chrome.lnk" *>$null

            #Brave
            $WScriptShell = New-Object -ComObject WScript.Shell
            $Brave = "$env:USERPROFILE\AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe"
            $BraveDirectory = "$env:USERPROFILE\AppData\Local\BraveSoftware\Brave-Browser\Application"
            $Shortcut.WorkingDirectory = "$env:USERPROFILE\AppData\Local\BraveSoftware\Brave-Browser\Application"
            $ShortcutFile = "C:\icons\Brave.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $Brave
            $Shortcut.WorkingDirectory = $BraveDirectory
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\Brave.lnk" *>$null

            #Firefox
            $WScriptShell = New-Object -ComObject WScript.Shell
            $Firefox = "C:\Program Files\Mozilla Firefox\firefox.exe"
            $ShortcutFile = "C:\icons\Firefox.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $Firefox
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\Firefox.lnk" *>$null

            #Librewolf
            $WScriptShell = New-Object -ComObject WScript.Shell
            $Librewolf = "C:\Program Files\LibreWolf\librewolf.exe"
            $ShortcutFile = "C:\icons\LibreWolf.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $Librewolf
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\LibreWolf.lnk" *>$null

            #File Explorer was here

            #Adobe Photoshop (offline)
            #$WScriptShell = New-Object -ComObject WScript.Shell
            #$Photoshop = "C:\Program Files\Adobe\Adobe Photoshop 2020\Photoshop.exe"
            #$PhotoshopPath = "C:\Program Files\Adobe\Adobe Photoshop 2020"
            #$ShortcutFile = "C:\icons\Adobe Photoshop 2020.lnk"
            #$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            #$Shortcut.TargetPath = $Photoshop
            #$Shortcut.WorkingDirectory = $PhotoshopPath
            #$Shortcut.Save()
            #Unblock-File -Path "C:\icons\Adobe Photoshop 2020.lnk" *>$null

            #Adobe Premiere Pro (offline)
            #$WScriptShell = New-Object -ComObject WScript.Shell
            #$Premiere = "C:\Program Files\Adobe\Adobe Premiere Pro 2020\Adobe Premiere Pro.exe"
            #$PremierePath = "C:\Program Files\Adobe\Adobe Premiere Pro 2020"
            #$ShortcutFile = "C:\icons\Adobe Premiere Pro 2020.lnk"
            #$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            #$Shortcut.TargetPath = $Premiere
            #$Shortcut.WorkingDirectory = $PremierePath
            #$Shortcut.Save()
            #Unblock-File -Path "C:\icons\Adobe Premiere Pro 2020.lnk" *>$null

            #Steam
            $WScriptShell = New-Object -ComObject WScript.Shell
            $Steam = "C:\Program Files (x86)\Steam\Steam.exe"
            $ShortcutFile = "C:\icons\Steam.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $Steam
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\Steam.lnk" *>$null

            #Epic Games
            $WScriptShell = New-Object -ComObject WScript.Shell
            $Epic = "C:\Program Files (x86)\Epic Games\Launcher\Portal\Binaries\Win32\EpicGamesLauncher.exe"
            $EpicPath = "C:\Program Files (x86)\Epic Games\"
            $ShortcutFile = "C:\icons\EpicGamesLauncher.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $Epic
            $Shortcut.WorkingDirectory = $EpicPath
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\EpicGamesLauncher.lnk" *>$null

            #HWMonitor
            $WScriptShell = New-Object -ComObject WScript.Shell
            $HW = "C:\Program Files\CPUID\HWMonitor\HWMonitor.exe"
            $ShortcutFile = "C:\icons\HWMonitor.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $HW
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\HWMonitor.lnk" *>$null

            #Crystal Disk Info
            $WScriptShell = New-Object -ComObject WScript.Shell
            $Crystal = "C:\ProgramData\chocolatey\lib\crystaldiskinfo.portable\tools\DiskInfo64.exe"
            $CrystalDirectory = "C:\ProgramData\chocolatey\lib\crystaldiskinfo.portable\tools\"
            $ShortcutFile = "C:\icons\CrystalDiskInfo.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $Crystal
            $Shortcut.WorkingDirectory = $CrystalDirectory
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\CrystalDiskInfo.lnk" *>$null

            #vMware Workstation
            $WScriptShell = New-Object -ComObject WScript.Shell
            $vMware = "C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe"
            $vMwareDirectory = "C:\Program Files (x86)\VMware\VMware Workstation\"
            $ShortcutFile = "C:\icons\VMware Workstation Pro.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $vMware
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\VMware Workstation Pro.lnk" *>$null

            #VirtualBox
            $WScriptShell = New-Object -ComObject WScript.Shell
            $VirtualBox = "C:\Program Files\Oracle\VirtualBox\VirtualBox.exe"
            $ShortcutFile = "C:\icons\Oracle VM VirtualBox.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $VirtualBox
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\Oracle VM VirtualBox.lnk" *>$null

            #Signal
            $WScriptShell = New-Object -ComObject WScript.Shell
            $Signal = "$env:USERPROFILE\AppData\Local\Programs\signal-desktop\Signal.exe"
            $ShortcutFile = "C:\icons\Signal.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $Signal
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\Signal.lnk" *>$null

            #Sticky Notes was here

            #Visual Studio
            $WScriptShell = New-Object -ComObject WScript.Shell
            $Visual = "C:\Program Files\Microsoft VS Code\Code.exe"
            $ShortcutFile = "C:\icons\Visual Studio Code.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $Visual
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\Visual Studio Code.lnk" *>$null

            #AnyDesk
            $WScriptShell = New-Object -ComObject WScript.Shell
            $Anydesk = "C:\ProgramData\chocolatey\lib\anydesk.portable\tools\AnyDesk.exe"
            $AnydeskPath = "C:\ProgramData\chocolatey\lib\anydesk.portable\tools\"
            $ShortcutFile = "C:\icons\AnyDesk.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $Anydesk
            $Shortcut.WorkingDirectory = $AnydeskPath
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\AnyDesk.lnk" *>$null

            #Terminal was here

            #SublimeText
            $WScriptShell = New-Object -ComObject WScript.Shell
            $SublimeText = "C:\Program Files\Sublime Text 3\sublime_text.exe"
            $SublimeTextPath = "C:\Program Files\Sublime Text 3\"
            $ShortcutFile = "C:\icons\Sublime Text.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $SublimeText
            $Shortcut.WorkingDirectory = $SublimeTextPath
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\Sublime Text.lnk" *>$null

            #Github Desktop
            $WScriptShell = New-Object -ComObject WScript.Shell
            $Github = "$env:USERPROFILE\AppData\Local\GitHubDesktop\GitHubDesktop.exe"
            $GithubPath = "$env:USERPROFILE\AppData\Local\GitHubDesktop\"
            $ShortcutFile = "C:\icons\GitHub Desktop.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $Github
            $Shortcut.WorkingDirectory = $GithubPath
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\GitHub Desktop.lnk" *>$null

            #Calculator was here

            #TreeSize
            $WScriptShell = New-Object -ComObject WScript.Shell
            $TreeSize = "C:\Program Files\JAM Software\TreeSize Free\TreeSizeFree.exe"
            $TreeSizePath = "C:\Program Files\JAM Software\TreeSize Free"
            $ShortcutFile = "C:\icons\TreeSize Free (Administrator).lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $TreeSize
            $Shortcut.WorkingDirectory = $TreeSizePath
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\TreeSize Free (Administrator).lnk" *>$null

            #Total Commander
            $WScriptShell = New-Object -ComObject WScript.Shell
            $TCM = "C:\Program Files\totalcmd\TOTALCMD64.EXE"
            $ShortcutFile = "C:\icons\Total Commander.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $TCM
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\Total Commander.lnk" *>$null

            #WireShark
            $WScriptShell = New-Object -ComObject WScript.Shell
            $WireShark = "C:\Program Files\Wireshark\Wireshark.exe"
            $ShortcutFile = "C:\icons\WireShark.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $WireShark
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\WireShark.lnk" *>$null

            #Putty
            $WScriptShell = New-Object -ComObject WScript.Shell
            $Putty = "C:\Program Files\PuTTY\putty.exe"
            $PuttyPath = "C:\Program Files\PuTTY\"
            $ShortcutFile = "C:\icons\Putty.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $Putty
            $Shortcut.WorkingDirectory = $PuttyPath
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\Putty.lnk" *>$null

            #Deluge
            $WScriptShell = New-Object -ComObject WScript.Shell
            $Deluge = "C:\Program Files\Deluge\deluge.exe"
            $ShortcutFile = "C:\icons\Deluge.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $Deluge
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\Deluge.lnk" *>$null

            #DBeaver
            $WScriptShell = New-Object -ComObject WScript.Shell
            $DBeaver = "C:\Program Files\DBeaver\dbeaver.exe"
            $DBeaverPath = "C:\Program Files\DBeaver\"
            $ShortcutFile = "C:\icons\DBeaver.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $DBeaver
            $Shortcut.WorkingDirectory = $DBeaverPath
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\DBeaver.lnk" *>$null

            #Cryptomator
            $WScriptShell = New-Object -ComObject WScript.Shell
            $Cryptomator = "C:\Program Files\Cryptomator\Cryptomator.exe"
            $ShortcutFile = "C:\icons\Cryptomator.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $Cryptomator
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\Cryptomator.lnk" *>$null

            #iTunes (problematic)
            #$WScriptShell = New-Object -ComObject WScript.Shell
            #$iTunes = "C:\Program Files\iTunes\iTunes.exe"
            #$ShortcutFile = "C:\icons\iTunes.lnk"
            #$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            #$Shortcut.TargetPath = $iTunes
            #$Shortcut.Save()
            #Unblock-File -Path "C:\icons\iTunes.lnk" *>$null

            #MS Teams
            $WScriptShell = New-Object -ComObject WScript.Shell
            $MSTeams = "$env:USERPROFILE\AppData\Local\Microsoft\Teams\Update.exe"
            $ShortcutFile = "C:\icons\Microsoft Teams.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = "$env:USERPROFILE\AppData\Local\Microsoft\Teams\Update.exe"
            $Shortcut.Arguments = "--processStart Teams.exe"
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\Microsoft Teams.lnk" *>$null

            #PowerToys
            $WScriptShell = New-Object -ComObject WScript.Shell
            $Powertoys = "C:\Program Files\PowerToys\WinUI3Apps\PowerToys.Settings.exe"
            $PowertoysPath = "C:\Program Files\PowerToys\WinUI3Apps\"
            $ShortcutFile = "C:\icons\PowerToys.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $Powertoys
            $Shortcut.WorkingDirectory = $PowertoysPath
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\PowerToys.lnk" *>$null

            #dupeGuru
            $WScriptShell = New-Object -ComObject WScript.Shell
            $dupeGuru = "C:\Program Files\Hardcoded Software\dupeGuru\dupeguru-win64.exe"
            $dupeGuruPath = "C:\Program Files\Hardcoded Software\dupeGuru\"
            $ShortcutFile = "C:\icons\dupeGuru.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $dupeGuru
            $Shortcut.WorkingDirectory = $dupeGuruPath
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\dupeGuru.lnk" *>$null

            #fan control manual installation
            Invoke-WebRequest -Uri "https://github.com/Rem0o/FanControl.Releases/blob/master/FanControl.zip?raw=true" -Outfile C:\fan_control.zip *>$null
            $OriginalProgressPreference = $Global:ProgressPreference
            $Global:ProgressPreference = 'SilentlyContinue'
            Expand-Archive -Path 'C:\fan_control.zip' -DestinationPath C:\fan_control\ -Force *>$null
            Remove-Item C:\fan_control.zip -recurse -ErrorAction SilentlyContinue
            Start-Process C:\fan_control\FanControl.exe
            Start-Sleep 5
            taskkill /f /im FanControl.exe *>$null

            #fan control
            $WScriptShell = New-Object -ComObject WScript.Shell
            $fanControl = "C:\fan_control\FanControl.exe"
            $fanControlPath = "C:\fan_control"
            $ShortcutFile = "C:\icons\FanControl.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $fanControl
            $Shortcut.WorkingDirectory = $fanControlPath
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\FanControl.lnk" *>$null
            #copy fan control to startup folder
            Copy-Item C:\icons\FanControl.lnk "$env:USERPROFILE\Appdata\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\FanControl.lnk" -Force

            #openrgb
            $WScriptShell = New-Object -ComObject WScript.Shell
            $openrgb = "C:\ProgramData\chocolatey\lib\openrgb\tools\OpenRGB Windows 64-bit\OpenRGB.exe"
            $openrgbpath = "C:\ProgramData\chocolatey\lib\openrgb\tools\OpenRGB Windows 64-bit\"
            $ShortcutFile = "C:\icons\openrgb.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $openrgb
            $Shortcut.WorkingDirectory = $openrgbpath
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\openrgb.lnk" *>$null
            #copy openrgb to startup folder
            Copy-Item C:\icons\openrgb.lnk "$env:USERPROFILE\Appdata\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\openrgb.lnk" -Force

            #create config folder
            $job = Start-Job -ScriptBlock { 
                & "C:\ProgramData\chocolatey\lib\openrgb\tools\OpenRGB Windows 64-bit\OpenRGB.exe" *>$null 2>&1
            } *> $null
         
            Start-Sleep 10
            taskkill.exe /f /im OpenRGB.exe *>$null

            #Set Pin
            $progressPreference = 'silentlyContinue'
            Get-ChildItem $env:USERPROFILE\Desktop\* | ForEach-Object { Remove-Item $_ }
            Get-ChildItem C:\users\Public\Desktop\*.lnk | ForEach-Object { Remove-Item $_ }
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/caglaryalcin/after-format/main/files/own/taskbar_pin.reg" -Outfile C:\taskbar_pin.reg
            reg import "C:\taskbar_pin.reg" *>$null
            Copy-Item -Path "C:\icons\*" -Destination "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\" -Force
            reg import "C:\taskbar_pin.reg" *>$null
            taskkill /f /im explorer.exe *>$null
            Remove-Item C:\taskbar_pin.reg -recurse -ErrorAction SilentlyContinue
            Start-Sleep 1
            start explorer.exe
            Start-Sleep 2

            #delete c:\icons folder
            Remove-Item C:\icons\ -recurse -ErrorAction SilentlyContinue
        }

        SetPins
                
        Function Drivers {
            #Chipset
            Write-Host `n"Installing Chipset Driver..." -NoNewline
            $OriginalProgressPreference = $Global:ProgressPreference
            $Global:ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri https://dlcdnets.asus.com/pub/ASUS/mb/03CHIPSET/DRV_Chipset_Intel_CML_TP_W10_64_V101182958201_20200423R.zip -OutFile C:\Asus.zip
            $OriginalProgressPreference = $Global:ProgressPreference
            $Global:ProgressPreference = 'SilentlyContinue'
            Expand-Archive -Path 'C:\Asus.zip' -DestinationPath C:\Asus\ -Force *>$null
            $OriginalProgressPreference = $Global:ProgressPreference
            $Global:ProgressPreference = 'SilentlyContinue'
            C:\Asus\SetupChipset.exe -s -NoNewWindow -Wait
            Remove-Item C:\Asus.zip -recurse -ErrorAction SilentlyContinue
            Start-Sleep 1
            Remove-Item C:\Asus -recurse -ErrorAction SilentlyContinue
            Start-Sleep 5
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black

            #NVIDIA Driver
            # Check for archiving software (7-zip or WinRAR)
            Write-Host "Installing Nvidia Driver..." -NoNewline
            $archiverProgram = $null
            $7zPath = Get-ItemProperty -Path "HKLM:\SOFTWARE\7-Zip\" -Name "Path" -ErrorAction SilentlyContinue
            if ($7zPath) {
                $archiverProgram = Join-Path $7zPath.Path "7z.exe"
            } else {
                $winrarPath = Get-ItemProperty -Path "HKLM:\SOFTWARE\WinRAR" -Name "exe64" -ErrorAction SilentlyContinue
                if ($winrarPath) {
                    $archiverProgram = $winrarPath.exe64
                }
            }
                        if (-not $archiverProgram) {
                Write-Host "No supported archiver found. Install 7-Zip or WinRAR and rerun the script." -ForegroundColor Red
                return
            }
            # Get the latest driver version
            $uri = 'https://gfwsl.geforce.com/services_toolkit/services/com/nvidia/services/AjaxDriverService.php' +
            '?func=DriverManualLookup&psid=120&pfid=929&osID=57&languageCode=1033&isWHQL=1&dch=1&sort1=0&numberOfResults=1'
            $OriginalProgressPreference = $Global:ProgressPreference
            $Global:ProgressPreference = 'SilentlyContinue'
            $response = Invoke-WebRequest -Uri $uri -Method GET -UseBasicParsing
            $payload = $response.Content | ConvertFrom-Json
            $version = $payload.IDS[0].downloadInfo.Version

            # Determine Windows version and architecture
            $windowsVersion = if ([Environment]::OSVersion.Version -ge [Version]::new(9, 1)) { "win10-win11" } else { "win8-win7" }
            $windowsArchitecture = if ([Environment]::Is64BitOperatingSystem) { "64bit" } else { "32bit" }

            # Set up temp folder and download link
            $nvidiaTempFolder = Join-Path $env:TEMP "NVIDIA"
            New-Item -Path $nvidiaTempFolder -ItemType Directory -Force | Out-Null
            $url = "https://international.download.nvidia.com/Windows/$version/$version-desktop-$windowsVersion-$windowsArchitecture-international-dch-whql.exe"

            # Download the installer
            $dlFile = Join-Path $nvidiaTempFolder "$version.exe"
            $OriginalProgressPreference = $Global:ProgressPreference
            $Global:ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $url -OutFile $dlFile -UseBasicParsing

            # Extract setup files
            $extractFolder = Join-Path $nvidiaTempFolder $version
            $filesToExtract = "Display.Driver", "HDAudio", "NVI2", "PhysX", "EULA.txt", "ListDevices.txt", "setup.cfg", "setup.exe"
            $tempOutFile = [System.IO.Path]::GetTempFileName()
            $tempErrFile = [System.IO.Path]::GetTempFileName()
            $arguments = @("x", "-aoa", "-o`"$extractFolder`"", "`"$dlFile`"") + $filesToExtract
            $null = Start-Process -FilePath $archiverProgram -ArgumentList $arguments -Wait -NoNewWindow -PassThru -RedirectStandardOutput $tempOutFile -RedirectStandardError $tempErrFile

            # Update setup.cfg to remove unneeded dependencies
            (Get-Content (Join-Path $extractFolder "setup.cfg")) -replace 'name="\${{(EulaHtmlFile|FunctionalConsentFile|PrivacyPolicyFile)}}"', '' | Set-Content (Join-Path $extractFolder "setup.cfg")

            # Install drivers
            $installArgs = "-passive", "-noreboot", "-noeula", "-nofinish", "-s"

            # Clean up
            Remove-Item $nvidiaTempFolder -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item "C:\NVIDIA" -Recurse -Force -ErrorAction SilentlyContinue

            # Delete temp files
            Remove-Item $tempOutFile -ErrorAction SilentlyContinue
            Remove-Item $tempErrFile -ErrorAction SilentlyContinue
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }
                
        Drivers

        #Restore Librewolf settings and extensions
        function installLibreWolfAddIn() {
            Write-Host "Librewolf settings and extensions are being restored..." -NoNewline

            #it is necessary to formation of a profile
            cd "C:\Program Files\LibreWolf\"
            .\librewolf.exe
            Start-Sleep 2
            taskkill /f /im "librewolf.exe" *>$null

            $instdir = "C:\Program Files\LibreWolf"
$distribution = $instdir + '\distribution'
$extensions = $instdir + '\distribution\extensions'

$addons = @{
    "bitwarden-password-manager" = '{446900e4-71c2-419f-a6a7-df9c091e268b}';
    "ublock-origin" = 'uBlock0@raymondhill.net';
    "privacy-badger17" = 'jid1-MnnxcxisBPnSXQ@jetpack';
    "darkreader" = 'addon@darkreader.org';
    "ublacklist" = '@ublacklist';
    "return-youtube-dislikes" = '{762f9885-5a13-4abd-9c77-433dcd38b8fd}';
    "best-internet-download-manager" = 'mozilla_cc3@internetdownloadmanager.com'
}

If (-Not(Test-Path $distribution)) {
    New-Item $distribution -ItemType Container | Out-Null
}
If (-Not(Test-Path $extensions)) {
    New-Item $extensions -ItemType Container | Out-Null
}

foreach ($addon in $addons.GetEnumerator()) {
    try {
        # Eklenti bilgilerini al
        $response = Invoke-RestMethod -Uri "https://addons.mozilla.org/api/v4/addons/addon/$($addon.Name)/"

        # En son sürüm numarasını al
        $latestVersion = $response.current_version.version

        # Eklenti adı ve sürüm numarasını kullanarak indirme URL'sini oluştur
        $addonUrl = "https://addons.mozilla.org/firefox/downloads/latest/$($addon.Name)/addon-$($addon.Name)-latest.xpi"

        $addonPath = $extensions + '\' + $addon.Value + '.xpi'

        # XPI dosyasını indir
        Invoke-WebRequest $addonUrl -Outfile $addonPath
    } catch {
        Write-Host "Error downloading or getting info for addon $($addon.Name): $_" -ForegroundColor Red
    }
}

            $dest = Get-ChildItem -Path $env:USERPROFILE\AppData\Roaming\librewolf\Profiles\ -Exclude *.default
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/user.js" -Outfile $dest\user.js
            New-Item $dest -Name chrome -ItemType "directory" *>$null
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/Tab%20Shapes.css" -Outfile "$dest\chrome\Tab Shapes.css"
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/userChrome.css" -Outfile "$dest\chrome\Toolbar.css"
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/userContent.css" -Outfile "$dest\chrome\userContent.css"
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/userChrome.css" -Outfile "$dest\chrome\userChrome.css"
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        installLibreWolfAddIn("");
                
        #Sublime text
        function Set-Configs {
            Write-Host "Setting my configs..." -NoNewline

            # Helper function for web requests
            function Safe-Invoke-WebRequest($uri, $outFile) {
                try {
                    Invoke-WebRequest -Uri $uri -Outfile $outFile
                }
                catch {
                    Write-Host " [WARNING] Failed to download from: $uri. Error: $_" -ForegroundColor Red -BackgroundColor Black
                }
            }
            
            # Ublacklist url to desktop
            $filePath = "$env:userprofile\Desktop\ublacklist-address.txt"
            Set-Content -Path $filePath -Value "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/extensions/ublacklist.txt"

            # Define directories and files to be downloaded
            $downloads = @{
                "$env:userprofile\AppData\Roaming\Sublime Text\Packages\User"      = @(
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/sublime-text/Preferences.sublime-settings",
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/sublime-text/cy.sublime-color-scheme",
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/sublime-text/Default%20(Windows).sublime-mousemap"
                )
                "$env:userprofile\AppData\Roaming\Sublime Text\Installed Packages" = @(
                    "https://packagecontrol.io/Package%20Control.sublime-package"
                )
                "$env:UserProfile\Documents\PowerToys\Backup"                      = @(
                    "https://github.com/caglaryalcin/after-format/raw/main/files/own/settings_133264013067260668.ptb"
                )
                "$env:userprofile\Desktop"                                         = @(
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/extensions/ublock.txt",
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/extensions/bookmarks.json"
                )
                "C:\fan_control\Configurations"                                    = @(
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/my_fan_config.json"
                )
                "$env:USERPROFILE\Appdata\Roaming\Openrgb"                         = @(
                    "https://github.com/caglaryalcin/my-configs/raw/main/my_led_config.orp"
                )
            }
            
            # Process each directory and download files
            foreach ($dir in $downloads.Keys) {
                Ensure-Directory -path $dir
                foreach ($url in $downloads[$dir]) {
                    $uri = [System.Uri]$url
                    $fileName = [System.IO.Path]::GetFileName($uri.LocalPath)
                    $outFile = Join-Path -Path $dir -ChildPath $fileName
                    Safe-Invoke-WebRequest -uri $url -outFile $outFile
                }
            }
            
            try {
                New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "electron.app.Twinkle Tray" -PropertyType String -Value "$env:userprofile\AppData\Local\Programs\twinkle-tray\Twinkle Tray.exe" | Out-Null
                New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowDevMgrUpdates" -PropertyType DWORD -Value "0" | Out-Null
                New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -PropertyType DWORD -Value "0" | Out-Null
                New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMDevicesEnumerationEnabled" -Value 0 | Out-Null
                New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableDeviceEnumeration" -PropertyType DWORD -Value 1 | Out-Null
            }
            catch {
                Write-Host " [WARNING] Failed in additional configurations. Error: $_" -ForegroundColor Red -BackgroundColor Black
            }
                    
            # Monitor settings prompt
            try {
                Start-Process "rundll32.exe" -ArgumentList "display.dll, ShowAdapterSettings 0" -NoNewWindow -Wait
                Start-Process "rundll32.exe" -ArgumentList "display.dll, ShowAdapterSettings 1" -NoNewWindow -Wait
            }
            catch {
                Write-Host " [WARNING] Failed to set monitor settings. Error: $_" -ForegroundColor Red -BackgroundColor Black
            }
                    
            # Import Cloudflare certificate
            try {
                $certPath = "C:\Cloudflare_CA.crt"
                Invoke-WebRequest -Uri "https://developers.cloudflare.com/cloudflare-one/static/documentation/connections/Cloudflare_CA.crt" -Outfile $certPath
                Import-Certificate -FilePath $certPath -CertStoreLocation "cert:\LocalMachine\Root" | Out-Null
                Remove-Item -Path $certPath -Force
            }
            catch {
                Write-Host " [WARNING] Failed to import Cloudflare certificate. Error: $_" -ForegroundColor Red -BackgroundColor Black
            }
                    
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }
                    
        Set-Configs
        
        function MediaFeaturePack {
            try {
                Write-Host "Installing Media Feature Pack..." -NoNewline
                # check new version
                $capability = DISM /Online /Get-Capabilities | Select-String 'Media.MediaFeaturePack~~~~'
                if ($capability) {
                    $newVersion = $capability.ToString().Trim()
                    $newVersion = $newVersion -replace 'Capability Identity : ', '' -replace '\s', ''
                    
                    # Add the capability
                    $installResult = DISM /Online /Add-Capability /CapabilityName:$newVersion /Quiet /NoRestart
                    
                    # 0 success, 3010 restart required
                    if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 3010) {
                        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                    }
                    else {
                        # throw "DISM exited with code $LASTEXITCODE. Message: $installResult"
                    }
                }
                else {
                    Write-Host "[WARNING] Media Feature Pack capability not found." -ForegroundColor Red -BackgroundColor Black
                }
            }
            catch {
                Write-Host " [WARNING] Failed. Error: $_" -ForegroundColor Red
            }
        }
        
        MediaFeaturePack

        #Set Wallpaper
        Function SetWallpaper {
            Write-Host "Setting Desktop Wallpaper..." -NoNewline
            $url = "https://raw.githubusercontent.com/caglaryalcin/after-format/main/files/own/hello.png"
            $filePath = "$HOME\Documents\hello.png"
            $wc = New-Object System.Net.WebClient
            try {
                $wc.DownloadFile($url, $filePath)
                Set-Itemproperty -path "HKCU:Control Panel\Desktop" -name WallPaper -value "$env:userprofile\Documents\hello.png"  | Out-Null
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
            }
            catch {
                Write-Host "[WARNING] Failed to set wallpaper: $_" -ForegroundColor Yellow
            }
        }
        
        SetWallpaper

        #Adobe DNG Codec
        Function DNGCodec {
        $url = "https://download.adobe.com/pub/adobe/dng/win/DNGCodec_2_0_Installer.exe"
        $filePath = "C:\DNGCodec_Installer.exe"

        Invoke-WebRequest -Uri $url -OutFile $filePath

        Start-Process -FilePath $filePath -ArgumentList "/S" -Wait -PassThru *>$null

        Remove-Item -Path $filePath

        }
        
        DNGCodec
    }

    Own

}

elseif ($response -eq 'n' -or $response -eq 'N') {
    Write-Host "[The Process Cancelled]" -ForegroundColor Red -BackgroundColor Black
}
else {
    Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
}


##########
#endregion My Custom Drivers
##########