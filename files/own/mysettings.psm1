##########
#region My Custom Drivers
##########
$myText = @"
###############################
######## DO NOT ACCEPT ########
###############################
"@

Write-Host $myText -ForegroundColor Red -BackgroundColor Black

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
            Start-Process "C:\ProgramData\chocolatey\lib\openrgb\tools\OpenRGB Windows 64-bit\OpenRGB.exe" *>$null
            Start-Sleep 5
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

            #Nvidia driver
            Write-Host "Installing latest version Nvidia Drivers..." -NoNewline

            # Check 7zip install path on registry
            $7zipinstalled = $false 
            if ((Test-path HKLM:\SOFTWARE\7-Zip\) -eq $true) {
                $7zpath = Get-ItemProperty -path  HKLM:\SOFTWARE\7-Zip\ -Name Path
                $7zpath = $7zpath.Path
                $7zpathexe = $7zpath + "7z.exe"
                if ((Test-Path $7zpathexe) -eq $true) {
                    $archiverProgram = $7zpathexe
                    $7zipinstalled = $true 
                }    
            }
            elseif ($7zipinstalled -eq $false) {
                if ((Test-path HKLM:\SOFTWARE\WinRAR) -eq $true) {
                    $winrarpath = Get-ItemProperty -Path HKLM:\SOFTWARE\WinRAR -Name exe64 
                    $winrarpath = $winrarpath.exe64
                    if ((Test-Path $winrarpath) -eq $true) {
                        $archiverProgram = $winrarpath
                    }
                }
            }
            else {
                Write-Host "Sorry, but it looks like you don't have a supported archiver."
                while ($choice -notmatch "[y|n]") {
                    $choice = read-host "Would you like to install 7-Zip now? (Y/N)"
                }
                if ($choice -eq "y") {
                    # Download and silently install 7-zip if the user presses y
                    $7zip = "https://www.7-zip.org/a/7z1900-x64.exe"
                    $output = "$PSScriptRoot\7Zip.exe"
                        (New-Object System.Net.WebClient).DownloadFile($7zip, $output)
       
                    Start-Process "7Zip.exe" -Wait -ArgumentList "/S"
                    # Delete the installer once it completes
                    Remove-Item "$PSScriptRoot\7Zip.exe"
                }
                else {
                    Write-Host "Fail..."
                }
            }
   
            # Checking currently installed driver version
            try {
                $VideoController = Get-WmiObject -ClassName Win32_VideoController | Where-Object { $_.Name -match "NVIDIA" }
                $ins_version = ($VideoController.DriverVersion.Replace('.', '')[-5..-1] -join '').insert(3, '.')
            }
            catch {
                Write-Host -ForegroundColor Yellow "Unable to detect a compatible Nvidia device."
            }

            # Checking latest driver version
            $uri = 'https://gfwsl.geforce.com/services_toolkit/services/com/nvidia/services/AjaxDriverService.php' +
            '?func=DriverManualLookup' +
            '&psid=120' + # Geforce RTX 30 Series
            '&pfid=929' + # RTX 3080
            '&osID=57' + # Windows 10 64bit
            '&languageCode=1033' + # en-US; seems to be "Windows Locale ID"[1] in decimal
            '&isWHQL=1' + # WHQL certified
            '&dch=1' + # DCH drivers (the new standard)
            '&sort1=0' + # sort: most recent first(?)
            '&numberOfResults=1' # single, most recent result is enough

            #[1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lcid/a9eac961-e77d-41a6-90a5-ce1a8b0cdb9c

            $response = Invoke-WebRequest -Uri $uri -Method GET -UseBasicParsing
            $payload = $response.Content | ConvertFrom-Json
            $version = $payload.IDS[0].downloadInfo.Version
            Write-Output "Latest version `t$version"

            # Checking Windows version
            if ([Environment]::OSVersion.Version -ge (new-object 'Version' 9, 1)) {
                $windowsVersion = "win10-win11"
            }
            else {
                $windowsVersion = "win8-win7"
            }

            # Checking Windows bitness
            if ([Environment]::Is64BitOperatingSystem) {
                $windowsArchitecture = "64bit"
            }
            else {
                $windowsArchitecture = "32bit"
            }

            # Create a new temp folder NVIDIA
            $nvidiaTempFolder = "$env:temp\NVIDIA"
            New-Item -Path $nvidiaTempFolder -ItemType Directory 2>&1 | Out-Null


            # Generating the download link
            $url = "https://international.download.nvidia.com/Windows/$version/$version-desktop-$windowsVersion-$windowsArchitecture-international-dch-whql.exe"
            $rp_url = "https://international.download.nvidia.com/Windows/$version/$version-desktop-$windowsVersion-$windowsArchitecture-international-dch-whql-rp.exe"


            # Downloading the installer
            $dlFile = "$nvidiaTempFolder\$version.exe"
            $OriginalProgressPreference = $Global:ProgressPreference
            $Global:ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $url -OutFile $dlFile

            # Extracting setup files
            $extractFolder = "$nvidiaTempFolder\$version"
            $filesToExtract = "Display.Driver HDAudio NVI2 PhysX EULA.txt ListDevices.txt setup.cfg setup.exe"

            if ($7zipinstalled) {
                Start-Process -FilePath $archiverProgram -NoNewWindow -ArgumentList "x -bso0 -bsp1 -bse1 -aoa $dlFile $filesToExtract -o""$extractFolder""" -wait
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            elseif ($archiverProgram -eq $winrarpath) {
                Start-Process -FilePath $archiverProgram -NoNewWindow -ArgumentList 'x $dlFile $extractFolder -IBCK $filesToExtract' -wait
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "Something went wrong. No archive program detected. This should not happen."
            }

            # Remove unneeded dependencies from setup.cfg
                (Get-Content "$extractFolder\setup.cfg") | Where-Object { $_ -notmatch 'name="\${{(EulaHtmlFile|FunctionalConsentFile|PrivacyPolicyFile)}}' } | Set-Content "$extractFolder\setup.cfg" -Encoding UTF8 -Force

            # Installing drivers
            $install_args = "-passive -noreboot -noeula -nofinish -s"
            Start-Process -FilePath "$extractFolder\setup.exe" -ArgumentList $install_args -wait

            # Cleaning up downloaded files
            Write-Host "Deleting downloaded files"
            Remove-Item $nvidiaTempFolder -Recurse -Force *>$null
            Remove-Item C:\NVIDIA -Recurse -Force *>$null
            Start-Sleep 3
        }
                
        Drivers

        #Restore Librewolf settings and extensions
        function Install-LibreWolfAddIn {
            Write-Host "Restoring Librewolf settings and extensions..." -NoNewline
        
            try {
                # Start and immediately stop LibreWolf to initiate profile creation
                Start-Process -FilePath "C:\Program Files\LibreWolf\librewolf.exe" -Wait
                Start-Sleep -Seconds 2
                Stop-Process -Name "librewolf" -Force
        
                $extensionsBasePath = "C:\Program Files\LibreWolf\distribution\extensions"
                $profilePath = Get-ChildItem -Path "$env:USERPROFILE\AppData\Roaming\librewolf\Profiles" -Exclude *.default
        
                # Ensure directories exist
                $null = New-Item -Path $extensionsBasePath -ItemType Container -Force
        
                # Define addons and their URLs
                $addons = @{
                    "bitwarden"        = "https://addons.mozilla.org/firefox/downloads/file/4164440/bitwarden_password_manager-2023.8.3.xpi"
                    "ublockorigin"     = "https://addons.mozilla.org/firefox/downloads/file/4171020/ublock_origin-1.52.2.xpi"
                    "privacybadger"    = "https://addons.mozilla.org/firefox/downloads/file/4167070/privacy_badger17-2023.9.12.xpi"
                    "darkreader"       = "https://addons.mozilla.org/firefox/downloads/file/4151368/darkreader-4.9.65.xpi"
                    "ublacklist"       = "https://addons.mozilla.org/firefox/downloads/file/4169526/ublacklist-8.3.4.xpi"
                    "returnytdl"       = "https://addons.mozilla.org/firefox/downloads/file/4147411/return_youtube_dislikes-3.0.0.10.xpi"
                    "idm"              = "https://addons.mozilla.org/firefox/downloads/file/4167725/tonec_idm_integration_module-6.41.20.xpi"
                }
        
                # Download and place each addon
                foreach ($addon in $addons.GetEnumerator()) {
                    $addonPath = Join-Path -Path $extensionsBasePath -ChildPath "$($addon.Name).xpi"
                    Invoke-WebRequest -Uri $addon.Value -OutFile $addonPath
                }
        
                # Download and apply user configurations
                $configUrls = @{
                    "user.js"          = "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/user.js"
                    "Tab Shapes.css"   = "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/Tab%20Shapes.css"
                    "Toolbar.css"      = "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/userChrome.css"
                    "userContent.css"  = "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/userContent.css"
                    "userChrome.css"   = "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/userChrome.css"
                }
        
                $chromeDir = New-Item -Path (Join-Path -Path $profilePath -ChildPath "chrome") -ItemType "directory" -Force
        
                foreach ($config in $configUrls.GetEnumerator()) {
                    $configPath = Join-Path -Path $chromeDir -ChildPath $config.Key
                    Invoke-WebRequest -Uri $config.Value -OutFile $configPath
                }
        
                Write-Host " [DONE]" -ForegroundColor Green -BackgroundColor Black
            } catch {
                Write-Host " [WARNING]: $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        Install-LibreWolfAddIn
                
        #sublime text
        function Set-Configs {
            Write-Host "Setting my configs..." -NoNewline
            # Helper function to create directories
            function Ensure-Directory($path) {
                try {
                    if (-Not (Test-Path $path)) {
                        New-Item -Path $path -ItemType "directory" | Out-Null
                    }
                } catch {
                    Write-Host " [WARNING] Failed to create directory at path: $path. Error: $_" -ForegroundColor Red -BackgroundColor Black
                }
            }
        
            # Helper function for web requests
            function Safe-Invoke-WebRequest($uri, $outFile) {
                try {
                    Invoke-WebRequest -Uri $uri -Outfile $outFile
                } catch {
                    Write-Host " [WARNING] Failed to download from: $uri. Error: $_" -ForegroundColor Red -BackgroundColor Black
                }
            }
        
            # Define directories and files to be downloaded
            $downloads = @{
                    "$env:userprofile\AppData\Roaming\Sublime Text\Packages\User" = @(
                        "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/sublime-text/Preferences.sublime-settings",
                        "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/sublime-text/cy.sublime-color-scheme",
                        "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/sublime-text/Default%20(Windows).sublime-mousemap"
                    )
                    "$env:userprofile\AppData\Roaming\Sublime Text\Installed Packages" = @(
                        "https://packagecontrol.io/Package%20Control.sublime-package"
                    )
                    "$env:UserProfile\Documents\PowerToys\Backup" = @(
                        "https://github.com/caglaryalcin/after-format/raw/main/files/own/settings_133264013067260668.ptb"
                    )
                    "$env:userprofile\Desktop" = @(
                        "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/extensions/ublock.txt",
                        "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/extensions/bookmarks.json",
                        "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/extensions/ublacklist.txt"
                    )
                    "C:\fan_control\Configurations" = @(
                        "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/my_fan_config.json"
                    )
                    "$env:USERPROFILE\Appdata\Roaming\Openrgb" = @(
                        "https://github.com/caglaryalcin/my-configs/raw/main/my_led_config.orp"
                    )
                }
        
            # Process each directory and download files
            foreach ($dir in $downloads.Keys) {
                Ensure-Directory -path $dir
                foreach ($url in $downloads[$dir]) {
                    $fileName = [System.IO.Path]::GetFileName((Convert-Path -URI $url))
                    $outFile = Join-Path -Path $dir -ChildPath $fileName
                    Safe-Invoke-WebRequest -uri $url -outFile $outFile
                }
            }
        
            # Additional configurations
            try {
                New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "electron.app.Twinkle Tray" -PropertyType String -Value "$env:userprofile\AppData\Local\Programs\twinkle-tray\Twinkle Tray.exe" | Out-Null
                New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowDevMgrUpdates" -PropertyType DWORD -Value "0" | Out-Null
                New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -PropertyType DWORD -Value "0" | Out-Null
                New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMDevicesEnumerationEnabled" -Value 0 | Out-Null
                New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableDeviceEnumeration" -PropertyType DWORD -Value 1 | Out-Null
            } catch {
                Write-Host " [WARNING] Failed in additional configurations. Error: $_" -ForegroundColor Red -BackgroundColor Black
            }
        
            # Monitor settings prompt
            try {
                 Start-Process "rundll32.exe" -ArgumentList "display.dll, ShowAdapterSettings 0" -NoNewWindow -Wait
                Start-Process "rundll32.exe" -ArgumentList "display.dll, ShowAdapterSettings 1" -NoNewWindow -Wait
            } catch {
                Write-Host " [WARNING] Failed to set monitor settings. Error: $_" -ForegroundColor Red -BackgroundColor Black
            }
        
            # Import Cloudflare certificate
            try {
                $certPath = "C:\Cloudflare_CA.crt"
                Invoke-WebRequest -Uri "https://developers.cloudflare.com/cloudflare-one/static/documentation/connections/Cloudflare_CA.crt" -Outfile $certPath
                Import-Certificate -FilePath $certPath -CertStoreLocation "cert:\LocalMachine\Root" | Out-Null
                Remove-Item -Path $certPath -Force
            } catch {
                Write-Host " [WARNING] Failed to import Cloudflare certificate. Error: $_" -ForegroundColor Red -BackgroundColor Black
            }
        
            Write-Host " [DONE]" -ForegroundColor Green -BackgroundColor Black
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
                    
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host " [DONE]" -ForegroundColor Green -BackgroundColor Black
                    }
                    else {
                        throw "DISM exited with code $LASTEXITCODE. Message: $installResult"
                    }
                }
                else {
                    throw "Media Feature Pack capability not found."
                }
            }
            catch {
                Write-Host " [WARNING] Failed. Error: $_" -ForegroundColor Red
            }
        }
        
        MediaFeaturePack
        
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