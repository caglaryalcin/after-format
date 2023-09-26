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
            $Opera = "$env:USERPROFILE\AppData\Local\Programs\Opera\launcher.exe"
            $OperaDirectory = "$env:USERPROFILE\AppData\Local\Local\Programs\Opera"
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
            $Crystal = "C:\Program Files\CrystalDiskInfo\DiskInfo64.exe"
            $CrystalDirectory = "C:\Program Files\CrystalDiskInfo"
            $Shortcut.WorkingDirectory = "C:\Program Files\CrystalDiskInfo"
            $ShortcutFile = "C:\icons\CrystalDiskInfo (64bit).lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $Crystal
            $Shortcut.WorkingDirectory = $CrystalDirectory
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\CrystalDiskInfo (64bit).lnk" *>$null

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
            $Visual = "$env:USERPROFILE\AppData\Local\Programs\Microsoft VS Code\Code.exe"
            $ShortcutFile = "C:\icons\Visual Studio Code.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $Visual
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\Visual Studio Code.lnk" *>$null

            #AnyDesk
            $WScriptShell = New-Object -ComObject WScript.Shell
            $Anydesk = "C:\Program Files (x86)\AnyDesk\AnyDesk.exe"
            $AnydeskPath = "C:\Program Files (x86)\AnyDesk"
            $ShortcutFile = "C:\icons\AnyDesk.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $Anydesk
            $Shortcut.WorkingDirectory = $AnydeskPath
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\AnyDesk.lnk" *>$null

            #Terminal was here

            #SublimeText
            $WScriptShell = New-Object -ComObject WScript.Shell
            $SublimeText = "C:\Program Files\Sublime Text\sublime_text.exe"
            $SublimeTextPath = "C:\Program Files\Sublime Text\"
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

            #VLC
            $WScriptShell = New-Object -ComObject WScript.Shell
            $VLC = "C:\Program Files\VideoLAN\VLC\vlc.exe"
            $ShortcutFile = "C:\icons\VLC media player.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $VLC
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\VLC media player.lnk" *>$null

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
            $ShortcutFile = "C:\icons\Putty.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $Putty
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
            $DBeaver = "$env:USERPROFILE\AppData\Local\DBeaver\dbeaver.exe"
            $DBeaverPath = "$env:USERPROFILE\AppData\Local\DBeaver"
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
            $Powertoys = "$env:USERPROFILE\AppData\Local\PowerToys\PowerToys.exe"
            $PowertoysPath = "$env:USERPROFILE\AppData\Local\PowerToys\Settings"
            $ShortcutFile = "C:\icons\PowerToys.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $Powertoys
            $Shortcut.WorkingDirectory = $PowertoysPath
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\PowerToys.lnk" *>$null

            #dupeGuru
            $WScriptShell = New-Object -ComObject WScript.Shell
            $dupeGuru = "$env:USERPROFILE\AppData\Local\Programs\Hardcoded Software\dupeGuru\dupeguru-win64.exe"
            $dupeGuruPath = "$env:USERPROFILE\AppData\Local\Programs\Hardcoded Software\dupeGuru"
            $ShortcutFile = "C:\icons\dupeGuru.lnk"
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $dupeGuru
            $Shortcut.WorkingDirectory = $dupeGuruPath
            $Shortcut.Save()
            Unblock-File -Path "C:\icons\dupeGuru.lnk" *>$null

            #Set Pin
            $progressPreference = 'silentlyContinue'
            Get-ChildItem $env:USERPROFILE\Desktop\* | ForEach-Object { Remove-Item $_ }
            Get-ChildItem C:\users\Public\Desktop\*.lnk | ForEach-Object { Remove-Item $_ }
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/caglaryalcin/post-wpe-w10/main/files/own/taskbar_pin.reg" -Outfile C:\taskbar_pin.reg
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
            Write-Host "Installing Chipset Driver..." -NoNewline
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

        #restore browser settings and extensions
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

            $bitwarden = "https://addons.mozilla.org/firefox/downloads/file/4093799/bitwarden_password_manager-2023.3.1.xpi"
            $bitwardenuid = '{446900e4-71c2-419f-a6a7-df9c091e268b}'
            $ublockorigin = "https://addons.mozilla.org/firefox/downloads/file/4099143/ublock_origin-1.49.0.xpi"
            $ublockoriginuid = 'uBlock0@raymondhill.net'
            $privacybadger = "https://addons.mozilla.org/firefox/downloads/file/4064595/privacy_badger17-2023.1.31.xpi"
            $privacybadgeruid = 'jid1-MnnxcxisBPnSXQ@jetpack'
            $darkreader = "https://addons.mozilla.org/firefox/downloads/file/4095037/darkreader-4.9.63.xpi"
            $darkreaderuid = 'addon@darkreader.org'
            $ublacklist = "https://addons.mozilla.org/firefox/downloads/file/4095141/ublacklist-8.3.0.xpi"
            $ublacklistuid = '@ublacklist'
            $returnytdl = 'https://addons.mozilla.org/firefox/downloads/file/4072734/return_youtube_dislikes-3.0.0.8.xpi'
            $returnytdluid = '{762f9885-5a13-4abd-9c77-433dcd38b8fd}'
            $idm = 'https://addons.mozilla.org/firefox/downloads/file/4083976/tonec_idm_integration_module-6.41.8.xpi'
            $idmuid = 'mozilla_cc3@internetdownloadmanager.com'
           
            $bitwardenpath = $extensions + '\' + $bitwardenuid + '.xpi'
            $ublockoriginpath = $extensions + '\' + $ublockoriginuid + '.xpi'
            $privacybadgerpath = $extensions + '\' + $privacybadgeruid + '.xpi'
            $darkreaderpath = $extensions + '\' + $darkreaderuid + '.xpi'
            $ublacklistpath = $extensions + '\' + $ublacklistuid + '.xpi'
            $returnytdlpath = $extensions + '\' + $returnytdluid + '.xpi'
            $idmpath = $extensions + '\' + $idmuid + '.xpi'

            #Download XPI file of AddIn
            If (-Not(Test-Path $distribution)) {
                New-Item $distribution -ItemType Container | Out-Null
            }
            If (-Not(Test-Path $extensions)) {
                New-Item $extensions -ItemType Container | Out-Null
            }
    
            Invoke-WebRequest $bitwarden -Outfile $bitwardenpath
            Invoke-WebRequest $ublockorigin -Outfile $ublockoriginpath
            Invoke-WebRequest $privacybadger -Outfile $privacybadgerpath
            Invoke-WebRequest $darkreader -Outfile $darkreaderpath
            Invoke-WebRequest $ublacklist -Outfile $ublacklistpath
            Invoke-WebRequest $returnytdl -Outfile $returnytdlpath
            Invoke-WebRequest $idm -Outfile $idmpath

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
                
        #sublime text
        Function configs {
            ##sublimetext
            $userconf = "$env:userprofile\AppData\Roaming\Sublime Text\Packages\User"
            $userpackage = "$env:userprofile\AppData\Roaming\Sublime Text\Installed Packages"

            #create directory
            New-Item $userconf -ItemType "directory" *>$null
            New-Item $userpackage -ItemType "directory" *>$null

            #settings and theme
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/sublime-text/Preferences.sublime-settings" -Outfile "$userconf\Preferences.sublime-settings"
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/sublime-text/cy.sublime-color-scheme" -Outfile "$userconf\cy.sublime-color-scheme"
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/sublime-text/Default%20(Windows).sublime-mousemap" -Outfile "$userconf\Default (Windows).sublime-mousemap"

            #packages
            Invoke-WebRequest -Uri "https://packagecontrol.io/Package%20Control.sublime-package" -Outfile "$userpackage\Package Control.sublime-package"

            #powertoys backup
            New-Item -Path "$env:UserProfile\Documents\" -Name "PowerToys" -ItemType "directory" *>$null
            New-Item -Path "$env:UserProfile\Documents\PowerToys\" -Name "Backup" -ItemType "directory" *>$null
            $powertoysbackup = "$env:UserProfile\Documents\PowerToys\Backup\settings_133264013067260668.ptb"
            Invoke-WebRequest -Uri "https://github.com/caglaryalcin/post-wpe-w10/raw/main/files/own/settings_133264013067260668.ptb" -Outfile $powertoysbackup

            #startup twinkle tray
            New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "electron.app.Twinkle Tray" -PropertyType String -Value "$env:userprofile\AppData\Local\Programs\twinkle-tray\Twinkle Tray.exe" *>$null
                
            #sound Settings
            Write-Host "`nSetting sound devices..." -NoNewline
            New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowDevMgrUpdates" -PropertyType DWORD -Value "0" *>$null
            New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -PropertyType DWORD -Value "0" *>$null
            New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMDevicesEnumerationEnabled" -Value 0 *>$null
            New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableDeviceEnumeration" -PropertyType DWORD -Value 1 *>$null

            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black

            #set monitor hertz
            Write-Host "Select the hertz rate of monitors..." -NoNewline
            Write-Host "(It doesn't continue without a choice)" -ForegroundColor Red -NoNewline -BackgroundColor Black
            cmd.exe /c "rundll32.exe display.dll, ShowAdapterSettings 0" -NoNewWindow -Wait
            cmd.exe /c "rundll32.exe display.dll, ShowAdapterSettings 1" -NoNewWindow -Wait
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black

            #import cloudflare certificates
            Invoke-WebRequest -Uri "https://developers.cloudflare.com/cloudflare-one/static/documentation/connections/Cloudflare_CA.crt" -Outfile C:\Cloudflare_CA.crt *>$null
            Get-Item "C:\Cloudflare_CA.crt" | Import-Certificate -CertStoreLocation "cert:\LocalMachine\Root" *>$null
            Remove-Item C:\Cloudflare_CA.crt -recurse -ErrorAction SilentlyContinue

            #download configs to desktop
            curl -o $env:userprofile\Desktop\uBlock.txt https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/extensions/ublock.txt
            curl -o $env:userprofile\Desktop\bookmarks.json https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/extensions/bookmarks.json

        }

        configs
        function MediaFeaturePack {
            # check new version
            $newVersion = (DISM /Online /Get-Capabilities | Select-String 'Media.MediaFeaturePack~~~~').ToString().Trim()
            $newVersion = $newVersion -replace 'Capability Identity : ', '' -replace '\s', ''
                
            cmd.exe /c DISM /Online /Add-Capability /CapabilityName:$newVersion /Quiet /NoRestart
                
            Write-Host "Update completed."
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