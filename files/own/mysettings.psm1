
$myText = @"
+---------------------------------------------+
|                                             |
|               DO NOT ACCEPT                 |
|                                             |
+---------------------------------------------+
"@

Write-Host `n$myText -ForegroundColor Red

Write-Host `n"Do you " -NoNewline
Write-Host "own this script?" -NoNewline -ForegroundColor Red -BackgroundColor Black
Write-Host "(Settings, downloads and installations of the script owner will be made):" -NoNewline -ForegroundColor Red -BackgroundColor Black
Write-Host "(y/n): " -NoNewline
$response = Read-Host

if ($response -eq 'y' -or $response -eq 'Y') {

    Function Own {

        # FanControl
        Function InstallFanControl {
            try {
                $OriginalProgressPreference = $Global:ProgressPreference
                $Global:ProgressPreference = 'SilentlyContinue'
        
                Invoke-WebRequest -Uri "https://github.com/Rem0o/FanControl.Releases/blob/master/FanControl.zip?raw=true" -Outfile "C:\fan_control.zip" *>$null
        
                $OriginalProgressPreference = $Global:ProgressPreference
                $Global:ProgressPreference = 'SilentlyContinue'
        
                Expand-Archive -Path "C:\fan_control.zip" -DestinationPath "C:\fan_control\" -Force *>$null
        
                Remove-Item "C:\fan_control.zip" -Recurse -ErrorAction SilentlyContinue
        
                Start-Process "C:\fan_control\FanControl.exe" -PassThru *>$null
        
                taskkill /f /im FanControl.exe *>$null
            }
            catch {
                Write-Host "[WARNING]:: There was an error loading FanControl. $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        InstallFanControl
		
        # SetPins
        Function SetPins {
            ##Create Icons folder
            New-Item -Path 'C:\icons' -ItemType Directory *>$null

            # CreateShortcut function
            function CreateShortcut([string]$exePath, [string]$shortcutPath, [string]$workingDirectory = $null, [string]$arguments = $null) {
                $WScriptShell = New-Object -ComObject WScript.Shell
                $Shortcut = $WScriptShell.CreateShortcut($shortcutPath)
                $Shortcut.TargetPath = $exePath
                if ($workingDirectory) {
                    $Shortcut.WorkingDirectory = $workingDirectory
                }
                if ($arguments) {
                    $Shortcut.Arguments = $arguments
                }
                $Shortcut.Save()
                Unblock-File -Path $shortcutPath *>$null
            }

            # CreateShortcuts function
            Function CreateShortcuts {
                $shortcutPaths = @{
                    "Google Chrome"           = @{
                        "Path"             = "C:\Program Files\Google\Chrome\Application\chrome.exe";
                        "WorkingDirectory" = "C:\Program Files\Google\Chrome\Application\";
                    };
                    "Brave"                   = @{
                        "Path"             = "$env:USERPROFILE\AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe";
                        "WorkingDirectory" = "$env:USERPROFILE\AppData\Local\BraveSoftware\Brave-Browser\Application";
                    };
                    "Firefox"                 = @{
                        "Path"             = "C:\Program Files\Mozilla Firefox\firefox.exe";
                        "WorkingDirectory" = "C:\Program Files\Mozilla Firefox\";
                    };
                    "Steam"                   = @{
                        "Path"             = "C:\Program Files (x86)\Steam\Steam.exe";
                        "WorkingDirectory" = "C:\Program Files (x86)\Steam\";
                    };
                    "Epic Games Launcher"     = @{
                        "Path"             = "C:\Program Files (x86)\Epic Games\Launcher\Portal\Binaries\Win32\EpicGamesLauncher.exe";
                        "WorkingDirectory" = "C:\Program Files (x86)\Epic Games\";
                    };
                    "HWMonitor"               = @{
                        "Path"             = "C:\Program Files\CPUID\HWMonitor\HWMonitor.exe";
                        "WorkingDirectory" = "C:\Program Files\CPUID\HWMonitor\";
                    };
                    "CrystalDiskInfo"         = @{
                        "Path"             = "C:\ProgramData\chocolatey\lib\crystaldiskinfo.portable\tools\DiskInfo64.exe";
                        "WorkingDirectory" = "C:\ProgramData\chocolatey\lib\crystaldiskinfo.portable\tools\";
                    };
                    "VMware Workstation Pro"  = @{
                        "Path"             = "C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe";
                        "WorkingDirectory" = "C:\Program Files (x86)\VMware\VMware Workstation\";
                    };
                    "Signal"                  = @{
                        "Path"             = "$env:USERPROFILE\AppData\Local\Programs\signal-desktop\Signal.exe";
                        "WorkingDirectory" = "$env:USERPROFILE\AppData\Local\Programs\signal-desktop\";
                    };
                    "Visual Studio Code"      = @{
                        "Path"             = "C:\Program Files\Microsoft VS Code\Code.exe";
                        "WorkingDirectory" = "C:\Program Files\Microsoft VS Code\";
                    };
                    "Notepad++"               = @{
                        "Path"             = "C:\Program Files\Notepad++\notepad++.exe";
                        "WorkingDirectory" = "C:\Program Files\Notepad++\";
                    };
                    "AnyDesk"                 = @{
                        "Path"             = "C:\ProgramData\chocolatey\lib\anydesk.portable\tools\AnyDesk.exe";
                        "WorkingDirectory" = "C:\ProgramData\chocolatey\lib\anydesk.portable\tools\";
                    };
                    "GitHub Desktop"          = @{
                        "Path"             = "$env:USERPROFILE\AppData\Local\GitHubDesktop\GitHubDesktop.exe";
                        "WorkingDirectory" = "$env:USERPROFILE\AppData\Local\GitHubDesktop\";
                    };
                    "TreeSizeFree"            = @{
                        "Path"             = "C:\Program Files\JAM Software\TreeSize Free\TreeSizeFree.exe";
                        "WorkingDirectory" = "C:\Program Files\JAM Software\TreeSize Free";
                    };
                    "Total Commander 64 bit"  = @{
                        "Path"             = "C:\Program Files\totalcmd\TOTALCMD64.EXE";
                        "WorkingDirectory" = "";
                    };
                    "WireShark"               = @{
                        "Path"             = "C:\Program Files\Wireshark\Wireshark.exe";
                        "WorkingDirectory" = "C:\Program Files\Wireshark\";
                    };
                    "Cryptomator"             = @{
                        "Path"             = "C:\Program Files\Cryptomator\Cryptomator.exe";
                        "WorkingDirectory" = "C:\Program Files\Cryptomator\";
                    };
                    "OpenRGB"                 = @{
                        "Path"             = "C:\ProgramData\chocolatey\lib\openrgb\tools\OpenRGB Windows 64-bit\OpenRGB.exe";
                        "WorkingDirectory" = "C:\ProgramData\chocolatey\lib\openrgb\tools\OpenRGB Windows 64-bit\";
                    };
                    "FanControl"              = @{
                        "Path"             = "C:\fan_control\FanControl.exe";
                        "WorkingDirectory" = "C:\fan_control\";
                    };
                    "Microsoft Teams classic" = @{
                        "Path"             = "$env:USERPROFILE\AppData\Local\Microsoft\Teams\Update.exe";
                        "Arguments"        = "--processStart Teams.exe";
                        "WorkingDirectory" = "$env:USERPROFILE\AppData\Local\Microsoft\Teams\";
                    };
                    "Google Play Games" = @{
                        "Path"             = "C:\Program Files\Google\Play Games\current\client\client.exe";
                        "WorkingDirectory" = "C:\Program Files\Google\Play Games\current\client";
                    };
                }

                foreach ($name in $shortcutPaths.Keys) {
                    $path = $shortcutPaths[$name].Path
                    $workingDirectory = $shortcutPaths[$name].WorkingDirectory
                    $arguments = $shortcutPaths[$name].Arguments
                    $shortcutFile = "C:\icons\$name.lnk"

                    CreateShortcut -exePath $path -shortcutPath $shortcutFile -workingDirectory $workingDirectory -arguments $arguments
                }
            }

            CreateShortcuts

            # Copy fan control to startup folder
            try {
                Copy-Item "C:\icons\FanControl.lnk" "$env:USERPROFILE\Appdata\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\FanControl.lnk" -Force
            }
            catch {
                Write-Host "[WARNING]: Error copying FanControl to startup folder. $_" -ForegroundColor Red
            }
            
            # Delete all files on desktop
            try {
                Get-ChildItem "$env:USERPROFILE\Desktop\*" | ForEach-Object { Remove-Item $_ -ErrorAction Stop }
                Get-ChildItem "C:\users\Public\Desktop\*.lnk" | ForEach-Object { Remove-Item $_ -ErrorAction Stop }
            }
            catch {
                Write-Host "[WARNING]: Error deleting all files on the desktop. $_" -ForegroundColor Red
            }
            

            # Remove Brave and Firefox shortcuts from taskbar
            $braveShortcut = "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Brave.lnk"
            $firefoxShortcut = "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Firefox.lnk"

            try {
                if (Test-Path $braveShortcut) {
                    Remove-Item -Path $braveShortcut -ErrorAction Stop
                }
            
                if (Test-Path $firefoxShortcut) {
                    Remove-Item -Path $firefoxShortcut -ErrorAction Stop
                }
            }
            catch {
                Write-Host "[WARNING]: Unable to delete Brave and Firefox shortcut from taskbar. $_" -ForegroundColor Red
            }
            
            # Remove registry path of all taskbar icons
            try {
                Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Recurse -Force -ErrorAction Stop
            }
            catch {
                Write-Host "[WARNING]: Error removing the registry path of taskbar icons. $_" -ForegroundColor Red
            }
            

            # Set taskbar icons and pin to taskbar
            try {
                # Download the registry file
                $progressPreference = 'SilentlyContinue'
                Invoke-WebRequest -Uri "https://raw.githubusercontent.com/caglaryalcin/after-format/main/files/own/taskbar_pin.reg" -Outfile "C:\taskbar_pin.reg" -ErrorAction Stop
                
                # Import the registry file
                reg import "C:\taskbar_pin.reg" *>$null
            
                # Copy the icons to the taskbar
                Copy-Item -Path "C:\icons\*" -Destination "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\" -Force -ErrorAction Stop
            
                # Apply the registry file import again
                reg import "C:\taskbar_pin.reg" *>$null
            
                # Restart explorer
                taskkill /f /im explorer.exe *>$null
                Start-Process explorer.exe *>$null 
            }
            catch {
                Write-Host "[WARNING]: Error while importing and setting taskbar icons. $_" -ForegroundColor Red
            }

            # Set taskbar right side layout
            try {
                $progressPreference = 'SilentlyContinue'
                Invoke-WebRequest -Uri "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/win/taskbar-rightside-layout.reg" -Outfile "C:\taskbar-rightside-layout.reg" -ErrorAction Stop

                # Import the registry file
                reg import "C:\taskbar-rightside-layout.reg" *>$null

                Start-Sleep 2

                # Apply the registry file import again
                reg import "C:\taskbar-rightside-layout.reg" *>$null

                # Restart explorer
                taskkill /f /im explorer.exe *>$null
            }
            catch {
                Write-Host "[WARNING]: Error while importing and setting taskbar icons. $_" -ForegroundColor Red
            }

            # Delete registry file and icons folder
            try {
                Remove-Item "C:\taskbar_pin.reg" -Recurse -ErrorAction Stop
                Remove-Item "C:\taskbar-rightside-layout.reg" -Recurse -ErrorAction Stop
                Start-Sleep 1

                Start-Process "explorer.exe" -ErrorAction Stop
                Start-Sleep 2

                Remove-Item "C:\icons\" -Recurse -ErrorAction Stop
            }
            catch {
                Write-Host "[WARNING]: Error deleting registry file and icons folder. $_" -ForegroundColor Red
            }
            
        }

        SetPins

        # Drivers
        Function Drivers {
            # Chipset
            Write-Host "`nInstalling Chipset Drivers..." -NoNewline
            try {
                # Download the Chipset driver files
                $OriginalProgressPreference = $Global:ProgressPreference
                $Global:ProgressPreference = 'SilentlyContinue'
                $ChipsetUri = "https://dlcdnets.asus.com/pub/ASUS/mb/03CHIPSET/DRV_Chipset_Intel_CML_TP_W10_64_V101182958201_20200423R.zip"
                $ChipsetEngineUri = "https://dlcdnets.asus.com/pub/ASUS/mb/03CHIPSET/DRV_MEI_Intel_Cons_19H1_TP_W10_64_VER19141201256_20191104R.zip"
                Invoke-WebRequest -Uri $ChipsetUri -OutFile "C:\Chipset.zip" -ErrorAction Stop
                Invoke-WebRequest -Uri $ChipsetEngineUri -OutFile "C:\ChipsetEngine.zip" -ErrorAction Stop
            
                # Extract the driver files
                $OriginalProgressPreference = $Global:ProgressPreference
                $Global:ProgressPreference = 'SilentlyContinue'
                Expand-Archive -Path "C:\Chipset.zip" -DestinationPath "C:\Chipset\" -Force -ErrorAction Stop
                Expand-Archive -Path "C:\ChipsetEngine.zip" -DestinationPath "C:\ChipsetEngine\" -Force -ErrorAction Stop

                # Run the Chipset drivers installer
                $OriginalProgressPreference = $Global:ProgressPreference
                $Global:ProgressPreference = 'SilentlyContinue'
                Start-Process -FilePath "cmd.exe" -ArgumentList "/c cd C:\Chipset && SetupChipset.exe" -NoNewWindow -Wait
                #Start-Process "C:\ChipsetEngine\SetupChipset.exe" -ArgumentList "-s" -NoNewWindow -Wait -ErrorAction Stop #force restart

                # Run the Chipset Engine driver installer
                Start-Process "C:\ChipsetEngine\SetupME.exe" -ArgumentList "-s" -NoNewWindow -Wait -ErrorAction Stop
            
                # Delete the driver files
                Start-Sleep 4
                Remove-Item "C:\Chipset.zip" -Recurse -ErrorAction SilentlyContinue
                Start-Sleep 1
                Remove-Item "C:\ChipsetEngine.zip" -Recurse -ErrorAction SilentlyContinue
                Start-Sleep 1
                Remove-Item "C:\Chipset" -Recurse -ErrorAction SilentlyContinue
                Start-Sleep 1
                Remove-Item "C:\ChipsetEngine" -Recurse -ErrorAction SilentlyContinue
            
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: Error installing Chipset drivers. $_" -ForegroundColor Red -BackgroundColor Black
            }

            # LAN
            Write-Host "Installing LAN Driver..." -NoNewline
            try {
                # Download the driver file
                $OriginalProgressPreference = $Global:ProgressPreference
                $Global:ProgressPreference = 'SilentlyContinue'
                Invoke-WebRequest -Uri "https://dlcdnets.asus.com/pub/ASUS/mb/04LAN/DRV_LAN_Intel_I219_UWD_TP_W10_64_V1219137_20210830R.zip" -OutFile "C:\LAN.zip" -ErrorAction Stop
            
                # Extract the driver files
                $OriginalProgressPreference = $Global:ProgressPreference
                $Global:ProgressPreference = 'SilentlyContinue'
                Expand-Archive -Path "C:\LAN.zip" -DestinationPath "C:\LAN\" -Force -ErrorAction Stop

                # Run the driver installer
                $OriginalProgressPreference = $Global:ProgressPreference
                $Global:ProgressPreference = 'SilentlyContinue'
                Invoke-Expression -Command "cd C:\LAN ; .\Install.bat" *>$null
            
                # Delete the driver files
                Start-Sleep 4
                Remove-Item "C:\LAN.zip" -Recurse -ErrorAction SilentlyContinue
                cd c:\
                Remove-Item "C:\LAN" -Recurse -Force -ErrorAction SilentlyContinue
            
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: Error installing LAN driver. $_" -ForegroundColor Red -BackgroundColor Black
            }

            # NVIDIA Driver installation
            Write-Host "Installing Nvidia Driver..." -NoNewline
            try {
                # Run NVCleanInstaller and wait for it to finish
                Start-Process "C:\Program Files\NVCleanstall\NVCleanstall.exe" -NoNewWindow -Wait | Out-Null *>$null
				
                # Alternative method to download Nvidia driver
                <#
                #NVIDIA API
                $Parameters = @{
                    Uri             = "https://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=3"
                    UseBasicParsing = $true
                }

                #version parameters
                [xml]$Content = (Invoke-WebRequest @Parameters).Content
                $CardModelName = (Get-CimInstance -ClassName CIM_VideoController | Where-Object -FilterScript { $_.AdapterDACType -ne "Internal" }).Caption.Split(" ")
                # Remove the first word in full model name. E.g. "NVIDIA"
                $CardModelName = [string]$CardModelName[1..($CardModelName.Count)]
                $ParentID = ($Content.LookupValueSearch.LookupValues.LookupValue | Where-Object -FilterScript { $_.Name -contains $CardModelName }).ParentID | Select-Object -First 1
                $Value = ($Content.LookupValueSearch.LookupValues.LookupValue | Where-Object -FilterScript { $_.Name -contains $CardModelName }).Value | Select-Object -First 1

                #set download url
                $Parameters = @{
                    Uri             = "https://gfwsl.geforce.com/services_toolkit/services/com/nvidia/services/AjaxDriverService.php?func=DriverManualLookup&psid=$ParentID&pfid=$Value&osID=57&languageCode=1033&beta=null&isWHQL=1&dltype=-1&dch=1&upCRD=0"
                    UseBasicParsing = $true
                }

                $Data = Invoke-RestMethod @Parameters

                $LatestVersion = $Data.IDS.downloadInfo.Version	

                $Parameters = @{
                    Uri             = $Data.IDS.downloadInfo.DownloadURL
                    OutFile         = "$env:USERPROFILE\Downloads\$LatestVersion-desktop-win10-win11-64bit-international-dch-whql.exe"
                    UseBasicParsing = $true
                    Verbose         = $true
                }

                #download lastest version
                $OriginalProgressPreference = $Global:ProgressPreference
                $Global:ProgressPreference = 'SilentlyContinue'
                Invoke-WebRequest @Parameters *>$null
                #>

                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                # If an error occurred during installation, output a warning
                Write-Host "[WARNING]:: Error installing Nvidia driver.." -ForegroundColor Red -BackgroundColor Black
            }
        }
                
        Drivers

        # MyConfigs
        Function Set-Configs {
            Write-Host "Setting my configs..." -NoNewline

            # Helper function to create directories
            Function Ensure-Directory($path) {
                try {
                    # Force creates the directory if it doesn't exist
                    New-Item -ItemType Directory -Force -Path $path | Out-Null
                }
                catch {
                    Write-Host " [WARNING]: Failed to create directory at path: $path. Error: $_" -ForegroundColor Red -BackgroundColor Black
                }
            }            

            # Helper function for web requests
            function Safe-Invoke-WebRequest($uri, $outFile) {
                try {
                    Invoke-WebRequest -Uri $uri -Outfile $outFile
                }
                catch {
                    Write-Host " [WARNING]: Failed to download from: $uri. Error: $_" -ForegroundColor Red -BackgroundColor Black
                }
            }
            
            # Stop all SteelSeries processes
            Get-Process | Where-Object { $_.Name -like "steel*" } | ForEach-Object { Stop-Process -Name $_.Name -Force }

            # Define config directories and files to download
            $OriginalProgressPreference = $Global:ProgressPreference
            $Global:ProgressPreference = 'SilentlyContinue'
            $downloads = @{
                # notepad++
                "$env:USERPROFILE\Appdata\Roaming\Notepad++\themes"                                          = @(
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/notepad%2B%2B/VS2018-Dark_plus.xml"
                )
                "$env:USERPROFILE\Appdata\Roaming\Notepad++\"                                                = @(
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/notepad%2B%2B/config.xml"
                )
            
                # fan control
                "C:\fan_control\Configurations"                                                              = @(
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/fan/my_fan_config.json"
                )
            
                # openrgb
                "$env:USERPROFILE\Appdata\Roaming\Openrgb"                                                   = @(
                    "https://github.com/caglaryalcin/my-configs/raw/main/led/my_led_config.orp"
                )
            
                # keyboard
                "C:\ProgramData\SteelSeries\"                                                                = @(
                    "https://github.com/caglaryalcin/my-configs/raw/main/keyboard/GG.zip"
                )

                # terminal
                "$env:USERPROFILE\AppData\Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState" = @(
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/win/terminal/settings.json"
                )

                # taskmanager
                "$env:USERPROFILE\AppData\Local\Microsoft\Windows\TaskManager"                               = @(
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/win/taskmgr/settings.json"
                )

                # cs2, twinkle tray, explorer patcher, nvidia profile
                "$env:userprofile\Desktop"                                                                   = @(
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/cs2/cs.cfg",
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/cs2/cs2_video.txt",
                    #"https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/extensions/ublock.txt", #in cloud
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/win/ExplorerPatcher.reg",
                    "https://github.com/caglaryalcin/my-configs/raw/main/nvidia/Base-Profile.nip",
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/win/display/display-layout.reg"
                )

                # twinkle tray
                "$env:userprofile\AppData\Roaming\twinkle-tray"                                              = @(
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/twinkle-tray/settings.json"
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

            # Run Nvidia Profile Inspector for importing the base profile
            try {
                $OriginalProgressPreference = $Global:ProgressPreference
                $Global:ProgressPreference = 'SilentlyContinue'
                Start-Process "C:\ProgramData\chocolatey\lib\nvidia-profile-inspector\tools\nvidiaProfileInspector.exe" -NoNewWindow -Wait | Out-Null *>$null
                Start-Sleep 2
                Remove-Item "$env:userprofile\Desktop\Base-Profile.nip" -Recurse -ErrorAction SilentlyContinue
            }
            catch {
                Write-Host " [WARNING]: Failed to run Nvidia Profile Inspector. Error: $_" -ForegroundColor Red -BackgroundColor Black
            }

            # Download ublacklist config file to desktop
            "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/extensions/ublacklist.txt" | Out-File -FilePath "$env:userprofile\Desktop\ublacklist.txt"

            # Create a batch file to move the cs2 video and cs.cfg files to the correct directories
            $filecontent = @'
$soru = "CS2 kuruldu mu? (E/H)"
$cevap = Read-Host -Prompt $soru

if ($cevap -eq "E" -or $cevap -eq "e") {
    Write-Host "CS konfigleri gonderiliyor.." -NoNewline
    $destpath = "C:\Program Files (x86)\Steam\userdata\"
    Set-Location -Path $destpath
    Get-ChildItem -Directory | ForEach-Object {
        Push-Location $_.FullName
    }
    Set-Location -Path ".\730"
    $localFolderPath = Join-Path -Path (Get-Location) -ChildPath "local"
    if (-not (Test-Path -Path $localFolderPath)) {
        New-Item -Name "local\cfg" -ItemType Directory | Out-Null
    }
    Set-Location -Path ".\local\cfg"
    $cs2configpath = "C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game\csgo\cfg"
    Move-Item -Path $env:userprofile\Desktop\cs.cfg -Destination $cs2configpath -Force
    Move-Item -Path $env:userprofile\Desktop\cs2_video.txt -Destination (Get-Location) -Force
    cd c:\
    Remove-Item "$env:userprofile\Desktop\cs-script.ps1" -Force -ErrorAction Stop
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}
elseif ($cevap -eq "H" -or $cevap -eq "h") {
    Write-Host "Once CS2 kurulumu yapin."
}
else {
    Write-Host "Gecersiz cevap. Sadece Evet (E) veya Hayir (H) yazin."
}
'@

            $filecontent | Out-File -FilePath "$env:userprofile\Desktop\cs-script.ps1" -Encoding UTF8

            # Restore SteelSeries keyboard settings
            try {
                # Restore SteelSeries keyboard settings
                $OriginalProgressPreference = $Global:ProgressPreference
                $Global:ProgressPreference = 'SilentlyContinue'
            
                # Expand the zip file
                Expand-Archive -Path 'C:\programdata\SteelSeries\GG.zip' -DestinationPath 'C:\programdata\SteelSeries\' -Force -ErrorAction Stop
            
                # Remove the zip file
                Remove-Item 'C:\programdata\SteelSeries\GG.zip' -Recurse -ErrorAction Stop
            }
            catch {
                Write-Host "[WARNING]: $_" -ForegroundColor Red
            }

            # Run the SteelSeries Engine
            Start-Process -FilePath "C:\Program Files\SteelSeries\GG\SteelSeriesGG.exe" -ArgumentList '-dataPath="C:\ProgramData\SteelSeries\GG"', '-dbEnv=production'

            Start-Sleep 10

            # Stop the SteelSeries Engine Client
            taskkill.exe /f /im SteelSeriesGGClient.exe *>$null
            
            # Create openrgb config folder
            try {
                $job = Start-Job -ScriptBlock { 
                    & "C:\ProgramData\chocolatey\lib\openrgb\tools\OpenRGB Windows 64-bit\OpenRGB.exe" *>$null 2>&1
                } -ErrorAction Stop
            
                Start-Sleep 10

                taskkill.exe /f /im OpenRGB.exe *>$null
            }
            catch {
                Write-Host "[WARNING]: Error creating OpenRGB config file. $_" -ForegroundColor Red
            }
            
            # ExplorerPatcher
            # Exclude the WinGet directory from Windows Defender
            Add-MpPreference -ExclusionPath "$env:USERPROFILE\AppData\Local\Temp\WinGet\"
			$OriginalProgressPreference = $Global:ProgressPreference
            $Global:ProgressPreference = 'SilentlyContinue'
            try {
                $osName = (systeminfo.exe | Select-String "OS Name").ToString() 2>$null
                if ($osName -like "*Windows 11*") {
                    winget install valinet.ExplorerPatcher -e --silent --accept-source-agreements --accept-package-agreements --force *>$null
                }
                else {
                    Write-Host "The OS is not Windows 11."
                }
            }
            catch {
                Write-Host "[WARNING]: ExplorerPatcher could not to be installed. $_"
            }

            # Adobe Creative Cloud
            try {
                winget install --id XPDLPKWG9SW2WD -e --silent --accept-source-agreements --accept-package-agreements --force *>$null
                Start-Sleep 5
                taskkill.exe /f /im "Creative Cloud.exe" *>$null
            }
            catch {
                Write-Host "[WARNING]: Adobe Creative Cloud could not to be installed. $_" -ForegroundColor Red
            }

            # Monitor settings prompt
            try {
                #usedregistry Start-Process "desk.cpl"; do { Start-Sleep -Milliseconds 500; } while ((Get-Process -Name SystemSettings -ErrorAction SilentlyContinue))
                #usedregistry SStart-Process "rundll32.exe" -ArgumentList "display.dll, ShowAdapterSettings 0" -NoNewWindow -Wait
                #usedregistry SStart-Process "rundll32.exe" -ArgumentList "display.dll, ShowAdapterSettings 1" -NoNewWindow -Wait
                
                # import monitor conf reg file
                reg import "$env:USERPROFILE\Desktop\display-layout.reg" *>$null
                Start-Sleep 1
                Remove-Item "$env:USERPROFILE\Desktop\display-layout.reg" -Recurse -ErrorAction SilentlyContinue
            
                # Restart explorer
                taskkill /f /im explorer.exe *>$null
                Start-Process explorer.exe *>$null
            }
            catch {
                Write-Host " [WARNING]: Failed to set monitor settings. Error: $_" -ForegroundColor Red -BackgroundColor Black
            }
                    
            # Import Cloudflare certificate
            try {
                $certPath = "C:\Cloudflare_CA.crt"
                Invoke-WebRequest -Uri "https://developers.cloudflare.com/cloudflare-one/static/documentation/connections/Cloudflare_CA.crt" -Outfile $certPath
                Import-Certificate -FilePath $certPath -CertStoreLocation "cert:\LocalMachine\Root" | Out-Null
                Remove-Item -Path $certPath -Force
            }
            catch {
                Write-Host " [WARNING]: Failed to import Cloudflare certificate. Error: $_" -ForegroundColor Red -BackgroundColor Black
            }
                    
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }
                    
        Set-Configs

        # Restore Firefox settings
        Function installFirefoxAddIn() {
            Write-Host "Firefox settings are being restored..." -NoNewline

            # Create Firefox profile directory
            Start-Process -FilePath "C:\Program Files\Mozilla Firefox\firefox.exe" -NoNewWindow
            Start-Sleep -Seconds 6
            taskkill /f /im "firefox.exe" *>$null
    
            # Initialize variables
            $firefoxDir = "C:\Program Files\Mozilla Firefox"
            $distributionDir = Join-Path $firefoxDir 'distribution'
            $extensionsDir = Join-Path $distributionDir 'extensions'
    
            # Ensure necessary directories exist
            $distributionDir, $extensionsDir | ForEach-Object {
                if (-Not (Test-Path $_)) { New-Item $_ -ItemType Directory | Out-Null }
            }
    
            # Install Bitwarden add-in
            try {
                $addonName = "bitwarden-password-manager"
                $addonId = '{446900e4-71c2-419f-a6a7-df9c091e268b}'
                $addonUrl = "https://addons.mozilla.org/firefox/downloads/latest/$addonName/addon-$addonName-latest.xpi"
                $addonPath = Join-Path $extensionsDir "$addonId.xpi"
    
                Invoke-WebRequest $addonUrl -Outfile $addonPath
            }
            catch {
                Write-Host "Error downloading or getting info for addon $addonName $_" -ForegroundColor Red
            }
    
            # Restore user profile settings
            try {
                # Get the user profile directory
                $userProfileDir = (Get-ChildItem -Path "$env:USERPROFILE\AppData\Roaming\Mozilla\Firefox\Profiles" -Filter "*.default-release" -Directory).FullName
        
                # Create user profile chrome directory
                New-Item $userProfileDir\chrome -ItemType Directory *>$null
        
                $configUrls = @{
                    "user.js"         = "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/user.js"
                    "Tab Shapes.css"  = "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/appearance/Tab%20Shapes.css"
                    "Toolbar.css"     = "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/appearance/userChrome.css"
                    "userContent.css" = "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/appearance/userContent.css"
                    "userChrome.css"  = "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/appearance/userChrome.css"
                }
        
                foreach ($file in $configUrls.Keys) {
                    # Download the file and save it to the user profile directory
                    $filePath = if ($file -eq "user.js") {
                        Join-Path $userProfileDir $file
                    }
                    else {
                        Join-Path $userProfileDir "chrome\$file"
                    }
                    $OriginalProgressPreference = $Global:ProgressPreference
                    $Global:ProgressPreference = 'SilentlyContinue'
                    Invoke-WebRequest -Uri $configUrls[$file] -Outfile $filePath
                }
            }
            catch {
                Write-Host "[WARNING]:  $_" -ForegroundColor Red
            }

            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }
    
        installFirefoxAddIn

        # Disable Chrome background running
        Function DisableChromeBackgroundRunning {
            Write-Host "Disabling the 'Continue running background apps' setting in Chrome..." -NoNewline
            try {
                $registryValue = 0
                $registryKey = "HKLM:\SOFTWARE\Policies\Google\Chrome"
        
                if (-not (Test-Path $registryKey)) {
                    New-Item -Path $registryKey -Force | Out-Null
                }
        
                Set-ItemProperty -Path $registryKey -Name "BackgroundModeEnabled" -Value $registryValue -Type DWORD -Force *>$null
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
            }
            catch {
                Write-Host "An error occurred while disabling Chrome background running: $_" -ForegroundColor Red
            }
        }
        
        DisableChromeBackgroundRunning        
        
        # Media Feature Pack
        Function MediaFeaturePack {
            try {
                Write-Host "Installing Media Feature Pack..." -NoNewline
                # check new version
                $output = DISM /Online /Get-Capabilities
                $capabilityLines = $output | Select-String -Pattern "Capability Identity" | Where-Object { $_ -like "*Media.MediaFeaturePack*" }
                if ($capabilityLines) {
                    foreach ($line in $capabilityLines) {
                        if ($line -match 'Capability Identity\s*:\s*(.+)') {
                            $capabilityIdentity = $matches[1]
                            DISM /Online /Add-Capability /CapabilityName:$capabilityIdentity *>$null 2>&1
                            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
                        }
                    }
                }
                else {
                    Write-Host "[INFO]: Media Feature Pack capability not found." -ForegroundColor Yellow -BackgroundColor Black
                }
            }
            catch {
                Write-Host " [WARNING]: Failed. Error: $_" -ForegroundColor Red
            }
        }

        #MediaFeaturePack problematic

        # Media Feature Pack Manual
        Function MediaFeaturePackManual {
            Write-Host "Installing Media Feature Pack manually..." -NoNewline
            try {
                $source = @"
using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace KeyboardSend
{
    public class KeyboardSend
    {
        [DllImport("user32.dll")]
        public static extern void keybd_event(byte bVk, byte bScan, int dwFlags, int dwExtraInfo);

        private const int KEYEVENTF_EXTENDEDKEY = 0;
        private const int KEYEVENTF_KEYUP = 2;

        public static void KeyDown(Keys vKey)
        {
            keybd_event((byte)vKey, 0, KEYEVENTF_EXTENDEDKEY, 0);
        }

        public static void KeyUp(Keys vKey)
        {
            keybd_event((byte)vKey, 0, KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP, 0);
        }
    }
}
"@
                Add-Type -TypeDefinition $source -ReferencedAssemblies "System.Windows.Forms"

                [KeyboardSend.KeyboardSend]::KeyDown("LWin")
                [KeyboardSend.KeyboardSend]::KeyDown("I")
                [KeyboardSend.KeyboardSend]::KeyUp("I")
                [KeyboardSend.KeyboardSend]::KeyUp("LWin")
                Start-Sleep 3
                [System.Windows.Forms.SendKeys]::SendWait("Optional")
                Start-Sleep 2
                [System.Windows.Forms.SendKeys]::SendWait("{DOWN}")
                Start-Sleep -Milliseconds 500
                [System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
                Start-Sleep 1
                [System.Windows.Forms.SendKeys]::SendWait(" ")
                Start-Sleep -Milliseconds 100
                [System.Windows.Forms.SendKeys]::SendWait("Media")
                Start-Sleep -Milliseconds 1500
                [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
                Start-Sleep -Milliseconds 100
                [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
                Start-Sleep -Milliseconds 100
                [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
                Start-Sleep -Milliseconds 100
                [System.Windows.Forms.SendKeys]::SendWait(" ")
                Start-Sleep -Milliseconds 50
                [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
                Start-Sleep -Milliseconds 50
                [System.Windows.Forms.SendKeys]::SendWait(" ")
                Start-Sleep -Milliseconds 50
                [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
                Start-Sleep -Milliseconds 50
                [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
                Start-Sleep -Milliseconds 50
                [System.Windows.Forms.SendKeys]::SendWait(" ")

                Start-Sleep 6
                taskkill /f /im SystemSettings.exe *>$null
                Write-Host "[Media feature pack keeps loading in the background.]" -ForegroundColor Green -BackgroundColor Black 
            }
            catch {
                Write-Host " [WARNING]: Error installing Media Feature Pack manually. Error: $_" -ForegroundColor Red
            }
        }

        MediaFeaturePackManual

        # Disable do not disturb mode
        Function DisableDoNotDisturb {
            Write-Host "Disabling do not disturb mode..." -NoNewline
            try {
                Start-Sleep 2
                [KeyboardSend.KeyboardSend]::KeyDown("LWin")
                [KeyboardSend.KeyboardSend]::KeyDown("I")
                [KeyboardSend.KeyboardSend]::KeyUp("I")
                [KeyboardSend.KeyboardSend]::KeyUp("LWin")
                Start-Sleep -Milliseconds 2000
                [System.Windows.Forms.SendKeys]::SendWait("do not disturb")
                Start-Sleep -Milliseconds 1500
                [System.Windows.Forms.SendKeys]::SendWait("{DOWN}")
                [System.Windows.Forms.SendKeys]::SendWait("{DOWN}")
                Start-Sleep -Milliseconds 800
                [System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
                Start-Sleep -Milliseconds 1000
                [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
                [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
                [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
                [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
                [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
                [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
                [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
                [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
                [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
                [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
                [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
                [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
                [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
                [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
                    
                Start-Sleep -Milliseconds 100
                [System.Windows.Forms.SendKeys]::SendWait(" ")
                    
                Start-Sleep 2

                taskkill /f /im SystemSettings.exe *>$null
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
            }
            catch {
                Write-Host " [WARNING]: Error turning off do not disturb mode.. Error: $_" -ForegroundColor Red
            }
        }

        DisableDoNotDisturb

        # Set night light
        Function SetNightlight {
            Write-Host "Enabling Night Mode..." -NoNewline
            try {
                [System.Windows.Forms.SendKeys]::SendWait('^{ESC}') #windows key
                Start-Sleep -Milliseconds 1500
                [System.Windows.Forms.SendKeys]::SendWait("Night")

                [System.Windows.Forms.SendKeys]::SendWait("{ENTER}")

                Start-Sleep 2

                [System.Windows.Forms.SendKeys]::SendWait(" ")

                Start-Sleep -Milliseconds 500

                [System.Windows.Forms.SendKeys]::SendWait("{RIGHT}")
                Start-Sleep -Milliseconds 1
                [System.Windows.Forms.SendKeys]::SendWait("{RIGHT}")
                Start-Sleep -Milliseconds 1
                [System.Windows.Forms.SendKeys]::SendWait("{RIGHT}")
                Start-Sleep -Milliseconds 1
                [System.Windows.Forms.SendKeys]::SendWait("{RIGHT}")
                Start-Sleep -Milliseconds 1
                [System.Windows.Forms.SendKeys]::SendWait("{RIGHT}")
                Start-Sleep -Milliseconds 1
                [System.Windows.Forms.SendKeys]::SendWait("{RIGHT}")
                Start-Sleep -Milliseconds 1
                [System.Windows.Forms.SendKeys]::SendWait("{RIGHT}")
                Start-Sleep -Milliseconds 1
                [System.Windows.Forms.SendKeys]::SendWait("{RIGHT}")
                Start-Sleep -Milliseconds 1
                [System.Windows.Forms.SendKeys]::SendWait("{RIGHT}")
                Start-Sleep -Milliseconds 1
                [System.Windows.Forms.SendKeys]::SendWait("{RIGHT}")
                Start-Sleep -Milliseconds 1
                [System.Windows.Forms.SendKeys]::SendWait("{RIGHT}")
                Start-Sleep -Milliseconds 1
                [System.Windows.Forms.SendKeys]::SendWait("{RIGHT}")
                Start-Sleep -Milliseconds 50
                [System.Windows.Forms.SendKeys]::SendWait("{RIGHT}")
                Start-Sleep -Milliseconds 50
                [System.Windows.Forms.SendKeys]::SendWait("{RIGHT}")
                Start-Sleep -Milliseconds 50
                [System.Windows.Forms.SendKeys]::SendWait("{RIGHT}")
                Start-Sleep -Milliseconds 50
                [System.Windows.Forms.SendKeys]::SendWait("{RIGHT}")

                taskkill /f /im SystemSettings.exe *>$null
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
            }
            catch {
                Write-Host " [WARNING]: There was an error enabling night mode.. Error: $_" -ForegroundColor Red
            }
        }

        SetNightlight

        # Set Wallpaper
        Function SetWallpaper {
            Write-Host "Setting Desktop Wallpaper..." -NoNewline
            $url = "https://raw.githubusercontent.com/caglaryalcin/after-format/main/files/own/hello.png"
            $filePath = "$HOME\Documents\hello.png"
            $wc = New-Object System.Net.WebClient
            try {
                $wc.DownloadFile($url, $filePath)
                Set-Itemproperty -path "HKCU:Control Panel\Desktop" -name WallPaper -value "$env:userprofile\Documents\hello.png"  | Out-Null
                Start-Sleep 2
                taskkill /f /im explorer.exe *>$null
                Start-Process explorer.exe *>$null
				Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: Failed to set wallpaper: $_" -ForegroundColor Yellow
            }
        }
        
        SetWallpaper

        # Adobe DNG Codec
        Function DNGCodec {
            Write-Host "Installing DNG Codec..." -NoNewline
            $url = "https://download.adobe.com/pub/adobe/dng/win/DNGCodec_2_0_Installer.exe"
            $filePath = "C:\DNGCodec_Installer.exe"
            $programName = "*Adobe DNG Codec*"
        
            # Download and install DNG Codec
            try {
                $OriginalProgressPreference = $Global:ProgressPreference
                $Global:ProgressPreference = 'SilentlyContinue'
                Invoke-WebRequest -Uri $url -OutFile $filePath
            }
            catch {
                Write-Host "[WARNING]: Failed to download Adobe DNG Codec file. $_" -ForegroundColor Red
            }
            
            # Install DNG Codec
            try {
                Start-Process -FilePath $filePath -ArgumentList "/S" -NoNewWindow -Wait -PassThru *>$null
            }
            catch {
                Write-Host "[WARNING]: Failed to install Adobe DNG Codec. $_" -ForegroundColor Red
            }
        
            # Delete the installer file
            try {
                Start-Sleep 1
                Remove-Item -Path $filePath -Force -ErrorAction SilentlyContinue
            }
            catch {
                Write-Host "[WARNING]: Failed to delete Adobe DNG Codec installer file. $_" -ForegroundColor Red
            }
        
            # Check if DNG Codec is installed
            # Set registry paths
            $registryPaths = @(
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
                "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
            )
        
            # Check if DNG Codec is installed
            $dngCodec = $null
            foreach ($path in $registryPaths) {
                # Get registry items
                $items = Get-ItemProperty $path\* -ErrorAction SilentlyContinue
                # Search for DNG Codec
                $dngCodec = $items | Where-Object { $_.DisplayName -like $programName }
                if ($dngCodec) {
                    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                    break
                }
            }
        
            if (-not $dngCodec) {
                Write-Host "[WARNING]: Adobe DNG Codec not found after install check." -ForegroundColor Yellow
            }
        }
        
        DNGCodec

        # Google Play Games Beta
        Function GooglePlayGamesBeta {
            Write-Host "Installing Google Play Games Beta..." -NoNewline
            Write-Host "(Kill client in taskbar after installation)" -ForegroundColor Red -BackgroundColor Black -NoNewline
            $url = "https://dl.google.com/tag/s/CiZ7NDdCMDdENzEtNTA1RC00NjY1LUFGRDQtNDk3MkEzMEM2NTMwfRIEYmV0YRo8CjoIAhIZb3JnYW5pYy1taWNyb3NpdGUtd2luZG93cxoWaHR0cHM6Ly93d3cuZ29vZ2xlLmNvbSjhrtMJKisI7gsSJntlZTBkZWVjMC0wMjFkLTRiOGUtYTk0My04Zjk3NmExYzgyNmJ9QAFKAmVuUgViMmkyZQ/play/games/install/10/Install-GooglePlayGames-Beta.exe"
            $filePath = "C:\GPGB.exe"
            
            # Install Google Services
            $gupdate = 'sc create gupdate binPath= "\"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe\" /svc" DisplayName= "Google Update Service (gupdate)"'
            $gupdatem = 'sc create gupdatem binPath= "\"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe\" /medsvc" DisplayName= "Google Update Service (gupdatem)"'
            $updates = $gupdate + "`r`n" + $gupdatem
            $updates | Out-File -FilePath "C:\gservices.bat" -Encoding Default
            Start-Process "C:\gservices.bat" *>$null
            Start-Sleep 2
            Remove-Item "C:\gservices.bat" -Recurse -ErrorAction SilentlyContinue
 

            # Download and install Google Play Games Beta
            try {
                $OriginalProgressPreference = $Global:ProgressPreference
                $Global:ProgressPreference = 'SilentlyContinue'
                Invoke-WebRequest -Uri $url -OutFile $filePath
            }
            catch {
                Write-Host "[WARNING]: Failed to download Google Play Games Beta file. $_" -ForegroundColor Red
            }
            
            # Install Google Play Games Beta
            try {
                Start-Process -FilePath $filePath -Wait *>$null
            }
            catch {
                Write-Host "[WARNING]: Failed to install Google Play Games Beta. $_" -ForegroundColor Red
            }
        
            # Delete Google Services and setup
            sc.exe delete gupdate *>$null
            sc.exe delete gupdatem *>$null
            Remove-Item $filePath -Recurse -ErrorAction SilentlyContinue

            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        GooglePlayGamesBeta

    }

    Own

}

elseif ($response -eq 'n' -or $response -eq 'N') {
    Write-Host "[The Process Cancelled]" -ForegroundColor Red -BackgroundColor Black
}
else {
    Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
}