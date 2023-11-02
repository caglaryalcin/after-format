##########
#region My Custom Drivers
##########
$myText = @"
###############################
######## DO NOT ACCEPT ########
###############################
"@

Write-Host `n$myText -ForegroundColor Red

Write-Host `n"Do you " -NoNewline
Write-Host "own this script?" -NoNewline -ForegroundColor Red -BackgroundColor Black
Write-Host "(Settings, downloads and installations of the script owner will be made):" -NoNewline -ForegroundColor Red -BackgroundColor Black
Write-Host "(y/n): " -NoNewline
$response = Read-Host

if ($response -eq 'y' -or $response -eq 'Y') {

    Function Own {
        Function SetPins {
            #fan control manual installation
            $OriginalProgressPreference = $Global:ProgressPreference
            $Global:ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri "https://github.com/Rem0o/FanControl.Releases/blob/master/FanControl.zip?raw=true" -Outfile C:\fan_control.zip *>$null
            $OriginalProgressPreference = $Global:ProgressPreference
            $Global:ProgressPreference = 'SilentlyContinue'
            Expand-Archive -Path 'C:\fan_control.zip' -DestinationPath C:\fan_control\ -Force *>$null
            Remove-Item C:\fan_control.zip -recurse -ErrorAction SilentlyContinue
            Start-Process C:\fan_control\FanControl.exe
            Start-Sleep 10
            taskkill /f /im FanControl.exe *>$null

            ##Create Icons folder
            New-Item -Path 'C:\icons' -ItemType Directory *>$null

            # CreateShortcut function to simplify the creation of shortcuts
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

            # Creating shortcuts
            $shortcutPaths = @{
                "Google Chrome"      = @{
                    "Path"             = "C:\Program Files\Google\Chrome\Application\chrome.exe";
                    "WorkingDirectory" = "C:\Program Files\Google\Chrome\Application\";
                };
                "Brave"              = @{
                    "Path"             = "$env:USERPROFILE\AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe";
                    "WorkingDirectory" = "$env:USERPROFILE\AppData\Local\BraveSoftware\Brave-Browser\Application";
                };
                "Firefox"            = @{
                    "Path"             = "C:\Program Files\Mozilla Firefox\firefox.exe";
                    "WorkingDirectory" = "C:\Program Files\Mozilla Firefox\";
                };
                "LibreWolf"          = @{
                    "Path"             = "C:\Program Files\LibreWolf\librewolf.exe";
                    "WorkingDirectory" = "C:\Program Files\LibreWolf\";
                };
                "Steam"              = @{
                    "Path"             = "C:\Program Files (x86)\Steam\Steam.exe";
                    "WorkingDirectory" = "C:\Program Files (x86)\Steam\";
                };
                "Epic Games"         = @{
                    "Path"             = "C:\Program Files (x86)\Epic Games\Launcher\Portal\Binaries\Win32\EpicGamesLauncher.exe";
                    "WorkingDirectory" = "C:\Program Files (x86)\Epic Games\";
                };
                "HWMonitor"          = @{
                    "Path"             = "C:\Program Files\CPUID\HWMonitor\HWMonitor.exe";
                    "WorkingDirectory" = "C:\Program Files\CPUID\HWMonitor\";
                };
                "Crystal Disk Info"  = @{
                    "Path"             = "C:\ProgramData\chocolatey\lib\crystaldiskinfo.portable\tools\DiskInfo64.exe";
                    "WorkingDirectory" = "C:\ProgramData\chocolatey\lib\crystaldiskinfo.portable\tools\";
                };
                "vMware Workstation" = @{
                    "Path"             = "C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe";
                    "WorkingDirectory" = "C:\Program Files (x86)\VMware\VMware Workstation\";
                };
                "VirtualBox"         = @{
                    "Path"             = "C:\Program Files\Oracle\VirtualBox\VirtualBox.exe";
                    "WorkingDirectory" = "C:\Program Files\Oracle\VirtualBox\";
                };
                "Signal"             = @{
                    "Path"             = "$env:USERPROFILE\AppData\Local\Programs\signal-desktop\Signal.exe";
                    "WorkingDirectory" = "$env:USERPROFILE\AppData\Local\Programs\signal-desktop\";
                };
                "Visual Studio"      = @{
                    "Path"             = "C:\Program Files\Microsoft VS Code\Code.exe";
                    "WorkingDirectory" = "C:\Program Files\Microsoft VS Code\";
                };
                "AnyDesk"            = @{
                    "Path"             = "C:\ProgramData\chocolatey\lib\anydesk.portable\tools\AnyDesk.exe";
                    "WorkingDirectory" = "C:\ProgramData\chocolatey\lib\anydesk.portable\tools\";
                };
                "SublimeText"        = @{
                    "Path"             = "C:\Program Files\Sublime Text 3\sublime_text.exe";
                    "WorkingDirectory" = "C:\Program Files\Sublime Text 3\";
                };
                "GitHub Desktop"     = @{
                    "Path"             = "$env:USERPROFILE\AppData\Local\GitHubDesktop\GitHubDesktop.exe";
                    "WorkingDirectory" = "$env:USERPROFILE\AppData\Local\GitHubDesktop\";
                };
                "TreeSize"           = @{
                    "Path"             = "C:\Program Files\JAM Software\TreeSize Free\TreeSizeFree.exe";
                    "WorkingDirectory" = "C:\Program Files\JAM Software\TreeSize Free";
                };
                "Total Commander"    = @{
                    "Path"             = "C:\Program Files\totalcmd\TOTALCMD64.EXE";
                    "WorkingDirectory" = "C:\Program Files\totalcmd\";
                };
                "Putty"              = @{
                    "Path"             = "C:\Program Files\PuTTY\putty.exe";
                    "WorkingDirectory" = "C:\Program Files\PuTTY\";
                };
                "Deluge"             = @{
                    "Path"             = "C:\Program Files\Deluge\deluge.exe";
                    "WorkingDirectory" = "C:\Program Files\Deluge\";
                };
                "WireShark"          = @{
                    "Path"             = "C:\Program Files\Wireshark\Wireshark.exe";
                    "WorkingDirectory" = "C:\Program Files\Wireshark\";
                };
                "DBeaver"            = @{
                    "Path"             = "C:\Program Files\DBeaver\dbeaver.exe";
                    "WorkingDirectory" = "C:\Program Files\DBeaver\";
                };
                "Cryptomator"        = @{
                    "Path"             = "C:\Program Files\Cryptomator\Cryptomator.exe";
                    "WorkingDirectory" = "C:\Program Files\Cryptomator\";
                };
                "PowerToys"          = @{
                    "Path"             = "C:\Program Files\PowerToys\WinUI3Apps\PowerToys.Settings.exe";
                    "WorkingDirectory" = "C:\Program Files\PowerToys\WinUI3Apps\";
                };
                "MS Teams"           = @{
                    "Path"             = "$env:USERPROFILE\AppData\Local\Microsoft\Teams\Update.exe";
                    "Arguments"        = "--processStart Teams.exe";
                    "WorkingDirectory" = "$env:USERPROFILE\AppData\Local\Microsoft\Teams\";
                };
                "dupeGuru"           = @{
                    "Path"             = "C:\Program Files\Hardcoded Software\dupeGuru\dupeguru-win64.exe";
                    "WorkingDirectory" = "C:\Program Files\Hardcoded Software\dupeGuru\";
                };
                "FanControl"       = @{
                    "Path"             = "C:\fan_control\FanControl.exe";
                    "WorkingDirectory" = "C:\fan_control\";
                };
                "OpenRGB"            = @{
                    "Path"             = "C:\ProgramData\chocolatey\lib\openrgb\tools\OpenRGB Windows 64-bit\OpenRGB.exe";
                    "WorkingDirectory" = "C:\ProgramData\chocolatey\lib\openrgb\tools\OpenRGB Windows 64-bit\";
                };
                "Cloudflare WARP"    = @{
                    "Path"             = "C:\Program Files\Cloudflare\Cloudflare WARP\Cloudflare WARP.exe";
                    "WorkingDirectory" = "C:\Program Files\Cloudflare\Cloudflare WARP\";
                };
            }

            foreach ($name in $shortcutPaths.Keys) {
                $WScriptShell = New-Object -ComObject WScript.Shell
                $path = $shortcutPaths[$name].Path
                $workingDirectory = $shortcutPaths[$name].WorkingDirectory
                $shortcutFile = "C:\icons\$name.lnk"
                $shortcut = $WScriptShell.CreateShortcut($shortcutFile)
                $shortcut.TargetPath = $path
                if ($shortcutPaths[$name].Arguments) {
                    $shortcut.Arguments = $shortcutPaths[$name].Arguments
                }
                $shortcut.WorkingDirectory = $workingDirectory
                $shortcut.Save()
                Unblock-File -Path $shortcutFile
            }

            #copy fan control to startup folder
            Copy-Item C:\icons\FanControl.lnk "$env:USERPROFILE\Appdata\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\FanControl.lnk" -Force

            #create config folder
            $job = Start-Job -ScriptBlock { 
                & "C:\ProgramData\chocolatey\lib\openrgb\tools\OpenRGB Windows 64-bit\OpenRGB.exe" *>$null 2>&1
            } *>$null
         
            Start-Sleep 10
            taskkill.exe /f /im OpenRGB.exe *>$null

            ##Set Pin
            $progressPreference = 'silentlyContinue'

            #delete all files on desktop
            Get-ChildItem $env:USERPROFILE\Desktop\* | ForEach-Object { Remove-Item $_ }
            Get-ChildItem C:\users\Public\Desktop\*.lnk | ForEach-Object { Remove-Item $_ }

            # set taskbar icons and pin to taskbar
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/caglaryalcin/after-format/main/files/own/taskbar_pin.reg" -Outfile C:\taskbar_pin.reg
            reg import "C:\taskbar_pin.reg" *>$null
            Copy-Item -Path "C:\icons\*" -Destination "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\" -Force
            reg import "C:\taskbar_pin.reg" *>$null
            taskkill /f /im explorer.exe *>$null

            #delete taskbar_pin.reg
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
            }
            else {
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
                "bitwarden-password-manager"     = '{446900e4-71c2-419f-a6a7-df9c091e268b}';
                "ublock-origin"                  = 'uBlock0@raymondhill.net';
                "privacy-badger17"               = 'jid1-MnnxcxisBPnSXQ@jetpack';
                "darkreader"                     = 'addon@darkreader.org';
                "ublacklist"                     = '@ublacklist';
                "return-youtube-dislikes"        = '{762f9885-5a13-4abd-9c77-433dcd38b8fd}';
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
                }
                catch {
                    Write-Host "Error downloading or getting info for addon $($addon.Name): $_" -ForegroundColor Red
                }
            }

            $dest = Get-ChildItem -Path $env:USERPROFILE\AppData\Roaming\librewolf\Profiles\ -Filter "*.default-default" -Directory
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/user.js" -Outfile "$($dest.FullName)\user.js"
            New-Item -Path "$($dest.FullName)" -Name chrome -ItemType "directory" *>$null
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/appearance/Tab%20Shapes.css" -Outfile "$($dest.FullName)\chrome\Tab Shapes.css"
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/appearance/userChrome.css" -Outfile "$($dest.FullName)\chrome\Toolbar.css"
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/appearance/userContent.css" -Outfile "$($dest.FullName)\chrome\userContent.css"
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/appearance/userChrome.css" -Outfile "$($dest.FullName)\chrome\userChrome.css"
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        installLibreWolfAddIn("");
                
        #Sublime text
        function Set-Configs {
            Write-Host "Setting my configs..." -NoNewline
            # Helper function to create directories
            function Ensure-Directory($path) {
                try {
                    if (-Not (Test-Path $path)) {
                        New-Item -Path $path -ItemType "directory" | Out-Null
                    }
                }
                catch {
                    Write-Host " [WARNING] Failed to create directory at path: $path. Error: $_" -ForegroundColor Red -BackgroundColor Black
                }
            }
            # Helper function for web requests
            function Safe-Invoke-WebRequest($uri, $outFile) {
                try {
                    Invoke-WebRequest -Uri $uri -Outfile $outFile
                }
                catch {
                    Write-Host " [WARNING] Failed to download from: $uri. Error: $_" -ForegroundColor Red -BackgroundColor Black
                }
            }
            
            function Ensure-Directory($path) {
                if (-Not (Test-Path $path)) {
                    New-Item -ItemType Directory -Force -Path $path | Out-Null
                }
            }

            # Ublacklist url to desktop
            $filePath = "$env:userprofile\Desktop\ublacklist-address.txt"
            Set-Content -Path $filePath -Value "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/extensions/ublacklist.txt"

            ## manual configs
            # twinkle tray
            & "$env:USERPROFILE\AppData\Local\Programs\twinkle-tray\Twinkle Tray.exe" *>$null
            Start-Sleep 10
            taskkill /f /im "Twinkle Tray.exe" *>$null

            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/twinkle-tray/settings.json" -Outfile "$env:USERPROFILE\AppData\Roaming\twinkle-tray\settings.json"
            
            # Define directories and files to be downloaded
            $downloads = @{
                # sublime text
                "$env:userprofile\AppData\Roaming\Sublime Text\Packages\User"      = @(
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/sublime-text/Preferences.sublime-settings",
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/sublime-text/cy.sublime-color-scheme",
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/sublime-text/Default%20(Windows).sublime-mousemap"
                )
                "$env:userprofile\AppData\Roaming\Sublime Text\Installed Packages" = @(
                    "https://packagecontrol.io/Package%20Control.sublime-package"
                )
                # power toys
                "$env:UserProfile\Documents\PowerToys\Backup"                      = @(
                    "https://github.com/caglaryalcin/after-format/raw/main/files/own/settings_133264013067260668.ptb"
                )
                # browser restore files
                "$env:userprofile\Desktop"                                         = @(
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/extensions/ublock.txt",
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/browser-conf/bookmarks/bookmarks.json"
                )
                # fan control
                "C:\fan_control\Configurations"                                    = @(
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/fan/my_fan_config.json"
                )
                # openrgb
                "$env:USERPROFILE\Appdata\Roaming\Openrgb"                         = @(
                    "https://github.com/caglaryalcin/my-configs/raw/main/led/my_led_config.orp"
                )
                # keyboard
                "C:\ProgramData\SteelSeries\GG\apps\engine\db"                     = @(
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/keyboard/engine/db/database.db",
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/keyboard/engine/db/database.db-shm",
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/keyboard/engine/db/database.db-wal",
                    "https://raw.githubusercontent.com/caglaryalcin/my-configs/main/keyboard/engine/db/dbconf.yml"
                )
                "C:\ProgramData\SteelSeries\GG\apps\engine\prism\db"               = @(
                    "https://github.com/caglaryalcin/my-configs/raw/main/keyboard/engine/db/database.db"
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
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "electron.app.Twinkle Tray" -Value "$env:userprofile\AppData\Local\Programs\twinkle-tray\Twinkle Tray.exe" | Out-Null
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowDevMgrUpdates" -Value "0" | Out-Null
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value "0" | Out-Null
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMDevicesEnumerationEnabled" -Value 0 | Out-Null
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableDeviceEnumeration" -Value 1 | Out-Null
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
                $capability = DISM / Online / Get-Capabilities | Select-String 'Media.MediaFeaturePack~~~~'
                if ($capability) {
                    $newVersion = $capability.ToString().Trim()
                    $newVersion = $newVersion -replace 'Capability Identity : ', '' -replace '\s', ''
                    
                    # Add the capability
                    $installResult = DISM / Online / Add-Capability / CapabilityName:$newVersion / Quiet / NoRestart
                    
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