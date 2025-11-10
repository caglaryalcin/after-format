##########
#region Priority
##########

Function Priority {
    $ErrorActionPreference = 'SilentlyContinue'
    New-PSDrive -PSProvider Registry -Name HKCU -Root HKEY_CURRENT_USER | Out-Null
    New-PSDrive -PSProvider Registry -Name HKLM -Root HKEY_LOCAL_MACHINE | Out-Null
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
    New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
}

Priority

Function Silent {
    $Global:ProgressPreference = 'SilentlyContinue'
}

$mode = (Get-ItemProperty -Path "HKCU:\Software\MyScript" -Name "Mode" -ErrorAction SilentlyContinue)."Mode"

##########
#endregion Priority
##########

$wingetWarnings = @()
Function InstallSoftwares {
    Write-Host "---------Mode Select" -ForegroundColor Blue -BackgroundColor Gray
    Write-Host "Chapter completed."
    Write-Host `n"---------Adjusting System Settings" -ForegroundColor Blue -BackgroundColor Gray
    Write-Host "Chapter completed."
    Write-Host `n"---------Adjusting Privacy Settings" -ForegroundColor Blue -BackgroundColor Gray
    Write-Host "Chapter completed."

    Write-Host `n"---------Installing Softwares" -ForegroundColor Blue -BackgroundColor Gray

    Write-Host `n"Installing/upgrading winget..." -NoNewline
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black

    # Create a directory for logs
    New-Item -Path "C:\packages-logs" -ItemType Directory -Force | Out-Null

    $appsToClose = @{
        "github-desktop"  = "GithubDesktop";
        "cloudflare-warp" = "Cloudflare WARP"
    }

    # This script block will continuously check for specified processes and stop them if found
    $scriptBlock = {
        Param($processNames)
        while ($true) {
            foreach ($process in $processNames) {
                Get-Process | Where-Object { $_.Name -eq $process } | Stop-Process -Force -ErrorAction SilentlyContinue
            }
            Start-Sleep -Seconds 2
        }
    }

    # Start the background job for monitoring and stopping processes
    if ($mode -eq "normal") {
        $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $appsToClose.Values
    }

    switch ($mode) {
        'normal' { $jsonUrl = 'https://raw.githubusercontent.com/caglaryalcin/after-format/main/files/apps/normal/winget.json' }
        'developer' { $jsonUrl = 'https://raw.githubusercontent.com/caglaryalcin/after-format/main/files/apps/dev-sys/winget.json' }
        'gaming' { $jsonUrl = 'https://raw.githubusercontent.com/caglaryalcin/after-format/main/files/apps/gaming/winget.json' }
    }

    $jsonContent = Invoke-RestMethod -Uri $jsonUrl -ErrorAction Stop
    $packages = $jsonContent.Sources.Packages

    foreach ($pkg in $packages) {
        $packageName = $pkg.PackageIdentifier
        $installerType = $pkg.InstallerType
        Write-Host "Installing $packageName..." -NoNewLine

        # Install the packages
        Start-Sleep -Milliseconds 5
        if ($packageName -eq 'Blizzard.BattleNet') {
            $tmp = "$env:TEMP\Battle.net-Setup.exe"
            Invoke-WebRequest -Uri "https://downloader.battle.net/download/getInstallerForGame?os=win&installer=Battle.net-Setup.exe" -OutFile $tmp -UseBasicParsing
            Unblock-File -Path $tmp
            $p = Start-Process -FilePath $tmp -ArgumentList @('--lang=enUS', '--installpath="C:\Program Files (x86)\Battle.net"') -Verb RunAs -PassThru
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            if ($p) { $p.WaitForExit(5 * 1000) | Out-Null }
            if ($p.HasExited) {
                $deadline = (Get-Date).AddMinutes(20)
                while ((Get-Process -Name 'Battle.net-Setup', 'Battle.net Installer', 'Battle.net' -ErrorAction SilentlyContinue) `
                        -and (Get-Date) -lt $deadline) {
                    Start-Sleep -Seconds 2
                }
            }
            else {
                $p.WaitForExit(20 * 60 * 1000) | Out-Null
            }
            $LASTEXITCODE = if ($p.HasExited) { $p.ExitCode } else { 1 }

            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            $result = ""
        }
        else {
            $args = @('install', $packageName, '-e', '--silent',
                '--accept-source-agreements', '--accept-package-agreements', '--force', '--disable-interactivity')
            if ($installerType) { $args += @('--installer-type', $installerType) }
            $result = & winget @args 2>&1 | Out-String
        }

        # Check if the installation was successful
        $err = $result -match '(?i)installer hash does not match|signature.*(invalid|failed)|download.*failed|\bfail(ed)?\b|\berror\b'
        $ok = $result -match '(?i)successfully installed|is already installed|no applicable update'

        $logFile = "C:\packages-logs\${packageName}_winget_install.log"
        ($result | Out-String) | Out-File -FilePath $logFile -Force

        if ($err) {
            Write-Host "[WARNING]" -ForegroundColor Red -BackgroundColor Black
            $wingetWarnings += $packageName
            Write-Host "[Check the log file at $logFile for details.]"
        }
        elseif ($ok) {
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }
        elseif ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 3010) {
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }
        else {
            Write-Host "[WARNING]" -ForegroundColor Red -BackgroundColor Black
            $wingetWarnings += $packageName
            Write-Host "[Check the log file at $logFile for details.]"
        }

    }

    # Once all installations are done, stop the background job
    if ($mode -eq "developer" -or $mode -eq "normal") {
        $deadline = (Get-Date).AddSeconds(30)
        do {
            Stop-Process -Name 'PowerToys*' -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        } while ((Get-Process -Name 'PowerToys*' -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline)
    }
}

InstallSoftwares

Function Get-InstalledProgram {
    param (
        [Parameter(Mandatory = $true)]
        [string]$programName
    )
        
    if ($wingetWarnings -contains $programName) {
        return $true
    }
            
    $installedProgram = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, 
    HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall, 
    HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall |
    Get-ItemProperty | 
    Where-Object { $_.DisplayName -like "*$programName*" } | 
    Select-Object -First 1
            
    if (-not $installedProgram) {
        $installedProgram = Get-AppxPackage | Where-Object { $_.Name -like "*$programName*" } | Select-Object -First 1
    }

    # check other paths
    $paths = @(
        'C:\programdata\',
        'C:\Program Files (x86)\',
        'C:\Program Files\'
    )
    
    foreach ($path in $paths) {
        if (-not $installedProgram) {
            $chocoPrograms = Get-ChildItem -Path $path -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$programName*" }
            if ($null -ne $chocoPrograms -and $chocoPrograms.Count -gt 0) {
                $installedProgram = $true
                break
            }
        }
    }
            
    return $null -ne $installedProgram
}

Write-Host `n"----------------" -ForegroundColor Yellow
Write-Host @"
Detecting programs that cannot be installed with winget...

"@
Function chocoinstall {
    $chocoExecutablePath = Join-Path -Path 'C:\ProgramData\chocolatey\bin' -ChildPath 'choco.exe'

    if (-not (Test-Path -Path $chocoExecutablePath)) {
        try {
            Write-Host "Installing Chocolatey..." -NoNewline

            # Disable Chocolatey's first run customization
            If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 1 -Type DWord

            # Install Chocolatey
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) *>$null
            Start-Sleep 10

            # Check if Chocolatey is installed
            if (Test-Path -Path $chocoExecutablePath) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                $errorMessage = "Chocolatey installation failed or Chocolatey is not available in PATH."
                Write-Host "[WARNING] $errorMessage" -ForegroundColor Red -BackgroundColor Black
                throw $errorMessage
            }

            # Disable -y requirement for all packages
            choco feature enable -n allowGlobalConfirmation *>$null

            # Set the Chocolatey path to the environment variable
            $env:PATH += ";C:\ProgramData\chocolatey\bin"
            [System.Environment]::SetEnvironmentVariable('Path', $env:Path + ';C:\ProgramData\chocolatey\bin', [System.EnvironmentVariableTarget]::Machine)
        }
        catch {
            Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
        }
    }
    else {
        $env:PATH += ";C:\ProgramData\chocolatey\bin"
        [System.Environment]::SetEnvironmentVariable('Path', $env:Path + ';C:\ProgramData\chocolatey\bin', [System.EnvironmentVariableTarget]::Machine)
    }
}

chocoinstall

if ($mode -eq "normal") {
    $checkJsonUrl = "https://raw.githubusercontent.com/caglaryalcin/after-format/main/files/apps/normal/check.json"
    $jsonContent = Invoke-RestMethod -Uri $checkJsonUrl
    $packagesToCheck = $jsonContent.Sources.Packages

    $chocoAppsConfigUrl = "https://raw.githubusercontent.com/caglaryalcin/after-format/main/files/apps/normal/choco-apps.config"
    [xml]$chocoConfig = Invoke-RestMethod -Uri $chocoAppsConfigUrl
}

if ($mode -eq "developer") {
    $checkJsonUrl = "https://raw.githubusercontent.com/caglaryalcin/after-format/main/files/apps/dev-sys/check.json"
    $jsonContent = Invoke-RestMethod -Uri $checkJsonUrl
    $packagesToCheck = $jsonContent.Sources.Packages

    $chocoAppsConfigUrl = "https://raw.githubusercontent.com/caglaryalcin/after-format/main/files/apps/dev-sys/choco-apps.config"
    [xml]$chocoConfig = Invoke-RestMethod -Uri $chocoAppsConfigUrl
}

if ($mode -eq "gaming") {
    $checkJsonUrl = "https://raw.githubusercontent.com/caglaryalcin/after-format/main/files/apps/gaming/check.json"
    $jsonContent = Invoke-RestMethod -Uri $checkJsonUrl
    $packagesToCheck = $jsonContent.Sources.Packages

    $chocoAppsConfigUrl = "https://raw.githubusercontent.com/caglaryalcin/after-format/main/files/apps/gaming/choco-apps.config"
    [xml]$chocoConfig = Invoke-RestMethod -Uri $chocoAppsConfigUrl
}

foreach ($pkg in $packagesToCheck) {
    $isInstalled = $false
        
    foreach ($identifier in $pkg.PackageIdentifier) {
        if (Get-InstalledProgram -programName $identifier) {
            $isInstalled = $true
            break
        }
    }
        
    if (-not $isInstalled) {
        foreach ($identifier in $pkg.PackageIdentifier) {
            $chocoPackageId = $chocoConfig.packages.package | Where-Object { $_.id -match $identifier } | Select-Object -ExpandProperty id
        
            if ($chocoPackageId) {
                Write-Host "$identifier" -ForegroundColor Red -BackgroundColor Black -NoNewline
                Write-Host " not installed" -NoNewline
                Write-Host " with winget." -NoNewline
                Write-Host "Trying with" -NoNewLine
                Write-Host " chocolatey..." -Foregroundcolor Yellow -NoNewline
                $result = choco install $chocoPackageId --ignore-checksums --force -y -Verbose -Timeout 0 2>&1 | Out-String
                if ($result -match "was successful*") {
                    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                    break
                }
                else {
                    Write-Host "[WARNING]" -ForegroundColor Red -BackgroundColor Black
                    $logFile = "C:\packages-logs\${identifier}_choco_install.log"
                    $result | Out-File -FilePath $logFile -Force
                    Write-Host "[Check the log file at $logFile for details.]"
                }
            }
            else {
                ##
            }
        }
    }
}

Write-Host @"
----------------

"@ -ForegroundColor Yellow

Function SafeTaskKill {
    param($processName)
        
    taskkill /f /im $processName *>$null

    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 128) {
        Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
    }
}

if ($mode -eq "developer" -or $mode -eq "normal") {
    SafeTaskKill "GithubDesktop.exe"
    SafeTaskKill "Cloudflare WARP.exe"
    SafeTaskKill "AnyDesk.exe"
    SafeTaskKill "Powertoys.exe"
}
if ($mode -eq "gaming") {
    SafeTaskKill "steam.exe"
    SafeTaskKill "Discord.exe"
    SafeTaskKill "EADesktop.exe"
    SafeTaskKill "Battle.net.exe"
}

Function Install-VSCodeExtensions {
    Write-Host "Installing Microsoft Visual Studio Code Extensions..." -NoNewline
    Start-Sleep 5
    $vsCodePath = "$env:USERPROFILE\AppData\Local\Programs\Microsoft VS Code\bin\code.cmd" # for winget installations

    if (-not (Test-Path "$env:USERPROFILE\AppData\Local\Programs\Microsoft VS Code")) {
        $vsCodePath = "C:\Program Files\Microsoft VS Code\bin\code.cmd" # for chocolatey installations
    }
        
    $docker = "eamodio.gitlens", "davidanson.vscode-markdownlint", "ms-azuretools.vscode-docker", "formulahendry.docker-explorer", "p1c2u.docker-compose", "ms-vscode-remote.remote-containers"
    $autocomplete = "formulahendry.auto-close-tag", "formulahendry.auto-rename-tag", "formulahendry.auto-complete-tag", "streetsidesoftware.code-spell-checker", 
    "redhat.vscode-xml", "dotjoshjohnson.xml"
    $design = "pkief.material-icon-theme"
    $vspowershell = "ms-vscode.powershell", "tobysmith568.run-in-powershell", "ms-vscode-remote.remote-wsl"
    $frontend = "emin.vscode-react-native-kit", "msjsdiag.vscode-react-native", "pranaygp.vscode-css-peek", "rodrigovallades.es7-react-js-snippets", 
    "dsznajder.es7-react-js-snippets", "dbaeumer.vscode-eslint", "christian-kohler.path-intellisense", "esbenp.prettier-vscode", "ms-python.python", 
    "naumovs.color-highlight", "meezilla.json", "oliversturm.fix-json"
    $github = "github.vscode-pull-request-github", "github.copilot"
    $linux = "rogalmic.bash-debug", "shakram02.bash-beautify", "mads-hartmann.bash-ide-vscode", "redhat.vscode-yaml"
    $vsextensions = $docker + $autocomplete + $design + $vspowershell + $frontend + $github + $linux
        
    $installed = & $vsCodePath --list-extensions
        
    foreach ($vse in $vsextensions) {
        if ($installed -contains $vse) {
            Write-Host "$vse already installed." -ForegroundColor Gray
        }
        else {
            & $vsCodePath --install-extension $vse *>$null
            Start-Sleep -Seconds 3  # Give some time for the extension to install
            $updatedInstalled = & $vsCodePath --list-extensions
        }
    }
        
    $allExtensionsInstalled = $True
    foreach ($vse in $vsextensions) {
        if (-not ($updatedInstalled -contains $vse)) {
            $allExtensionsInstalled = $False
            break
        }
    }
        
    if ($allExtensionsInstalled) {
        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    }
    else {
        Write-Host "[INFO] VSCode's $vse plugin failed to install" -ForegroundColor Yellow -BackgroundColor Black
    }
}

if ($mode -eq "developer") {
    Install-VSCodeExtensions

    # Visual Studio Code json path
    $settingsPath = "$env:USERPROFILE\AppData\Roaming\Code\User\settings.json"

    # Get json content
    $jsonContent = @"
{
"workbench.colorTheme": "Visual Studio Dark",
"workbench.iconTheme": "material-icon-theme"
}
"@

    # Create or rewrite json file
    Set-Content -Path $settingsPath -Value $jsonContent -Force


    # 7-Zip on PS
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force *>$null
        Set-PSRepository -Name 'PSGallery' -SourceLocation "https://www.powershellgallery.com/api/v2" -InstallationPolicy Trusted *>$null
        Install-Module -Name 7Zip4PowerShell -Force *>$null

        if (-Not (Get-Module -ListAvailable -Name 7Zip4PowerShell)) { throw "7Zip4PowerShell module not installed" }
    }
    catch {
        Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
    }

}

# Malwarebytes trial reset
Function MalwarebytesReset {
    Write-Host "Adding task for Malwarebytes trial version reset..." -NoNewline

    $taskName = "Malwarebytes-Reset"
    $taskPath = "\"
    $taskDescription = "A task that resets the Malwarebytes Premium trial by changing the MachineGuid registry value"
    $currentTime = (Get-Date).ToString("HH:mm")
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $powerShellScript = {
        New-Guid | ForEach-Object {
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name 'MachineGuid' -Value $_.Guid
        }
    }

    $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command $powerShellScript"

    $taskTrigger = New-ScheduledTaskTrigger -Daily -DaysInterval 13 -At $currentTime
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden
    $taskprincipal = New-ScheduledTaskPrincipal -UserId $currentUser -RunLevel Highest

    $task = New-ScheduledTask -Action $taskAction -Principal $taskPrincipal -Trigger $taskTrigger -Settings $taskSettings -Description $taskDescription

    $result = Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -InputObject $task

    if ($result) {
        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    }
    else {
        Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
    }
}

if ($mode -eq "normal" -or $mode -eq "developer") {
    MalwarebytesReset
}

if ($mode -eq "normal" -or $mode -eq "developer") {
    # webview2 is being forcibly reloaded because it is necessary
    try {
        Write-Host "Reinstalling Microsoft Edge WebView2 Runtime..." -NoNewline
        Silent
        winget install Microsoft.EdgeWebView2Runtime -e --silent --accept-source-agreements --accept-package-agreements --force *>$null
        Invoke-WebRequest -Uri "https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/bfbbeee6-130c-46b7-bf66-6b8eab0e894d/MicrosoftEdgeWebview2Setup.exe" -OutFile "$env:USERPROFILE\Desktop\WebView2Runtime.exe" -UseBasicParsing
        Start-Process -FilePath "$env:USERPROFILE\Desktop\WebView2Runtime.exe" -ArgumentList "/silent", "/install" -Wait
        Remove-Item -Path "$env:USERPROFILE\Desktop\WebView2Runtime.exe" -Force
        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    }
    catch {
        Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black

    }
}

if ($mode -eq "developer") {
    setx /M PATH "$($env:PATH);C:\Program Files\OpenSSL-Win64\bin"
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH /t REG_EXPAND_SZ /d "$($env:PATH);C:\Program Files\OpenSSL-Win64\bin" /f
}

##########
#region Remove Unused Apps/Softwares
##########
Function UnusedApps {
    # Remove temp softwares task
    $taskName = "softwares"
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false

    Write-Host `n"---------Remove Unused Apps/Softwares" -ForegroundColor Blue -BackgroundColor Gray

    Write-Host `n"Do you want " -NoNewline
    Write-Host "Uninstall Unused Apps & Softwares?" -ForegroundColor Yellow -NoNewline
    Write-Host "(y/n): " -ForegroundColor Green -NoNewline
    $response = Read-Host

    if ($response -eq 'y' -or $response -eq 'Y') {

        # Remove Apps 
        Function UninstallThirdPartyBloat {
            Write-Host "Uninstalling Default Third Party Applications..." -NoNewline
            
            $UninstallAppxPackages = 
            "Microsoft.WindowsAlarms", #Alarm and clock app for Windows.
            "Microsoft.549981C3F5F10", #Code likely represents a specific app or service, specifics unknown without context.
            "Microsoft.WindowsFeedbackHub", #Platform for user feedback on Windows.
            "Microsoft.Bing*", #Bing search engine related services and apps.
            "Microsoft.Zune*", #Media software for music and videos, now discontinued.
            "Microsoft.PowerAutomateDesktop", #Automation tool for desktop workflows.
            "Microsoft.WindowsSoundRecorder", #Audio recording app for Windows.
            "Microsoft.MicrosoftSolitaireCollection", #Solitaire game collection.
            "Microsoft.GamingApp", #Likely related to Xbox or Windows gaming services.
            "*microsoft.windowscomm**", #Likely refers to communication services in Windows, specifics unclear.
            "MicrosoftCorporationII.QuickAssist", #Remote assistance app by Microsoft.
            "Microsoft.Todos", #Task management app.
            "Microsoft.SkypeApp", #Skype communication app for Windows.
            "Microsoft.Microsoft3DViewer", #App for viewing 3D models.
            "Microsoft.Wallet", #Digital wallet app, now discontinued.
            "Microsoft.WebMediaExtensions", #Extensions for media formats in web browsers.
            "MicrosoftWindows.Client.WebExperience", #Likely related to the web browsing experience in Windows, specifics unclear.
            "Clipchamp.Clipchamp", #Video editing app.
            "Microsoft.WindowsMaps", #Mapping and navigation app.
            "Microsoft.Advertising.Xaml", #Advertising SDK for apps.
            "Microsoft.MixedReality.Portal", #Mixed Reality portal app for immersive experiences.
            "Microsoft.BingNews", #News aggregation app.
            "Microsoft.GetHelp", #Support and troubleshooting app.
            "Microsoft.Getstarted", #Introduction and tips app for Windows features.
            "Microsoft.MicrosoftOfficeHub", #Central hub for Office apps and services.
            "Microsoft.OneConnect", #Connectivity and cloud services app.
            "Microsoft.People", #Contact management and social integration app.
            "Microsoft.Xbox.TCUI", #Xbox text, chat, and user interface services.
            "Microsoft.XboxApp", #Main app for Xbox social and gaming features.
            "Microsoft.XboxGameOverlay", #In-game overlay for Xbox features and social interactions.
            "Microsoft.XboxIdentityProvider", #Service for Xbox account authentication.
            "Microsoft.XboxSpeechToTextOverlay" #Speech-to-text services for Xbox gaming.

            $UninstallExcludeXboxAppxPackages =
            "Microsoft.WindowsAlarms", #Alarm and clock app for Windows.
            "Microsoft.549981C3F5F10", #Code likely represents a specific app or service, specifics unknown without context.
            "Microsoft.WindowsFeedbackHub", #Platform for user feedback on Windows.
            "Microsoft.Bing*", #Bing search engine related services and apps.
            "Microsoft.Zune*", #Media software for music and videos, now discontinued.
            "Microsoft.PowerAutomateDesktop", #Automation tool for desktop workflows.
            "Microsoft.WindowsSoundRecorder", #Audio recording app for Windows.
            "Microsoft.MicrosoftSolitaireCollection", #Solitaire game collection.
            "Microsoft.GamingApp", #Likely related to Xbox or Windows gaming services.
            "*microsoft.windowscomm**", #Likely refers to communication services in Windows, specifics unclear.
            "MicrosoftCorporationII.QuickAssist", #Remote assistance app by Microsoft.
            "Microsoft.Todos", #Task management app.
            "Microsoft.SkypeApp", #Skype communication app for Windows.
            "Microsoft.Microsoft3DViewer", #App for viewing 3D models.
            "Microsoft.Wallet", #Digital wallet app, now discontinued.
            "Microsoft.WebMediaExtensions", #Extensions for media formats in web browsers.
            "MicrosoftWindows.Client.WebExperience", #Likely related to the web browsing experience in Windows, specifics unclear.
            "Clipchamp.Clipchamp", #Video editing app.
            "Microsoft.WindowsMaps", #Mapping and navigation app.
            "Microsoft.Advertising.Xaml", #Advertising SDK for apps.
            "Microsoft.MixedReality.Portal", #Mixed Reality portal app for immersive experiences.
            "Microsoft.BingNews", #News aggregation app.
            "Microsoft.GetHelp", #Support and troubleshooting app.
            "Microsoft.Getstarted", #Introduction and tips app for Windows features.
            "Microsoft.MicrosoftOfficeHub", #Central hub for Office apps and services.
            "Microsoft.OneConnect", #Connectivity and cloud services app.
            "Microsoft.People" #Contact management and social integration app.
        
            $installedApps = Get-AppxPackage -AllUsers
            
            Silent #silently
            
            if ($mode -eq "normal" -or $mode -eq "developer") {
                foreach ($package in $UninstallAppxPackages) {
                    $app = $installedApps | Where-Object { $_.Name -like $package }
                    if ($null -ne $app) {
                        try {
                            $app | Remove-AppxPackage -ErrorAction Stop
                        }
                        catch {
                            Write-Host "[WARNING] $($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Black
                        }
                    }
                }
            }

            if ($mode -eq "gaming") {
                foreach ($package in $UninstallExcludeXboxAppxPackages) {
                    $app = $installedApps | Where-Object { $_.Name -like $package }
                    if ($null -ne $app) {
                        try {
                            $app | Remove-AppxPackage -ErrorAction Stop
                        }
                        catch {
                            Write-Host "[WARNING] $($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Black
                        }
                    }
                }
            }    
        
            # Uninstall Microsoft Teams Outlook Add-in
            $TeamsAddinGUID = '{A7AB73A3-CB10-4AA5-9D38-6AEFFBDE4C91}'
            $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$TeamsAddinGUID"
            if (Test-Path $registryPath) {
                try {
                    Start-Process msiexec.exe -ArgumentList "/x $TeamsAddinGUID /qn /norestart" -NoNewWindow -Wait
                }
                catch {
                    Write-Host "[WARNING] $($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Black
                }
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }
        
        UninstallThirdPartyBloat

        # Uninstall Windows Media Player
        Function UninstallMediaPlayer {
            Write-Host `n"Uninstalling Windows Media Player..." -NoNewline
            try {
                Silent #silently
                Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "WindowsMediaPlayer" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
                Get-WindowsCapability -Online | Where-Object { $_.Name -like "Media.WindowsMediaPlayer*" } | Remove-WindowsCapability -Online | Out-Null
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }

        UninstallMediaPlayer

        # Uninstall Work Folders Client - Not applicable to Server
        Function UninstallWorkFolders {
            Write-Host "Uninstalling Work Folders Client..." -NoNewline
            try {
                Silent #silently
                Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "WorkFolders-Client" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }

        UninstallWorkFolders

        # Uninstall Microsoft XPS Document Writer 
        Function UninstallXPSPrinter {
            Write-Host "Uninstalling Microsoft XPS Document Writer..." -NoNewline
            try {
                Remove-Printer -Name "Microsoft XPS Document Writer" -ErrorAction SilentlyContinue 
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }

        UninstallXPSPrinter

        # Remove Default Fax Printer 
        Function RemoveFaxPrinter {
            Write-Host "Removing Default Fax Printer..." -NoNewline
            try {
                Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }

        RemoveFaxPrinter

        # Uninstall Windows Fax and Scan Services - Not applicable to Server
        Function UninstallFaxAndScan {
            Write-Host "Uninstalling Windows Fax and Scan Services..." -NoNewline
            try {
                Silent #silently
                Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "FaxServicesClientPackage" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
                Get-WindowsCapability -Online | Where-Object { $_.Name -like "Print.Fax.Scan*" } | Remove-WindowsCapability -Online | Out-Null
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }

        UninstallFaxAndScan

        # Delete some folders from This PC
        Function UnpinExplorer {
            Write-Host "Deleting 3D Folders, Pictures, Videos, Music from This PC..." -NoNewline
            $basePath = "HKLM:\SOFTWARE"
            $wow6432Node = "Wow6432Node\"
            $explorerPath = "Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\"
            $quickAccessPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderMSGraph\NameSpace\DelegateFolders\{3936E9E4-D92C-4EEE-A85A-BC16D5EA0819}"
            $homePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace_36354489\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}"
            $namespaces = @{
                "3DFolders" = "{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
                "Videos"    = "{A0953C92-50DC-43bf-BE83-3742FED03C9C}", "{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}"
                "Pictures"  = "{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}", "{24ad3ad4-a569-4530-98e1-ab02f9417aa8}"
            }
            
            foreach ($category in $namespaces.Keys) {
                foreach ($id in $namespaces[$category]) {
                    $paths = @(
                        "$basePath\$explorerPath$id",
                        "$basePath\$wow6432Node$explorerPath$id"
                    )
                    
                    foreach ($path in $paths) {
                        try {
                            Remove-Item -Path $path -Recurse -ErrorAction SilentlyContinue
                        }
                        catch {
                            Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                        }
                    }
                }
            }
        
            # Additional paths
            try {
                Remove-Item -Path $quickAccessPath -Recurse -ErrorAction SilentlyContinue
                Remove-Item -Path $homePath -Recurse -ErrorAction SilentlyContinue
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
            
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }
        
        UnpinExplorer        

        # Block Microsoft Edge telemetry
        Function EdgePrivacySettings {
            Write-Host "Adjusting Microsoft Edge privacy settings..." -NoNewline
            
            $EdgePrivacyCUPath = "HKCU:\Software\Policies\Microsoft\Edge"
            $EdgePrivacyAUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
        
            $EdgePrivacyKeys = @(
                "PaymentMethodQueryEnabled",
                "PersonalizationReportingEnabled",
                "AddressBarMicrosoftSearchInBingProviderEnabled",
                "UserFeedbackAllowed",
                "AutofillCreditCardEnabled",
                "AutofillAddressEnabled",
                "LocalProvidersEnabled",
                "SearchSuggestEnabled",
                "EdgeShoppingAssistantEnabled",
                "WebWidgetAllowed",
                "HubsSidebarEnabled"
            )
        
            $EdgePrivacyKeys | ForEach-Object {
                if (-not (Test-Path $EdgePrivacyCUPath)) {
                    New-Item -Path $EdgePrivacyCUPath -Force *>$null
                }
                try {
                    Set-ItemProperty -Path $EdgePrivacyCUPath -Name $_ -Value 0
                    Set-ItemProperty -Path $EdgePrivacyCUPath -Name "ConfigureDoNotTrack" -Value 1
                }
                catch {
                    Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                }
            }
        
            $EdgePrivacyAUKeys = @(
                "DoNotTrack",
                "QuicAllowed",
                "SearchSuggestEnabled",
                "AllowSearchAssistant",
                "FormFillEnabled",
                "PaymentMethodQueryEnabled",
                "PersonalizationReportingEnabled",
                "AddressBarMicrosoftSearchInBingProviderEnabled",
                "UserFeedbackAllowed",
                "AutofillCreditCardEnabled",
                "AutofillAddressEnabled",
                "LocalProvidersEnabled",
                "SearchSuggestEnabled",
                "EdgeShoppingAssistantEnabled",
                "WebWidgetAllowed",
                "HubsSidebarEnabled"
            )
        
            $EdgePrivacyAUKeys | ForEach-Object {
                if (-not (Test-Path $EdgePrivacyAUPath)) {
                    New-Item -Path $EdgePrivacyAUPath -Force *>$null
                }
                try {
                    Set-ItemProperty -Path $EdgePrivacyAUPath -Name $_ -Value 0
                    Set-ItemProperty -Path $EdgePrivacyAUPath -Name "ConfigureDoNotTrack" -Value 1
                }
                catch {
                    Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                }
            }
        
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }
        
        EdgePrivacySettings

        Function OfficePrivacySettings {
            Write-Host "Adjusting Microsoft Office privacy settings..." -NoNewline
            $OfficePrivacyRegistryKeys = @{
                "HKCU:\Software\Microsoft\Office\Common\ClientTelemetry"          = @{
                    "DisableTelemetry" = 1
                }
                "HKCU:\Software\Policies\Microsoft\Office\Common\ClientTelemetry" = @{
                    "SendTelemetry" = 3
                }
                "HKCU:\Software\Policies\Microsoft\Office\16.0\Common"            = @{
                    "QMEnable" = 0;
                    "LinkedIn" = 0
                }
                "HKCU:\Software\Microsoft\Office\16.0\Common\MailSettings"        = @{
                    "InlineTextPrediction" = 0
                }
                "HKCU:\Software\Policies\Microsoft\Office\16.0\osm"               = @{
                    "Enablelogging"         = 0;
                    "EnableUpload"          = 0;
                    "EnableFileObfuscation" = 1
                }
                "HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Feedback"   = @{
                    "SurveyEnabled" = 0;
                    "Enabled"       = 0;
                    "IncludeEmail"  = 0
                }
            }
        
            foreach ($key in $OfficePrivacyRegistryKeys.GetEnumerator()) {
                $registryPath = $key.Key
                $registryValues = $key.Value
        
                if (-not (Test-Path $registryPath)) {
                    New-Item -Path $registryPath -Force *>$null
                }
        
                foreach ($valueName in $registryValues.GetEnumerator()) {
                    $value = $valueName.Key
                    $data = $valueName.Value
        
                    try {
                        Set-ItemProperty -Path $registryPath -Name $value -Value $data
                    }
                    catch {
                        Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                    }
                }
            }
        
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }
        
        OfficePrivacySettings  
        
        Function DisableWindowsSync {
            Write-Host "Disabling Windows Sync..." -NoNewline
            $WindowsSyncRegistryKeys = @{
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync"                        = @{
                    "SyncPolicy" = 5
                }
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" = @{
                    "Enabled" = 0
                }
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" = @{
                    "Enabled" = 0
                }
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials"     = @{
                    "Enabled" = 0
                }
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language"        = @{
                    "Enabled" = 0
                }
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility"   = @{
                    "Enabled" = 0
                }
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows"         = @{
                    "Enabled" = 0
                }
            }
        
            foreach ($key in $WindowsSyncRegistryKeys.GetEnumerator()) {
                $registryPath = $key.Key
                $registryValues = $key.Value
        
                if (-not (Test-Path $registryPath)) {
                    New-Item -Path $registryPath -Force *>$null
                }
        
                foreach ($valueName in $registryValues.GetEnumerator()) {
                    $value = $valueName.Key
                    $data = $valueName.Value
        
                    try {
                        Set-ItemProperty -Path $registryPath -Name $value -Value $data
                    }
                    catch {
                        Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                    }
                }
            }
        
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }
        
        DisableWindowsSync        

        # The function is here because programs add themselves to the right click menu after loading
        Function RightClickMenu {
            try {
                Write-Host "Editing the right click menu..." -NoNewline
                # New PS Drives
                New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
        
                # Old right click menu
                $regPath = "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
                reg.exe add $regPath /f /ve *>$null
        
                $contextMenuPaths = @(
                    "HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo", #remove send to
                    "HKEY_CLASSES_ROOT\UserLibraryFolder\shellex\ContextMenuHandlers\SendTo", #remove send to
                    "HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\ModernSharing", #remove share
                    "HKEY_CLASSES_ROOT\*\shell\pintohomefile", #remove favorites
                    #remove give access
                    "HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\Sharing",
                    "HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers\Sharing",
                    "HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\Sharing",
                    "HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers\Sharing",
                    "HKEY_CLASSES_ROOT\LibraryFolder\background\shellex\ContextMenuHandlers\Sharing",
                    "HKEY_CLASSES_ROOT\UserLibraryFolder\shellex\ContextMenuHandlers\Sharing",
                    #remove previous
                    "HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
                    "HKEY_CLASSES_ROOT\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
                    "HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
                    "HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
                    #remove "Include in library"
                    "HKEY_CLASSES_ROOT\Folder\ShellEx\ContextMenuHandlers\Library Location",
                    "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Folder\ShellEx\ContextMenuHandlers\Library Location"
                    #remove "copy as path"
                    "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\CopyAsPathMenu"
                    #remove git
                    "HKEY_CLASSES_ROOT\Directory\Background\shell\git_gui",
                    "HKEY_CLASSES_ROOT\Directory\Background\shell\git_shell",
                    #remove treesize
                    "HKEY_CLASSES_ROOT\Directory\Background\shell\TreeSize Free",
                    "HKEY_CLASSES_ROOT\Directory\Background\shell\VSCode"
                    #remove mpc player
                    "HKEY_CLASSES_ROOT\Directory\shell\mplayerc64.enqueue"
                    #remove sharex
                    "HKEY_CLASSES_ROOT\Directory\shell\ShareX"
                    #remove vlc
                    "HKEY_CLASSES_ROOT\Directory\shell\AddToPlaylistVLC"
                    #remove google drive
                    "HKEY_CLASSES_ROOT\GoogleDriveFS.gcsedoc"
                    "HKEY_CLASSES_ROOT\GoogleDriveFS.gcsesheet"
                    "HKEY_CLASSES_ROOT\GoogleDriveFS.gcseslides"
                    "HKEY_CLASSES_ROOT\GoogleDriveFS.gdoc"
                    "HKEY_CLASSES_ROOT\GoogleDriveFS.gdraw"
                    "HKEY_CLASSES_ROOT\GoogleDriveFS.gdrive"
                    "HKEY_CLASSES_ROOT\GoogleDriveFS.gform"
                    "HKEY_CLASSES_ROOT\GoogleDriveFS.gjam"
                    "HKEY_CLASSES_ROOT\GoogleDriveFS.glink"
                    "HKEY_CLASSES_ROOT\GoogleDriveFS.gmaillayout"
                    "HKEY_CLASSES_ROOT\GoogleDriveFS.gmap"
                    "HKEY_CLASSES_ROOT\GoogleDriveFS.gnote"
                    "HKEY_CLASSES_ROOT\GoogleDriveFS.gscript"
                    "HKEY_CLASSES_ROOT\GoogleDriveFS.gsheet"
                    "HKEY_CLASSES_ROOT\GoogleDriveFS.gsite"
                    "HKEY_CLASSES_ROOT\GoogleDriveFS.gslides"
                    "HKEY_CLASSES_ROOT\GoogleDriveFS.gtable"
                    "HKEY_CLASSES_ROOT\GoogleDriveFS.gvid"
                )
    
                foreach ($path in $contextMenuPaths) {
                    $regPath = $path -replace 'HKCR:\\', 'HKEY_CLASSES_ROOT\' 
                    $cmd = "reg delete `"$regPath`" /f"
                    Invoke-Expression $cmd *>$null
                }
        
                # New hash menu for right click
                $regpath = "HKEY_CLASSES_ROOT\*\shell\hash"
                $sha256menu = "HKEY_CLASSES_ROOT\*\shell\hash\shell\02menu"
                $md5menu = "HKEY_CLASSES_ROOT\*\shell\hash\shell\03menu"
        
                reg add $regpath /f *>$null
                reg add $regpath /v "MUIVerb" /t REG_SZ /d HASH /f *>$null
                reg add $regpath /v "SubCommands" /t REG_SZ /d """" /f *>$null
                reg add "$regpath\shell" /f *>$null
        
                reg add "$sha256menu" /f *>$null
                reg add "$sha256menu\command" /f *>$null
                reg add "$sha256menu" /v "MUIVerb" /t REG_SZ /d SHA256 /f *>$null
        
                $tempOut = [System.IO.Path]::GetTempFileName()
                $tempErr = [System.IO.Path]::GetTempFileName()
                Start-Process cmd.exe -ArgumentList '/c', 'reg add "HKEY_CLASSES_ROOT\*\shell\hash\shell\02menu\command" /ve /d "powershell -noexit get-filehash -literalpath \"%1\" -algorithm SHA256 | format-list" /f' -NoNewWindow -RedirectStandardOutput $tempOut -RedirectStandardError $tempErr
                Remove-Item $tempOut -ErrorAction Ignore
                Remove-Item $tempErr -ErrorAction Ignore
        
                reg add "$md5menu" /f *>$null
                reg add "$md5menu\command" /f *>$null
                reg add "$md5menu" /v "MUIVerb" /t REG_SZ /d MD5 /f *>$null
        
                $tempOut = [System.IO.Path]::GetTempFileName()
                $tempErr = [System.IO.Path]::GetTempFileName()
                Start-Process cmd.exe -ArgumentList '/c', 'reg add "HKEY_CLASSES_ROOT\*\shell\hash\shell\03menu\command" /ve /d "powershell -noexit get-filehash -literalpath \"%1\" -algorithm MD5 | format-list" /f' -NoNewWindow -RedirectStandardOutput $tempOut -RedirectStandardError $tempErr
                Remove-Item $tempOut -ErrorAction Ignore
                Remove-Item $tempErr -ErrorAction Ignore
        
                # Add Turn Off Display Menu
                curl -o "$env:USERPROFILE\Desktop\turn_off_button.reg" https://raw.githubusercontent.com/caglaryalcin/old-right-click/refs/heads/main/turn_off_button.reg
                reg import "$env:USERPROFILE\Desktop\turn_off_button.reg" 2>$null
                Remove-Item "$env:USERPROFILE\Desktop\turn_off_button.reg" -Recurse -ErrorAction Stop
                
                # Add "Find Empty Folders"
                $paths = @(
                    "Registry::HKEY_CLASSES_ROOT\Directory\shell\FindEmptyFolders",
                    "Registry::HKEY_CLASSES_ROOT\Directory\shell\FindEmptyFolders\command",
                    "Registry::HKEY_CLASSES_ROOT\Directory\Background\shell\FindEmptyFolders",
                    "Registry::HKEY_CLASSES_ROOT\Directory\Background\shell\FindEmptyFolders\command",
                    "Registry::HKEY_CLASSES_ROOT\Drive\shell\FindEmptyFolders",
                    "Registry::HKEY_CLASSES_ROOT\Drive\shell\FindEmptyFolders\command"
                )
    
                $icon = "imageres.dll,-1025"
                $defaultValue = "Find Empty Folders"
                $command = 'powershell.exe -NoExit -Command "Get-ChildItem -Path ''%V'' -Directory -Recurse | Where-Object { $_.GetFileSystemInfos().Count -eq 0 } | ForEach-Object { $_.FullName }"'
    
                $paths | ForEach-Object {
                    if (-not (Test-Path $_)) {
                        New-Item -Path $_ -Force | Out-Null
                    }
    
                    if ($_ -like '*command') {
                        Set-ItemProperty -Path $_ -Name "(Default)" -Value $command
                    }
                    else {
                        Set-ItemProperty -Path $_ -Name "(Default)" -Value $defaultValue
                        Set-ItemProperty -Path $_ -Name "Icon" -Value $icon
                    }
                }
                
                # Add blocked keys
                $blockedkeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"
                if (-not (Test-Path -Path $blockedkeyPath)) {
                    New-Item -Path $blockedkeyPath -Force | Out-Null
                }
                else {
                    ##
                }
    
                # Add to "Boot to UEFI Firmware Settings"
                New-Item -Path "HKCR:\DesktopBackground\Shell\Firmware" -Force | Out-Null
                Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\Firmware" -Name "Icon" -Value "bootux.dll,-1016"
                Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\Firmware" -Name "MUIVerb" -Value "Boot to UEFI Firmware Settings"
                Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\Firmware" -Name "Position" -Value "Top"
            
                New-Item -Path "HKCR:\DesktopBackground\Shell\Firmware\command" -Force | Out-Null
                Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\Firmware\command" -Name "(default)" -Value 'powershell.exe -WindowStyle Hidden -Command "Start-Process cmd -ArgumentList ''/s,/c,shutdown /r /fw'' -Verb RunAs"'
    
                # Remove "Edit in Notepad"
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{CA6CC9F1-867A-481E-951E-A28C5E4F01EA}" -Value "Edit in Notepad"
    
                # Remove "Cast to Device"
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" -Value "Play to Menu"
    
                # Restart Windows Explorer
                taskkill /f /im explorer.exe *>$null
                Start-Sleep 1
                Start-Process "explorer.exe" -ErrorAction Stop
        
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
        
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        RightClickMenu

        Function DisableWidgets {
            Write-Host "Disabling Windows Widgets..." -NoNewline
            try {
                Get-AppxPackage -AllUsers -Name *WebExperience* | Remove-AppxPackage -AllUsers *>$null
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            } 
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
    
        }

        DisableWidgets

        # Remove Tasks in Task Scheduler
        Function RemoveTasks {
            $description = @"
+---------------------------------------------+
|    If you apply it,                         |
|    it turns off windows automatic updates,  |
|    you can only update manually.            |
+---------------------------------------------+
"@
            Write-Host `n$description -ForegroundColor Yellow
        
            Write-Host `n"Do you want " -NoNewline
            Write-Host "apps and Windows update tasks to be deleted?" -ForegroundColor Yellow -NoNewline
            Write-Host "(y/n): " -ForegroundColor Green -NoNewline
            
            $response = Read-Host
        
            if ($response -eq 'y' -or $response -eq 'Y') {
                Write-Host "Removing Unnecessary Tasks..." -NoNewline
                $taskPatterns = @("OneDrive*", "MicrosoftEdge*", "Google*", "Brave*", "Intel*", "klcp*", "MSI*", 
                    "*Adobe*", "CCleaner*", "G2M*", "Opera*", "Overwolf*", "User*", "CreateExplorer*", "{*", "*Samsung*", "*npcap*", 
                    "*Consolidator*", "*Dropbox*", "*Heimdal*", "*klcp*", "*UsbCeip*", "*DmClient*", "*Office Auto*", "*Office Feature*", 
                    "*OfficeTelemetry*", "*GPU*", "Xbl*", "Firefox Back*")
                        
                $windowsUpdateTasks = @(
                    "\Microsoft\Windows\WindowsUpdate\Scheduled Start",
                    "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
                    "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task",
                    "\Microsoft\Windows\UpdateOrchestrator\Schedule Work",
                    "\Microsoft\Windows\UpdateOrchestrator\Report policies",
                    "\Microsoft\Windows\UpdateOrchestrator\UpdateModelTask",
                    "\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker",
                    "\Microsoft\Windows\WaaSMedic\PerformRemediation"
                )
                        
                $allTasks = Get-ScheduledTask
                        
                foreach ($task in $allTasks) {
                    $taskName = $task.TaskName
                    $remove = $false
                        
                    foreach ($pattern in $taskPatterns) {
                        if ($taskName -like $pattern) {
                            $remove = $true
                            break
                        }
                    }
                        
                    if ($windowsUpdateTasks -contains $task.TaskPath + $taskName) {
                        $remove = $true
                    }
                        
                    if ($remove) {
                        try {
                            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
                        }
                        catch {
                            Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                        }
                    }
                }

                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 

            }
            elseif ($response -eq 'n' -or $response -eq 'N') {
                Write-Host "[Unused tasks will not be deleted.]" -ForegroundColor Red -BackgroundColor Black
            }
            else {
                Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
                RemoveTasks
            }
        }
        
        RemoveTasks

        # Disable Copilot
        Function DisableCopilot {
            Write-Host `n"Do you want " -NoNewline
            Write-Host "to disable Microsoft Copilot?" -ForegroundColor Yellow -NoNewline
            Write-Host "(y/n): " -ForegroundColor Green -NoNewline
            $response = Read-Host
        
            if ($response -eq 'y' -or $response -eq 'Y') {
                Write-Host "Disabling Microsoft Copilot..." -NoNewline
                
                $registryPath = "HKCU:\Software\Policies\Microsoft\Windows"
                $registryName = "WindowsCopilot"
                $registryProperty = "TurnOffWindowsCopilot"
                $edgeRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
                $explorerRegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
                
                if (-not (Test-Path $registryPath)) {
                    New-Item -Path $registryPath -Name $registryName -Force *>$null
                }
                
                New-ItemProperty -Path $registryPath\$registryName -Name $registryProperty -Value 1 -PropertyType DWORD -Force *>$null
                
                if (-not (Test-Path $edgeRegistryPath)) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\" -Name "Edge" -Force *>$null
                }
                
                New-ItemProperty -Path $edgeRegistryPath -Name "HubsSidebarEnabled" -Value 0 -PropertyType DWORD -Force *>$null
        
                # Remove Copilot button from File Explorer
                Set-ItemProperty -Path $explorerRegistryPath -Name "ShowCopilotButton" -Value 0 -Force *>$null
                
                $lmRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows"
                $wowRegistryPath = "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows"
                
                if (-not (Test-Path $lmRegistryPath\$registryName)) {
                    New-Item -Path $lmRegistryPath -Name $registryName -Force *>$null
                }
                
                Set-ItemProperty -Path $lmRegistryPath\$registryName -Name $registryProperty -Value 1 -Force *>$null
        
                if (-not (Test-Path $wowRegistryPath\$registryName)) {
                    New-Item -Path $wowRegistryPath -Name $registryName -Force *>$null
                }
                
                Set-ItemProperty -Path $wowRegistryPath\$registryName -Name $registryProperty -Value 1 -Force *>$null

                $currentSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
                If (-not (Test-Path "HKU:\$currentSID\Software\Policies\Microsoft\Windows\WindowsCopilot")) {
                    New-Item -Path "HKU:\$currentSID\Software\Policies\Microsoft\Windows" -Name "WindowsCopilot" -Force *>$null
                }
                Set-ItemProperty -Path "HKU:\$currentSID\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1
        
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            elseif ($response -eq 'n' -or $response -eq 'N') {
                Write-Host "[Copilot will not be disabled]" -ForegroundColor Red -BackgroundColor Black
            }
            else {
                Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
                DisableCopilot
            }
        }
        
        DisableCopilot        

        # Uninstall OneDrive
        Function UninstallOneDrive {
            Write-Host `n"Do you want " -NoNewline
            Write-Host "uninstall Microsoft OneDrive?" -ForegroundColor Yellow -NoNewline
            Write-Host "(y/n): " -ForegroundColor Green -NoNewline
            $response = Read-Host
            if ($response -eq 'y' -or $response -eq 'Y') {
                Write-Host "Removing Microsoft OneDrive..." -NoNewline
                Silent #silently
                try {
                    # Stop OneDrive and Explorer processes
                    taskkill /f /im OneDrive.exe *>$null

                    # Uninstall OneDrive
                    $OneDriveSetupPaths = @(
                        "$env:systemroot\System32\OneDriveSetup.exe",
                        "$env:systemroot\SysWOW64\OneDriveSetup.exe"
                    )

                    foreach ($Path in $OneDriveSetupPaths) {
                        if (Test-Path $Path) {
                            & $Path /uninstall
                        }
                    }

                    $OneDriveFolders = @(
                        "$env:localappdata\Microsoft\OneDrive",
                        "$env:programdata\Microsoft OneDrive",
                        "$env:systemdrive\OneDriveTemp",
                        "$env:userprofile\OneDrive"
                    )

                    $OneDriveFolders | ForEach-Object {
                        Remove-Item -Path $_ -Recurse -Force -ErrorAction SilentlyContinue
                    }

                    New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
                    $OneDriveClsid = "{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
                    $ClsidPaths = @(
                        "HKCR:\CLSID\$OneDriveClsid",
                        "HKCR:\Wow6432Node\CLSID\$OneDriveClsid"
                    )

                    foreach ($Path in $ClsidPaths) {
                        if (-not (Test-Path $Path)) {
                            New-Item -Path $Path -Force | Out-Null
                            Set-ItemProperty -Path $Path -Name "System.IsPinnedToNameSpaceTree" -Value 0
                        }
                    }

                    If (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive") {
                        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
                    }

                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Force -ErrorAction SilentlyContinue

                    # Remove OneDrive from the registry
                    reg load "HKU\Default" "C:\Users\Default\NTUSER.DAT" *>$null
                    reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f *>$null
                    reg unload "HKU\Default" *>$null
                    
                    Remove-Item -Path "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force -ErrorAction SilentlyContinue

                    Start-Sleep 3
                    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black

                }
                catch {
                    Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                }
                
            }
            elseif ($response -eq 'n' -or $response -eq 'N') {
                Write-Host "[Windows OneDrive will not be deleted]" -ForegroundColor Red -BackgroundColor Black
            }
            else {
                Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
                UninstallOneDrive
            }
        }
        
        UninstallOneDrive

        # Disable Edge desktop shortcut creation after certain Windows updates are applied 
        Function UninstallEdge {
            Write-Host `n"Do you want " -NoNewline
            Write-Host "uninstall Microsoft Edge?" -ForegroundColor Yellow -NoNewline
            Write-Host "(y/n): " -ForegroundColor Green -NoNewline
            $response = Read-Host
            if ($response -eq 'y' -or $response -eq 'Y') {
                Write-Host "Removing Microsoft Edge..." -NoNewline

                try {
                    taskkill /f /im msedge.exe *>$null 2>&1
                    taskkill /f /im explorer.exe *>$null 2>&1
        
                    # Remove Edge Services
                    $edgeservices = "edgeupdate", "edgeupdatem"
                    foreach ($service in $edgeservices) {
                        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                        Set-Service -Name $service -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
                        sc.exe delete $service *>$null 2>&1
                    }
        
                    # Uninstall - Edge
                    $regView = [Microsoft.Win32.RegistryView]::Registry32
                    $microsoft = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $regView).OpenSubKey('SOFTWARE\Microsoft', $true)
                    $edgeClient = $microsoft.OpenSubKey('EdgeUpdate\ClientState\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}', $true)
                    if ($null -ne $edgeClient.GetValue('experiment_control_labels')) {
                        $edgeClient.DeleteValue('experiment_control_labels')
                    }
        
                    $microsoft.CreateSubKey('EdgeUpdateDev').SetValue('AllowUninstall', '')
        
                    $uninstallRegKey = $microsoft.OpenSubKey('Windows\CurrentVersion\Uninstall\Microsoft Edge')
                    $uninstallString = $uninstallRegKey.GetValue('UninstallString') + ' --force-uninstall'
                    Silent #silently
                    Start-Process cmd.exe "/c $uninstallString" -WindowStyle Hidden
        
                    $appxStore = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
                    $pattern = "HKLM:$appxStore\InboxApplications\Microsoft.MicrosoftEdge_*_neutral__8wekyb3d8bbwe"
                    $key = (Get-Item -Path $pattern).PSChildName
                    reg delete "HKLM$appxStore\InboxApplications\$key" /f *>$null
        
                    #if error use this > $SID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                    $user = "$env:USERDOMAIN\$env:USERNAME"
                    (New-Object System.Security.Principal.NTAccount($user)).Translate([System.Security.Principal.SecurityIdentifier]).Value *>$null
                    New-Item -Path "HKLM:$appxStore\EndOfLife\$SID\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" -Force *>$null
                    Get-AppxPackage -Name Microsoft.MicrosoftEdge | Remove-AppxPackage -ErrorAction SilentlyContinue
                    Remove-Item -Path "HKLM:$appxStore\EndOfLife\$SID\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" -ErrorAction SilentlyContinue
        
                    # Delete additional files
                    $additionalFilesPath = "C:\Windows\System32\MicrosoftEdgeCP.exe"
                    if (Test-Path -Path $additionalFilesPath) {
                        $additionalFiles = Get-ChildItem -Path "C:\Windows\System32\MicrosoftEdge*" -File
                        foreach ($file in $additionalFiles) {
                            $takeownArgs = "/f $($file.FullName)"
                            Start-Process -FilePath "takeown.exe" -ArgumentList $takeownArgs -Wait | Out-Null
                            $icaclsArgs = "`"$($file.FullName)`" /inheritance:e /grant `"$($env:UserName)`":(OI)(CI)F /T /C"
                            Start-Process -FilePath "icacls.exe" -ArgumentList $icaclsArgs -Wait | Out-Null
                            Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
                        }
                    }
        
                    $keyPath = "HKLM:\SOFTWARE\Microsoft\EdgeUpdate"
                    $propertyName = "DoNotUpdateToEdgeWithChromium"
                    if (-not (Test-Path $keyPath)) {
                        New-Item -Path $keyPath -Force | Out-Null
                    }
                    Set-ItemProperty -Path $keyPath -Name $propertyName -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        
                    taskkill /f /im "MicrosoftEdgeUpdate.exe" *>$null
        
                    $edgeDirectories = Get-ChildItem -Path "C:\Program Files (x86)\Microsoft" -Filter "Edge*" -Directory -ErrorAction SilentlyContinue
                    if ($edgeDirectories) {
                        $edgeDirectories | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                    }
        
                    $progressPreference = 'SilentlyContinue'
                    Get-AppxPackage -AllUsers Microsoft.Edge | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
        
                    $paths = @(
                        "C:\Program Files (x86)\Microsoft\*edge*",
                        "C:\Program Files (x86)\Microsoft\Edge",
                        "C:\Program Files (x86)\Microsoft\Temp",
                        "C:\Program Files (x86)\Microsoft\*"
                    )
        
                    foreach ($path in $paths) {
                        $items = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue
                        if ($items) {
                            Remove-Item -Path $path -Force -Recurse -ErrorAction SilentlyContinue *>$null
                        }
                    }
        
                    # Final check if Edge is still installed
                    if (!(Get-Process "msedge" -ErrorAction SilentlyContinue)) {
                        Start-Process explorer.exe -NoNewWindow
                        Start-Sleep 4
                        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                    }
                    else {
                        throw "Microsoft Edge process is still running."
                    }

                    # Delete the lnk files in the taskbar
                    $edgedesktop = "$env:USERPROFILE\Desktop\"
                    $taskBarPath = "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
                    $taskBarPath1 = "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\"
                    $taskBarPath2 = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs"
                    $shortcuts = "Microsoft Edge.lnk", "Microsoft Teams classic.lnk"

                    $shortcuts | ForEach-Object {
                        $fullPath1 = Join-Path $taskBarPath $_
                        $fullPath2 = Join-Path $taskBarPath1 $_
                        $fullPath3 = Join-Path $taskBarPath2 $_
                        $desktoppath = Join-Path $edgedesktop $_

                        if (Test-Path $fullPath1) {
                            Remove-Item $fullPath1 -ErrorAction Stop
                        }

                        if (Test-Path $fullPath2) {
                            Remove-Item $fullPath2 -ErrorAction Stop
                        }

                        if (Test-Path $fullPath3) {
                            Remove-Item $fullPath3 -ErrorAction Stop
                        }

                        if (Test-Path $desktoppath) {
                            Remove-Item $desktoppath -ErrorAction Stop
                        }
                    }

                    # Remove Edge tasks
                    $tasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "*edge*" }

                    foreach ($task in $tasks) {
                        Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false
                    }

                }
                catch {
                    Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                }
        
            }
            elseif ($response -eq 'n' -or $response -eq 'N') {

                # Disable Edge Services
                $edgeservices = "edgeupdate", "edgeupdatem"
                foreach ($service in $edgeservices) {
                    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $service -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
                }
                Write-Host "[Windows Edge will not be uninstalled]" -ForegroundColor Red -BackgroundColor Black
        
            }
            else {
                Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
                UninstallEdge
            }
        }

        UninstallEdge

        Function RemoveRecall {
            Write-Host "Removing Windows 11 Recall..." -NoNewline
            try {
                Silent
                DISM /Online /Disable-Feature /FeatureName:"Recall"​ *>$null
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }

        RemoveRecall

        Function Removelnks {
            Write-Host "Removing Desktop shortcuts..." -NoNewline
            try {
                Get-ChildItem C:\users\Public\Desktop\*.lnk | ForEach-Object { Remove-Item $_ -ErrorAction SilentlyContinue } *>$null
                Get-ChildItem $env:USERPROFILE\Desktop\*.lnk | ForEach-Object { Remove-Item $_ -ErrorAction SilentlyContinue } *>$null
                Get-ChildItem -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }

        Removelnks
                
    }
    elseif ($response -eq 'n' -or $response -eq 'N') {
        Write-Host "[Unnecessary apps will not be uninstalled]" -ForegroundColor Red -BackgroundColor Black
    }
    else {
        Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
        UnusedApps
    }
}

UnusedApps

Function TaskbarPins {
    Write-Host "Configure the pins of taskbar icons..." -NoNewline
    try {
        # Create Icons folder
        New-Item -Path 'C:\icons' -ItemType Directory *>$null
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

        # Discord
        $discordfoldername = Get-ChildItem -Path "$env:USERPROFILE\AppData\Local\Discord\" -Directory | Where-Object { $_.Name -like "app*" -and $_.Name -ne "packages" } | Select-Object -ExpandProperty Name
                
        Function CreateShortcuts {
            $defaultPaths = @{
                "Google Chrome" = @{
                    "DefaultPath"    = "$env:USERPROFILE\AppData\Local\Google\Chrome\Application\chrome.exe";
                    "ChocolateyPath" = "C:\Program Files\Google\Chrome\Application\chrome.exe";
                };
            }
                
            $shortcutPaths = @{
                "Discord"             = @{
                    "Path"             = "$env:USERPROFILE\AppData\Local\Discord\$discordfoldername\Discord.exe";
                    "WorkingDirectory" = "$env:USERPROFILE\AppData\Local\Discord\$discordfoldername";
                };
                "Steam"               = @{
                    "Path"             = "C:\Program Files (x86)\Steam\Steam.exe";
                    "WorkingDirectory" = "C:\Program Files (x86)\Steam\";
                };
                "Epic Games Launcher" = @{
                    "Path"             = "C:\Program Files (x86)\Epic Games\Launcher\Portal\Binaries\Win32\EpicGamesLauncher.exe";
                    "WorkingDirectory" = "C:\Program Files (x86)\Epic Games\";
                };
                "Battle.net"          = @{
                    "Path"             = "C:\Program Files (x86)\Battle.net\Battle.net.exe";
                    "WorkingDirectory" = "C:\Program Files (x86)\Battle.net";
                };
                "Ubisoft Connect"     = @{
                    "Path"             = "C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\UbisoftConnect.exe";
                    "WorkingDirectory" = "C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher";
                };
                "EA Desktop"          = @{
                    "Path"             = "C:\Program Files\Electronic Arts\EA Desktop\EA Desktop\EADesktop.exe";
                    "WorkingDirectory" = "C:\Program Files\Electronic Arts\EA Desktop\EA Desktop";
                };
            }
                
            # Create shortcuts for the default paths
            foreach ($program in $defaultPaths.Keys) {
                $paths = $defaultPaths[$program]
                $pathFound = $false
                
                foreach ($pathType in $paths.Keys) {
                    $path = $paths[$pathType] -replace '\$env:USERPROFILE', $env:USERPROFILE
                
                    if (Test-Path $path) {
                        $workingDirectory = Split-Path -Parent $path
                        $shortcutFile = "C:\icons\$program.lnk"
                        CreateShortcut -exePath $path -shortcutPath $shortcutFile -workingDirectory $workingDirectory
                        $pathFound = $true
                        break
                    }
                }
                
                if (-not $pathFound) {
                    Write-Host "[INFO] Failed to create shortcut, path to program not found: $program" -ForegroundColor Yellow -BackgroundColor Black -NoNewline
                }
            }
                
            # Create shortcuts for the custom paths
            foreach ($program in $shortcutPaths.Keys) {
                $details = $shortcutPaths[$program]
                $path = $details["Path"] -replace '\$env:USERPROFILE', $env:USERPROFILE
                $workingDirectory = $details["WorkingDirectory"] -replace '\$env:USERPROFILE', $env:USERPROFILE
                $arguments = $details["Arguments"]
                
                if (Test-Path $path) {
                    $shortcutFile = "C:\icons\$program.lnk"
                    CreateShortcut -exePath $path -shortcutPath $shortcutFile -workingDirectory $workingDirectory -arguments $arguments
                }
                else {
                    Write-Host "[INFO] Failed to create shortcut, path to program not found: $program" -ForegroundColor Yellow -BackgroundColor Black -NoNewline
                }
            }
        }
                
        CreateShortcuts

        # Remove registry path of all taskbar icons
        Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Recurse -Force -ErrorAction Stop
            
        # Set taskbar icons and pin to taskbar
        # Download the registry file
        $taskbarpin = "https://raw.githubusercontent.com/caglaryalcin/after-format/refs/heads/main/files/apps/gaming/taskbar.reg"
        $progressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $taskbarpin -Outfile "C:\taskbar_pin.reg" -ErrorAction Stop
            
        # Import the registry file
        reg import "C:\taskbar_pin.reg" *>$null
        # Copy the icons to the taskbar
        Copy-Item -Path "C:\icons\*" -Destination "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\" -Force -ErrorAction Stop
        # Apply the registry file import again
        reg import "C:\taskbar_pin.reg" *>$null
        # kill explorer
        taskkill /f /im explorer.exe *>$null

        # Delete registry file and icons folder
        Remove-Item "C:\taskbar_pin.reg" -Recurse -ErrorAction Stop
        Start-Sleep 1

        Start-Process "explorer.exe" -ErrorAction Stop
        Start-Sleep 1

        Remove-Item "C:\icons\" -Recurse -ErrorAction Stop
        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    }
    catch {
        Write-Host "[WARNING]: $_" -ForegroundColor Red -BackgroundColor Black
    }
            
}

if ($mode -eq "gaming") {
    TaskbarPins
}

Function EnableTask {
    Write-Host "Enabling upgrade-packages task..."
    Enable-ScheduledTask -TaskName "upgrade-packages" *>$null
    Enable-ScheduledTask -TaskName "startup" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

EnableTask

##########
#endregion Remove Unused Apps/Softwares
##########

Function Restart {
    Write-Host `n"Do you " -NoNewline
    Write-Host "want restart?" -NoNewline -ForegroundColor Red -BackgroundColor Black
    Write-Host "(y/n): " -NoNewline
    $response = Read-Host

    if ($response -eq 'y' -or $response -eq 'Y') {
        cmd.exe /c "shutdown /r /t 0"
    }
    elseif ($response -eq 'n' -or $response -eq 'N') {
        Write-Host("[Restart process cancelled]") -ForegroundColor Red -BackgroundColor Black
    }
    else {
        Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
    }
 
}

Restart