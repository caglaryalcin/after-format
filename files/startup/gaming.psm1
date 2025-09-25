#region Set MAP

$ErrorActionPreference = 'SilentlyContinue'
New-PSDrive -PSProvider Registry -Name HKCU -Root HKEY_CURRENT_USER
New-PSDrive -PSProvider Registry -Name HKLM -Root HKEY_LOCAL_MACHINE
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
$ErrorActionPreference = 'Continue'


# Remove Toggle and Sticky Keys and File Explorer Ribbon Settings
Function RibbonandKeys {
    # File Explorer Ribbon Settings
    $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon"
    
    if (-Not (Test-Path $path)) {
        New-Item -Path $path | Out-Null
    }
    
    $settings = @{
        "MinimizedStateTabletModeOff" = 0;
        "Minimized"                   = 0;
    }
    
    foreach ($name in $settings.Keys) {
        Set-ItemProperty -Path $path -Name $name -Value $settings[$name] -Type DWord
    }
    
    # Remove Toggle and Sticky Keys
    $combinedSettings = @{
        "HKCU:\Control Panel\Accessibility\StickyKeys"        = @{ "Flags" = "506" }; # 506 Off, 510 On
        "HKCU:\Control Panel\Accessibility\Keyboard Response" = @{ "Flags" = "122" }; # 122 Off, 126 On
        "HKCU:\Control Panel\Accessibility\ToggleKeys"        = @{ "Flags" = "58" }; # 58 Off, 62 On
        "HKCU:\Keyboard Layout\Toggle"                        = @{ "Language HotKey" = "3"; "Layout HotKey" = "3" };
    }

    foreach ($path in $combinedSettings.Keys) {
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }

        foreach ($prop in $combinedSettings[$path].GetEnumerator()) {
            Set-ItemProperty -Path $path -Name $prop.Key -Value $prop.Value -Type String
        }
    }
}

RibbonandKeys

# Remove Tasks in Task Scheduler
Function RemoveTasks {
    Write-Host "Removing Unnecessary Tasks..." -NoNewline

    $taskPatterns = @("OneDrive*", "MicrosoftEdge*", "Google*", "Brave*", "Intel*", 
        "update*", "klcp*", "MSI*", "*Adobe*", "CCleaner*", "G2M*", "Opera*", 
        "Overwolf*", "User*", "CreateExplorer*", "{*", "*Samsung*", "*npcap*", 
        "*Consolidator*", "*Dropbox*", "*Heimdal*", "*klcp*", "*UsbCeip*", 
        "*DmClient*", "*Office Auto*", "*Office Feature*", "*OfficeTelemetry*", 
        "*GPU*", "Xbl*", "Autorun*", "BackgroundDownload*", "ScheduledDefrag",
        "ProactiveScan", "SilentCleanup", "UsageDataReportin", "ReconcileFeatures", 
        "PenSyncDataAvailable", "LocalUserSyncDataAvailable", "MouseSyncDataAvailable", 
        "TouchpadSyncDataAvailable", "Synchronize Language Settings", "PrinterCleanupTask",
        "SpeechModelDownloadTask", "QueueReporting", "Scheduled Start", "Firefox Back*")

    $allTasks = Get-ScheduledTask

    foreach ($pattern in $taskPatterns) {
        $filteredTasks = $allTasks | Where-Object { $_.TaskName -like $pattern }
        foreach ($task in $filteredTasks) {
            Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false
        }
    }
}

RemoveTasks

# Hide Defender Tray Icon
Function HideDefenderTrayIcon {
    $defenderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray"
    $runPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    
    # Ensure the registry key exists
    If (!(Test-Path $defenderPath)) {
        New-Item -Path $defenderPath -Force *>$null
    }
    
    # Set the property to hide the systray icon
    Set-ItemProperty -Path $defenderPath -Name "HideSystray" -Type DWord -Value 1

    # Check OS build version and remove specific properties
    $osBuild = [System.Environment]::OSVersion.Version.Build
    Switch ($osBuild) {
        14393 {
            if (Test-Path $runPath) {
                Remove-ItemProperty -Path $runPath -Name "WindowsDefender" -ErrorAction SilentlyContinue
            }
        }
        { $_ -ge 15063 } {
            if (Test-Path $runPath) {
                Remove-ItemProperty -Path $runPath -Name "SecurityHealth" -ErrorAction SilentlyContinue
            }
        }
    }
}

HideDefenderTrayIcon

# Disable Startup App 
Function DisableStartupApps {
    $StartPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32\", 
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run\",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\", 
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\", 
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run\"
    )
        
    $StartFilePaths = @(
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    
    $removeList = @(
        "Security*", "*Teams*", "Microsoft team*", "*Update*", #Microsoft & Updates
        "NVD*", "NVI*", "NVN*", "NVP*", "*NVT*", #Nvidia
        "*CCX*", "Adobe*", "*CC*", #Adobe
        "*uTorrent*", "*Deluge*", #Torrent
        "*Brave*", "Google*", "*Chrome*", "*Opera*", "*vivaldi", "*Edge*", "*Yandex*", "*Firefox*", "*Librewolf*", #Browsers
        "*EADM*", "*Java*", "*cisco*", "*npcap*", "*IDMan*", "*Disc*", "*CORS*", "*Next*", "*One*", "*iTunes*", "*iTunes*", "*Ai*", "*Skype*",
        "*vmware*", "*Any*", "Tailscale*", "Docker*", "GarminExpress" #Other
    )
    
    # Remove from registry
    foreach ($path in $StartPaths) {
        foreach ($item in $removeList) {
            Remove-ItemProperty -Path $path -Name $item
        }
    }
    
    # Remove from startup folders
    foreach ($folder in $StartFilePaths) {
        Get-ChildItem -Path $folder -Recurse | 
        Where-Object { 
            $item = $_.Name
            foreach ($pattern in $removeList) {
                if ($item -like $pattern) {
                    return $true
                }
            }
            return $false
        } | 
        Remove-Item -Force -Recurse
    }

}
    
DisableStartupApps

# Remove Edge Updates

Function RemoveEdgeUpdates {
    # Remove Edge lnk file
    Get-ChildItem -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

    # Registry keys and files to remove
    $registryPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Services\edgeupdate",
        "HKLM:\SYSTEM\CurrentControlSet\Services\edgeupdatem",
        "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}"
    )

    # Check if registry keys exist and remove them if they do
    foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            Remove-Item -Path $path -Recurse -Force
        }
    }

    # Services to stop and disable
    $edgeservices = @("edgeupdate", "edgeupdatem")

    # Check if services exist, stop them, disable them, and delete them
    foreach ($service in $edgeservices) {
        $serviceObject = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($serviceObject -ne $null) {
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Set-Service -Name $service -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
            sc.exe delete $service *>$null 2>&1
        }
    }
}

RemoveEdgeUpdates

# Remove Chrome Updates
Function RemoveChromeUpdates {
    # Registry keys and files to remove
    $registryPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Services\gupdate",
        "HKLM:\SYSTEM\CurrentControlSet\Services\gupdatem",
        "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{8A69D345-D564-463c-AFF1-A69D9E530F96}"
    )

    # Check if registry keys exist and remove them if they do
    foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            Remove-Item -Path $path -Recurse -Force
        }
    }

    # Services to stop and disable
    $chromeservices = @("gupdate", "gupdatem")

    # Check if services exist, stop them, disable them, and delete them
    foreach ($service in $chromeservices) {
        $serviceObject = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($serviceObject -ne $null) {
            if ($serviceObject.Status -ne 'Stopped' -or $serviceObject.StartType -ne 'Disabled') {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                sc.exe delete $service *>$null 2>&1
            }
        }
    }
}

RemoveChromeUpdates

# Sync Time
Function SyncTime {
    Set-Service -Name "W32Time" -StartupType Automatic
    Restart-Service -Name "W32Time" -Force

    w32tm /resync /force *>$null
    w32tm /config /manualpeerlist:time.windows.com, 0x1 /syncfromflags:manual /reliable:yes /update *>$null
}

SyncTime

Function UpdateRegistrySettings {
    param (
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWord"
    )
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
}

Function ApplySettings {
    # Disable Print Screen key for Snipping Tool
    UpdateRegistrySettings -Path "HKCU:\Control Panel\Keyboard" -Name "PrintScreenKeyForSnippingEnabled" -Value 0

    # Disable search box in taskbar
    UpdateRegistrySettings -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0

    # Set windows 11 taskbar corner overflow icons
    $registryPath = "HKCU:\Control Panel\NotifyIconSettings"
    Get-ChildItem -Path $registryPath | ForEach-Object {
        UpdateRegistrySettings -Path "$registryPath\$($_.PSChildName)" -Name "IsPromoted" -Value 1
    }

    # Show Desktop Button
    $advancedPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    if (-not (Test-Path $advancedPath)) {
        New-Item -Path $advancedPath -Force | Out-Null
    }
    UpdateRegistrySettings -Path $advancedPath -Name "TaskbarSd" -Value 1
}

ApplySettings