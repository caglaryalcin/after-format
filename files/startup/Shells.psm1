##########
#region Set MAP
##########
$ErrorActionPreference = 'SilentlyContinue'
New-PSDrive -PSProvider Registry -Name HKCU -Root HKEY_CURRENT_USER
New-PSDrive -PSProvider Registry -Name HKLM -Root HKEY_LOCAL_MACHINE
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
$ErrorActionPreference = 'Continue'
##########
#endregion MAP
##########

Function TRFormats {
    Set-TimeZone -Name "Turkey Standard Time" -ErrorAction Stop
    Set-Culture tr-TR -ErrorAction Stop
    Set-ItemProperty -Path "HKCU:\Control Panel\International" -name ShortDate -value "dd/MM/yyyy" -ErrorAction Stop

    #sync time
    Set-Service -Name "W32Time" -StartupType Automatic -ErrorAction Stop
    Restart-Service W32Time *>$null
    if (-not $?) { throw "Failed to stop W32Time" }
    w32tm /resync /force *>$null
    if (-not $?) { throw "Failed to resync time" }
    w32tm /config /manualpeerlist:"time.windows.com" /syncfromflags:manual /reliable:yes /update *>$null
    if (-not $?) { throw "Failed to configure time sync settings" }
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

TRFormats

# Show language bar
Function ShowLanguageBar {
    # Show language bar
    Set-WinLanguageBarOption -UseLegacySwitchMode
}

ShowLanguageBar

Function FileExplorerExpandRibbon {
    Write-Host "Expanding for File Explorer..." -NoNewline
    
    $allSuccessful = $true
    $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon"
    
    if (-Not (Test-Path $path)) {
        try {
            New-Item -Path $path -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Host "[WARNING] Error: $_" -ForegroundColor Red
            $allSuccessful = $false
        }
    }
    
    $settings = @{
        "MinimizedStateTabletModeOff" = 0;
        "Minimized"                   = 0;
    }
    
    foreach ($name in $settings.Keys) {
        try {
            Set-ItemProperty -Path $path -Name $name -Value $settings[$name] -Type DWord -ErrorAction Stop
        }
        catch {
            Write-Host "[WARNING] Error: $_" -ForegroundColor Red
            $allSuccessful = $false
        }
    }
    
    if ($allSuccessful) {
        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    }
    else {
        Write-Host "[COMPLETED WITH ERRORS]" -ForegroundColor Yellow -BackgroundColor Black
    }
}
    
FileExplorerExpandRibbon

# Remove Sticky Keys
Function RemoveStickyKeys {
    $settings = @{
        "HKCU:\Control Panel\Accessibility\StickyKeys"        = @{ "Flags" = "506" }  # 506 Off, 510 On
        "HKCU:\Control Panel\Accessibility\Keyboard Response" = @{ "Flags" = "122" }  # 122 Off, 126 On
        "HKCU:\Control Panel\Accessibility\ToggleKeys"        = @{ "Flags" = "58" }   # 58 Off, 62 On
    }

    foreach ($path in $settings.Keys) {
        # Ensure the registry key exists
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force *>$null
        }

        # Set the properties
        foreach ($prop in $settings[$path].GetEnumerator()) {
            Set-ItemProperty -Path $path -Name $prop.Key -Type String -Value $prop.Value -ErrorAction SilentlyContinue
        }
    }
}

RemoveStickyKeys

# Set WinLanguageBarOption
Function SetWinLanguageBarOption {
    Set-WinLanguageBarOption
}

SetWinLanguageBarOption

# Remove Toggle Keys
Function RemoveToggleKeys {
    $registryPaths = @(
        "HKCU:\Keyboard Layout\Toggle",
        "HKU:\.DEFAULT\Keyboard Layout\Toggle"
    )

    $properties = @{
        "Language HotKey" = "3"
        "Layout HotKey"   = "3"
    }

    foreach ($path in $registryPaths) {
        # Ensure the registry key exists
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force *>$null
        }

        # Set the properties
        foreach ($prop in $properties.GetEnumerator()) {
            New-ItemProperty -Path $path -Name $prop.Key -Type String -Value $prop.Value -ErrorAction SilentlyContinue | Out-Null
        }
    }
}

RemoveToggleKeys

# Remove Tasks in Task Scheduler
Function RemoveTasks {
    Write-Host "Removing Unnecessary Tasks..." -NoNewline
    
    #BackgroundDownload - VSCode Updates
    #ScheduledDefrag - Defrag
    #ProactiveScan - Checkdisk
    #SilentCleanup - Disk Cleanup
    #UsageDataReportin/ReconcileFeatures - Task periodically logging feature usage reports
    #PenSyncDataAvailable/LocalUserSyncDataAvailable/MouseSyncDataAvailable/TouchpadSyncDataAvailable
    #Synchronize Language Settings - Synchronize User Language Settings from other devices
    #PrinterCleanupTask - Clean Printer Processes
    #SpeechModelDownloadTask - The Windows operating system offers several speech recognition features
    #QueueReporting - Windows Error Reporting task to process queued reports
    #Scheduled Start - This task is used to start the Windows Update service when needed to perform scheduled operations such as scans

    $taskPatterns = @("OneDrive*", "MicrosoftEdge*", "Google*", "Brave*", "Intel*", 
        "update-s*", "klcp*", "MSI*", "*Adobe*", "CCleaner*", "G2M*", "Opera*", 
        "Overwolf*", "User*", "CreateExplorer*", "{*", "*Samsung*", "*npcap*", 
        "*Consolidator*", "*Dropbox*", "*Heimdal*", "*klcp*", "*UsbCeip*", 
        "*DmClient*", "*Office Auto*", "*Office Feature*", "*OfficeTelemetry*", 
        "*GPU*", "Xbl*", "Autorun*", "BackgroundDownload*", "ScheduledDefrag",
        "ProactiveScan", "SilentCleanup", "UsageDataReportin", "ReconcileFeatures", 
        "PenSyncDataAvailable", "LocalUserSyncDataAvailable", "MouseSyncDataAvailable", 
        "TouchpadSyncDataAvailable", "Synchronize Language Settings", "PrinterCleanupTask",
        "SpeechModelDownloadTask", "QueueReporting", "Scheduled Start")

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
    
        if ($remove) {
            try {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
            }
            catch {
                Write-Host "`n[WARNING]: Error: $_" -ForegroundColor Red
            }
        }
    }
    
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}
    
RemoveTasks

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
            Remove-ItemProperty -Path $runPath -Name "WindowsDefender" -ErrorAction SilentlyContinue
        }
        { $_ -ge 15063 } {
            Remove-ItemProperty -Path $runPath -Name "SecurityHealth" -ErrorAction SilentlyContinue
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
        "*NV*", #Nvidia
        "*CCX*", "Adobe*", "*CC*", #Adobe
        "*uTorrent*", "*Deluge*", #Torrent
        "FACEIT*", "*Riot*", "*Epic*", "*Vanguard*", "*Blitz*", #Gaming
        "*Brave*", "Google*", "*Chrome*", "*Opera*", "*vivaldi", "*Edge*", "*Yandex*", "*Firefox*", "*Librewolf*", #Browsers
        "*EADM*", "*Java*", "*cisco*", "*npcap*", "*IDMan*", "*Disc*", "*CORS*", "*Next*", "*One*", "*iTunes*", "*iTunes*", "*Ai*", "*Skype*",
        "*vmware*", "*Any*", "Tailscale*", "Docker*" #Other
    )
    
    # Remove from registry
    foreach ($path in $StartPaths) {
        foreach ($item in $removeList) {
            try {
                Remove-ItemProperty -Path $path -Name $item -ErrorAction SilentlyContinue
            }
            catch {
                # Do nothing, continue to the next item
            }
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
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }
    
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}
    
DisableStartupApps

Function RemoveEdgeUpdates {
    $edgeFolders = @(
        "C:\Program Files (x86)\Microsoft\*edge*",
        "C:\Program Files (x86)\Microsoft\Edge",
        "C:\Program Files (x86)\Microsoft\Temp"
    )

    foreach ($folder in $edgeFolders) {
        if (Test-Path $folder) {
            Remove-Item $folder -Force -Recurse -ErrorAction SilentlyContinue
        }
    }
}

RemoveEdgeUpdates

Function RemoveChromeUpdates {
    # Registry keys and files to remove
    $registryPaths = "HKLM:\SYSTEM\CurrentControlSet\Services\gupdate",
    "HKLM:\SYSTEM\CurrentControlSet\Services\gupdatem",
    "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{8A69D345-D564-463c-AFF1-A69D9E530F96}"

    foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            Remove-Item -Path $path -Recurse -ErrorAction Stop
        }
            
    }
}

#RemoveChromeUpdates

Function SyncTime {
    Set-Service -Name "W32Time" -StartupType Automatic

    Restart-Service -Name "W32Time" -Force

    w32tm /resync /force *>$null
    w32tm /config /manualpeerlist:time.windows.com, 0x1 /syncfromflags:manual /reliable:yes /update *>$null
}

SyncTime

# Remove search box from taskbar
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0