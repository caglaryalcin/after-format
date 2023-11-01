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
    New-PSDrive -PSProvider Registry -Name HKCU -Root HKEY_CURRENT_USER *>$null
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value 506 *>$null #506 Off 510 On
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Type String -Value 122 *>$null #122 Off 126 On
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Type String -Value 58 *>$null #58 Off 62 On
}
RemoveStickyKeys

# Remove Toggle Keys
Function RemoveToggleKeys {
    New-ItemProperty -Path "HKCU:\Keyboard Layout\Toggle" -Name "Language HotKey" -Type String -Value 3 *>$null
    New-ItemProperty -Path "HKCU:\Keyboard Layout\Toggle" -Name "Layout HotKey" -Type String -Value 3 *>$null
    New-ItemProperty -Path "HKU:\.DEFAULT\Keyboard Layout\Toggle" -Name "Language HotKey" -Type String -Value 3 *>$null
    New-ItemProperty -Path "HKU:\.DEFAULT\Keyboard Layout\Toggle" -Name "Layout HotKey" -Type String -Value 3 *>$null
}
RemoveToggleKeys

# Remove Tasks in Task Scheduler
Function RemoveTasks {
    Write-Host "Removing Unnecessary Tasks..." -NoNewline
    
    $taskPatterns = @("OneDrive*", "MicrosoftEdge*", "Google*", "Nv*", "Brave*", "Intel*", "update-s*", "klcp*", "MSI*", "*Adobe*", "CCleaner*", "G2M*", "Opera*", "Overwolf*", "User*", "CreateExplorer*", "{*", "*Samsung*", "*npcap*", "*Consolidator*", "*Dropbox*", "*Heimdal*", "*klcp*", "*UsbCeip*", "*DmClient*", "*Office Auto*", "*Office Feature*", "*OfficeTelemetry*", "*GPU*", "Xbl*")
    
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
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Force *>$null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Name "HideSystray" -Type DWord -Value 1
    If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -ErrorAction SilentlyContinue
    }
    ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
    }
}
HideDefenderTrayIcon

# Disable Startup App 
Function DisableStartupApps {
    $StartPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32\", 
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\", 
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\", 
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\", 
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run\", 
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run\",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\"
    )
        
    $StartFilePaths = @(
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    
    $removeList = @(
        "*EADM*", "*Java*", "*CCX*", "*cisco*", "*vivaldi", "*NV*", "*npcap*", "*Edge*", 
        "*Brave*", "*Riot*", "*IDMan*", "*Teams*", "*Disc*", "*Epic*", "*CORS*", "*Next*", 
        "*One*", "*Chrome*", "*Opera*", "*iTunes*", "*CC*", "*Cloud*", "*Vanguard*", "*Update*", 
        "*iTunes*", "*Ai*", "*Skype*", "*Yandex*", "*uTorrent*", "*Deluge*", "*Blitz*", "*vmware*", "*Any*"
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
        Where-Object { $removeList -contains $_.Name } | 
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }
    
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}
    
DisableStartupApps

Function RemoveEdgeUpdates {
    Remove-Item "C:\Program Files (x86)\Microsoft\*edge*" -recurse -ErrorAction SilentlyContinue
    Remove-Item "C:\Program Files (x86)\Microsoft\Edge" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item "C:\Program Files (x86)\Microsoft\Temp" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item "C:\Program Files (x86)\Microsoft\*" -Force -Recurse -ErrorAction SilentlyContinue

}
RemoveEdgeUpdates

# Sync Localtime
Function SyncTime {
    Set-Service -Name "W32Time" -StartupType Automatic
    net stop W32Time *>$null
    net start W32Time *>$null
    w32tm /resync /force *>$null
    w32tm /config /manualpeerlist:time.windows.com, 0x1 /syncfromflags:manual /reliable:yes /update *>$null
}
SyncTime

# Remove search box from taskbar
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
