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
        Get-ScheduledTask "Chrome*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "OneDrive*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "MicrosoftEdge*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "Google*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "Nv*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "Brave*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "Intel*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "update-s*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "klcp*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "MSI*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "*Adobe*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "CCleaner*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "Blue*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "klcp*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "Driver*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "G2M*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "klcp*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "Opera*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "PC*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "Overwolf*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "klcp*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "User*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "CreateExplorer*" | Unregister-ScheduledTask -Confirm:$false    
        Get-ScheduledTask "{*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "*Samsung*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "*Auto*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "*McAfee*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "*npcap*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "*Consolidator*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "*Dropbox*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "*Heimdal*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "*klcp*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "*UsbCeip*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "*DmClient*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "*Office*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "*GPU*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "*Firefox*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask "*Post*" | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask -TaskName "*XblGameSaveTask*" | Disable-ScheduledTask -ea 0 | Out-Null
        Get-ScheduledTask -TaskName "*XblGameSaveTaskLogon*" | Disable-ScheduledTask -ea 0 | Out-Null
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
        $StartPaths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32\", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run\", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run\")
        $StartFilePaths = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
        $removeList = @("*EADM*", "*Java*", "*CCX*", "*cisco*", "*vivaldi", "*NV*", "*npcap*", "*Edge*", "*Brave*", "*Riot*", "*IDMan*", "*Teams*", "*Disc*", "*Epic*", "*CORS*", "*Next*", "*One*", "*Chrome*", "*Opera*", "*iTunes*", "*CC*", "*Cloud*", "*Vanguard*", "*Update*", "*iTunes*", "*Ai*", "*Skype*", "*Yandex*", "*uTorrent*", "*Deluge*", "*Blitz*", "*vmware*", "*Any*")
    
        #Remove
        Remove-ItemProperty $StartPaths -Name $removeList *>$null
        Get-ChildItem -Path $StartFilePaths -Recurse | Remove-Item -force -recurse  -ErrorAction SilentlyContinue

        #delete files
        $shellstartup = "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\"
        $shellcommonstartup = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"

        # Exclude list
        $excludeItems = @("FanControl*", "Steel*", "Cloudflare*")

        # Startup Folder Delete Files
        Get-ChildItem -Path $shellstartup -Exclude $excludeItems -Recurse | Remove-Item -Recurse -ErrorAction SilentlyContinue
        Get-ChildItem -Path $shellcommonstartup -Exclude $excludeItems -Recurse | Remove-Item -Recurse -ErrorAction SilentlyContinue

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
