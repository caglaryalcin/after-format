##########
#region Set MAP
##########

New-PSDrive -PSProvider Registry -Name HKCU -Root HKEY_CURRENT_USER
New-PSDrive -PSProvider Registry -Name HKLM -Root HKEY_LOCAL_MACHINE
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null

##########
#endregion MAP
##########

# Remove secondary en-US keyboard
Function ImportTask {
	Register-ScheduledTask -Xml (get-content 'C:\startup\Startup.xml' | out-string) -TaskName "Startup" -Force *>$null
}

# Remove secondary en-US keyboard
Function RemoveENKeyboard {
	$langs = Get-WinUserLanguageList
	Set-WinUserLanguageList ($langs | Where-Object {$_.LanguageTag -ne "en-US"}) -Force *>$null
}

# Add TR Keyboard
Function AddTRKeyboard {
	$langs = Get-WinUserLanguageList
	$langs.Add("tr-TR")
	Set-WinUserLanguageList $langs -Force *>$null
    #HKU
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS *>$null
    Remove-ItemProperty -Path "HKU:\.DEFAULT\Keyboard Layout\Preload" -Name "1" *>$null
    Remove-ItemProperty -Path "HKU:\.DEFAULT\Keyboard Layout\Preload" -Name "2" *>$null
    Remove-ItemProperty -Path "HKU:\.DEFAULT\Keyboard Layout\Preload" -Name "3" *>$null
    Remove-ItemProperty -Path "HKU:\.DEFAULT\Keyboard Layout\Preload" -Name "4" *>$null
    Set-ItemProperty -Path "HKU:\.DEFAULT\Keyboard Layout\Preload" -Name "1" -Type String -Value 0000041f *>$null 
    Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\International" -Name "Locale" -Type String -Value 0000041f *>$null

    #HKCU
    New-PSDrive -PSProvider Registry -Name HKCU -Root HKEY_CURRENT_USER
    Remove-ItemProperty -Path "HKCU:\Keyboard Layout\Preload" -Name "1" *>$null
    Remove-ItemProperty -Path "HKCU:\Keyboard Layout\Preload" -Name "2" *>$null
    Remove-ItemProperty -Path "HKCU:\Keyboard Layout\Preload" -Name "3" *>$null
    Remove-ItemProperty -Path "HKCU:\Keyboard Layout\Preload" -Name "4" *>$null
    Set-ItemProperty -Path "HKCU:\Keyboard Layout\Preload" -Name "1" -Type String -Value 0000041f *>$null
}

# Remove Sticky Keys
Function RemoveStickyKeys {
    New-PSDrive -PSProvider Registry -Name HKCU -Root HKEY_CURRENT_USER *>$null
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value 506 *>$null #506 Off 510 On
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Type String -Value 122 *>$null #122 Off 126 On
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Type String -Value 58 *>$null #58 Off 62 On
}

# Remove Sticky Keys
Function RemoveToggleKeys {
    New-ItemProperty -Path "HKCU:\Keyboard Layout\Toggle" -Name "Language HotKey" -Type String -Value 3 *>$null
    New-ItemProperty -Path "HKCU:\Keyboard Layout\Toggle" -Name "Layout HotKey" -Type String -Value 3 *>$null
    New-ItemProperty -Path "HKU:\.DEFAULT\Keyboard Layout\Toggle" -Name "Language HotKey" -Type String -Value 3 *>$null
    New-ItemProperty -Path "HKU:\.DEFAULT\Keyboard Layout\Toggle" -Name "Layout HotKey" -Type String -Value 3 *>$null
}

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
    Get-ScheduledTask -TaskName "*XblGameSaveTask*" | Disable-ScheduledTask -ea 0 | Out-Null
    Get-ScheduledTask -TaskName "*XblGameSaveTaskLogon*" | Disable-ScheduledTask -ea 0 | Out-Null
}

# Delete WindowsDefender History
Function DefenderHistory { 
    Remove-Item 'C:\programdata\Microsoft\Windows Defender\Scans\History\Store\' -Recurse -Force -Verbose *>$null
}

Function DisableDefender {
    # Disable Defender Cloud
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force *>$null
    }
    # REG
    Remove-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Recurse -ErrorAction SilentlyContinue
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -PropertyType Dword -Value "1" *>$null
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -PropertyType Dword -Value "1" *>$null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" -Name "DisableRoutinelyTakingAction"-PropertyType Dword -Value "1" *>$null
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine" -Force *>$null
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpEnablePus" -PropertyType Dword -Value "0" *>$null
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Force *>$null
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -PropertyType Dword -Value "1" *>$null
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -PropertyType Dword -Value "1" *>$null
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -PropertyType Dword -Value "1" *>$null
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -PropertyType Dword -Value "1" *>$null
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -PropertyType Dword -Value "1" *>$null
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting" -Force *>$null
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableEnhancedNotifications" -PropertyType Dword -Value "1" *>$null
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\SpyNet" -Force *>$null
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\SpyNet" -Name "DisableBlockAtFirstSeen" -PropertyType Dword -Value "1" *>$null
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\SpyNet" -Name "SpynetReporting" -PropertyType Dword -Value "0" *>$null
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\SpyNet" -Name "SubmitSamplesConsent" -PropertyType Dword -Value "0" *>$null
    Set-Item "HKLM:\SOFTWARE\Classes\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}\InprocServer32" "" *>$null
    
    # Disable Logging
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" -Name "Start" -Type Dword -Value 0 *>$null
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" -Name "Start" -Type Dword -Value 0 *>$null
    
    # Disable WD Tasks
    schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable *>$null
    schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable *>$null
    schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable *>$null
    schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable *>$null
    schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable *>$null
    
    # Remove WD context menu
    New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
    Remove-Item -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\EPP" -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCR:\Directory\shellex\ContextMenuHandlers\EPP" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCR:\Drive\shellex\ContextMenuHandlers\EPP" -Recurse -ErrorAction SilentlyContinue

    # Disable WD services
    #reg add "HKLM\System\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f
    #reg add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f
    #reg add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f
    #reg add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
    #reg add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
    #reg add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
    
    #PS
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Ignore;
    Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction Ignore;
    Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction Ignore;
    Set-MpPreference -DisableIOAVProtection $true -ErrorAction Ignore;
    Set-MpPreference -DisablePrivacyMode $true -ErrorAction Ignore;
    Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true -ErrorAction Ignore;
    Set-MpPreference -DisableArchiveScanning $true -ErrorAction Ignore;
    Set-MpPreference -DisableIntrusionPreventionSystem $true -ErrorAction Ignore;
    Set-MpPreference -DisableScriptScanning $true -ErrorAction Ignore;
    Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction Ignore;
    Set-MpPreference -MAPSReporting 0 -ErrorAction Ignore;
    Set-MpPreference -HighThreatDefaultAction 6 -Force -ErrorAction Ignore;
    Set-MpPreference -ModerateThreatDefaultAction 6 -ErrorAction Ignore;
    Set-MpPreference -LowThreatDefaultAction 6 -ErrorAction Ignore;
    Set-MpPreference -SevereThreatDefaultAction 6 -ErrorAction Ignore;
}

Function HideDefenderTrayIcon {
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Force *>$null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Name "HideSystray" -Type DWord -Value 1
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -ErrorAction SilentlyContinue
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
	}
}

# Disable Startup App 
Function DisableStartupApps {
    $StartPaths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32\","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run\","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run\")
    $removeList = @("*Riot*","*IDMan*","*Any*","*Terminal*","*Steam*","*Teams*","*Disc*","*Epic*","*CORS*","*Next*","*One*","*Chrome*","*Opera*","*iTunes*","*CC*","*Cloud*","*Vanguard*","*Update*","*iTunes*","*Ai*","*Skype*","*Yandex*","*uTorrent*","*Deluge*","*Blitz*")
    #$DisableValue = ([byte[]](0x03,0x00,0x00,0x00,0x81,0xf4,0xad,0xc9,0xa3,0x48,0xd7,0x01))
    
    #Disable
    #Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32\ -Name "vmware-tray.exe" -Value $DisableValue

    $commonstartup = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*Any*"
    Remove-Item $commonstartup -recurse -ErrorAction SilentlyContinue


    #Remove
    Remove-ItemProperty $StartPaths -Name $removeList *>$null

    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

# Sync Localtime
Function SyncTime {
    Set-Service -Name "W32Time" -StartupType Automatic
    net stop W32Time *>$null
    net start W32Time *>$null
    w32tm /resync /force *>$null
    w32tm /config /manualpeerlist:time.windows.com,0x1 /syncfromflags:manual /reliable:yes /update *>$null
}
