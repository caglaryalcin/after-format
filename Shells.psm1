##########
#region Set MAP
##########

New-PSDrive -PSProvider Registry -Name HKCU -Root HKEY_CURRENT_USER | Out-Null
New-PSDrive -PSProvider Registry -Name HKLM -Root HKEY_LOCAL_MACHINE | Out-Null
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null

##########
#endregion MAP
##########

##########
#region Priority
##########

Function Info {
    Get-ComputerInfo CsProcessors |Out-Host;
    Get-CimInstance -ClassName Win32_VideoController | Select Description |Out-Host;
    Get-Disk | Select FriendlyName, HealthStatus |Out-Host;
    Get-ComputerInfo -Property OSName, OsArchitecture, CsProcessorsOSName |Out-Host;
}

Function Priority {
    $progressPreference = 'silentlyContinue'
    Get-WindowsPackage -Online | Where PackageName -like *QuickAssist* | Remove-WindowsPackage -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
}

##########
#endregion Priority
##########

##########
#region System Settings
##########

#Set TR Formatss
Function TRFormats {
    Write-Host `n"---------Adjusting System Settings" -ForegroundColor Blue -BackgroundColor Black

    Write-Host `n"Setting date format of Turkey..." -NoNewline
    Set-TimeZone -Name "Turkey Standard Time"
    Set-Culture tr-TR
    Set-ItemProperty -Path "HKCU:\Control Panel\International" -name ShortDate -value "dd/MM/yyyy"
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

#Default .ps1 file for Powershell
Function Defaultps1 {
    reg import "C:\after-format-main\files\default_ps.reg" *>$null
}

#Get the Old Classic Right-Click Context Menu for Windows 11
Function RightClickMenu {
    Write-Host "Getting the Old Classic Right-Click Context Menu for Windows 11..." -NoNewline
    New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" *>$null
    New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" *>$null
    Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(Default)" -Type String -Value $null *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

#Turn Off News and Interest
Function DisableNews {
    Write-Host "Disabling News and Interes on Taskbar..." -NoNewline
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" *>$null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0 *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

#Default Photo Viewer Old
Function DefaultPhotoViewer {
    Write-Host "Default Old Photo Viewer..." -NoNewline
    reg import "C:\after-format-main\files\default_foto.reg" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

# Set Dark Mode for Applications
Function SetAppsDarkMode {
	Write-Host "Setting Dark Mode for Applications..." -NoNewline
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

# Set Dark Mode for System - Applicable since 1903
Function SetSystemDarkMode {
	Write-Host "Setting Dark Mode for System..." -NoNewline
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

# Set Control Panel view to Large icons (Classic)
Function SetControlPanelLargeIcons {
	Write-Host "Setting Control Panel view to large icons..." -NoNewline
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

# Enable NumLock after startup
Function EnableNumlock {
	Write-Host "Enabling NumLock after startup..." -NoNewline
	If (!(Test-Path "HKU:")) {
		New-PSDrive -Name "HKU" -PSProvider "Registry" -Root "HKEY_USERS" | Out-Null
	}
	Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
	Add-Type -AssemblyName System.Windows.Forms
	If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

# Set Hostname
Function SetHostname {
	Write-Host "Hostname is Setting..." 
    $hostname = Read-Host -Prompt 'Please enter your hostname'
    Rename-Computer -NewName "$hostname" *>$null
    Write-Host "Hostname is set to "$hostname"" -ForegroundColor Yellow -BackgroundColor Black -NoNewline
}

# Disable Windows Beep Sound
Function DisableBeepSound {
	Write-Host "Disabling Windows Beep Sound..." -NoNewline
	Set-ItemProperty -Path "HKCU:\Control Panel\Sound" -Name "Beep" -Type String -Value no
    Set-Service beep -StartupType disabled *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

# Disable IPv6 stack for all installed network interfaces 
Function DisableIPv6 {
	Write-Host "Disabling IPv6 stack..." -NoNewline
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip6"
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

# Disable VMware and VirtualBox Ethernet Adapters 
Function DisableVMEthernets {
	Write-Host "Disabling Virtual Ethernet Adapters..." -NoNewline
	Disable-NetAdapter -Name "*VMware*" -Confirm:$false *>$null
    Disable-NetAdapter -Name "*Virtual*" -Confirm:$false *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

# Disable Startup App 
Function DisableStartupApps {
	Write-Host "Disabling Startup Apps..." -NoNewline
    $StartPaths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32\","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run\","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run\")
    $removeList = @("*Teams*","*Disc*","*Epic*","*CORS*","*Next*","*One*","*Chrome*","*Opera*","*iTunes*","*CC*","*Cloud*","*Vanguard*","*Update*","*iTunes*","*Ai*","*Skype*","*Yandex*","*uTorrent*","*Deluge*","*Blitz*","*Snagit*")
    #$DisableValue = ([byte[]](0x03,0x00,0x00,0x00,0x81,0xf4,0xad,0xc9,0xa3,0x48,0xd7,0x01))
    
    #Disable
    #Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32\ -Name "vmware-tray.exe" -Value $DisableValue

    #Remove
    Remove-ItemProperty $StartPaths -Name $removeList *>$null

    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

# Disable IPv6 stack for all installed network interfaces 
Function SetCFDNS {
	Write-Host "Setting Cloud Flare DNS..." -NoNewline
	Set-DnsClientServerAddress -InterfaceIndex 1 -ServerAddresses ("1.1.1.1","1.0.0.1") -ErrorAction SilentlyContinue
    Set-DnsClientServerAddress -InterfaceIndex 2 -ServerAddresses ("1.1.1.1","1.0.0.1") -ErrorAction SilentlyContinue
    Set-DnsClientServerAddress -InterfaceIndex 3 -ServerAddresses ("1.1.1.1","1.0.0.1") -ErrorAction SilentlyContinue
    Set-DnsClientServerAddress -InterfaceIndex 4 -ServerAddresses ("1.1.1.1","1.0.0.1") -ErrorAction SilentlyContinue
    Set-DnsClientServerAddress -InterfaceIndex 5 -ServerAddresses ("1.1.1.1","1.0.0.1") -ErrorAction SilentlyContinue
    Set-DnsClientServerAddress -InterfaceIndex 6 -ServerAddresses ("1.1.1.1","1.0.0.1") -ErrorAction SilentlyContinue
    Set-DnsClientServerAddress -InterfaceIndex 7 -ServerAddresses ("1.1.1.1","1.0.0.1") -ErrorAction SilentlyContinue
    Set-DnsClientServerAddress -InterfaceIndex 8 -ServerAddresses ("1.1.1.1","1.0.0.1") -ErrorAction SilentlyContinue
    Set-DnsClientServerAddress -InterfaceIndex 9 -ServerAddresses ("1.1.1.1","1.0.0.1") -ErrorAction SilentlyContinue
    Set-DnsClientServerAddress -InterfaceIndex 10 -ServerAddresses ("1.1.1.1","1.0.0.1") -ErrorAction SilentlyContinue
    Set-DnsClientServerAddress -InterfaceIndex 11 -ServerAddresses ("1.1.1.1","1.0.0.1") -ErrorAction SilentlyContinue
    Set-DnsClientServerAddress -InterfaceIndex 12 -ServerAddresses ("1.1.1.1","1.0.0.1") -ErrorAction SilentlyContinue
    Set-DnsClientServerAddress -InterfaceIndex 13 -ServerAddresses ("1.1.1.1","1.0.0.1") -ErrorAction SilentlyContinue
    Set-DnsClientServerAddress -InterfaceIndex 14 -ServerAddresses ("1.1.1.1","1.0.0.1") -ErrorAction SilentlyContinue
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black        
}

# Hide Taskbar People icon
Function HideTaskbarPeopleIcon {
	Write-Host "Hiding People Icon from Taskbar..." -NoNewline
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

# Hide Taskbar Taskview icon
Function HideTaskbarTaskviewIcon {
	Write-Host "Hiding Taskview Icon from Taskbar..." -NoNewline
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

# Hide Taskbar MultiTaskview icon
Function HideTaskbarMultiTaskviewIcon {
	Write-Host "Hiding MultiTaskview Icon from Taskbar..." -NoNewline
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MultitaskingView\")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MultitaskingView\" | Out-Null
    }
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MultitaskingView\AllUpView")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MultitaskingView\AllUpView" | Out-Null
    }
	New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MultitaskingView\AllUpView" -Name "AllUpView" -Type DWord -Value 0  *>$null
	New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MultitaskingView\AllUpView" -Name "Remove TaskView" -Type DWord -Value 0  *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

# Show small icons in taskbar
Function ShowSmallTaskbarIcons {
	Write-Host "Showing Small Icons in Taskbar..." -NoNewline
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

# Hide Taskbar Search icon / box
Function HideTaskbarSearch {
	Write-Host "Hiding Taskbar Search Icon / Box..." -NoNewline
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

# Hide Taskbar Remove Chat from the Taskbar
Function RemoveTaskbarChat {
	Write-Host "Removing Chat from Taskbar..." -NoNewline
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\" -Name "TaskbarMn" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

# Hide Taskbar Remove Widgets from the Taskbar
Function RemoeTaskbarWidgets {
	Write-Host "Removing Widgets from Taskbar..." -NoNewline
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\" -Name "TaskbarDa" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

# Hide Taskbar Start button alignment left
Function TaskbarAlignLeft {
	Write-Host "Taskbar Aligns Left..." -NoNewline
	New-itemproperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value "0" -PropertyType Dword *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

# Hide Recycle Bin shortcut from desktop
Function HideRecycleBinFromDesktop {
	Write-Host "Hiding Recycle Bin Shortcut from Desktop..." -NoNewline
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Type DWord -Value 1
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Type DWord -Value 1
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

# Disable Hiberfil - fast windows startup (with ssd) 
Function DisableHiberfil {
	Write-Host "Disabling hiberfil.sys..." -NoNewline
    powercfg -h off
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black        
}

# Disable Display and Sleep mode timeouts 
Function DisableSleepTimeout {
	Write-Host "Disabling display and sleep mode timeouts..." -NoNewline
	powercfg /X monitor-timeout-ac 0
	powercfg /X monitor-timeout-dc 0
	powercfg /X standby-timeout-ac 0
	powercfg /X standby-timeout-dc 0
    powercfg /X standby-timeout-ac 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

Function DisableDefender {
	Write-Host "Disabling Windows Defender..." -NoNewline
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
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

Function HideDefenderTrayIcon {
	Write-Host "Hiding Windows Defender SysTray icon..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Name "HideSystray" -Type DWord -Value 1
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -ErrorAction SilentlyContinue
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
	}
	Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

# Disable receiving updates for other Microsoft products via Windows Update
Function DisableUpdateMSProducts {
	Write-Host "Disabling Updates for Other Microsoft Products..." -NoNewline
	If ((New-Object -ComObject Microsoft.Update.ServiceManager).Services | Where-Object { $_.ServiceID -eq "7971f918-a847-4430-9279-4a52d1efe18d"}) {
		(New-Object -ComObject Microsoft.Update.ServiceManager).RemoveService("7971f918-a847-4430-9279-4a52d1efe18d") | Out-Null
	}
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

# Disable Cortana 
Function DisableCortana {
	Write-Host "Disabling Cortana..." -NoNewline
	If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
		New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
		New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -Name "Value" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Type DWord -Value 0
    $progressPreference = 'silentlyContinue'
	Get-AppxPackage "Microsoft.549981C3F5F10" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

# Disable Web Search in Start Menu
Function DisableWebSearch {
	Write-Host "Disabling Bing Search in Start Menu..." -NoNewline
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

# Disable SmartScreen Filter 
Function DisableSmartScreen {
	Write-Host "Disabling SmartScreen Filter..." -NoNewline
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

# Disable sensor features, such as screen auto rotation 
Function DisableSensors {
	Write-Host "Disabling Sensors..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -Type DWord -Value 1
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

# Disable Tailored Experiences 
Function DisableTailoredExperiences {
	Write-Host "Disabling Tailored Experiences..." -NoNewline
	If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

# Disable XBox GameBar (Win+G) 
Function DisableXboxGamebar {
	Write-Host "Disabling Xbox Gamebar..." -NoNewline
    $progressPreference = 'silentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.XboxGamingOverlay | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

# Disable Xbox features - Not applicable to Server
Function DisableXboxFeatures {
	Write-Host "Disabling Xbox Features..." -NoNewline
    $progressPreference = 'silentlyContinue'
	Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "Microsoft.XboxGamingOverlay" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

# Disable blocking of downloaded files (i.e. storing zone information - no need to do File\Properties\Unblock) 
Function DisableDownloadBlocking {
	Write-Host "Disabling Blocking of Downloaded Files..." -NoNewline
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Type DWord -Value 1
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

# File Explorer with 'This PC'
Function FileExplorerWithThisPC {
	Write-Host "Setting 'This PC' for File Explorer..." -NoNewline
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1 #1 'This PC' #2 'Quick Access'
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

# File Explorer Expand Ribbon
Function FileExplorerExpandRibbon {
	Write-Host "Expanding for File Explorer..." -NoNewline
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" -Name "MinimizedStateTabletModeOff" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

# Disable nightly wake-up for Automatic Maintenance and Windows Updates 
Function DisableMaintenanceWakeUp {
	Write-Host "Disabling nightly wake-up for Automatic Maintenance..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "WakeUp" -Type DWord -Value 0 | Out-Null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

# Disable Storage Sense - Applicable since 1703 NOT 
Function DisableStorageSense {
	Write-Host "Disabling Storage Sense..." -NoNewline
    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

# Unpin all Start Menu tiles
# Note: This function has no counterpart. You have to pin the tiles back manually. NOT 
Function UnpinStartMenuTiles {
	Write-Host "Unpinning all Start Menu tiles..." -NoNewline
        $progressPreference = 'silentlyContinue'
	If ([System.Environment]::OSVersion.Version.Build -ge 15063 -And [System.Environment]::OSVersion.Version.Build -le 16299) {
		Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount" -Include "*.group" -Recurse | ForEach-Object {
			$data = (Get-ItemProperty -Path "$($_.PsPath)\Current" -Name "Data").Data -Join ","
			$data = $data.Substring(0, $data.IndexOf(",0,202,30") + 9) + ",0,202,80,0,0"
			Set-ItemProperty -Path "$($_.PsPath)\Current" -Name "Data" -Type Binary -Value $data.Split(",")-ErrorAction SilentlyContinue
		}
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 17134) {
		$key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*start.tilegrid`$windows.data.curatedtilecollection.tilecollection\Current"
		$data = $key.Data[0..25] + ([byte[]](202,50,0,226,44,1,1,0,0))
		Set-ItemProperty -Path $key.PSPath -Name "Data" -Type Binary -Value $data -ErrorAction SilentlyContinue
		Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
        #Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
	}
}

# --- Variant 2: Pin / Unpin Applications and UWP Apps already listed in Start Menu
function getExplorerVerb([string]$verb) {
    $getstring = @'
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        internal static extern int LoadString(IntPtr hInstance, uint uID, StringBuilder lpBuffer, int nBufferMax);

        public static string GetString(uint strId) {
            IntPtr intPtr = GetModuleHandle("shell32.dll");
            StringBuilder sb = new StringBuilder(255);
            LoadString(intPtr, strId, sb, sb.Capacity);
            return sb.ToString();
        }
'@
    $getstring = Add-Type $getstring -PassThru -Name GetStr -Using System.Text

    if ($verb -eq "PinToTaskbar")     { $getstring[0]::GetString(5386) }  # String: Pin to Taskbar
    if ($verb -eq "UnpinFromTaskbar") { $getstring[0]::GetString(5387) }  # String: Unpin from taskbar
    if ($verb -eq "PinToStart")       { $getstring[0]::GetString(51201) } # String: Pin to start
    if ($verb -eq "UnpinFromStart")   { $getstring[0]::GetString(51394) } # String: Unpin from start
}

function Get-ExplorerApps([string]$AppName) {
    $apps = (New-Object -Com Shell.Application).NameSpace("shell:::{4234d49b-0245-4df3-b780-3893943456e1}").Items()
    $apps | Where {$_.Name -like $AppName -or $app.Path -like $AppName}     
}

function List-ExplorerApps() { List-ExplorerApps(""); }
function List-ExplorerApps([string]$AppName) {
    $apps = Get-ExplorerApps("*$AppName*")
    $AppList = @{};
    foreach ($app in $apps) { $AppList.Add($app.Path, $app.Name) }
    $AppList | Format-Table -AutoSize
}

function Configure-TaskbarPinningApp([string]$AppName, [string]$Verb) {
    $myProcessName = Get-Process | where {$_.ID -eq $pid} | % {$_.ProcessName}
    if (-not ($myProcessName -like "explorer")) { Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black }

    $apps = Get-ExplorerApps($AppName)
    if ($apps.Count -eq 0) { Write-Host "Error: No App with exact Path or Name '$AppName' found" }
    $ExplorerVerb = getExplorerVerb($Verb);
    foreach ($app in $apps) {
        $done = "False (Verb $Verb not found)"
        $app.Verbs() | Where {$_.Name -eq $ExplorerVerb} | ForEach {$_.DoIt(); $done=$true }
        #Write-Host $verb $app.Name "-> Result:" $done
    }
}
    
function Remove-TaskbarPinningApp([string]$AppName) { Configure-TaskbarPinningApp $AppName "UnpinFromTaskbar" }

# Disable built-in Adobe Flash in IE and Edge 
Function DisableAdobeFlash {
	Write-Host "Disabling Built-in Adobe Flash in IE and Edge..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "DisableFlashInIE" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

# Disable Edge preload after Windows startup - Applicable since Win10 1809 
Function DisableEdgePreload {
	Write-Host "Disabling Edge Preload..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "AllowTabPreloading" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

# Disable Internet Explorer first run wizard 
Function DisableIEFirstRun {
	Write-Host "Disabling Internet Explorer First Run Wizard..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Type DWord -Value 1
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

# Disable Windows Media Player online access - audio file metadata download, radio presets, DRM. 
Function DisableMediaOnlineAccess {
	Write-Host "Disabling Windows Media Player Online Access..." -NoNewline
	If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer")) {
		New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCDDVDMetadataRetrieval" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventMusicFileMetadataRetrieval" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventRadioPresetsRetrieval" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type DWord -Value 1
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

# Show known file extensions 
Function ShowKnownExtensions {
	Write-Host "Showing Known File Extensions..." -NoNewline
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

# Disable Action Center (Notification Center) 
Function DisableActionCenter {
	Write-Host "Disabling Action Center (Notification Center)..." -NoNewline
	If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

# Disable System restore 
Function DisableRestorePoints {
	Write-Host "Disabling System Restore for System Drive..." -NoNewline
	Disable-ComputerRestore -Drive "$env:SYSTEMDRIVE" *>$null
    vssadmin delete shadows /all /Quiet | Out-Null
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore")) {
	    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" -Force *>$null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" -Name "DisableConfig" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" -Name "DisableSR" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "DisableConfig" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "DisableSR" -Type DWord -Value 1
    schtasks /Change /TN "\Microsoft\Windows\SystemRestore\SR" /disable  | Out-Null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

# Lower UAC level (disabling it completely would break apps) 
Function SetUACLow {
    Write-Host "Setting Low UAC Level..." -NoNewline
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

# Fix Corrupt System Files
Function Sfc {
    Write-Host "Fixing System Files..." -NoNewline
    DISM.exe /Online /Cleanup-image /Restorehealth
    Start-Process -FilePath "${env:Windir}\System32\SFC.EXE" -ArgumentList '/scannow' -Wait -NoNewWindow -ErrorAction SilentlyContinue
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Remove Tasks in Task Scheduler
Function RemoveTasks {
    Write-Host "Removing Unnecessary Tasks..." -NoNewline
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
    Get-ScheduledTask "klcp*" | Unregister-ScheduledTask -Confirm:$false
    Get-ScheduledTask "G2M*" | Unregister-ScheduledTask -Confirm:$false
    Get-ScheduledTask "klcp*" | Unregister-ScheduledTask -Confirm:$false
    Get-ScheduledTask "Opera*" | Unregister-ScheduledTask -Confirm:$false
    Get-ScheduledTask "Overwolf*" | Unregister-ScheduledTask -Confirm:$false
    Get-ScheduledTask "klcp*" | Unregister-ScheduledTask -Confirm:$false
    Get-ScheduledTask "User*" | Unregister-ScheduledTask -Confirm:$false
    Get-ScheduledTask "CreateExplorer*" | Unregister-ScheduledTask -Confirm:$false    
    Get-ScheduledTask "{*" | Unregister-ScheduledTask -Confirm:$false
    Get-ScheduledTask "*Samsung*" | Unregister-ScheduledTask -Confirm:$false
    Get-ScheduledTask "*npcap*" | Unregister-ScheduledTask -Confirm:$false
    Get-ScheduledTask "*Consolidator*" | Unregister-ScheduledTask -Confirm:$false
    Get-ScheduledTask "*Dropbox*" | Unregister-ScheduledTask -Confirm:$false
    Get-ScheduledTask "*Heimdal*" | Unregister-ScheduledTask -Confirm:$false
    Get-ScheduledTask "*klcp*" | Unregister-ScheduledTask -Confirm:$false
    Get-ScheduledTask "*UsbCeip*" | Unregister-ScheduledTask -Confirm:$false
    Get-ScheduledTask "*DmClient*" | Unregister-ScheduledTask -Confirm:$false
    Get-ScheduledTask "*Office Auto*" | Unregister-ScheduledTask -Confirm:$false
    Get-ScheduledTask "*Office Feature*" | Unregister-ScheduledTask -Confirm:$false
    Get-ScheduledTask "*OfficeTelemetry*" | Unregister-ScheduledTask -Confirm:$false
    Get-ScheduledTask "*GPU*" | Unregister-ScheduledTask -Confirm:$false
    Get-ScheduledTask -TaskName "*XblGameSaveTask*" | Disable-ScheduledTask -ea 0 | Out-Null
    Get-ScheduledTask -TaskName "*XblGameSaveTaskLogon*" | Disable-ScheduledTask -ea 0 | Out-Null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disk cleanup 
Function DiskClean {
    $progressPreference = 'silentlyContinue'
    Write-Host "Disk Cleaning..." -NoNewline
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Setup Files" -Name "StateFlags0077" -Type DWord -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Old ChkDsk Files" -Name "StateFlags0077" -Type DWord -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Setup Log Files" -Name "StateFlags0077" -Type DWord -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup" -Name "StateFlags0077" -Type DWord -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Defender" -Name "StateFlags0077" -Type DWord -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Diagnostic Data Viewer database files" -Name "StateFlags0077" -Type DWord -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Downloaded Program Files" -Name "StateFlags0077" -Type DWord -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Internet Cache Files" -Name "StateFlags0077" -Type DWord -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Setup Files" -Name "StateFlags0077" -Type DWord -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error memory dump files" -Name "StateFlags0077" -Type DWord -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error minidump files" -Name "StateFlags0077" -Type DWord -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting Files" -Name "StateFlags0077" -Type DWord -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\BranchCache" -Name "StateFlags0077" -Type DWord -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\D3D Shader Cache" -Name "StateFlags0077" -Type DWord -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Delivery Optimization Files" -Name "StateFlags0077" -Type DWord -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Language Pack" -Name "StateFlags0077" -Type DWord -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Recycle Bin" -Name "StateFlags0077" -Type DWord -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files" -Name "StateFlags0077" -Type DWord -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\RetailDemo Offline Content" -Name "StateFlags0077" -Type DWord -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name "StateFlags0077" -Type DWord -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\User file versions" -Name "StateFlags0077" -Type DWord -Value 2
    cleanmgr.exe /sagerun:77
    Start-Sleep -Seconds 15
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
   
    ## Deletes the contents of windows software distribution.
    $progressPreference = 'silentlyContinue'
    Get-ChildItem "C:\Windows\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -recurse -ErrorAction SilentlyContinue 

    ## Deletes the contents of the Windows Temp folder.
    $progressPreference = 'silentlyContinue'
    Get-ChildItem "C:\Windows\Temp\*" -Recurse -Force  -ErrorAction SilentlyContinue | Remove-Item -recurse -ErrorAction SilentlyContinue 
    Write-host "Windows Temp have been removing." -NoNewline
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    
    ## Deletes all files and folders in user's Temp folder older then $DaysToDelete
    $progressPreference = 'silentlyContinue'
    Get-ChildItem "$env:userprofile\AppData\Local\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -force -recurse -ErrorAction SilentlyContinue 
    Write-Host "TEMP have been removing." -NoNewline
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black

    ## Removes all files and folders in user's Temporary Internet Files older then $DaysToDelete
    $progressPreference = 'silentlyContinue'
    Get-ChildItem "$env:userprofile\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" -Recurse -Force  -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue 
    Write-Host "All Temporary Internet Files have been removing." -NoNewline
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black

    ## Removes *.log from C:\windows\CBS
    if(Test-Path C:\Windows\logs\CBS\){
    Get-ChildItem "C:\Windows\logs\CBS\*.log" -Recurse -Force -ErrorAction SilentlyContinue |
        remove-item -force -recurse -ErrorAction SilentlyContinue 
    Write-Host "All CBS logs have been removing." -NoNewline
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    } else {
        Write-Host "C:\inetpub\logs\LogFiles\ does not exist, there is nothing to cleanup." -NoNewline -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
    }

    ## Cleans IIS Logs older then $DaysToDelete
    if (Test-Path C:\inetpub\logs\LogFiles\) {
        Get-ChildItem "C:\inetpub\logs\LogFiles\*" -Recurse -Force -ErrorAction SilentlyContinue  | Remove-Item -Force  -Recurse -ErrorAction SilentlyContinue
        Write-Host "All IIS Logfiles over $DaysToDelete days old have been removing" -NoNewline
        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    }
    else {
        Write-Host "C:\Windows\logs\CBS\ does not exist, there is nothing to cleanup." -NoNewline -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
    }

    ## Removes C:\Config.Msi
    if (test-path C:\Config.Msi){
        remove-item -Path C:\Config.Msi -force -recurse  -ErrorAction SilentlyContinue
    } else {
        Write-Host "C:\Config.Msi does not exist, there is nothing to cleanup." -NoNewline -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
    }

    ## Removes c:\Intel
    if (test-path c:\Intel){
        remove-item -Path c:\Intel -force -recurse  -ErrorAction SilentlyContinue
    } else {
        Write-Host "c:\Intel does not exist, there is nothing to cleanup." -NoNewline -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
    }

    ## Removes c:\PerfLogs
    if (test-path c:\PerfLogs){
        remove-item -Path c:\PerfLogs -force -recurse  -ErrorAction SilentlyContinue
    } else {
        Write-Host "c:\PerfLogs does not exist, there is nothing to cleanup." -NoNewline -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
    }

    ## Removes $env:windir\memory.dmp
    if (test-path $env:windir\memory.dmp){
        remove-item $env:windir\memory.dmp -force  -ErrorAction SilentlyContinue
    } else {
        Write-Host "C:\Windows\memory.dmp does not exist, there is nothing to cleanup." -NoNewline -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
    }

    ## Removes Windows Error Reporting files
    if (test-path C:\ProgramData\Microsoft\Windows\WER){
        Get-ChildItem -Path C:\ProgramData\Microsoft\Windows\WER -Recurse | Remove-Item -force -recurse  -ErrorAction SilentlyContinue
            Write-host "Deleting Windows Error Reporting files!" -NoNewline
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        } else {
            Write-Host "C:\ProgramData\Microsoft\Windows\WER does not exist, there is nothing to cleanup." -NoNewline -ForegroundColor DarkGray
            Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
    }

    ## Removes System and User Temp Files - lots of access denied will occur.
    ## Cleans up c:\windows\temp
    if (Test-Path $env:windir\Temp\) {
        Remove-Item -Path "$env:windir\Temp\*" -Force -Recurse  -ErrorAction SilentlyContinue
    } else {
            Write-Host "C:\Windows\Temp does not exist, there is nothing to cleanup." -NoNewline -ForegroundColor DarkGray
            Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
    }

    ## Cleans up minidump
    if (Test-Path $env:windir\minidump\) {
        Remove-Item -Path "$env:windir\minidump\*" -Force -Recurse  -ErrorAction SilentlyContinue
    } else {
            Write-Host "$env:windir\minidump\ does not exist, there is nothing to cleanup." -NoNewline -ForegroundColor DarkGray
            Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
    }

    ## Cleans up prefetch
    if (Test-Path $env:windir\Prefetch\) {
        Remove-Item -Path "$env:windir\Prefetch\*" -Force -Recurse  -ErrorAction SilentlyContinue
    } else {
            Write-Host "$env:windir\Prefetch\ does not exist, there is nothing to cleanup." -NoNewline -ForegroundColor DarkGray
            Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
    }

    ## Cleans up each users temp folder
    if (Test-Path "$env:userprofile\AppData\Local\Temp\") {
        Remove-Item -Path "%userprofile%\AppData\Local\Temp\*" -Force -Recurse  -ErrorAction SilentlyContinue
    } else {
            Write-Host "$env:userprofile\AppData\Local\Temp\ does not exist, there is nothing to cleanup." -NoNewline -ForegroundColor DarkGray
            Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
    }

    ## Cleans up all users windows error reporting
    if (Test-Path "$env:userprofile\AppData\Local\Microsoft\Windows\WER\") {
        Remove-Item -Path "$env:userprofile\AppData\Local\Microsoft\Windows\WER\*" -Force -Recurse  -ErrorAction SilentlyContinue
    } else {
            Write-Host "C:\ProgramData\Microsoft\Windows\WER does not exist, there is nothing to cleanup." -NoNewline -ForegroundColor DarkGray
            Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
    }

    ## Cleans up users temporary internet files
    if (Test-Path "$env:userprofile\AppData\Local\Microsoft\Windows\Temporary Internet Files\") {
        Remove-Item -Path "$env:userprofile\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" -Force -Recurse  -ErrorAction SilentlyContinue
    } else {
            Write-Host "$env:userprofile\AppData\Local\Microsoft\Windows\Temporary Internet Files\ does not exist." -NoNewline -ForegroundColor DarkGray
            Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
    }

    ## Cleans up Internet Explorer cache
    if (Test-Path "$env:userprofile\AppData\Local\Microsoft\Windows\IECompatCache\") {
        Remove-Item -Path "$env:userprofile\AppData\Local\Microsoft\Windows\IECompatCache\*" -Force -Recurse  -ErrorAction SilentlyContinue
    } else {
            Write-Host "$env:userprofile\AppData\Local\Microsoft\Windows\IECompatCache\ does not exist." -NoNewline -ForegroundColor DarkGray
            Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
    }

    ## Cleans up Internet Explorer cache
    if (Test-Path "$env:userprofile\AppData\Local\Microsoft\Windows\IECompatUaCache\") {
        Remove-Item -Path "%userprofile%\AppData\Local\Microsoft\Windows\IECompatUaCache\*" -Force -Recurse  -ErrorAction SilentlyContinue
    } else {
            Write-Host "$env:userprofile\AppData\Local\Microsoft\Windows\IECompatUaCache\ does not exist." -NoNewline -ForegroundColor DarkGray
            Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
    }

    ## Cleans up Internet Explorer download history
    if (Test-Path "$env:userprofile\AppData\Local\Microsoft\Windows\IEDownloadHistory\") {
        Remove-Item -Path "$env:userprofile\AppData\Local\Microsoft\Windows\IEDownloadHistory\*" -Force -Recurse  -ErrorAction SilentlyContinue
    } else {
            Write-Host "$env:userprofile\AppData\Local\Microsoft\Windows\IEDownloadHistory\ does not exist." -NoNewline -ForegroundColor DarkGray
            Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
    }

    ## Cleans up Internet Cache
    if (Test-Path "$env:userprofile\AppData\Local\Microsoft\Windows\INetCache\") {
        Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\INetCache\*" -Force -Recurse  -ErrorAction SilentlyContinue
    } else {
            Write-Host "$env:userprofile\AppData\Local\Microsoft\Windows\INetCache\ does not exist." -NoNewline -ForegroundColor DarkGray
            Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
    }

    ## Cleans up Internet Cookies
    if (Test-Path "$env:userprofile\AppData\Local\Microsoft\Windows\INetCookies\") {
        Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\INetCookies\*" -Force -Recurse  -ErrorAction SilentlyContinue
    } else {
            Write-Host "$env:userprofile\AppData\Local\Microsoft\Windows\INetCookies\ does not exist." -NoNewline -ForegroundColor DarkGray
            Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
    }

    ## Cleans up terminal server cache
    if (Test-Path "$env:userprofile\AppData\Local\Microsoft\Terminal Server Client\Cache\") {
        Remove-Item -Path "$env:userprofile\AppData\Local\Microsoft\Terminal Server Client\Cache\*" -Force -Recurse  -ErrorAction SilentlyContinue
    } else {
            Write-Host "$env:userprofile\AppData\Local\Microsoft\Terminal Server Client\Cache\ does not exist." -NoNewline -ForegroundColor DarkGray
            Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
    }

    Write-host "Removing System and User Temp Files." -NoNewline
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black

    ## Removes the hidden recycling bin.
    if (Test-path 'C:\$Recycle.Bin'){
        Remove-Item 'C:\$Recycle.Bin' -Recurse -Force  -ErrorAction SilentlyContinue
    } else {
        Write-Host "C:\`$Recycle.Bin does not exist, there is nothing to cleanup." -NoNewline -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
    }

    ## Turns errors back on
    $ErrorActionPreference = "Continue"

    ## Checks the version of PowerShell
    ## If PowerShell version 4 or below is installed the following will process
    if ($PSVersionTable.PSVersion.Major -le 4) {

        ## Empties the recycling bin, the desktop recyling bin
        $Recycler = (New-Object -ComObject Shell.Application).NameSpace(0xa)
        $Recycler.items() | ForEach-Object { 
            ## If PowerShell version 4 or bewlow is installed the following will process
            Remove-Item -Include $_.path -Force -Recurse 
            Write-Host "The recycling bin has been cleaned up successfully!" -NoNewline
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }
    } elseif ($PSVersionTable.PSVersion.Major -ge 5) {
         ## If PowerShell version 5 is running on the machine the following will process
         Clear-RecycleBin -DriveLetter C:\ -Force 
         Write-Host "The recycling bin has been cleaned up successfully!" -NoNewline
         Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    }
}

# Disable Scheduled Defragmentation Task 
Function DisableDefragmentation {
    Write-Host "Disabling Scheduled Defragmentation..." -NoNewline
    $progressPreference = 'silentlyContinue'
    Schtasks /Delete /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" /F *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

# Enable clearing of recent files on exit 
# Empties most recently used (MRU) items lists such as 'Recent Items' menu on the Start menu, jump lists, and shortcuts at the bottom of the 'File' menu in applications during every logout.
Function EnableClearRecentFiles {
	Write-Host "Enabling Clearing of Recent Files on Exit..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -Type DWord -Value 1
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable recent files lists 
# Stops creating most recently used (MRU) items lists such as 'Recent Items' menu on the Start menu, jump lists, and shortcuts at the bottom of the 'File' menu in applications.
Function DisableRecentFiles {
	Write-Host "Disabling Recent Files Lists..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Type DWord -Value 1
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable search for app in store for unknown extensions
Function DisableSearchAppInStore {
	Write-Host "Disabling Search for App in Store for Unknown Extensions..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Hide 'Recently added' list from the Start Menu
Function HideRecentlyAddedApps {
	Write-Host "Hiding 'Recently added' List from the Start Menu..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Type DWord -Value 1
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

Function DisableServices {
	Write-Host "Stop and Disabling Unnecessary Services..." -NoNewline
    ##Xbox services
    Stop-Service -Name "XblAuthManager" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "XblAuthManager" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "XblGameSave" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "XblGameSave" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "XboxNetApiSvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "XboxNetApiSvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "XboxGipSvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "XboxGipSvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##wallet services
    Stop-Service -Name "WalletService" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "WalletService" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##RDP services
    Stop-Service -Name "RemoteAccess" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "RemoteAccess" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##WMPLayer Share services
    Stop-Service -Name "WMPNetworkSvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "WMPNetworkSvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##port sharing services
    Stop-Service -Name "NetTcpPortSharing" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "NetTcpPortSharing" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##akilli cihaz
    Stop-Service -Name "AJRouter" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "AJRouter" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##ntfs dosya baÃ„Å¸lantisi
    Stop-Service -Name "TrkWks" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "TrkWks" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##WAP Push mesaji
    Stop-Service -Name "dmwappushservice" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "dmwappushservice" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Bing haritalar
    Stop-Service -Name "MapsBroker" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "MapsBroker" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Faks
    Stop-Service -Name "Fax" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "Fax" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##cevrimdiÃ…Å¸i aÃ„Å¸ klasorleri
    Stop-Service -Name "CscService" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "CscService" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Ebeveyn denetimleri
    Stop-Service -Name "WpcMonSvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "WpcMonSvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##taÃ…Å¸inabilir cihaz numaralandirma
    Stop-Service -Name "WPDBusEnum" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "WPDBusEnum" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Uyumluluk modu
    Stop-Service -Name "PcaSvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "PcaSvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##uzak kayit defteri
    Stop-Service -Name "RemoteRegistry" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "RemoteRegistry" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##demo modu
    Stop-Service -Name "RetailDemo" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "RetailDemo" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##ikincil oturum acma
    Stop-Service -Name "seclogon" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "seclogon" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##NetBIOS
    Stop-Service -Name "lmhosts" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "lmhosts" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Windows hata gonderme
    Stop-Service -Name "WerSvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "WerSvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Insider hizmeti
    Stop-Service -Name "wisvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "wisvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##bluetooth
    Stop-Service -Name "BTAGService" -Force -ErrorAction SilentlyContinue
    Stop-Service -Name "bthserv" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "BTAGService" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    Set-Service -Name "bthserv" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Telefon
    Stop-Service -Name "PhoneSvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "PhoneSvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Bitlocker
    Stop-Service -Name "EFS" -Force -ErrorAction SilentlyContinue
    Stop-Service -Name "BDESVC" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "EFS" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    Set-Service -Name "BDESVC" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Sertifika
    Stop-Service -Name "CertPropSvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "CertPropSvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Akilli kart
    Stop-Service -Name "SCardSvr" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "SCardSvr" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Dosya gecmiÃ…Å¸i
    Stop-Service -Name "fhsvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "fhsvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Sensor hizmeti
    Stop-Service -Name "SensorDataService" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "SensorDataService" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "SensrSvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "SensrSvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "SensorService" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "SensorService" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Biometrik servisi
    Stop-Service -Name "WbioSrvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "WbioSrvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Mobil hotspot
    Stop-Service -Name "icssvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "icssvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Konum
    Stop-Service -Name "lfsvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "lfsvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##NFC
    Stop-Service -Name "SEMgrSvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "SEMgrSvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Notification
    Stop-Service -Name "WpnService" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "WpnService" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "SENS" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "SENS" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Backup Service
    Stop-Service -Name "SDRSVC" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "SDRSVC" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Print Spooler
    Stop-Service -Name "Spooler" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "Spooler" -StartupType disabled -ErrorAction SilentlyContinue
    ##Bonjour Service
    Stop-Service -Name "Bonjour Service" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "Bonjour Service" -StartupType disabled -ErrorAction SilentlyContinue
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

#Set Wallpaper
Function SetWallpaper {
	Write-Host "Setting Desktop Wallpaper..." -NoNewline
    Copy-Item -Path "c:\after-format-main\files\hello.png" -Destination $env:USERPROFILE\Documents -Force
    Set-Itemproperty -path "HKCU:Control Panel\Desktop" -name WallPaper -value "$env:userprofile\Documents\hello.png"  | Out-Null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Always show all icons in the notification area and remove icons
Function ShowAllIcons {
	Write-Host "Show All Icons on Taskbar..." -NoNewline  
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Value 0  -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Value 1  -ErrorAction SilentlyContinue
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

#Copy Files to Documents
Function CopyFiles {
	Write-Host "Copy Files to documents..." -NoNewline
    Copy-Item -Path "c:\after-format-main\files\Tools\SpaceSniffer.exe" -Destination $env:USERPROFILE\Documents -Force *>$null
    Copy-Item -Path "c:\after-format-main\files\Tools\speedtest.exe" -Destination $env:USERPROFILE\Documents -Force *>$null
    Set-Itemproperty -path "HKCU:\Control Panel\Desktop" -name WallPaper -value "$env:userprofile\Documents\hello.png"  | Out-Null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

#Import Batch to Startup
Function ImportStartup {
	Write-Host "Importing Startup task in Task Scheduler..." -NoNewline
    Copy-Item -Path "C:\after-format-main\files\startup\" -Destination "c:\" -Recurse *>$null
    cmd /c "C:\startup\Default.cmd" *>$null
    Register-ScheduledTask -Xml (get-content 'C:\startup\Startup.xml' | out-string) -TaskName "Startup" -Force *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

##########
#endregion System Settings
##########

##########
#region Privacy Settings
##########

# Disable Telemetry 
Function DisableTelemetry {
    Write-Host `n"---------Setting Privacy Settings" -ForegroundColor Blue -BackgroundColor Black

	Write-Host `n"Disabling Telemetry..." -NoNewline
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "MaxTelemetryAllowed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type DWord -Value 0 -ErrorAction SilentlyContinue
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type DWord -Value 0 -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -Type DWord -Value 0
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null -ErrorAction SilentlyContinue
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null -ErrorAction SilentlyContinue
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null -ErrorAction SilentlyContinue
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" -ErrorAction SilentlyContinue
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" -ErrorAction SilentlyContinue
	Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null -ErrorAction SilentlyContinue
	# Office 2016 / 2019
	Disable-ScheduledTask -TaskName "Microsoft\Office\Office ClickToRun Service Monitor" -ErrorAction SilentlyContinue
	Disable-ScheduledTask -TaskName "Microsoft\Office\OfficeTelemetryAgentFallBack2016" -ErrorAction SilentlyContinue
	Disable-ScheduledTask -TaskName "Microsoft\Office\OfficeTelemetryAgentLogOn2016" -ErrorAction SilentlyContinue
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Type DWord -Value "0" *>$null
    # Privacy Settings for your device
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -Name "DisablePrivacyExperience" -Type Dword -Value "1"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MdmCommon\SettingValues" -Name "LocationSyncEnabled" -Type Dword -Value "0"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type Dword -Value "0" 
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "MaxTelemetryAllowed" -Type Dword -Value "0"
    If (!(Test-Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings")) {
		New-Item -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings" -Force | Out-Null
    }
    If (!(Test-Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy")) {
		New-Item -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Type Dword -Value "0"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" -Name "ShowedToastAtLevel" -Type Dword -Value "1"
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Input\TIPC" -Name "Enabled" -Type Dword -Value "0"
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type Dword -Value "0"
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type Dword -Value "1"
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type Dword -Value "0"
    If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI")) {
		New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" -Name "DisableMFUTracking" -Type Dword -Value "1"
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

Function AddTelemetryHost {
	Write-Host "Blocking Telemetry in Host File..." -NoNewline
    $file = "C:\Windows\System32\drivers\etc\hosts"
    $hostfile = Get-Content $file
    $hostfile += "## Disable Windows 10 Privacy ##
127.0.0.1 vortex.data.microsoft.com
127.0.0.1 vortex-win.data.microsoft.com
127.0.0.1 telecommand.telemetry.microsoft.com
127.0.0.1 telecommand.telemetry.microsoft.com.nsatc.net
127.0.0.1 oca.telemetry.microsoft.com
127.0.0.1 oca.telemetry.microsoft.com.nsatc.net
127.0.0.1 sqm.telemetry.microsoft.com
127.0.0.1 sqm.telemetry.microsoft.com.nsatc.net
127.0.0.1 watson.telemetry.microsoft.com
127.0.0.1 watson.telemetry.microsoft.com.nsatc.net
127.0.0.1 redir.metaservices.microsoft.com
127.0.0.1 choice.microsoft.com
127.0.0.1 choice.microsoft.com.nsatc.net
127.0.0.1 df.telemetry.microsoft.com
127.0.0.1 reports.wes.df.telemetry.microsoft.com
127.0.0.1 wes.df.telemetry.microsoft.com
127.0.0.1 services.wes.df.telemetry.microsoft.com
127.0.0.1 sqm.df.telemetry.microsoft.com
127.0.0.1 telemetry.microsoft.com
127.0.0.1 watson.ppe.telemetry.microsoft.com
127.0.0.1 telemetry.appex.bing.net
127.0.0.1 telemetry.urs.microsoft.com
127.0.0.1 telemetry.appex.bing.net:443
127.0.0.1 settings-sandbox.data.microsoft.com
127.0.0.1 vortex-sandbox.data.microsoft.com
127.0.0.1 survey.watson.microsoft.com
127.0.0.1 watson.live.com
127.0.0.1 watson.microsoft.com
127.0.0.1 statsfe2.ws.microsoft.com
127.0.0.1 corpext.msitadfs.glbdns2.microsoft.com
127.0.0.1 compatexchange.cloudapp.net
127.0.0.1 cs1.wpc.v0cdn.net
127.0.0.1 a-0001.a-msedge.net
127.0.0.1 statsfe2.update.microsoft.com.akadns.net
127.0.0.1 diagnostics.support.microsoft.com
127.0.0.1 corp.sts.microsoft.com
127.0.0.1 statsfe1.ws.microsoft.com
127.0.0.1 pre.footprintpredict.com
127.0.0.1 i1.services.social.microsoft.com
127.0.0.1 i1.services.social.microsoft.com.nsatc.net
127.0.0.1 bingads.microsoft.com
127.0.0.1 www.bingads.microsoft.com
    ## END Windows 10 Privacy Settings ##"
    Set-Content -Path $file -Value $hostfile -Force *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable Feedback 
Function DisableFeedback {
	Write-Host "Disabling Feedback..." -NoNewline
	If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
		New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable Activity History feed in Task View 
Function DisableActivityHistory {
	Write-Host "Disabling Activity History..." -NoNewline
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable setting 'Let websites provide locally relevant content by accessing my language list' 
Function DisableWebLangList {
	Write-Host "Disabling Website Access to Language List..." -NoNewline
	Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type DWord -Value 1
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Stop and disable Connected User Experiences and Telemetry (previously named Diagnostics Tracking Service)
Function DisableDiagTrack {
	Write-Host "Stopping and Disabling Connected User Experiences and Telemetry Service..." -NoNewline
	Stop-Service "DiagTrack" -WarningAction SilentlyContinue
	Set-Service "DiagTrack" -StartupType Disabled
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable Advertising ID 
Function DisableAdvertisingID {
	Write-Host "Disabling Advertising ID..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable Wi-Fi Sense
Function DisableWiFiSense {
	Write-Host "Disabling Wi-Fi Sense..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable Application suggestions and automatic installation
Function DisableAppSuggestions {
	Write-Host "Disabling Application Suggestions..." -NoNewline
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Type DWord -Value 0
	# Empty placeholder tile collection in registry cache and restart Start Menu process to reload the cache
	If ([System.Environment]::OSVersion.Version.Build -ge 17134) {
		$key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*windows.data.placeholdertilecollection\Current"
		Set-ItemProperty -Path $key.PSPath -Name "Data" -Type Binary -Value $key.Data[0..15]
		Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
	}
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable UWP apps background access - ie. if UWP apps can download data or update themselves when they aren't used
Function DisableUWPBackgroundApps {
	Write-Host "Disabling UWP Apps Background Access..." -NoNewline
	If ([System.Environment]::OSVersion.Version.Build -ge 17763) {
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Type DWord -Value 2
	} Else {
		Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*", "Microsoft.Windows.ShellExperienceHost*" | ForEach-Object {
			Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
			Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
		}
	}
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable access to voice activation from UWP apps
Function DisableUWPVoiceActivation {
	Write-Host "Disabling Access to Voice Activation from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoice" -Type DWord -Value 2
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable access to notifications from UWP apps
Function DisableUWPNotifications {
	Write-Host "Disabling Access to Notifications from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable access to account info from UWP apps
Function DisableUWPAccountInfo {
	Write-Host "Disabling Access to account Info from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable access to contacts from UWP apps
Function DisableUWPContacts {
	Write-Host "Disabling Access to Contacts from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable access to calendar from UWP apps
Function DisableUWPCalendar {
	Write-Host "Disabling Access to Calendar from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable access to phone calls from UWP apps
Function DisableUWPPhoneCalls {
	Write-Host "Disabling Access to Phone Calls from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable access to call history from UWP apps
Function DisableUWPCallHistory {
	Write-Host "Disabling Access to Call History from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable access to email from UWP apps
Function DisableUWPEmail {
	Write-Host "Disabling Access to Email from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessEmail" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable access to tasks from UWP apps
Function DisableUWPTasks {
	Write-Host "Disabling Access to Tasks from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTasks" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable access to messaging (SMS, MMS) from UWP apps
Function DisableUWPMessaging {
	Write-Host "Disabling Access to Messaging from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable access to radios (e.g. Bluetooth) from UWP apps
Function DisableUWPRadios {
	Write-Host "Disabling Access to Radios from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessRadios" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable access to other devices (unpaired, beacons, TVs etc.) from UWP apps
Function DisableUWPOtherDevices {
	Write-Host "Disabling Access to Other Devices from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable access to diagnostic information from UWP apps
Function DisableUWPDiagInfo {
	Write-Host "Disabling Access to Diagnostic Information from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsGetDiagnosticInfo" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable access to libraries and file system from UWP apps
Function DisableUWPFileSystem {
	Write-Host "Disabling Access to Libraries and File System from UWP Apps..." -NoNewline
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Name "Value" -Type String -Value "Deny"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Name "Value" -Type String -Value "Deny"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Name "Value" -Type String -Value "Deny"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Name "Value" -Type String -Value "Deny"
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable UWP apps swap file
# This disables creation and use of swapfile.sys and frees 256 MB of disk space. Swapfile.sys is used only by UWP apps. The tweak has no effect on the real swap in pagefile.sys.
Function DisableUWPSwapFile {
	Write-Host "Disabling UWP Apps Swap File..." -NoNewline
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "SwapfileControl" -Type Dword -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable automatic Maps updates 
Function DisableMapUpdates {
	Write-Host "Disabling Automatic Maps Updates..." -NoNewline
	Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable automatic restart after Windows Update installation
# The tweak is slightly experimental, as it registers a dummy debugger for MusNotification.exe
# which blocks the restart prompt executable from running, thus never schedulling the restart  
Function DisableUpdateRestart {
	Write-Host "Disabling Windows Update Automatic Restart..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe" -Name "Debugger" -Type String -Value "cmd.exe"
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable Windows Update automatic downloads 
Function DisableUpdateAutoDownload {
	Write-Host "Disabling Windows Update Automatic Downloads..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

##########
#endregion Privacy Settings
##########

##########
#region Remove Unused Apps/Softwares
##########

# Remove Apps 
Function UninstallThirdPartyBloat {
    Write-Host `n"---------Remove Unused Apps/Softwares" -ForegroundColor Blue -BackgroundColor Black

	Write-Host `n"Uninstalling Default Third Party Applications..." -NoNewline
    $progressPreference = 'silentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.WindowsAlarms | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -Allusers Microsoft.AppConnector | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.Cortana | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -Allusers Microsoft.549981C3F5F10 | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.YourPhone | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.Edge| Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.BingFinance | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.BingFoodAndDrink | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.BingHealthAndFitness | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.BingMaps | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.BingNews | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.BingSports | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.BingTranslator | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.BingTravel | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.BingWeather | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.WindowsFeedbackHub| Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.GetHelp| Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.3DBuilder | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.MicrosoftOfficeHub | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers *Skype* | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.Getstarted | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.WindowsZuneMusic | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.ZuneMusic | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.WindowsMaps | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -Allusers Microsoft.Skydrive | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers *messaging* | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.MicrosoftSolitaireCollection | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.WindowsZuneVideo | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.ZuneVideo | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.Office.OneNote | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.OneConnect | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.People | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.WindowsPhone | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.Windows.Photos | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.Reader | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.Office.Sway | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.SoundRecorder | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.XboxApp | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers *ACG* | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers *CandyCrush* | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers *Facebook* | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers *Plex* | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers *Spotify* | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers *Twitter* | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers *Viber* | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers *3d* | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers *comm* | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers *mess* | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.CommsPhone | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.ConnectivityStore | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.FreshPaint | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.GetHelp | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.Getstarted | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.HelpAndTips | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.Media.PlayReadyClient.2 | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.Messaging | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.Microsoft3DViewer | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.MicrosoftOfficeHub | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.MicrosoftPowerBIForWindows | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.MicrosoftSolitaireCollection | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.MinecraftUWP | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.MixedReality.Portal | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.MoCamera | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.MSPaint | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.NetworkSpeedTest | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.OfficeLens | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.Office.OneNote | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.Office.Sway | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.OneConnect | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.People | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.Print3D | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.Reader | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.SkypeApp | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.Todos | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.Wallet | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.WebMediaExtensions | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.Whiteboard | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.WindowsAlarms | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers microsoft.windowscommunicationsapps | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.WindowsFeedbackHub | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.WindowsMaps | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.WindowsPhone | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.Windows.Photos | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.WindowsReadingList | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.WindowsScan | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.WindowsSoundRecorder | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.WinJS.1.0 | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.WinJS.2.0 | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.YourPhone | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.ZuneMusic | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.ZuneVideo | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.Advertising.Xaml | Remove-AppxPackage  | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers *Microsoft.ScreenSketch*  | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Get-AppxPackage "2414FC7A.Viber" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "41038Axilesoft.ACGMediaPlayer" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "46928bounde.EclipseManager" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "4DF9E0F8.Netflix" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "64885BlueEdge.OneCalendar" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "7EE7776C.LinkedInforWindows" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "828B5831.HiddenCityMysteryofShadows" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "89006A2E.AutodeskSketchBook" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "A278AB0D.DisneyMagicKingdoms" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "A278AB0D.DragonManiaLegends" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "A278AB0D.MarchofEmpires" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "ActiproSoftwareLLC.562882FEEB491" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "AD2F1837.GettingStartedwithWindows8" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "AD2F1837.HPJumpStart" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "AD2F1837.HPRegistration" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "AdobeSystemsIncorporated.AdobePhotoshopExpress" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "Amazon.com.Amazon" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "C27EB4BA.DropboxOEM" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "CAF9E577.Plex" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "CyberLinkCorp.hs.PowerMediaPlayer14forHPConsumerPC" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "D52A8D61.FarmVille2CountryEscape" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "D5EA27B7.Duolingo-LearnLanguagesforFree" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "DB6EA5DB.CyberLinkMediaSuiteEssentials" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "DolbyLaboratories.DolbyAccess" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "Drawboard.DrawboardPDF" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "Facebook.Facebook" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "Fitbit.FitbitCoach" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "flaregamesGmbH.RoyalRevolt2" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "GAMELOFTSA.Asphalt8Airborne" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "KeeperSecurityInc.Keeper" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "king.com.BubbleWitch3Saga" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "king.com.CandyCrushFriends" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "king.com.CandyCrushSaga" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "king.com.FarmHeroesSaga" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "Nordcurrent.CookingFever" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "PandoraMediaInc.29680B314EFC2" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "PricelinePartnerNetwork.Booking.comBigsavingsonhot" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "SpotifyAB.SpotifyMusic" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "ThumbmunkeysLtd.PhototasticCollage" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "WinZipComputing.WinZipUniversal" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
	Get-AppxPackage "XINGAG.XING" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

# Uninstall Windows Media Player
Function UninstallMediaPlayer {
	Write-Host "Uninstalling Windows Media Player..." -NoNewline
    $progressPreference = 'silentlyContinue'
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "WindowsMediaPlayer" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Media.WindowsMediaPlayer*" } | Remove-WindowsCapability -Online | Out-Null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Uninstall Work Folders Client - Not applicable to Server
Function UninstallWorkFolders {
	Write-Host "Uninstalling Work Folders Client..." -NoNewline
    $progressPreference = 'silentlyContinue'
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "WorkFolders-Client" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Uninstall Microsoft XPS Document Writer 
Function UninstallXPSPrinter {
	Write-Host "Uninstalling Microsoft XPS Document Writer..." -NoNewline
    Remove-Printer -Name "Microsoft XPS Document Writer" -ErrorAction SilentlyContinue
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Remove Default Fax Printer 
Function RemoveFaxPrinter {
	Write-Host "Removing Default Fax Printer..." -NoNewline
	Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

# Disable OneDrive
Function DisableOneDrive {
	Write-Host "Disabling & Uninstalling OneDrive..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

Function UninstallOneDrive {
$TeamsPath = [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Microsoft', 'Teams')
$TeamsUpdateExePath = [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Microsoft', 'Teams', 'Update.exe')

try
{
    if (Test-Path -Path $TeamsUpdateExePath) {
        Write-Host "Uninstalling Teams process"

        # Uninstall app
        $proc = Start-Process -FilePath $TeamsUpdateExePath -ArgumentList "-uninstall -s" -PassThru
        $proc.WaitForExit()
    }
    if (Test-Path -Path $TeamsPath) {
        Write-Host "Deleting Teams directory"
        Remove-Item -Path $TeamsPath -Recurse
                    
    }
}
catch
{
    Write-Error -ErrorRecord $_
    exit /b 1
}
}
# Disable Edge desktop shortcut creation after certain Windows updates are applied 
Function UninstallEdge {
	Write-Host "Removing Microsoft Edge..." -NoNewline
	cd "c:\after-format-main\files" *>$null
    .\remove_edge.bat *>$null
    Remove-Item -Path $env:temp\edge_version.txt -Force
    Get-ChildItem $env:USERPROFILE\Desktop\*.lnk|ForEach-Object { Remove-Item $_ }
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

# Uninstall Windows Fax and Scan Services - Not applicable to Server
Function UninstallFaxAndScan {
	Write-Host "Uninstalling Windows Fax and Scan Services..." -NoNewline
    $progressPreference = 'silentlyContinue'
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "FaxServicesClientPackage" } | Disable-WindowsOptionalFeature -Online -NoRestart | Out-Null
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Print.Fax.Scan*" } | Remove-WindowsCapability -Online | Out-Null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

##########
#endregion Remove Download Unused
##########

##########
#region Install Softwares
##########

Function Winget {
    Write-Host `n"---------Install Softwares" -ForegroundColor Blue -BackgroundColor Black

    Write-Host `n"Installing Winget..." -NoNewline
    $progressPreference = 'silentlyContinue'
	Add-AppxPackage -Path https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx *>$null
    Add-AppxPackage -Path https://github.com/microsoft/winget-cli/releases/download/v1.1.12653/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

Function InstallSoftwares {
    Write-Host "Installing 7-Zip..." -NoNewline
cmd.exe /c "winget install 7-Zip -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 

    Write-Host "Installing Firefox..." -NoNewline
cmd.exe /c "winget install Mozilla.Firefox -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 

    Write-Host "Installing Chrome..." -NoNewline
cmd.exe /c "winget install Google.Chrome -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 

    Write-Host "Installing PuTTY..." -NoNewline
cmd.exe /c "winget install PuTTY -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 

    Write-Host "Installing iTunes..." -NoNewline
cmd.exe /c "winget install iTunes -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 

    Write-Host "Installing Notepad++..." -NoNewline
cmd.exe /c "winget install Notepad++ -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 

    Write-Host "Installing VMWare Workstation Pro..." -NoNewline
cmd.exe /c "winget install VMware.WorkstationPro -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 

    Write-Host "Installing Filezilla..." -NoNewline
cmd.exe /c "winget install TimKosse.FileZilla.Client -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
    
    Write-Host "Installing Deluge..." -NoNewline
cmd.exe /c "winget install DelugeTeam.Deluge -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 

    Write-Host "Installing HWMonitor..." -NoNewline
cmd.exe /c "winget install hwmonitor -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 

    Write-Host "Installing Cryptomator..." -NoNewline
cmd.exe /c "winget install Cryptomator -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 

    Write-Host "Installing LibreOffice..." -NoNewline
cmd.exe /c "winget install LibreOffice -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 

    Write-Host "Installing Wireshark..." -NoNewline
cmd.exe /c "winget install Wireshark -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 

    Write-Host "Installing VirtualBox..." -NoNewline
cmd.exe /c "winget install Oracle.VirtualBox -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 

    Write-Host "Installing Steam..." -NoNewline
cmd.exe /c "winget install Steam -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 

    Write-Host "Installing Signal Desktop..." -NoNewline
cmd.exe /c "winget install OpenWhisperSystems.Signal -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 

    Write-Host "Installing Rufus..." -NoNewline
cmd.exe /c "winget install Rufus -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 

    Write-Host "Installing K-Lite Codec Pack Mega..." -NoNewline
cmd.exe /c "winget install CodecGuide.K-LiteCodecPack.Mega -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 

    Write-Host "Installing TreeSize..." -NoNewline
cmd.exe /c "winget install TreeSize -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 

    Write-Host "Installing Speedtest..." -NoNewline
cmd.exe /c "winget install Ookla.Speedtest -e --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 

    Write-Host "Installing AnyDesk..." -NoNewline
cmd.exe /c "winget install AnyDesk -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
    
    Write-Host "Installing Visual Studio Code..." -NoNewline
cmd.exe /c "winget install Microsoft.VisualStudioCode -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 

    Write-Host "Installing Windows Terminal..." -NoNewline
$progressPreference = 'silentlyContinue'
Invoke-WebRequest -Uri 'https://github.com/microsoft/terminal/releases/download/v1.12.10982.0/Microsoft.WindowsTerminal_Win10_1.12.10982.0_8wekyb3d8bbwe.msixbundle' -OutFile 'C:\WindowsTerminal.msixbundle'
Add-AppPackage -path "C:\WindowsTerminal.msixbundle"
Remove-Item -Path C:\WindowsTerminal.msixbundle -recurse
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

##########
#endregion Install Software
##########

Function Restart {
cmd.exe /c "shutdown /r /t 0"
}
