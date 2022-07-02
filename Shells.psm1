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

Function Priority {
    $progressPreference = 'silentlyContinue'
    Get-WindowsPackage -Online | Where PackageName -like *QuickAssist*15** | Remove-WindowsPackage -Online -NoRestart -WarningAction SilentlyContinue *>$null
}

RequireAdmin
Priority

##########
#endregion Priority
##########

##########
#region System Settings
##########

Write-Host `n"Do you want " -NoNewline
Write-Host "System Settings?" -ForegroundColor Yellow -NoNewline
Write-Host "(y/n): " -ForegroundColor Green -NoNewline
$systemset = Read-Host

if ($systemset -match "[Yy]") {

Write-Host `n"---------Adjusting System Settings" -ForegroundColor Blue -BackgroundColor Black

#Set TR Formatss
Function TRFormats {
    Write-Host `n"Do you want to " -NoNewline
    Write-Host "change the region settings to Turkey?" -BackgroundColor Yellow -ForegroundColor Black -NoNewline
    Write-Host "(y/n): " -ForegroundColor Green -NoNewline
    $input = Read-Host
    if ($input -match "[Yy]") {
    Write-Host "Setting date format of Turkey..." -NoNewline
    Set-TimeZone -Name "Turkey Standard Time"
    Set-Culture tr-TR
    Set-ItemProperty -Path "HKCU:\Control Panel\International" -name ShortDate -value "dd/MM/yyyy"
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}
else {
    Write-Host "[Turkish region format adjustment has been canceled]" -ForegroundColor Red -BackgroundColor Black
}
}

TRFormats

# Set Hostname
Function SetHostname {
    Write-Host `n"Do you want " -NoNewline
    Write-Host "change your hostname?" -BackgroundColor Yellow -ForegroundColor Black -NoNewline
    Write-Host "(y/n): " -ForegroundColor Green -NoNewline
    $input = Read-Host
    if ($input -match "[Yy]") {
    $hostq = Write-Host "Please enter your hostname: " -ForegroundColor Red -NoNewline
    $hostname = Read-Host -Prompt $hostq
    Rename-Computer -NewName "$hostname" *>$null
    Write-Host "Hostname was set to"$hostname"" -ForegroundColor Yellow -BackgroundColor Black
    }
else {
    Write-Host "[The Process Cancelled]" -ForegroundColor Red -BackgroundColor Black
}
}

SetHostname

Write-Host `n"Do you want " -NoNewline
Write-Host "disable Windows Defender?" -BackgroundColor Yellow -ForegroundColor Black -NoNewline
Write-Host "(y/n): " -ForegroundColor Green -NoNewline
$systemset = Read-Host

if ($systemset -match "[Yy]") {

# DisableDefender
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

DisableDefender

# Hide Defender Tray Icon on Taskbar
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

HideDefenderTrayIcon

}
else {
    Write-Host "[Windows Defender will not be disabled]" -ForegroundColor Red -BackgroundColor Black
}

#Default .ps1 file for Powershell
Function Defaultps1 {
    reg import "C:\after-format-main\files\default_ps.reg" *>$null
}

Defaultps1

#Get the Old Classic Right-Click Context Menu for Windows 11
Function RightClickMenu {
    Write-Host `n"Getting the Old Classic Right-Click Context Menu for Windows 11..." -NoNewline
    New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" *>$null
    New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" *>$null
    Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(Default)" -Type String -Value $null *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

RightClickMenu

#Turn Off News and Interest
Function DisableNews {
    Write-Host "Disabling News and Interes on Taskbar..." -NoNewline
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" *>$null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0 *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

DisableNews

#Default Photo Viewer Old
Function DefaultPhotoViewer {
    Write-Host "Default Old Photo Viewer..." -NoNewline
    reg import "C:\after-format-main\files\default_foto.reg" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

DefaultPhotoViewer

# Set Dark Mode for Applications
Function SetAppsDarkMode {
	Write-Host "Setting Dark Mode for Applications..." -NoNewline
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

SetAppsDarkMode

# Set Dark Mode for System - Applicable since 1903
Function SetSystemDarkMode {
	Write-Host "Setting Dark Mode for System..." -NoNewline
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

SetSystemDarkMode

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

SetControlPanelLargeIcons

# Enable NumLock after startup
Function EnableNumlock {
	Write-Host "Enabling NumLock after startup..." -NoNewline
	If (!(Test-Path "HKU:")) {
		New-PSDrive -Name "HKU" -PSProvider "Registry" -Root "HKEY_USERS" | Out-Null
	}
	Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value "2147483650"
	Add-Type -AssemblyName System.Windows.Forms
	If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

EnableNumlock

# Disable Windows Beep Sound
Function DisableBeepSound {
	Write-Host "Disabling Windows Beep Sound..." -NoNewline
	Set-ItemProperty -Path "HKCU:\Control Panel\Sound" -Name "Beep" -Type String -Value no
    Set-Service beep -StartupType disabled *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

DisableBeepSound

# Disable IPv6 stack for all installed network interfaces 
Function DisableIPv6 {
	Write-Host "Disabling IPv6 stack..." -NoNewline
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip6"
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

DisableIPv6

# Disable VMware and VirtualBox Ethernet Adapters 
Function DisableVMEthernets {
	Write-Host "Disabling Virtual Ethernet Adapters..." -NoNewline
	Disable-NetAdapter -Name "*VMware*" -Confirm:$false *>$null
    Disable-NetAdapter -Name "*Virtual*" -Confirm:$false *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

#DisableVMEthernets

# Disable Startup App 
Function DisableStartupApps {
    Write-Host "Disabling Startup Apps..." -NoNewline
    $StartPaths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32\","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run\","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run\")
    $StartFilePaths = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    $removeList = @("*Riot*","*IDMan*","*Steam*","*Teams*","*Disc*","*Epic*","*CORS*","*Next*","*One*","*Chrome*","*Opera*","*iTunes*","*CC*","*Cloud*","*Vanguard*","*Update*","*iTunes*","*Ai*","*Skype*","*Yandex*","*uTorrent*","*Deluge*","*Blitz*","*vmware*","*Any*")
    #$DisableValue = ([byte[]](0x03,0x00,0x00,0x00,0x81,0xf4,0xad,0xc9,0xa3,0x48,0xd7,0x01))
    
    #Disable
    #Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32\ -Name "vmware-tray.exe" -Value $DisableValue

    #Remove
    Remove-ItemProperty $StartPaths -Name $removeList *>$null
    Get-ChildItem -Path $StartFilePaths -Recurse | Remove-Item -force -recurse  -ErrorAction SilentlyContinue

    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

DisableStartupApps

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

SetCFDNS

# Hide Taskbar People icon
Function HideTaskbarPeopleIcon {
	Write-Host "Hiding People Icon from Taskbar..." -NoNewline
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

HideTaskbarPeopleIcon

# Hide Taskbar Taskview icon
Function HideTaskbarTaskviewIcon {
	Write-Host "Hiding Taskview Icon from Taskbar..." -NoNewline
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

HideTaskbarTaskviewIcon

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

HideTaskbarMultiTaskviewIcon

# Show small icons in taskbar
Function ShowSmallTaskbarIcons {
	Write-Host "Showing Small Icons in Taskbar..." -NoNewline
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

ShowSmallTaskbarIcons

# Hide Taskbar Search icon / box
Function HideTaskbarSearch {
	Write-Host "Hiding Taskbar Search Icon / Box..." -NoNewline
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

HideTaskbarSearch

# Hide Taskbar Remove Chat from the Taskbar
Function RemoveTaskbarChat {
	Write-Host "Removing Chat from Taskbar..." -NoNewline
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\" -Name "TaskbarMn" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

RemoveTaskbarChat

# Hide Taskbar Remove Widgets from the Taskbar
Function RemoeTaskbarWidgets {
	Write-Host "Removing Widgets from Taskbar..." -NoNewline
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\" -Name "TaskbarDa" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

RemoeTaskbarWidgets

# Hide Taskbar Start button alignment left
Function TaskbarAlignLeft {
	Write-Host "Taskbar Aligns Left..." -NoNewline
	New-itemproperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value "0" -PropertyType Dword *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

TaskbarAlignLeft

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

HideRecycleBinFromDesktop

# Disable Hiberfil - fast windows startup (with ssd) 
Function DisableHiberfil {
	Write-Host "Disabling hiberfil.sys..." -NoNewline
    powercfg -h off
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black        
}

DisableHiberfil

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

DisableSleepTimeout

# Disable receiving updates for other Microsoft products via Windows Update
Function DisableUpdateMSProducts {
	Write-Host "Disabling Updates for Other Microsoft Products..." -NoNewline
	If ((New-Object -ComObject Microsoft.Update.ServiceManager).Services | Where-Object { $_.ServiceID -eq "7971f918-a847-4430-9279-4a52d1efe18d"}) {
		(New-Object -ComObject Microsoft.Update.ServiceManager).RemoveService("7971f918-a847-4430-9279-4a52d1efe18d") | Out-Null
	}
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

DisableUpdateMSProducts

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

DisableCortana

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

DisableWebSearch

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

DisableSmartScreen

# Disable sensor features, such as screen auto rotation 
Function DisableSensors {
	Write-Host "Disabling Sensors..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -Type DWord -Value 1
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

DisableSensors

# Disable Tailored Experiences 
Function DisableTailoredExperiences {
	Write-Host "Disabling Tailored Experiences..." -NoNewline
	If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

DisableTailoredExperiences

# Disable XBox GameBar (Win+G) 
Function DisableXboxGamebar {
	Write-Host "Disabling Xbox Gamebar..." -NoNewline
    $progressPreference = 'silentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.XboxGamingOverlay | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

DisableXboxGamebar

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

DisableXboxFeatures

# Disable blocking of downloaded files (i.e. storing zone information - no need to do File\Properties\Unblock) 
Function DisableDownloadBlocking {
	Write-Host "Disabling Blocking of Downloaded Files..." -NoNewline
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Type DWord -Value 1
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

DisableDownloadBlocking

# File Explorer with 'This PC'
Function FileExplorerWithThisPC {
	Write-Host "Setting 'This PC' for File Explorer..." -NoNewline
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1 #1 'This PC' #2 'Quick Access'
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

FileExplorerWithThisPC

# File Explorer Expand Ribbon
Function FileExplorerExpandRibbon {
	Write-Host "Expanding for File Explorer..." -NoNewline
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" -Name "MinimizedStateTabletModeOff" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

FileExplorerExpandRibbon

# Disable nightly wake-up for Automatic Maintenance and Windows Updates 
Function DisableMaintenanceWakeUp {
	Write-Host "Disabling nightly wake-up for Automatic Maintenance..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "WakeUp" -Type DWord -Value 0 | Out-Null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

DisableMaintenanceWakeUp

# Disable Storage Sense - Applicable since 1703 NOT 
Function DisableStorageSense {
	Write-Host "Disabling Storage Sense..." -NoNewline
    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

DisableStorageSense

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

UnpinStartMenuTiles
Remove-TaskbarPinningApp

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

DisableAdobeFlash

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

DisableEdgePreload

# Disable Internet Explorer first run wizard 
Function DisableIEFirstRun {
	Write-Host "Disabling Internet Explorer First Run Wizard..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Type DWord -Value 1
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

DisableIEFirstRun

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

DisableMediaOnlineAccess

# Show known file extensions 
Function ShowKnownExtensions {
	Write-Host "Showing Known File Extensions..." -NoNewline
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

ShowKnownExtensions

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

DisableActionCenter

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

DisableRestorePoints

# Lower UAC level (disabling it completely would break apps) 
Function SetUACLow {
    Write-Host "Setting Low UAC Level..." -NoNewline
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

SetUACLow

# Fix Corrupt System Files
Function Sfc {
    Write-Host "Fixing System Files..." -NoNewline
    DISM.exe /Online /Cleanup-image /Restorehealth
    Start-Process -FilePath "${env:Windir}\System32\SFC.EXE" -ArgumentList '/scannow' -Wait -NoNewWindow -ErrorAction SilentlyContinue
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

#Sfc

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

RemoveTasks

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

#DiskClean

# Disable Scheduled Defragmentation Task 
Function DisableDefragmentation {
    Write-Host "Disabling Scheduled Defragmentation..." -NoNewline
    $progressPreference = 'silentlyContinue'
    Schtasks /Delete /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" /F *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

#DisableDefragmentation

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

EnableClearRecentFiles

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

DisableRecentFiles

# Disable search for app in store for unknown extensions
Function DisableSearchAppInStore {
	Write-Host "Disabling Search for App in Store for Unknown Extensions..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

DisableSearchAppInStore

# Hide 'Recently added' list from the Start Menu
Function HideRecentlyAddedApps {
	Write-Host "Hiding 'Recently added' List from the Start Menu..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Type DWord -Value 1
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

HideRecentlyAddedApps

Function DisableServices {
	Write-Host "Stop and Disabling Unnecessary Services..." -NoNewline
    ##Xbox Services
    Stop-Service -Name "XblAuthManager" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "XblAuthManager" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "XblGameSave" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "XblGameSave" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "XboxNetApiSvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "XboxNetApiSvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "XboxGipSvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "XboxGipSvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Wallet Services
    Stop-Service -Name "WalletService" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "WalletService" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##RDP services
    Stop-Service -Name "RemoteAccess" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "RemoteAccess" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##WMPLayer Share services
    Stop-Service -Name "WMPNetworkSvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "WMPNetworkSvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Port Sharing Services
    Stop-Service -Name "NetTcpPortSharing" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "NetTcpPortSharing" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Smart Device
    Stop-Service -Name "AJRouter" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "AJRouter" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Ntfs File Connection
    Stop-Service -Name "TrkWks" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "TrkWks" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##WAP Push message
    Stop-Service -Name "dmwappushservice" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "dmwappushservice" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Bing maps
    Stop-Service -Name "MapsBroker" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "MapsBroker" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Fax
    Stop-Service -Name "Fax" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "Fax" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Offline Files
    Stop-Service -Name "CscService" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "CscService" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Parental Controls
    Stop-Service -Name "WpcMonSvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "WpcMonSvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Removable Device Numbering
    Stop-Service -Name "WPDBusEnum" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "WPDBusEnum" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Compatibility Mode
    Stop-Service -Name "PcaSvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "PcaSvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Remote Registry
    Stop-Service -Name "RemoteRegistry" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "RemoteRegistry" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Demo Mode
    Stop-Service -Name "RetailDemo" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "RetailDemo" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Secondary Login
    Stop-Service -Name "seclogon" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "seclogon" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##NetBIOS
    Stop-Service -Name "lmhosts" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "lmhosts" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Windows Error Sending
    Stop-Service -Name "WerSvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "WerSvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Insider service
    Stop-Service -Name "wisvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "wisvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Bluetooth
    Stop-Service -Name "BTAGService" -Force -ErrorAction SilentlyContinue
    Stop-Service -Name "bthserv" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "BTAGService" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    Set-Service -Name "bthserv" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Phone
    Stop-Service -Name "PhoneSvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "PhoneSvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Bitlocker
    Stop-Service -Name "EFS" -Force -ErrorAction SilentlyContinue
    Stop-Service -Name "BDESVC" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "EFS" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    Set-Service -Name "BDESVC" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Cert
    Stop-Service -Name "CertPropSvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "CertPropSvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Smart Cart
    Stop-Service -Name "SCardSvr" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "SCardSvr" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##File history
    Stop-Service -Name "fhsvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "fhsvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Sensor services
    Stop-Service -Name "SensorDataService" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "SensorDataService" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "SensrSvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "SensrSvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "SensorService" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "SensorService" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Biometric services
    Stop-Service -Name "WbioSrvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "WbioSrvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Mobil hotspot
    Stop-Service -Name "icssvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "icssvc" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    ##Location
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
    #Google Update Services
    Stop-Service -Name "gupdate" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "gupdate" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    sc.exe delete gupdate *>$null
    Stop-Service -Name "gupdatem" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "gupdatem" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    sc.exe delete gupdatem *>$null
    Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\gupdate" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\gupdatem" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{8A69D345-D564-463c-AFF1-A69D9E530F96}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item "C:\Program Files\Google\Chrome\Application\102.0.5005.63\Installer\chrmstp.exe" -recurse -ErrorAction SilentlyContinue
}

DisableServices

#Set Wallpaper
Function SetWallpaper {
	Write-Host "Setting Desktop Wallpaper..." -NoNewline
    Copy-Item -Path "c:\after-format-main\files\hello.png" -Destination $env:USERPROFILE\Documents -Force
    Set-Itemproperty -path "HKCU:Control Panel\Desktop" -name WallPaper -value "$env:userprofile\Documents\hello.png"  | Out-Null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

SetWallpaper

# Always show all icons in the notification area and remove icons
Function ShowAllIcons {
	Write-Host "Show All Icons on Taskbar..." -NoNewline  
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Value 0  -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Value 1  -ErrorAction SilentlyContinue
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

ShowAllIcons

#Copy Files to Documents
Function CopyFiles {
	Write-Host "Copy Files to documents..." -NoNewline
    Set-Itemproperty -path "HKCU:\Control Panel\Desktop" -name WallPaper -value "$env:userprofile\Documents\hello.png"  | Out-Null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

CopyFiles

#Import Batch to Startup
Function ImportStartup {
	Write-Host "Importing Startup task in Task Scheduler..." -NoNewline
    Copy-Item -Path "C:\after-format-main\files\startup\" -Destination "c:\" -Recurse *>$null
    Unblock-File -Path C:\startup\Run.cmd *>$null
    Unblock-File -Path C:\startup\Run.vbs *>$null
    Unblock-File -Path C:\after-format-main\files\startup\upgrade.bat *>$null
    Unblock-File -Path C:\\startup\upgrade.bat *>$null
    cmd /c "C:\startup\Default.cmd" *>$null
    Register-ScheduledTask -Xml (get-content 'C:\startup\Startup.xml' | out-string) -TaskName "Startup" -Force *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

ImportStartup

}
else {
    Write-Host "[System Settings Cancelled]" -ForegroundColor Red -BackgroundColor Black
}

##########
#endregion System Settings
##########

##########
#region Privacy Settings
##########

Write-Host `n"Do you want " -NoNewline
Write-Host "Privacy Settings?" -ForegroundColor Yellow -NoNewline
Write-Host "(y/n): " -ForegroundColor Green -NoNewline
$privacyset = Read-Host

if ($privacyset -match "[Yy]") {

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

DisableTelemetry

# Block Telemetry Url's to host file
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

AddTelemetryHost

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

DisableFeedback

# Disable Activity History feed in Task View 
Function DisableActivityHistory {
	Write-Host "Disabling Activity History..." -NoNewline
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

DisableActivityHistory

# Disable setting 'Let websites provide locally relevant content by accessing my language list' 
Function DisableWebLangList {
	Write-Host "Disabling Website Access to Language List..." -NoNewline
	Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type DWord -Value 1
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

DisableWebLangList

# Stop and disable Connected User Experiences and Telemetry (previously named Diagnostics Tracking Service)
Function DisableDiagTrack {
	Write-Host "Stopping and Disabling Connected User Experiences and Telemetry Service..." -NoNewline
	Stop-Service "DiagTrack" -WarningAction SilentlyContinue
	Set-Service "DiagTrack" -StartupType Disabled
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

DisableDiagTrack

# Disable Advertising ID 
Function DisableAdvertisingID {
	Write-Host "Disabling Advertising ID..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

DisableAdvertisingID

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

DisableWiFiSense

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

DisableAppSuggestions

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

DisableUWPBackgroundApps

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

DisableUWPVoiceActivation

# Disable access to notifications from UWP apps
Function DisableUWPNotifications {
	Write-Host "Disabling Access to Notifications from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

DisableUWPNotifications

# Disable access to account info from UWP apps
Function DisableUWPAccountInfo {
	Write-Host "Disabling Access to account Info from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

DisableUWPAccountInfo

# Disable access to contacts from UWP apps
Function DisableUWPContacts {
	Write-Host "Disabling Access to Contacts from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

DisableUWPContacts

# Disable access to calendar from UWP apps
Function DisableUWPCalendar {
	Write-Host "Disabling Access to Calendar from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

DisableUWPCalendar

# Disable access to phone calls from UWP apps
Function DisableUWPPhoneCalls {
	Write-Host "Disabling Access to Phone Calls from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

DisableUWPPhoneCalls

# Disable access to call history from UWP apps
Function DisableUWPCallHistory {
	Write-Host "Disabling Access to Call History from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

DisableUWPCallHistory

# Disable access to email from UWP apps
Function DisableUWPEmail {
	Write-Host "Disabling Access to Email from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessEmail" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

DisableUWPEmail

# Disable access to tasks from UWP apps
Function DisableUWPTasks {
	Write-Host "Disabling Access to Tasks from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTasks" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

DisableUWPTasks

# Disable access to messaging (SMS, MMS) from UWP apps
Function DisableUWPMessaging {
	Write-Host "Disabling Access to Messaging from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

DisableUWPMessaging

# Disable access to radios (e.g. Bluetooth) from UWP apps
Function DisableUWPRadios {
	Write-Host "Disabling Access to Radios from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessRadios" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

DisableUWPRadios

# Disable access to other devices (unpaired, beacons, TVs etc.) from UWP apps
Function DisableUWPOtherDevices {
	Write-Host "Disabling Access to Other Devices from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

DisableUWPOtherDevices

# Disable access to diagnostic information from UWP apps
Function DisableUWPDiagInfo {
	Write-Host "Disabling Access to Diagnostic Information from UWP Apps..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsGetDiagnosticInfo" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

DisableUWPDiagInfo

# Disable access to libraries and file system from UWP apps
Function DisableUWPFileSystem {
	Write-Host "Disabling Access to Libraries and File System from UWP Apps..." -NoNewline
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Name "Value" -Type String -Value "Deny"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Name "Value" -Type String -Value "Deny"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Name "Value" -Type String -Value "Deny"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Name "Value" -Type String -Value "Deny"
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

DisableUWPFileSystem

# Disable UWP apps swap file
# This disables creation and use of swapfile.sys and frees 256 MB of disk space. Swapfile.sys is used only by UWP apps. The tweak has no effect on the real swap in pagefile.sys.
Function DisableUWPSwapFile {
	Write-Host "Disabling UWP Apps Swap File..." -NoNewline
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "SwapfileControl" -Type Dword -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

DisableUWPSwapFile

# Disable automatic Maps updates 
Function DisableMapUpdates {
	Write-Host "Disabling Automatic Maps Updates..." -NoNewline
	Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

DisableMapUpdates

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

DisableUpdateRestart

# Disable Windows Update automatic downloads 
Function DisableUpdateAutoDownload {
	Write-Host "Disabling Windows Update Automatic Downloads..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 2
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

DisableUpdateAutoDownload

}
else {
    Write-Host "[Privacy Settings Cancelled]" -ForegroundColor Red -BackgroundColor Black
}

##########
#endregion Privacy Settings
##########

##########
#region Install Softwares
##########

Write-Host `n"Do you want to " -NoNewline
Write-Host "install the specified applications on Github?" -ForegroundColor Yellow -NoNewline
Write-Host "(y/n): " -ForegroundColor Green -NoNewline
$installapps = Read-Host

if ($installapps -match "[Yy]") {

Function Winget {
    Write-Host `n"---------Install Softwares" -ForegroundColor Blue -BackgroundColor Black

    Write-Host `n"Installing Winget..." -NoNewline
    $progressPreference = 'silentlyContinue'
	Add-AppxPackage -Path https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx *>$null
    Add-AppxPackage -Path https://github.com/microsoft/winget-cli/releases/download/v1.2.10271/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

Winget

Function InstallSoftwares {
    Write-Host "Installing 7-Zip..." -NoNewline
cmd.exe /c "winget install 7-Zip -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 

    Write-Host "Installing Brave Browser..." -NoNewline
cmd.exe /c "winget install BraveSoftware.BraveBrowser -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
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
    
    Write-Host "Installing Twinkle-Tray..." -NoNewline
cmd.exe /c "winget install xanderfrangos.twinkletray -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    
    Write-Host "Installing Total Commander..." -NoNewline
cmd.exe /c "winget install Ghisler.TotalCommander -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black

    Write-Host "Installing Notepad++..." -NoNewline
cmd.exe /c "winget install Notepad++ -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 

    Write-Host "Installing VMWare Workstation Pro..." -NoNewline
cmd.exe /c "winget install VMware.WorkstationPro -e --silent --accept-source-agreements --accept-package-agreements --force"
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
    
    Write-Host "Installing Libre Wolf..." -NoNewline
cmd.exe /c "winget install LibreWolf.LibreWolf -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
    
    Write-Host "Installing VLC Media Player..." -NoNewline
cmd.exe /c "winget install VideoLAN.VLC -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
    
    Write-Host "Installing Microsoft Visual Studio Code..." -NoNewline
cmd.exe /c "winget install Microsoft.VisualStudioCode -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    
    Write-Host "Installing Nvidia GeForce Experience..." -NoNewline
cmd.exe /c "winget install Nvidia.GeForceExperience -e --silent --accept-source-agreements --accept-package-agreements --force" *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black

    Write-Host "Installing Windows Terminal..." -NoNewline
$progressPreference = 'silentlyContinue'
Invoke-WebRequest -Uri 'https://github.com/microsoft/terminal/releases/download/v1.12.10982.0/Microsoft.WindowsTerminal_Win10_1.12.10982.0_8wekyb3d8bbwe.msixbundle' -OutFile 'C:\WindowsTerminal.msixbundle'
Add-AppPackage -path "C:\WindowsTerminal.msixbundle"
Remove-Item -Path C:\WindowsTerminal.msixbundle -recurse
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

InstallSoftwares

Function Lightshot {
    Write-Host "Installing Lightshot..." -NoNewline
    $progressPreference = 'silentlyContinue'
    Invoke-WebRequest -Uri https://github.com/caglaryalcin/after-format/raw/main/files/Skillbrains.zip -OutFile C:\Skillbrains.zip *>$null
    $progressPreference = 'silentlyContinue'
    Expand-Archive -Path 'C:\Skillbrains.zip' -DestinationPath "C:\Program Files (x86)\" -Force *>$null
    $progressPreference = 'silentlyContinue'
    cmd.exe /c "C:\Program Files (x86)\Skillbrains\lightshot\Lightshot.exe"
    $startpath = ((Get-WMIObject -ClassName Win32_ComputerSystem).Username).Split('\')[1]
    Copy-Item -Path "C:\Program Files (x86)\Skillbrains\lightshot\*.lnk" -Destination "C:\Users\$startpath\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    Remove-Item C:\Skillbrains.zip -recurse -ErrorAction SilentlyContinue
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

Lightshot

Function Valorant {
    Write-Host "Installing Valorant..." -NoNewline
    $progressPreference = 'silentlyContinue'
    Invoke-WebRequest -Uri https://valorant.secure.dyn.riotcdn.net/channels/public/x/installer/current/live.live.eu.exe -OutFile C:\valo.exe
    Start-Process C:\valo.exe -NoNewWindow -Wait
    Remove-Item C:\valo.exe -recurse -ErrorAction SilentlyContinue
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

Valorant

}

else {
    Write-Host "[The Process Cancelled]" -ForegroundColor Red -BackgroundColor Black
}

##########
#endregion Install Software
##########

##########
#region Remove Unused Apps/Softwares
##########

Write-Host `n"Do you want " -NoNewline
Write-Host "Uninstall Unused Apps & Softwares?" -ForegroundColor Yellow -NoNewline
Write-Host "(y/n): " -ForegroundColor Green -NoNewline
$removeapps = Read-Host

if ($removeapps -match "[Yy]") {

# Remove Apps 
Function UninstallThirdPartyBloat {
    Write-Host `n"---------Remove Unused Apps/Softwares" -ForegroundColor Blue -BackgroundColor Black
    
    Write-Host `n"Uninstalling Default Third Party Applications..." -NoNewline
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.WindowsAlarms | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -Allusers Microsoft.AppConnector | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.Cortana | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -Allusers Microsoft.549981C3F5F10 | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.YourPhone | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.BingFinance | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.BingFoodAndDrink | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.BingHealthAndFitness | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.BingMaps | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.BingNews | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.BingSports | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.BingTranslator | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.BingTravel | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.BingWeather | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.WindowsFeedbackHub| Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.GetHelp| Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.3DBuilder | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.MicrosoftOfficeHub | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers *Skype* | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.Getstarted | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.WindowsZuneMusic | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.ZuneMusic | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.WindowsMaps | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -Allusers Microsoft.Skydrive | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers *messaging* | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.MicrosoftSolitaireCollection | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.WindowsZuneVideo | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.ZuneVideo | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.Office.OneNote | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.OneConnect | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.People | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.WindowsPhone | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.Windows.Photos | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.Reader | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.Office.Sway | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.SoundRecorder | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.XboxApp | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers *ACG* | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers *CandyCrush* | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers *Facebook* | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers *Plex* | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers *Spotify* | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers *Twitter* | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers *Viber* | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers *3d* | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers *comm* | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers *mess* | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.CommsPhone | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.ConnectivityStore | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.FreshPaint | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.GetHelp | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.Getstarted | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.HelpAndTips | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.Media.PlayReadyClient.2 | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.Messaging | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.Microsoft3DViewer | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.MicrosoftOfficeHub | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.MicrosoftPowerBIForWindows | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.MicrosoftSolitaireCollection | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.MinecraftUWP | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.MixedReality.Portal | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.MoCamera | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.MSPaint | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.NetworkSpeedTest | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.OfficeLens | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.Office.OneNote | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.Office.Sway | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.OneConnect | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.People | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.Print3D | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.Reader | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.Todos | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.Wallet | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.WebMediaExtensions | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.Whiteboard | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.WindowsAlarms | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers microsoft.windowscommunicationsapps | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.WindowsFeedbackHub | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.WindowsMaps | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.WindowsPhone | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.Windows.Photos | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.WindowsReadingList | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.WindowsScan | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.WindowsSoundRecorder | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.WinJS.1.0 | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.WinJS.2.0 | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.YourPhone | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.ZuneMusic | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.ZuneVideo | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.Advertising.Xaml | Remove-AppxPackage  | Out-Null -ErrorAction SilentlyContinue *>$null
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers *Microsoft.ScreenSketch*  | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    Get-AppxPackage "2414FC7A.Viber" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "41038Axilesoft.ACGMediaPlayer" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "46928bounde.EclipseManager" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "4DF9E0F8.Netflix" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "64885BlueEdge.OneCalendar" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "7EE7776C.LinkedInforWindows" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "828B5831.HiddenCityMysteryofShadows" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "89006A2E.AutodeskSketchBook" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "A278AB0D.DisneyMagicKingdoms" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "A278AB0D.DragonManiaLegends" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "A278AB0D.MarchofEmpires" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "ActiproSoftwareLLC.562882FEEB491" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "AD2F1837.GettingStartedwithWindows8" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "AD2F1837.HPJumpStart" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "AD2F1837.HPRegistration" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "AdobeSystemsIncorporated.AdobePhotoshopExpress" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "Amazon.com.Amazon" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "C27EB4BA.DropboxOEM" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "CAF9E577.Plex" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "CyberLinkCorp.hs.PowerMediaPlayer14forHPConsumerPC" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "D52A8D61.FarmVille2CountryEscape" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "D5EA27B7.Duolingo-LearnLanguagesforFree" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "DB6EA5DB.CyberLinkMediaSuiteEssentials" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "DolbyLaboratories.DolbyAccess" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "Drawboard.DrawboardPDF" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "Facebook.Facebook" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "Fitbit.FitbitCoach" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "flaregamesGmbH.RoyalRevolt2" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "GAMELOFTSA.Asphalt8Airborne" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "KeeperSecurityInc.Keeper" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "king.com.BubbleWitch3Saga" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "king.com.CandyCrushFriends" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "king.com.CandyCrushSaga" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "king.com.FarmHeroesSaga" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "Nordcurrent.CookingFever" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "PandoraMediaInc.29680B314EFC2" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "PricelinePartnerNetwork.Booking.comBigsavingsonhot" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "SpotifyAB.SpotifyMusic" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "ThumbmunkeysLtd.PhototasticCollage" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "WinZipComputing.WinZipUniversal" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
	Get-AppxPackage "XINGAG.XING" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
}

UninstallThirdPartyBloat

# Uninstall Windows Media Player
Function UninstallMediaPlayer {
	Write-Host "Uninstalling Windows Media Player..." -NoNewline
    $progressPreference = 'silentlyContinue'
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "WindowsMediaPlayer" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Media.WindowsMediaPlayer*" } | Remove-WindowsCapability -Online | Out-Null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

#UninstallMediaPlayer

# Uninstall Work Folders Client - Not applicable to Server
Function UninstallWorkFolders {
	Write-Host "Uninstalling Work Folders Client..." -NoNewline
    $progressPreference = 'silentlyContinue'
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "WorkFolders-Client" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

UninstallWorkFolders

# Uninstall Microsoft XPS Document Writer 
Function UninstallXPSPrinter {
	Write-Host "Uninstalling Microsoft XPS Document Writer..." -NoNewline
    Remove-Printer -Name "Microsoft XPS Document Writer" -ErrorAction SilentlyContinue 
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

UninstallXPSPrinter

# Remove Default Fax Printer 
Function RemoveFaxPrinter {
	Write-Host "Removing Default Fax Printer..." -NoNewline
	Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

RemoveFaxPrinter

# Uninstall Windows Fax and Scan Services - Not applicable to Server
Function UninstallFaxAndScan {
	Write-Host "Uninstalling Windows Fax and Scan Services..." -NoNewline
    $progressPreference = 'silentlyContinue'
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "FaxServicesClientPackage" } | Disable-WindowsOptionalFeature -Online -NoRestart *>$null
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Print.Fax.Scan*" } | Remove-WindowsCapability -Online *>$null
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

UninstallFaxAndScan

Write-Host `n"Do you want " -NoNewline
Write-Host "remove Windows OneDrive?" -BackgroundColor Yellow -ForegroundColor Black -NoNewline
Write-Host "(y/n): " -ForegroundColor Green -NoNewline
$input = Read-Host
if ($input -match "[Yy]") {

# Disable OneDrive
Function DisableOneDrive {
	Write-Host "Disabling & Uninstalling OneDrive..." -NoNewline
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
     Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
}

DisableOneDrive

Function UninstallOneDrive {
$TeamsPath = [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Microsoft', 'Teams')
$TeamsUpdateExePath = [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Microsoft', 'Teams', 'Update.exe')
cmd /c "%SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall"
try
{
    if (Test-Path -Path $TeamsUpdateExePath) {
        Write-Host "Uninstalling Teams process"

        # Uninstall app
        $proc = Start-Process -FilePath $TeamsUpdateExePath -ArgumentList "-uninstall -s" -PassThru
        $proc.WaitForExit()
        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    }
    if (Test-Path -Path $TeamsPath) {
        Write-Host "Deleting Teams directory"
        Remove-Item -Path $TeamsPath -Recurse
        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                    
    }
}
catch
{
    Write-Error -ErrorRecord $_
    exit /b 1
}
}

UninstallOneDrive

}

else {
    Write-Host "[Windows OneDrive will not be deleted]" -ForegroundColor Red -BackgroundColor Black
}

# Disable Edge desktop shortcut creation after certain Windows updates are applied 
Function UninstallEdge {
    Write-Host `n"Do you want " -NoNewline
    Write-Host "remove Windows Edge?" -BackgroundColor Yellow -ForegroundColor Black -NoNewline
    Write-Host "(y/n): " -ForegroundColor Green -NoNewline
    $input = Read-Host
    if ($input -match "[Yy]") {
	Write-Host "Removing Microsoft Edge..." -NoNewline
    taskkill /f /im msedge.exe *>$null
    cd "C:\Program Files (x86)\Microsoft\Edge\Application\103*\Installer\"
    .\setup.exe -uninstall -system-level -verbose-logging -force-uninstall
    Get-ChildItem C:\users\Public\Desktop\*.lnk|ForEach-Object { Remove-Item $_ }
    Get-ChildItem $env:USERPROFILE\Desktop\*.lnk|ForEach-Object { Remove-Item $_ }
    $progressPreference = 'SilentlyContinue'
    Get-AppxPackage -AllUsers Microsoft.Edge | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
    Remove-Item "C:\Program Files (x86)\Microsoft\*edge*" -recurse -ErrorAction SilentlyContinue
    Remove-Item "C:\Program Files (x86)\Microsoft\Edge" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item "C:\Program Files (x86)\Microsoft\Temp" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item "C:\Program Files (x86)\Microsoft\*" -Force -Recurse -ErrorAction SilentlyContinue
    
    #Edge Services
    Stop-Service -Name "edgeupdate" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "edgeupdate" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    sc.exe delete edgeupdate *>$null
    Stop-Service -Name "edgeupdatem" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "edgeupdatem" -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
    sc.exe delete edgeupdatem *>$null
    Start-Sleep 3
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
}

else {
    Write-Host "[Windows Edge will not be deleted]" -ForegroundColor Red -BackgroundColor Black
}
}

UninstallEdge

}
else {
    Write-Host "[The Process Cancelled]" -ForegroundColor Red -BackgroundColor Black
}

##########
#endregion Remove Unused Apps/Softwares
##########

##########
#region My Custom Drivers
##########

Write-Host `n"Do you own " -NoNewline
Write-Host "this script?" -ForegroundColor Red -NoNewline -BackgroundColor Black
Write-Host "(Drivers will be installed): " -NoNewline
$systemset = Read-Host

if ($systemset -match "[Yy]") {

Function Own {

#Sound Settings
#Get-PnpDevice -FriendlyName "*Microsoft*" | Disable-PnpDevice -confirm:$false *>$null

###Taskbar Pins
##Create Icons folder
New-Item -Path 'C:\after-format-main\files\icons' -ItemType Directory *>$null

##Create Shortcuts
#Firefox
$WScriptShell = New-Object -ComObject WScript.Shell
$Firefox = "C:\Program Files\Mozilla Firefox\firefox.exe"
$ShortcutFile = "C:\after-format-main\files\icons\Firefox.lnk"
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $Firefox
$Shortcut.Save()
Unblock-File -Path "C:\after-format-main\files\icons\Firefox.lnk" *>$null

#Librewolf
$WScriptShell = New-Object -ComObject WScript.Shell
$Librewolf = "C:\Program Files\LibreWolf\librewolf.exe"
$ShortcutFile = "C:\after-format-main\files\icons\LibreWolf.lnk"
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $Librewolf
$Shortcut.Save()
Unblock-File -Path "C:\after-format-main\files\icons\LibreWolf.lnk" *>$null

#Chrome
$WScriptShell = New-Object -ComObject WScript.Shell
$Chrome = "C:\Program Files\Google\Chrome\Application\chrome.exe"
$ShortcutFile = "C:\after-format-main\files\icons\Google Chrome.lnk"
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $Chrome
$Shortcut.Save()
Unblock-File -Path "C:\after-format-main\files\icons\Google Chrome.lnk" *>$null

#Brave
$WScriptShell = New-Object -ComObject WScript.Shell
$Brave = "$env:USERPROFILE\AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe"
$BraveDirectory = "C:\Users\m4a1\AppData\Local\BraveSoftware\Brave-Browser\Application"
$Shortcut.WorkingDirectory = "C:\Users\m4a1\AppData\Local\BraveSoftware\Brave-Browser\Application"
$ShortcutFile = "C:\after-format-main\files\icons\Brave.lnk"
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $Brave
$Shortcut.WorkingDirectory = $BraveDirectory
$Shortcut.Save()
Unblock-File -Path "C:\after-format-main\files\icons\Brave.lnk" *>$null

#File Explorer was here

#Steam
$WScriptShell = New-Object -ComObject WScript.Shell
$Steam = "C:\Program Files (x86)\Steam\Steam.exe"
$ShortcutFile = "C:\after-format-main\files\icons\Steam.lnk"
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $Steam
$Shortcut.Save()
Unblock-File -Path "C:\after-format-main\files\icons\Steam.lnk" *>$null

#HWMonitor
$WScriptShell = New-Object -ComObject WScript.Shell
$HW = "C:\Program Files\CPUID\HWMonitor\HWMonitor.exe"
$ShortcutFile = "C:\after-format-main\files\icons\HWMonitor.lnk"
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $HW
$Shortcut.Save()
Unblock-File -Path "C:\after-format-main\files\icons\HWMonitor.lnk" *>$null

#vMware Workstation
$WScriptShell = New-Object -ComObject WScript.Shell
$vMware = "C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe"
$ShortcutFile = "C:\after-format-main\files\icons\VMware Workstation Pro.lnk"
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $vMware
$Shortcut.Save()
Unblock-File -Path "C:\after-format-main\files\icons\VMware Workstation Pro.lnk" *>$null

#VirtualBox
$WScriptShell = New-Object -ComObject WScript.Shell
$VirtualBox = "C:\Program Files\Oracle\VirtualBox\VirtualBox.exe"
$ShortcutFile = "C:\after-format-main\files\icons\Oracle VM VirtualBox.lnk"
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $VirtualBox
$Shortcut.Save()
Unblock-File -Path "C:\after-format-main\files\icons\Oracle VM VirtualBox.lnk" *>$null

#Signal
$WScriptShell = New-Object -ComObject WScript.Shell
$Signal = "C:\Users\m4a1\AppData\Local\Programs\signal-desktop\Signal.exe"
$ShortcutFile = "C:\after-format-main\files\icons\Signal.lnk"
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $Signal
$Shortcut.Save()
Unblock-File -Path "C:\after-format-main\files\icons\Signal.lnk" *>$null

#Sticky Notes was here

#Visual Studio
$WScriptShell = New-Object -ComObject WScript.Shell
$Visual = "C:\Users\m4a1\AppData\Local\Programs\Microsoft VS Code\Code.exe"
$ShortcutFile = "C:\after-format-main\files\icons\Visual Studio Code.lnk"
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $Visual
$Shortcut.Save()
Unblock-File -Path "C:\after-format-main\files\icons\Visual Studio Code.lnk" *>$null

#AnyDesk
$WScriptShell = New-Object -ComObject WScript.Shell
$Anydesk = "C:\Program Files (x86)\AnyDeskMSI\AnyDeskMSI.exe"
$ShortcutFile = "C:\after-format-main\files\icons\AnyDesk.lnk"
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $Anydesk
$Shortcut.Save()
Unblock-File -Path "C:\after-format-main\files\icons\AnyDesk.lnk" *>$null

#Terminal was here

#Speedtest
$WScriptShell = New-Object -ComObject WScript.Shell
$Speedtest = "C:\Program Files\Speedtest\Speedtest.exe"
$ShortcutFile = "C:\after-format-main\files\icons\Speedtest.lnk"
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $Speedtest
$Shortcut.Save()
Unblock-File -Path "C:\after-format-main\files\icons\Speedtest.lnk" *>$null

#Notepad++
$WScriptShell = New-Object -ComObject WScript.Shell
$Notepad = "C:\Program Files\Notepad++\notepad++.exe"
$ShortcutFile = "C:\after-format-main\files\icons\Notepad++.lnk"
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $Notepad
$Shortcut.Save()
Unblock-File -Path "C:\after-format-main\files\icons\Notepad++.lnk" *>$null

#VLC
$WScriptShell = New-Object -ComObject WScript.Shell
$VLC = "C:\Program Files\VideoLAN\VLC\vlc.exe"
$ShortcutFile = "C:\after-format-main\files\icons\VLC media player.lnk"
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $VLC
$Shortcut.Save()
Unblock-File -Path "C:\after-format-main\files\icons\VLC media player.lnk" *>$null

#Calculator was here

#TreeSize
$WScriptShell = New-Object -ComObject WScript.Shell
$TreeSize = "C:\Program Files\JAM Software\TreeSize\TreeSize.exe"
$TreeSizePath = "C:\Program Files\JAM Software\TreeSize"
$ShortcutFile = "C:\after-format-main\files\icons\TreeSize (2).lnk"
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TreeSize
$Shortcut.WorkingDirectory = $TreeSizePath
$Shortcut.Save()
Unblock-File -Path "C:\after-format-main\files\icons\TreeSize (2).lnk" *>$null

#Total Commander
$WScriptShell = New-Object -ComObject WScript.Shell
$TCM = "C:\Program Files\totalcmd\TOTALCMD64.EXE"
$ShortcutFile = "C:\after-format-main\files\icons\Total Commander.lnk"
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TCM
$Shortcut.Save()
Unblock-File -Path "C:\after-format-main\files\icons\Total Commander.lnk" *>$null

#Rufus was here

#WireShark
$WScriptShell = New-Object -ComObject WScript.Shell
$WireShark = "C:\Program Files\Wireshark\Wireshark.exe"
$ShortcutFile = "C:\after-format-main\files\icons\WireShark.lnk"
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $WireShark
$Shortcut.Save()
Unblock-File -Path "C:\after-format-main\files\icons\WireShark.lnk" *>$null

#Putty
$WScriptShell = New-Object -ComObject WScript.Shell
$Putty = "C:\Program Files\PuTTY\putty.exe"
$ShortcutFile = "C:\after-format-main\files\icons\Putty.lnk"
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $Putty
$Shortcut.Save()
Unblock-File -Path "C:\after-format-main\files\icons\Putty.lnk" *>$null

#Filezilla
$WScriptShell = New-Object -ComObject WScript.Shell
$Filezilla = "C:\Program Files\FileZilla FTP Client\filezilla.exe"
$ShortcutFile = "C:\after-format-main\files\icons\Filezilla.lnk"
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $Filezilla
$Shortcut.Save()
Unblock-File -Path "C:\after-format-main\files\icons\Filezilla.lnk" *>$null

#Deluge
$WScriptShell = New-Object -ComObject WScript.Shell
$Deluge = "C:\Program Files (x86)\Deluge\deluge.exe"
$ShortcutFile = "C:\after-format-main\files\icons\Deluge.lnk"
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $Deluge
$Shortcut.Save()
Unblock-File -Path "C:\after-format-main\files\icons\Deluge.lnk" *>$null

#Cryptomator
$WScriptShell = New-Object -ComObject WScript.Shell
$Cryptomator = "C:\Program Files\Cryptomator\Cryptomator.exe"
$ShortcutFile = "C:\after-format-main\files\icons\Cryptomator.lnk"
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $Cryptomator
$Shortcut.Save()
Unblock-File -Path "C:\after-format-main\files\icons\Cryptomator.lnk" *>$null

#Set Pin
$progressPreference = 'silentlyContinue'
Get-ChildItem $env:USERPROFILE\Desktop\*|ForEach-Object { Remove-Item $_ }
Get-ChildItem C:\users\Public\Desktop\*.lnk|ForEach-Object { Remove-Item $_ }
reg import "C:\after-format-main\files\taskbar_pin.reg" *>$null
Copy-Item -Path "C:\after-format-main\files\icons\*" -Destination "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\" -Force
reg import "C:\after-format-main\files\taskbar_pin.reg" *>$null
taskkill /f /im explorer.exe
Start-Sleep 1
start explorer.exe
Start-Sleep 2

#Drivers
Write-Host `n"Installing Chipset Driver..." -NoNewline
$progressPreference = 'silentlyContinue'
Invoke-WebRequest -Uri https://dlcdnets.asus.com/pub/ASUS/mb/03CHIPSET/DRV_Chipset_Intel_CML_TP_W10_64_V101182958201_20200423R.zip -OutFile C:\Asus.zip
$progressPreference = 'silentlyContinue'
Expand-Archive -Path 'C:\Asus.zip' -DestinationPath C:\Asus\ -Force *>$null
$progressPreference = 'silentlyContinue'
C:\Asus\SetupChipset.exe -s
Remove-Item C:\Asus -recurse -ErrorAction SilentlyContinue
Remove-Item C:\Asus.zip -recurse -ErrorAction SilentlyContinue
Start-Sleep 20

Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black

}

Own

}

else {
    Write-Host "[The Process Cancelled]" -ForegroundColor Green -BackgroundColor Black
}


##########
#endregion My Custom Drivers
##########

Function Restart {
cmd.exe /c "shutdown /r /t 0"
}

Restart
