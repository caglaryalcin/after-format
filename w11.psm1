##########
#region Priority
##########

Function Priority {
    $ErrorActionPreference = 'SilentlyContinue'
    New-PSDrive -PSProvider Registry -Name HKCU -Root HKEY_CURRENT_USER | Out-Null
    New-PSDrive -PSProvider Registry -Name HKLM -Root HKEY_LOCAL_MACHINE | Out-Null
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
    New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
    $ErrorActionPreference = 'SilentlyContinue'
    $checkQuickAssist = Get-WindowsCapability -online | where-object { $_.name -like "*QuickAssist*" }
    Remove-WindowsCapability -online -name $checkQuickAssist.name -ErrorAction Stop *>$null
    Set-ExecutionPolicy RemoteSigned -Force -Scope CurrentUser
    $ErrorActionPreference = 'Continue'
}

Priority

##########
#endregion Priority
##########

##########
#region System Settings 
##########
Function SystemSettings {
    Write-Host `n"---------Adjusting System Settings" -ForegroundColor Blue -BackgroundColor Gray

    Write-Host `n"Do you want " -NoNewline
    Write-Host "System Settings?" -ForegroundColor Yellow -NoNewline
    Write-Host "(y/n): " -ForegroundColor Green -NoNewline
    $response = Read-Host

    if ($response -eq 'y' -or $response -eq 'Y') {

        #Set TR Formats
        Function TRFormats {
            Write-Host `n"Do you want to " -NoNewline
            Write-Host "change the region settings to Turkiye?" -ForegroundColor Yellow -NoNewline
            Write-Host "(y/n): " -ForegroundColor Green -NoNewline
            $response = Read-Host
        
            if ($response -eq 'y' -or $response -eq 'Y') {
                Write-Host "Setting date format of Turkiye..." -NoNewline
                try {
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
                catch {
                    Write-Host "[WARNING]: The date format could not be set to turkey. $_" -ForegroundColor Red
                }
            }
            elseif ($response -eq 'n' -or $response -eq 'N') {
                Write-Host "[Turkish region format adjustment has been canceled]" -ForegroundColor Red -BackgroundColor Black
            }
            else {
                Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
                TRFormats
            }
        }
        
        TRFormats

        Function SetHostname {
            Write-Host `n"Do you want " -NoNewline
            Write-Host "change your hostname?" -ForegroundColor Yellow -NoNewline
            Write-Host "(y/n): " -ForegroundColor Green -NoNewline
            $response = Read-Host
            if ($response -eq 'y' -or $response -eq 'Y') {
                $hostq = Write-Host "Please enter your hostname: " -NoNewline
                $hostname = Read-Host -Prompt $hostq
                Rename-Computer -NewName "$hostname" *>$null
                Write-Host "Hostname was set to " -NoNewline
                Write-Host "$hostname" -ForegroundColor Green -BackgroundColor Black
            }
            elseif ($response -eq 'n' -or $response -eq 'N') {
                Write-Host "[Hostname will not be changed]" -ForegroundColor Red -BackgroundColor Black
            }
            else {
                Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
                SetHostname
            }
        }

        SetHostname

        # DisableDefender
        Function DisableDefender {
            Write-Host "`nDo you want to disable Windows Defender?" -ForegroundColor Yellow -NoNewline
            Write-Host "(y/n): " -ForegroundColor Green -NoNewline
            $response = Read-Host
        
            if ($response -eq 'y' -or $response -eq 'Y') {
                Write-Host "Disabling Windows Defender..." -NoNewline
        
                try {
                    # Disable Defender Cloud
                    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
                        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force *>$null
                    }
        
                    # Remove existing policies
                    Remove-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Recurse -ErrorAction SilentlyContinue
        
                    # Create new policies
                    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Force *>$null
                    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -PropertyType Dword -Value "1" *>$null
                    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -PropertyType Dword -Value "1" *>$null
        
                    # Disable Real-Time Protection
                    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Force *>$null
                    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -PropertyType Dword -Value "1" *>$null
                    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -PropertyType Dword -Value "1" *>$null
                    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -PropertyType Dword -Value "1" *>$null
                    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -PropertyType Dword -Value "1" *>$null
                    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -PropertyType Dword -Value "1" *>$null
        
                    # Disable Cloud-Based Protection
                    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Force *>$null
                    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "DisableBlockAtFirstSeen" -PropertyType Dword -Value "1" *>$null
                    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -PropertyType Dword -Value "0" *>$null
                    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -PropertyType Dword -Value "0" *>$null
        
                    # Disable Enhanced Notifications
                    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting" -Force *>$null
                    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableEnhancedNotifications" -PropertyType Dword -Value "1" *>$null
        
                    # Disable Windows Defender tasks
                    schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable *>$null
                    schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable *>$null
                    schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable *>$null
                    schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable *>$null
                    schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable *>$null
        
                    # Remove Windows Defender context menu entries
                    New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
                    Remove-Item -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\EPP" -ErrorAction SilentlyContinue
                    Remove-Item -Path "HKCR:\Directory\shellex\ContextMenuHandlers\EPP" -Recurse -ErrorAction SilentlyContinue
                    Remove-Item -Path "HKCR:\Drive\shellex\ContextMenuHandlers\EPP" -Recurse -ErrorAction SilentlyContinue
        
                    # Restart Windows Explorer
                    taskkill /f /im explorer.exe *>$null
                    Start-Process "explorer.exe" -NoNewWindow
        
                    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
                }
                catch {
                    Write-Host "[WARNING]: An error occurred while disabling Windows Defender. $_" -ForegroundColor Red -BackgroundColor Black
                }
            }
            elseif ($response -eq 'n' -or $response -eq 'N') {
                Write-Host "[Windows Defender will not be disabled]" -ForegroundColor Red -BackgroundColor Black
            }
            else {
                Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
                DisableDefender
            }
        }
        
        DisableDefender
        
        Function SetKeyboardLayout {
            Write-Host `n"Do you want to " -NoNewline
            Write-Host "set the keyboard layout to UK or TR?" -ForegroundColor Yellow -NoNewline
            Write-Host "(y/n): " -ForegroundColor Green -NoNewline
            $response = Read-Host
        
            if ($response -eq 'y' -or $response -eq 'Y') {
                Write-Host "`nWhich keyboard layout do you want to set? Write 1, 2 or 3."
                Write-Host "[1]" -NoNewline -BackgroundColor Black -ForegroundColor Yellow
                Write-Host " - Turkish keyboard layout"
                Write-Host "[2]" -NoNewline -BackgroundColor Black -ForegroundColor Yellow
                Write-Host " - United Kingdom keyboard layout"
                Write-Host "[3]" -NoNewline -BackgroundColor Black -ForegroundColor Yellow
                Write-Host " - Both Turkish and United Kingdom keyboard layout"
                $choice = Read-Host -Prompt `n"Choice"
        
                switch ($choice) {
                    "1" {
                        # TR keyboard layout
                        # Remove all keyboard layouts under HKCU
                        Get-ItemProperty "HKCU:\Keyboard Layout\Preload" | ForEach-Object {
                            $_.PSObject.Properties.Name | Where-Object { $_ -ne "PSPath" -and $_ -ne "PSParentPath" -and $_ -ne "PSChildName" -and $_ -ne "PSDrive" -and $_ -ne "PSProvider" } | ForEach-Object {
                                Remove-ItemProperty -Path "HKCU:\Keyboard Layout\Preload" -Name $_ -ErrorAction SilentlyContinue
                            }
                        }
                        
                        # Remove all keyboard layouts under HKEY_USERS\.DEFAULT
                        Get-ItemProperty "HKU:\.DEFAULT\Keyboard Layout\Preload" | ForEach-Object {
                            $_.PSObject.Properties.Name | Where-Object { $_ -ne "PSPath" -and $_ -ne "PSParentPath" -and $_ -ne "PSChildName" -and $_ -ne "PSDrive" -and $_ -ne "PSProvider" } | ForEach-Object {
                                Remove-ItemProperty -Path "HKU:\.DEFAULT\Keyboard Layout\Preload" -Name $_ -ErrorAction SilentlyContinue
                            }
                        }

                        # Set keyboard layout to TR
                        Get-ChildItem "HKCU:\Keyboard Layout\Preload", "HKU:\.DEFAULT\Keyboard Layout\Preload" | Remove-ItemProperty -Name * -ErrorAction SilentlyContinue
                        Set-ItemProperty -Path "HKCU:\Keyboard Layout\Preload" -Name "1" -Value "0000041f"
                        Set-ItemProperty -Path "HKU:\.DEFAULT\Keyboard Layout\Preload" -Name "1" -Value "0000041f"
                        Set-WinLanguageBarOption -UseLegacyLanguageBar

                        #disable different input for each app 
                        Set-WinLanguageBarOption

                        # Disable Print Screen key for Snipping Tool
                        Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "PrintScreenKeyForSnippingEnabled" -Value 0 *>$null
                    }
                    "2" {
                        # UK keyboard layout
                        # Remove all keyboard layouts under HKCU
                        Get-ItemProperty "HKCU:\Keyboard Layout\Preload" | ForEach-Object {
                            $_.PSObject.Properties.Name | Where-Object { $_ -ne "PSPath" -and $_ -ne "PSParentPath" -and $_ -ne "PSChildName" -and $_ -ne "PSDrive" -and $_ -ne "PSProvider" } | ForEach-Object {
                                Remove-ItemProperty -Path "HKCU:\Keyboard Layout\Preload" -Name $_ -ErrorAction SilentlyContinue
                            }
                        }
                        
                        # Remove all keyboard layouts under HKEY_USERS\.DEFAULT
                        Get-ItemProperty "HKU:\.DEFAULT\Keyboard Layout\Preload" | ForEach-Object {
                            $_.PSObject.Properties.Name | Where-Object { $_ -ne "PSPath" -and $_ -ne "PSParentPath" -and $_ -ne "PSChildName" -and $_ -ne "PSDrive" -and $_ -ne "PSProvider" } | ForEach-Object {
                                Remove-ItemProperty -Path "HKU:\.DEFAULT\Keyboard Layout\Preload" -Name $_ -ErrorAction SilentlyContinue
                            }
                        }

                        # Set keyboard layout to UK
                        Get-ChildItem "HKCU:\Keyboard Layout\Preload", "HKU:\.DEFAULT\Keyboard Layout\Preload" | Remove-ItemProperty -Name * -ErrorAction SilentlyContinue
                        Set-ItemProperty -Path "HKCU:\Keyboard Layout\Preload" -Name "1" -Value "00000809"
                        Set-ItemProperty -Path "HKU:\.DEFAULT\Keyboard Layout\Preload" -Name "1" -Value "00000809"
                        Set-WinLanguageBarOption -UseLegacyLanguageBar

                        #disable different input for each app 
                        Set-WinLanguageBarOption

                        # Disable Print Screen key for Snipping Tool
                        Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "PrintScreenKeyForSnippingEnabled" -Value 0 *>$null
                    }
                    "3" {
                        # Both TR and UK keyboard layout
                        # Remove all keyboard layouts under HKCU
                        Get-ItemProperty "HKCU:\Keyboard Layout\Preload" | ForEach-Object {
                            $_.PSObject.Properties.Name | Where-Object { $_ -ne "PSPath" -and $_ -ne "PSParentPath" -and $_ -ne "PSChildName" -and $_ -ne "PSDrive" -and $_ -ne "PSProvider" } | ForEach-Object {
                                Remove-ItemProperty -Path "HKCU:\Keyboard Layout\Preload" -Name $_ -ErrorAction SilentlyContinue
                            }
                        }

                        # Remove all keyboard layouts under HKEY_USERS\.DEFAULT
                        Get-ItemProperty "HKU:\.DEFAULT\Keyboard Layout\Preload" | ForEach-Object {
                            $_.PSObject.Properties.Name | Where-Object { $_ -ne "PSPath" -and $_ -ne "PSParentPath" -and $_ -ne "PSChildName" -and $_ -ne "PSDrive" -and $_ -ne "PSProvider" } | ForEach-Object {
                                Remove-ItemProperty -Path "HKU:\.DEFAULT\Keyboard Layout\Preload" -Name $_ -ErrorAction SilentlyContinue
                            }
                        }
                        # Set keyboard layout to TR and UK
                        Get-ChildItem "HKCU:\Keyboard Layout\Preload", "HKU:\.DEFAULT\Keyboard Layout\Preload" | Remove-ItemProperty -Name * -ErrorAction SilentlyContinue
                        Set-ItemProperty -Path "HKCU:\Keyboard Layout\Preload" -Name "1" -Value "00000809"
                        Set-ItemProperty -Path "HKCU:\Keyboard Layout\Preload" -Name "2" -Value "0000041f"
                        Set-ItemProperty -Path "HKU:\.DEFAULT\Keyboard Layout\Preload" -Name "1" -Value "00000809"
                        Set-ItemProperty -Path "HKU:\.DEFAULT\Keyboard Layout\Preload" -Name "2" -Value "0000041f"
                        Set-WinLanguageBarOption -UseLegacyLanguageBar

                        #disable different input for each app 
                        Set-WinLanguageBarOption

                        # Disable Print Screen key for Snipping Tool
                        Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "PrintScreenKeyForSnippingEnabled" -Value 0 *>$null
                    }
                    default {
                        Write-Host "Invalid input. Please enter 1, 2 or 3."
                    }
                }
            }
            elseif ($response -eq 'n' -or $response -eq 'N') {
                Write-Host "[Keyboard layout will not be changed.]" -ForegroundColor Red -BackgroundColor Black
            }
            else {
                Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
                SetKeyboardLayout
            }
        }
        
        SetKeyboardLayout

        #Import Batch to Startup
        Function ImportStartup {
            Write-Host `n"For detailed information " -NoNewline
            Write-Host "https://github.com/caglaryalcin/after-format#description" -ForegroundColor DarkCyan
            Write-Host "Do you want to " -NoNewline
            Write-Host "add the start task to the task scheduler?" -ForegroundColor Yellow -NoNewline
            Write-Host "(y/n): " -ForegroundColor Green -NoNewline
            $response = Read-Host

            if ($response -eq 'y' -or $response -eq 'Y') {
                Write-Host "Importing Startup task in Task Scheduler..." -NoNewline
        
                $downloadUrl = "https://raw.githubusercontent.com/caglaryalcin/after-format/main/files/startup/startup.xml"
                $taskXmlPath = "$env:TEMP\startup.xml"
        
                try {
                    Invoke-WebRequest -Uri $downloadUrl -OutFile $taskXmlPath -ErrorAction Stop
                }
                catch {
                    Write-Host "[WARNING]: Failed to download XML file: $_" -ForegroundColor Red -BackgroundColor Black
                }
        
                $taskName = "startup"
                $taskXmlContent = Get-Content $taskXmlPath -Raw
        
                $taskService = New-Object -ComObject "Schedule.Service"
                $taskService.Connect()
        
                $taskFolder = $taskService.GetFolder("\")
                $taskDefinition = $taskService.NewTask(0)
                $taskDefinition.XmlText = $taskXmlContent
        
                try {
                    $taskFolder.RegisterTaskDefinition($taskName, $taskDefinition, 6, $null, $null, 3) *>$null
                }
                catch {
                    Write-Host "[WARNING]: Failed to register the task: $_" -ForegroundColor Red -BackgroundColor Black
                }
        
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            elseif ($response -eq 'n' -or $response -eq 'N') {
                Write-Host "[The start task will not be added to the task scheduler.]" -ForegroundColor Red -BackgroundColor Black
            }
            else {
                Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
                ImportStartup
            }
        }
        
        ImportStartup

        Function DisableSnap {
            Write-Host "Do you want to " -NoNewline
            Write-Host "disable the Snap windows feature?" -ForegroundColor Yellow -NoNewline
            Write-Host "(y/n): " -ForegroundColor Green -NoNewline
            $response = Read-Host

            if ($response -eq 'y' -or $response -eq 'Y') {
                Write-Host `n"Disabling Snap windows feature..." -NoNewline
                try {
                    #Disable Snap windows
                    #Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WindowArrangementActive -Value 0 *>$null

                    #Disable "When I snap a window, suggest what I can snap next to it"
                    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name SnapAssist -Value 0 *>$null

                    #Disable "Show snap layouts when I hover over a window's maximize button"
                    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name EnableSnapAssistFlyout -Value 0 *>$null

                    #Disable "Show snap layouts when I drag a window to the top of my screen"
                    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name EnableSnapBar -Value 0 *>$null

                    #Disable "Show my snapped windows when I hover taskbar apps, in Task View, and when I press Alt+Tab"
                    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name EnableTaskGroups -Value 0 *>$null

                    #Disable "When I drag a window, let me snap it without dragging all the way to the screen edge"
                    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name DITest -Value 0 *>$null

                    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                }
                catch {
                    Write-Host "[WARNING]: Snap windows feature could not be disabled. $_" -ForegroundColor Red
                }
            }
        }

        DisableSnap

        # Enable Right-Click Menu for Windows 11
        Function RightClickMenu {
            Write-Host `n"Getting the Old Classic Right-Click Context Menu for Windows 11..." -NoNewline
            try {
                reg.exe add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve *>$null
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: The old right click menu could not be set. $_" -ForegroundColor Red
            }
        }

        RightClickMenu

        # Hide Taskbar Start button alignment left for Windows 11
        Function TaskbarAlignLeft {
            Write-Host "Taskbar Aligns Left..." -NoNewline
            try {
                New-itemproperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value "0" -PropertyType Dword *>$null
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: The taskbar could not be aligned to the left. $_" -ForegroundColor Red
            }
        }

        TaskbarAlignLeft

        # Disable Gallery for Windows 11
        Function DisableGallery {
            Write-Host "Disabling gallery folder..." -NoNewline
            try {
                New-Item -Path "HKCU:\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" -ItemType Key *>$null
                New-itemproperty -Path "HKCU:\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" -Name "System.IsPinnedToNameSpaceTree" -Value "0" -PropertyType Dword *>$null
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: The gallery folder could not be disabled. $_" -ForegroundColor Red
            }
        }

        DisableGallery
        
        # Enable Show Desktop Button for Windows 11
        Function EnableShowDesktop {
            Write-Host "Enabling Show Desktop Button..." -NoNewline
            
            try {
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSd" -Value 1 -ErrorAction SilentlyContinue *>$null
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: Show Desktop could not be enabled. $_" -ForegroundColor Red
            }
        }
        
        EnableShowDesktop

        # Disable Sync your settings
        Function DisableSync {
            Write-Host "Disabling Sync your settings..." -NoNewline
            $registryPath = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"

            if (-not (Test-Path $registryPath)) {
                New-Item -Path $registryPath -Force *>$null
            }

            try {
                Set-ItemProperty -Path $registryPath -Name "DisableSettingSyncUserOverride" -Value 1
                Set-ItemProperty -Path $registryPath -Name "DisableSyncYourSettings" -Value 1
                Set-ItemProperty -Path $registryPath -Name "DisableWebBrowser" -Value 1
                Set-ItemProperty -Path $registryPath -Name "DisablePersonalization" -Value 1
                Set-ItemProperty -Path $registryPath -Name "DisableSettingSync" -Value 2
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: Windows sync could not to be disabled. $_" -ForegroundColor Red -BackgroundColor Black
            }
        }

        DisableSync

        # Disable Spotlight
        Function DisableSpotlight {
            Write-Host "Disabling Spotlight..." -NoNewline
        
            $DisableSpotlight1 = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        
            if (-not (Test-Path $DisableSpotlight1)) {
                New-Item -Path $DisableSpotlight1 -Force *>$null
            }
        
            $DisableSpotlight2 = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
        
            if (-not (Test-Path $DisableSpotlight2)) {
                New-Item -Path $DisableSpotlight2 -Force *>$null
            }
        
            try {
                Set-ItemProperty -Path $DisableSpotlight1 -Name "NoWindowsSpotlight" -Value 1
                Set-ItemProperty -Path $DisableSpotlight2 -Name "RotatingLockScreenOverlayEnabled" -Value 0
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: Spotlight could not to be disabled. $_" -ForegroundColor Red -BackgroundColor Black
            }
        }

        DisableSpotlight

        # Disable Lock Screen Notifications
        Function DisableLockScreenNotifications {
            Write-Host "Disabling toast and apps notifications on lock screen..." -NoNewline
        
            $locksreen1 = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings"
        
            if (-not (Test-Path $locksreen1)) {
                New-Item -Path $locksreen1 -Force *>$null
            }
        
            $locksreen2 = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
        
            if (-not (Test-Path $locksreen2)) {
                New-Item -Path $locksreen2 -Force *>$null
            }
        
            try {
                Set-ItemProperty -Path $locksreen1 -Name "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" -Value 0
                Set-ItemProperty -Path $locksreen2 -Name "NoToastApplicationNotificationOnLockScreen" -Value 1
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: Lock screen notification could not to be disabled. $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        DisableLockScreenNotifications

        # Disable Windows Media Player diagnostics
        Function DisableWMPDiagnostics {
            Write-Host "Disabling Windows Media Player diagnostics..." -NoNewline
        
            $WMPDiag1 = "HKCU:\Software\Microsoft\MediaPlayer\Preferences\HME"
        
            if (-not (Test-Path $WMPDiag1)) {
                New-Item -Path $WMPDiag1 -Force *>$null
            }
        
            $WMPDiag2 = "HKCU:\Software\Microsoft\MediaPlayer\Preferences"
        
            if (-not (Test-Path $WMPDiag2)) {
                New-Item -Path $WMPDiag2 -Force *>$null
            }
        
            try {
                Set-ItemProperty -Path $WMPDiag1 -Name "WMPDiagnosticsEnabled" -Value 0
                Set-ItemProperty -Path $WMPDiag2 -Name "UsageTracking" -Value 0
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: Windows media player diagnostics could not to be disabled. $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        DisableWMPDiagnostics

        # Disable Windows Search with Bing
        Function DisableBingSearchExtension {
            Write-Host "Disabling extension of Windows search with Bing..." -NoNewline
        
            # Registry path
            $bingsearch = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
        
            if (-not (Test-Path $bingsearch)) {
                New-Item -Path $bingsearch -Force *>$null
            }
        
            try {
                Set-ItemProperty -Path $bingsearch -Name "DisableSearchBoxSuggestions" -Value 1
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: Windows search extension with Bing could not be disabled. $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        DisableBingSearchExtension

        #Default Photo Viewer Old
        Function DefaultPhotoViewer {
            Write-Host "Default Old Photo Viewer..." -NoNewline
            $OldPhotoViewer = ".bmp", ".dng", ".ico", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".raw"
        
            foreach ($extension in $OldPhotoViewer) {
                try {
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" -Name $extension -Type String -Value "PhotoViewer.FileAssoc.Tiff" -ErrorAction Stop
                }
                catch {
                    Write-Host "[WARNING]: Old photo viewer could not be set. $_" -ForegroundColor Red
                }
            }
        }
        
        DefaultPhotoViewer

        # Set Dark Mode for Applications
        Function SetAppsDarkMode {
            Write-Host "Setting Dark Mode for Applications..." -NoNewline
            try {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0
            }
            catch {
                Write-Host "[WARNING]: Aplications could not be set to dark mode. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        SetAppsDarkMode

        # Set Dark Mode for System
        Function SetSystemDarkMode {
            Write-Host "Setting Dark Mode for System..." -NoNewline
            try {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 0

                # Disable transparency
                Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'EnableTransparency' -Value 0
            }
            catch {
                Write-Host "[WARNING]: System could not be set to dark mode. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        SetSystemDarkMode

        # Set Control Panel view to Large icons (Classic)
        Function SetControlPanelLargeIcons {
            Write-Host "Setting Control Panel view to large icons..." -NoNewline

            try {
                If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
                    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Force -ErrorAction Stop | Out-Null
                }
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1 -ErrorAction Stop
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 0 -ErrorAction Stop
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: Control panel icons could not be set to large. $_" -ForegroundColor Red
            }
        }
        
        SetControlPanelLargeIcons

        # Disable user interface and device recognition features
        Function DisableDeviceEnumeration {
            try {
                # Disable devicemanager updates
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowDevMgrUpdates" -Value "0" -ErrorAction Stop
        
                # Disable Windows sync notifications
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value "0" -ErrorAction Stop
        
                # Disable Multimedia Device Enumeration
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMDevicesEnumerationEnabled" -Value 0 -ErrorAction Stop
        
                # Disable device enumeration in File Explorer
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableDeviceEnumeration" -Value 1 -ErrorAction Stop
            }
            catch {
                Write-Host "[WARNING]: $_" -ForegroundColor Red
            }
        }
        
        DisableDeviceEnumeration

        # Enable NumLock after startup
        Function EnableNumlock {
            Write-Host "Enabling NumLock after startup..." -NoNewline

            try {
                If (!(Test-Path "HKU:")) {
                    New-PSDrive -Name "HKU" -PSProvider "Registry" -Root "HKEY_USERS" -ErrorAction Stop | Out-Null
                }
                
                # Enable NumLock after startup
                Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value "2147483650" -ErrorAction Stop
                
                # Numlock control and settings
                Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
                If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
                    $wsh = New-Object -ComObject WScript.Shell
                    $wsh.SendKeys('{NUMLOCK}')
                }
            }
            catch {
                Write-Host "[WARNING]: Numlock could not be set. $_" -ForegroundColor Red
            }
        }
        
        EnableNumlock        

        # Disable Windows Beep Sound
        Function DisableBeepSound {
            Write-Host "Disabling Windows Beep Sound..." -NoNewline
            try {
                Set-ItemProperty -Path "HKCU:\Control Panel\Sound" -Name "Beep" -Type String -Value no
                Set-Service beep -StartupType disabled *>$null
            }
            catch {
                Write-Host "[WARNING]: Windows beep sound could not be disable. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        DisableBeepSound

        # Disable IPv6 stack for all installed network interfaces 
        Function DisableIPv6 {
            Write-Host "Disabling IPv6 stack..." -NoNewline
            try {
                Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip6"
            }
            catch {
                Write-Host "[WARNING]: Could not to be disable IPv6. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        DisableIPv6

        # Disable VMware and VirtualBox Ethernet Adapters 
        Function DisableVMEthernets {
            Write-Host "Disabling Virtual Ethernet Adapters..." -NoNewline
            try {
                Disable-NetAdapter -Name "*VMware*" -Confirm:$false *>$null
                Disable-NetAdapter -Name "*Virtual*" -Confirm:$false *>$null
            }
            catch {
                Write-Host "[WARNING]: VMware ethernet adapters could not be disabled. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        #DisableVMEthernets

        # Cloudflare 
        Function SetCFDNS {
            Write-Host "Setting Cloud Flare DNS..." -NoNewline
            try {
                $interfaces = "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14"
                Set-DnsClientServerAddress -InterfaceIndex $interfaces -ServerAddresses ("1.1.1.1", "1.0.0.1") -ErrorAction SilentlyContinue
            }
            catch {
                Write-Host "[WARNING]: CloudFlare DNS could not be set. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black        
        }

        SetCFDNS

        # Windows Explorer configure settings
        Function Hidequickaccess {
            Write-Host "Configuring Windows Explorer settings..." -NoNewline
        
            $settings = @{
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"          = @{
                    "HudMode" = 1 #hide quick access
                };
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{
                    "LaunchTo"                     = 1; # 1 'This PC' #2 'Quick Access'
                    "HideFileExt"                  = 0; # Show known file extensions
                    "NavPaneExpandToCurrentFolder" = 0; # expand all folders
                    "NavPaneShowAllFolders"        = 0 # show all folders
                };
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"          = @{
                    "ShowFrequent"   = 0; # Hide frequently used folders in quick access
                    "EnableAutoTray" = 0 # Show All Icons
                };
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" = @{
                    "HideSCAMeetNow" = 1 # HideSCAMeetNow
                }
            }
        
            $allSuccessful = $true
        
            foreach ($path in $settings.Keys) {
                foreach ($name in $settings[$path].Keys) {
                    try {
                        Set-ItemProperty -Path $path -Name $name -Value $settings[$path][$name] -ErrorAction Stop
                    }
                    catch {
                        Write-Host "[WARNING]: Errors occurred while adjusting hidequick access settings. $_" -ForegroundColor Red
                        $allSuccessful = $false
                    }
                }
            }
        
            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[COMPLETED WITH ERRORS]" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        Hidequickaccess

        # File Explorer Expand Ribbon
        Function FileExplorerExpandRibbon {
            Write-Host "Expanding for File Explorer..." -NoNewline
        
            $allSuccessful = $true
            $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon"
        
            if (-Not (Test-Path $path)) {
                try {
                    New-Item -Path $path -ErrorAction Stop | Out-Null
                }
                catch {
                    Write-Host "[WARNING]: Unable to create ribbon registry key. $_" -ForegroundColor Red
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
                    Write-Host "[WARNING]: Unable to set ribbon registry key. $_" -ForegroundColor Red
                    $allSuccessful = $false
                }
            }
        
            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[COMPLETED WITH ERRORS]" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        FileExplorerExpandRibbon

        # Hide Recycle Bin shortcut from desktop
        Function HideRecycleBinFromDesktop {
            Write-Host "Hiding Recycle Bin Shortcut from Desktop..." -NoNewline
        
            $allSuccessful = $true
            $paths = @{
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" = "{645FF040-5081-101B-9F08-00AA002F954E}";
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"    = "{645FF040-5081-101B-9F08-00AA002F954E}";
            }
        
            foreach ($path in $paths.Keys) {
                if (-Not (Test-Path $path)) {
                    try {
                        New-Item -Path $path -Force -ErrorAction Stop | Out-Null
                    }
                    catch {
                        Write-Host "[WARNING]: Reg key to hide the recycle bin could not be generated. $_" -ForegroundColor Red
                        $allSuccessful = $false
                    }
                }
        
                try {
                    Set-ItemProperty -Path $path -Name $paths[$path] -Value 1 -Type DWord -ErrorAction Stop
                }
                catch {
                    Write-Host "[WARNING]: Reg key to hide the recycle bin could not be set. $_" -ForegroundColor Red
                    $allSuccessful = $false
                }
            }
        
            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[COMPLETED WITH ERRORS]" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        HideRecycleBinFromDesktop

        # Disable Hiberfil - fast windows startup (with ssd) 
        Function DisableHiberfil {
            Write-Host "Disabling hiberfil.sys..." -NoNewline
            try { 
                powercfg -h off
            }
            catch {
                Write-Host "[WARNING]: Hiberfil could not be disabled. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black        
        }

        DisableHiberfil

        # Disable Display and Sleep mode timeouts 
        Function DisableSleepTimeout {
            Write-Host "Disabling display and sleep mode timeouts..." -NoNewline
        
            $allSuccessful = $true
            $commands = @(
                "powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
                "powercfg /X monitor-timeout-ac 0",
                "powercfg /X monitor-timeout-dc 0",
                "powercfg /X standby-timeout-ac 0",
                "powercfg /X standby-timeout-dc 0",
                "powercfg /X standby-timeout-ac 0",
                "powercfg -change -disk-timeout-dc 0",
                "powercfg -change -disk-timeout-ac 0"
            )
        
            foreach ($command in $commands) {
                $process = Start-Process cmd.exe -ArgumentList "/c $command" -PassThru -Wait -WindowStyle Hidden
        
                if ($process.ExitCode -ne 0) {
                    Write-Host "[WARNING]: Command failed for display and sleep mode: $command with Exit Code: $($process.ExitCode)" -ForegroundColor Red
                    $allSuccessful = $false
                }
            }
        
            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[COMPLETED WITH ERRORS]" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        DisableSleepTimeout

        # Disable receiving updates for other Microsoft products via Windows Update
        Function DisableUpdateMSProducts {
            Write-Host "Disabling Updates for Other Microsoft Products..." -NoNewline
            try {
                If ((New-Object -ComObject Microsoft.Update.ServiceManager).Services | Where-Object { $_.ServiceID -eq "7971f918-a847-4430-9279-4a52d1efe18d" }) {
                    (New-Object -ComObject Microsoft.Update.ServiceManager).RemoveService("7971f918-a847-4430-9279-4a52d1efe18d") | Out-Null
                }
            }
            catch {
                Write-Host "[WARNING]: Microsoft products update settings could not be turned off. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
        }

        DisableUpdateMSProducts

        # Disable Cortana 
        Function DisableCortana {
            Write-Host "Disabling Cortana..." -NoNewline
        
            $allSuccessful = $true

            try {
                # Personalization Settings
                If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
                    New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
            
                # Input Personalization
                If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
                    New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
            
                # Show Cortana Button
                Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0
            
                # Allow Cortana Policy
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -Name "Value" -Type DWord -Value 0
            
                # Windows Search Policies
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
            
                # Input Personalization Policies
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Type DWord -Value 0
            
                # Remove Cortana Package
                $progressPreference = 'SilentlyContinue'
                Get-AppxPackage "Microsoft.549981C3F5F10" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
            }
            catch {
                Write-Host "[WARNING]: Cortana could not be disabled. $_" -ForegroundColor Red
                $allSuccessful = $false
            }

            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[WARNING]: Not all operations were successful." -ForegroundColor Red
            }

        }
        
        DisableCortana

        # Disable Web Search in Start Menu
        Function DisableWebSearch {
            Write-Host "Disabling Bing Search in Start Menu..." -NoNewline
        
            $allSuccessful = $true

            try {
                # Disable BingSearchEnabled
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
            
                # Set CortanaConsent
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
            
                # Disable WebSearch
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
            }
            catch {
                Write-Host "[WARNING]: Errors were received when setting the web search disable settings. $_" -ForegroundColor Red
                $allSuccessful = $false
            }

            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[WARNING]: Not all operations were successful." -ForegroundColor Red
            }
        }
        
        DisableWebSearch

        # Disable SmartScreen Filter 
        Function DisableSmartScreen {
            Write-Host "Disabling SmartScreen Filter..." -NoNewline
        
            $allSuccessful = $true

            try {
                # Disable SmartScreen Filter
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0
            
                # Disable SmartScreen for Microsoft Edge
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0
            }
            catch {
                Write-Host "[WARNING]: Could not to disable smart screen. $_" -ForegroundColor Red
                $allSuccessful = $false
            }

            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[WARNING]: Not all operations were successful." -ForegroundColor Red
            }
        }
        
        DisableSmartScreen

        # Disable sensor features, such as screen auto rotation 
        Function DisableSensors {
            Write-Host "Disabling Sensors..." -NoNewline
        
            $allSuccessful = $true

            try {
                # LocationAndSensors kayıt defteri anahtarını oluştur
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
                }
            
                # DisableSensors özelliğini ayarla
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -Type DWord -Value 1
            }
            catch {
                Write-Host "[WARNING]: Sensors could not be disabled. $_" -ForegroundColor Red
                $allSuccessful = $false
            }

            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[WARNING]: Not all operations were successful." -ForegroundColor Red
            }

        }
        
        DisableSensors

        # Disable Tailored Experiences 
        Function DisableTailoredExperiences {
            Write-Host "Disabling Tailored Experiences..." -NoNewline
        
            $allSuccessful = $true
        
            try {
                If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent")) {
                    New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
                }
            }
            catch {
                Write-Host "[WARNING]: Could not create 'CloudContent' registry key. $_" -ForegroundColor Red
                $allSuccessful = $false
            }
        
            try {
                Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
            }
            catch {
                Write-Host "[WARNING]: Could not set 'DisableTailoredExperiencesWithDiagnosticData' property. $_" -ForegroundColor Red
                $allSuccessful = $false
            }
        
            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[WARNING]: Not all operations were successful." -ForegroundColor Red
            }
        }
        
        DisableTailoredExperiences

        # Disable Xbox features - Not applicable to Server
        Function DisableXboxFeatures {
            Write-Host "Disabling Xbox Features..." -NoNewline
        
            # Helper Function to create key if it doesn't exist and set the value
            Function Set-RegistryValue($path, $name, $value) {
                $keyPath = Split-Path -Path $path
                $itemName = Split-Path -Path $path -Leaf
        
                # Check if the key exists, if not, create it
                if (-not (Test-Path $keyPath)) {
                    New-Item -Path $keyPath -Force | Out-Null
                }
        
                # Check if the item exists, if not, create it
                if (-not (Test-Path $path)) {
                    New-Item -Path $path -Force | Out-Null
                }
        
                # Set the value
                Set-ItemProperty -Path $path -Name $name -Value $value -Type DWord
            }
        
            $allSuccessful = $true
        
            try {
                Set-RegistryValue -path "HKCU:\Software\Microsoft\GameBar" -name "AutoGameModeEnabled" -value 0
            }
            catch {
                $allSuccessful = $false
            }
        
            try {
                Set-RegistryValue -path "HKCU:\System\GameConfigStore" -name "GameDVR_Enabled" -value 0
            }
            catch {
                $allSuccessful = $false
            }
        
            try {
                Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -name "AllowGameDVR" -value 0
            }
            catch {
                $allSuccessful = $false
            }
        
            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[DONE WITH ERRORS]" -ForegroundColor Red
            }
        }
        
        DisableXboxFeatures

        # Disable blocking of downloaded files (i.e. storing zone information - no need to do File\Properties\Unblock) 
        Function DisableDownloadBlocking {
            Write-Host "Disabling Blocking of Downloaded Files..." -NoNewline
            try {
                If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments")) {
                    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" | Out-Null
                }
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Type DWord -Value 1
            }
            catch {
                Write-Host "[WARNING]: Download blocking could not be disabled. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
        }

        DisableDownloadBlocking

        # Disable nightly wake-up for Automatic Maintenance and Windows Updates 
        Function DisableMaintenanceWakeUp {
            Write-Host "Disabling nightly wake-up for Automatic Maintenance..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "WakeUp" -Type DWord -Value 0 | Out-Null
            }
            catch {
                Write-Host "[WARNING]: Maintenance wake up feature could not be disabled. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
        }

        DisableMaintenanceWakeUp

        # Disable Storage Sense - Applicable since 1703 NOT 
        Function DisableStorageSense {
            Write-Host "Disabling Storage Sense..." -NoNewline
            try {
                Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
            }
            catch {
                Write-Host "[WARNING]: Storage Sense could not be disabled. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
        }

        DisableStorageSense

        # Disable built-in Adobe Flash in IE and Edge 
        Function DisableAdobeFlash {
            Write-Host "Disabling Built-in Adobe Flash in IE and Edge..." -NoNewline
        
            $allSuccessful = $true

            try {
                # Disable Adobe Flash in Internet Explorer
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "DisableFlashInIE" -Type DWord -Value 1
            
                # Disable Adobe Flash in Edge
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -Type DWord -Value 0
            }
            catch {
                Write-Host "[WARNING]: Adobe flash could not be disabled. $_" -ForegroundColor Red
                $allSuccessful = $false
            }

            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[WARNING]: Not all operations were successful." -ForegroundColor Red
            }

        }
        
        DisableAdobeFlash

        # Disable Edge preload after Windows startup - Applicable since Win10 1809 
        Function DisableEdgePreload {
            Write-Host "Disabling Edge Preload..." -NoNewline
        
            $allSuccessful = $true

            try {
                # Set AllowPrelaunch for Microsoft Edge
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Type DWord -Value 0
            
                # Set AllowTabPreloading for Microsoft Edge
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "AllowTabPreloading" -Type DWord -Value 0
            }
            catch {
                Write-Host "[WARNING]: Edge preload could not be disabled. $_" -ForegroundColor Red
                $allSuccessful = $false
            }

            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[WARNING]: Not all operations were successful." -ForegroundColor Red
            }

        }
        
        DisableEdgePreload

        # Disable Internet Explorer first run wizard 
        Function DisableIEFirstRun {
            Write-Host "Disabling Internet Explorer First Run Wizard..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Type DWord -Value 1
            }
            catch {
                Write-Host "[WARNING]: Edge first run wizard could not be disabled. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
        }

        DisableIEFirstRun

        # Disable Windows Media Player online access - audio file metadata download, radio presets, DRM. 
        Function DisableMediaOnlineAccess {
            Write-Host "Disabling Windows Media Player Online Access..." -NoNewline
        
            $allSuccessful = $true

            try {
                # Configure Windows Media Player
                If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer")) {
                    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Force | Out-Null
                }
            
                $DisableMediaPlayer = "PreventCDDVDMetadataRetrieval", "PreventMusicFileMetadataRetrieval", "PreventRadioPresetsRetrieval"
            
                foreach ($property in $DisableMediaPlayer) {
                    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name $property -Type DWord -Value 1
                }
            
                # Configure Windows Media DRM
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type DWord -Value 1
            }
            catch {
                Write-Host "[WARNING]: Mediaplayer online access could not be configured. $_" -ForegroundColor Red
                $allSuccessful = $false
            }

            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[WARNING]: Not all operations were successful." -ForegroundColor Red
            }

        }
        
        DisableMediaOnlineAccess

        # Disable Action Center (Notification Center) 
        Function DisableActionCenter {
            Write-Host "Disabling Action Center (Notification Center)..." -NoNewline
        
            $allSuccessful = $true
        
            try {
                If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer")) {
                    New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" | Out-Null
                }
                Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
            }
            catch {
                Write-Host "[WARNING]: Could not set 'DisableNotificationCenter' property. $_" -ForegroundColor Red
                $allSuccessful = $false
            }
        
            try {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0
            }
            catch {
                Write-Host "[WARNING]: Could not set 'ToastEnabled' property. $_" -ForegroundColor Red
                $allSuccessful = $false
            }
        
            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[WARNING]: Not all operations were successful." -ForegroundColor Red
            }
        }
        
        DisableActionCenter

        # Disable System restore 
        Function DisableRestorePoints {
            Write-Host "Disabling System Restore for System Drive..." -NoNewline
        
            $allSuccessful = $true
        
            try {
                Disable-ComputerRestore -Drive "$env:SYSTEMDRIVE" *>$null
            }
            catch {
                Write-Host "[WARNING]: Could not disable system restore. $_" -ForegroundColor Red
                $allSuccessful = $false
            }
        
            try {
                vssadmin delete shadows /all /Quiet | Out-Null
            }
            catch {
                Write-Host "[WARNING]: Could not delete all existing restore points. $_" -ForegroundColor Red
                $allSuccessful = $false
            }
        
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" -Force *>$null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" -Name "DisableConfig" -Type DWord -Value 0
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" -Name "DisableSR" -Type DWord -Value 1
            }
            catch {
                Write-Host "[WARNING]: Could not set SystemRestore properties. $_" -ForegroundColor Red
                $allSuccessful = $false
            }
        
            try {
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "DisableConfig" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "DisableSR" -Type DWord -Value 1
            }
            catch {
                Write-Host "[WARNING]: Could not set CurrentVersion\SystemRestore properties. $_" -ForegroundColor Red
                $allSuccessful = $false
            }
        
            try {
                schtasks /Change /TN "\Microsoft\Windows\SystemRestore\SR" /disable  | Out-Null *>$null
            }
            catch {
                Write-Host "[WARNING]: Could not disable the scheduled task. $_" -ForegroundColor Red
                $allSuccessful = $false
            }
        
            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[WARNING]: Not all operations were successful." -ForegroundColor Red
            }
        }
        
        DisableRestorePoints
       

        # Lower UAC level (disabling it completely would break apps) 
        Function SetUACLow {
            Write-Host "Setting Low UAC Level..." -NoNewline
            try {
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
            }
            catch {
                Write-Host "[WARNING]: Low UAC level could not be set. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
        }

        SetUACLow

        # Enable clearing of recent files on exit 
        Function EnableClearRecentFiles {
            Write-Host "Enabling Clearing of Recent Files on Exit..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
                    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -Type DWord -Value 1
            }
            catch {
                Write-Host "[WARNING]: Clearing of recent files on exit could not be configured. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }

        EnableClearRecentFiles

        # Disable recent files lists 
        Function DisableRecentFiles {
            Write-Host "Disabling Recent Files Lists..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
                    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Type DWord -Value 1
            }
            catch {
                Write-Host "[WARNING]: Recent files list could not be disabled. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }

        DisableRecentFiles

        # Disable search for app in store for unknown extensions
        Function DisableSearchAppInStore {
            Write-Host "Disabling Search for App in Store for Unknown Extensions..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1
            }
            catch {
                Write-Host "[WARNING]: Suggestions for microsoft file types could not be disabled. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }

        DisableSearchAppInStore

        # Hide 'Recently added' list from the Start Menu
        Function HideRecentlyAddedApps {
            Write-Host "Hiding 'Recently added' List from the Start Menu..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Type DWord -Value 1
            }
            catch {
                Write-Host "[WARNING]: Failed to disable hiding recently added from start menu. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }

        HideRecentlyAddedApps

        Function Disable-Services {
            param (
                [string[]]$disableservices
            )
            Write-Host "Stop and Disabling Unnecessary Services..." -NoNewline
        
            foreach ($service in $disableservices) {
                try {
                    $currentService = Get-Service -Name $service -ErrorAction SilentlyContinue
                    if ($null -ne $currentService) {
                        Stop-Service -Name $service -Force -ErrorAction Stop *>$null
                        Set-Service -Name $service -StartupType Disabled -ErrorAction Stop *>$null
                    }
                }
                catch {
                    Write-Warning "Could not stop/disable $service" -NoNewline
                }
            }
        
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }
        
        # Function usage
        $disableservices = @("XblAuthManager", "XblGameSave", "XblGameSave", "XboxNetApiSvc", "XboxGipSvc", "WalletService", "RemoteAccess", "WMPNetworkSvc", "NetTcpPortSharing", "AJRouter", "TrkWks", "dmwappushservice",
            "MapsBroker", "Fax", "CscService", "WpcMonSvc", "WPDBusEnum", "PcaSvc", "RemoteRegistry", "RetailDemo", "lmhosts", "WerSvc", "wisvc", "PhoneSvc", "EFS", "BDESVC",
            "CertPropSvc", "SCardSvr", "fhsvc", "SensorDataService", "SensorService", "icssvc", "lfsvc", "SEMgrSvc", "WpnService", "SDRSVC", "Spooler", "Bonjour Service", "SensrSvc", "WbioSrvc", "Sens")
        
        Disable-Services -disableservices $disableservices

        ##########
        #region Taskbar Settings
        ##########

        #Turn Off News and Interest
        Function DisableNews {
            Write-Host "Disabling News and Interest on Taskbar..." -NoNewline
        
            try {
                # Test and create 'Windows Feeds' path if it doesn't exist
                $feedsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"
                if (-not (Test-Path -Path $feedsPath)) {
                    New-Item -Path $feedsPath -ErrorAction Stop | Out-Null
                }
        
                # Set 'EnableFeeds' registry value to 0
                Set-ItemProperty -Path $feedsPath -Name "EnableFeeds" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
        
                # Disable news and interests in the taskbar
                $taskbarFeedsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds"
                Set-ItemProperty -Path $taskbarFeedsPath -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2 -ErrorAction Stop | Out-Null
        
                # Disable news and interests via Policies\Explorer
                $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                if (-not (Test-Path $registryPath)) {
                    New-Item -Path $registryPath -Force | Out-Null
                }
                Set-ItemProperty -Path $registryPath -Name "NoNewsAndInterests" -Value 1 -ErrorAction Stop
            }
            catch {
                Write-Host "[WARNING]: News could not be disabled. $_" -ForegroundColor Red
            }
        
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }
        
        DisableNews

        # Hide Taskbar People icon
        Function HideTaskbarPeopleIcon {
            Write-Host "Hiding People Icon from Taskbar..." -NoNewline
            try {
                If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
                    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
                }
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
            }
            catch {
                Write-Host "[WARNING]: Taskbar people icon could not be disabled. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        HideTaskbarPeopleIcon

        # Hide Taskbar Taskview icon
        Function HideTaskbarTaskviewIcon {
            Write-Host "Hiding Taskview Icon from Taskbar..." -NoNewline
            try {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
            }
            catch {
                Write-Host "[WARNING]: Taskbar task view icon could not be disabled. $_" -ForegroundColor Red
            }
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
            try {
                New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MultitaskingView\AllUpView" -Name "AllUpView" -Type DWord -Value 0  *>$null
                New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MultitaskingView\AllUpView" -Name "Remove TaskView" -Type DWord -Value 0  *>$null
            }
            catch {
                Write-Host "[WARNING]: Taskbar multi task view icon could not be disabled. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        HideTaskbarMultiTaskviewIcon

        # Show small icons in taskbar
        Function ShowSmallTaskbarIcons {
            Write-Host "Showing Small Icons in Taskbar..." -NoNewline
            try {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1
            }
            catch {
                Write-Host "[WARNING]: Unable to set icons in the taskbar to be small. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        #ShowSmallTaskbarIcons

        # Hide Taskbar Search icon / box
        Function HideTaskbarSearch {
            Write-Host "Hiding Taskbar Search Icon / Box..." -NoNewline
            try {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
            }
            catch {
                Write-Host "[WARNING]: Taskbar search icon could not be disabled. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        HideTaskbarSearch

        # Hide Taskbar Remove Chat from the Taskbar
        Function RemoveTaskbarChat {
            Write-Host "Removing Chat from Taskbar..." -NoNewline
            try {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\" -Name "TaskbarMn" -Type DWord -Value 0
            }
            catch {
                Write-Host "[WARNING]: Taskbar chat icon could not be disabled. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        RemoveTaskbarChat

        # Hide Taskbar Remove Widgets from the Taskbar
        Function RemoveTaskbarWidgets {
            Write-Host "Removing Widgets from Taskbar..." -NoNewline
            try {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\" -Name "TaskbarDa" -Type DWord -Value 0
            }
            catch {
                Write-Host "[WARNING]: Taskbar widget icon could not be disabled. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        RemoveTaskbarWidgets

        # Enable Windows Game Mode
        Function Gamemode {
            Write-Host "Enabling Windows Game Mode..." -NoNewline
            try {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "UseNexusForGameDetection" -Value 1
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 1
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Value 1
            }
            catch {
                Write-Host "[WARNING]: Game Mode could not be enabled. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        Gamemode

        Function Telnet {
            Write-Host "Enabling Telnet Client..." -NoNewline
            try {
                Enable-WindowsOptionalFeature -Online -FeatureName "TelnetClient" -NoRestart  | Out-Null
            }
            catch {
                Write-Host "[WARNING]: Telnet Client could not be enabled. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        Telnet

        # Hide Taskbar Remove Widgets from the Taskbar
        Function UnpinEverything {
            Param(
                [string]$RemoveUnpin
            )
        
            try {
                Write-Host "Unpin all taskbar pins..." -NoNewline
        
                Function UnpinStartMenuTiles {
                    $progressPreference = 'silentlyContinue'
                    If ([System.Environment]::OSVersion.Version.Build -ge 15063 -And [System.Environment]::OSVersion.Version.Build -le 16299) {
                        Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount" -Include "*.group" -Recurse | ForEach-Object {
                            $data = (Get-ItemProperty -Path "$($_.PsPath)\Current" -Name "Data").Data -Join ","
                            $data = $data.Substring(0, $data.IndexOf(",0,202,30") + 9) + ",0,202,80,0,0"
                            Set-ItemProperty -Path "$($_.PsPath)\Current" -Name "Data" -Type Binary -Value $data.Split(",")-ErrorAction SilentlyContinue
                        }
                    }
                    ElseIf ([System.Environment]::OSVersion.Version.Build -ge 17134) {
                        $key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*start.tilegrid`$windows.data.curatedtilecollection.tilecollection\Current"
                        $data = $key.Data[0..25] + ([byte[]](202, 50, 0, 226, 44, 1, 1, 0, 0))
                        Set-ItemProperty -Path $key.PSPath -Name "Data" -Type Binary -Value $data -ErrorAction SilentlyContinue
                        Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
                        #Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                    }
                }
        
                Function getExplorerVerb {
                    Param([string]$verb)
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
        
                    if ($verb -eq "PinToTaskbar") { $getstring[0]::GetString(5386) }  # String: Pin to Taskbar
                    if ($verb -eq "UnpinFromTaskbar") { $getstring[0]::GetString(5387) }  # String: Unpin from taskbar
                    if ($verb -eq "PinToStart") { $getstring[0]::GetString(51201) } # String: Pin to start
                    if ($verb -eq "UnpinFromStart") { $getstring[0]::GetString(51394) } # String: Unpin from start
                }
        
                Function Get-ExplorerApps {
                    Param([string]$RemoveUnpin)
                    $apps = (New-Object -Com Shell.Application).NameSpace("shell:::{4234d49b-0245-4df3-b780-3893943456e1}").Items()
                    $apps | Where { $_.Name -like $AppName -or $app.Path -like $AppName }
                }
        
                Function Configure-TaskbarPinningApp {
                    Param([string]$RemoveUnpin, [string]$Verb)
                    $myProcessName = Get-Process | where { $_.ID -eq $pid } | % { $_.ProcessName }
                    if (-not ($myProcessName -like "explorer")) { 
                        #Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
                    }
        
                    $apps = Get-ExplorerApps($AppName)
                    if ($apps.Count -eq 0) { Write-Host "Error: No App with exact Path or Name '$AppName' found" }
                    $ExplorerVerb = getExplorerVerb($Verb);
                    foreach ($app in $apps) {
                        $done = "False (Verb $Verb not found)"
                        $app.Verbs() | Where { $_.Name -eq $ExplorerVerb } | ForEach { $_.DoIt(); $done = $true }
                        #Write-Host $verb $app.Name "-> Result:" $done
                    }
                }
        
                UnpinStartMenuTiles
                Configure-TaskbarPinningApp -RemoveUnpin $RemoveUnpin -Verb "UnpinFromTaskbar"
                
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
            }
            catch {
                Write-Host "[WARNING]: An error occurred: $($_.Exception.Message)"
            }
        }
        
        UnpinEverything -RemoveUnpin $RemoveUnpin
        
        ##########
        #endregion Taskbar Settings
        ##########

    }
    elseif ($response -eq 'n' -or $response -eq 'N') {
        Write-Host "[System Settings Cancelled]" -ForegroundColor Red -BackgroundColor Black
    }
    else {
        Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
        SystemSettings
    }
}

SystemSettings

##########
#endregion System Settings
##########

##########
#region Privacy Settings
##########
Function PrivacySettings {
    Write-Host `n"---------Adjusting Privacy Settings" -ForegroundColor Blue -BackgroundColor Gray

    Write-Host `n"Do you want " -NoNewline
    Write-Host "Privacy Settings?" -ForegroundColor Yellow -NoNewline
    Write-Host "(y/n): " -ForegroundColor Green -NoNewline
    $response = Read-Host

    if ($response -eq 'y' -or $response -eq 'Y') {

        # Disable Telemetry 
        Function DisableTelemetry {
            Write-Host `n"Disabling Telemetry..." -NoNewline
        
            $registrySettings = @(
                @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "AllowTelemetry"; Type = "DWord"; Value = 0 },
                @{Path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "AllowTelemetry"; Type = "DWord"; Value = 0 },
                @{Path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "MaxTelemetryAllowed"; Type = "DWord"; Value = 0 },
                @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "AllowTelemetry"; Type = "DWord"; Value = 0 },
                @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"; Name = "AllowBuildPreview"; Type = "DWord"; Value = 0 },
                @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"; Name = "NoGenTicket"; Type = "DWord"; Value = 1 },
                @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"; Name = "CEIPEnable"; Type = "DWord"; Value = 0 },
                @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Name = "AITEnable"; Type = "DWord"; Value = 0 },
                @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Name = "DisableInventory"; Type = "DWord"; Value = 1 },
                @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP"; Name = "CEIPEnable"; Type = "DWord"; Value = 0 },
                @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"; Name = "PreventHandwritingDataSharing"; Type = "DWord"; Value = 1 },
                @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput"; Name = "AllowLinguisticDataCollection"; Type = "DWord"; Value = 0 },
                @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE"; Name = "DisablePrivacyExperience"; Type = "Dword"; Value = "1" },
                @{Path = "HKLM:\SOFTWARE\Microsoft\MdmCommon\SettingValues"; Name = "LocationSyncEnabled"; Type = "Dword"; Value = "0" },
                @{Path = "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy"; Name = "HasAccepted"; Type = "Dword"; Value = "0" },
                @{Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack"; Name = "ShowedToastAtLevel"; Type = "Dword"; Value = "1" },
                @{Path = "HKCU:\Software\Microsoft\Input\TIPC"; Name = "Enabled"; Type = "Dword"; Value = "0" },
                @{Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy"; Name = "TailoredExperiencesWithDiagnosticDataEnabled"; Type = "Dword"; Value = "0" },
                @{Path = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"; Name = "DisableTailoredExperiencesWithDiagnosticData"; Type = "Dword"; Value = "1" },
                @{Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; Name = "Enabled"; Type = "Dword"; Value = "0" },
                @{Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI"; Name = "DisableMFUTracking"; Type = "Dword"; Value = "1" }
            )
        
            try {
                foreach ($reg in $registrySettings) {
                    if (!(Test-Path $reg.Path)) {
                        New-Item -Path $reg.Path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $reg.Path -Name $reg.Name -Type $reg.Type -Value $reg.Value -ErrorAction Stop
                }
        
                $tasks = @(
                    "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
                    "Microsoft\Windows\Application Experience\ProgramDataUpdater",
                    "Microsoft\Windows\Autochk\Proxy",
                    "Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
                    "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
                    "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
                    "Microsoft\Office\Office ClickToRun Service Monitor",
                    "Microsoft\Office\OfficeTelemetryAgentFallBack2016",
                    "Microsoft\Office\OfficeTelemetryAgentLogOn2016"
                )
        
                foreach ($task in $tasks) {
                    Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue *>$null
                }
        
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: Could not to be disable telemetry. $_" -ForegroundColor Red -BackgroundColor Black
                Write-Host $_.Exception.Message -ForegroundColor Red
            }
        }
        
        DisableTelemetry

        # Block Telemetry Url's to host file
        Function BlockUrlsToHost {
            Write-Host "Blocking Telemetry in Host File..." -NoNewline
            $file = "C:\Windows\System32\drivers\etc\hosts"
            if ((Test-Path -Path $file) -and (Get-Item $file).IsReadOnly -eq $false) {
                try {
                    # hosts file url
                    iwr -Uri "https://raw.githubusercontent.com/caglaryalcin/block-windows-telemetry/main/host" -OutFile "$env:USERPROFILE\Desktop\host"
                    Move-Item -Path "$env:userprofile\Desktop\host" -Destination C:\windows\system32\drivers\etc\hosts -Force
                    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                }
                catch {
                    Write-Host "[WARNING]: Failed to add telemetry urls to block to host file. $_" -ForegroundColor Red -BackgroundColor Black
                }
            }
            else {
                Write-Host "[WARNING]: Hosts file not found or is read-only!" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        BlockUrlsToHost

        # Disable Feedback 
        Function DisableFeedback {
            Write-Host "Disabling Feedback..." -NoNewline
        
            try {
                If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
                    New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0 -ErrorAction Stop
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1 -ErrorAction Stop
        
                $tasks = @("Microsoft\Windows\Feedback\Siuf\DmClient", "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload")
                foreach ($task in $tasks) {
                    $result = Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
                    if ($null -eq $result) { throw "Task $task could not be disabled or not found." }
                }
        
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: Feedback could not be disabled. $_" -ForegroundColor Red -BackgroundColor Black
                Write-Host $_.Exception.Message -ForegroundColor Red
            }
        }
        
        DisableFeedback

        # Disable Activity History feed in Task View 
        Function DisableActivityHistory {
            Write-Host "Disabling Activity History..." -NoNewline
        
            try {
                $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
                if (!(Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
        
                Set-ItemProperty -Path $regPath -Name "EnableActivityFeed" -Type DWord -Value 0 -ErrorAction Stop
                Set-ItemProperty -Path $regPath -Name "PublishUserActivities" -Type DWord -Value 0 -ErrorAction Stop
                Set-ItemProperty -Path $regPath -Name "UploadUserActivities" -Type DWord -Value 0 -ErrorAction Stop
                
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: Activity history could not be disabled. $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        DisableActivityHistory

        # Disable clipboard history
        Function DisableClipboardHistory {
            Write-Host "Disabling clipboard history..." -NoNewline
        
            $Clipboardreg1 = "HKCU:\Software\Microsoft\Clipboard"
        
            if (-not (Test-Path $Clipboardreg1)) {
                New-Item -Path $Clipboardreg1 -Force *>$null
            }

            $Clipboardreg2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
        
            if (-not (Test-Path $Clipboardreg2)) {
                New-Item -Path $Clipboardreg2 -Force *>$null
            }
        
            try {
                Set-ItemProperty -Path $Clipboardreg1 -Name "EnableClipboardHistory" -Value 0
                Set-ItemProperty -Path $Clipboardreg2 -Name "AllowClipboardHistory" -Value 0 -Type DWord -Force
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: Clipboard history could not be disabled. $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        DisableClipboardHistory

        # Disable User Steps Recorder
        Function DisableUserStepsRecorder {
            Write-Host "Disabling User Steps Recorder..." -NoNewline
        
            $stepspath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
        
            if (-not (Test-Path $stepspath)) {
                New-Item -Path $stepspath -Force *>$null
            }
        
            try {
                Set-ItemProperty -Path $stepspath -Name "DisableUAR" -Value 1
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: User steps recorder could not be disabled. $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        DisableUserStepsRecorder

        # Disable Hardware Keyboard Text Suggestions
        Function DisableHardwareKeyboardTextSuggestions {
            Write-Host "Turning off text suggestions for hardware keyboard..." -NoNewline
        
            $keyboardtext = "HKCU:\Software\Microsoft\Input\Settings"
        
            if (-not (Test-Path $keyboardtext)) {
                New-Item -Path $keyboardtext -Force *>$null
            }
        
            try {
                Set-ItemProperty -Path $keyboardtext -Name "EnableHwkbTextPrediction" -Value 0
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: Hardware Keyboard Text Suggestions could not to be disabled. $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        DisableHardwareKeyboardTextSuggestions

        # Disable App Launch Tracking
        Function DisableAppLaunchTracking {
            Write-Host "Disabling App Launch Tracking..." -NoNewline
        
            $applaunchtr = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        
            if (-not (Test-Path $applaunchtr)) {
                New-Item -Path $applaunchtr -Force *>$null
            }
        
            try {
                Set-ItemProperty -Path $applaunchtr -Name "Start_TrackProgs" -Value 0
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: App Launch Tracking could not to be disabled. $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        DisableAppLaunchTracking

        # Disable setting 'Let websites provide locally relevant content by accessing my language list' 
        Function DisableWebLangList {
            Write-Host "Disabling Website Access to Language List..." -NoNewline
            try {
                Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type DWord -Value 1
            }
            catch {
                Write-Host "[WARNING]: Website access to language list could not to be disabled. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }

        DisableWebLangList

        # Stop and disable Connected User Experiences and Telemetry (previously named Diagnostics Tracking Service)
        Function DisableDiagTrack {
            Write-Host "Stopping and Disabling Connected User Experiences and Telemetry Service..." -NoNewline
        
            try {
                $diagservice = Get-Service "DiagTrack" -ErrorAction Stop
        
                if ($diagservice.Status -eq 'Running') {
                    Stop-Service "DiagTrack" -Force -ErrorAction Stop
                }
        
                Set-Service "DiagTrack" -StartupType Disabled -ErrorAction Stop
        
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: User experience and telemetry services could not to be disabled. $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        DisableDiagTrack

        # Disable Advertising ID 
        Function DisableAdvertisingID {
            Write-Host "Disabling Advertising ID..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
            }
            catch {
                Write-Host "[WARNING]: Advertising ID could not to be disabled. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }

        DisableAdvertisingID

        # Disable Wi-Fi Sense
        Function DisableWiFiSense {
            Write-Host "Disabling Wi-Fi Sense..." -NoNewline
        
            try {
                $paths = @(
                    "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting",
                    "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots",
                    "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
                )
        
                foreach ($path in $paths) {
                    if (!(Test-Path $path)) {
                        New-Item -Path $path -Force | Out-Null
                    }
                }
        
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0 -ErrorAction Stop
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0 -ErrorAction Stop
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type DWord -Value 0 -ErrorAction Stop
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Type DWord -Value 0 -ErrorAction Stop
        
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: Wifi sense could not to be disabled. $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        DisableWiFiSense

        # Disable Application suggestions and automatic installation
        Function DisableAppSuggestions {
            Write-Host "Disabling Application Suggestions..." -NoNewline
        
            try {
                $DisableAppSuggestions = @("ContentDeliveryAllowed", "OemPreInstalledAppsEnabled", "PreInstalledAppsEnabled", "PreInstalledAppsEverEnabled", "SilentInstalledAppsEnabled", "SubscribedContent-310093Enabled",
                    "SubscribedContent-314559Enabled", "SubscribedContent-338387Enabled", "SubscribedContent-338388Enabled", "SubscribedContent-338389Enabled", "SubscribedContent-338393Enabled", "SubscribedContent-353694Enabled",
                    "SubscribedContent-353696Enabled", "SubscribedContent-353698Enabled", "SystemPaneSuggestionsEnabled")
        
                foreach ($property in $DisableAppSuggestions) {
                    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name $property -Type DWord -Value 0 -ErrorAction Stop
                }
        
                If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement")) {
                    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Type DWord -Value 0 -ErrorAction Stop
        
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Type DWord -Value 0 -ErrorAction Stop
        
                If ([System.Environment]::OSVersion.Version.Build -ge 17134) {
                    $key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*windows.data.placeholdertilecollection\Current"
                    Set-ItemProperty -Path $key.PSPath -Name "Data" -Type Binary -Value $key.Data[0..15] -ErrorAction Stop
                    Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
                }
        
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: App suggestions could not to be disabled. $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        DisableAppSuggestions
        

        # Disable UWP apps background access - ie. if UWP apps can download data or update themselves when they aren't used
        Function DisableUWPBackgroundApps {
            Write-Host "Disabling UWP Apps Background Access..." -NoNewline
        
            try {
                If ([System.Environment]::OSVersion.Version.Build -ge 17763) {
                    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
                        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
                    }
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Type DWord -Value 2 -ErrorAction Stop
                }
                Else {
                    $backgroundApps = Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*", "Microsoft.Windows.ShellExperienceHost*"
        
                    foreach ($app in $backgroundApps) {
                        Set-ItemProperty -Path $app.PsPath -Name "Disabled" -Type DWord -Value 1 -ErrorAction Stop
                        Set-ItemProperty -Path $app.PsPath -Name "DisabledByUser" -Type DWord -Value 1 -ErrorAction Stop
                    }
                }
        
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: UWP apps background accecss could not to be disabled. $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        DisableUWPBackgroundApps

        # Disable access to voice activation from UWP apps
        Function DisableUWPVoiceActivation {
            Write-Host "Disabling Access to Voice Activation from UWP Apps..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoice" -Type DWord -Value 2
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock" -Type DWord -Value 2
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
            }
            catch {
                Write-Host "[WARNING]: UWP voice activation could not to be disabled. $_" -ForegroundColor Red
            }
        }

        DisableUWPVoiceActivation

        # Disable access to notifications from UWP apps
        Function DisableUWPNotifications {
            Write-Host "Disabling Access to Notifications from UWP Apps..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications" -Type DWord -Value 2
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
            }
            catch {
                Write-Host "[WARNING]: UWP notifications could not to be disabled. $_" -ForegroundColor Red
            }
        }

        DisableUWPNotifications

        # Disable access to account info from UWP apps
        Function DisableUWPAccountInfo {
            Write-Host "Disabling Access to account Info from UWP Apps..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo" -Type DWord -Value 2
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
            }
            catch {
                Write-Host "[WARNING]: UWP account info could not to be disabled. $_" -ForegroundColor Red
            }
        }

        DisableUWPAccountInfo

        # Disable access to contacts from UWP apps
        Function DisableUWPContacts {
            Write-Host "Disabling Access to Contacts from UWP Apps..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts" -Type DWord -Value 2
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
            }
            catch {
                Write-Host "[WARNING]: UWP contacts could not to be disabled. $_" -ForegroundColor Red
            }
        }

        DisableUWPContacts

        # Disable access to calendar from UWP apps
        Function DisableUWPCalendar {
            Write-Host "Disabling Access to Calendar from UWP Apps..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar" -Type DWord -Value 2
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
            }
            catch {
                Write-Host "[WARNING]: UWP calender could not to be disabled. $_" -ForegroundColor Red
            }
        }

        DisableUWPCalendar

        # Disable access to phone calls from UWP apps
        Function DisableUWPPhoneCalls {
            Write-Host "Disabling Access to Phone Calls from UWP Apps..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone" -Type DWord -Value 2
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
            }
            catch {
                Write-Host "[WARNING]: UWP phone calls could not to be disabled. $_" -ForegroundColor Red
            }
        }

        DisableUWPPhoneCalls

        # Disable access to call history from UWP apps
        Function DisableUWPCallHistory {
            Write-Host "Disabling Access to Call History from UWP Apps..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory" -Type DWord -Value 2
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
            }
            catch {
                Write-Host "[WARNING]: UWP call history could not to be disabled. $_" -ForegroundColor Red
            }
        }

        DisableUWPCallHistory

        # Disable access to email from UWP apps
        Function DisableUWPEmail {
            Write-Host "Disabling Access to Email from UWP Apps..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessEmail" -Type DWord -Value 2
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
            }
            catch {
                Write-Host "[WARNING]: UWP e-mail could not to be disabled. $_" -ForegroundColor Red
            }
        }

        DisableUWPEmail

        # Disable access to tasks from UWP apps
        Function DisableUWPTasks {
            Write-Host "Disabling Access to Tasks from UWP Apps..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTasks" -Type DWord -Value 2
            }
            catch {
                Write-Host "[WARNING]: UWP tasks could not to be disabled. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }

        DisableUWPTasks

        # Disable access to messaging (SMS, MMS) from UWP apps
        Function DisableUWPMessaging {
            Write-Host "Disabling Access to Messaging from UWP Apps..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging" -Type DWord -Value 2
            }
            catch {
                Write-Host "[WARNING]: UWP messaging could not to be disabled. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        DisableUWPMessaging

        # Disable access to radios (e.g. Bluetooth) from UWP apps
        Function DisableUWPRadios {
            Write-Host "Disabling Access to Radios from UWP Apps..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessRadios" -Type DWord -Value 2
            }
            catch {
                Write-Host "[WARNING]: UWP radios could not to be disabled. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }

        DisableUWPRadios

        # Disable access to other devices (unpaired, beacons, TVs etc.) from UWP apps
        Function DisableUWPOtherDevices {
            Write-Host "Disabling Access to Other Devices from UWP Apps..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices" -Type DWord -Value 2
            }
            catch {
                Write-Host "[WARNING]: Some of them UWP could not to be disabled. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }

        DisableUWPOtherDevices

        # Disable access to diagnostic information from UWP apps
        Function DisableUWPDiagInfo {
            Write-Host "Disabling Access to Diagnostic Information from UWP Apps..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsGetDiagnosticInfo" -Type DWord -Value 2
            }
            catch {
                Write-Host "[WARNING]: UWP diagnostic information could not to be disabled. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }

        DisableUWPDiagInfo

        # Disable access to libraries and file system from UWP apps
        Function DisableUWPFileSystem {
            Write-Host "Disabling Access to Libraries and File System from UWP Apps..." -NoNewline
        
            $paths = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat"
            )
        
            try {
                foreach ($path in $paths) {
                    Set-ItemProperty -Path $path -Name "Value" -Type String -Value "Deny" -ErrorAction Stop
                }
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: UWP file system could not to be disabled. $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        DisableUWPFileSystem

        # Disable UWP apps swap file
        # This disables creation and use of swapfile.sys and frees 256 MB of disk space. Swapfile.sys is used only by UWP apps. The tweak has no effect on the real swap in pagefile.sys.
        Function DisableUWPSwapFile {
            Write-Host "Disabling UWP Apps Swap File..." -NoNewline
        
            try {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "SwapfileControl" -Type Dword -Value 0
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
            }
            catch {
                Write-Host "[WARNING]: UWP swap file could not to be disabled. $_" -ForegroundColor Red
            }
        }
        
        DisableUWPSwapFile

        # Disable automatic Maps updates 
        Function DisableMapUpdates {
            Write-Host "Disabling Automatic Maps Updates..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SYSTEM\Maps")) {
                    New-Item -Path "HKLM:\SYSTEM\Maps" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0 -ErrorAction Stop
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
            }
            catch {
                Write-Host "[WARNING]: Automatic maps updates could not to be disabled. $_" -ForegroundColor Red
            }
        }
        
        DisableMapUpdates

        # Disable automatic restart after Windows Update installation
        # The tweak is slightly experimental, as it registers a dummy debugger for MusNotification.exe
        # which blocks the restart prompt executable from running, thus never schedulling the restart  
        Function DisableUpdateRestart {
            Write-Host "Disabling Windows Update Automatic Restart..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe")) {
                    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe" -Name "Debugger" -Type String -Value "cmd.exe"
            }
            catch {
                Write-Host "[WARNING]: Failed to set Windows Update Disable Automatic Restart. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }

        DisableUpdateRestart

        # Disable Windows Update automatic downloads 
        Function DisableUpdateAutoDownload {
            Write-Host "Disabling Windows Update Automatic Downloads..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWord -Value 1 -ErrorAction Stop
            }
            catch {
                Write-Host "[WARNING]: Failed to set Disable Windows Update Automatic Downloads. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }

        DisableUpdateAutoDownload

    }
    elseif ($response -eq 'n' -or $response -eq 'N') {
        Write-Host "[Privacy Settings Cancelled]" -ForegroundColor Red -BackgroundColor Black
    }
    else {
        Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
        PrivacySettings
    }
}

PrivacySettings

##########
#endregion Privacy Settings
##########

##########
#region Install Softwares
##########
Function GithubSoftwares {
    Write-Host `n"---------Installing Softwares" -ForegroundColor Blue -BackgroundColor Gray

    Write-Host `n"Do you want to " -NoNewline
    Write-Host "install applications that are written on github?" -ForegroundColor Yellow -NoNewline
    Write-Host "(y/n): " -ForegroundColor Green -NoNewline
    $response = Read-Host
    if ($response -eq 'y' -or $response -eq 'Y') {

        Function choco-install {
            try {
                Write-Host `n"Installing chocolatey..." -NoNewline
        
                #disable first run customize for chocolatey
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Type DWord -Value 1
        
                #install choco
                Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) *>$null
                Start-Sleep 10
        
                #install vcredist 2015
                $output = choco install microsoft-vclibs --ignore-checksums --force -y -Timeout 0
                If ($output -match "successful") {
                    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                }
                else {
                    Write-Host "[WARNING]: Installation of microsoft-vclibs-140-00 failed." -ForegroundColor Red
                }
        
                $chocoPath = Get-Command "choco" -ErrorAction SilentlyContinue
                if ($null -eq $chocoPath) {
                    Write-Host "[WARNING]: Chocolatey is not installed properly. $_" -ForegroundColor Red
                    return
                }
        
                #eliminates the -y requirement
                choco feature enable -n allowGlobalConfirmation *>$null
            }
            catch {
                Write-Host "[WARNING]: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        
        choco-install
        
        Function InstallSoftwares {
            $configUrl = "https://raw.githubusercontent.com/caglaryalcin/after-format/main/files/apps/choco-apps.config"

            $response = Invoke-WebRequest -Uri $configUrl

            [xml]$configContent = $response.Content

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
                    Start-Sleep -Seconds 2  # check every 2 seconds
                }
            }

            # Start the background job for monitoring and stopping processes
            $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $appsToClose.Values

            # Start the installation process for each package and print the status
            foreach ($package in $configContent.packages.package) {
                $packageName = $package.id
                Write-Host "Installing $packageName..." -NoNewline

                # Capture the result of the installation
                $result = choco install $packageName --force -y -Verbose -Timeout 0 2>&1 | Out-String

                # Check the installation result for errors
                if ($result -like "*The install of $packageName was successful*") {
                    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                }
                else {
                    Write-Host "[WARNING]:" -ForegroundColor Red -BackgroundColor Black
                    # If there was an error, write the output to a log file
                    $logFile = "C:\${packageName}_choco_install.log"
                    $result | Out-File -FilePath $logFile -Force
                    Write-Host "Check the log file at $logFile for details."
                }
            }

            # Once all installations are done, stop the background job
            Stop-Job -Job $job
            Remove-Job -Job $job

            Function Install-VSCodeExtensions {
                Write-Host "Installing Microsoft Visual Studio Code Extensions..." -NoNewline
                Start-Sleep 5
                $vsCodePath = "C:\Program Files\Microsoft VS Code\bin\code.cmd"
            
                $docker = "eamodio.gitlens", "davidanson.vscode-markdownlint", "ms-azuretools.vscode-docker"
                $autocomplete = "formulahendry.auto-close-tag", "formulahendry.auto-rename-tag", "formulahendry.auto-complete-tag", "streetsidesoftware.code-spell-checker"
                $design = "pkief.material-icon-theme"
                $vspowershell = "ms-vscode.powershell", "tobysmith568.run-in-powershell", "ms-vscode-remote.remote-wsl"
                $frontend = "emin.vscode-react-native-kit", "msjsdiag.vscode-react-native", "pranaygp.vscode-css-peek", "rodrigovallades.es7-react-js-snippets", "dsznajder.es7-react-js-snippets", "dbaeumer.vscode-eslint", "christian-kohler.path-intellisense", "esbenp.prettier-vscode", "ms-python.python"
                $github = "github.vscode-pull-request-github", "github.copilot"
                $vsextensions = $docker + $autocomplete + $design + $vspowershell + $frontend + $github
            
                $installed = & $vsCodePath --list-extensions
            
                foreach ($vse in $vsextensions) {
                    if ($installed -contains $vse) {
                        Write-Host $vse "already installed." -ForegroundColor Gray
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
                    Write-Host "[WARNING]:" -ForegroundColor Yellow
                    Write-Host " VSCode's $vse plugin failed to install"
                }
            }

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
        }
        
        InstallSoftwares

        Function Get-InstalledProgram {
            param (
                [Parameter(Mandatory = $true)]
                [string]$programName
            )
        
            # Search Uninstall logs first
            $installedProgram = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall, HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$programName*" } | Select-Object -First 1
        
            # If Uninstall does not find it in the registry, search in Win32_Product
            if (-not $installedProgram) {
                $installedProgram = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*$programName*" } | Select-Object -First 1
            }
        
            # If still not found, search with Get-Package
            if (-not $installedProgram) {
                $installedProgram = Get-Package | Where-Object { $_.Name -like "*$programName*" } | Select-Object -First 1
            }
        
            # If you still can't find it, check in the Chocolatey lib folder
            if (-not $installedProgram) {
                $chocoPaths = Get-ChildItem -Path "C:\ProgramData\chocolatey\lib\" -Directory | Where-Object { $_.Name -like "*$programName*" }
                if ($chocoPaths) {
                    return $chocoPaths.Name
                }
            }
        
            if ($installedProgram) {
                if ($installedProgram -is [System.Management.Automation.PSCustomObject]) {
                    return $installedProgram.DisplayName
                }
                else {
                    return $installedProgram.Name
                }
            }
            else {
                return $null
            }
        }
        
        # Reading packages from .json file
        $wingetPackagesContent = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/caglaryalcin/after-format/main/files/apps/check.json"
        $wingetPackages = $wingetPackagesContent.Content | ConvertFrom-Json

        $appsPackagesContent = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/caglaryalcin/after-format/main/files/apps/winget.json"
        $appsPackages = $appsPackagesContent.Content | ConvertFrom-Json

        Write-Host `n"--------" -ForegroundColor Yellow -BackgroundColor Black
        Write-Host @"
Detecting programs that cannot be installed with chocolatey...

"@
        foreach ($package in $wingetPackages.Sources.Packages) {
            $installedProgramName = Get-InstalledProgram -programName "$($package.PackageIdentifier)"
            if ($installedProgramName) {
                #Write-Host "Program yüklü: $installedProgramName"
            }
            else {
                Write-Host "Not Installed " -NoNewline
                Write-Host "$($package.PackageIdentifier)" -ForegroundColor Red -BackgroundColor Black -NoNewline
                Write-Host " with chocolatey."
        
                # Searching for the full name of this package in winget.json
                $matchingPackage = $appsPackages.Sources.Packages | Where-Object { $_.PackageIdentifier -like "*$($package.PackageIdentifier)*" }
        
                if ($matchingPackage) {
                    Write-Host "Installing $($matchingPackage.PackageIdentifier) with" -NoNewline
                    Write-Host " winget..." -Foregroundcolor Yellow -NoNewline
        
                    $result = & winget install $($matchingPackage.PackageIdentifier) -e --silent --accept-source-agreements --accept-package-agreements --force 2>&1 | Out-String
        
                    if ($LASTEXITCODE -ne 0) {
                        Write-Host "[WARNING]:" -ForegroundColor Red -BackgroundColor Black
                        $logFile = "C:\$($matchingPackage.PackageIdentifier)_winget_install.log"
                        $result | Out-File -FilePath $logFile -Force
                        Write-Host "Check the log file at $logFile for details."
                    }
                    else {
                        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                    }
        
                }
                else {
                    Write-Host "$($package.PackageIdentifier) was not found in winget.json." -ForegroundColor Yellow
                }
            }
        }

        Write-Host "--------" -ForegroundColor Yellow -BackgroundColor Black

        Function Safe-TaskKill {
            param($processName)
        
            taskkill /f /im $processName *>$null

            if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 128) {
                Write-Host "[WARNING]: Could not close $processName, exit code: $LASTEXITCODE" -ForegroundColor Red
            }
        }
        
        Safe-TaskKill "GithubDesktop.exe"
        Safe-TaskKill "Cloudflare WARP.exe"

        # 7-Zip on PS
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force *>$null
            Set-PSRepository -Name 'PSGallery' -SourceLocation "https://www.powershellgallery.com/api/v2" -InstallationPolicy Trusted *>$null
            Install-Module -Name 7Zip4PowerShell -Force *>$null

            if (-Not (Get-Module -ListAvailable -Name 7Zip4PowerShell)) { throw "7Zip4PowerShell module not installed" }
        }
        catch {
            Write-Host "[WARNING]: Unable to set 7zip for powershell. $_" -ForegroundColor Red
        }

        Function Remove-ChromeComponents {
            Write-Host `n"Disabling and removing Chrome Update services..." -NoNewline
            $chromeservices = "gupdate", "gupdatem"
            foreach ($service in $chromeservices) {
                $serviceObject = Get-Service -Name $service -ErrorAction SilentlyContinue
        
                if ($serviceObject) {
                    if ($serviceObject.Status -ne 'Running' -and $serviceObject.StartType -eq 'Disabled') {
                        # The service is already stopped and disabled, so there is no need to do anything.
                        continue
                    }
        
                    try {
                        Stop-Service -Name $service -Force -ErrorAction Stop
                        Set-Service -Name $service -StartupType Disabled -ErrorAction Stop
                    }
                    catch {
                        $errorMessage = $_.Exception.Message
                        Write-Host "[WARNING]: Error stopping or disabling ${service}: $errorMessage" -ForegroundColor Red
                    }
        
                    try {
                        sc.exe delete $service *>$null
                        if ($LASTEXITCODE -ne 0) { throw "sc.exe returned error code: $LASTEXITCODE" }
                    }
                    catch {
                        $errorMessage = $_.Exception.Message
                        Write-Host "[WARNING]: Error deleting ${service}: $errorMessage" -ForegroundColor Red
                    }
                }
                else {
                    # The service is not available, so there is no need to do anything.
                }
            }
        
            $chromeDirectory = "C:\Program Files\Google\Chrome\Application\"
            $chromeVersion = Get-ChildItem -Path $chromeDirectory -Directory -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -match '^1\d+' } | 
            Sort-Object { [Version]($_.Name) } | 
            Select-Object -Last 1
        
            if ($chromeVersion -eq $null) {
                Write-Host "[WARNING]: Chrome version not found." -ForegroundColor Red
            }
            else {
                $chromeInstallerPath = Join-Path -Path $chromeDirectory -ChildPath $chromeVersion.Name
                $installerDirectory = Join-Path -Path $chromeInstallerPath -ChildPath "Installer"
                if (Test-Path $installerDirectory) {
                    Set-Location -Path $installerDirectory
                    Remove-Item -Path chrmstp.exe -Recurse -ErrorAction SilentlyContinue
                    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                }
                else {
                    Write-Host "[INFO]: Chrome Installer directory not found." -ForegroundColor Yellow
                }
            }
        }
        
        #Remove-ChromeComponents

        # Malwarebytes trial reset
        Function MalwarebytesReset {
            Write-Host "Adding task for Malwarebytes trial version reset..." -NoNewline

            $taskName = "Malwarebytes-Reset"
            $taskPath = "\"
            $taskDescription = "A task that resets the Malwarebytes Premium trial by changing the MachineGuid registry value"
            $currentTime = (Get-Date).ToString("HH:mm")

            $powerShellScript = {
                New-Guid | ForEach-Object {
                    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name 'MachineGuid' -Value $_.Guid
                }
            }

            $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command $powerShellScript"

            $taskTrigger = New-ScheduledTaskTrigger -Daily -DaysInterval 13 -At $currentTime
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden
            $taskPrincipal = New-ScheduledTaskPrincipal -UserId $currentUser -RunLevel Highest

            $task = New-ScheduledTask -Action $taskAction -Principal $taskPrincipal -Trigger $taskTrigger -Settings $taskSettings -Description $taskDescription

            $result = Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -InputObject $task

            if ($result) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[WARNING]: Failed to add Malwarebytes-reset task.. $_" -ForegroundColor Red
            }
        }

        MalwarebytesReset

        #workstation key
        try {
            Write-Host "Vmware serial number is being set...." -NoNewline
            $key = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation\Dormant\License.ws.17.0.e5.202208"
            Set-ItemProperty -Path $key.PSPath -Name "Serial" -Type String -Value 4A4RR-813DK-M81A9-4U35H-06KND
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }
        catch {
            Write-Host "[WARNING]: Vmware Workstation could not to be set serial key. $_" -ForegroundColor Red
        }
        
    }

    elseif ($response -eq 'n' -or $response -eq 'N') {
        Write-Host "[Softwares written on Github will not be installed]" -ForegroundColor Red -BackgroundColor Black
    }
    else {
        Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
        GithubSoftwares
    }
}

GithubSoftwares

##########
#endregion Install Softwares
##########

##########
#region Remove Unused Apps/Softwares
##########
Function UnusedApps {
    Write-Host `n"---------Remove Unused Apps/Softwares" -ForegroundColor Blue -BackgroundColor Gray

    Write-Host `n"Do you want " -NoNewline
    Write-Host "Uninstall Unused Apps & Softwares?" -ForegroundColor Yellow -NoNewline
    Write-Host "(y/n): " -ForegroundColor Green -NoNewline
    $response = Read-Host

    if ($response -eq 'y' -or $response -eq 'Y') {

        # Remove Apps 
        Function UninstallThirdPartyBloat {
            Write-Host "Uninstalling Default Third Party Applications..." -NoNewline
        
            $Uninstall3Party = "Microsoft.WindowsAlarms", "Microsoft.AppConnector", "Microsoft.Cortana", "Microsoft.549981C3F5F10", "Microsoft.YourPhone", "Microsoft.BingFinance", "Microsoft.BingFoodAndDrink",
            "Microsoft.BingHealthAndFitness", "Microsoft.BingMaps", "Microsoft.BingNews", "Microsoft.BingSports", "Microsoft.BingTranslator", "Microsoft.BingTravel", "Microsoft.BingWeather", "Microsoft.WindowsFeedbackHub",
            "Microsoft.GetHelp", "Microsoft.3DBuilder", "Microsoft.MicrosoftOfficeHub", "*Skype*", "Microsoft.Getstarted", "Microsoft.WindowsZuneMusic", "Microsoft.ZuneMusic", "Microsoft.WindowsMaps", "*messaging*", "Microsoft.Skydrive",
            "Microsoft.MicrosoftSolitaireCollection", "Microsoft.WindowsZuneVideo", "Microsoft.ZuneVideo", "Microsoft.Office.OneNote", "Microsoft.OneConnect", "Microsoft.People*", "Microsoft.WindowsPhone", "Microsoft.Windows.Photos",
            "Microsoft.Reader", "Microsoft.Office.Sway", "Microsoft.SoundRecorder", "Microsoft.XboxApp", "*ACG*", "*CandyCrush*", "*Facebook*", "*Plex*", "*Spotify*", "*Twitter*", "*Viber*", "*3d*", "*comm*", "*mess*", "Microsoft.CommsPhone", "Microsoft.ConnectivityStore",
            "Microsoft.FreshPaint", "Microsoft.HelpAndTips", "Microsoft.Media.PlayReadyClient*", "Microsoft.Messaging", "Microsoft.MicrosoftPowerBIForWindows", "Microsoft.MinecraftUWP", "Microsoft.MixedReality.Portal", "Microsoft.MoCamera", "Microsoft.MSPaint",
            "Microsoft.NetworkSpeedTest", "Microsoft.OfficeLens", "Microsoft.Print3D", "Microsoft.Todos", "Microsoft.Wallet", "Microsoft.WebMediaExtensions", "Microsoft.Whiteboard", "microsoft.windowscommunicationsapps", "Microsoft.WindowsFeedbackHub",
            "Microsoft.WindowsMaps", "Microsoft.WindowsPhone", "Microsoft.Windows.Photos", "Microsoft.WindowsReadingList", "Microsoft.WindowsScan", "Microsoft.WindowsSoundRecorder", "Microsoft.WinJS.1.0", "Microsoft.WinJS.2.0", "*Microsoft.ScreenSketch*", "Microsoft.XboxGamingOverlay",
            "*WebExperience*", "*PowerAutomate*", "*QuickAssist*", "*Clipchamp*", "*DevHome*"
            
            $UninstallAppxPackages = "2414FC7A.Viber", "41038Axilesoft.ACGMediaPlayer", "46928bounde.EclipseManager", "4DF9E0F8.Netflix", "64885BlueEdge.OneCalendar", "7EE7776C.LinkedInforWindows", "828B5831.HiddenCityMysteryofShadows",
            "89006A2E.AutodeskSketchBook", "9E2F88E3.Twitter", "A278AB0D.DisneyMagicKingdoms", "A278AB0D.DragonManiaLegends", "A278AB0D.MarchofEmpires", "ActiproSoftwareLLC.562882FEEB491", "AD2F1837.GettingStartedwithWindows8", "AD2F1837.HPJumpStart",
            "AD2F1837.HPRegistration", "AdobeSystemsIncorporated.AdobePhotoshopExpress", "Amazon.com.Amazon", "C27EB4BA.DropboxOEM", "CAF9E577.Plex", "CyberLinkCorp.hs.PowerMediaPlayer14forHPConsumerPC",
            "D52A8D61.FarmVille2CountryEscape", "D5EA27B7.Duolingo-LearnLanguagesforFree", "DB6EA5DB.CyberLinkMediaSuiteEssentials", "DolbyLaboratories.DolbyAccess", "Drawboard.DrawboardPDF", "Facebook.Facebook",
            "Fitbit.FitbitCoach", "flaregamesGmbH.RoyalRevolt2", "GAMELOFTSA.Asphalt8Airborne", "KeeperSecurityInc.Keeper", "king.com.BubbleWitch3Saga", "king.com.CandyCrushFriends", "king.com.CandyCrushSaga", "king.com.CandyCrushSodaSaga",
            "king.com.FarmHeroesSaga", "Nordcurrent.CookingFever", "PandoraMediaInc.29680B314EFC2", "PricelinePartnerNetwork.Booking.comBigsavingsonhot", "SpotifyAB.SpotifyMusic", "ThumbmunkeysLtd.PhototasticCollage", "WinZipComputing.WinZipUniversal", "XINGAG.XING", "Microsoft.XboxIdentityProvider", "Microsoft.XboxSpeechToTextOverlay",
            "Microsoft.XboxGameOverlay", "Microsoft.Xbox.TCUI"
        
            $allPackages = $Uninstall3Party + $UninstallAppxPackages
        
            foreach ($package in $allPackages) {
                try {
                    $app = Get-AppxPackage -AllUsers | Where-Object { $_.Name -like $package }
                    if ($null -ne $app) {
                        $appName = $app.Name
                        $OriginalProgressPreference = $Global:ProgressPreference
                        $Global:ProgressPreference = 'SilentlyContinue'
                        $app | Remove-AppxPackage -ErrorAction Stop
                        Start-Sleep 2
                        Start-Process msiexec.exe -ArgumentList '/x', '{A7AB73A3-CB10-4AA5-9D38-6AEFFBDE4C91}', '/qn', '/norestart' -NoNewWindow -Wait *>$null #Microsoft Teams Outlook Add-in
                    }
                    else {
                    }
                }
                catch {
                    Write-Host "[WARNING]: Windows 3party applications could not be deleted. $_" -ForegroundColor Red
                }
            }

            # Uninstall Health Check
            try {
                $progressPreference = 'silentlyContinue'
                taskkill /f /im PCHealthCheck.exe *>$null
                Get-CimInstance -ClassName Win32_Product -Filter "Name = 'Microsoft.WindowsPCHealthCheck'" | ForEach-Object { $_.Uninstall() } *>$null
            }
            catch {
                Write-Host "[WARNING]: Health Check could not be deleted. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        UninstallThirdPartyBloat

        # Disable Copilot
        Function DisableCopilot {
            Write-Host `n"Do you want " -NoNewline
            Write-Host "disable Microsoft Copilot?" -ForegroundColor Yellow -NoNewline
            Write-Host "(y/n): " -ForegroundColor Green -NoNewline
            $response = Read-Host
        
            if ($response -eq 'y' -or $response -eq 'Y') {
                Write-Host "Disabling Microsoft Copilot..." -NoNewline
                if (-not (Test-Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot")) {
                    New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows" -Name "WindowsCopilot" -Force *>$null
                }
                
                New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1 -PropertyType DWORD -Force *>$null
                
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            elseif ($response -eq 'n' -or $response -eq 'N') {
                Write-Host "[Copilot will not be uninstalled]" -ForegroundColor Red -BackgroundColor Black
            }
            else {
                Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
                DisableCopilot
            }
        }

        DisableCopilot

        # Uninstall Windows Media Player
        Function UninstallMediaPlayer {
            Write-Host `n"Uninstalling Windows Media Player..." -NoNewline
            try {
                $OriginalProgressPreference = $Global:ProgressPreference
                $Global:ProgressPreference = 'SilentlyContinue'
                Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "WindowsMediaPlayer" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
                Get-WindowsCapability -Online | Where-Object { $_.Name -like "Media.WindowsMediaPlayer*" } | Remove-WindowsCapability -Online | Out-Null
            }
            catch {
                Write-Host "[WARNING]: Windows media player could not be deleted. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }

        UninstallMediaPlayer

        # Uninstall Work Folders Client - Not applicable to Server
        Function UninstallWorkFolders {
            Write-Host "Uninstalling Work Folders Client..." -NoNewline
            try {
                $OriginalProgressPreference = $Global:ProgressPreference
                $Global:ProgressPreference = 'SilentlyContinue'
                Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "WorkFolders-Client" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
            }
            catch {
                Write-Host "[WARNING]: Work folders could not be deleted. $_" -ForegroundColor Red
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
                Write-Host "[WARNING]: XPS printer could not be deleted. $_" -ForegroundColor Red
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
                Write-Host "[WARNING]: Fax printer could not be deleted. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }

        RemoveFaxPrinter

        # Uninstall Windows Fax and Scan Services - Not applicable to Server
        Function UninstallFaxAndScan {
            Write-Host "Uninstalling Windows Fax and Scan Services..." -NoNewline
            try {
                $OriginalProgressPreference = $Global:ProgressPreference
                $Global:ProgressPreference = 'SilentlyContinue'
                Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "FaxServicesClientPackage" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
                Get-WindowsCapability -Online | Where-Object { $_.Name -like "Print.Fax.Scan*" } | Remove-WindowsCapability -Online | Out-Null
            }
            catch {
                Write-Host "[WARNING]: Fax and scan services could not to be deleted. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }

        UninstallFaxAndScan

        # Remove 3D Folders
        Function Remove3D {
            Write-Host "Removing 3D Folders..." -NoNewline
            try {
                Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
                Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
            }
            catch {
                Write-Host "[WARNING]: 3d folders could not to be removed. $_" -ForegroundColor Red
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }
    
        Remove3D

        # Block Microsoft Edge telemetry
        Function EdgePrivacy {
            Write-Host "Microsoft Edge privacy settings are being adjusted..." -NoNewline
            # Registry path for Edge privacy settings
            $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
        
            if (-not (Test-Path $registryPath)) {
                New-Item -Path $registryPath -Force *>$null
            }
        
            try {
                Set-ItemProperty -Path $registryPath -Name "DoNotTrack" -Value 1
                Set-ItemProperty -Path $registryPath -Name "QuicAllowed" -Value 0
                Set-ItemProperty -Path $registryPath -Name "SearchSuggestEnabled" -Value 0
                Set-ItemProperty -Path $registryPath -Name "AllowSearchAssistant" -Value 0
                Set-ItemProperty -Path $registryPath -Name "FormFillEnabled" -Value 0
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING]: Failed to apply Edge privacy settings $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        EdgePrivacy

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
            Write-Host "apps and windows update tasks to be deleted?" -ForegroundColor Yellow -NoNewline
            Write-Host "(y/n): " -ForegroundColor Green -NoNewline
            
            $response = Read-Host
        
            if ($response -eq 'y' -or $response -eq 'Y') {
                Write-Host "Removing Unnecessary Tasks..." -NoNewline
                $taskPatterns = @("OneDrive*", "MicrosoftEdge*", "Google*", "Nv*", "Brave*", "Intel*", "klcp*", "MSI*", 
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
                            Write-Host "`n[WARNING]: Error: $_" -ForegroundColor Red
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

        # Uninstall OneDrive
        Function UninstallOneDrive {
            Write-Host `n"Do you want " -NoNewline
            Write-Host "uninstall Microsoft OneDrive?" -ForegroundColor Yellow -NoNewline
            Write-Host "(y/n): " -ForegroundColor Green -NoNewline
            $response = Read-Host
            if ($response -eq 'y' -or $response -eq 'Y') {
                Write-Host "Removing Microsoft OneDrive..." -NoNewline
                $OriginalProgressPreference = $Global:ProgressPreference
                $Global:ProgressPreference = 'SilentlyContinue'
                try {
                    # Stop OneDrive and Explorer processes
                    Stop-Process -Name "OneDrive", "explorer" -Force -ErrorAction SilentlyContinue
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

                    # Remove OneDrive from the registry
                    reg load "HKU\Default" "C:\Users\Default\NTUSER.DAT" *>$null
                    reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f *>$null
                    reg unload "HKU\Default" *>$null

                    Remove-Item -Path "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force -ErrorAction SilentlyContinue

                    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black

                }
                catch {
                    Write-Host "[WARNING]: Onedrive could not to be deleted. $_" -ForegroundColor Red -BackgroundColor Black
                }
                finally {
                    $Global:ProgressPreference = $OriginalProgressPreference
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
            Write-Host "(Not recommended for Windows 11)" -ForegroundColor Red -BackgroundColor Black -NoNewline
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
                    $OriginalProgressPreference = $Global:ProgressPreference
                    $Global:ProgressPreference = 'SilentlyContinue'
                    Start-Process cmd.exe "/c $uninstallString" -WindowStyle Hidden
                
                    $appxStore = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
                    $pattern = "HKLM:$appxStore\InboxApplications\Microsoft.MicrosoftEdge_*_neutral__8wekyb3d8bbwe"
                    $key = (Get-Item -Path $pattern).PSChildName
                    reg delete "HKLM$appxStore\InboxApplications\$key" /f *>$null
                
                    $SID = (New-Object System.Security.Principal.NTAccount($env:USERNAME)).Translate([Security.Principal.SecurityIdentifier]).Value
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
                
                    Get-ChildItem C:\users\Public\Desktop\*.lnk | ForEach-Object { Remove-Item $_ -ErrorAction SilentlyContinue } *>$null
                    Get-ChildItem $env:USERPROFILE\Desktop\*.lnk | ForEach-Object { Remove-Item $_ -ErrorAction SilentlyContinue } *>$null
                
                    Get-ChildItem -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                
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
                        Start-Process explorer.exe
                        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                    }
                    else {
                        throw "Microsoft Edge process is still running."
                    }
                }
                catch {
                    Write-Host "[WARNING]: Windows Edge could not to be removed. $_" -ForegroundColor Red -BackgroundColor Black
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

##########
#endregion Remove Unused Apps/Softwares
##########

Function Restart {
    Write-Host `n"Do you " -NoNewline
    Write-Host "want restart?" -NoNewline -ForegroundColor Red -BackgroundColor Black
    Write-Host "(y/n): " -NoNewline
    $response = Read-Host

    if ($response -eq 'y' -or $response -eq 'Y') {
        Remove-Item C:\Asus -recurse -ErrorAction SilentlyContinue

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

##########
#region My Settings
##########

Function MySettings {
    iwr "https://raw.githubusercontent.com/caglaryalcin/after-format/main/files/own/mysettings.psm1" -UseB | iex
}

MySettings

##########
#endregion My Settings
##########

Function Restart {
    Write-Host `n"Do you " -NoNewline
    Write-Host "want restart?" -NoNewline -ForegroundColor Red -BackgroundColor Black
    Write-Host "(y/n): " -NoNewline
    $response = Read-Host

    if ($response -eq 'y' -or $response -eq 'Y') {
        Remove-Item C:\Asus -recurse -ErrorAction SilentlyContinue

        cmd.exe /c "shutdown /r /t 0"
    }
    elseif ($response -eq 'n' -or $response -eq 'N') {
        Write-Host("Restart process cancelled") -ForegroundColor Red -BackgroundColor Black
    }
    else {
        Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
    }
 
}

Restart