##########
#region Set MAP
##########

$ErrorActionPreference = 'SilentlyContinue'
New-PSDrive -PSProvider Registry -Name HKCU -Root HKEY_CURRENT_USER | Out-Null
New-PSDrive -PSProvider Registry -Name HKLM -Root HKEY_LOCAL_MACHINE | Out-Null
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
$ErrorActionPreference = 'Continue'
    
##########
#endregion MAP
##########

##########
#region Priority
##########

Function Priority {
    $ErrorActionPreference = 'SilentlyContinue'
    $checkQuickAssist = Get-WindowsCapability -online | where-object { $_.name -like "*QuickAssist*" }
    Remove-WindowsCapability -online -name $checkQuickAssist.name -ErrorAction Stop *>$null
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
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
    Write-Host `n"---------Adjusting System Settings" -ForegroundColor Blue -BackgroundColor Black

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
                Set-TimeZone -Name "Turkey Standard Time"
                Set-Culture tr-TR
                Set-ItemProperty -Path "HKCU:\Control Panel\International" -name ShortDate -value "dd/MM/yyyy"
    
                #sync time
                Set-Service -Name "W32Time" -StartupType Automatic
                net stop W32Time *>$null
                net start W32Time *>$null
                w32tm /resync /force *>$null
                w32tm /config /manualpeerlist:time.windows.com, 0x1 /syncfromflags:manual /reliable:yes /update *>$null
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
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
                $hostq = Write-Host "Please enter your hostname: " -ForegroundColor Red -NoNewline
                $hostname = Read-Host -Prompt $hostq
                Rename-Computer -NewName "$hostname" *>$null
                Write-Host "Hostname was set to"$hostname"" -ForegroundColor Yellow -BackgroundColor Black
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
            Write-Host `n"Do you want " -NoNewline
            Write-Host "disable Windows Defender?" -ForegroundColor Yellow -NoNewline
            Write-Host "(y/n): " -ForegroundColor Green -NoNewline
            $response = Read-Host

            if ($response -eq 'y' -or $response -eq 'Y') {
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
                $SetMpPreference = @{
                    DisableRealtimeMonitoring                    = $true
                    DisableBehaviorMonitoring                    = $true
                    DisableBlockAtFirstSeen                      = $true
                    DisableIOAVProtection                        = $true
                    DisablePrivacyMode                           = $true
                    SignatureDisableUpdateOnStartupWithoutEngine = $true
                    DisableArchiveScanning                       = $true
                    DisableIntrusionPreventionSystem             = $true
                    DisableScriptScanning                        = $true
                }
    
                Set-MpPreference @SetMpPreference -ErrorAction Ignore
    
                Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction Ignore;
                Set-MpPreference -MAPSReporting 0 -ErrorAction Ignore;
                Set-MpPreference -HighThreatDefaultAction 6 -Force -ErrorAction Ignore;
                Set-MpPreference -ModerateThreatDefaultAction 6 -ErrorAction Ignore;
                Set-MpPreference -LowThreatDefaultAction 6 -ErrorAction Ignore;
                Set-MpPreference -SevereThreatDefaultAction 6 -ErrorAction Ignore;
                
                #Exclude github folders for scan
                Set-MpPreference -ExclusionExtension ".psm1", ".bat", ".cmd", ".ps1", ".vbs"
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
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

        #Default .ps1 file for Powershell
        Function Defaultps1 {
            New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
            Set-ItemProperty -Path "HKCR:\Microsoft.PowerShellScript.1\Shell\Open\Command" -Name "(Default)" -Value '"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "%1"'
        }

        Defaultps1

        #Default Photo Viewer Old
        Function DefaultPhotoViewer {
            Write-Host `n"Default Old Photo Viewer..." -NoNewline
            $OldPhotoViewer = ".bmp", ".dng", ".ico", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".raw"

            foreach ($extension in $OldPhotoViewer) {
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" -Name $extension -Type String -Value "PhotoViewer.FileAssoc.Tiff" -ErrorAction SilentlyContinue
            }

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

        # Set Dark Mode for System
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

        # Cloudflare 
        Function SetCFDNS {
            Write-Host "Setting Cloud Flare DNS..." -NoNewline
            $interfaces = "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14"
            Set-DnsClientServerAddress -InterfaceIndex $interfaces -ServerAddresses ("1.1.1.1", "1.0.0.1") -ErrorAction SilentlyContinue

            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black        
        }

        SetCFDNS

        # Windows Explorer configure settings
        Function hidequickaccess {
            Write-Host "Configuring Windows Explorer settings..." -NoNewline
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "HudMode" -Type DWord -Value 1 #hide quick access
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1 #1 'This PC' #2 'Quick Access'
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0 #Hide frequently used folders in quick access
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0 # Show known file extensions
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Value 0  -ErrorAction SilentlyContinue #Show All Icons
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Value 1  -ErrorAction SilentlyContinue #HideSCAMeetNow
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneExpandToCurrentFolder" -Type DWord -Value 0 #expand all folders
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowAllFolders" -Type DWord -Value 0 #expand all folders
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        hidequickaccess

        # File Explorer Expand Ribbon
        Function FileExplorerExpandRibbon {
            Write-Host "Expanding for File Explorer..." -NoNewline
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" -Name "MinimizedStateTabletModeOff" -Type DWord -Value 0
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" -Name "Minimized" -Type DWord -Value 0
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
        }

        FileExplorerExpandRibbon

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
            powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
            powercfg /X monitor-timeout-ac 0
            powercfg /X monitor-timeout-dc 0
            powercfg /X standby-timeout-ac 0
            powercfg /X standby-timeout-dc 0
            powercfg /X standby-timeout-ac 0
            powercfg -change -disk-timeout-dc 0
            powercfg -change -disk-timeout-ac 0
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
        }

        DisableSleepTimeout

        # Disable receiving updates for other Microsoft products via Windows Update
        Function DisableUpdateMSProducts {
            Write-Host "Disabling Updates for Other Microsoft Products..." -NoNewline
            If ((New-Object -ComObject Microsoft.Update.ServiceManager).Services | Where-Object { $_.ServiceID -eq "7971f918-a847-4430-9279-4a52d1efe18d" }) {
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

        # Disable Xbox features - Not applicable to Server
        Function DisableXboxFeatures {
            Write-Host "Disabling Xbox Features..." -NoNewline
            $progressPreference = 'silentlyContinue'
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 0 *>$null
            Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0 *>$null
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
            $DisableMediaPlayer = "PreventCDDVDMetadataRetrieval", "PreventMusicFileMetadataRetrieval", "PreventRadioPresetsRetrieval"

            foreach ($property in $DisableMediaPlayer) {
                Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name $property -Type DWord -Value 1
            }

            If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type DWord -Value 1
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
        }

        DisableMediaOnlineAccess

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
            if (Test-Path C:\Windows\logs\CBS\) {
                Get-ChildItem "C:\Windows\logs\CBS\*.log" -Recurse -Force -ErrorAction SilentlyContinue |
                remove-item -force -recurse -ErrorAction SilentlyContinue 
                Write-Host "All CBS logs have been removing." -NoNewline
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
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
            if (test-path C:\Config.Msi) {
                remove-item -Path C:\Config.Msi -force -recurse  -ErrorAction SilentlyContinue
            }
            else {
                Write-Host "C:\Config.Msi does not exist, there is nothing to cleanup." -NoNewline -ForegroundColor DarkGray
                Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
            }

            ## Removes c:\Intel
            if (test-path c:\Intel) {
                remove-item -Path c:\Intel -force -recurse  -ErrorAction SilentlyContinue
            }
            else {
                Write-Host "c:\Intel does not exist, there is nothing to cleanup." -NoNewline -ForegroundColor DarkGray
                Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
            }

            ## Removes c:\PerfLogs
            if (test-path c:\PerfLogs) {
                remove-item -Path c:\PerfLogs -force -recurse  -ErrorAction SilentlyContinue
            }
            else {
                Write-Host "c:\PerfLogs does not exist, there is nothing to cleanup." -NoNewline -ForegroundColor DarkGray
                Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
            }

            ## Removes $env:windir\memory.dmp
            if (test-path $env:windir\memory.dmp) {
                remove-item $env:windir\memory.dmp -force  -ErrorAction SilentlyContinue
            }
            else {
                Write-Host "C:\Windows\memory.dmp does not exist, there is nothing to cleanup." -NoNewline -ForegroundColor DarkGray
                Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
            }

            ## Removes Windows Error Reporting files
            if (test-path C:\ProgramData\Microsoft\Windows\WER) {
                Get-ChildItem -Path C:\ProgramData\Microsoft\Windows\WER -Recurse | Remove-Item -force -recurse  -ErrorAction SilentlyContinue
                Write-host "Deleting Windows Error Reporting files!" -NoNewline
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "C:\ProgramData\Microsoft\Windows\WER does not exist, there is nothing to cleanup." -NoNewline -ForegroundColor DarkGray
                Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
            }

            ## Removes System and User Temp Files - lots of access denied will occur.
            ## Cleans up c:\windows\temp
            if (Test-Path $env:windir\Temp\) {
                Remove-Item -Path "$env:windir\Temp\*" -Force -Recurse  -ErrorAction SilentlyContinue
            }
            else {
                Write-Host "C:\Windows\Temp does not exist, there is nothing to cleanup." -NoNewline -ForegroundColor DarkGray
                Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
            }

            ## Cleans up minidump
            if (Test-Path $env:windir\minidump\) {
                Remove-Item -Path "$env:windir\minidump\*" -Force -Recurse  -ErrorAction SilentlyContinue
            }
            else {
                Write-Host "$env:windir\minidump\ does not exist, there is nothing to cleanup." -NoNewline -ForegroundColor DarkGray
                Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
            }

            ## Cleans up prefetch
            if (Test-Path $env:windir\Prefetch\) {
                Remove-Item -Path "$env:windir\Prefetch\*" -Force -Recurse  -ErrorAction SilentlyContinue
            }
            else {
                Write-Host "$env:windir\Prefetch\ does not exist, there is nothing to cleanup." -NoNewline -ForegroundColor DarkGray
                Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
            }

            ## Cleans up each users temp folder
            if (Test-Path "$env:userprofile\AppData\Local\Temp\") {
                Remove-Item -Path "%userprofile%\AppData\Local\Temp\*" -Force -Recurse  -ErrorAction SilentlyContinue
            }
            else {
                Write-Host "$env:userprofile\AppData\Local\Temp\ does not exist, there is nothing to cleanup." -NoNewline -ForegroundColor DarkGray
                Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
            }

            ## Cleans up all users windows error reporting
            if (Test-Path "$env:userprofile\AppData\Local\Microsoft\Windows\WER\") {
                Remove-Item -Path "$env:userprofile\AppData\Local\Microsoft\Windows\WER\*" -Force -Recurse  -ErrorAction SilentlyContinue
            }
            else {
                Write-Host "C:\ProgramData\Microsoft\Windows\WER does not exist, there is nothing to cleanup." -NoNewline -ForegroundColor DarkGray
                Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
            }

            ## Cleans up users temporary internet files
            if (Test-Path "$env:userprofile\AppData\Local\Microsoft\Windows\Temporary Internet Files\") {
                Remove-Item -Path "$env:userprofile\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" -Force -Recurse  -ErrorAction SilentlyContinue
            }
            else {
                Write-Host "$env:userprofile\AppData\Local\Microsoft\Windows\Temporary Internet Files\ does not exist." -NoNewline -ForegroundColor DarkGray
                Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
            }

            ## Cleans up Internet Explorer cache
            if (Test-Path "$env:userprofile\AppData\Local\Microsoft\Windows\IECompatCache\") {
                Remove-Item -Path "$env:userprofile\AppData\Local\Microsoft\Windows\IECompatCache\*" -Force -Recurse  -ErrorAction SilentlyContinue
            }
            else {
                Write-Host "$env:userprofile\AppData\Local\Microsoft\Windows\IECompatCache\ does not exist." -NoNewline -ForegroundColor DarkGray
                Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
            }

            ## Cleans up Internet Explorer cache
            if (Test-Path "$env:userprofile\AppData\Local\Microsoft\Windows\IECompatUaCache\") {
                Remove-Item -Path "%userprofile%\AppData\Local\Microsoft\Windows\IECompatUaCache\*" -Force -Recurse  -ErrorAction SilentlyContinue
            }
            else {
                Write-Host "$env:userprofile\AppData\Local\Microsoft\Windows\IECompatUaCache\ does not exist." -NoNewline -ForegroundColor DarkGray
                Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
            }

            ## Cleans up Internet Explorer download history
            if (Test-Path "$env:userprofile\AppData\Local\Microsoft\Windows\IEDownloadHistory\") {
                Remove-Item -Path "$env:userprofile\AppData\Local\Microsoft\Windows\IEDownloadHistory\*" -Force -Recurse  -ErrorAction SilentlyContinue
            }
            else {
                Write-Host "$env:userprofile\AppData\Local\Microsoft\Windows\IEDownloadHistory\ does not exist." -NoNewline -ForegroundColor DarkGray
                Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
            }

            ## Cleans up Internet Cache
            if (Test-Path "$env:userprofile\AppData\Local\Microsoft\Windows\INetCache\") {
                Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\INetCache\*" -Force -Recurse  -ErrorAction SilentlyContinue
            }
            else {
                Write-Host "$env:userprofile\AppData\Local\Microsoft\Windows\INetCache\ does not exist." -NoNewline -ForegroundColor DarkGray
                Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
            }

            ## Cleans up Internet Cookies
            if (Test-Path "$env:userprofile\AppData\Local\Microsoft\Windows\INetCookies\") {
                Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\INetCookies\*" -Force -Recurse  -ErrorAction SilentlyContinue
            }
            else {
                Write-Host "$env:userprofile\AppData\Local\Microsoft\Windows\INetCookies\ does not exist." -NoNewline -ForegroundColor DarkGray
                Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
            }

            ## Cleans up terminal server cache
            if (Test-Path "$env:userprofile\AppData\Local\Microsoft\Terminal Server Client\Cache\") {
                Remove-Item -Path "$env:userprofile\AppData\Local\Microsoft\Terminal Server Client\Cache\*" -Force -Recurse  -ErrorAction SilentlyContinue
            }
            else {
                Write-Host "$env:userprofile\AppData\Local\Microsoft\Terminal Server Client\Cache\ does not exist." -NoNewline -ForegroundColor DarkGray
                Write-Host "[WARNING]" -ForegroundColor Yellow -BackgroundColor Black
            }

            Write-host "Removing System and User Temp Files." -NoNewline
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black

            ## Removes the hidden recycling bin.
            if (Test-path 'C:\$Recycle.Bin') {
                Remove-Item 'C:\$Recycle.Bin' -Recurse -Force  -ErrorAction SilentlyContinue
            }
            else {
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
            }
            elseif ($PSVersionTable.PSVersion.Major -ge 5) {
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

            $disableservices = "XblAuthManager", "XblGameSave", "XblGameSave", "XboxNetApiSvc", "XboxGipSvc", "WalletService", "RemoteAccess", "WMPNetworkSvc", "NetTcpPortSharing", "AJRouter", "TrkWks", "dmwappushservice",
            "MapsBroker", "Fax", "CscService", "WpcMonSvc", "WPDBusEnum", "PcaSvc", "RemoteRegistry", "RetailDemo", "seclogon", "lmhosts", "WerSvc", "wisvc", "BTAGService", "BTAGService", "bthserv", "PhoneSvc", "EFS", "BDESVC",
            "CertPropSvc", "SCardSvr", "fhsvc", "SensorDataService", "SensrSvc", "SensorService", "WbioSrvc", "icssvc", "lfsvc", "SEMgrSvc", "WpnService", "SENS", "SDRSVC", "Spooler", "Bonjour Service"

            foreach ($service in $disableservices) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
            }

            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }

        DisableServices

        #Set Wallpaper
        Function SetWallpaper {
            Write-Host "Setting Desktop Wallpaper..." -NoNewline
            $url = "https://raw.githubusercontent.com/caglaryalcin/post-wpe-w10/main/files/own/hello.png"
            $filePath = "$HOME\Documents\hello.png"
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile($url, $filePath)
            Set-Itemproperty -path "HKCU:Control Panel\Desktop" -name WallPaper -value "$env:userprofile\Documents\hello.png"  | Out-Null
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }

        SetWallpaper

        ##########
        #region Taskbar Settings
        ##########

        #Turn Off News and Interest
        Function DisableNews {
            Write-Host "Disabling News and Interes on Taskbar..." -NoNewline
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" *>$null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0 *>$null
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        DisableNews

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

        # Unpin all Start Menu tiles
        Function UnpinStartMenuTiles {
            #Write-Host "Unpinning all Start Menu tiles..."
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

            if ($verb -eq "PinToTaskbar") { $getstring[0]::GetString(5386) }  # String: Pin to Taskbar
            if ($verb -eq "UnpinFromTaskbar") { $getstring[0]::GetString(5387) }  # String: Unpin from taskbar
            if ($verb -eq "PinToStart") { $getstring[0]::GetString(51201) } # String: Pin to start
            if ($verb -eq "UnpinFromStart") { $getstring[0]::GetString(51394) } # String: Unpin from start
        }

        function Get-ExplorerApps([string]$AppName) {
            $apps = (New-Object -Com Shell.Application).NameSpace("shell:::{4234d49b-0245-4df3-b780-3893943456e1}").Items()
            $apps | Where { $_.Name -like $AppName -or $app.Path -like $AppName }     
        }

        function List-ExplorerApps() { List-ExplorerApps(""); }
        function List-ExplorerApps([string]$AppName) {
            $apps = Get-ExplorerApps("*$AppName*")
            $AppList = @{};
            foreach ($app in $apps) { $AppList.Add($app.Path, $app.Name) }
            $AppList | Format-Table -AutoSize
        }

        function Configure-TaskbarPinningApp([string]$AppName, [string]$Verb) {
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
    
        function Remove-TaskbarPinningApp([string]$AppName) { Configure-TaskbarPinningApp $AppName "UnpinFromTaskbar" }

        UnpinStartMenuTiles
        Remove-TaskbarPinningApp

        ##########
        #endregion Taskbar Settings
        ##########

        #Import Batch to Startup
        Function ImportStartup {
            Write-Host "Importing Startup task in Task Scheduler..." -NoNewline

            #import remote xml file into task scheduler
            $downloadUrl = "https://raw.githubusercontent.com/caglaryalcin/post-wpe-w10/main/files/startup/Startup.xml"
            $taskXmlPath = "$env:TEMP\startup.xml"
            Invoke-WebRequest -Uri $downloadUrl -OutFile $taskXmlPath

            $taskName = "startup"
            $taskXmlContent = Get-Content $taskXmlPath -Raw

            $taskService = New-Object -ComObject "Schedule.Service"
            $taskService.Connect()

            $taskFolder = $taskService.GetFolder("\")
            $taskDefinition = $taskService.NewTask(0)
            $taskDefinition.XmlText = $taskXmlContent

            $taskFolder.RegisterTaskDefinition($taskName, $taskDefinition, 6, $null, $null, 3) *>$null

            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }

        ImportStartup

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
    Write-Host `n"---------Setting Privacy Settings" -ForegroundColor Blue -BackgroundColor Black

    Write-Host `n"Do you want " -NoNewline
    Write-Host "Privacy Settings?" -ForegroundColor Yellow -NoNewline
    Write-Host "(y/n): " -ForegroundColor Green -NoNewline
    $response = Read-Host

    if ($response -eq 'y' -or $response -eq 'Y') {

        # Disable Telemetry 
        Function DisableTelemetry {
                

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
            Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" Out-Null -ErrorAction SilentlyContinue
            Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" Out-Null -ErrorAction SilentlyContinue
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
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MdmCommon\SettingValues" -Name "LocationSyncEnabled" -Type Dword -Value "0" *>$null
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
            $DisableAppSuggestions = "ContentDeliveryAllowed", "OemPreInstalledAppsEnabled", "PreInstalledAppsEnabled", "PreInstalledAppsEverEnabled", "SilentInstalledAppsEnabled", "SubscribedContent-310093Enabled",
            "SubscribedContent-314559Enabled", "SubscribedContent-338387Enabled", "SubscribedContent-338388Enabled", "SubscribedContent-338389Enabled", "SubscribedContent-338393Enabled", "SubscribedContent-353694Enabled",
            "SubscribedContent-353696Enabled", "SubscribedContent-353698Enabled", "SystemPaneSuggestionsEnabled"

            foreach ($property in $DisableAppSuggestions) {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name $property -Type DWord -Value 0
            }

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
            }
            Else {
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
    Write-Host `n"---------Install Softwares" -ForegroundColor Blue -BackgroundColor Black

    Write-Host `n"Do you want to " -NoNewline
    Write-Host "install applications that are written on github?" -ForegroundColor Yellow -NoNewline
    Write-Host "(y/n): " -ForegroundColor Green -NoNewline
    $response = Read-Host

    if ($response -eq 'y' -or $response -eq 'Y') {
        Function Winget {
            Write-Host `n"Installing Winget..." -NoNewline
            $progressPreference = 'silentlyContinue'
            iwr "https://raw.githubusercontent.com/caglaryalcin/post-wpe-w10/main/files/apps/winget.psm1" -UseB | iex *>$null
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        Winget

        Function InstallSoftwares {
            Start-Sleep 10
            #Softwares
            $appsUrl = 'https://raw.githubusercontent.com/caglaryalcin/post-wpe-w10/main/files/apps/apps.json'

            $jsonContent = Invoke-RestMethod -Uri $appsUrl
            $packages = $jsonContent.Sources[0].Packages

            foreach ($package in $packages) {
                $packageIdentifier = $package.PackageIdentifier
                Write-Host "Installing '$packageIdentifier'..." -NoNewline
                Start-Process -FilePath "winget" -ArgumentList "install", $packageIdentifier, "-e", "--silent", "--accept-source-agreements", "--accept-package-agreements", "--force" -WindowStyle Hidden -Wait *>$null
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            Start-Sleep 5
            $progressPreference = 'silentlyContinue'
            taskkill /f /im Powertoys.exe *>$null

            #VSCode extensions
            Write-Host "Installing Microsoft Visual Studio Code Extensions..." -NoNewline
    
            $vsCodePath = "$env:LOCALAPPDATA\Programs\Microsoft VS Code\bin\code.cmd"

            $docker = "eamodio.gitlens", "davidanson.vscode-markdownlint"
            $autocomplete = "formulahendry.auto-close-tag", "formulahendry.auto-rename-tag", "formulahendry.auto-complete-tag", "streetsidesoftware.code-spell-checker"
            $design = "pkief.material-icon-theme"
            $vspowershell = "ms-vscode.powershell", "tobysmith568.run-in-powershell"
            $frontend = "emin.vscode-react-native-kit", "msjsdiag.vscode-react-native", "pranaygp.vscode-css-peek", "rodrigovallades.es7-react-js-snippets", "dsznajder.es7-react-js-snippets", "dbaeumer.vscode-eslint", "christian-kohler.path-intellisense", "esbenp.prettier-vscode"
            $github = "github.vscode-pull-request-github", "github.copilot"
            $vsextensions = $docker + $autocomplete + $design + $vspowershell + $frontend + $github

            $installed = & $vsCodePath --list-extensions

            foreach ($vse in $vsextensions) {
                if ($installed -contains $vse) {
                    Write-Host $vse "already installed." -ForegroundColor Gray
                }
                else {
                    & $vsCodePath --install-extension $vse *>$null
                }
            }

            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black

            #other softwares
            $otherappsUrl = 'https://raw.githubusercontent.com/caglaryalcin/post-wpe-w10/main/files/apps/othapps.json'

            $jsonContent = Invoke-RestMethod -Uri $otherappsUrl
            $packages = $jsonContent.Sources[0].Packages

            foreach ($package in $packages) {
                $packageIdentifier = $package.PackageIdentifier
                Write-Host "Installing '$packageIdentifier'..." -NoNewline
                Start-Process -FilePath "winget" -ArgumentList "install", $packageIdentifier, "-e", "--silent", "--accept-source-agreements", "--accept-package-agreements", "--force" -WindowStyle Hidden -Wait *>$null
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }

            #7-Zip on PS
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force *>$null
            Set-PSRepository -Name 'PSGallery' -SourceLocation "https://www.powershellgallery.com/api/v2" -InstallationPolicy Trusted *>$null
            Install-Module -Name 7Zip4PowerShell -Force *>$null
    
            #Disable Chrome Tasks
            $chromeservices = "gupdate", "gupdatem"

            foreach ($service in $chromeservices) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
                sc.exe delete $service *>$null
            }

            Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\gupdate" -Recurse -ErrorAction SilentlyContinue
            Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\gupdatem" -Recurse -ErrorAction SilentlyContinue
            Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{8A69D345-D564-463c-AFF1-A69D9E530F96}" -Recurse -ErrorAction SilentlyContinue
            Remove-Item "C:\Program Files\Google\Chrome\Application\10*\Installer\chrmstp.exe" -recurse -ErrorAction SilentlyContinue
    
            #workstation key
            Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation\Dormant\License.ws.17.0.e5.202208" -Name "Serial" -Type String -Value 4A4RR-813DK-M81A9-4U35H-06KND

            Write-Host `n"Do you want install " -NoNewline
            Write-Host "Valorant?" -ForegroundColor Yellow -NoNewline
            Write-Host "(y/n): " -ForegroundColor Green -NoNewline
            $response = Read-Host

            if ($response -eq 'y' -or $response -eq 'Y') {

                Write-Host "Installing Valorant..." -NoNewline
                $progressPreference = 'silentlyContinue'
                Invoke-WebRequest -Uri https://valorant.secure.dyn.riotcdn.net/channels/public/x/installer/current/live.live.eu.exe -OutFile C:\valo.exe
                Write-Host "[You are expected to close the installation screen!]" -NoNewline -ForegroundColor Red
                Start-Process C:\valo.exe -NoNewWindow -Wait
                Remove-Item C:\valo.exe -recurse -ErrorAction SilentlyContinue
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            elseif ($response -eq 'n' -or $response -eq 'N') {
                Write-Host "[Valorant installation canceled]" -ForegroundColor Red -BackgroundColor Black
            }
            else {
                Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
            }
   
        }

        InstallSoftwares

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
Write-Host `n"---------Remove Unused Apps/Softwares" -ForegroundColor Blue -BackgroundColor Black

Write-Host `n"Do you want " -NoNewline
Write-Host "Uninstall Unused Apps & Softwares?" -ForegroundColor Yellow -NoNewline
Write-Host "(y/n): " -ForegroundColor Green -NoNewline
$removeapps = Read-Host

if ($removeapps -eq 'y' -or $response -eq 'Y') {

    # Remove Apps 
    Function UninstallThirdPartyBloat {
        Write-Host `n"Uninstalling Default Third Party Applications..." -NoNewline
    
        $Uninstall3Party = "Microsoft.WindowsAlarms", "Microsoft.AppConnector", "Microsoft.Cortana", "Microsoft.549981C3F5F10", "Microsoft.YourPhone", "Microsoft.BingFinance", "Microsoft.BingFoodAndDrink",
        "Microsoft.BingHealthAndFitness", "Microsoft.BingMaps", "Microsoft.BingNews", "Microsoft.BingSports", "Microsoft.BingTranslator", "Microsoft.BingTravel", "Microsoft.BingWeather", "Microsoft.WindowsFeedbackHub",
        "Microsoft.GetHelp", "Microsoft.3DBuilder", "Microsoft.MicrosoftOfficeHub", "*Skype*", "Microsoft.Getstarted", "Microsoft.WindowsZuneMusic", "Microsoft.ZuneMusic", "Microsoft.WindowsMaps", "*messaging*", "Microsoft.Skydrive",
        "Microsoft.MicrosoftSolitaireCollection", "Microsoft.WindowsZuneVideo", "Microsoft.ZuneVideo", "Microsoft.Office.OneNote", "Microsoft.OneConnect", "Microsoft.People", "Microsoft.WindowsPhone", "Microsoft.Windows.Photos",
        "Microsoft.Reader", "Microsoft.Office.Sway", "Microsoft.SoundRecorder", "Microsoft.XboxApp", "*ACG*", "*CandyCrush*", "*Facebook*", "*Plex*", "*Spotify*", "*Twitter*", "*Viber*", "*3d*", "*comm*", "*mess*", "Microsoft.CommsPhone", "Microsoft.ConnectivityStore",
        "Microsoft.FreshPaint", "Microsoft.HelpAndTips", "Microsoft.Media.PlayReadyClient*", "Microsoft.Messaging", "Microsoft.MicrosoftPowerBIForWindows", "Microsoft.MinecraftUWP", "Microsoft.MixedReality.Portal", "Microsoft.MoCamera", "Microsoft.MSPaint",
        "Microsoft.NetworkSpeedTest", "Microsoft.OfficeLens", "Microsoft.Print3D", "Microsoft.Todos", "Microsoft.Wallet", "Microsoft.WebMediaExtensions", "Microsoft.Whiteboard", "microsoft.windowscommunicationsapps", "Microsoft.WindowsFeedbackHub",
        "Microsoft.WindowsMaps", "Microsoft.WindowsPhone", "Microsoft.Windows.Photos", "Microsoft.WindowsReadingList", "Microsoft.WindowsScan", "Microsoft.WindowsSoundRecorder", "Microsoft.WinJS.1.0", "Microsoft.WinJS.2.0", "*Microsoft.ScreenSketch*", "Microsoft.XboxGamingOverlay"
    
        $UninstallAppxPackages = "2414FC7A.Viber", "41038Axilesoft.ACGMediaPlayer", "46928bounde.EclipseManager", "4DF9E0F8.Netflix", "64885BlueEdge.OneCalendar", "7EE7776C.LinkedInforWindows", "828B5831.HiddenCityMysteryofShadows",
        "89006A2E.AutodeskSketchBook", "9E2F88E3.Twitter", "A278AB0D.DisneyMagicKingdoms", "A278AB0D.DragonManiaLegends", "A278AB0D.MarchofEmpires", "ActiproSoftwareLLC.562882FEEB491", "AD2F1837.GettingStartedwithWindows8", "AD2F1837.HPJumpStart",
        "AD2F1837.HPRegistration", "AdobeSystemsIncorporated.AdobePhotoshopExpress", "Amazon.com.Amazon", "C27EB4BA.DropboxOEM", "CAF9E577.Plex", "CyberLinkCorp.hs.PowerMediaPlayer14forHPConsumerPC",
        "D52A8D61.FarmVille2CountryEscape", "D5EA27B7.Duolingo-LearnLanguagesforFree", "DB6EA5DB.CyberLinkMediaSuiteEssentials", "DolbyLaboratories.DolbyAccess", "Drawboard.DrawboardPDF", "Facebook.Facebook",
        "Fitbit.FitbitCoach", "flaregamesGmbH.RoyalRevolt2", "GAMELOFTSA.Asphalt8Airborne", "KeeperSecurityInc.Keeper", "king.com.BubbleWitch3Saga", "king.com.CandyCrushFriends", "king.com.CandyCrushSaga", "king.com.CandyCrushSodaSaga",
        "king.com.FarmHeroesSaga", "Nordcurrent.CookingFever", "PandoraMediaInc.29680B314EFC2", "PricelinePartnerNetwork.Booking.comBigsavingsonhot", "SpotifyAB.SpotifyMusic", "ThumbmunkeysLtd.PhototasticCollage", "WinZipComputing.WinZipUniversal", "XINGAG.XING", "Microsoft.XboxIdentityProvider", "Microsoft.XboxSpeechToTextOverlay",
        "Microsoft.XboxGameOverlay", "Microsoft.Xbox.TCUI"

        $Uninstall3Party | ForEach-Object {
            Get-AppxPackage -AllUsers $_ | Remove-AppxPackage -ErrorAction SilentlyContinue
        }

        $UninstallAppxPackages | ForEach-Object {
            Get-AppxPackage $_ | Remove-AppxPackage -ErrorAction SilentlyContinue
        }


        # Uninstall Health Check
        $progressPreference = 'silentlyContinue'
        taskkill /f /im PCHealthCheck.exe *>$null
        cmd.exe /c "winget uninstall Microsoft.WindowsPCHealthCheck --force" *>$null
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

    # Remove 3D Folders
    Function Remove3D {
        Write-Host "Removing 3D Folders..." -NoNewline
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
        Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
    }
    
    Remove3D

    # Remove Tasks in Task Scheduler
    Function RemoveTasks {
        Write-Host "Removing Unnecessary Tasks..." -NoNewline

        $RemoveTasks = "OneDrive*", "MicrosoftEdge*", "Google*", "Nv*", "Brave*", "Intel*", "update-s*", "klcp*", "MSI*", "*Adobe*", "CCleaner*", "G2M*", "Opera*", "Overwolf*", "User*", "CreateExplorer*", "{*",
        "*Samsung*", "*npcap*", "*Consolidator*", "*Dropbox*", "*Heimdal*", "*klcp*", "*UsbCeip*", "*DmClient*", "*Office Auto*", "*Office Feature*", "*OfficeTelemetry*", "*GPU*", "Xbl*"
  
        Get-ScheduledTask  $RemoveTasks | Unregister-ScheduledTask -Confirm:$false    

        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
    }

    RemoveTasks

    # Uninstall OneDrive
    Function UninstallOneDrive {
        Write-Host `n"Do you want " -NoNewline
        Write-Host "uninstall Windows OneDrive?" -ForegroundColor Yellow -NoNewline
        Write-Host "(y/n): " -ForegroundColor Green -NoNewline
        $input = Read-Host
        if ($input -eq 'y' -or $response -eq 'Y') {
            Write-Host "Removing Microsoft OneDrive..." -NoNewline
            $progressPreference = 'silentlyContinue'
            taskkill /f /im onedrive.exe *>$null
            cmd /c "%SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall" *>$null
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        elseif ($response -eq 'n' -or $response -eq 'N') {
            Write-Host "[Windows OneDrive will not be deleted]" -ForegroundColor Red -BackgroundColor Black
        }
        else {
            Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
        }
    }

    UninstallOneDrive

    # Disable Edge desktop shortcut creation after certain Windows updates are applied 
    Function UninstallEdge {
        Write-Host `n"Do you want " -NoNewline
        Write-Host "uninstall Windows Edge?" -ForegroundColor Yellow -NoNewline
        Write-Host "(y/n): " -ForegroundColor Green -NoNewline
        $input = Read-Host
        if ($input -eq 'y' -or $response -eq 'Y') {
            Write-Host "Removing Microsoft Edge..." -NoNewline
            taskkill /f /im msedge.exe *>$null
    
            #Edge Services
            $edgeservices = "edgeupdate", "edgeupdatem"
            foreach ($service in $edgeservices) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
                sc.exe delete $service *>$null
            }

            # Uninstall - Edge
            $regView = [Microsoft.Win32.RegistryView]::Registry32
            $microsoft = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $regView).
            OpenSubKey('SOFTWARE\Microsoft', $true)

            $edgeClient = $microsoft.OpenSubKey('EdgeUpdate\ClientState\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}', $true)
            if ($null -ne $edgeClient.GetValue('experiment_control_labels')) {
                $edgeClient.DeleteValue('experiment_control_labels')
            }

            $microsoft.CreateSubKey('EdgeUpdateDev').SetValue('AllowUninstall', '')

            $uninstallRegKey = $microsoft.OpenSubKey('Windows\CurrentVersion\Uninstall\Microsoft Edge')
            $uninstallString = $uninstallRegKey.GetValue('UninstallString') + ' --force-uninstall'
            Start-Process cmd.exe "/c $uninstallString" -WindowStyle Hidden

            $appxStore = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
            $pattern = "HKLM:$appxStore\InboxApplications\Microsoft.MicrosoftEdge_*_neutral__8wekyb3d8bbwe"
            $key = (Get-Item -Path $pattern).PSChildName
            reg delete "HKLM$appxStore\InboxApplications\$key" /f *>$null

            $SID = (New-Object System.Security.Principal.NTAccount($env:USERNAME)).Translate([Security.Principal.SecurityIdentifier]).Value

            New-Item -Path "HKLM:$appxStore\EndOfLife\$SID\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" -Force *>$null
            Get-AppxPackage -Name Microsoft.MicrosoftEdge | Remove-AppxPackage *>$null
            Remove-Item -Path "HKLM:$appxStore\EndOfLife\$SID\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" *>$null

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

            #do not update edge
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\EdgeUpdate" -Name "DoNotUpdateToEdgeWithChromium" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
            taskkill /f /im "MicrosoftEdgeUpdate.exe" *>$null
            Get-ChildItem -Path "C:\Program Files (x86)\Microsoft" -Filter "Edge*" -Directory | Remove-Item -Force -Recurse *>$null

            #delete shortcuts
            Get-ChildItem C:\users\Public\Desktop\*.lnk | ForEach-Object { Remove-Item $_ } *>$null
            Get-ChildItem $env:USERPROFILE\Desktop\*.lnk | ForEach-Object { Remove-Item $_ } *>$null

            #delete startup apps
            Get-ChildItem -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -Force | Remove-Item -Recurse -Force

            $progressPreference = 'SilentlyContinue'
            Get-AppxPackage -AllUsers Microsoft.Edge | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue *>$null
            Remove-Item "C:\Program Files (x86)\Microsoft\*edge*" -recurse -ErrorAction SilentlyContinue
            Remove-Item "C:\Program Files (x86)\Microsoft\Edge" -Force -Recurse -ErrorAction SilentlyContinue
            Remove-Item "C:\Program Files (x86)\Microsoft\Temp" -Force -Recurse -ErrorAction SilentlyContinue
            Remove-Item "C:\Program Files (x86)\Microsoft\*" -Force -Recurse -ErrorAction SilentlyContinue

            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black

        }

        elseif ($response -eq 'n' -or $response -eq 'N') {
            Write-Host "[Windows Edge will not be deleted]" -ForegroundColor Red -BackgroundColor Black
        }
        else {
            Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
        }
    }

    UninstallEdge

}
elseif ($response -eq 'n' -or $response -eq 'N') {
    Write-Host "[Unnecessary apps will not be uninstalled]" -ForegroundColor Red -BackgroundColor Black
}
else {
    Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
}

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
        Write-Host("Cancel restart process") -ForegroundColor Red
    }
    else {
        Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
    }
 
}

Restart
