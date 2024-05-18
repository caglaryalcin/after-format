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

Function Silent {
    $Global:ProgressPreference = 'SilentlyContinue'
}

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

                    #set time sync to Cloudflare
                    w32tm /config /manualpeerlist:"time.cloudflare.com" /syncfromflags:manual /reliable:yes /update *>$null
                    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                }
                catch {
                    Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[Hostname was set to " -NoNewline -BackgroundColor Black
                Write-Host "$hostname" -ForegroundColor Green -BackgroundColor Black -NoNewline
                Write-Host "]" -BackgroundColor Black
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
                    Start-Sleep 4
        
                    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
                }
                catch {
                    Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
        
        # Keyboard Layout
        Function SetKeyboardLayout {
            Write-Host "`nDo you want to " -NoNewline
            Write-Host "set the keyboard layout to UK or TR?" -ForegroundColor Yellow -NoNewline
            Write-Host "(y/n): " -ForegroundColor Green -NoNewline
            $response = Read-Host
        
            if ($response -eq 'y' -or $response -eq 'Y') {
                do {
                    Write-Host "Which keyboard layout do you want to set? Write 1, 2 or 3."
                    Write-Host "[1]" -NoNewline -BackgroundColor Black -ForegroundColor Yellow
                    Write-Host " - Turkish keyboard layout"
                    Write-Host "[2]" -NoNewline -BackgroundColor Black -ForegroundColor Yellow
                    Write-Host " - United Kingdom keyboard layout"
                    Write-Host "[3]" -NoNewline -BackgroundColor Black -ForegroundColor Yellow
                    Write-Host " - Both Turkish and United Kingdom keyboard layout"
                    $choice = Read-Host -Prompt "`n[Choice]"
        
                    $validChoice = $true
        
                    switch ($choice) {
                        "1" {
                            # TR keyboard layout
                            New-PSDrive -PSProvider Registry -Name HKCU -Root HKEY_CURRENT_USER | Out-Null
                            New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
        
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
                            New-PSDrive -PSProvider Registry -Name HKCU -Root HKEY_CURRENT_USER | Out-Null
                            New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
        
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
                            New-PSDrive -PSProvider Registry -Name HKCU -Root HKEY_CURRENT_USER | Out-Null
                            New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
        
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
                            $validChoice = $false
                        }
                    }
                } while (-not $validChoice)
            }
            elseif ($response -eq 'n' -or $response -eq 'N') {
                Write-Host "[Keyboard layout will not be changed.]" -ForegroundColor Red -BackgroundColor Black
            }
            else {
                Write-Host "[Invalid input. Please enter 'y' for yes or 'n' for no.]" -ForegroundColor Red -BackgroundColor Black
                SetKeyboardLayout
            }
        }
        
        SetKeyboardLayout

        #Import Batch to Startup
        Function ImportStartup {
            Write-Host `n"For detailed information > " -NoNewline
            Write-Host "https://github.com/caglaryalcin/after-format#description" -ForegroundColor DarkCyan
            Write-Host "Do you want to " -NoNewline
            Write-Host "add the start task to the task scheduler?" -ForegroundColor Yellow -NoNewline
            Write-Host "(y/n): " -ForegroundColor Green -NoNewline
            $response = Read-Host

            if ($response -eq 'y' -or $response -eq 'Y') {
                Write-Host "Importing Startup task in Task Scheduler..." -NoNewline
        
                #upgrade
                $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -Command `"`winget upgrade --all`""
                $trigger = New-ScheduledTaskTrigger -AtStartup
                $settings = New-ScheduledTaskSettingsSet -Hidden:$true
                $description = "You can check all the operations of this project at this link.  https://github.com/caglaryalcin/after-format"
                $principal = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-544" -RunLevel Highest
                $taskname = "upgrade-packages"
                $delay = "PT1M"  # 1 minutes delay
                $trigger.Delay = $delay

                Register-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal -TaskName $taskname -Description $description *>$null

                #startup
                $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -Command `"iwr 'https://raw.githubusercontent.com/caglaryalcin/after-format/main/files/startup/Shells.psm1' -UseB | iex`""
                $trigger = New-ScheduledTaskTrigger -AtStartup
                $description = "You can check all the operations of this project at this link.  https://github.com/caglaryalcin/after-format"
                $principal = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-544" -RunLevel Highest
                $taskname = "startup"
                $delay = "PT5M" # 5 minutes delay
                $trigger.Delay = $delay

                $settings = New-ScheduledTaskSettingsSet -Hidden:$true

                $task = Register-ScheduledTask -TaskName $taskname -Trigger $trigger -Action $action -Principal $principal -Settings $settings -Description $description
                $task.Triggers.Repetition.Duration = ""
                $task.Triggers.Repetition.Interval = "PT3H"
                $task | Set-ScheduledTask *>$null
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

        # Disable snap
        Function DisableSnap {
            Write-Host `n"Do you want to " -NoNewline
            Write-Host "disable the Snap windows feature?" -ForegroundColor Yellow -NoNewline
            Write-Host "(y/n): " -ForegroundColor Green -NoNewline
            $response = Read-Host
        
            if ($response -eq 'y' -or $response -eq 'Y') {
                Write-Host "Disabling Snap windows feature..." -NoNewline
                #Disable Snap
                # Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WindowArrangementActive -Value 0 *>$null
        
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
                Write-Host ""
            }
        }
        
        DisableSnap

        Function NVCleanUpdateTask {
            Write-Host "Importing NVCleanstall Update task in Task Scheduler..." -NoNewline
            $nvcleanstall = "https://drive.usercontent.google.com/download?id=1mLE9M8XckmwMD_7A6hkmuQ_j5Noz6pPr&export=download&confirm=t&uuid=3dafda5a-d638-4e45-8655-3e4dcc5a7212&at=APZUnTXgUibc057YzjK_mWRb_0Di%3A1713698912361"
            $nvcleanpath = "C:\Program Files\NVCleanstall"

            New-Item -ItemType Directory -Force -Path $nvcleanpath | Out-Null

            Silent
            Invoke-WebRequest -Uri $nvcleanstall -Outfile "$nvcleanpath\NVCleanstall_1.16.0.exe" -ErrorAction Stop

            #update task
            $action = New-ScheduledTaskAction -Execute "$nvcleanpath\NVCleanstall_1.16.0.exe" -Argument "/check"
            $description = "Check for new graphics card drivers"
            $trigger1 = New-ScheduledTaskTrigger -AtLogon
            $trigger2 = New-ScheduledTaskTrigger -AtLogon
            $principal = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-544" -RunLevel Highest
            $taskname = "NVCleanstall"

            $settings = New-ScheduledTaskSettingsSet

            $task = Register-ScheduledTask -TaskName $taskname -Trigger $trigger1, $trigger2 -Action $action -Principal $principal -Settings $settings -Description $description

            # Remove repetition for trigger1
            $task.Triggers[0].Repetition = $null

            # Set repetition interval for trigger2
            $task.Triggers[1].Repetition.Interval = "PT4H"

            $task | Set-ScheduledTask *>$null

            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        NVCleanUpdateTask

        # Disable Gallery
        Function DisableGallery {
            try {
                Write-Host "Disabling gallery folder..." -NoNewline
                New-Item -Path "HKCU:\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" -ItemType Key *>$null
                New-itemproperty -Path "HKCU:\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" -Name "System.IsPinnedToNameSpaceTree" -Value "0" -PropertyType Dword *>$null
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        DisableGallery
        
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }

        DisableSync

        # Disable Spotlight
        function DisableSpotlight {
            Write-Host "Disabling Spotlight..." -NoNewline
            
            $RegistryKeys = @(
                "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent",
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
            )
        
            foreach ($Key in $RegistryKeys) {
                if (-not (Test-Path $Key)) {
                    New-Item -Path $Key -Force *>$null
                }
            }
        
            try {
                Set-ItemProperty -Path $RegistryKeys[0] -Name "NoWindowsSpotlight" -Value 1
                Set-ItemProperty -Path $RegistryKeys[1] -Name "RotatingLockScreenOverlayEnabled" -Value 0
                Set-ItemProperty -Path $RegistryKeys[1] -Name "SoftLandingEnabled" -Value 0
                Set-ItemProperty -Path $RegistryKeys[1] -Name "RotatingLockScreenEnabled" -Value 0
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        DisableSpotlight        

        # Disable Lock Screen Notifications
        function DisableLockScreenNotifications {
            Write-Host "Disabling lock screen notifications..." -NoNewline
            
            $registryPaths = @(
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings",
                "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications",
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications"
            )
            
            foreach ($path in $registryPaths) {
                if (-not (Test-Path $path)) {
                    New-Item -Path $path -Force *>$null
                }
            }
            
            try {
                Set-ItemProperty -Path $registryPaths[0] -Name "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" -Value 0
                Set-ItemProperty -Path $registryPaths[1] -Name "NoToastApplicationNotificationOnLockScreen" -Value 1
                Set-ItemProperty -Path $registryPaths[1] -Name "ToastEnabled" -Value 0
                Set-ItemProperty -Path $registryPaths[2] -Name "ToastEnabled" -Value 0
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings")) {
                    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Force *>$null
                }
                New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
                $currentSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                Set-ItemProperty -Path "HKU:\$currentSID\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDynamicSearchBoxEnabled" -Value 0

                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        DisableBingSearchExtension

        # Set Dark Mode for Applications
        Function SetAppsDarkMode {
            Write-Host "Setting Dark Mode for Applications..." -NoNewline
            try {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        #DisableVMEthernets

        # DNS Settings 
        Function SetDNS {
            Write-Host `n"Which DNS provider " -NoNewline
            Write-Host "do you want to use?" -ForegroundColor Yellow
            Write-Host `n"[1]" -NoNewline -BackgroundColor Black -ForegroundColor Yellow
            Write-Host " - Cloudflare"
            Write-Host "[2]" -NoNewline -BackgroundColor Black -ForegroundColor Yellow
            Write-Host " - Google"
            Write-Host "[3]" -NoNewline -BackgroundColor Black -ForegroundColor Yellow
            Write-Host " - Adguard"
            $choice = Read-Host -Prompt `n"[Choice]"
        
            $dnsServers = @()
            switch ($choice) {
                1 {
                    Write-Host `n"Setting Cloudflare DNS..." -NoNewline
                    $dnsServers = @("1.1.1.1", "1.0.0.1")
                }
                2 {
                    Write-Host `n"Setting Google DNS..." -NoNewline
                    $dnsServers = @("8.8.8.8", "8.8.4.4")
                }
                3 {
                    Write-Host `n"Setting Adguard DNS..." -NoNewline
                    $dnsServers = @("94.140.14.14", "94.140.15.15")
                }
                default {
                    Write-Host "Invalid input. Please enter 1, 2 or 3."
                    return
                }
            }
        
            try {
                $interfaces = "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14"
                Set-DnsClientServerAddress -InterfaceIndex $interfaces -ServerAddresses $dnsServers -ErrorAction SilentlyContinue
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }
        
        SetDNS        

        # Windows Explorer configure settings
        Function ExplorerSettings {
            Write-Host "Configuring Windows Explorer settings..." -NoNewline
        
            $settings = @{
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"                    = @{
                    "HudMode" = 1 # hide quick access
                };
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"           = @{
                    "LaunchTo"                     = 1; # 1 'This PC' #2 'Quick Access'
                    "HideFileExt"                  = 0; # Show known file extensions
                    "NavPaneExpandToCurrentFolder" = 0; # expand all folders
                    "NavPaneShowAllFolders"        = 0 # show all folders
                };
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"                    = @{
                    "ShowFrequent"                = 0; # Hide frequently used folders in quick access
                    "EnableAutoTray"              = 0; # Show All Icons
                    "ShowCloudFilesInQuickAccess" = 0; # Hide cloud files in quick access
                };
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"           = @{
                    "HideSCAMeetNow" = 1 # HideSCAMeetNow
                };
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"           = @{
                    "HideSCAMeetNow" = 1 #Disable "meet now" in the taskbar
                }
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState"       = @{
                    "FullPath" = 1; # Show full path in title bar
                };
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Search\Preferences" = @{
                    "ArchivedFiles" = 1 # Show archived files in search results
                }
            }
        
            $allSuccessful = $true
        
            foreach ($path in $settings.Keys) {
                foreach ($name in $settings[$path].Keys) {
                    if (-not (Test-Path $path)) {
                        New-Item -Path $path -Force *>$null
                    }
                    
                    try {
                        Set-ItemProperty -Path $path -Name $name -Value $settings[$path][$name] -ErrorAction Stop
                    }
                    catch {
                        Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                        $allSuccessful = $false
                    }
                }
            }
        
            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[DONE WITH ERRORS]" -ForegroundColor Yellow -BackgroundColor Black
            }
        }
        
        ExplorerSettings

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
                    Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                    Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                    $allSuccessful = $false
                }
            }
        
            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[DONE WITH ERRORS]" -ForegroundColor Yellow -BackgroundColor Black
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
                        Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                        $allSuccessful = $false
                    }
                }
        
                try {
                    Set-ItemProperty -Path $path -Name $paths[$path] -Value 1 -Type DWord -ErrorAction Stop
                }
                catch {
                    Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                    $allSuccessful = $false
                }
            }
        
            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[DONE WITH ERRORS]" -ForegroundColor Yellow -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                    Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                    $allSuccessful = $false
                }
            }
        
            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[DONE WITH ERRORS]" -ForegroundColor Yellow -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black  
        }

        DisableUpdateMSProducts

        # Disable Cortana 
        function DisableCortana {
            Write-Host "Disabling Cortana..." -NoNewline
            
            $allSuccessful = $true
        
            try {
                # Define registry keys and their values
                $RegistryKeys = @{
                    "HKCU:\Software\Microsoft\Personalization\Settings"                      = @{
                        "AcceptedPrivacyPolicy" = 0
                    }
                    "HKCU:\Software\Microsoft\InputPersonalization"                          = @{
                        "RestrictImplicitTextCollection" = 1
                        "RestrictImplicitInkCollection"  = 1
                    }
                    "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore"         = @{
                        "HarvestContacts" = 0
                    }
                    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"      = @{
                        "ShowCortanaButton" = 0
                    }
                    "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" = @{
                        "Value" = 0
                    }
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"               = @{
                        "AllowCortana"              = 0
                        "AllowSearchToUseLocation"  = 0
                        "DisableWebSearch"          = 1
                        "ConnectedSearchUseWeb"     = 0
                        "AllowCloudSearch"          = 0
                        "AllowCortanaAboveLock"     = 0
                        "EnableDynamicContentInWSB" = 0
                    }
                    "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"                 = @{
                        "AllowInputPersonalization" = 0
                    }
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Windows Search"         = @{
                        "CortanaConsent" = 0
                    }
                    "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences"                    = @{
                        "ModelDownloadAllowed" = 0
                    }
                }
        
                # Apply registry changes
                foreach ($Key in $RegistryKeys.Keys) {
                    if (-not (Test-Path $Key)) {
                        New-Item -Path $Key -Force | Out-Null
                    }
                    foreach ($Property in $RegistryKeys[$Key].Keys) {
                        Set-ItemProperty -Path $Key -Name $Property -Type DWord -Value $RegistryKeys[$Key][$Property]
                    }
                }
        
                # Remove Cortana Package
                $progressPreference = 'SilentlyContinue'
                Get-AppxPackage "Microsoft.549981C3F5F10" | Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                $allSuccessful = $false
            }
        
            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[WARNING] An error occurred." -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                $allSuccessful = $false
            }

            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                $allSuccessful = $false
            }

            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        DisableSmartScreen

        # Disable sensor features, such as screen auto rotation 
        function DisableSensors {
            Write-Host "Disabling Sensors..." -NoNewline
            
            $allSuccessful = $true
        
            try {
                # Create LocationAndSensors key if it doesn't exist
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
                }
                If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\LocationAndSensors")) {
                    New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
                }

                $HKLMRegistryValues = @{
                    "DisableLocation"                = 1
                    "DisableWindowsLocationProvider" = 1
                    "DisableLocationScripting"       = 1
                }
        
                # Set registry values
                $RegistryValues = @{
                    "DisableSensors"                 = 1
                    "DisableLocation"                = 1
                    "DisableWindowsLocationProvider" = 1
                    "DisableLocationScripting"       = 1
                }
        
                foreach ($Property in $RegistryValues.Keys) {
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name $Property -Type DWord -Value $RegistryValues[$Property]
                }

                foreach ($Property in $HKLMRegistryValues.Keys) {
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\LocationAndSensors" -Name $Property -Type DWord -Value $RegistryValues[$Property]
                }
        
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                $allSuccessful = $false
            }
        
            if (-not $allSuccessful) {
                Write-Host "[WARNING] An error occurred." -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                $allSuccessful = $false
            }
        
            try {
                Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                $allSuccessful = $false
            }
        
            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        DisableTailoredExperiences

        # Disable Xbox features - Not applicable to Server
        Function DisableXboxFeatures {
            Write-Host "Disabling Xbox Features..." -NoNewline
        
            try {
                $registryPaths = @{
                    "HKCU:\Software\Microsoft\GameBar" = @{
                        "AutoGameModeEnabled"       = 1
                        "AllowAutoGameMode"         = 1
                        "UseNexusForGameDetection"  = 0
                        "UseNexusForGameBarEnabled" = 0
                    }
                    "HKCU:\System\GameConfigStore"     = @{
                        "GameDVR_Enabled" = 0
                    }
                }
        
                foreach ($path in $registryPaths.Keys) {
                    foreach ($name in $registryPaths[$path].Keys) {
                        $value = $registryPaths[$path][$name]
                        Set-ItemProperty -Path $path -Name $name -Value $value -Type DWord -Force
                    }
                }
        
                $gameDVRKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
                if (-not (Test-Path $gameDVRKeyPath)) {
                    New-Item -Path $gameDVRKeyPath -Force | Out-Null
                }
                Set-ItemProperty -Path $gameDVRKeyPath -Name "AllowGameDVR" -Value 0 -Type DWord -Force
        
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[DONE WITH ERRORS]" -ForegroundColor Yellow -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                $allSuccessful = $false
            }

            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                $allSuccessful = $false
            }

            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                $allSuccessful = $false
            }

            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }

        }
        
        DisableMediaOnlineAccess

        # Disable System restore 
        Function DisableRestorePoints {
            Write-Host "Disabling System Restore for System Drive..." -NoNewline
        
            $allSuccessful = $true
        
            try {
                Disable-ComputerRestore -Drive "$env:SYSTEMDRIVE" *>$null
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                $allSuccessful = $false
            }
        
            try {
                vssadmin delete shadows /all /Quiet | Out-Null
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                $allSuccessful = $false
            }
        
            try {
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "DisableConfig" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "DisableSR" -Type DWord -Value 1
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                $allSuccessful = $false
            }
        
            try {
                schtasks /Change /TN "\Microsoft\Windows\SystemRestore\SR" /disable  | Out-Null *>$null
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                $allSuccessful = $false
            }
        
            if ($allSuccessful) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                    Write-Host "Could not stop/disable $service" -NoNewline
                }
            }
        
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }
        
        # Function usage
        $disableservices = @("XblAuthManager", "XblGameSave", "XblGameSave", "XboxNetApiSvc", "XboxGipSvc", "WalletService", "RemoteAccess", "WMPNetworkSvc", "NetTcpPortSharing", "AJRouter", "TrkWks", "dmwappushservice",
            "MapsBroker", "Fax", "CscService", "WpcMonSvc", "WPDBusEnum", "PcaSvc", "RemoteRegistry", "RetailDemo", "lmhosts", "WerSvc", "wisvc", "PhoneSvc", "EFS", "BDESVC",
            "CertPropSvc", "SCardSvr", "fhsvc", "SensorDataService", "SensorService", "icssvc", "lfsvc", "SEMgrSvc", "WpnService", "SDRSVC", "Spooler", "Bonjour Service", "SensrSvc", "WbioSrvc", "Sens")
        
        Disable-Services -disableservices $disableservices        

        Function Telnet {
            Write-Host "Enabling Telnet Client..." -NoNewline
            try {
                Enable-WindowsOptionalFeature -Online -FeatureName "TelnetClient" -NoRestart | Out-Null
            }
            catch {
                if ($_ -match "NoRestart") {
                    Write-Host "[INFO] Restart is suppressed because NoRestart is specified." -ForegroundColor Yellow -BackgroundColor Black
                }
                else {
                    Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                }
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }
        
        Telnet

        # Remove Quota on the disk menu
        Function RemoveQuota {
            Write-Host "Removing Quota on the disk menu..." -NoNewline
            try {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowInfoTip" -Type DWord -Value 0
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        RemoveQuota

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
                if (-not (Test-Path $taskbarFeedsPath)) {
                    New-Item -Path $taskbarFeedsPath -Force | Out-Null
                }
                Set-ItemProperty -Path $taskbarFeedsPath -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2 -ErrorAction Stop | Out-Null

                # Disable Show recommendations for tips, shortcuts, new apps
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_IrisRecommendations" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
        
                # Start Menu Layout
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_Layout" -Type DWord -Value 1 -ErrorAction Stop | Out-Null

                # Turn off "Show recently opened items in Start, Jump Lists, and File Explorer"
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Type DWord -Value 0 -ErrorAction Stop | Out-Null

                # Disable news and interests via Policies\Explorer
                $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                if (-not (Test-Path $registryPath)) {
                    New-Item -Path $registryPath -Force | Out-Null
                }
                Set-ItemProperty -Path $registryPath -Name "NoNewsAndInterests" -Value 1 -ErrorAction Stop
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        HideTaskbarMultiTaskviewIcon

        # Hide Taskbar Search icon / box
        Function HideTaskbarSearch {
            Write-Host "Hiding Taskbar Search Icon / Box..." -NoNewline
            try {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        RemoveTaskbarWidgets

        # Turn off suggested content in Settings
        Function TurnOffSuggestedContent {
            Write-Host "Turning off suggested content in Settings..." -NoNewline
            $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
            $contentSettings = @(
                "SubscribedContent-338393Enabled",
                "SubscribedContent-353694Enabled",
                "SubscribedContent-353696Enabled"
            )
        
            try {
                foreach ($setting in $contentSettings) {
                    Set-ItemProperty -Path $registryPath -Name $setting -Type DWord -Value 0
                }
                
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        TurnOffSuggestedContent
		
        # Set always show combine on taskbar
        Function TaskbarAlwaysCombine {
            try {
                Write-Host "Taskbar Always Combine..." -NoNewline
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Value 0 -ErrorAction SilentlyContinue *>$null
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        TaskbarAlwaysCombine
		
        # Hide Taskbar Start button alignment left
        Function TaskbarAlignLeft {
            try {
                Write-Host "Taskbar Aligns Left..." -NoNewline
                New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value "0" -PropertyType Dword *>$null
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        TaskbarAlignLeft
		
        # Enable Show Desktop Button
        Function EnableShowDesktop {
            try {
                Write-Host "Enabling Show Desktop Button..." -NoNewline
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSd" -Value 1 -ErrorAction SilentlyContinue *>$null
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        EnableShowDesktop

        # Hide Taskbar Remove Widgets from the Taskbar
        Function UnpinEverything {
            Param(
                [string]$RemoveUnpin
            )
        
            try {
                Write-Host "Unpin all taskbar pins..." -NoNewline
        
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
        
                Function ConfigureTaskbarPinningApp {
                    Param([string]$RemoveUnpin, [string]$Verb)
                    $myProcessName = Get-Process | Where-Object { $_.ID -eq $pid } | ForEach-Object { $_.ProcessName }
                    if (-not ($myProcessName -like "explorer")) {
                        return
                    }
        
                    
                }
        
                ConfigureTaskbarPinningApp -RemoveUnpin $RemoveUnpin -Verb "UnpinFromTaskbar"
        
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        UnpinEverything -RemoveUnpin ""
        
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
                #HKLM
                @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "AllowTelemetry"; Type = "DWord"; Value = 0 },
                @{Path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "AllowTelemetry"; Type = "DWord"; Value = 0 },
                @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "LimitDiagnosticLogCollection"; Type = "DWord"; Value = 1 },
                @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "DisableOneSettingsDownloads"; Type = "DWord"; Value = 1 },
                @{Path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "MaxTelemetryAllowed"; Type = "DWord"; Value = 0 },
                @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "AllowTelemetry"; Type = "DWord"; Value = 0 },
                @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"; Name = "AllowBuildPreview"; Type = "DWord"; Value = 0 },
                @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"; Name = "NoGenTicket"; Type = "DWord"; Value = 1 },
                @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"; Name = "CEIPEnable"; Type = "DWord"; Value = 0 },
                @{Path = "HKLM:\SOFTWARE\Microsoft\SQMClient\Windows"; Name = "CEIPEnable"; Type = "DWord"; Value = 0 },
                @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Name = "AITEnable"; Type = "DWord"; Value = 0 },
                @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Name = "DisableInventory"; Type = "DWord"; Value = 1 },
                @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP"; Name = "CEIPEnable"; Type = "DWord"; Value = 0 },
                @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"; Name = "PreventHandwritingDataSharing"; Type = "DWord"; Value = 1 },
                @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput"; Name = "AllowLinguisticDataCollection"; Type = "DWord"; Value = 0 },
                @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE"; Name = "DisablePrivacyExperience"; Type = "Dword"; Value = "1" },
                @{Path = "HKLM:\SOFTWARE\Microsoft\MdmCommon\SettingValues"; Name = "LocationSyncEnabled"; Type = "Dword"; Value = "0" },
                @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; Name = "Enabled"; Type = "Dword"; Value = "0" },
                #HKCU
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/caglaryalcin/block-windows-telemetry/main/host" -OutFile "$env:USERPROFILE\Desktop\host"
                    Move-Item -Path "$env:userprofile\Desktop\host" -Destination C:\windows\system32\drivers\etc\hosts -Force
                    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                }
                catch {
                    Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                }
            }
            else {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        BlockUrlsToHost

        # Disable Feedback 
        function DisableFeedback {
            Write-Host "Disabling Feedback..." -NoNewline
            
            try {
                # Define registry keys and their values
                $RegistryKeys = @{
                    "HKCU:\Software\Microsoft\Siuf\Rules"                      = @{
                        "PeriodInNanoSeconds"  = 0
                        "NumberOfSIUFInPeriod" = 0
                    }
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" = @{
                        "DoNotShowFeedbackNotifications" = 1
                    }
                }
        
                # Apply registry changes
                foreach ($Key in $RegistryKeys.Keys) {
                    if (-not (Test-Path $Key)) {
                        New-Item -Path $Key -Force | Out-Null
                    }
                    foreach ($Property in $RegistryKeys[$Key].Keys) {
                        Set-ItemProperty -Path $Key -Name $Property -Type DWord -Value $RegistryKeys[$Key][$Property] -ErrorAction Stop
                    }
                }
        
                # Disable scheduled tasks
                $tasks = @("Microsoft\Windows\Feedback\Siuf\DmClient", "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload")
                foreach ($task in $tasks) {
                    $result = Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
                    if ($null -eq $result) { throw "Task $task could not be disabled or not found." }
                }
        
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                Write-Host $_.Exception.Message -ForegroundColor Red
            }
        }
        
        DisableFeedback       
        
        # Disable Text Suggestions
        Function DisableTextSuggestions {
            Write-Host "Disabling Text Suggestions..." -NoNewline
            if (-not (Test-Path "HKCU:\Software\Microsoft\TabletTip\1.7" )) {
                New-Item -Path "HKCU:\Software\Microsoft\TabletTip\1.7"  -Force *>$null
            }

            Set-ItemProperty -Path "HKCU:\Software\Microsoft\TabletTip\1.7" -Name "EnableTextPrediction" -Value 0
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        DisableTextSuggestions

        # Disable Windows Error Reporting
        Function DisableErrorReporting {
            Write-Host "Disabling Windows Error Reporting..." -NoNewline
            If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting")) {
                New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Force | Out-Null
            }

            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        DisableErrorReporting

        # Disable camera in logon screen
        Function DisableCameraonLogon {
            Write-Host "Disabling Camera on Logon Screen..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Value 1
                If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Personalization")) {
                    New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Personalization" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Value 1
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }

        DisableCameraonLogon

        # Disable backup of text messages into the cloud
        Function DisableTextMessageBackup {
            Write-Host "Disabling Backup of Text Messages into the Cloud..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -Name "AllowMessageSync" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
               
                If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Messaging")) {
                    New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Messaging" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Messaging" -Name "AllowMessageSync" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }

        DisableTextMessageBackup

        # Disable sharing of handwriting error reports
        Function DisableHandwritingErrorReports {
            Write-Host "Disabling Sharing of Handwriting Error Reports..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }

        DisableHandwritingErrorReports

        # Disable password reveal button
        Function DisablePasswordRevealButton {
            Write-Host "Disabling Password Reveal Button..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Type DWord -Value 1 -ErrorAction Stop | Out-Null

                If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\CredUI")) {
                    New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\CredUI" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Type DWord -Value 1 -ErrorAction Stop | Out-Null

                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }

        DisablePasswordRevealButton

        # Disable the transfer of the clipboard to other devices via the cloud
        Function DisableClipboardSharing {
            Write-Host "Disabling Clipboard Sharing..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\System")) {
                    New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\System" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\System" -Name "AllowCrossDeviceClipboard" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }

        DisableClipboardSharing

        # Disable functionality to locate the system
        Function Disablelocatesystem {
            Write-Host "Disabling Functionality to Locate the System..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth")) {
                    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" -Name "DisableWindowsLocationProvider" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }

        Disablelocatesystem

        # Disable ads via Bluetooth
        Function AdsviaBluetooth {
            Write-Host "Disabling Ads via Bluetooth..." -NoNewline
            try {
                If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth")) {
                    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" -Name "AllowAdvertising" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }

        AdsviaBluetooth

        # Disable Activity History feed in Task View 
        Function DisableActivityHistory {
            Write-Host "Disabling Activity History..." -NoNewline
            $settings = @{
                "EnableActivityFeed"        = 0
                "PublishUserActivities"     = 0
                "UploadUserActivities"      = 0
                "AllowCrossDeviceClipboard" = 0
            }
        
            $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"

            try {
                if (!(Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
        
                $settings.GetEnumerator() | ForEach-Object {
                    Set-ItemProperty -Path $regPath -Name $_.Key -Type DWord -Value $_.Value -ErrorAction Stop
                }
        
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        DisableClipboardHistory

        # Disable diagnostic log collection
        Function DisableDiagnosticLogCollection {
            Write-Host "Disabling Diagnostic Log Collection..." -NoNewline
        
            $diagpath = "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DataCollection"
        
            if (-not (Test-Path $diagpath)) {
                New-Item -Path $diagpath -Force *>$null
            }
        
            try {
                Set-ItemProperty -Path $diagpath -Name "LimitDiagnosticLogCollection" -Value 1 #Disable diagnostic log collection
                Set-ItemProperty -Path $diagpath -Name "DisableOneSettingsDownloads" -Value 1 #Disable downloading of OneSettings configuration settings
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }

        DisableDiagnosticLogCollection

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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat",
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation",
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics"
            )
        
            try {
                foreach ($path in $paths) {
                    Set-ItemProperty -Path $path -Name "Value" -Type String -Value "Deny" -ErrorAction Stop
                }
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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

                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type DWord -Value 0 -ErrorAction Stop

                If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
                    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Force | Out-Null
                }

                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 0 -ErrorAction Stop
                
                If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DeliveryOptimization")) {
                    New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DeliveryOptimization" -Force | Out-Null
                }

                Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type DWord -Value 0 -ErrorAction Stop
                
                New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
                $currentSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                $userKey = "HKU:\$currentSID"
                If (!(Test-Path "$userKey\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization")) {
                    New-Item -Path "$userKey\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Force | Out-Null
                }
                
                Set-ItemProperty -Path "$userKey\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Type DWord -Value 0 -ErrorAction Stop
                
                # Disable updates to the speech recognition and speech synthesis modules
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Speech")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Speech" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Speech" -Name "AllowSpeechModelUpdate" -Type DWord -Value 0 -ErrorAction Stop

                If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Speech")) {
                    New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Speech" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Speech" -Name "AllowSpeechModelUpdate" -Type DWord -Value 0 -ErrorAction Stop
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
        }

        DisableUpdateAutoDownload

        # Enable Task Scheduler History
        Function EnableTaskSchedulerHistory {
            Write-Host "Enabling Task Scheduler History..." -NoNewline
            wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        EnableTaskSchedulerHistory
        
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

        Function installwinget {
            # I now use asheroto's https://github.com/asheroto/winget-install repo to install winget
            Write-Host `n"Installing/upgrading winget..." -NoNewline
            
            $job = Start-Job -ScriptBlock {
                &([ScriptBlock]::Create((irm winget.pro))) -Force *>$null
            }
            
            Wait-Job -Job $job | Out-Null
            
            #create softwares task
            $wtPath = Get-Command wt.exe | Select-Object -ExpandProperty Definition

            $psCommand = "powershell.exe -ExecutionPolicy Bypass -Command `"iwr 'https://raw.githubusercontent.com/caglaryalcin/after-format/main/resume.psm1' -UseBasicParsing | iex`""
            $wtCommand = "-w 0 new-tab $psCommand"
            $action = New-ScheduledTaskAction -Execute $wtPath -Argument $wtCommand
            $trigger = New-ScheduledTaskTrigger -AtLogon
            $principal = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-544" -RunLevel Highest
            $taskname = "softwares"
            $description = "temp task"
            $settings = New-ScheduledTaskSettingsSet

            $task = Register-ScheduledTask -TaskName $taskname -Trigger $trigger -Action $action -Principal $principal -Settings $settings -Description $description
            $task | Set-ScheduledTask *>$null

            Start-Sleep 2
            Restart-Computer -Force
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black

        }
        
        installwinget
        
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