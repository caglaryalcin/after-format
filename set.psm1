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
#region Mode
##########

Function ModeSelect {
    $choiceregPath = "HKCU:\Software\MyScript"
    $choiceregName = "Mode"

    Write-Host "`n---------Mode Select" -ForegroundColor Blue -BackgroundColor Gray

    do {
        $mode = $null
        Write-Host "`nWhat do you use " -NoNewline
        Write-Host "your computer?" -ForegroundColor Yellow -NoNewline
        Write-Host " (1/2/3): " -ForegroundColor Green
        Write-Host `n"[1]" -NoNewline -BackgroundColor Black -ForegroundColor Yellow
        Write-Host " - Developer-Sys Eng"
        Write-Host "[2]" -NoNewline -BackgroundColor Black -ForegroundColor Yellow
        Write-Host " - Normal"
        Write-Host "[3]" -NoNewline -BackgroundColor Black -ForegroundColor Yellow
        Write-Host " - Gaming"

        $response = Read-Host -Prompt `n"[Choice]"

        switch ($response.Trim()) {
            '1' { $mode = 'developer'; Write-Host "`nDeveloper-Sys Eng. mode is being set... " -NoNewline; Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black }
            '2' { $mode = 'normal'; Write-Host "`nNormal mode is being set... " -NoNewline; Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black }
            '3' { $mode = 'gaming'; Write-Host "`nGaming mode is being set... " -NoNewline; Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black }
            default { Write-Host "[Invalid input. Please enter 1, 2 or 3.]" -ForegroundColor Red -BackgroundColor Black }
        }
    } while (-not $mode)

    if (-not (Test-Path $choiceregPath)) { New-Item -Path $choiceregPath -Force | Out-Null }
    Set-ItemProperty -Path $choiceregPath -Name $choiceregName -Value $mode -Type String -Force
}

ModeSelect

$mode = (Get-ItemProperty -Path "HKCU:\Software\MyScript" -Name "Mode" -ErrorAction SilentlyContinue)."Mode"

##########
#endregion Priority
##########

##########
#region System Settings 
##########
Function SystemSettings {
    Write-Host "`n---------Adjusting System Settings" -ForegroundColor Blue -BackgroundColor Gray

    Write-Host "`nDo you want " -NoNewline
    Write-Host "System Settings?" -ForegroundColor Yellow -NoNewline
    Write-Host "(y/n): " -ForegroundColor Green -NoNewline
    $response = Read-Host

    if ($response -eq 'y' -or $response -eq 'Y') {

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

        Function WinActivation {
            Write-Host `n"Would you like to " -NoNewline
            Write-Host "active Windows?" -ForegroundColor Yellow -NoNewline
            Write-Host "(y/n): " -ForegroundColor Green -NoNewline
            $response = Read-Host
        
            if ($response -eq 'y' -or $response -eq 'Y') {
                Write-Host "Activating Windows..." -NoNewline
                
                & ([ScriptBlock]::Create((curl.exe -s --doh-url https://1.1.1.1/dns-query https://get.activated.win | Out-String))) /K-Windows
        
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            elseif ($response -eq 'n' -or $response -eq 'N') {
                Write-Host "[Windows activation will not be performed.]" -ForegroundColor Red -BackgroundColor Black
            }
            else {
                Write-Host "[Invalid input. Please enter 'y' for yes or 'n' for no.]" -ForegroundColor Red -BackgroundColor Black
                DisableSnap
            }
        }
        
        WinActivation

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

                    # Disable system guard
                    $systemguardPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard"
                    if (-not (Test-Path $systemguardPath)) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios" -Name "SystemGuard" -Force *>$null }
                    New-ItemProperty -Path $systemguardPath -Name "Enabled" -Value 0 -PropertyType DWORD -Force *>$null
        
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
                Write-Host "[Invalid input. Please enter 'y' for yes or 'n' for no.]" -ForegroundColor Red -BackgroundColor Black
                DisableDefender
            }
        }
        
        DisableDefender

        Function SetKeyboardLayout {
            Write-Host "`nDo you want to " -NoNewline
            Write-Host "set the keyboard layout to UK or TR?" -ForegroundColor Yellow -NoNewline
            Write-Host "(y/n): " -ForegroundColor Green -NoNewline
            $response = Read-Host
        
            if ($response -eq 'y' -or $response -eq 'Y') {
                do {
                    Write-Host "Which keyboard layout do you want to set? Write 1, 2, 3 or 4."
                    Write-Host `n"[1]" -NoNewline -BackgroundColor Black -ForegroundColor Yellow
                    Write-Host " - Turkish keyboard layout"
                    Write-Host "[2]" -NoNewline -BackgroundColor Black -ForegroundColor Yellow
                    Write-Host " - United Kingdom keyboard layout"
                    Write-Host "[3]" -NoNewline -BackgroundColor Black -ForegroundColor Yellow
                    Write-Host " - Both Turkish and United Kingdom keyboard layout"
                    Write-Host "[4]" -NoNewline -BackgroundColor Black -ForegroundColor Yellow
                    Write-Host " - None"
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
                        "4" {
                            Write-Host "[No changes will be made to the keyboard layout.]" -ForegroundColor Red -BackgroundColor Black
                        }
                        default {
                            Write-Host "Invalid input. Please enter 1, 2, 3 or 4."
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
                Write-Host "[Invalid input. Please enter 'y' for yes or 'n' for no.]" -ForegroundColor Red -BackgroundColor Black
                ImportStartup
            }
        }
        
        ImportStartup

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
            }
            elseif ($response -eq 'n' -or $response -eq 'N') {
                Write-Host "[Snap windows feature will not be disabled.]" -ForegroundColor Red -BackgroundColor Black
            }
            else {
                Write-Host "[Invalid input. Please enter 'y' for yes or 'n' for no.]" -ForegroundColor Red -BackgroundColor Black
                DisableSnap
            }
        }
        
        DisableSnap
        Function NVCleanUpdateTask {
            Write-Host "`nDo you want to " -NoNewline
            Write-Host "install NVCleanstall and import the update task?" -ForegroundColor Yellow -NoNewline
            Write-Host "(y/n): " -ForegroundColor Green -NoNewline
            $response = Read-Host
        
            if ($response -eq 'y' -or $response -eq 'Y') {
                Write-Host "Importing NVCleanstall Update task in Task Scheduler..." -NoNewline
                $nvcleanstall = "https://drive.usercontent.google.com/download?id=1BenAUmJ5HiaSfELsZnlWna2py2dWQHKb&export=download&confirm=t&uuid=3dafda5a-d638-4e45-8655-3e4dcc5a7212&at=APZUnTXgUibc057YzjK_mWRb_0Di%3A1713698912361"
                $nvcleanpath = "C:\Program Files\NVCleanstall"
        
                New-Item -ItemType Directory -Force -Path $nvcleanpath | Out-Null
                Silent
                Invoke-WebRequest -Uri $nvcleanstall -Outfile "$nvcleanpath\NVCleanstall_1.19.0.exe" -ErrorAction Stop
        
                # Update task
                $action = New-ScheduledTaskAction -Execute "$nvcleanpath\NVCleanstall_1.19.0.exe" -Argument "/check"
                $description = "Check for new graphics card drivers"
                $trigger1 = New-ScheduledTaskTrigger -AtLogon
                $trigger2 = New-ScheduledTaskTrigger -Daily -At "10:00AM"
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
            elseif ($response -eq 'n' -or $response -eq 'N') {
                Write-Host "[NVCleanstall installation and update task import will not be performed.]" -ForegroundColor Red -BackgroundColor Black
            }
            else {
                Write-Host "[Invalid input. Please enter 'y' for yes or 'n' for no.]" -ForegroundColor Red -BackgroundColor Black
                NVCleanUpdateTask
            }
        }
        
        NVCleanUpdateTask

        Function TerminalConfig {
            Write-Host "`nDo you want to " -NoNewline
            Write-Host "configure Windows Terminal config?" -ForegroundColor Yellow -NoNewline
            Write-Host "(y/n): " -ForegroundColor Green -NoNewline
            $response = Read-Host

            if ($response -eq 'y' -or $response -eq 'Y') {
                Write-Host "Configuring Windows Terminal..." -NoNewline
                $profileFolder = "$HOME\Documents\WindowsPowerShell"
                if (-Not (Test-Path -Path $profileFolder)) {
                    New-Item -ItemType Directory -Path $profileFolder *>$null
                }
    
                $profileFile = "$profileFolder\Microsoft.PowerShell_profile.ps1"
                $commands = @'
    oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH\star.omp.json" | Invoke-Expression
    clear
'@
                Set-Content -Path $profileFile -Value $commands
    
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            elseif ($response -eq 'n' -or $response -eq 'N') {
                Write-Host "[Windows Terminal config will not be set.]" -ForegroundColor Red -BackgroundColor Black
            }
            else {
                Write-Host "[Invalid input. Please enter 'y' for yes or 'n' for no.]" -ForegroundColor Red -BackgroundColor Black
                TerminalConfig
            }
        }

        if ($mode -eq "developer") { TerminalConfig }

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

        Function ExplorerView {
            # Set the separator setting in explorer
            param (
                [byte[]]$newColInfoValue = @(
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0xFD, 0xDF, 0xDF, 0xFD, 0x10, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x04, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
                    0x30, 0xF1, 0x25, 0xB7, 0xEF, 0x47, 0x1A, 0x10,
                    0xA5, 0xF1, 0x02, 0x60, 0x8C, 0x9E, 0xEB, 0xAC,
                    0x0A, 0x00, 0x00, 0x00, 0x17, 0x01, 0x00, 0x00,
                    0x30, 0xF1, 0x25, 0xB7, 0xEF, 0x47, 0x1A, 0x10,
                    0xA5, 0xF1, 0x02, 0x60, 0x8C, 0x9E, 0xEB, 0xAC,
                    0x0E, 0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00,
                    0x30, 0xF1, 0x25, 0xB7, 0xEF, 0x47, 0x1A, 0x10,
                    0xA5, 0xF1, 0x02, 0x60, 0x8C, 0x9E, 0xEB, 0xAC,
                    0x04, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00,
                    0x30, 0xF1, 0x25, 0xB7, 0xEF, 0x47, 0x1A, 0x10,
                    0xA5, 0xF1, 0x02, 0x60, 0x8C, 0x9E, 0xEB, 0xAC,
                    0x0C, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00
                )
            )
            Write-Host `n"Do you want to all folder views in explorer to be selected as " -NoNewline
            Write-Host "details" -ForegroundColor Red -BackgroundColor Black -NoNewline
            Write-Host " and set to separate?" -NoNewline
            Write-Host "(y/n): " -ForegroundColor Green -NoNewline
            $response = Read-Host
        
            if ($response -eq 'y' -or $response -eq 'Y') {
                Write-Host "Setting Explorer view settings to 'Details'..." -NoNewline
    
                # Set the view settings to Details for all folders
                $basePath = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags"
                $bags = Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue
    
                foreach ($bag in $bags) {
                    # Exclude specific bags
                    if ($bag.PSChildName -in "1", "4", "24") {
                        continue
                    }
    
                    $shellPath = Join-Path $bag.PSPath "Shell"
    
                    if (Test-Path $shellPath) {
                        $subKeys = Get-ChildItem -Path $shellPath -Recurse -ErrorAction SilentlyContinue
    
                        foreach ($subKey in $subKeys) {
                            $subKeyPath = $subKey.PSPath
    
                            # Change the view settings
                            Set-ItemProperty -Path $subKeyPath -Name "Mode" -Value 4 -Type DWord -ErrorAction SilentlyContinue
                            Set-ItemProperty -Path $subKeyPath -Name "LogicalViewMode" -Value 1 -Type DWord -ErrorAction SilentlyContinue
                            Set-ItemProperty -Path $subKeyPath -Name "IconSize" -Value 10 -Type DWord -ErrorAction SilentlyContinue
                            Set-ItemProperty -Path $subKeyPath -Name "Vid" -Value "{137E7700-3573-11CF-AE69-08002B2E1262}" -Type String -ErrorAction SilentlyContinue
                        }
                    }
                }
    
                # Set the view separator settings to Details for all folders
                Get-ChildItem -Path $basePath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                    $subKeyPath = $_.PSPath
                    Get-ChildItem -Path $subKeyPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                        $colInfoPath = $_.PSPath
                        if (Test-Path -Path $colInfoPath -ErrorAction SilentlyContinue) {
                            $colInfo = Get-ItemProperty -Path $colInfoPath -Name "ColInfo" -ErrorAction SilentlyContinue
                            if ($colInfo) {
                                Set-ItemProperty -Path $colInfoPath -Name "ColInfo" -Value $newColInfoValue -ErrorAction SilentlyContinue
                            }
                        }
                    }
                }

                # Set control panel view
                $Key1 = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU"
                $Data1 = "06 00 00 00 02 00 00 00 03 00 00 00 01 00 00 00 07 00 00 00 05 00 00 00 04 00 00 00 00 00 00 00 FF FF FF FF"
                $byteArray1 = $Data1 -split ' ' | ForEach-Object { [byte]::Parse($_, [System.Globalization.NumberStyles]::HexNumber) }
                Set-ItemProperty -Path $Key1 -Name "MRUListEx" -Value $byteArray1 -Type Binary -ErrorAction SilentlyContinue
            
                $Key2 = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\24\Shell\{D674391B-52D9-4E07-834E-67C98610F39D}"
                $Data2 = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FD DF DF FD 10 00 00 00 00 00 00 00 00 00 00 00 05 00 00 00 18 00 00 00 30 F1 25 B7 EF 47 1A 10 A5 F1 02 60 8C 9E EB AC 0A 00 00 00 17 01 00 00 90 4F 1E 84 59 FF 16 4D 89 47 E8 1B BF FA B3 6D 02 00 00 00 C0 00 00 00 90 4F 1E 84 59 FF 16 4D 89 47 E8 1B BF FA B3 6D 0B 00 00 00 50 00 00 00 30 F1 25 B7 EF 47 1A 10 A5 F1 02 60 8C 9E EB AC 0C 00 00 00 50 00 00 00 53 7D EF 0C 64 FA D1 11 A2 03 00 00 F8 1F ED EE 08 00 00 00 80 00 00 00"
                $byteArray2 = $Data2 -split ' ' | ForEach-Object { [byte]::Parse($_, [System.Globalization.NumberStyles]::HexNumber) }
                Set-ItemProperty -Path $Key2 -Name "ColInfo" -Value $byteArray2 -Type Binary -ErrorAction SilentlyContinue
    
                # Remove ShareX from context menu
                reg delete "HKEY_CLASSES_ROOT\*\shell\ShareX" /f *> $null
    
                # Restart Explorer
                taskkill /f /im explorer.exe *> $null
                Start-Process "explorer.exe" -NoNewWindow
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            elseif ($response -eq 'n' -or $response -eq 'N') {
                Write-Host "[Explorer view will not be set to details.]" -ForegroundColor Red -BackgroundColor Black
            }
            else {
                Write-Host "[Invalid input. Please enter 'y' for yes or 'n' for no.]" -ForegroundColor Red -BackgroundColor Black
                ExplorerView
            }
        }
        
        ExplorerView

        Function SetAppsMode {
            Write-Host "`nWhich application mode do you want to use?"
            Write-Host "`n[1]" -NoNewline -BackgroundColor Black -ForegroundColor Yellow
            Write-Host " - Light Mode"
            Write-Host "[2]" -NoNewline -BackgroundColor Black -ForegroundColor Yellow
            Write-Host " - Dark Mode"

            $response = Read-Host -Prompt `n"[Choice]"

            switch ($response.Trim()) {
                '1' {
                    Write-Host "Setting Light Mode for Applications..." -NoNewline
                    try {
                        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 1
                        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 1
                        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0
                    }
                    catch {
                        Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                    }
                    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                }

                '2' {
                    Write-Host "Setting Dark Mode for Applications..." -NoNewline
                    try {
                        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0
                        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 0
                        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0
                    }
                    catch {
                        Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                    }
                    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                }

                default {
                    Write-Host "[Invalid input. Please enter 1 for Light or 2 for Dark.]" -ForegroundColor Red -BackgroundColor Black
                    SetAppsMode
                }
            }
        }

        SetAppsMode

        Function SetDNS {
            Function GetPingTime {
                param (
                    [string]$address
                )

                $pingOutput = ping $address -n 2 | Select-String "time=" | Select-Object -Last 1
                if ($pingOutput) {
                    $pingTime = [regex]::Match($pingOutput.ToString(), 'time=(\d+)ms').Groups[1].Value
                    return $pingTime
                }
                else {
                    return "N/A"
                }
            }

            do {
                Write-Host `n"Would you like to change your " -NoNewline
                Write-Host "DNS setting?" -ForegroundColor Yellow -NoNewline
                Write-Host " (y/n): " -ForegroundColor Green -NoNewline
                $confirmation = Read-Host

                $valid = $confirmation -match '^(?i:y|yes|n|no)$'
                if (-not $valid) { Write-Host "[Invalid input. Please enter 'y' for yes or 'n' for no.]" -ForegroundColor Red -BackgroundColor Black }
            } until ($valid)

            if ($confirmation -match '^(?i:n|no)$') {
                Write-Host "DNS settings will not be changed."
                return
            }

            Write-Host "MS values are being calculated..." -NoNewline

            $cloudflareDNS = "1.1.1.1"
            $googleDNS = "8.8.8.8"
            $adguardDNS = "94.140.14.14"

            $cloudflarePing = GetPingTime -address $cloudflareDNS
            $googlePing = GetPingTime -address $googleDNS
            $adguardPing = GetPingTime -address $adguardDNS
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            Write-Host "`nWhich DNS provider " -NoNewline
            Write-Host "do you want to use?" -ForegroundColor Yellow -NoNewline
            Write-Host " Write 1, 2 or 3."

            do {
                Write-Host `n"[1]" -NoNewline -BackgroundColor Black -ForegroundColor Yellow
                Write-Host " - Cloudflare " -NoNewline
                Write-Host "[$cloudflarePing" -ForegroundColor Yellow -BackgroundColor Black -NoNewline
                Write-Host "ms]" -ForegroundColor Yellow -BackgroundColor Black
                Write-Host "[2]" -NoNewline -BackgroundColor Black -ForegroundColor Yellow
                Write-Host " - Google " -NoNewline
                Write-Host "[$googlePing" -ForegroundColor Yellow -BackgroundColor Black -NoNewline
                Write-Host "ms]" -ForegroundColor Yellow -BackgroundColor Black
                Write-Host "[3]" -NoNewline -BackgroundColor Black -ForegroundColor Yellow
                Write-Host " - Adguard " -NoNewline
                Write-Host "[$adguardPing" -ForegroundColor Yellow -BackgroundColor Black -NoNewline
                Write-Host "ms]" -ForegroundColor Yellow -BackgroundColor Black

                $choice = Read-Host -Prompt `n"[Choice]"
                $validChoice = $choice -match '^[123]$'
                if (-not $validChoice) { Write-Host "[Invalid input. Please enter 1, 2, or 3.]" -ForegroundColor Red -BackgroundColor Black }
            } until ($validChoice)

            $dnsServers = @()
            switch ([int]$choice) {
                1 { Write-Host `n"Setting Cloudflare DNS..." -NoNewline; $dnsServers = @("1.1.1.1", "1.0.0.1") }
                2 { Write-Host `n"Setting Google DNS..."     -NoNewline; $dnsServers = @("8.8.8.8", "8.8.4.4") }
                3 { Write-Host `n"Setting Adguard DNS..."    -NoNewline; $dnsServers = @("94.140.14.14", "94.140.15.15") }
            }

            try {
                $interfaces = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -ExpandProperty ifIndex
                Set-DnsClientServerAddress -InterfaceIndex $interfaces -ServerAddresses $dnsServers -ErrorAction Stop
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Black
            }
        }

        SetDNS

        Function DisableSync {
            Write-Host "Synchronization with Microsoft is completely disabling..." -NoNewline
            $syncPath = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"
            $msaccountpath = "HKLM:\SOFTWARE\Microsoft\Windows\Currentversion\Policies\System"
            $msaccountpath2 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowYourAccount"

            if (-not (Test-Path $syncPath)) {
                New-Item -Path $syncPath -Force *>$null
            }

            try {
                Set-ItemProperty -Path $syncPath -Name "DisableSettingSyncUserOverride" -Value 1
                Set-ItemProperty -Path $syncPath -Name "DisableSyncYourSettings" -Value 1
                Set-ItemProperty -Path $syncPath -Name "DisableWebBrowser" -Value 1
                Set-ItemProperty -Path $syncPath -Name "DisablePersonalization" -Value 1
                Set-ItemProperty -Path $syncPath -Name "DisableSettingSync" -Value 2
                Set-ItemProperty -Path $msaccountpath -Name "NoConnectedUser" -Value 3
                Set-ItemProperty -Path $msaccountpath2 -Name "value" -Value 0

                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }

        DisableSync

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

        function DisableLockScreenNotifications {
            Write-Host "Disabling lock screen notifications..." -NoNewline
            
            $lockregistryPaths = @(
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings",
                "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications",
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications"
            )
            
            foreach ($path in $lockregistryPaths) {
                if (-not (Test-Path $path)) {
                    New-Item -Path $path -Force *>$null
                }
            }
            
            try {
                Set-ItemProperty -Path $lockregistryPaths[0] -Name "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" -Value 0
                Set-ItemProperty -Path $lockregistryPaths[1] -Name "NoToastApplicationNotificationOnLockScreen" -Value 1
                Set-ItemProperty -Path $lockregistryPaths[1] -Name "ToastEnabled" -Value 0
                Set-ItemProperty -Path $lockregistryPaths[2] -Name "ToastEnabled" -Value 0
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        DisableLockScreenNotifications

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

        Function DisableBingSearchExtension {
            Write-Host "Disabling extension of Windows search with Bing..." -NoNewline
            
            $bingsearch = "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings"

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

        Function SetControlPanelLargeIcons {
            Write-Host `n"Setting Control Panel view to large icons..." -NoNewline

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

        Function Disable-Services {
            param (
                [string[]]$disableservices
            )
            Write-Host "Stop and Disabling Unnecessary Services..." -NoNewline
            
            $infoOccurred = $false
            
            foreach ($service in $disableservices) {
                try {
                    $currentService = Get-Service -Name $service -ErrorAction SilentlyContinue
                    if ($null -ne $currentService) {
                        Stop-Service -Name $service -Force -ErrorAction Stop *>$null
                        Set-Service -Name $service -StartupType Disabled -ErrorAction Stop *>$null
                    }
                }
                catch {
                    Write-Host "[INFO] Could not stop/disable $service" -ForegroundColor Yellow -BackgroundColor Black -NoNewline
                    $infoOccurred = $true
                }
            }
        
            if (-not $infoOccurred) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
        }

        $disableservices = @("XblAuthManager", "XblGameSave", "XblGameSave", "XboxNetApiSvc", "XboxGipSvc", "WalletService", "RemoteAccess", "WMPNetworkSvc", "NetTcpPortSharing", "AJRouter", "TrkWks", "dmwappushservice",
            "MapsBroker", "Fax", "CscService", "WpcMonSvc", "WPDBusEnum", "PcaSvc", "RemoteRegistry", "RetailDemo", "lmhosts", "WerSvc", "wisvc", "EFS", "BDESVC",
            "CertPropSvc", "SCardSvr", "fhsvc", "SensorDataService", "SensorService", "icssvc", "lfsvc", "SEMgrSvc", "WpnService", "SDRSVC", "Spooler", "Bonjour Service", "SensrSvc", "WbioSrvc", "Sens")
        
        $forgaming = @("WalletService", "RemoteAccess", "WMPNetworkSvc", "NetTcpPortSharing", "AJRouter", "TrkWks", "dmwappushservice",
            "MapsBroker", "Fax", "CscService", "WpcMonSvc", "WPDBusEnum", "PcaSvc", "RemoteRegistry", "RetailDemo", "lmhosts", "WerSvc", "wisvc", "EFS", "BDESVC",
            "CertPropSvc", "SCardSvr", "fhsvc", "SensorDataService", "SensorService", "icssvc", "lfsvc", "SEMgrSvc", "WpnService", "SDRSVC", "Spooler", "Bonjour Service", "SensrSvc", "WbioSrvc", "Sens")    

        if ($mode -eq "gaming") {
            Disable-Services -disableservices $forgaming
        }
        elseif ($mode -eq "normal" -or $mode -eq "developer") {
            Disable-Services -disableservices $disableservices
        }

        Function DisableXboxFeatures {
            Write-Host "Disabling Xbox Features..." -NoNewline
        
            try {
                $xboxregistryPaths = @{
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
        
                foreach ($path in $xboxregistryPaths.Keys) {
                    foreach ($name in $xboxregistryPaths[$path].Keys) {
                        $value = $xboxregistryPaths[$path][$name]
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
                
        if ($mode -eq "developer" -or $mode -eq "normal") { DisableXboxFeatures }

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
        
        if ($mode -eq 'normal' -or $mode -eq 'developer') {
            Telnet
        }

        Function EnableSudo {
            Write-Host "Enabling Sudo..." -NoNewline
            try {
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo" -Name "Enabled" -Type DWord -Value 1
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }
    
        if ($mode -eq 'normal' -or $mode -eq 'developer') {
            EnableSudo
        }

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

        if ($gaming -eq 'n') {
            DisableStorageSense
        }

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

        Function TaskbarSettings {
            Write-Host "Disabling Search for App in Store for Unknown Extensions..." -NoNewline
            $taskbarregPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
        
            try {
                If (!(Test-Path $taskbarregPath)) {
                    New-Item -Path $taskbarregPath | Out-Null
                }
        
                # Disable Search for App in Store for Unknown Extensions
                Set-ItemProperty -Path $taskbarregPath -Name "NoUseStoreOpenWith" -Type DWord -Value 1
        
                # Hide 'Recently added' list from the Start Menu
                Set-ItemProperty -Path $taskbarregPath -Name "HideRecentlyAddedApps" -Type DWord -Value 1
        
                # Hide 'Recommended Settings' in the Start Menu
                Set-ItemProperty -Path $taskbarregPath -Name "HideRecommendedSettings" -Type DWord -Value 1
    
                # Hide 'Recommended Apps' in the Start Menu
                Set-ItemProperty -Path $taskbarregPath -Name "HideRecommendedApps" -Type DWord -Value 1
    
                # Hide 'Recommended Personalized Sites' in the Start Menu
                Set-ItemProperty -Path $taskbarregPath -Name "HideRecommendedPersonalizedSites" -Type DWord -Value 1
    
                # Hide 'Recommended Section' in the Start Menu
                Set-ItemProperty -Path $taskbarregPath -Name "HideRecommendedSection" -Type DWord -Value 1
    
                # Add Phone link to the Start Menu
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Start\Companions\Microsoft.YourPhone_8wekyb3d8bbwe" -Force *>$null
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Start\Companions\Microsoft.YourPhone_8wekyb3d8bbwe" -Name "IsEnabled" -Type DWord -Value 1

                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        TaskbarSettings

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

        Function PasswordNeverExpires {
            Write-Host "Setting password never expires for local admins..." -NoNewline
            $localAdmins = Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.ObjectClass -eq 'User' }

            foreach ($admin in $localAdmins) {
                $username = $admin.Name.Split("\")[1]
    
                try {
                    Set-LocalUser -Name $username -PasswordNeverExpires $true
                    
                }
                catch {
                    Write-Host "[WARNING] Failed to set password never expires for $username $_" -ForegroundColor Red -BackgroundColor Black
                }
            }

            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black

        }

        PasswordNeverExpires

        Function DisableAccountNotifications {
            Write-Host "Disabling Account Notifications..." -NoNewline
            try {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_AccountNotifications" -Type DWord -Value 0
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        DisableAccountNotifications

        Function AutoEndTask {
            Write-Host "Setting AutoEndTasks..." -NoNewline
            try {
                Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value 1 -Type DWord
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }
    
        AutoEndTask

        Function LocationNotifications {
            Write-Host "Disabling Location Notifications..." -NoNewline
            try {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "ShowGlobalPrompts" -Type DWord -Value 0
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }
    
        LocationNotifications

        Function RemoveAboutThisPicture {
            Write-Host "Removing About this picture from desktop..." -NoNewline
            try {
                Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{2cc5ca98-6485-489a-920e-b3e88a6ccce3}" -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{2cc5ca98-6485-489a-920e-b3e88a6ccce3}" -Value 1 -Type DWord
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black

        }
            
        RemoveAboutThisPicture

        Function RemoveShortcutName {
            Write-Host "Removing Shortcut Name..." -NoNewline
            try {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Value ([byte[]](0, 0, 0, 0)) *> $null
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates" -Force *> $null
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates" -Name "ShortcutNameTemplate" -Value "ShortcutNameTemplate" *> $null
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }
        
        RemoveShortcutName

        ##########
        #region Taskbar Settings
        ##########

        Function DisableNews {
            Write-Host "Disabling News and Interest on Taskbar..." -NoNewline
            $hadWarning = $false
        
            try {
                # Test and create 'Windows Feeds' path if it doesn't exist
                $winfeedsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"
                if (-not (Test-Path -Path $winfeedsPath)) {
                    New-Item -Path $winfeedsPath -ErrorAction Stop | Out-Null
                }
        
                # Set 'EnableFeeds' registry value to 0
                Set-ItemProperty -Path $winfeedsPath -Name "EnableFeeds" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
        
                # Disable news and interests in the taskbar
                #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2 -ErrorAction Stop | Out-Null

                # Disable Show recommendations for tips, shortcuts, new apps
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_IrisRecommendations" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
        
                # Start Menu Layout
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_Layout" -Type DWord -Value 1 -ErrorAction Stop | Out-Null

                # Turn off "Show recently opened items in Start, Jump Lists, and File Explorer"
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Type DWord -Value 0 -ErrorAction Stop | Out-Null

                # Disable news and interests via Policies\Explorer
                $newregistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                if (-not (Test-Path $newregistryPath)) {
                    New-Item -Path $newregistryPath -Force | Out-Null
                }
                Set-ItemProperty -Path $newregistryPath -Name "NoNewsAndInterests" -Value 1 -ErrorAction Stop
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                $hadWarning = $true
            }

            if (-not $hadWarning) {
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
        }
        
        DisableNews

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

        Function TurnOffSuggestedContent {
            Write-Host "Turning off suggested content in Settings..." -NoNewline
            $suggestregPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
            $contentSettings = @(
                "SubscribedContent-338393Enabled",
                "SubscribedContent-353694Enabled",
                "SubscribedContent-353696Enabled"
            )
        
            try {
                foreach ($setting in $contentSettings) {
                    Set-ItemProperty -Path $suggestregPath -Name $setting -Type DWord -Value 0
                }
                
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        TurnOffSuggestedContent

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

        function EnableEndTaskButton {
            try {
                Write-Host "Enabling End Task Button..." -NoNewline
                $keyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
                $subKey = "TaskbarDeveloperSettings"
                $propertyName = "TaskbarEndTask"
                $propertyValue = 1
        
                if (-not (Test-Path -Path "$keyPath\$subKey")) {
                    New-Item -Path $keyPath -Name $subKey -Force *>$null
                }
        
                Set-ItemProperty -Path "$keyPath\$subKey" -Name $propertyName -Value $propertyValue -Type DWord
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        EnableEndTaskButton
        
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
                @{Path = "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows NT\Terminal Services"; Name = "fAllowToGetHelp"; Type = "Dword"; Value = "0" },
                @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy"; Name = "TailoredExperiencesWithDiagnosticDataEnabled"; Type = "Dword"; Value = "0" },
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
                    if (Test-Path $path) {
                        ##
                    }
                    else {
                        New-Item -Path $path -Force | Out-Null
                        Set-ItemProperty -Path $path -Name "Value" -Type String -Value "Deny" -ErrorAction Stop
                    }
                }
                Write-Host "[DONE]" -ForegroundColor Green
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red
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

            Function CreateTask {
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

            CreateTask

        }
        
        installwinget
        
    }

    elseif ($response -eq 'n' -or $response -eq 'N') {
        Write-Host "[Softwares written on Github will not be installed]" -ForegroundColor Red -BackgroundColor Black

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
            
                    $UninstallAppxPackages = 
                    "Microsoft.WindowsAlarms", #Alarm and clock app for Windows.
                    "Microsoft.549981C3F5F10", #Code likely represents a specific app or service, specifics unknown without context.
                    "Microsoft.WindowsFeedbackHub", #Platform for user feedback on Windows.
                    "Microsoft.Bing*", #Bing search engine related services and apps.
                    "Microsoft.Zune*", #Media software for music and videos, now discontinued.
                    "Microsoft.PowerAutomateDesktop", #Automation tool for desktop workflows.
                    "Microsoft.WindowsSoundRecorder", #Audio recording app for Windows.
                    "Microsoft.MicrosoftSolitaireCollection", #Solitaire game collection.
                    "Microsoft.GamingApp", #Likely related to Xbox or Windows gaming services.
                    "*microsoft.windowscomm**", #Likely refers to communication services in Windows, specifics unclear.
                    "MicrosoftCorporationII.QuickAssist", #Remote assistance app by Microsoft.
                    "Microsoft.Todos", #Task management app.
                    "Microsoft.SkypeApp", #Skype communication app for Windows.
                    "Microsoft.Microsoft3DViewer", #App for viewing 3D models.
                    "Microsoft.Wallet", #Digital wallet app, now discontinued.
                    "Microsoft.WebMediaExtensions", #Extensions for media formats in web browsers.
                    "MicrosoftWindows.Client.WebExperience", #Likely related to the web browsing experience in Windows, specifics unclear.
                    "Clipchamp.Clipchamp", #Video editing app.
                    "Microsoft.WindowsMaps", #Mapping and navigation app.
                    "Microsoft.Advertising.Xaml", #Advertising SDK for apps.
                    "Microsoft.MixedReality.Portal", #Mixed Reality portal app for immersive experiences.
                    "Microsoft.BingNews", #News aggregation app.
                    "Microsoft.GetHelp", #Support and troubleshooting app.
                    "Microsoft.Getstarted", #Introduction and tips app for Windows features.
                    "Microsoft.MicrosoftOfficeHub", #Central hub for Office apps and services.
                    "Microsoft.OneConnect", #Connectivity and cloud services app.
                    "Microsoft.People", #Contact management and social integration app.
                    "Microsoft.Xbox.TCUI", #Xbox text, chat, and user interface services.
                    "Microsoft.XboxApp", #Main app for Xbox social and gaming features.
                    "Microsoft.XboxGameOverlay", #In-game overlay for Xbox features and social interactions.
                    "Microsoft.XboxIdentityProvider", #Service for Xbox account authentication.
                    "Microsoft.XboxSpeechToTextOverlay" #Speech-to-text services for Xbox gaming.
        
                    $installedApps = Get-AppxPackage -AllUsers
            
                    Silent #silently
            
                    foreach ($package in $UninstallAppxPackages) {
                        $app = $installedApps | Where-Object { $_.Name -like $package }
                        if ($null -ne $app) {
                            try {
                                $app | Remove-AppxPackage -ErrorAction Stop
                            }
                            catch {
                                Write-Host "[WARNING] $($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Black
                            }
                        }
                    }
        
                    # Uninstall Microsoft Teams Outlook Add-in
                    $TeamsAddinGUID = '{A7AB73A3-CB10-4AA5-9D38-6AEFFBDE4C91}'
                    $teamsregpath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$TeamsAddinGUID"
                    if (Test-Path $teamsregpath) {
                        try {
                            Start-Process msiexec.exe -ArgumentList "/x $TeamsAddinGUID /qn /norestart" -NoNewWindow -Wait
                        }
                        catch {
                            Write-Host "[WARNING] $($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Black
                        }
                    }
                    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                }
        
                UninstallThirdPartyBloat

                # Uninstall Windows Media Player
                Function UninstallMediaPlayer {
                    Write-Host `n"Uninstalling Windows Media Player..." -NoNewline
                    try {
                        Silent #silently
                        Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "WindowsMediaPlayer" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
                        Get-WindowsCapability -Online | Where-Object { $_.Name -like "Media.WindowsMediaPlayer*" } | Remove-WindowsCapability -Online | Out-Null
                    }
                    catch {
                        Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                    }
                    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
                }

                UninstallMediaPlayer

                # Uninstall Work Folders Client - Not applicable to Server
                Function UninstallWorkFolders {
                    Write-Host "Uninstalling Work Folders Client..." -NoNewline
                    try {
                        Silent #silently
                        Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "WorkFolders-Client" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
                    }
                    catch {
                        Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                        Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                        Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                    }
                    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
                }

                RemoveFaxPrinter

                # Uninstall Windows Fax and Scan Services - Not applicable to Server
                Function UninstallFaxAndScan {
                    Write-Host "Uninstalling Windows Fax and Scan Services..." -NoNewline
                    try {
                        Silent #silently
                        Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "FaxServicesClientPackage" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
                        Get-WindowsCapability -Online | Where-Object { $_.Name -like "Print.Fax.Scan*" } | Remove-WindowsCapability -Online | Out-Null
                    }
                    catch {
                        Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                    }
                    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
                }

                UninstallFaxAndScan

                # Delete some folders from This PC
                Function UnpinExplorer {
                    Write-Host "Deleting 3D Folders, Pictures, Videos, Music from This PC..." -NoNewline
                    $basePath = "HKLM:\SOFTWARE"
                    $wow6432Node = "Wow6432Node\"
                    $explorerPath = "Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\"
                    $quickAccessPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderMSGraph\NameSpace\DelegateFolders\{3936E9E4-D92C-4EEE-A85A-BC16D5EA0819}"
                    $homePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace_36354489\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}"
                    $homePath2 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}"
                    $namespaces = @{
                        "3DFolders" = "{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
                        "Videos"    = "{A0953C92-50DC-43bf-BE83-3742FED03C9C}", "{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}"
                        "Pictures"  = "{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}", "{24ad3ad4-a569-4530-98e1-ab02f9417aa8}"
                    }
                        
                    foreach ($category in $namespaces.Keys) {
                        foreach ($id in $namespaces[$category]) {
                            $paths = @(
                                "$basePath\$explorerPath$id",
                                "$basePath\$wow6432Node$explorerPath$id"
                            )
                                
                            foreach ($path in $paths) {
                                try {
                                    Remove-Item -Path $path -Recurse -ErrorAction SilentlyContinue
                                }
                                catch {
                                    Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                                }
                            }
                        }
                    }
                    
                    # homepath additional settings
                    New-Item -Path $homePath2 -Force *>$null
                    Set-ItemProperty -Path $homePath2 -Name "(Default)" -Value "CLSID_MSGraphHomeFolder"
                    Set-ItemProperty -Path $homePath2 -Name "HiddenByDefault" -Value 1 -Type DWord
            
                    # Additional paths
                    try {
                        Remove-Item -Path $quickAccessPath -Recurse -ErrorAction SilentlyContinue
                        Remove-Item -Path $homePath -Recurse -ErrorAction SilentlyContinue
                    }
                    catch {
                        Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                    }
                        
                    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                }
                    
                UnpinExplorer

                # Block Microsoft Edge telemetry
                Function EdgePrivacySettings {
                    Write-Host "Adjusting Microsoft Edge privacy settings..." -NoNewline
            
                    $EdgePrivacyCUPath = "HKCU:\Software\Policies\Microsoft\Edge"
                    $EdgePrivacyAUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
        
                    $EdgePrivacyKeys = @(
                        "PaymentMethodQueryEnabled",
                        "PersonalizationReportingEnabled",
                        "AddressBarMicrosoftSearchInBingProviderEnabled",
                        "UserFeedbackAllowed",
                        "AutofillCreditCardEnabled",
                        "AutofillAddressEnabled",
                        "LocalProvidersEnabled",
                        "SearchSuggestEnabled",
                        "EdgeShoppingAssistantEnabled",
                        "WebWidgetAllowed",
                        "HubsSidebarEnabled"
                    )
        
                    $EdgePrivacyKeys | ForEach-Object {
                        if (-not (Test-Path $EdgePrivacyCUPath)) {
                            New-Item -Path $EdgePrivacyCUPath -Force *>$null
                        }
                        try {
                            Set-ItemProperty -Path $EdgePrivacyCUPath -Name $_ -Value 0
                            Set-ItemProperty -Path $EdgePrivacyCUPath -Name "ConfigureDoNotTrack" -Value 1
                        }
                        catch {
                            Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                        }
                    }
        
                    $EdgePrivacyAUKeys = @(
                        "DoNotTrack",
                        "QuicAllowed",
                        "SearchSuggestEnabled",
                        "AllowSearchAssistant",
                        "FormFillEnabled",
                        "PaymentMethodQueryEnabled",
                        "PersonalizationReportingEnabled",
                        "AddressBarMicrosoftSearchInBingProviderEnabled",
                        "UserFeedbackAllowed",
                        "AutofillCreditCardEnabled",
                        "AutofillAddressEnabled",
                        "LocalProvidersEnabled",
                        "SearchSuggestEnabled",
                        "EdgeShoppingAssistantEnabled",
                        "WebWidgetAllowed",
                        "HubsSidebarEnabled"
                    )
        
                    $EdgePrivacyAUKeys | ForEach-Object {
                        if (-not (Test-Path $EdgePrivacyAUPath)) {
                            New-Item -Path $EdgePrivacyAUPath -Force *>$null
                        }
                        try {
                            Set-ItemProperty -Path $EdgePrivacyAUPath -Name $_ -Value 0
                            Set-ItemProperty -Path $EdgePrivacyAUPath -Name "ConfigureDoNotTrack" -Value 1
                        }
                        catch {
                            Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                        }
                    }
        
                    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                }
        
                EdgePrivacySettings

                Function OfficePrivacySettings {
                    Write-Host "Adjusting Microsoft Office privacy settings..." -NoNewline
                    $OfficePrivacyRegistryKeys = @{
                        "HKCU:\Software\Microsoft\Office\Common\ClientTelemetry"          = @{
                            "DisableTelemetry" = 1
                        }
                        "HKCU:\Software\Policies\Microsoft\Office\Common\ClientTelemetry" = @{
                            "SendTelemetry" = 3
                        }
                        "HKCU:\Software\Policies\Microsoft\Office\16.0\Common"            = @{
                            "QMEnable" = 0;
                            "LinkedIn" = 0
                        }
                        "HKCU:\Software\Microsoft\Office\16.0\Common\MailSettings"        = @{
                            "InlineTextPrediction" = 0
                        }
                        "HKCU:\Software\Policies\Microsoft\Office\16.0\osm"               = @{
                            "Enablelogging"         = 0;
                            "EnableUpload"          = 0;
                            "EnableFileObfuscation" = 1
                        }
                        "HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Feedback"   = @{
                            "SurveyEnabled" = 0;
                            "Enabled"       = 0;
                            "IncludeEmail"  = 0
                        }
                    }
        
                    foreach ($key in $OfficePrivacyRegistryKeys.GetEnumerator()) {
                        $officeregpath = $key.Key
                        $registryValues = $key.Value
        
                        if (-not (Test-Path $officeregpath)) {
                            New-Item -Path $officeregpath -Force *>$null
                        }
        
                        foreach ($valueName in $registryValues.GetEnumerator()) {
                            $value = $valueName.Key
                            $data = $valueName.Value
        
                            try {
                                Set-ItemProperty -Path $officeregpath -Name $value -Value $data
                            }
                            catch {
                                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                            }
                        }
                    }
        
                    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                }
        
                OfficePrivacySettings  
        
                Function DisableWindowsSync {
                    Write-Host "Disabling Windows Sync..." -NoNewline
                    $WindowsSyncRegistryKeys = @{
                        "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync"                        = @{
                            "SyncPolicy" = 5
                        }
                        "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" = @{
                            "Enabled" = 0
                        }
                        "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" = @{
                            "Enabled" = 0
                        }
                        "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials"     = @{
                            "Enabled" = 0
                        }
                        "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language"        = @{
                            "Enabled" = 0
                        }
                        "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility"   = @{
                            "Enabled" = 0
                        }
                        "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows"         = @{
                            "Enabled" = 0
                        }
                    }
        
                    foreach ($key in $WindowsSyncRegistryKeys.GetEnumerator()) {
                        $syncregPath = $key.Key
                        $registryValues = $key.Value
        
                        if (-not (Test-Path $syncregPath)) {
                            New-Item -Path $syncregPath -Force *>$null
                        }
        
                        foreach ($valueName in $registryValues.GetEnumerator()) {
                            $value = $valueName.Key
                            $data = $valueName.Value
        
                            try {
                                Set-ItemProperty -Path $syncregPath -Name $value -Value $data
                            }
                            catch {
                                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                            }
                        }
                    }
        
                    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                }
        
                DisableWindowsSync        

                # The function is here because programs add themselves to the right click menu after loading
                Function RightClickMenu {
                    try {
                        Write-Host "Editing the right click menu..." -NoNewline
                        # New PS Drives
                        New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
                
                        # Old right click menu
                        $regPath = "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
                        reg.exe add $regPath /f /ve *>$null
                
                        $contextMenuPaths = @(
                            "HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo", #remove send to
                            "HKEY_CLASSES_ROOT\UserLibraryFolder\shellex\ContextMenuHandlers\SendTo", #remove send to
                            "HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\ModernSharing", #remove share
                            "HKEY_CLASSES_ROOT\*\shell\pintohomefile", #remove favorites
                            #remove give access
                            "HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\Sharing",
                            "HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers\Sharing",
                            "HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\Sharing",
                            "HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers\Sharing",
                            "HKEY_CLASSES_ROOT\LibraryFolder\background\shellex\ContextMenuHandlers\Sharing",
                            "HKEY_CLASSES_ROOT\UserLibraryFolder\shellex\ContextMenuHandlers\Sharing",
                            #remove previous
                            "HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
                            "HKEY_CLASSES_ROOT\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
                            "HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
                            "HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
                            #remove git
                            "HKEY_CLASSES_ROOT\Directory\Background\shell\git_gui",
                            "HKEY_CLASSES_ROOT\Directory\Background\shell\git_shell",
                            #remove treesize
                            "HKEY_CLASSES_ROOT\Directory\Background\shell\TreeSize Free",
                            "HKEY_CLASSES_ROOT\Directory\Background\shell\VSCode"
                        )
                
                        foreach ($path in $contextMenuPaths) {
                            $regPath = $path -replace 'HKCR:\\', 'HKEY_CLASSES_ROOT\' 
                            $cmd = "reg delete `"$regPath`" /f"
                            Invoke-Expression $cmd *>$null
                        }
                
                        # New hash menu for right click
                        $regpath = "HKEY_CLASSES_ROOT\*\shell\hash"
                        $sha256menu = "HKEY_CLASSES_ROOT\*\shell\hash\shell\02menu"
                        $md5menu = "HKEY_CLASSES_ROOT\*\shell\hash\shell\03menu"
                
                        reg add $regpath /f *>$null
                        reg add $regpath /v "MUIVerb" /t REG_SZ /d HASH /f *>$null
                        reg add $regpath /v "SubCommands" /t REG_SZ /d """" /f *>$null
                        reg add "$regpath\shell" /f *>$null
                
                        reg add "$sha256menu" /f *>$null
                        reg add "$sha256menu\command" /f *>$null
                        reg add "$sha256menu" /v "MUIVerb" /t REG_SZ /d SHA256 /f *>$null
                
                        $tempOut = [System.IO.Path]::GetTempFileName()
                        $tempErr = [System.IO.Path]::GetTempFileName()
                        Start-Process cmd.exe -ArgumentList '/c', 'reg add "HKEY_CLASSES_ROOT\*\shell\hash\shell\02menu\command" /ve /d "powershell -noexit get-filehash -literalpath \"%1\" -algorithm SHA256 | format-list" /f' -NoNewWindow -RedirectStandardOutput $tempOut -RedirectStandardError $tempErr
                        Remove-Item $tempOut -ErrorAction Ignore
                        Remove-Item $tempErr -ErrorAction Ignore
                
                        reg add "$md5menu" /f *>$null
                        reg add "$md5menu\command" /f *>$null
                        reg add "$md5menu" /v "MUIVerb" /t REG_SZ /d MD5 /f *>$null
                
                        $tempOut = [System.IO.Path]::GetTempFileName()
                        $tempErr = [System.IO.Path]::GetTempFileName()
                        Start-Process cmd.exe -ArgumentList '/c', 'reg add "HKEY_CLASSES_ROOT\*\shell\hash\shell\03menu\command" /ve /d "powershell -noexit get-filehash -literalpath \"%1\" -algorithm MD5 | format-list" /f' -NoNewWindow -RedirectStandardOutput $tempOut -RedirectStandardError $tempErr
                        Remove-Item $tempOut -ErrorAction Ignore
                        Remove-Item $tempErr -ErrorAction Ignore
                
                        # Add Turn Off Display Menu
                        $turnOffDisplay = "HKEY_CLASSES_ROOT\DesktopBackground\Shell\TurnOffDisplay"
                        reg add $turnOffDisplay /f *>$null
                        reg add $turnOffDisplay /v "Icon" /t REG_SZ /d "imageres.dll,-109" /f *>$null
                        reg add $turnOffDisplay /v "MUIVerb" /t REG_SZ /d "Turn off display" /f *>$null
                        reg add $turnOffDisplay /v "Position" /t REG_SZ /d "Bottom" /f *>$null
                        reg add $turnOffDisplay /v "SubCommands" /t REG_SZ /d """" /f *>$null
                
                        reg add "$turnOffDisplay\shell" /f *>$null
                        $turnOffMenu1 = "$turnOffDisplay\shell\01menu"
                        reg add $turnOffMenu1 /f *>$null
                        reg add $turnOffMenu1 /v "Icon" /t REG_SZ /d "powercpl.dll,-513" /f *>$null
                        reg add $turnOffMenu1 /v "MUIVerb" /t REG_SZ /d "Turn off display" /f *>$null
                        reg add "$turnOffMenu1\command" /f *>$null
                        reg add "$turnOffMenu1\command" /ve /d 'cmd /c "powershell.exe -Command \"(Add-Type ''[DllImport(\\\"user32.dll\\\")]public static extern int SendMessage(int hWnd,int hMsg,int wParam,int lParam);'' -Name a -Pas)::SendMessage(-1,0x0112,0xF170,2)\""' /f *>$null
                
                        $turnOffMenu2 = "$turnOffDisplay\shell\02menu"
                        reg add $turnOffMenu2 /f *>$null
                        reg add $turnOffMenu2 /v "MUIVerb" /t REG_SZ /d "Lock computer and Turn off display" /f *>$null
                        reg add $turnOffMenu2 /v "CommandFlags" /t REG_DWORD /d 0x20 /f *>$null
                        reg add $turnOffMenu2 /v "Icon" /t REG_SZ /d "imageres.dll,-59" /f *>$null
                        reg add "$turnOffMenu2\command" /f *>$null
                        reg add "$turnOffMenu2\command" /ve /d 'cmd /c "powershell.exe -Command \"(Add-Type ''[DllImport(\\\"user32.dll\\\")]public static extern int SendMessage(int hWnd,int hMsg,int wParam,int lParam);'' -Name a -Pas)::SendMessage(-1,0x0112,0xF170,2)\" & rundll32.exe user32.dll, LockWorkStation"' /f *>$null

                        # Add "Find Empty Folders"
                        $command = 'powershell.exe -NoExit -Command "Get-ChildItem -Path ''%V'' -Directory -Recurse | Where-Object { $_.GetFileSystemInfos().Count -eq 0 } | ForEach-Object { $_.FullName }"'

                        $rightclickregpath = @(
                            "Registry::HKEY_CLASSES_ROOT\Directory\shell\FindEmptyFolders",
                            "Registry::HKEY_CLASSES_ROOT\Directory\shell\FindEmptyFolders\command",
                            "Registry::HKEY_CLASSES_ROOT\Directory\Background\shell\FindEmptyFolders",
                            "Registry::HKEY_CLASSES_ROOT\Directory\Background\shell\FindEmptyFolders\command",
                            "Registry::HKEY_CLASSES_ROOT\Drive\shell\FindEmptyFolders",
                            "Registry::HKEY_CLASSES_ROOT\Drive\shell\FindEmptyFolders\command"
                        )

                        $icon = "imageres.dll,-1025"
                        $defaultValue = "Find Empty Folders"

                        $rightclickregpath | ForEach-Object {
                            New-Item -Path $_ -Force | Out-Null
                            Set-ItemProperty -Path $_ -Name "(Default)" -Value $defaultValue
                            Set-ItemProperty -Path $_ -Name "Icon" -Value $icon
                        }

                        # Add to "Boot to UEFI Firmware Settings"
                        New-Item -Path "HKCR:\DesktopBackground\Shell\Firmware" -Force | Out-Null
                        Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\Firmware" -Name "Icon" -Value "bootux.dll,-1016"
                        Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\Firmware" -Name "MUIVerb" -Value "Boot to UEFI Firmware Settings"
                        Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\Firmware" -Name "Position" -Value "Top"
                    
                        New-Item -Path "HKCR:\DesktopBackground\Shell\Firmware\command" -Force | Out-Null
                        Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\Firmware\command" -Name "(default)" -Value "powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/s,/c,shutdown /r /fw' -Verb runAs\""

                        # Add blocked keys
                        $blockedkeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"
                        if (-not (Test-Path -Path $blockedkeyPath)) {
                            New-Item -Path $blockedkeyPath -Force | Out-Null
                        }
                        else {
                            ##
                        }

                        # Remove "Edit in Notepad"
                        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{CA6CC9F1-867A-481E-951E-A28C5E4F01EA}" -Value "Edit in Notepad"

                        # Remove "Cast to Device"
                        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" -Value "Play to Menu"
                            
                        # Restart Windows Explorer
                        taskkill /f /im explorer.exe *>$null
                        Start-Sleep 1
                        Start-Process "explorer.exe" -ErrorAction Stop
                
                        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                    }
                
                    catch {
                        Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                    }
                }
                
                RightClickMenu

                Function DisableWidgets {
                    Write-Host "Disabling Windows Widgets..." -NoNewline
                    try {
                        Get-AppxPackage -AllUsers -Name *WebExperience* | Remove-AppxPackage -AllUsers *>$null
                        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                    } 
                    catch {
                        Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                    }
            
                }

                DisableWidgets

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
                    Write-Host "apps and Windows update tasks to be deleted?" -ForegroundColor Yellow -NoNewline
                    Write-Host "(y/n): " -ForegroundColor Green -NoNewline
            
                    $response = Read-Host
        
                    if ($response -eq 'y' -or $response -eq 'Y') {
                        Write-Host "Removing Unnecessary Tasks..." -NoNewline
                        $taskPatterns = @("OneDrive*", "MicrosoftEdge*", "Google*", "Brave*", "Intel*", "klcp*", "MSI*", 
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
                                    Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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

                # Disable Copilot
                Function DisableCopilot {
                    Write-Host `n"Do you want " -NoNewline
                    Write-Host "to disable Microsoft Copilot?" -ForegroundColor Yellow -NoNewline
                    Write-Host "(y/n): " -ForegroundColor Green -NoNewline
                    $response = Read-Host
        
                    if ($response -eq 'y' -or $response -eq 'Y') {
                        Write-Host "Disabling Microsoft Copilot..." -NoNewline
                
                        $copilotregPath = "HKCU:\Software\Policies\Microsoft\Windows"
                        $registryName = "WindowsCopilot"
                        $registryProperty = "TurnOffWindowsCopilot"
                        $edgeRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
                        $explorerRegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
                
                        if (-not (Test-Path $copilotregPath)) {
                            New-Item -Path $copilotregPath -Name $registryName -Force *>$null
                        }
                
                        New-ItemProperty -Path $copilotregPath\$registryName -Name $registryProperty -Value 1 -PropertyType DWORD -Force *>$null
                
                        if (-not (Test-Path $edgeRegistryPath)) {
                            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\" -Name "Edge" -Force *>$null
                        }
                
                        New-ItemProperty -Path $edgeRegistryPath -Name "HubsSidebarEnabled" -Value 0 -PropertyType DWORD -Force *>$null
        
                        # Remove Copilot button from File Explorer
                        Set-ItemProperty -Path $explorerRegistryPath -Name "ShowCopilotButton" -Value 0 -Force *>$null
                
                        $lmRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows"
                        $wowRegistryPath = "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows"
                
                        if (-not (Test-Path $lmRegistryPath\$registryName)) {
                            New-Item -Path $lmRegistryPath -Name $registryName -Force *>$null
                        }
                
                        Set-ItemProperty -Path $lmRegistryPath\$registryName -Name $registryProperty -Value 1 -Force *>$null
        
                        if (-not (Test-Path $wowRegistryPath\$registryName)) {
                            New-Item -Path $wowRegistryPath -Name $registryName -Force *>$null
                        }
                
                        Set-ItemProperty -Path $wowRegistryPath\$registryName -Name $registryProperty -Value 1 -Force *>$null

                        $currentSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                        New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
                        If (-not (Test-Path "HKU:\$currentSID\Software\Policies\Microsoft\Windows\WindowsCopilot")) {
                            New-Item -Path "HKU:\$currentSID\Software\Policies\Microsoft\Windows" -Name "WindowsCopilot" -Force *>$null
                        }
                        Set-ItemProperty -Path "HKU:\$currentSID\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1

                        Get-AppxPackage *CoPilot* -AllUsers | Remove-AppPackage -AllUsers
                        Get-AppxProvisionedPackage -Online | where-object { $_.PackageName -like "*Copilot*" } | Remove-AppxProvisionedPackage -online
        
                        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                    }
                    elseif ($response -eq 'n' -or $response -eq 'N') {
                        Write-Host "[Copilot will not be disabled]" -ForegroundColor Red -BackgroundColor Black
                    }
                    else {
                        Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
                        DisableCopilot
                    }
                }
        
                DisableCopilot

                # Uninstall OneDrive
                Function UninstallOneDrive {
                    Write-Host `n"Do you want " -NoNewline
                    Write-Host "uninstall Microsoft OneDrive?" -ForegroundColor Yellow -NoNewline
                    Write-Host "(y/n): " -ForegroundColor Green -NoNewline
                    $response = Read-Host
                    if ($response -eq 'y' -or $response -eq 'Y') {
                        Write-Host "Removing Microsoft OneDrive..." -NoNewline
                        Silent #silently
                        try {
                            # Stop OneDrive and Explorer processes
                            taskkill /f /im OneDrive.exe *>$null

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

                            New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
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

                            If (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive") {
                                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
                            }

                            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Force -ErrorAction SilentlyContinue

                            # Remove OneDrive from the registry
                            reg load "HKU\Default" "C:\Users\Default\NTUSER.DAT" *>$null
                            reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f *>$null
                            reg unload "HKU\Default" *>$null
                    
                            Remove-Item -Path "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force -ErrorAction SilentlyContinue

                            Start-Sleep 3
                            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black

                        }
                        catch {
                            Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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
                    Write-Host "(y/n): " -ForegroundColor Green -NoNewline
                    $response = Read-Host
                    if ($response -eq 'y' -or $response -eq 'Y') {
                        Write-Host "Removing Microsoft Edge..." -NoNewline
       
                        try {
                            $ProgressPreference = 'SilentlyContinue'
                            $sys32 = [Environment]::GetFolderPath('System')
                            $windir = [Environment]::GetFolderPath('Windows')
                            $env:path = "$windir;$sys32;$sys32\Wbem;$sys32\WindowsPowerShell\v1.0;" + $env:path
                            $baseKey = 'HKLM:\SOFTWARE' + $(if ([Environment]::Is64BitOperatingSystem) { '\WOW6432Node' }) + '\Microsoft'
                            $msedgeExe = "$([Environment]::GetFolderPath('ProgramFilesx86'))\Microsoft\Edge\Application\msedge.exe"
                            $edgeUWP = "$windir\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe"

                            function DeleteIfExist($Path) {
                                if (Test-Path $Path) {
                                    Remove-Item -Path $Path -Force -Recurse -Confirm:$false 2>$null
                                }
                            }

                            function Get-MsiexecAppByName {
                                param(
                                    [Parameter(Mandatory = $true)]
                                    [ValidateNotNullOrEmpty()]
                                    [string]$Name
                                )

                                $uninstallKeyPath = 'Microsoft\Windows\CurrentVersion\Uninstall'
                                $uninstallKeys = (Get-ChildItem -Path @(
                                        "HKLM:\SOFTWARE\$uninstallKeyPath",
                                        "HKLM:\SOFTWARE\WOW6432Node\$uninstallKeyPath",
                                        "HKCU:\SOFTWARE\$uninstallKeyPath",
                                        "HKCU:\SOFTWARE\WOW6432Node\$uninstallKeyPath"
                                    ) -EA SilentlyContinue) -match '\{\b[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}\b\}'

                                $edges = @()
                                foreach ($key in $uninstallKeys.PSPath) {
                                    if (((Get-ItemProperty -Path $key -EA 0).DisplayName -like "*$Name*") -and ((Get-ItemProperty -Path $key -EA 0).UninstallString -like '*MsiExec.exe*')) {
                                        $edges += Split-Path -Path $key -Leaf
                                    }
                                }

                                return $edges
                            }

                            function EdgeInstalled {
                                Test-Path $msedgeExe
                            }

                            function KillEdgeProcesses {
                                $ErrorActionPreference = 'SilentlyContinue'
                                foreach ($service in (Get-Service -Name '*edge*' | Where-Object { $_.DisplayName -like '*Microsoft Edge*' }).Name) {
                                    Stop-Service -Name $service -Force 2>$null
                                }
                                foreach (
                                    $process in
                                    (Get-Process | Where-Object { ($_.Path -like "$([Environment]::GetFolderPath('ProgramFilesX86'))\Microsoft\*") -or ($_.Name -like '*msedge*') }).Id
                                ) {
                                    Stop-Process -Id $process -Force 2>$null
                                }
                                $ErrorActionPreference = 'Continue'	
                            }

                            function RemoveEdgeChromium {
                                $msis = Get-MsiexecAppByName -Name 'Microsoft Edge'

                                function UninstallStringFail {
                                    $script:edgeUninstallers = @()
                                    'LocalApplicationData', 'ProgramFilesX86', 'ProgramFiles' | ForEach-Object {
                                        $folder = [Environment]::GetFolderPath($_)
                                        $script:edgeUninstallers += Get-ChildItem "$folder\Microsoft\Edge*\setup.exe" -Recurse -EA 0 |
                                        Where-Object { ($_ -like '*Edge\Application*') -or ($_ -like '*SxS\Application*') }
                                    }
                                }

                                $uninstallKeyPath = "$baseKey\Windows\CurrentVersion\Uninstall\Microsoft Edge"
                                $uninstallString = (Get-ItemProperty -Path $uninstallKeyPath -EA 0).UninstallString
                                if ([string]::IsNullOrEmpty($uninstallString) -and ($msis.Count -le 0)) {
                                    $uninstallString = $null
                                    UninstallStringFail
                                }
                                else {
                                    $uninstallPath, $uninstallArgs = $uninstallString -split '"', 3 |
                                    Where-Object { $_ } |
                                    ForEach-Object { [System.Environment]::ExpandEnvironmentVariables($_.Trim()) }

                                    if (![System.IO.Path]::IsPathRooted($uninstallPath) -or !(Test-Path $uninstallPath -PathType Leaf)) {
                                        $uninstallPath = $null
                                        UninstallStringFail
                                    }
                                }

                                if (($msis.Count -le 0) -and ($script:edgeUninstallers.Count -le 0) -and !$uninstallPath) {
                                    exit 2
                                }

                                function ToggleEURegion([bool]$Enable) {
                                    $geoKey = 'Registry::HKEY_USERS\.DEFAULT\Control Panel\International\Geo'

                                    $values = @{
                                        'Name'   = 'FR'
                                        'Nation' = '84'
                                    }
                                    $geoChange = 'EdgeSaved'

                                    if ($Enable) {
                                        $values.GetEnumerator() | ForEach-Object {
                                            Rename-ItemProperty -Path $geoKey -Name $_.Key -NewName "$($_.Key)$geoChange" -Force -EA 0
                                            Set-ItemProperty -Path $geoKey -Name $_.Key -Value $_.Value -Force
                                        }
                                    }
                                    else {
                                        $values.GetEnumerator() | ForEach-Object {
                                            Remove-ItemProperty -Path $geoKey -Name $_.Key -Force -EA 0
                                            Rename-ItemProperty -Path $geoKey -Name "$($_.Key)$geoChange" -NewName $_.Key -Force -EA 0
                                        }
                                    }
                                }

                                function ModifyRegionJSON {
                                    $cleanup = $false
                                    $script:integratedServicesPath = "$sys32\IntegratedServicesRegionPolicySet.json"

                                    if (Test-Path $integratedServicesPath) {
                                        $cleanup = $true
                                        try {
                                            $admin = [System.Security.Principal.NTAccount]$(New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount]).Value

                                            $acl = Get-Acl -Path $integratedServicesPath
                                            $script:backup = [System.Security.AccessControl.FileSecurity]::new()
                                            $script:backup.SetSecurityDescriptorSddlForm($acl.Sddl)
                                            $acl.SetOwner($admin)
                                            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($admin, 'FullControl', 'Allow')
                                            $acl.AddAccessRule($rule)
                                            Set-Acl -Path $integratedServicesPath -AclObject $acl

                                            $integratedServices = Get-Content $integratedServicesPath | ConvertFrom-Json
                                            ($integratedServices.policies | Where-Object { ($_.'$comment' -like '*Edge*') -and ($_.'$comment' -like '*uninstall*') }).defaultState = 'enabled'
                                            $modifiedJson = $integratedServices | ConvertTo-Json -Depth 100

                                            $script:backupIntegratedServicesName = "IntegratedServicesRegionPolicySet.json.$([System.IO.Path]::GetRandomFileName())"
                                            Rename-Item $integratedServicesPath -NewName $script:backupIntegratedServicesName -Force
                                            Set-Content $integratedServicesPath -Value $modifiedJson -Force -Encoding UTF8
                                        }
                                        catch {}
                                    }

                                    return $cleanup
                                }

                                function UninstallEdge {
                                    foreach ($msi in $msis) {
                                        Start-Process -FilePath 'msiexec.exe' -ArgumentList "/qn /X$(Split-Path -Path $msi -Leaf) REBOOT=ReallySuppress /norestart" -Wait -WindowStyle Hidden
                                    }

                                    if ($uninstallPath) {
                                        Start-Process -Wait -FilePath $uninstallPath -ArgumentList "$uninstallArgs --force-uninstall" -WindowStyle Hidden
                                    }
                                    else {
                                        foreach ($setup in $edgeUninstallers) {
                                            if (Test-Path $setup) {
                                                $sulevel = ('--system-level', '--user-level')[$setup -like '*\AppData\Local\*']
                                                Start-Process -Wait $setup -ArgumentList "--uninstall --msedge $sulevel --channel=stable --verbose-logging --force-uninstall" -WindowStyle Hidden
                                            }
                                        }
                                    }

                                    return EdgeInstalled
                                }

                                function GlobalRemoveMethods {
                                    Remove-ItemProperty -Path "$baseKey\EdgeUpdate\ClientState\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" -Name 'experiment_control_labels' -Force -EA 0

                                    $devKeyPath = "$baseKey\EdgeUpdateDev"
                                    if (!(Test-Path $devKeyPath)) { New-Item -Path $devKeyPath -ItemType 'Key' -Force | Out-Null }
                                    Set-ItemProperty -Path $devKeyPath -Name 'AllowUninstall' -Value '' -Type String -Force
	
                                    KillEdgeProcesses
                                }

                                $fail = $true
                                $method = 1
                                while ($fail) {
                                    switch ($method) {
                                        1 {
                                            GlobalRemoveMethods
                                            if (!(Test-Path "$edgeUWP\MicrosoftEdge.exe")) {
                                                New-Item $edgeUWP -ItemType Directory -ErrorVariable cleanup -EA 0 | Out-Null
                                                New-Item "$edgeUWP\MicrosoftEdge.exe" -EA 0 | Out-Null
                                                $cleanup = $true
                                            }

                                            $fail = UninstallEdge

                                            if ($cleanup) {
                                                Remove-Item $edgeUWP -Force -EA 0 -Recurse
                                            }
                                        }

                                        2 {
                                            GlobalRemoveMethods
                                            $envPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
                                            try {
                                                Set-ItemProperty -Path $envPath -Name 'windir' -Value '' -Type ExpandString
                                                $env:windir = [System.Environment]::GetEnvironmentVariable('windir', [System.EnvironmentVariableTarget]::Machine)

                                                $fail = UninstallEdge
                                            }
                                            finally {
                                                Set-ItemProperty -Path $envPath -Name 'windir' -Value '%SystemRoot%' -Type ExpandString
                                            }
                                        }

                                        3 {
                                            GlobalRemoveMethods
                                            ToggleEURegion $true

                                            $fail = UninstallEdge

                                            ToggleEURegion $false
                                        }

                                        4 {
                                            GlobalRemoveMethods
                                            $cleanup = ModifyRegionJSON
				
                                            $fail = UninstallEdge

                                            if ($cleanup) {
                                                Remove-Item $integratedServicesPath -Force -EA 0
                                                Rename-Item "$sys32\$backupIntegratedServicesName" -NewName $integratedServicesPath -Force -EA 0
                                                Set-Acl -Path $integratedServicesPath -AclObject $backup -EA 0
                                            }
                                        }

                                        default {
                                            exit 3
                                        }
                                    }

                                    $method++
                                }

                                "$([Environment]::GetFolderPath('Desktop'))\Microsoft Edge.lnk",
                                "$([Environment]::GetFolderPath('CommonStartMenu'))\Microsoft Edge.lnk" | ForEach-Object { DeleteIfExist $_ }

                                if ((Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowCopilotButton' -EA 0).'ShowCopilotButton' -eq 1) {
                                    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
                                }
                            }

                            function RemoveEdgeAppX {
                                $SID = (New-Object System.Security.Principal.NTAccount([Environment]::UserName)).Translate([Security.Principal.SecurityIdentifier]).Value

                                $appxStore = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
                                $pattern = "HKLM:$appxStore\InboxApplications\Microsoft.MicrosoftEdge_*_neutral__8wekyb3d8bbwe"
                                $edgeAppXKey = (Get-Item -Path $pattern -EA 0).PSChildName
                                if (Test-Path "$pattern") { reg delete "HKLM$appxStore\InboxApplications\$edgeAppXKey" /f 2>$null | Out-Null }

                                New-Item -Path "HKLM:$appxStore\EndOfLife\$SID\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" -Force -EA 0 | Out-Null
                                Get-AppxPackage -Name Microsoft.MicrosoftEdge -EA 0 | Remove-AppxPackage -EA 0 | Out-Null
                                Remove-Item -Path "HKLM:$appxStore\EndOfLife\$SID\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" -Force -EA 0 | Out-Null
                            }

                            if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18') {
                                exit 1
                            }

                            if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
                                Start-Process cmd "/c PowerShell -NoP -EP Bypass -File `"$PSCommandPath`"" -Verb RunAs -WindowStyle Hidden
                                exit
                            }

                            RemoveEdgeChromium

                            if ($null -ne (Get-AppxPackage -Name Microsoft.MicrosoftEdge -EA 0)) {
                                RemoveEdgeAppX
                            }

                            # Remove Edge tasks
                            $tasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "*edge*" }

                            # Block Updates
                            if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18') {
                                Write-Status "This script can't be ran as TrustedInstaller/SYSTEM.
Please relaunch this script under a regular admin account." -Level Critical -Exit
                            }
                            else {
                                if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
                                    if ($PSBoundParameters.Count -le 0 -and !$args) {
                                        Start-Process cmd "/c PowerShell -NoP -EP Bypass -File `"$PSCommandPath`"" -Verb RunAs
                                        exit
                                    }
                                    else {
                                        throw "This script must be run as an administrator."
                                    }
                                }
                            }

                            'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate', 'HKCU:\SOFTWARE\Policies\Microsoft\EdgeUpdate' | % {
                                Remove-Item -Path $_ -Recurse -Force -EA 0
                                New-Item -Path $_ -Force | Out-Null
                            }

                            $EdgeUpdateDisabled = "$EdgeRemoverReg\EdgeUpdateDisabled"
                            $EdgeUpdateOrchestrator = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\EdgeUpdate'
                            if (!(Test-Path $EdgeUpdateOrchestrator) -and (Test-Path $EdgeUpdateDisabled)) {
                                Move-Item -Path $EdgeUpdateDisabled -Destination $EdgeUpdateOrchestrator -Force
                            }

                            # Delete tasks
                            foreach ($task in $tasks) {
                                Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false
                            }

                        }
                        catch {
                            Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
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

                Function Removelnks {
                    Write-Host `n"Removing Desktop shortcuts..." -NoNewline
                    try {
                        Get-ChildItem C:\users\Public\Desktop\*.lnk | ForEach-Object { Remove-Item $_ -ErrorAction SilentlyContinue } *>$null
                        Get-ChildItem $env:USERPROFILE\Desktop\*.lnk | ForEach-Object { Remove-Item $_ -ErrorAction SilentlyContinue } *>$null
                        Get-ChildItem -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                    }
                    catch {
                        Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                    }
                }

                Removelnks

                Function RemoveRecall {
                    Write-Host `n"Removing Windows 11 Recall..." -NoNewline
                    try {
                        Silent
                        DISM /Online /Disable-Feature /FeatureName:"Recall"​ *>$null
                        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
                    }
                    catch {
                        Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                    }
                }

                RemoveRecall
                
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