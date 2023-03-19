![Alt Text](https://github.com/caglaryalcin/caglaryalcin/blob/main/flx.gif)

## Description

> **_NOTE 1:_** Before running the script, you only need to turn off the real-time protection setting of Windows defender once.
Windows Security Settings / Virus and threat protection / Manage settings / Real-time protection. 

![alt text](https://github.com/caglaryalcin/caglaryalcin/blob/main/win-def.jpg)

> **_NOTE 2:_** All the script is all set to path 'C:\', so file 'after-format-main' must be inside 'C:\'.  

![alt text](https://github.com/caglaryalcin/caglaryalcin/blob/main/C.jpg)

> **_NOTE 3:_** This script takes about 35 minutes with 100mbps internet.

If you new formatted your computer on Windows 10 Pro, Windows 11, you can run this script.

```
curl -o $env:userprofile\Desktop\after-format.zip https://github.com/caglaryalcin/after-format/archive/refs/heads/main.zip; Expand-Archive -Path $env:userprofile\Desktop\after-format.zip -DestinationPath C:\ -Force *>$null; Remove-Item $env:userprofile\Desktop\after-format.zip -recurse -ErrorAction SilentlyContinue ; cd C:\after-format-main\ ; .\Run.cmd
```
After running the above code with powershell, the 'after-format-main' file will be created in C:. Then double click(don't right click and 'run as administrator') on 'Run.cmd' confirm User Account Control prompt. Make sure your account is a member of Administrators group as the script attempts to run with elevated privileges.

This script does exactly the following; (Some are optional(y/n))

<details><summary>System Settings</summary>&nbsp;
  
- Date format is set to turkey
- Getting the Old Classic Right-Click Context Menu (For Windows 11)
- Disabling News and Interes on Taskbar
- Default Old Photo Viewer
- Setting Dark Mode for Applications
- Setting Dark Mode for System
- Setting Control Panel View to Large Icons
- Enabling NumLock After Startup
- Hostname is set to 'm4a1'
- Disabling Windows Beep Sound
- Disabling IPv6 stack
- Disabling Startup Apps
- Setting Cloud Flare DNS
- Hiding People Icon from Taskbar
- Hiding Taskview Icon from Taskbar
- Hiding MultiTaskview Icon from Taskbar
- Showing Small Icons in Taskbar
- Hiding Taskbar Search
- Removing Chat from Taskbar
- Removing Widgets from Taskbar
- Taskbar Aligns Left (For Windows 11)
- Hiding Recycle Bin Shortcut from Desktop
- Disabling hiberfil.sys
- Disabling Display and Sleep Mode Timeouts
- Disabling Windows Defender
- Disabling Updates for Other Microsoft Products
- Disabling Cortana
- Disabling Bing Search in Start Menu
- Disabling SmartScreen Filter
- Disabling Sensors
- Disabling Tailored Experiences
- Disabling Xbox Gamebar
- Disabling Xbox Features
- Disabling Blocking of Downloaded Files
- Setting 'This PC' for File Explorer
- Expanding for File Explorer
- Disabling Nightly Wake-up for Automatic Maintenance
- Disabling Storage Sense
- Unpinning all Start Menu tiles
- Disabling Built-in Adobe Flash in IE and Edge
- Disabling Edge Preload
- Disabling Internet Explorer First Run Wizard
- Disabling Windows Media Player Online Access
- Showing Known File Extensions
- Disabling Action Center (Notification Center)
- Disabling System Restore for System Drive
- Setting Low UAC Level
- Removing Unnecessary Tasks
- Enabling Clearing of Recent Files on Exit
- Disabling Recent Files Lists
- Disabling Search for App in Store for Unknown Extensions
- Hiding 'Recently added' List from the Start Menu
- Stopping and Disabling Unnecessary Services
- Setting Desktop Wallpaper
- Show All Icons on Taskbar
- Copy Files to Documents
- Importing Startup task in Task Scheduler
</details>
<details><summary>Privacy Settings</summary>&nbsp;
  
- Disabling Telemetry
- Blocking Telemetry in Host File
- Disabling Feedback
- Disabling Activity History
- Disabling Website Access to Language List
- Stopping and Disabling Connected User Experiences and Telemetry Service
- Disabling Advertising ID
- Disabling Wi-Fi Sense
- Disabling Application Suggestions
- Disabling UWP Apps Background Access
- Disabling Access to Voice Activation from UWP Apps
- Disabling Access to Notifications from UWP Apps
- Disabling Access to account Info from UWP Apps
- Disabling Access to Contacts from UWP Apps
- Disabling Access to Calendar from UWP Apps
- Disabling Access to Phone Calls from UWP Apps
- Disabling Access to Call History from UWP Apps
- Disabling Access to Email from UWP Apps
- Disabling Access to Tasks from UWP Apps
- Disabling Access to Messaging from UWP Apps
- Disabling Access to Radios from UWP Apps
- Disabling Access to Other Devices from UWP Apps
- Disabling Access to Diagnostic Information from UWP Apps
- Disabling Access to Libraries and File System from UWP Apps
- Disabling UWP Apps Swap File
- Disabling Automatic Maps Updates
- Disabling Windows Update Automatic Restart
- Disabling Windows Update Automatic Downloads
</details>
<details><summary>Install Softwares</summary>&nbsp;

- Installing  Winget for Windows 10, Mozilla Firefox, Opera, Google Chrome, Libre Wolf, Brave Browser, Steam, Epic Games, HWMonitor, Crystal Disk Info, VMWare Workstation Pro, VirtualBox, Signal Desktop, Microsoft Visual Studio Code (with extensions), Softwares for developers(MSVS Community, MSVS Buildtools, WindowsSDK, NodeJS, Python and Git), Chocolatey, AnyDesk, Windows Terminal, Speedtest, Notepad++, VLC Media Player, TreeSize Free, Total Commander, Rufus, Wireshark, PuTTY, Deluge, DBeaver, HEIC Converter, Cryptomator, Docker Desktop, WSL, Minikube, MS Teams, iTunes, 7-Zip (with terminal), Lightshot, Twinkle-Tray, K-Lite Codec Pack Mega, Nvidia GeForce Experience and Valorant.
- [Installing startup script](https://github.com/caglaryalcin/after-format/blob/main/README.md#startup-script).

</details>

<details><summary>Remove Unused Apps/Softwares</summary>&nbsp;
  
- Uninstalling Default Third Party Applications
- Uninstalling Windows Media Player
- Uninstalling Work Folders Client
- Uninstalling Microsoft XPS Document Writer
- Removing Default Fax Printer
- Uninstalling OneDrive
- Removing Microsoft Edge
- Uninstalling Windows Fax and Scan Services
</details>

<details><summary>Taskbar Pins</summary>&nbsp;

  The taskbar pins that I use are set respectively.
</details>
<details><summary>My Custom Drivers</summary>&nbsp;
  
- ![#f03c15](https://via.placeholder.com/15/f03c15/f03c15.png) `When this question is asked, answer by saying 'n'. Because the settings here are specifically my specific settings.`
</details>
<p>

### Startup Script
  
There is another script called startup in the script. This script does exactly the following;

- Remove En-US Keyboard
- Adding Turkey Keyboard
- Importing Previously Set Task to Task Scheduler
- Removing Stick Keys
- Removing Toggle Keys
- Remove Unnecessary Tasks(update and such) in Task Scheduler.(It also adds task to delete Unnecessary Tasks on every boot)
- Sync Windows Localtime
- Update apps (browsers, apps, softwares and such..) with WinGet&nbsp;
  
> **_NOTE 1:_** You can put '#' at the beginning of the functions you want to add or remove in the functions.preset file in 'C:\after-format-main\files\startup' folder.
  
  If you don't want to use startup updates, you can as below edit 'run.vbs' file in 'C:\after-format-main\files\startup' folder.
```vbs
Set WshShell = CreateObject("WScript.Shell") 
WshShell.Run chr(34) & "C:\startup\Run.cmd" & Chr(34), 0
Set WshShell = Nothing
```
</details>
