## Description

If you are already using a system, you can run this script.

After downloading the [zip](https://github.com/caglaryalcin/after-format/archive/refs/heads/main.zip) file, move the 'after-format-main' file inside the zip to 'C:\'. Then double click(don't right click and 'run as administrator') on 'Run.cmd' confirm User Account Control prompt. Make sure your account is a member of Administrators group as the script attempts to run with elevated privileges.

This script does exactly the following;

<details><summary>System Settings</summary>&nbsp;
  
- Date format is set to turkey
- Getting the Old Classic Right-Click Context Menu
- Disabling News and Interes on Taskbar
- Default Old Photo Viewer
- Setting Dark Mode for Applications
- Setting Dark Mode for System
- Setting Control Panel View to Large Icons
- Enabling NumLock After Startup
- Disabling IPv6 stack
- Disabling Virtual Ethernet Adapters
- Disabling Startup Apps
- Setting Cloud Flare DNS
- Hiding People Icon from Taskbar
- Hiding Taskview Icon from Taskbar
- Hiding MultiTaskview Icon from Taskbar
- Showing Small Icons in Taskbar
- Removing Chat from Taskbar
- Removing Widgets from Taskbar
- Taskbar Aligns Left
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
- Fixing System Files
- Removing Unnecessary Tasks
- Disk Cleaning
- Disabling Scheduled Defragmentation
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
<details><summary>Remove Unused Apps/Softwares</summary>&nbsp;
  
- Uninstalling Default Third Party Applications
- Uninstalling Windows Media Player
- Uninstalling Work Folders Client
- Uninstalling Microsoft XPS Document Writer
- Removing Default Fax Printer
- Disabling & Uninstalling OneDrive
- Removing Microsoft Edge
- Uninstalling Windows Fax and Scan Services
</details>
<details><summary>Install Softwares</summary>&nbsp;

- [Installing WinGet for Windows 10](https://github.com/caglaryalcin/after-format/blob/main/README.md#startup-script)
- Installing Latest Version Brave Browser
</details>
  
> **_NOTE 1:_** Before executing the script, add # at the beginning of the line you don't want from file 'Functions.Preset'.

> **_NOTE 2:_** All the script is all set to path 'C:\', so file 'after-format-main' must be inside 'C:\'.
  
> **_NOTE 3:_** After run this script, you can check useful tools from in Documents.
  

<p>

### Startup Script
  
You can use just startup script too, follow the instructions below.
After downloading the [zip](https://github.com/caglaryalcin/windows-scripts/archive/refs/heads/main.zip) file, move the 'after-format-main\files\startup' folder inside the zip to 'C:\'. Then double click(don't right click and 'run as administrator') on 'Run.cmd' confirm User Account Control prompt. Make sure your account is a member of Administrators group as the script attempts to run with elevated privileges.

This script does exactly the following;
- Importing Previously Set Task to Task Scheduler
- Removing Secondary en-US Keyboard
- Adding tr-TR Keyboard
- Removing Stick Keys
- Removing Toggle Keys
- Remove Unnecessary Tasks(update and such) in Task Scheduler.(It also adds task to delete Unnecessary Tasks on every boot)
- Deleting Windows Defender History
- Sync Windows Localtime
- Update apps (browsers, apps, softwares and such..) with WinGet&nbsp;
  
  If you don't want to use WinGet, you can as below edit 'run.vbs' file in startup folder.
```vbs
Set WshShell = CreateObject("WScript.Shell") 
WshShell.Run chr(34) & "C:\startup\Run.cmd" & Chr(34), 0
Set WshShell = Nothing
```
</details>
