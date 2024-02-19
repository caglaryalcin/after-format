![Alt Text](https://github.com/caglaryalcin/caglaryalcin/blob/main/after-format/main.gif)

## Description

If you new formatted your computer on Windows 10 or Windows 11(all versions) you can run this script.

This script does exactly the following; (Some are optional: <kbd>y/n</kbd>)

<details><summary>System Settings</summary>&nbsp;
  
![](https://github.com/caglaryalcin/caglaryalcin/blob/main/after-format/1.png)
  
- It asks if you want Region change to Turkey.  
- It asks if you want change your hostname.
- It asks if you want disable Windows Defender.
- Date format is set to turkey
- Disabling News and Interes on Taskbar
- Default Old Photo Viewer
- Setting Dark Mode for Applications
- Setting Dark Mode for System
- Setting Control Panel View to Large Icons
- Enabling NumLock After Startup
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
- Hiding Recycle Bin Shortcut from Desktop
- Disabling hiberfil.sys
- Disabling Display and Sleep Mode Timeouts
- Disabling Windows Defender
- Get the Old Classic Right-Click Context Menu (for Windows 11)
- Hide Taskbar Start button alignment left (for Windows 11)
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

![](https://github.com/caglaryalcin/caglaryalcin/blob/main/after-format/2.png)
  
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

![](https://github.com/caglaryalcin/caglaryalcin/blob/main/after-format/3.png)
  
It asks if you want to install the following softwares or not.

- Chrome
- Brave
- Firefox
- LibreWolf
- Steam
- Epic Games
- HWMonitor
- CrystalDisk Info
- VMware Workstation
- VirtualBox
- Signal
- VSCode Community
- VSCode Build
- VSCode (with extensions)
- Notepad
- Windows SDK
- Node.js
- Python
- Git
- AnyDesk
- Terminal
- Speedtest for terminal
- GitHub
- VLC
- TreeSize
- Total Commander
- Wireshark
- Deluge
- DBeaver
- Cryptomator
- Microsoft Teams
- DupeGuru
- SteelSeries
- Java
- 7zip
- Lightshot
- Twinkle Tray
- Codec Pack Mega
- Malwarebytes
- Internet Download Manager
- Cloudflare Warp
- OpenRGB
- Tailscale
- WinFsp for Cryptomator
- NVCleanstall
- Nvidia Inspector

If an error is received while loading packets with chocolatey, it will try to load them with winget.

![](https://github.com/caglaryalcin/caglaryalcin/blob/main/after-format/5.png)

</details>

<details><summary>Remove Unused Apps/Softwares</summary>&nbsp;

![](https://github.com/caglaryalcin/caglaryalcin/blob/main/after-format/4.png)
  
- Uninstalling Default Third Party Applications
- Uninstalling Windows Media Player
- Uninstalling Work Folders Client
- Uninstalling Microsoft XPS Document Writer
- Removing Default Fax Printer
- Uninstalling OneDrive
- Removing Microsoft Edge
- Uninstalling Windows Fax and Scan Services
- It asks if you want uninstall Windows OneDrive.
- It asks if you want uninstall Windows Edge.

</details>

<details><summary>Startup Script</summary>&nbsp;

![](https://github.com/caglaryalcin/caglaryalcin/blob/main/after-format/startup.png)

This script adds a task named 'startup' to the task scheduler. This task does exactly the following;

- Remove En-US Keyboard
- Adding Turkey Keyboard
- Importing Previously Set Task to Task Scheduler
- Removing Stick Keys
- Removing Toggle Keys
- Remove Unnecessary Tasks(update and such) in Task Scheduler.(It also adds task to delete Unnecessary Tasks on every boot)
- Sync Windows Localtime
- Update apps (browsers, apps, softwares and such..) with WinGet&nbsp;

</details>

My Custom Drivers

🟠 When this question is asked, you must answer by saying <kbd>n</kbd>. Because the settings here 
are my specific settings.


> [!NOTE]  
> This script takes about 40-60 minutes with 100mbps internet.


## Start the script

####
> [!IMPORTANT]  
> Powershell must be run as admin
<br />

for **Windows 10**
```powershell
iwr "w10.caglaryalcin.com" -UseB | iex
```

for **Windows 11**
```powershell
iwr "w11.caglaryalcin.com" -UseB | iex
```
