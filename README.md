![Alt Text](https://github.com/caglaryalcin/caglaryalcin/blob/main/after-format/main.gif)

## Description

If you new formatted your computer on Windows 11(all versions) you can run this script. 

This script allows Windows 1x users to control data collection, privacy and security functions and does exactly the following; (Some are optional: <kbd>y/n</kbd>)

<details><summary>System Settings</summary>&nbsp;
  
![](https://github.com/caglaryalcin/caglaryalcin/blob/main/after-format/1.png)
  
- It asks if you want region change to turkey.
- It asks if you want change your hostname.
- It asks if you want disable windows defender.
- It asks if you want date format and keyboard layout
- Ask if you want to add a "startup" task to run at startup (recommended)
- Get the old classic right-click context menu
- Taskbar aligns left
- Disabling gallery folder
- Desktop button in taskbar is enabled
- Disabling sync your settings
- Disabling spotligt
- Disabling toast and apps notifications on lock screen
- Disabling windows media player diagnostics
- Disabling extension of windows search with bing
- Default old photo viewer
- Setting dark mode for applications
- Setting dark mode for system
- Setting control panel view to large icons
- Disabling user interface and device recognition features
- Enabling numlock after startup
- Disabling windows beep sound
- Disabling ipv6 stack
- Disabling virtual ethernet adapters...
- Setting cloud flare dns
- Configuring windows explorer settings
- Expanding for file explorer
- Hiding recycle bin shortcut from desktop
- Disabling hiberfil.sys
- Disabling display and sleep mode timeouts
- Disabling updates for other microsoft products
- Disabling cortana
- Disabling bing search in start menu
- Disabling smartscreen filter
- Disabling sensors
- Disabling tailored experiences
- Disabling xbox features
- Disabling blocking of downloaded files
- Disabling nightly wake-up for automatic maintenance
- Disabling storage sense
- Disabling built-in adobe flash in ie and edge
- Disabling edge preload
- Disabling internet explorer first run wizard
- Disabling windows media player online access
- Disabling action center (notification center)
- Disabling system restore for system drive
- Setting low uac level
- Removing unnecessary tasks
- Enabling clearing of recent files on exit
- Disabling recent files lists
- Disabling search for app in store for unknown extensions
- Hiding 'recently added' list from the start menu
- Stopping and disabling unnecessary services
- Disabling news and interest on taskbar
- Hiding people icon from taskbar
- Hiding taskview icon from taskbar
- Hiding multitaskview icon from taskbar
- Showing small icons in taskbar
- Hiding taskbar search
- Removing chat from taskbar
- Removing widgets from taskbar
- Enabling telnet client
- Unpinning all start menu tiles

</details>

<details><summary>Privacy Settings</summary>&nbsp;

![](https://github.com/caglaryalcin/caglaryalcin/blob/main/after-format/2.png)
  
- Disabling telemetry
- Blocking telemetry in host file
- Disabling feedback
- Disabling activity history
- Disabling clipboard history
- Disabling user steps recorder
- Turning off text suggestions for hardware keyboard
- Disabling app launch tracking
- Disabling website access to language list
- Stopping and disabling Connected User Experiences and Telemetry service
- Disabling advertising ID
- Disabling Wi-Fi Sense
- Disabling application suggestions
- Disabling UWP apps background access
- Disabling access to voice activation from UWP apps
- Disabling access to notifications from UWP apps
- Disabling access to account info from UWP apps
- Disabling access to contacts from UWP apps
- Disabling access to calendar from UWP apps
- Disabling access to phone calls from UWP apps
- Disabling access to call history from UWP apps
- Disabling access to email from UWP apps
- Disabling access to tasks from UWP apps
- Disabling access to messaging from UWP apps
- Disabling access to radios from UWP apps
- Disabling access to other devices from UWP apps
- Disabling access to diagnostic information from UWP apps
- Disabling access to libraries and file system from UWP apps
- Disabling UWP apps swap file
- Disabling automatic maps updates
- Disabling windows update automatic restart
- Disabling windows update automatic downloads

</details>
<details><summary>Install Softwares</summary>&nbsp;

![](https://github.com/caglaryalcin/caglaryalcin/blob/main/after-format/3.png)

> 💡It asks if you want to install the following softwares or not. If an error is received while loading packets with chocolatey, it will try to load them with winget.

![](https://github.com/caglaryalcin/caglaryalcin/blob/main/after-format/5.png)

- Chrome
- Brave
- Firefox
- Steam
- Epic Games
- HWMonitor
- CrystalDisk Info
- VMware Workstation
- VirtualBox
- Signal
- VSCode (with extensions)
- Notepad
- Windows SDK
- Node.js
- Python
- Git
- AnyDesk
- Terminal
- Speedtest cli
- GitHub
- VLC
- TreeSize
- Total Commander
- Wireshark
- Deluge
- DBeaver
- Cryptomator
- Microsoft Teams
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
- Rufus
- Regshot

</details>

<details><summary>Remove Unused apps/Softwares</summary>&nbsp;

![](https://github.com/caglaryalcin/caglaryalcin/blob/main/after-format/4.png)
  
- Uninstalling default third party applications
- It asks if you want disable Microsoft Copilot.
- Uninstalling windows media player
- Uninstalling work folders client
- Uninstalling microsoft XPS document writer
- Removing default fax printer
- Uninstalling windows fax and scan services
- Removing 3D folders
- Microsoft edge privacy settings are being adjusted
- It asks if you want remove unnecessary tasks
- It asks if you want uninstall windows onedrive
- It asks if you want uninstall windows edge

</details>

<details><summary>Startup Script</summary>&nbsp;

![](https://github.com/caglaryalcin/caglaryalcin/blob/main/after-format/startup.png)

> [!TIP]
> This script adds a task named 'startup' to the task scheduler. This task does exactly the following;

> [!IMPORTANT]  
> startup task > This task starts 3 minutes after the computer is turned on, runs again every 3 hours and performs the following operations.

- Time zone is set to Turkey
- Language bar is set to appear in the taskbar
- It does expand for file explorer ribbon
- It does removing stick keys
- f12 is disabled for snipping tool
- It does remove toggle keys
- It does remove unnecessary tasks(update and such) in task scheduler
- It does remove windows defender icon in taskbar
- Disables unnecessary applications that open on connection
- It does remove microsoft edge updates in task scheduler
- It does remove google chrome updates in task scheduler
- It does enable shot desktop button
- Sync windows localtime

> upgrade-packages > This task runs 3 minutes after the computer is turned on and performs the following operations.

- Updates all applications and packages with winget.

</details>

My custom configs and drivers

> [!WARNING]  
> When this question is asked, you must answer by saying <kbd>n</kbd>. Because the settings here 
are my specific settings.

![](https://github.com/caglaryalcin/caglaryalcin/blob/main/after-format/6.png)

## Start the script

####
> [!NOTE]  
> This script takes about 60 minutes with 100mbps internet.

> [!IMPORTANT]  
> Powershell must be run as admin
<br />

```powershell
iwr "set.caglaryalcin.com" -UseB | iex
```
