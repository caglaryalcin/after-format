![Alt Text](https://raw.githubusercontent.com/caglaryalcin/caglaryalcin/refs/heads/main/main.gif)

## After Format

![LATEST RELEASE](https://img.shields.io/github/v/release/caglaryalcin/after-format?label=LATEST%20RELEASE&labelColor=4d4d4d&color=red)  ![](https://badgen.net/github/license/caglaryalcin/after-format)

A comprehensive Windows 11 post-installation script that automates system configuration, privacy hardening, software installation, and bloatware removal. The script supports all Windows 11 versions and offers three distinct operation modes tailored to different use cases. Some settings are optional and prompted interactively (<kbd>y/n</kbd>).

---

### How It Works

The script runs in two phases:

1. **`set.psm1`** — Configures system settings, applies privacy tweaks, initiates software installation, and removes bloatware.
2. **`resume.psm1`** — Runs after reboot to complete software installation, install VSCode extensions, configure developer tools (WSL, npm, OpenSSL, Claude Code), and perform final cleanup.

---

<details><summary><strong>Mode Selection</strong></summary>&nbsp;

The script starts by asking you to choose one of three modes. All subsequent settings, software installations, and optimizations are configured based on your selection.

| Mode | Description |
|------|-------------|
| **Normal** | Standard desktop usage — basic utilities, productivity tools |
| **Gaming** | Optimized for gaming — game launchers, Discord, NVIDIA tools, performance tweaks |
| **Dev-Sys Eng** | Full development environment — IDEs, SDKs, languages, CLI tools, containers |

<img width="991" height="303" alt="image" src="https://github.com/user-attachments/assets/7c16420e-cb4e-4fe1-b49c-ab0f7a2876a8" />

</details>

<details><summary><strong>System Settings</strong></summary>&nbsp;

![image](https://github.com/user-attachments/assets/df445708-a6eb-4cc0-9a64-fd5983d0a502)

#### Interactive Prompts (y/n)

- Region change to Turkiye (date/time/currency formats)
- Hostname customization
- Windows activation via [Microsoft Activation Scripts](https://github.com/massgravel/Microsoft-Activation-Scripts)
- Windows Update delay configuration

<img width="1016" height="692" alt="image" src="https://github.com/user-attachments/assets/cbd63641-ae29-4df8-ab51-77e5493016b8" />

- Windows Defender removal
- Date format and keyboard layout selection (TR/UK)
- Explorer folder view set to "Details" with custom separator settings

![image](https://github.com/user-attachments/assets/6a5a335f-1ffe-4427-94a0-75d01204668e)

- Startup scheduled task creation (recommended)

#### NVIDIA Driver Optimization (Gaming mode, optional for others)

The script uses [NVCleanstall](https://www.techpowerup.com/nvcleanstall/) to install NVIDIA graphics drivers **without bloatware**. Instead of NVIDIA's default installer — which bundles telemetry, GeForce Experience, HD Audio via HDMI, and other unnecessary components — NVCleanstall strips everything down and installs only the pure display driver and essential packages. This results in a cleaner, lighter, and more performant system.

Additionally, [NVIDIA Profile Inspector](https://github.com/Orbmu2k/nvidiaProfileInspector) is installed and a pre-configured base profile is imported to optimize driver-level settings for maximum gaming performance. A scheduled task is also created to automatically check for new driver updates at logon and every 4 hours.

> In Gaming mode this runs automatically. In Normal and Dev-Sys modes, you will be prompted whether to apply NVIDIA optimizations.

#### Taskbar & UI

- Classic right-click context menu restoration

![image](https://github.com/user-attachments/assets/1066a699-f11c-4266-a481-cc000da1b451)
![image](https://github.com/user-attachments/assets/572b299c-a032-4394-b625-7e092e1bfbed)

- Taskbar left alignment
- Snap windows disabled
- Oh-My-Posh integration for Windows Terminal (Dev-Sys & Normal modes)

![image](https://github.com/user-attachments/assets/154e85b6-0872-45ee-b6bb-846655846890)

- Gallery folder disabled
- Desktop button enabled on taskbar
- News, interest, people icon, task view, multitask view, search, chat, and widgets removed from taskbar
- Category view disabled on taskbar
- Always combine taskbar buttons

#### Display & Appearance

- Dark mode for applications and system
- Control panel set to large icons view
- Classic photo viewer restored
- Shortcut name prefix removed

![image](https://github.com/user-attachments/assets/5d44a918-bf3f-49df-a27a-105b461a07e3)

#### Power & Performance

- Hibernate file (`hiberfil.sys`) disabled
- Display and sleep mode timeouts disabled
- Ultimate Performance power plan enabled
- Memory compression enabled/disabled based on RAM amount
- GPU performance mode set for specific applications
- Storage Sense disabled

#### Network

- IPv6 stack disabled
- DNS provider selection (Cloudflare, Google, AdGuard) with automatic ping-based optimization
- Virtual ethernet adapters disabled

#### Security & System

- SmartScreen filter disabled
- Low UAC level set
- System restore disabled for system drive
- Password never expires for local admins
- Account notifications disabled
- Auto-end task on logout/restart enabled
- Disk quota removed
- Mapped drives enabled in elevated Command Prompt
- Downloaded files blocking disabled
- Automatic maintenance wake-up disabled

#### Features & Services

- WSL enabled
- Telnet client enabled (Dev-Sys & Normal modes)
- Sudo enabled (Dev-Sys & Normal modes)
- Xbox features disabled (Dev-Sys & Normal modes)
- Unnecessary services stopped and disabled
- NumLock enabled after startup
- Windows beep sound disabled
- Sensors disabled
- Tailored experiences disabled
- Settings sync disabled
- Spotlight disabled
- Toast and lock screen notifications disabled
- Windows Media Player diagnostics disabled
- Bing search in Start Menu disabled
- Built-in Adobe Flash disabled in IE and Edge
- Edge preload disabled
- IE first run wizard disabled
- Windows Media Player online access disabled
- Recent files clearing enabled on exit

![image](https://github.com/user-attachments/assets/ed4a0085-fe62-4e33-967a-4a3a1ccdd812)

- Recent files list disabled
- Start menu tiles unpinned
- Start menu: Recently Added, Recommended, Personalized Sites hidden
- Known Windows errors fixed

![image](https://github.com/user-attachments/assets/869227a1-a299-4e20-8450-b0ba279409ff)

</details>

<details><summary><strong>Privacy Settings</strong></summary>&nbsp;

#### Telemetry & Tracking

- Telemetry disabled via registry
- Telemetry endpoints blocked in hosts file
- Connected User Experiences and Telemetry service stopped
- Diagnostic data collection disabled
- Diagnostic log collection disabled
- Error reporting disabled
- Handwriting error reports disabled
- Advertising ID disabled
- Activity history disabled
- App launch tracking disabled
- Tailored experiences disabled
- User steps recorder disabled
- Feedback disabled

#### Input & Communication

- Clipboard history disabled
- Clipboard sharing disabled
- Text suggestions for hardware keyboard disabled
- Text message cloud backup disabled
- Password reveal button disabled
- Website access to language list disabled

#### Network & Connectivity

- Wi-Fi Sense disabled
- Bluetooth advertising disabled
- Location system disabled
- Automatic maps updates disabled

#### UWP App Permissions

All UWP app access restricted for:
- Voice activation, Notifications, Account info, Contacts, Calendar
- Phone calls, Call history, Email, Tasks, Messaging
- Radios, Other devices, Diagnostic info, File system
- Background access disabled
- UWP swap file disabled

#### Windows Update

- Automatic restart disabled
- Automatic downloads disabled
- Updates for other Microsoft products disabled

#### Other

- Application suggestions disabled
- Task scheduler history enabled

</details>

<details><summary><strong>Software Installation</strong></summary>&nbsp;

![image](https://github.com/user-attachments/assets/048bf752-293e-474e-944d-f15fe9dcecb6)

> 💡Packages are installed via **winget** with automatic **Chocolatey** fallback for failed installations. The package list depends on the mode selected at the start.

![image](https://github.com/user-attachments/assets/88b71d2a-3e78-4ecf-aeb8-df98f7952a3d)

#### Normal Mode
| Category | Packages |
|----------|----------|
| Browser | Chrome |
| Monitoring | HWMonitor, CrystalDisk Info |
| Utilities | AnyDesk, Speedtest CLI, TreeSize, Lightshot, Twinkle Tray, Rufus, PowerToys |
| Media | VLC, K-Lite Codec Pack Mega |
| Security | Malwarebytes |
| System | FanControl |

#### Gaming Mode
| Category | Packages |
|----------|----------|
| Browser | Chrome |
| Game Launchers | Steam, Epic Games, Battle.net, EA Desktop, Ubisoft Connect |
| Gaming | Discord, FACEIT Client, FACEIT AC, Google Play Games |
| Monitoring | HWMonitor, CrystalDisk Info |
| Utilities | Speedtest CLI, 7-Zip |
| System | FanControl |

#### Dev-Sys Eng Mode
| Category | Packages |
|----------|----------|
| Browsers | Chrome, Brave, Firefox |
| Game Launchers | Steam, Epic Games |
| IDEs & Editors | VSCode (with extensions), Notepad++ |
| Languages & Runtimes | Node.js, Python, Git, Yarn, .NET Desktop Runtime 8, PowerShell |
| SDKs | Windows SDK, OpenSSL |
| Dev Tools | GitHub Desktop, DBeaver, Oh-My-Posh, iPerf3, Claude Code |
| Communication | Signal, Microsoft Teams |
| Monitoring | HWMonitor, CrystalDisk Info |
| Utilities | AnyDesk, Speedtest CLI, TreeSize, Total Commander, qBittorrent, 7-Zip, Flameshot, Twinkle Tray, Rufus, PowerToys, IDM |
| Media | VLC, K-Lite Codec Pack Mega |
| Security | Malwarebytes |
| System | FanControl, EdgeWebView2 Runtime |

#### VSCode Extensions (Dev-Sys Eng Mode)

Automatically installed after VSCode setup:

- **Docker**: GitLens, Docker, Docker Explorer, Docker Compose, Remote Containers
- **Autocomplete**: Auto Close/Rename/Complete Tag, Spell Checker, XML
- **Design**: Material Icon Theme
- **PowerShell**: PowerShell, Run in PowerShell, Remote WSL
- **Frontend**: React Native, CSS Peek, ES7 Snippets, ESLint, Path Intellisense, Prettier, Python, Color Highlight, JSON
- **GitHub**: Pull Request, Copilot
- **Linux**: Bash Debug, Bash Beautify, Bash IDE, YAML

#### Additional Dev Setup (Dev-Sys Eng Mode)

- WSL with Ubuntu installation
- npm global configuration
- OpenSSL PATH configuration
- Claude Code installation

</details>

<details><summary><strong>Remove Unused Apps</strong></summary>&nbsp;

![image](https://github.com/user-attachments/assets/6166868e-7eef-4012-b530-ee6c10eb6674)

#### Automatic Removal

- Default third-party bloatware applications
- Windows Media Player
- Work Folders Client
- Microsoft XPS Document Writer
- Default fax printer
- Windows Fax and Scan Services
- 3D Object folders
- Windows 11 Recall
- Desktop shortcuts cleanup

#### Privacy Adjustments

- Microsoft Edge privacy settings hardened
- Microsoft Office privacy settings hardened
- Windows sync disabled

#### Interactive Prompts (y/n)

- Microsoft Copilot removal
- Microsoft AI features removal
- Unnecessary scheduled tasks removal
- OneDrive uninstallation
- Microsoft Edge uninstallation

![edge(1)](https://github.com/user-attachments/assets/3ee26ac9-7aeb-43cc-ae5a-567d730d1480)

</details>

<details><summary><strong>Startup Script</strong></summary>&nbsp;

![image](https://github.com/user-attachments/assets/b2cc1a6e-7354-4f0b-a572-6a181bcd2a43)

The script creates two scheduled tasks in Task Scheduler:

#### `startup` Task
> 💡Runs 3 minutes after boot, repeats every 3 hours

- Expands File Explorer ribbon
- Removes Sticky Keys and Toggle Keys
- Disables F12 for Snipping Tool
- Removes unnecessary scheduled tasks (updates, etc.)
- Removes Windows Defender icon from taskbar
- Disables unnecessary startup applications (varies by mode)
- Removes Microsoft Edge update tasks
- Removes Google Chrome update tasks
- Enables Show Desktop button
- Syncs Windows local time

#### `upgrade-packages` Task
> 💡 Runs 3 minutes after boot

- Updates all installed packages via `winget upgrade --all`

</details>

---

## Usage

> [!WARNING]
> This script makes extensive changes to Windows settings, registry, and services. While carefully tested to avoid breaking OS functionality, **use at your own risk**.

> [!NOTE]
> Approximate execution times with 100 Mbps internet:
>
> | Mode | Duration |
> |------|----------|
> | Normal | ~15 min |
> | Gaming | ~30 min |
> | Dev-Sys Eng | ~60 min |

> [!IMPORTANT]
> PowerShell must be run as **Administrator**

```powershell
iwr "set.caglaryalcin.com" -UseB | iex
```
