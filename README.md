# Win11 Pro Minimalist Script

A conservative debloat + policy hardening PowerShell script for a fresh Windows 11 Pro install.
Designed for **one-time post-install cleanup** with **audit-friendly logs** (full log + changes-only log).

> Safety goals: **do not remove** Microsoft Store, Windows Update, Edge, or WebView2 runtime.

## Features

- Removes common “consumer” Appx packages (Teams, Copilot, New Outlook, Phone Link, DevHome, Office hub, etc.)
- Optional: Uninstall OneDrive
- Optional: Disable Xbox services
- Policies:
  - Reduce telemetry (Pro-safe level)
  - Disable consumer experiences / cloud optimized content
  - Disable Windows Copilot
  - Disable Start Menu web/Bing results (local-only search)
- Gaming cleanup:
  - Disable GameDVR / background capture
  - Remove `ms-gamingoverlay:` protocol handler to stop “Get an app to open this link” popup
- UX:
  - Confirmation prompt
  - Progress bar
- Auditing:
  - Full log + transcript
  - Changes-only log showing only what actually changed

## Requirements

- Windows 11 Pro
- PowerShell run **as Administrator**
- Run while logged in as your target local user (so HKCU changes apply to that user)

## Usage

### Option A: Run the wrapper script (recommended)
1) Copy the repo to a local folder (example: `C:\scripts\win11-pro-minimalist`)
2) Open PowerShell **as Administrator**
3) Run:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
cd C:\scripts\win11-pro-minimalist\src
.\Invoke-Win11ProMinimalist.ps1
```

### Option B: Import as a module
From an elevated PowerShell in `src`:

```powershell
Import-Module .\Win11ProMinimalist -Force
Invoke-Win11ProMinimalist
```

> The function accepts switches for overrides:
> - `-UninstallOneDrive:$false` (keep OneDrive)
> - `-DisableXboxServices:$false` (keep Xbox services)
> - `-WhatIfOnly` (simulate)

## Logs


The script outputs three files in `%TEMP%`:

- `Win11-Minimalist-<timestamp>.log` — full activity log
- `Win11-Minimalist-<timestamp>-CHANGES.log` — only actual changes (best for auditing)
- `Win11-Minimalist-<timestamp>-transcript.txt` — PowerShell transcript

## Configuration

At the top of the script:

```powershell
$Config = [ordered]@{
  UninstallOneDrive     = $true
  DisableXboxServices   = $true
  WhatIfOnly            = $false
}
```

- `WhatIfOnly = $true` will simulate actions and log intended changes.

## Notes / Gotchas

- HKCU changes apply only to the user running the script. If you run it under the built-in Administrator profile, per-user settings may not apply to your daily user.
- Removing the `ms-gamingoverlay` protocol prevents the “Get an app to open this link” popup when games call Xbox Game Bar.
- Keeping Edge + WebView2 is recommended for Windows stability.

## Repository Layout

```text
.
├─ src/
│  ├─ Invoke-Win11ProMinimalist.ps1
│  └─ Win11ProMinimalist/
│     ├─ Win11ProMinimalist.psm1
│     └─ Win11ProMinimalist.psd1
├─ docs/
│  ├─ VersionHistory.txt
│  ├─ VERSIONING.md
│  └─ git-setup.md
├─ CHANGELOG.md
└─ README.md
```
.
├─ src/
│  └─ Win11ProMinimalist.ps1
├─ docs/
│  └─ VersionHistory.txt
├─ CHANGELOG.md
└─ README.md
```

## License

Personal-use / internal-use. Add your preferred license here if you plan to share publicly.
