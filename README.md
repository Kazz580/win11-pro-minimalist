# Win11 Pro Minimalist

![Release](https://img.shields.io/github/v/release/Kazz580/win11-pro-minimalist?sort=semver)
![CI](https://github.com/Kazz580/win11-pro-minimalist/actions/workflows/ci.yml/badge.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%2011-lightgrey)

A conservative Windows 11 Pro debloat + policy hardening **PowerShell module** for fresh installs.

Designed for post-install cleanup with structured logging and audit-friendly change tracking.

> Safety principle: **Do not remove Microsoft Store, Windows Update, Edge, or WebView2 runtime.**

---

## Features

### App Cleanup
- Removes common consumer Appx packages (Teams, Copilot, New Outlook, Phone Link, DevHome, Office Hub, etc.)
- Optional: Uninstall OneDrive
- Optional: Disable Xbox services

### Policy Hardening
- Reduce telemetry (Pro-safe level)
- Disable consumer experiences / cloud optimized content
- Disable Windows Copilot
- Disable Start Menu web/Bing results (local-only search)

### Gaming Cleanup
- Disable GameDVR / background capture
- Remove `ms-gamingoverlay:` protocol handler (prevents Xbox Game Bar popup)

### UX & Safety
- Confirmation prompt
- Progress bar
- Designed to be rerunnable (idempotent behavior)

### Auditing
- Full activity log
- Changes-only log (records only actual modifications)
- PowerShell transcript

---

## Requirements

- Windows 11 Pro
- Run PowerShell **as Administrator**
- Run while logged in as your target local user (so HKCU changes apply to that user)

---

## Usage

### Option A — Wrapper (Recommended)

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
cd C:\scripts\win11-pro-minimalist\src
.\Invoke-Win11ProMinimalist.ps1
```

### Option B — Import Module

```powershell
Import-Module .\src\Win11ProMinimalist -Force
Invoke-Win11ProMinimalist
```

### Optional Parameters

```powershell
Invoke-Win11ProMinimalist `
  -UninstallOneDrive:$false `
  -DisableXboxServices:$false `
  -WhatIfOnly
```

- `-WhatIfOnly` simulates changes without modifying the system.

---

## Logs

Each run creates timestamped files under `%TEMP%`:

- `Win11-Minimalist-<timestamp>.log` — Full activity log  
- `Win11-Minimalist-<timestamp>-CHANGES.log` — Only actual modifications  
- `Win11-Minimalist-<timestamp>-transcript.txt` — PowerShell transcript  

Logs are never appended. Each execution generates new files.

---

## Configuration

Default configuration (inside module):

```powershell
$Config = [ordered]@{
  UninstallOneDrive     = $true
  DisableXboxServices   = $true
  WhatIfOnly            = $false
}
```

---

## Design Principles

- Conservative removals (no Store/Update breakage)
- Policy-based where possible
- Idempotent (safe to rerun)
- Explicit logging for auditing
- Avoid breaking Windows servicing stack

---

## Repository Structure

```text
.
├─ src/
│  ├─ Invoke-Win11ProMinimalist.ps1
│  └─ Win11ProMinimalist/
│     ├─ Win11ProMinimalist.psm1
│     └─ Win11ProMinimalist.psd1
├─ CHANGELOG.md
└─ README.md
```

---

## Versioning

This project follows **Semantic Versioning (MAJOR.MINOR.PATCH)**.

The following must always match:

- Module version (`Win11ProMinimalist.psd1`)
- Top entry in `CHANGELOG.md`
- Git tag (`vX.Y.Z`)

CI automatically validates version consistency.

---

## License

Personal-use / internal-use.  
Add a formal license if distributing publicly.
