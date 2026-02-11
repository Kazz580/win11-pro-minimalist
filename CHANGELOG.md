# Win11 Pro Minimalist Script - CHANGELOG

All notable changes to this project will be documented in this file.

This project follows Semantic Versioning (MAJOR.MINOR.PATCH).

---

## [1.5.1] - 2026-02-11

### Fixed
- Fixed PowerShell string interpolation issue causing “Variable reference is not valid” error.
- Renamed internal helper functions to approved verbs to satisfy PSScriptAnalyzer.

---

## [1.5.0] - 2026-02-10

### Added
- Converted standalone script into PowerShell module:
  - `Win11ProMinimalist.psm1`
  - `Win11ProMinimalist.psd1`
- Exported function: `Invoke-Win11ProMinimalist`
- Added wrapper script: `Invoke-Win11ProMinimalist.ps1`
- Module metadata (author, version, tags)
- README updated for module usage

### Changed
- Project structure reorganized into module layout
- Documentation aligned strictly to implemented functionality

---

## [1.4.0] - Initial Structured Logging & Gaming Cleanup

### Added
- Dual logging system:
  - Full activity log
  - Changes-only log (records only actual modifications)
- Registry change detection (logs old → new values)
- Appx removal tracking
- Service disable tracking
- Protocol handler removal tracking

### Security
- Removed `ms-gamingoverlay:` protocol handler to suppress popup
- Disabled GameDVR background capture

---

## [1.3.0] - Copilot & Search Cleanup

### Added
- Removal of Copilot Appx packages
- Windows Copilot disabled via policy:
  - `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot\TurnOffWindowsCopilot = 1`

### Changed
- Disabled Start Menu web search:
  - `DisableWebSearch`
  - `ConnectedSearchUseWeb`
  - `AllowCloudSearch`
  - `BingSearchEnabled`
  - `CortanaConsent`

---

## [1.2.0] - Xbox & Gaming Component Cleanup

### Added
- Disabled GameDVR via registry
- Disabled Xbox services (optional via config):
  - XblAuthManager
  - XblGameSave
  - XboxGipSvc
  - XboxNetApiSvc

### Changed
- Removed Xbox App and related Appx packages

---

## [1.1.0] - Policy & Telemetry Controls

### Added
- Reduced telemetry policy (Pro-safe level)
- Disabled Windows consumer experiences
- Disabled cloud optimized content

---

## [1.0.0] - Initial Minimalist Build

### Added
- Removal of common consumer/bloat apps:
  - Teams, Skype, Clipchamp, GetHelp, GetStarted
  - ZuneMusic, ZuneVideo, FeedbackHub
  - Solitaire Collection
- Optional OneDrive removal
- Progress bar + confirmation prompt
- Transcript logging

---

End of CHANGELOG
