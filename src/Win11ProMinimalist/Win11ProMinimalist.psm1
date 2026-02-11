<# 
Win11 Pro Minimalist PowerShell Module
Exports: Invoke-Win11ProMinimalist
#>

function Invoke-Win11ProMinimalist {
  [CmdletBinding()]
  param(
    [switch]$UninstallOneDrive,
    [switch]$DisableXboxServices,
    [switch]$WhatIfOnly
  )

  # Admin check (equivalent to #Requires -RunAsAdministrator for module usage)
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) {
    throw "This function must be run in an elevated PowerShell session (Run as Administrator)."
  }

  # Map switches to config defaults. If switch not provided, use module defaults (same as original script).
  # Note: switches default to $false, so we use 'IsPresent' to detect override intent.
  $script:Config = [ordered]@{
    UninstallOneDrive     = $true
    DisableXboxServices   = $true
    WhatIfOnly            = $false
  }

  if ($PSBoundParameters.ContainsKey('UninstallOneDrive'))   { $script:Config.UninstallOneDrive   = [bool]$UninstallOneDrive.IsPresent }
  if ($PSBoundParameters.ContainsKey('DisableXboxServices')) { $script:Config.DisableXboxServices = [bool]$DisableXboxServices.IsPresent }
  if ($PSBoundParameters.ContainsKey('WhatIfOnly'))          { $script:Config.WhatIfOnly          = [bool]$WhatIfOnly.IsPresent }

<#  Win11 Pro - Controlled Minimalist Setup (Progress + Confirmation + Full Log + Changes-Only Log)

    - Removes common consumer/bloat Appx packages (incl. Teams) + deprovisions them
    - Removes Copilot + New Outlook + DevHome + OfficeHub + Phone Link + Maps + Power Automate Desktop (if present)
    - Keeps Widgets, Edge, WebView2 Runtime (does NOT remove them)
    - Disables Windows Copilot via policy
    - Disables Start menu web/Bing search (local-only search)
    - Disables GameDVR / background capture (DWORDs requested)
    - Removes ms-gamingoverlay protocol handler to stop the popup if Game Bar is removed
    - Optional: Uninstall OneDrive (toggle)
    - Optional: Disable Xbox services (toggle)
    - gpupdate refresh

    Logs:
      - Full log:      %TEMP%\Win11-Minimalist-<timestamp>.log
      - Changes-only:  %TEMP%\Win11-Minimalist-<timestamp>-CHANGES.log
      - Transcript:    %TEMP%\Win11-Minimalist-<timestamp>-transcript.txt

    Notes:
      - HKCU changes apply to the user running the script. For best results, run while logged into your target
        local user account and start PowerShell "Run as administrator" (so HKCU points at that user, not built-in Administrator).

#>
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -------------------- TOGGLES --------------------
$Config = [ordered]@{
  UninstallOneDrive     = $true   # set $false to keep OneDrive
  DisableXboxServices   = $true   # set $false to keep Xbox services
  WhatIfOnly            = $false  # set $true to simulate (no changes), still logs planned actions
}

# -------------------- LOGGING --------------------
$Timestamp      = Get-Date -Format "yyyyMMdd-HHmmss"
$LogPath        = Join-Path $env:TEMP "Win11-Minimalist-$Timestamp.log"
$ChangeLogPath  = Join-Path $env:TEMP "Win11-Minimalist-$Timestamp-CHANGES.log"
$TranscriptPath = Join-Path $env:TEMP "Win11-Minimalist-$Timestamp-transcript.txt"

function Write-Log {
  param([string]$Message, [ValidateSet("INFO","WARN","ERROR")] [string]$Level="INFO")
  $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
  Add-Content -Path $LogPath -Value $line
  Write-Host $line
}

function Write-Write-ChangeLog {
  param([string]$Message)
  $line = "{0} [CHANGE] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
  Add-Content -Path $ChangeLogPath -Value $line
}

Start-Transcript -Path $TranscriptPath -Append | Out-Null
Write-Log "Starting Win11 Minimalist script."
Write-Log "Full log:      $LogPath"
Write-Log "Changes-only:  $ChangeLogPath"
Write-Log "Transcript:    $TranscriptPath"
Log ("Config: " + ($Config.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" } -join ", "))

# -------------------- CONFIRMATION --------------------
Write-Host ""
Write-Host "This will REMOVE selected built-in apps (Teams/Copilot/Outlook/etc) and apply privacy/policy settings." -ForegroundColor Yellow
Write-Host "Full log:     $LogPath" -ForegroundColor Yellow
Write-Host "Changes-only: $ChangeLogPath" -ForegroundColor Yellow
Write-Host ""
$confirm = Read-Host "Type YES to proceed"
if ($confirm -ne "YES") {
  Write-Log "User did not confirm. Exiting." "WARN"
  Stop-Transcript | Out-Null
  return
}

# -------------------- PROGRESS FRAMEWORK --------------------
$Tasks = New-Object System.Collections.Generic.List[object]

function Add-Task {
  param(
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][scriptblock]$Action
  )
  $Tasks.Add([pscustomobject]@{ Name = $Name; Action = $Action }) | Out-Null
}

function Invoke-Tasks {
  $total = $Tasks.Count
  for ($i = 0; $i -lt $total; $i++) {
    $t = $Tasks[$i]
    $pct = [int](($i / [math]::Max($total,1)) * 100)
    Write-Progress -Activity "Win11 Minimalist Setup" -Status $t.Name -PercentComplete $pct
    Write-Log "BEGIN: $($t.Name)"
    try {
      & $t.Action
      Write-Log "END:   $($t.Name)"
    } catch {
      Write-Log "FAILED: $($t.Name) - $($_.Exception.Message)" "ERROR"
      throw
    }
  }
  Write-Progress -Activity "Win11 Minimalist Setup" -Completed -Status "Completed"
}

# -------------------- HELPERS --------------------
function Initialize-RegistryKey {
  param([Parameter(Mandatory=$true)][string]$Path)
  if (-not (Test-Path $Path)) {
    if (-not $Config.WhatIfOnly) { New-Item -Path $Path -Force | Out-Null }
    Write-Log "Ensured registry key exists: $Path"
    if (-not $Config.WhatIfOnly) { Write-ChangeWrite-Log "Created registry key: $Path" }
  }
}

function Set-Dword {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][int]$Value
  )

  Initialize-RegistryKey -Path $Path

  $existing = $null
  $hadValue = $false
  try {
    $existing = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
    $hadValue = $true
  } catch {}

  if ($Config.WhatIfOnly) {
    Write-Log "WHATIF: Set DWORD $Path\$Name = $Value"
    return
  }

  New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
  Write-Log "Set DWORD $Path\$Name = $Value"

  if (-not $hadValue) {
    Write-ChangeLog "Created DWORD: $Path\$Name = $Value"
  } elseif ([int]$existing -ne [int]$Value) {
    Write-ChangeLog "Changed DWORD: ${Path}\${Name}: ${existing} -> ${Value}"
  }
}

function Remove-AppxLike {
  param([Parameter(Mandatory=$true)][string[]]$Patterns)

  foreach ($p in $Patterns) {
    Write-Log "Processing Appx pattern: $p"

    $installed = @(Get-AppxPackage -AllUsers $p -ErrorAction SilentlyContinue)
    if ($installed.Count -eq 0) {
      Write-Log "No installed Appx packages found for: $p"
    } else {
      foreach ($pkg in $installed) {
        Write-Log "Found installed: $($pkg.Name) ($($pkg.PackageFullName))"
        if ($Config.WhatIfOnly) {
          Write-Log "WHATIF: Remove-AppxPackage -AllUsers -Package $($pkg.PackageFullName)"
        } else {
          try {
            Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction SilentlyContinue
            Write-Log "Removed installed package: $($pkg.PackageFullName)"
            Write-ChangeLog "Removed Appx (installed): $($pkg.PackageFullName)"
          } catch {
            Write-Log "Could not remove installed package (may already be gone / in use): $($pkg.PackageFullName) - $($_.Exception.Message)" "WARN"
          }
        }
      }
    }

    $prov = @(Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $p })
    if ($prov.Count -eq 0) {
      Write-Log "No provisioned packages found for: $p"
    } else {
      foreach ($pp in $prov) {
        Write-Log "Found provisioned: $($pp.DisplayName) ($($pp.PackageName))"
        if ($Config.WhatIfOnly) {
          Write-Log "WHATIF: Remove-AppxProvisionedPackage -Online -PackageName $($pp.PackageName)"
        } else {
          try {
            Remove-AppxProvisionedPackage -Online -PackageName $pp.PackageName -ErrorAction SilentlyContinue | Out-Null
            Write-Log "Deprovisioned package: $($pp.PackageName)"
            Write-ChangeLog "Deprovisioned Appx: $($pp.PackageName)"
          } catch {
            Write-Log "Could not deprovision package: $($pp.PackageName) - $($_.Exception.Message)" "WARN"
          }
        }
      }
    }
  }
}

function Disable-Services {
  param([Parameter(Mandatory=$true)][string[]]$ServiceNames)

  foreach ($s in $ServiceNames) {
    $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
      Write-Log "Service not found: $s"
      continue
    }

    $startMode = (Get-CimInstance Win32_Service -Filter "Name='$s'" -ErrorAction SilentlyContinue).StartMode
    Write-Log "Service: $s (Status=$($svc.Status), StartMode=$startMode)"

    if ($Config.WhatIfOnly) {
      Write-Log "WHATIF: Stop-Service $s; Set-Service $s -StartupType Disabled"
      continue
    }

    $changed = $false
    try { Stop-Service -Name $s -Force -ErrorAction SilentlyContinue } catch {}
    try {
      if ($startMode -ne "Disabled") {
        Set-Service -Name $s -StartupType Disabled -ErrorAction SilentlyContinue
        $changed = $true
      }
    } catch {}

    if ($changed) {
      Write-Log "Disabled service: $s"
      Write-ChangeLog "Disabled service: $s"
    } else {
      Write-Log "Service already disabled (or could not change): $s"
    }
  }
}

function Remove-ProtocolHandler {
  param([Parameter(Mandatory=$true)][string]$ProtocolName)

  $path = "Registry::HKEY_CLASSES_ROOT\$ProtocolName"
  if (-not (Test-Path $path)) {
    Write-Log "Protocol handler not found: HKCR:\$ProtocolName"
    return
  }

  if ($Config.WhatIfOnly) {
    Write-Log "WHATIF: Remove protocol handler HKCR:\$ProtocolName"
    return
  }

  try {
    Remove-Item -Path $path -Recurse -Force
    Write-Log "Removed protocol handler: HKCR:\$ProtocolName"
    Write-ChangeLog "Removed protocol handler: HKCR:\$ProtocolName"
  } catch {
    Write-Log "Failed to remove protocol handler HKCR:\$ProtocolName - $($_.Exception.Message)" "WARN"
  }
}

# -------------------- TASKS --------------------

Add-Task "Remove common consumer/bloat apps (incl. Teams, Copilot, Outlook)" {
  # Conservative list — does NOT remove Widgets, Edge, or WebView2 runtime.
  $BloatPatterns = @(
    "*MicrosoftTeams*",
    "*Teams*",
    "*SkypeApp*",
    "*Clipchamp*",
    "*GetHelp*",
    "*GetStarted*",

    "*Microsoft.Windows.Ai.Copilot*",
    "*Microsoft.Copilot*",

    "*Microsoft.OutlookForWindows*",
    "*Microsoft.MicrosoftOfficeHub*",
    "*Microsoft.DevHome*",
    "*Microsoft.YourPhone*",
    "*Microsoft.WindowsMaps*",
    "*Microsoft.PowerAutomateDesktop*",

    "*Microsoft.People*",
    "*Microsoft.BingWeather*",
    "*Microsoft.BingNews*",
    "*Microsoft.BingSports*",
    "*Microsoft.BingFinance*",

    "*Microsoft.GamingApp*",
    "*Microsoft.XboxApp*",
    "*Microsoft.XboxGamingOverlay*",
    "*Microsoft.XboxGameOverlay*",
    "*Microsoft.XboxIdentityProvider*",
    "*Microsoft.XboxSpeechToTextOverlay*",

    "*Microsoft.ZuneMusic*",
    "*Microsoft.ZuneVideo*",
    "*Microsoft.WindowsFeedbackHub*",
    "*Microsoft.MicrosoftSolitaireCollection*"
  )

  Remove-AppxLike -Patterns $BloatPatterns
}

Add-Task "Optional: Uninstall OneDrive" {
  if (-not $Config.UninstallOneDrive) {
    Write-Log "UninstallOneDrive disabled; skipping."
    return
  }

  $OneDriveSetup = Join-Path $env:SystemRoot "SysWOW64\OneDriveSetup.exe"
  if (-not (Test-Path $OneDriveSetup)) { $OneDriveSetup = Join-Path $env:SystemRoot "System32\OneDriveSetup.exe" }

  if (-not (Test-Path $OneDriveSetup)) {
    Write-Log "OneDriveSetup.exe not found; skipping." "WARN"
    return
  }

  Write-Log "Uninstalling OneDrive via: $OneDriveSetup"
  if ($Config.WhatIfOnly) {
    Write-Log "WHATIF: Start-Process `"$OneDriveSetup`" /uninstall"
    return
  }

  Start-Process -FilePath $OneDriveSetup -ArgumentList "/uninstall" -Wait -WindowStyle Hidden
  Write-Log "OneDrive uninstall command completed."
  Write-ChangeLog "Ran OneDrive uninstall."
}

Add-Task "Policies: Reduce telemetry + disable consumer experiences + disable Copilot" {
  # Telemetry on Pro: 1 = Basic (stable). 0 generally only honored on Enterprise/Education.
  Set-Dword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 1

  # Prevent Windows from reinstalling/suggesting consumer apps
  Set-Dword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1
  Set-Dword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableCloudOptimizedContent" -Value 1

  # Disable Windows Copilot (policy + hide button)
  Set-Dword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1
  Set-Dword -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCopilotButton" -Value 0
}

Add-Task "Disable Start menu web/Bing search (local-only search)" {
  Set-Dword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1
  Set-Dword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Value 0
  Set-Dword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Value 0

  # Per-user toggles
  Set-Dword -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0
  Set-Dword -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0
}

Add-Task "Reduce ads/suggestions (current user)" {
  Set-Dword -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0
  Set-Dword -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 0
  Set-Dword -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Value 0
  Set-Dword -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value 0
  Set-Dword -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value 0
  Set-Dword -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_IrisRecommendations" -Value 0
  Set-Dword -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0
}

Add-Task "Disable GameDVR / background capture (prevents Game Bar capture)" {
  # Disable Game DVR via policy (machine-wide)
  Set-Dword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0

  # Disable per-user capture
  Set-Dword -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0
  Set-Dword -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0
  Set-Dword -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Value 2
}

Add-Task "Remove ms-gamingoverlay protocol handler (stops popup if Game Bar removed)" {
  # Prevents Windows from trying to open ms-gamingoverlay: when games call it.
  Remove-ProtocolHandler -ProtocolName "ms-gamingoverlay"
}

Add-Task "Optional: Disable Xbox services" {
  if (-not $Config.DisableXboxServices) {
    Log "DisableXboxServices disabled; skipping."
    return
  }

  Disable-Services -ServiceNames @(
    "XblAuthManager",
    "XblGameSave",
    "XboxGipSvc",
    "XboxNetApiSvc"
  )
}

Add-Task "Policy refresh (gpupdate)" {
  if ($Config.WhatIfOnly) {
    Log "WHATIF: gpupdate /force"
    return
  }
  & gpupdate /target:computer /force | Out-Null
  & gpupdate /target:user /force | Out-Null
  Log "Group Policy refresh completed."
}

Add-Task "Finalize: Reboot reminder" {
  Log "All tasks complete. Reboot is recommended to finalize removals/policy changes." "WARN"
  Write-ChangeLog "Reboot recommended to finalize changes."
}

# -------------------- RUN --------------------
try {
  Invoke-Tasks
  Log "Completed successfully."
} catch {
  Log "Script terminated due to an error. Check logs:" "ERROR"
  Log "  Full log:     $LogPath" "ERROR"
  Log "  Changes-only: $ChangeLogPath" "ERROR"
  throw
} finally {
  Stop-Transcript | Out-Null
  Write-Host ""
  Write-Host "Full log saved to:     $LogPath" -ForegroundColor Yellow
  Write-Host "Changes-only saved to: $ChangeLogPath" -ForegroundColor Yellow
  Write-Host "Transcript saved to:   $TranscriptPath" -ForegroundColor Yellow
  Write-Host "Reboot recommended." -ForegroundColor Yellow
}

}

Export-ModuleMember -Function Invoke-Win11ProMinimalist
