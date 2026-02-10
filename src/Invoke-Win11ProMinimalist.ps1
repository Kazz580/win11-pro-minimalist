#Requires -RunAsAdministrator
Set-ExecutionPolicy Bypass -Scope Process -Force | Out-Null

$modulePath = Join-Path $PSScriptRoot 'Win11ProMinimalist'
Import-Module $modulePath -Force

# Run with defaults (same behavior as module defaults)
Invoke-Win11ProMinimalist
