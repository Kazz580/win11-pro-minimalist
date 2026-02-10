@{
  RootModule        = 'Win11ProMinimalist.psm1'
  ModuleVersion     = '1.4.0'
  GUID              = 'd9c4f7a5-3d4e-4f3a-9d3b-6a8d5a8b5f1b'
  Author            = 'Kazz'
  CompanyName       = 'Personal'
  Copyright         = '(c) 2026. All rights reserved.'
  Description       = 'Conservative Windows 11 Pro debloat + policy hardening with full and changes-only logs.'
  PowerShellVersion = '5.1'
  CompatiblePSEditions = @('Desktop','Core')
  FunctionsToExport = @('Invoke-Win11ProMinimalist')
  CmdletsToExport   = @()
  VariablesToExport = @()
  AliasesToExport   = @()
  PrivateData = @{
    PSData = @{
      Tags = @('windows11','debloat','hardening','policy','appx','logging')
      ProjectUri = ''
      LicenseUri = ''
      ReleaseNotes = 'See CHANGELOG.md'
    }
  }
}
