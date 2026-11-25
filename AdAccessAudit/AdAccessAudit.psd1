@{
    RootModule           = 'AdAccessAudit.psm1'
    ModuleVersion        = '1.0.0'
    GUID                 = '6f1c2b7e-3d4a-4b8e-9c21-5a7d0e8f4c13'
    Author               = 'Gabriel Souza'
    Copyright            = '(c) 2026 Gabriel Souza. MIT License.'
    Description          = 'Read-only Active Directory access audit: stale accounts, privileged groups, password and logon-hours risks in one HTML/CSV/JSON report. Includes an offline mode that works from a JSON snapshot.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @('Invoke-AdAccessAudit', 'Export-AdSnapshot')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags       = @('ActiveDirectory', 'Security', 'Audit', 'IAM', 'LGPD', 'Report')
            LicenseUri = 'https://github.com/gavicoding/ad-access-audit/blob/main/LICENSE'
            ProjectUri = 'https://github.com/gavicoding/ad-access-audit'
        }
    }
}
