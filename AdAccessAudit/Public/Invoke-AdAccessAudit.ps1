function Invoke-AdAccessAudit {
    <#
    .SYNOPSIS
        Audits Active Directory accounts and writes an HTML/CSV/JSON report. Read-only.

    .DESCRIPTION
        Looks for stale accounts, passwords that never expire or are too old, disabled accounts
        still in privileged groups, privileged members to review, orphan adminCount=1, service
        or third-party accounts without logon hours and accounts that never logged on.

        The function never changes anything in the directory: it only uses Get-AD* cmdlets.
        With -InputJson it works fully offline from a snapshot created by Export-AdSnapshot.

    .PARAMETER StaleDays
        Enabled accounts without logon for more than this many days are reported. Default 90.

    .PARAMETER PasswordAgeDays
        Passwords older than this many days are reported. Default 365.

    .PARAMETER NeverLoggedOnDays
        Accounts that never logged on are reported once they are older than this. Default 30.

    .PARAMETER PrivilegedGroups
        Groups considered privileged. Nested groups are expanded.

    .PARAMETER OutputPath
        Folder for the report files. When omitted, no file is written and only the result
        object is returned.

    .PARAMETER Format
        One or more of Html, Csv, Json. Default: all three.

    .PARAMETER InputJson
        Snapshot file to audit instead of querying Active Directory (offline mode).

    .PARAMETER ReferenceDate
        Date used as "now" for the age calculations. Defaults to the snapshot generatedAt in
        offline mode and to the current UTC time in live mode.

    .PARAMETER ServiceAccountPattern
        Regex (on samAccountName or description) that identifies service accounts. Accounts
        with a servicePrincipalName are always treated as service accounts.

    .PARAMETER ThirdPartyPattern
        Regex (on samAccountName or description) that identifies third-party accounts.

    .PARAMETER Server
        Domain controller or domain to query in live mode.

    .PARAMETER Credential
        Credential for the live queries. Any regular domain user can read these attributes.

    .EXAMPLE
        Invoke-AdAccessAudit -InputJson .\samples\snapshot-ficticio.json -OutputPath .\out

    .EXAMPLE
        Invoke-AdAccessAudit -StaleDays 60 -OutputPath C:\Audits\2026-11 -Format Html,Csv
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [ValidateRange(1, 3650)]
        [int]$StaleDays = 90,

        [ValidateRange(1, 3650)]
        [int]$PasswordAgeDays = 365,

        [ValidateRange(1, 3650)]
        [int]$NeverLoggedOnDays = 30,

        [ValidateNotNullOrEmpty()]
        [string[]]$PrivilegedGroups = (Get-DefaultPrivilegedGroup),

        [string]$OutputPath,

        [ValidateSet('Html', 'Csv', 'Json')]
        [string[]]$Format = @('Html', 'Csv', 'Json'),

        [string]$InputJson,

        [datetime]$ReferenceDate,

        [ValidateNotNullOrEmpty()]
        [string]$ServiceAccountPattern = '(?i)^(svc|srv|sa)[-_.]|\bservice account\b|\bconta de servi.o\b',

        [ValidateNotNullOrEmpty()]
        [string]$ThirdPartyPattern = '(?i)^(ext|terc|vnd|vendor)[-_.]|\b(terceiro|terceirizado|fornecedor|prestador|vendor|contractor|third[- ]party)\b',

        [string]$Server,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    foreach ($pattern in $ServiceAccountPattern, $ThirdPartyPattern) {
        try { [void][regex]::new($pattern) }
        catch { throw "Invalid regular expression '$pattern': $($_.Exception.Message)" }
    }

    if ($InputJson) {
        $snapshot = Import-AuditSnapshot -Path $InputJson
        $source = 'Offline mode, snapshot file {0}' -f [System.IO.Path]::GetFileName($InputJson)
    }
    else {
        $raw = Get-AdLiveSnapshot -PrivilegedGroups $PrivilegedGroups -Server $Server -Credential $Credential
        $snapshot = ConvertTo-AuditSnapshot -InputObject $raw -Source 'Active Directory'
        $source = 'Live query of Active Directory'
        if ($Server) { $source = "$source ($Server)" }
    }

    if ($PSBoundParameters.ContainsKey('ReferenceDate')) {
        $refDate = ConvertTo-AuditDate -Value $ReferenceDate
    }
    elseif ($null -ne $snapshot.GeneratedAt) {
        $refDate = $snapshot.GeneratedAt
    }
    else {
        $refDate = [datetime]::UtcNow
    }

    $findingParams = @{
        Snapshot              = $snapshot
        ReferenceDate         = $refDate
        StaleDays             = $StaleDays
        PasswordAgeDays       = $PasswordAgeDays
        NeverLoggedOnDays     = $NeverLoggedOnDays
        PrivilegedGroups      = $PrivilegedGroups
        ServiceAccountPattern = $ServiceAccountPattern
        ThirdPartyPattern     = $ThirdPartyPattern
    }
    $findings = @(Get-AuditFinding @findingParams)

    $summary = [ordered]@{ Critical = 0; High = 0; Medium = 0; Low = 0 }
    foreach ($f in $findings) { $summary[$f.Severity]++ }

    $moduleVersion = '1.0.0'
    if ($MyInvocation.MyCommand.Module) { $moduleVersion = [string]$MyInvocation.MyCommand.Module.Version }

    $result = [pscustomobject]@{
        Domain          = $snapshot.Domain
        ReferenceDate   = ConvertTo-AuditIsoString $refDate
        GeneratedAt     = ConvertTo-AuditIsoString ([datetime]::UtcNow)
        Source          = $source
        ToolVersion     = $moduleVersion
        AccountsScanned = @($snapshot.Users).Count
        Parameters      = [ordered]@{
            StaleDays         = $StaleDays
            PasswordAgeDays   = $PasswordAgeDays
            NeverLoggedOnDays = $NeverLoggedOnDays
            PrivilegedGroups  = @($PrivilegedGroups)
        }
        Summary         = $summary
        Findings        = $findings
        Files           = @()
    }

    if ($OutputPath) {
        $stamp = $refDate.ToString('yyyyMMdd', [System.Globalization.CultureInfo]::InvariantCulture)
        $safeDomain = ($snapshot.Domain -replace '[^A-Za-z0-9._-]', '_')
        $baseName = "ad-access-audit-$safeDomain-$stamp"
        $files = [System.Collections.Generic.List[string]]::new()

        if ($Format -contains 'Html') {
            $files.Add((Write-AuditTextFile -Path (Join-Path $OutputPath "$baseName.html") -Content (ConvertTo-AuditHtml -Result $result)))
        }

        if ($Format -contains 'Csv') {
            $csvRows = foreach ($f in $findings) {
                [pscustomobject]@{
                    Severity         = $f.Severity
                    RuleId           = $f.RuleId
                    Rule             = $f.Rule
                    Title            = $f.Title
                    Account          = $f.Account
                    DisplayName      = $f.DisplayName
                    Enabled          = $f.Enabled
                    PrivilegedGroups = (@($f.PrivilegedGroups) -join '; ')
                    Detail           = $f.Detail
                    Recommendation   = $f.Recommendation
                }
            }
            $csvText = ''
            if ($csvRows) { $csvText = (@($csvRows) | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine }
            else { $csvText = '"Severity","RuleId","Rule","Title","Account","DisplayName","Enabled","PrivilegedGroups","Detail","Recommendation"' }
            $files.Add((Write-AuditTextFile -Path (Join-Path $OutputPath "$baseName.csv") -Content ($csvText + [Environment]::NewLine)))
        }

        if ($Format -contains 'Json') {
            $jsonObject = [ordered]@{
                domain          = $result.Domain
                referenceDate   = $result.ReferenceDate
                generatedAt     = $result.GeneratedAt
                source          = $result.Source
                toolVersion     = $result.ToolVersion
                accountsScanned = $result.AccountsScanned
                parameters      = $result.Parameters
                summary         = $result.Summary
                findings        = @($findings)
            }
            $json = ConvertTo-Json -InputObject $jsonObject -Depth 6
            $files.Add((Write-AuditTextFile -Path (Join-Path $OutputPath "$baseName.json") -Content $json))
        }

        $result.Files = $files.ToArray()
    }

    return $result
}
