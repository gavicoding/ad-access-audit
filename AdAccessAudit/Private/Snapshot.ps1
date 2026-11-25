function ConvertTo-AuditDate {
    <#
    .SYNOPSIS
        Normalizes a date coming from JSON or from the AD module to a UTC DateTime (or $null).
    .NOTES
        Windows PowerShell 5.1 keeps ISO dates from ConvertFrom-Json as strings, while
        PowerShell 7 converts them to DateTime. Both paths end up here.
    #>
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter(Position = 0)]
        [AllowNull()]
        [object]$Value,

        [string]$FieldName = 'date'
    )

    if ($null -eq $Value) { return $null }

    if ($Value -is [datetime]) {
        switch ($Value.Kind) {
            'Utc' { return $Value }
            'Local' { return $Value.ToUniversalTime() }
            default { return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc) }
        }
    }

    if ($Value -is [System.DateTimeOffset]) { return $Value.UtcDateTime }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    $parsed = [datetime]::MinValue
    if ([datetime]::TryParse($text, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return [datetime]::SpecifyKind($parsed, [System.DateTimeKind]::Utc)
    }

    throw "Invalid value for '$FieldName': '$text'. Use ISO 8601, for example 2026-11-20T12:00:00Z."
}

function ConvertTo-AuditIsoString {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0)]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) { return $null }
    $date = ConvertTo-AuditDate -Value $Value
    if ($null -eq $date) { return $null }
    return $date.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-SnapshotValue {
    <#
    .SYNOPSIS
        Reads an optional property from a deserialized JSON object without tripping strict mode.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name,

        [object]$Default = $null
    )

    if ($null -eq $InputObject) { return $Default }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return $Default }
    return $property.Value
}

function ConvertTo-AuditSnapshot {
    <#
    .SYNOPSIS
        Validates and normalizes a raw snapshot object (from JSON or from the live AD reader).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [string]$Source = 'snapshot'
    )

    $usersProperty = $InputObject.PSObject.Properties['users']
    if ($null -eq $usersProperty -or $null -eq $usersProperty.Value) {
        throw "Invalid snapshot ($Source): property 'users' is missing."
    }
    $rawUsers = @($usersProperty.Value)

    $users = [System.Collections.Generic.List[object]]::new()
    $index = 0
    foreach ($raw in @($rawUsers)) {
        $index++
        $sam = [string](Get-SnapshotValue -InputObject $raw -Name 'samAccountName' -Default '')
        if ([string]::IsNullOrWhiteSpace($sam)) {
            throw "Invalid snapshot ($Source): user #$index has no samAccountName."
        }

        $spns = @(Get-SnapshotValue -InputObject $raw -Name 'servicePrincipalNames' -Default @()) |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            ForEach-Object { [string]$_ }

        $users.Add([pscustomobject]@{
                SamAccountName       = $sam
                DisplayName          = [string](Get-SnapshotValue -InputObject $raw -Name 'displayName' -Default $sam)
                DistinguishedName    = [string](Get-SnapshotValue -InputObject $raw -Name 'distinguishedName' -Default '')
                Enabled              = [bool](Get-SnapshotValue -InputObject $raw -Name 'enabled' -Default $false)
                WhenCreated          = ConvertTo-AuditDate -Value (Get-SnapshotValue -InputObject $raw -Name 'whenCreated') -FieldName "$sam.whenCreated"
                LastLogonDate        = ConvertTo-AuditDate -Value (Get-SnapshotValue -InputObject $raw -Name 'lastLogonDate') -FieldName "$sam.lastLogonDate"
                PasswordLastSet      = ConvertTo-AuditDate -Value (Get-SnapshotValue -InputObject $raw -Name 'passwordLastSet') -FieldName "$sam.passwordLastSet"
                PasswordNeverExpires = [bool](Get-SnapshotValue -InputObject $raw -Name 'passwordNeverExpires' -Default $false)
                AdminCount           = [int](Get-SnapshotValue -InputObject $raw -Name 'adminCount' -Default 0)
                Description          = [string](Get-SnapshotValue -InputObject $raw -Name 'description' -Default '')
                ServicePrincipalNames = [string[]]@($spns)
                LogonHours           = [string](Get-SnapshotValue -InputObject $raw -Name 'logonHours' -Default '')
            })
    }

    $groups = [System.Collections.Generic.List[object]]::new()
    foreach ($raw in @(Get-SnapshotValue -InputObject $InputObject -Name 'groups' -Default @())) {
        $name = [string](Get-SnapshotValue -InputObject $raw -Name 'name' -Default '')
        if ([string]::IsNullOrWhiteSpace($name)) {
            throw "Invalid snapshot ($Source): a group has no name."
        }

        $members = foreach ($member in @(Get-SnapshotValue -InputObject $raw -Name 'members' -Default @())) {
            if ($member -is [string]) {
                [pscustomobject]@{ Name = $member; ObjectClass = 'user' }
            }
            else {
                [pscustomobject]@{
                    Name        = [string](Get-SnapshotValue -InputObject $member -Name 'name' -Default '')
                    ObjectClass = ([string](Get-SnapshotValue -InputObject $member -Name 'objectClass' -Default 'user')).ToLowerInvariant()
                }
            }
        }

        $groups.Add([pscustomobject]@{
                Name              = $name
                Alias             = [string](Get-SnapshotValue -InputObject $raw -Name 'alias' -Default '')
                DistinguishedName = [string](Get-SnapshotValue -InputObject $raw -Name 'distinguishedName' -Default '')
                Members           = @($members | Where-Object { $_.Name })
            })
    }

    return [pscustomobject]@{
        SchemaVersion = [int](Get-SnapshotValue -InputObject $InputObject -Name 'schemaVersion' -Default 1)
        Domain        = [string](Get-SnapshotValue -InputObject $InputObject -Name 'domain' -Default 'unknown')
        GeneratedAt   = ConvertTo-AuditDate -Value (Get-SnapshotValue -InputObject $InputObject -Name 'generatedAt') -FieldName 'generatedAt'
        Users         = $users.ToArray()
        Groups        = $groups.ToArray()
    }
}

function Import-AuditSnapshot {
    <#
    .SYNOPSIS
        Reads a snapshot JSON file (offline mode).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Snapshot file not found: $Path"
    }

    $text = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $Path).ProviderPath, [System.Text.Encoding]::UTF8)
    try {
        $raw = $text | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Snapshot file is not valid JSON: $Path ($($_.Exception.Message))"
    }

    return ConvertTo-AuditSnapshot -InputObject $raw -Source $Path
}

function Test-UnrestrictedLogonHour {
    <#
    .SYNOPSIS
        True when logonHours is empty or allows all 168 hours of the week.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$LogonHours
    )

    if ([string]::IsNullOrWhiteSpace($LogonHours)) { return $true }

    try {
        $bytes = [System.Convert]::FromBase64String($LogonHours)
    }
    catch {
        throw "Invalid logonHours value (expected base64 of 21 bytes): '$LogonHours'"
    }

    if ($bytes.Length -ne 21) { return $true }
    foreach ($b in $bytes) {
        if ($b -ne 0xFF) { return $false }
    }
    return $true
}

function Write-AuditTextFile {
    <#
    .SYNOPSIS
        Writes UTF-8 text (no BOM) to a report file, creating the folder when needed.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Content
    )

    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $folder = [System.IO.Path]::GetDirectoryName($fullPath)
    if ($folder -and -not [System.IO.Directory]::Exists($folder)) {
        [void][System.IO.Directory]::CreateDirectory($folder)
    }
    [System.IO.File]::WriteAllText($fullPath, $Content, [System.Text.UTF8Encoding]::new($false))
    return $fullPath
}
