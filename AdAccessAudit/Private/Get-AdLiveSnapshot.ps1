function Get-DefaultPrivilegedGroup {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    return @(
        'Domain Admins',
        'Enterprise Admins',
        'Schema Admins',
        'Administrators',
        'Account Operators',
        'Backup Operators',
        'Server Operators'
    )
}

function Get-WellKnownGroupSid {
    <#
    .SYNOPSIS
        Returns the well-known SID of a default privileged group, so the audit also works
        on domains installed in other languages (where "Domain Admins" has another name).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$DomainSid
    )

    switch ($Name) {
        'Domain Admins' { return "$DomainSid-512" }
        'Schema Admins' { return "$DomainSid-518" }
        'Enterprise Admins' { return "$DomainSid-519" }
        'Administrators' { return 'S-1-5-32-544' }
        'Account Operators' { return 'S-1-5-32-548' }
        'Server Operators' { return 'S-1-5-32-549' }
        'Backup Operators' { return 'S-1-5-32-551' }
        default { return $null }
    }
}

function Get-AdLiveSnapshot {
    <#
    .SYNOPSIS
        Reads users and privileged groups from Active Directory. Read-only: Get-AD* cmdlets only.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string[]]$PrivilegedGroups = (Get-DefaultPrivilegedGroup),

        [string]$Server,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw 'The ActiveDirectory module (RSAT) is not installed. Install RSAT or use -InputJson with a snapshot exported elsewhere.'
    }
    Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false

    $adParams = @{}
    if ($Server) { $adParams['Server'] = $Server }
    if ($Credential -and $Credential -ne [System.Management.Automation.PSCredential]::Empty) { $adParams['Credential'] = $Credential }

    $domain = Get-ADDomain @adParams -ErrorAction Stop
    $domainSid = $domain.DomainSID.Value

    $properties = @(
        'DisplayName', 'Enabled', 'LastLogonDate', 'WhenCreated', 'PasswordLastSet',
        'PasswordNeverExpires', 'adminCount', 'Description', 'servicePrincipalName', 'logonHours'
    )

    Write-Verbose "Reading users from $($domain.DNSRoot)"
    $adUsers = @(Get-ADUser -Filter * -Properties $properties @adParams -ErrorAction Stop)

    $usersByDn = @{}
    $users = foreach ($u in $adUsers) {
        $usersByDn[$u.DistinguishedName] = $u.SamAccountName
        $logonHours = $null
        if ($u.logonHours) { $logonHours = [System.Convert]::ToBase64String([byte[]]$u.logonHours) }

        [ordered]@{
            samAccountName        = $u.SamAccountName
            displayName           = $u.DisplayName
            distinguishedName     = $u.DistinguishedName
            enabled               = [bool]$u.Enabled
            whenCreated           = ConvertTo-AuditIsoString $u.WhenCreated
            lastLogonDate         = ConvertTo-AuditIsoString $u.LastLogonDate
            passwordLastSet       = ConvertTo-AuditIsoString $u.PasswordLastSet
            passwordNeverExpires  = [bool]$u.PasswordNeverExpires
            adminCount            = [int]$u.adminCount
            description           = $u.Description
            servicePrincipalNames = @($u.servicePrincipalName | ForEach-Object { [string]$_ })
            logonHours            = $logonHours
        }
    }

    # Walk the privileged groups and every nested group below them.
    $groups = [ordered]@{}
    $queue = [System.Collections.Generic.Queue[object]]::new()
    foreach ($name in $PrivilegedGroups) {
        $group = $null
        try {
            $group = Get-ADGroup -Identity $name -Properties member @adParams -ErrorAction Stop
        }
        catch {
            $sid = Get-WellKnownGroupSid -Name $name -DomainSid $domainSid
            if ($sid) {
                try { $group = Get-ADGroup -Identity $sid -Properties member @adParams -ErrorAction Stop } catch { $group = $null }
            }
        }

        if ($null -eq $group) {
            Write-Warning "Privileged group not found: '$name'. It will be skipped."
            continue
        }
        $queue.Enqueue([pscustomobject]@{ Group = $group; Alias = $name })
    }

    while ($queue.Count -gt 0) {
        $item = $queue.Dequeue()
        $group = $item.Group
        if ($groups.Contains($group.DistinguishedName)) { continue }

        $members = foreach ($memberDn in @($group.member)) {
            if ($usersByDn.ContainsKey($memberDn)) {
                [ordered]@{ name = $usersByDn[$memberDn]; objectClass = 'user' }
                continue
            }

            $nested = $null
            try { $nested = Get-ADGroup -Identity $memberDn -Properties member @adParams -ErrorAction Stop } catch { $nested = $null }
            if ($nested) {
                $queue.Enqueue([pscustomobject]@{ Group = $nested; Alias = '' })
                [ordered]@{ name = $nested.Name; objectClass = 'group' }
            }
            else {
                $cn = ($memberDn -split ',')[0] -replace '^CN=', ''
                [ordered]@{ name = $cn; objectClass = 'other' }
            }
        }

        $alias = ''
        if ($item.Alias -and $item.Alias -ne $group.Name) { $alias = $item.Alias }

        $groups[$group.DistinguishedName] = [ordered]@{
            name              = $group.Name
            alias             = $alias
            distinguishedName = $group.DistinguishedName
            members           = @($members)
        }
    }

    return [pscustomobject]@{
        schemaVersion = 1
        domain        = $domain.DNSRoot
        generatedAt   = ConvertTo-AuditIsoString ([datetime]::UtcNow)
        users         = @($users)
        groups        = @($groups.Values)
    }
}
