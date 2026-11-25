function Resolve-PrivilegedMembership {
    <#
    .SYNOPSIS
        Expands the privileged groups (including nested groups) and returns a map
        samAccountName -> list of privileged groups the user belongs to.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Groups,

        [Parameter(Mandatory)]
        [string[]]$PrivilegedGroups
    )

    $byName = @{}
    foreach ($group in $Groups) {
        $byName[$group.Name] = $group
        if ($group.Alias -and -not $byName.ContainsKey($group.Alias)) { $byName[$group.Alias] = $group }
    }

    $membership = @{}
    foreach ($privileged in $PrivilegedGroups) {
        if (-not $byName.ContainsKey($privileged)) { continue }

        $visited = @{}
        $stack = [System.Collections.Generic.Stack[object]]::new()
        $stack.Push($byName[$privileged])

        while ($stack.Count -gt 0) {
            $group = $stack.Pop()
            if ($visited.ContainsKey($group.Name)) { continue }
            $visited[$group.Name] = $true

            foreach ($member in $group.Members) {
                if ($member.ObjectClass -eq 'group') {
                    if ($byName.ContainsKey($member.Name)) { $stack.Push($byName[$member.Name]) }
                    continue
                }
                if ($member.ObjectClass -ne 'user') { continue }

                if (-not $membership.ContainsKey($member.Name)) {
                    $membership[$member.Name] = [System.Collections.Generic.List[string]]::new()
                }
                if (-not $membership[$member.Name].Contains($privileged)) {
                    $membership[$member.Name].Add($privileged)
                }
            }
        }
    }

    return $membership
}

function Get-SeverityRank {
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)][string]$Severity)

    switch ($Severity) {
        'Critical' { return 0 }
        'High' { return 1 }
        'Medium' { return 2 }
        'Low' { return 3 }
        default { return 9 }
    }
}

function Get-AuditFinding {
    <#
    .SYNOPSIS
        Runs every rule over a normalized snapshot and returns the findings, sorted by severity.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Snapshot,

        [Parameter(Mandatory)]
        [datetime]$ReferenceDate,

        [int]$StaleDays = 90,
        [int]$PasswordAgeDays = 365,
        [int]$NeverLoggedOnDays = 30,
        [string[]]$PrivilegedGroups = (Get-DefaultPrivilegedGroup),
        [string]$ServiceAccountPattern = '(?i)^(svc|srv|sa)[-_.]|\bservice account\b|\bconta de servi.o\b',
        [string]$ThirdPartyPattern = '(?i)^(ext|terc|vnd|vendor)[-_.]|\b(terceiro|terceirizado|fornecedor|prestador|vendor|contractor|third[- ]party)\b'
    )

    $catalog = Get-AuditRuleCatalog
    $membership = Resolve-PrivilegedMembership -Groups @($Snapshot.Groups) -PrivilegedGroups $PrivilegedGroups
    $findings = [System.Collections.Generic.List[object]]::new()
    $now = ConvertTo-AuditDate -Value $ReferenceDate

    $newFinding = {
        param($RuleId, $Entry, $Detail, [string[]]$Groups, [bool]$Privileged)

        $rule = $catalog[$RuleId]
        $severity = $rule.BaseSeverity
        if ($Privileged) { $severity = $rule.PrivilegedSeverity }

        [pscustomobject]@{
            Severity         = $severity
            RuleId           = $rule.RuleId
            Rule             = $rule.Name
            Title            = $rule.Title
            Account          = $Entry.SamAccountName
            DisplayName      = $Entry.DisplayName
            Enabled          = $Entry.Enabled
            PrivilegedGroups = @($Groups)
            Detail           = $Detail
            Explanation      = $rule.Explanation
            Recommendation   = $rule.Recommendation
        }
    }

    foreach ($user in $Snapshot.Users) {
        $sam = $user.SamAccountName
        $groups = @()
        if ($membership.ContainsKey($sam)) { $groups = @($membership[$sam].ToArray()) }
        $isPrivileged = $groups.Count -gt 0
        $escalate = $isPrivileged -and $user.Enabled

        if ($user.Enabled) {
            # AAA001: enabled account without logon for more than StaleDays.
            if ($null -ne $user.LastLogonDate) {
                $idle = [int][math]::Floor(($now - $user.LastLogonDate).TotalDays)
                if ($idle -gt $StaleDays) {
                    $findings.Add((& $newFinding 'AAA001' $user ("Last logon {0:yyyy-MM-dd} ({1} days ago, threshold {2})." -f $user.LastLogonDate, $idle, $StaleDays) $groups $escalate))
                }
            }

            # AAA008: never logged on and created more than NeverLoggedOnDays ago.
            if ($null -eq $user.LastLogonDate -and $null -ne $user.WhenCreated) {
                $age = [int][math]::Floor(($now - $user.WhenCreated).TotalDays)
                if ($age -gt $NeverLoggedOnDays) {
                    $findings.Add((& $newFinding 'AAA008' $user ("Created {0:yyyy-MM-dd} ({1} days ago) and never logged on." -f $user.WhenCreated, $age) $groups $escalate))
                }
            }

            # AAA002 / AAA003: password policy.
            $pwdAge = $null
            if ($null -ne $user.PasswordLastSet) {
                $pwdAge = [int][math]::Floor(($now - $user.PasswordLastSet).TotalDays)
            }

            if ($user.PasswordNeverExpires) {
                $detail = 'Password never expires.'
                if ($null -ne $pwdAge) { $detail = "Password never expires. Last change {0:yyyy-MM-dd} ({1} days ago)." -f $user.PasswordLastSet, $pwdAge }
                $findings.Add((& $newFinding 'AAA002' $user $detail $groups $escalate))
            }
            elseif ($null -ne $pwdAge -and $pwdAge -gt $PasswordAgeDays) {
                $findings.Add((& $newFinding 'AAA003' $user ("Last password change {0:yyyy-MM-dd} ({1} days ago, threshold {2})." -f $user.PasswordLastSet, $pwdAge, $PasswordAgeDays) $groups $escalate))
            }

            # AAA007: service or third-party account without logon hours.
            $kind = $null
            if ($user.ServicePrincipalNames.Count -gt 0 -or $sam -match $ServiceAccountPattern -or $user.Description -match $ServiceAccountPattern) {
                $kind = 'Service account'
            }
            elseif ($sam -match $ThirdPartyPattern -or $user.Description -match $ThirdPartyPattern) {
                $kind = 'Third-party account'
            }
            if ($kind -and (Test-UnrestrictedLogonHour -LogonHours $user.LogonHours)) {
                $findings.Add((& $newFinding 'AAA007' $user "$kind with no logonHours restriction (allowed 24x7)." $groups $escalate))
            }

            # AAA005: privileged membership, for review.
            if ($isPrivileged) {
                $findings.Add((& $newFinding 'AAA005' $user ('Member of: {0}.' -f ($groups -join ', ')) $groups $false))
            }
        }
        elseif ($isPrivileged) {
            # AAA004: disabled account still in a privileged group.
            $findings.Add((& $newFinding 'AAA004' $user ('Disabled, still member of: {0}.' -f ($groups -join ', ')) $groups $false))
        }

        # AAA006: adminCount=1 without privileged membership (krbtgt is expected to have it).
        if ($user.AdminCount -eq 1 -and -not $isPrivileged -and $sam -ne 'krbtgt') {
            $state = 'an enabled'
            if (-not $user.Enabled) { $state = 'a disabled' }
            $findings.Add((& $newFinding 'AAA006' $user "adminCount=1 on $state account that is not in any audited privileged group." $groups $false))
        }
    }

    $sorted = $findings |
        Sort-Object -Property @{ Expression = { Get-SeverityRank -Severity $_.Severity } }, RuleId, Account

    return @($sorted)
}
