function Get-AuditRuleCatalog {
    <#
    .SYNOPSIS
        Returns the catalog of audit rules (id, title, base severity, explanation, recommendation).
    .NOTES
        BaseSeverity applies to regular accounts. PrivilegedSeverity applies when the account is
        an enabled member of one of the privileged groups, because the same weakness on an
        administrator is a much bigger problem.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param()

    $catalog = [ordered]@{}

    $catalog['AAA001'] = [pscustomobject]@{
        RuleId             = 'AAA001'
        Name               = 'StaleAccount'
        Title              = 'Enabled account without logon for too long'
        BaseSeverity       = 'Medium'
        PrivilegedSeverity = 'Critical'
        Explanation        = 'The account is enabled but has not logged on for longer than the configured threshold. Forgotten accounts keep working credentials that nobody watches, which makes them a favorite target for password spraying and for people who already left.'
        Recommendation     = 'Confirm with the owner or manager whether the account is still needed. If not, disable it now and delete it after your retention period. For service accounts, prefer a gMSA.'
    }

    $catalog['AAA002'] = [pscustomobject]@{
        RuleId             = 'AAA002'
        Name               = 'PasswordNeverExpires'
        Title              = 'Password set to never expire'
        BaseSeverity       = 'Medium'
        PrivilegedSeverity = 'Critical'
        Explanation        = 'The account ignores the domain password policy. A password that leaked years ago keeps working, and nobody is forced to notice.'
        Recommendation     = 'Remove the "Password never expires" flag. For service accounts, move to a group Managed Service Account (gMSA) or rotate the password on a documented schedule.'
    }

    $catalog['AAA003'] = [pscustomobject]@{
        RuleId             = 'AAA003'
        Name               = 'PasswordTooOld'
        Title              = 'Password not changed for too long'
        BaseSeverity       = 'Low'
        PrivilegedSeverity = 'High'
        Explanation        = 'The password has not been changed for longer than the configured threshold. Old passwords are more likely to appear in leaks or to be shared informally.'
        Recommendation     = 'Ask the user to change the password, or force a change at next logon. Check whether a fine-grained password policy is exempting this account.'
    }

    $catalog['AAA004'] = [pscustomobject]@{
        RuleId             = 'AAA004'
        Name               = 'DisabledPrivileged'
        Title              = 'Disabled account still in a privileged group'
        BaseSeverity       = 'High'
        PrivilegedSeverity = 'High'
        Explanation        = 'The account is disabled but kept its administrative group membership. Anyone who re-enables it, by mistake or on purpose, instantly gets full privileges without any new approval.'
        Recommendation     = 'Remove the account from every privileged group as part of the offboarding process. Keep the removal in your change log.'
    }

    $catalog['AAA005'] = [pscustomobject]@{
        RuleId             = 'AAA005'
        Name               = 'PrivilegedMember'
        Title              = 'Member of a privileged group (review)'
        BaseSeverity       = 'Low'
        PrivilegedSeverity = 'Low'
        Explanation        = 'The account is an enabled member of a privileged group, directly or through nested groups. This is not wrong by itself, but every entry here should have a name, an owner and a reason.'
        Recommendation     = 'Review this list with the account owners at least every quarter. Use separate admin accounts for daily work and remove memberships that nobody can justify.'
    }

    $catalog['AAA006'] = [pscustomobject]@{
        RuleId             = 'AAA006'
        Name               = 'OrphanAdminCount'
        Title              = 'adminCount=1 without privileged membership'
        BaseSeverity       = 'Low'
        PrivilegedSeverity = 'Low'
        Explanation        = 'The account still has adminCount=1, a mark left by AdminSDHolder when it was in a protected group, but it is no longer in any of the audited privileged groups. Its permissions stay locked to the protected template and inheritance stays disabled, which hides delegation problems.'
        Recommendation     = 'Confirm the account is really out of every protected group, clear adminCount and re-enable permission inheritance on the object.'
    }

    $catalog['AAA007'] = [pscustomobject]@{
        RuleId             = 'AAA007'
        Name               = 'UnrestrictedLogonHours'
        Title              = 'Service or third-party account without logon hours'
        BaseSeverity       = 'Medium'
        PrivilegedSeverity = 'High'
        Explanation        = 'The account looks like a service or third-party account and can log on at any hour, any day. Supplier and contractor access is a common entry point, and an attack at 3 AM on a Sunday goes unnoticed for longer.'
        Recommendation     = 'Set logonHours to the agreed support window for third parties. For service accounts, deny interactive logon and restrict them to the servers they need (logonWorkstations, "Log on as a service" rights).'
    }

    $catalog['AAA008'] = [pscustomobject]@{
        RuleId             = 'AAA008'
        Name               = 'NeverLoggedOn'
        Title              = 'Account never used'
        BaseSeverity       = 'Medium'
        PrivilegedSeverity = 'High'
        Explanation        = 'The account is enabled, was created a while ago and has never logged on. It usually comes from a hiring that did not happen, a test or a forgotten request, and it often still has the initial password.'
        Recommendation     = 'Check whether the account is still expected. If not, disable and remove it. If it is, force a password change at next logon.'
    }

    return $catalog
}
