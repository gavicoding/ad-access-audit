function Export-AdSnapshot {
    <#
    .SYNOPSIS
        Exports users and privileged groups from Active Directory to a JSON snapshot. Read-only.

    .DESCRIPTION
        The snapshot can be audited later, on any machine, with
        Invoke-AdAccessAudit -InputJson. Useful when the auditor has no access to the domain,
        or to keep a point-in-time record of who had access.

        Only Get-AD* cmdlets are used. Nothing is changed in the directory.

    .PARAMETER Path
        JSON file to write.

    .PARAMETER PrivilegedGroups
        Groups to export with their (nested) members.

    .PARAMETER Server
        Domain controller or domain to query.

    .PARAMETER Credential
        Credential for the queries.

    .EXAMPLE
        Export-AdSnapshot -Path .\snapshot-2026-11.json
    #>
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [ValidateNotNullOrEmpty()]
        [string[]]$PrivilegedGroups = (Get-DefaultPrivilegedGroup),

        [string]$Server,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $snapshot = Get-AdLiveSnapshot -PrivilegedGroups $PrivilegedGroups -Server $Server -Credential $Credential
    $json = ConvertTo-Json -InputObject $snapshot -Depth 6
    $written = Write-AuditTextFile -Path $Path -Content $json
    return Get-Item -LiteralPath $written
}
