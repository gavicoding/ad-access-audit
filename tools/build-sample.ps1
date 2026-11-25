<#
.SYNOPSIS
    Rebuilds samples/snapshot-ficticio.json and docs/sample-report.html.
.DESCRIPTION
    Every account, group and name here is fictitious (domain exemplo.local).
    Run from the repository root: ./tools/build-sample.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dc = 'DC=exemplo,DC=local'

# Business hours (roughly 08:00 to 18:00, Monday to Friday) as a 21-byte logonHours mask.
$business = [byte[]](@(0, 0, 0) + (@(0, 0xFF, 0x03) * 5) + @(0, 0, 0))
$businessHours = [Convert]::ToBase64String($business)
$allHours = [Convert]::ToBase64String([byte[]](@(0xFF) * 21))

$user = {
    param(
        [string]$Sam,
        [string]$Name,
        [string]$Ou,
        [bool]$Enabled = $true,
        [string]$Created = '2024-03-01T12:00:00Z',
        [string]$LastLogon = '2026-11-18T09:12:00Z',
        [string]$PwdSet = '2026-09-01T10:00:00Z',
        [bool]$NeverExpires = $false,
        [int]$AdminCount = 0,
        [string]$Description = '',
        [string[]]$Spn = @(),
        [string]$LogonHours = $null
    )
    [ordered]@{
        samAccountName        = $Sam
        displayName           = $Name
        distinguishedName     = "CN=$Name,OU=$Ou,$dc"
        enabled               = $Enabled
        whenCreated           = $Created
        lastLogonDate         = $(if ($LastLogon) { $LastLogon } else { $null })
        passwordLastSet       = $(if ($PwdSet) { $PwdSet } else { $null })
        passwordNeverExpires  = $NeverExpires
        adminCount            = $AdminCount
        description           = $Description
        servicePrincipalNames = @($Spn)
        logonHours            = $(if ($LogonHours) { $LogonHours } else { $null })
    }
}

$users = @(
    # Built-in accounts
    (& $user -Sam 'Administrator' -Name 'Administrator' -Ou 'Builtin Users' -Created '2019-02-10T10:00:00Z' -PwdSet '2024-01-10T10:00:00Z' -AdminCount 1 -Description 'Built-in account for administering the domain')
    (& $user -Sam 'krbtgt' -Name 'krbtgt' -Ou 'Builtin Users' -Enabled $false -Created '2019-02-10T10:00:00Z' -LastLogon '' -PwdSet '2019-02-10T10:00:00Z' -AdminCount 1)
    (& $user -Sam 'Guest' -Name 'Guest' -Ou 'Builtin Users' -Enabled $false -Created '2019-02-10T10:00:00Z' -LastLogon '' -PwdSet '')

    # Administrators
    (& $user -Sam 'adm.carlos' -Name 'Carlos Exemplo (admin)' -Ou 'Admins' -AdminCount 1)
    (& $user -Sam 'adm.joana' -Name 'Joana Teste (admin)' -Ou 'Admins' -Enabled $false -LastLogon '2026-02-03T08:00:00Z' -AdminCount 1 -Description 'Desligada em fev/2026')
    (& $user -Sam 'adm.rafael' -Name 'Rafael Modelo (admin)' -Ou 'Admins' -NeverExpires $true -PwdSet '2023-05-15T10:00:00Z' -AdminCount 1)
    (& $user -Sam 'adm.paulo' -Name 'Paulo Amostra (admin)' -Ou 'Admins' -LastLogon '2026-05-02T14:30:00Z' -PwdSet '2026-04-01T10:00:00Z' -AdminCount 1)
    (& $user -Sam 'helpdesk.lucas' -Name 'Lucas Ficticio (helpdesk)' -Ou 'Admins' -AdminCount 1)
    (& $user -Sam 'old.admin.tiago' -Name 'Tiago Exemplo' -Ou 'Users' -AdminCount 1 -Description 'Ex-administrador, hoje no financeiro')

    # Service accounts
    (& $user -Sam 'svc.backup' -Name 'svc.backup' -Ou 'Service Accounts' -Created '2021-06-01T10:00:00Z' -NeverExpires $true -PwdSet '2021-06-01T10:00:00Z' -AdminCount 1 -Description 'Conta de servico do backup noturno')
    (& $user -Sam 'svc.sql' -Name 'svc.sql' -Ou 'Service Accounts' -Created '2022-01-20T10:00:00Z' -NeverExpires $true -PwdSet '2022-01-20T10:00:00Z' -Spn @('MSSQLSvc/sql01.exemplo.local:1433') -Description 'SQL Server do sistema interno')
    (& $user -Sam 'svc.web' -Name 'svc.web' -Ou 'Service Accounts' -Created '2023-03-01T10:00:00Z' -PwdSet '2026-08-01T10:00:00Z' -LogonHours $businessHours -Description 'Pool da intranet')
    (& $user -Sam 'svc.print' -Name 'svc.print' -Ou 'Service Accounts' -Created '2020-09-01T10:00:00Z' -PwdSet '2023-02-01T10:00:00Z' -LogonHours $allHours -Description 'Servidor de impressao')
    (& $user -Sam 'svc.monitor' -Name 'svc.monitor' -Ou 'Service Accounts' -Created '2024-07-01T10:00:00Z' -PwdSet '2026-07-01T10:00:00Z' -LogonHours $businessHours -Description 'Coleta de metricas')

    # Third parties
    (& $user -Sam 'ext.consultoria' -Name 'Consultoria Exemplo' -Ou 'Third Parties' -Created '2026-09-01T10:00:00Z' -PwdSet '2026-09-01T10:00:00Z' -Description 'Terceiro: Empresa Exemplo Ltda')
    (& $user -Sam 'ext.suporte' -Name 'Suporte Externo Teste' -Ou 'Third Parties' -Created '2025-04-01T10:00:00Z' -PwdSet '2026-10-01T10:00:00Z' -LogonHours $businessHours -Description 'Prestador de suporte, horario comercial')
    (& $user -Sam 'vnd.erp' -Name 'Fornecedor ERP' -Ou 'Third Parties' -Created '2024-02-01T10:00:00Z' -LastLogon '2026-03-10T16:00:00Z' -PwdSet '2026-01-10T10:00:00Z' -Description 'Fornecedor do ERP')
    (& $user -Sam 'joao.prestador' -Name 'Joao Teste' -Ou 'Third Parties' -Created '2025-10-01T10:00:00Z' -PwdSet '2026-10-15T10:00:00Z' -LogonHours $businessHours -Description 'Prestador de servico (contrato 2026)')

    # Former employees
    (& $user -Sam 'ex.marcos' -Name 'Marcos Modelo' -Ou 'Disabled' -Enabled $false -LastLogon '2026-01-20T17:00:00Z' -AdminCount 1)
    (& $user -Sam 'ex.fernanda' -Name 'Fernanda Amostra' -Ou 'Disabled' -Enabled $false -LastLogon '2025-12-01T17:00:00Z' -AdminCount 1)
    (& $user -Sam 'ex.renato' -Name 'Renato Exemplo' -Ou 'Disabled' -Enabled $false -LastLogon '2025-08-01T17:00:00Z')

    # Regular users with problems
    (& $user -Sam 'maria.teste' -Name 'Maria Teste' -Ou 'Users' -LastLogon '2026-06-01T08:30:00Z')
    (& $user -Sam 'estagio.bia' -Name 'Beatriz Modelo' -Ou 'Users' -LastLogon '2026-04-15T08:30:00Z' -NeverExpires $true -PwdSet '2025-02-01T10:00:00Z')
    (& $user -Sam 'joao.exemplo' -Name 'Joao Exemplo' -Ou 'Users' -Created '2026-08-01T10:00:00Z' -LastLogon '' -PwdSet '2026-08-01T10:00:00Z')
    (& $user -Sam 'teste.sistema' -Name 'Teste Sistema' -Ou 'Users' -Created '2025-03-01T10:00:00Z' -LastLogon '' -PwdSet '2025-03-01T10:00:00Z' -Description 'Conta de teste')
    (& $user -Sam 'pedro.modelo' -Name 'Pedro Modelo' -Ou 'Users' -PwdSet '2025-06-01T10:00:00Z')
    (& $user -Sam 'lucia.amostra' -Name 'Lucia Amostra' -Ou 'Users' -NeverExpires $true -PwdSet '2026-01-05T10:00:00Z')
    (& $user -Sam 'recepcao' -Name 'Recepcao' -Ou 'Users' -Created '2020-01-10T10:00:00Z' -NeverExpires $true -PwdSet '2020-01-10T10:00:00Z' -Description 'Conta compartilhada da recepcao')

    # Recent account that never logged on yet (still inside the 30 day window, no finding)
    (& $user -Sam 'nova.contratada' -Name 'Nova Contratada' -Ou 'Users' -Created '2026-11-10T10:00:00Z' -LastLogon '' -PwdSet '2026-11-10T10:00:00Z')

    # Clean accounts
    (& $user -Sam 'ana.exemplo' -Name 'Ana Exemplo' -Ou 'Users')
    (& $user -Sam 'bruno.teste' -Name 'Bruno Teste' -Ou 'Users' -LastLogon '2026-11-19T08:01:00Z')
    (& $user -Sam 'camila.modelo' -Name 'Camila Modelo' -Ou 'Users' -PwdSet '2026-06-20T10:00:00Z')
    (& $user -Sam 'diego.amostra' -Name 'Diego Amostra' -Ou 'Users' -LastLogon '2026-11-17T13:45:00Z')
    (& $user -Sam 'elisa.exemplo' -Name 'Elisa Exemplo' -Ou 'Users' -PwdSet '2026-03-10T10:00:00Z')
    (& $user -Sam 'fabio.teste' -Name 'Fabio Teste' -Ou 'Users' -LastLogon '2026-10-30T09:00:00Z')
    (& $user -Sam 'gabriela.modelo' -Name 'Gabriela Modelo' -Ou 'Users')
    (& $user -Sam 'heitor.amostra' -Name 'Heitor Amostra' -Ou 'Users' -PwdSet '2026-10-02T10:00:00Z')
    (& $user -Sam 'ines.exemplo' -Name 'Ines Exemplo' -Ou 'Users' -LastLogon '2026-09-15T11:20:00Z')
    (& $user -Sam 'julio.teste' -Name 'Julio Teste' -Ou 'Users')
    (& $user -Sam 'karen.modelo' -Name 'Karen Modelo' -Ou 'Users' -LastLogon '2026-11-20T07:55:00Z')
)

$group = {
    param([string]$Name, [object[]]$Members, [string]$Ou = 'Users')
    [ordered]@{
        name              = $Name
        alias             = ''
        distinguishedName = "CN=$Name,CN=$Ou,$dc"
        members           = @($Members | ForEach-Object {
                if ($_ -like 'group:*') { [ordered]@{ name = $_.Substring(6); objectClass = 'group' } }
                else { [ordered]@{ name = $_; objectClass = 'user' } }
            })
    }
}

$groups = @(
    (& $group 'Domain Admins' @('Administrator', 'adm.carlos', 'adm.joana', 'adm.paulo', 'group:GG-TI-Admins'))
    (& $group 'Enterprise Admins' @('Administrator'))
    (& $group 'Schema Admins' @('Administrator'))
    (& $group 'Administrators' @('Administrator', 'group:Domain Admins', 'group:Enterprise Admins', 'svc.backup') 'Builtin')
    (& $group 'Account Operators' @('helpdesk.lucas') 'Builtin')
    (& $group 'Backup Operators' @('svc.backup', 'ex.marcos') 'Builtin')
    (& $group 'Server Operators' @() 'Builtin')
    (& $group 'GG-TI-Admins' @('adm.rafael', 'group:GG-TI-Plantao'))
    (& $group 'GG-TI-Plantao' @('adm.carlos', 'group:GG-TI-Admins'))
)

$snapshot = [ordered]@{
    schemaVersion = 1
    domain        = 'exemplo.local'
    generatedAt   = '2026-11-20T12:00:00Z'
    users         = $users
    groups        = $groups
}

$utf8 = [System.Text.UTF8Encoding]::new($false)
$samplePath = Join-Path $root 'samples/snapshot-ficticio.json'
[System.IO.File]::WriteAllText($samplePath, (ConvertTo-Json -InputObject $snapshot -Depth 6), $utf8)
Write-Output "Wrote $samplePath ($($users.Count) users, $($groups.Count) groups)"

Import-Module (Join-Path $root 'AdAccessAudit/AdAccessAudit.psd1') -Force
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('aaa-' + [guid]::NewGuid().ToString('N'))
$result = Invoke-AdAccessAudit -InputJson $samplePath -OutputPath $tmp -Format Html
$html = [System.IO.File]::ReadAllText($result.Files[0])
[System.IO.File]::WriteAllText((Join-Path $root 'docs/sample-report.html'), $html, $utf8)
Remove-Item -LiteralPath $tmp -Recurse -Force
Write-Output ("Wrote docs/sample-report.html ({0} findings: {1})" -f $result.Findings.Count, (($result.Summary.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '))
