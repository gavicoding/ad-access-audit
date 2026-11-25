#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $script:repoRoot = Split-Path -Parent $PSScriptRoot
    $script:moduleRoot = Join-Path $repoRoot 'AdAccessAudit'
    $script:samplePath = Join-Path $repoRoot 'samples/snapshot-ficticio.json'
    Import-Module (Join-Path $moduleRoot 'AdAccessAudit.psd1') -Force

    $script:result = Invoke-AdAccessAudit -InputJson $samplePath

    function Get-Hit {
        param([string]$RuleId, [string]$Account)
        @($script:result.Findings | Where-Object { $_.RuleId -eq $RuleId -and $_.Account -eq $Account })
    }

    function Invoke-WithSnapshot {
        param([hashtable]$Snapshot, [hashtable]$Parameters = @{})
        $path = Join-Path $TestDrive ('snap-' + [guid]::NewGuid().ToString('N') + '.json')
        [System.IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject $Snapshot -Depth 6))
        Invoke-AdAccessAudit -InputJson $path @Parameters
    }

    function Get-BaseUser {
        param([hashtable]$Override = @{})
        $u = [ordered]@{
            samAccountName       = 'user.base'
            displayName          = 'User Base'
            enabled              = $true
            whenCreated          = '2025-01-01T00:00:00Z'
            lastLogonDate        = '2026-11-19T00:00:00Z'
            passwordLastSet      = '2026-10-01T00:00:00Z'
            passwordNeverExpires = $false
            adminCount           = 0
            description          = ''
        }
        foreach ($k in $Override.Keys) { $u[$k] = $Override[$k] }
        $u
    }
}

Describe 'Module surface' {
    It 'exports only the two public commands' {
        $names = (Get-Command -Module AdAccessAudit).Name | Sort-Object
        $names | Should -Be @('Export-AdSnapshot', 'Invoke-AdAccessAudit')
    }

    It 'has the documented defaults' {
        $cmd = Get-Command Invoke-AdAccessAudit
        foreach ($p in 'StaleDays', 'PasswordAgeDays', 'PrivilegedGroups', 'OutputPath', 'Format', 'InputJson') {
            $cmd.Parameters.Keys | Should -Contain $p
        }
        $cmd.Parameters['Format'].Attributes.ValidValues | Should -Be @('Html', 'Csv', 'Json')
    }
}

Describe 'Read-only guarantee' {
    BeforeAll {
        $files = Get-ChildItem -Path $moduleRoot -Recurse -Include '*.ps1', '*.psm1'
        $script:commands = foreach ($file in $files) {
            $tokens = $null; $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
            $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                ForEach-Object { $_.GetCommandName() } | Where-Object { $_ }
        }
        $script:members = foreach ($file in $files) {
            $tokens = $null; $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
            $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true) |
                ForEach-Object { $_.Member.Extent.Text }
        }
    }

    It 'never calls a write verb (Set, Remove, New, Add, Disable, Enable, Move, Rename)' {
        $write = @($commands | Where-Object { $_ -match '^(Set|Remove|New|Add|Disable|Enable|Move|Rename|Clear|Unlock|Reset|Grant|Revoke)-' })
        $write | Should -BeNullOrEmpty
    }

    It 'only uses Get-* cmdlets from the ActiveDirectory module' {
        $adCommands = @($commands | Where-Object { $_ -match '^[A-Za-z]+-AD' })
        $adCommands | Should -Not -BeNullOrEmpty
        $adCommands | Where-Object { $_ -notmatch '^Get-AD' } | Should -BeNullOrEmpty
    }

    It 'never calls ADSI write methods' {
        $members | Where-Object { $_ -match '^(SetInfo|Put|PutEx|CommitChanges|DeleteTree|Delete|Rename|MoveTo|SetPassword)$' } | Should -BeNullOrEmpty
    }
}

Describe 'Findings on the sample snapshot' {
    It 'loads the 40 fictitious accounts of exemplo.local' {
        $result.Domain | Should -Be 'exemplo.local'
        $result.AccountsScanned | Should -Be 40
        $result.ReferenceDate | Should -Be '2026-11-20T12:00:00Z'
    }

    It 'covers every rule in the catalog' {
        $ids = $result.Findings.RuleId | Sort-Object -Unique
        $ids | Should -Be @('AAA001', 'AAA002', 'AAA003', 'AAA004', 'AAA005', 'AAA006', 'AAA007', 'AAA008')
    }

    It 'AAA001 flags enabled accounts idle for more than 90 days' {
        (Get-Hit 'AAA001' 'maria.teste').Severity | Should -Be 'Medium'
        Get-Hit 'AAA001' 'vnd.erp' | Should -HaveCount 1
        Get-Hit 'AAA001' 'fabio.teste' | Should -HaveCount 0
        Get-Hit 'AAA001' 'ex.renato' | Should -HaveCount 0
    }

    It 'AAA001 escalates to Critical for privileged accounts' {
        (Get-Hit 'AAA001' 'adm.paulo').Severity | Should -Be 'Critical'
    }

    It 'AAA002 flags passwords that never expire' {
        (Get-Hit 'AAA002' 'lucia.amostra').Severity | Should -Be 'Medium'
        (Get-Hit 'AAA002' 'svc.backup').Severity | Should -Be 'Critical'
        (Get-Hit 'AAA002' 'adm.rafael').Severity | Should -Be 'Critical'
    }

    It 'AAA003 flags old passwords and does not repeat AAA002' {
        (Get-Hit 'AAA003' 'pedro.modelo').Severity | Should -Be 'Low'
        (Get-Hit 'AAA003' 'Administrator').Severity | Should -Be 'High'
        Get-Hit 'AAA003' 'recepcao' | Should -HaveCount 0
    }

    It 'AAA004 flags disabled accounts that are still privileged' {
        (Get-Hit 'AAA004' 'adm.joana').Severity | Should -Be 'High'
        (Get-Hit 'AAA004' 'ex.marcos').PrivilegedGroups | Should -Be @('Backup Operators')
        Get-Hit 'AAA005' 'adm.joana' | Should -HaveCount 0
    }

    It 'AAA005 lists privileged members, including nested groups' {
        (Get-Hit 'AAA005' 'adm.rafael').PrivilegedGroups | Should -Contain 'Domain Admins'
        (Get-Hit 'AAA005' 'adm.carlos').PrivilegedGroups | Should -Contain 'Administrators'
        Get-Hit 'AAA005' 'helpdesk.lucas' | Should -HaveCount 1
        Get-Hit 'AAA005' 'ana.exemplo' | Should -HaveCount 0
    }

    It 'AAA006 flags orphan adminCount=1 but ignores krbtgt' {
        Get-Hit 'AAA006' 'old.admin.tiago' | Should -HaveCount 1
        Get-Hit 'AAA006' 'ex.fernanda' | Should -HaveCount 1
        Get-Hit 'AAA006' 'krbtgt' | Should -HaveCount 0
        Get-Hit 'AAA006' 'adm.carlos' | Should -HaveCount 0
    }

    It 'AAA007 flags service and third-party accounts without logon hours' {
        Get-Hit 'AAA007' 'svc.sql' | Should -HaveCount 1
        Get-Hit 'AAA007' 'ext.consultoria' | Should -HaveCount 1
        Get-Hit 'AAA007' 'vnd.erp' | Should -HaveCount 1
        (Get-Hit 'AAA007' 'svc.backup').Severity | Should -Be 'High'
    }

    It 'AAA007 treats an all-hours mask as unrestricted and a real window as restricted' {
        Get-Hit 'AAA007' 'svc.print' | Should -HaveCount 1
        Get-Hit 'AAA007' 'svc.web' | Should -HaveCount 0
        Get-Hit 'AAA007' 'ext.suporte' | Should -HaveCount 0
        Get-Hit 'AAA007' 'joao.prestador' | Should -HaveCount 0
    }

    It 'AAA008 flags accounts that never logged on after 30 days' {
        Get-Hit 'AAA008' 'joao.exemplo' | Should -HaveCount 1
        Get-Hit 'AAA008' 'teste.sistema' | Should -HaveCount 1
        Get-Hit 'AAA008' 'nova.contratada' | Should -HaveCount 0
        Get-Hit 'AAA008' 'Guest' | Should -HaveCount 0
    }

    It 'gives every finding a severity, explanation and recommendation' {
        foreach ($f in $result.Findings) {
            $f.Severity | Should -BeIn @('Critical', 'High', 'Medium', 'Low')
            $f.Explanation | Should -Not -BeNullOrEmpty
            $f.Recommendation | Should -Not -BeNullOrEmpty
        }
    }

    It 'sorts findings from Critical to Low and the summary matches' {
        $rank = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
        $ranks = @($result.Findings | ForEach-Object { $rank[$_.Severity] })
        $ranks | Should -Be ($ranks | Sort-Object)
        foreach ($sev in 'Critical', 'High', 'Medium', 'Low') {
            $result.Summary[$sev] | Should -Be @($result.Findings | Where-Object Severity -EQ $sev).Count
        }
    }

    It 'clean accounts produce no findings' {
        foreach ($sam in 'ana.exemplo', 'bruno.teste', 'karen.modelo', 'svc.monitor') {
            @($result.Findings | Where-Object Account -EQ $sam) | Should -HaveCount 0
        }
    }
}

Describe 'Parameters' {
    It '-StaleDays changes the idle threshold' {
        $r = Invoke-AdAccessAudit -InputJson $samplePath -StaleDays 30
        @($r.Findings | Where-Object { $_.RuleId -eq 'AAA001' -and $_.Account -eq 'ines.exemplo' }) | Should -HaveCount 1
        $r = Invoke-AdAccessAudit -InputJson $samplePath -StaleDays 365
        @($r.Findings | Where-Object RuleId -EQ 'AAA001') | Should -HaveCount 0
    }

    It '-PasswordAgeDays changes the password age threshold' {
        $r = Invoke-AdAccessAudit -InputJson $samplePath -PasswordAgeDays 3000
        @($r.Findings | Where-Object RuleId -EQ 'AAA003') | Should -HaveCount 0
        $r = Invoke-AdAccessAudit -InputJson $samplePath -PasswordAgeDays 100
        @($r.Findings | Where-Object { $_.RuleId -eq 'AAA003' -and $_.Account -eq 'camila.modelo' }) | Should -HaveCount 1
    }

    It '-NeverLoggedOnDays changes the never-used threshold' {
        $r = Invoke-AdAccessAudit -InputJson $samplePath -NeverLoggedOnDays 5
        @($r.Findings | Where-Object { $_.RuleId -eq 'AAA008' -and $_.Account -eq 'nova.contratada' }) | Should -HaveCount 1
    }

    It '-PrivilegedGroups limits which groups count as privileged' {
        $r = Invoke-AdAccessAudit -InputJson $samplePath -PrivilegedGroups 'Backup Operators'
        ($r.Findings | Where-Object RuleId -EQ 'AAA005').Account | Should -Be @('svc.backup')
        @($r.Findings | Where-Object { $_.RuleId -eq 'AAA006' -and $_.Account -eq 'adm.carlos' }) | Should -HaveCount 1
        $r.Parameters.PrivilegedGroups | Should -Be @('Backup Operators')
    }

    It '-ReferenceDate overrides the snapshot date' {
        $r = Invoke-AdAccessAudit -InputJson $samplePath -ReferenceDate '2026-11-25T00:00:00Z'
        $r.ReferenceDate | Should -Be '2026-11-25T00:00:00Z'
    }

    It 'rejects out-of-range thresholds and unknown formats' {
        { Invoke-AdAccessAudit -InputJson $samplePath -StaleDays 0 } | Should -Throw
        { Invoke-AdAccessAudit -InputJson $samplePath -Format Pdf } | Should -Throw
    }

    It 'rejects an invalid regex' {
        { Invoke-AdAccessAudit -InputJson $samplePath -ServiceAccountPattern '([' } | Should -Throw '*Invalid regular expression*'
    }
}

Describe 'Output files' {
    BeforeAll {
        $script:out = Join-Path $TestDrive 'report'
        $script:written = Invoke-AdAccessAudit -InputJson $samplePath -OutputPath $out
    }

    It 'writes HTML, CSV and JSON by default' {
        $written.Files | Should -HaveCount 3
        foreach ($ext in 'html', 'csv', 'json') {
            Join-Path $out "ad-access-audit-exemplo.local-20261120.$ext" | Should -Exist
        }
    }

    It 'writes only the requested formats' {
        $dir = Join-Path $TestDrive 'only-csv'
        $r = Invoke-AdAccessAudit -InputJson $samplePath -OutputPath $dir -Format Csv
        $r.Files | Should -HaveCount 1
        $r.Files[0] | Should -BeLike '*.csv'
    }

    It 'returns the result without writing files when -OutputPath is omitted' {
        $result.Files | Should -HaveCount 0
    }

    It 'CSV has one row per finding' {
        $rows = Import-Csv (Join-Path $out 'ad-access-audit-exemplo.local-20261120.csv')
        $rows | Should -HaveCount $written.Findings.Count
        $rows[0].Severity | Should -Be 'Critical'
    }

    It 'JSON round-trips with summary and findings' {
        $json = [System.IO.File]::ReadAllText((Join-Path $out 'ad-access-audit-exemplo.local-20261120.json')) | ConvertFrom-Json
        $json.domain | Should -Be 'exemplo.local'
        @($json.findings) | Should -HaveCount $written.Findings.Count
        $json.summary.Critical | Should -Be $written.Summary['Critical']
    }

    It 'HTML is self-contained, with summary, filters and theme toggle' {
        $html = [System.IO.File]::ReadAllText((Join-Path $out 'ad-access-audit-exemplo.local-20261120.html'))
        $html | Should -Match '<style>'
        $html | Should -Match 'data-toggle-sev="Critical"'
        $html | Should -Match 'id="q"'
        $html | Should -Match 'id="theme"'
        $html | Should -Match 'prefers-color-scheme'
        $html | Should -Not -Match '(src|href)\s*=\s*"(https?:)?//'
        $html | Should -Not -Match '<link\b'
        $html | Should -Not -Match '@import'
    }

    It 'HTML-encodes values coming from the directory' {
        $snap = @{
            domain      = 'exemplo.local'
            generatedAt = '2026-11-20T12:00:00Z'
            users       = @(Get-BaseUser @{ samAccountName = 'x.inject'; displayName = '<script>alert(1)</script>'; passwordNeverExpires = $true })
            groups      = @()
        }
        $r = Invoke-WithSnapshot -Snapshot $snap -Parameters @{ OutputPath = (Join-Path $TestDrive 'xss'); Format = 'Html' }
        $html = [System.IO.File]::ReadAllText($r.Files[0])
        $html | Should -Not -Match '<script>alert'
        $html | Should -Match '&lt;script&gt;alert'
    }

    It 'docs/sample-report.html exists and matches the sample domain' {
        $doc = Join-Path $repoRoot 'docs/sample-report.html'
        $doc | Should -Exist
        [System.IO.File]::ReadAllText($doc) | Should -Match 'exemplo\.local'
    }
}

Describe 'Error handling and edge cases' {
    It 'fails clearly when the snapshot file does not exist' {
        { Invoke-AdAccessAudit -InputJson (Join-Path $TestDrive 'missing.json') } | Should -Throw '*not found*'
    }

    It 'fails clearly on invalid JSON' {
        $bad = Join-Path $TestDrive 'bad.json'
        [System.IO.File]::WriteAllText($bad, '{ this is not json')
        { Invoke-AdAccessAudit -InputJson $bad } | Should -Throw '*not valid JSON*'
    }

    It 'fails clearly when users are missing' {
        { Invoke-WithSnapshot -Snapshot @{ domain = 'exemplo.local'; groups = @() } } | Should -Throw "*'users' is missing*"
    }

    It 'fails clearly on a user without samAccountName' {
        { Invoke-WithSnapshot -Snapshot @{ users = @(@{ displayName = 'Sem Login' }) } } | Should -Throw '*no samAccountName*'
    }

    It 'fails clearly on an invalid date' {
        $snap = @{ users = @(Get-BaseUser @{ lastLogonDate = 'ontem' }) }
        { Invoke-WithSnapshot -Snapshot $snap } | Should -Throw "*user.base.lastLogonDate*"
    }

    It 'fails clearly on an invalid logonHours value' {
        $snap = @{ generatedAt = '2026-11-20T12:00:00Z'; users = @(Get-BaseUser @{ samAccountName = 'svc.bad'; logonHours = '%%%' }) }
        { Invoke-WithSnapshot -Snapshot $snap } | Should -Throw '*logonHours*'
    }

    It 'handles an empty domain without findings' {
        $r = Invoke-WithSnapshot -Snapshot @{ domain = 'vazio.local'; generatedAt = '2026-11-20T12:00:00Z'; users = @(); groups = @() } -Parameters @{ OutputPath = (Join-Path $TestDrive 'empty') }
        $r.Findings | Should -HaveCount 0
        $r.Files | Should -HaveCount 3
        [System.IO.File]::ReadAllText(($r.Files | Where-Object { $_ -like '*.html' })) | Should -Match 'No findings'
    }

    It 'survives cyclic nested groups' {
        $snap = @{
            generatedAt = '2026-11-20T12:00:00Z'
            users       = @(Get-BaseUser @{ samAccountName = 'adm.loop' })
            groups      = @(
                @{ name = 'Domain Admins'; members = @(@{ name = 'G1'; objectClass = 'group' }) },
                @{ name = 'G1'; members = @(@{ name = 'G2'; objectClass = 'group' }) },
                @{ name = 'G2'; members = @(@{ name = 'G1'; objectClass = 'group' }, @{ name = 'adm.loop'; objectClass = 'user' }) }
            )
        }
        $r = Invoke-WithSnapshot -Snapshot $snap
        ($r.Findings | Where-Object RuleId -EQ 'AAA005').Account | Should -Be 'adm.loop'
    }

    It 'matches localized group names through the alias field' {
        $snap = @{
            generatedAt = '2026-11-20T12:00:00Z'
            users       = @(Get-BaseUser @{ samAccountName = 'adm.local' })
            groups      = @(@{ name = 'Admins. do dominio'; alias = 'Domain Admins'; members = @('adm.local') })
        }
        $r = Invoke-WithSnapshot -Snapshot $snap
        ($r.Findings | Where-Object RuleId -EQ 'AAA005').PrivilegedGroups | Should -Be @('Domain Admins')
    }

    It 'treats accounts with a servicePrincipalName as service accounts' {
        $snap = @{ generatedAt = '2026-11-20T12:00:00Z'; users = @(Get-BaseUser @{ samAccountName = 'app01'; servicePrincipalNames = @('HTTP/app01.exemplo.local') }) }
        $r = Invoke-WithSnapshot -Snapshot $snap
        ($r.Findings | Where-Object RuleId -EQ 'AAA007').Detail | Should -BeLike 'Service account*'
    }

    It 'live mode fails with a clear message when RSAT is missing' -Skip:([bool](Get-Module -ListAvailable -Name ActiveDirectory)) {
        { Invoke-AdAccessAudit } | Should -Throw '*ActiveDirectory module*'
        { Export-AdSnapshot -Path (Join-Path $TestDrive 'x.json') } | Should -Throw '*ActiveDirectory module*'
    }
}
