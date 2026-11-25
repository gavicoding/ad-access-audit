function ConvertTo-AuditHtml {
    <#
    .SYNOPSIS
        Renders the audit result as a single self-contained HTML page (inline CSS and JS,
        no external resources, works offline).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Result
    )

    $enc = { param($Text) [System.Net.WebUtility]::HtmlEncode([string]$Text) }

    $rows = [System.Text.StringBuilder]::new()
    foreach ($f in $Result.Findings) {
        $sev = $f.Severity.ToLowerInvariant()
        $groups = (@($f.PrivilegedGroups) -join ', ')
        $search = ('{0} {1} {2} {3} {4} {5}' -f $f.Account, $f.DisplayName, $f.Title, $f.Detail, $groups, $f.RuleId).ToLowerInvariant()
        $status = 'Enabled'
        if (-not $f.Enabled) { $status = 'Disabled' }

        [void]$rows.AppendLine(('<tr data-sev="{0}" data-rule="{1}" data-search="{2}">' -f $sev, (& $enc $f.RuleId), (& $enc $search)))
        [void]$rows.AppendLine(('<td><span class="badge {0}">{1}</span></td>' -f $sev, (& $enc $f.Severity)))
        [void]$rows.AppendLine(('<td><strong>{0}</strong><div class="muted">{1}</div><div class="muted small">{2}</div></td>' -f (& $enc $f.Account), (& $enc $f.DisplayName), $status))
        [void]$rows.AppendLine(('<td><span class="rule">{0}</span> {1}<div class="muted">{2}</div></td>' -f (& $enc $f.RuleId), (& $enc $f.Title), (& $enc $f.Detail)))
        [void]$rows.AppendLine(('<td><details><summary>Why and what to do</summary><p>{0}</p><p><strong>Recommendation:</strong> {1}</p></details></td>' -f (& $enc $f.Explanation), (& $enc $f.Recommendation)))
        [void]$rows.AppendLine('</tr>')
    }

    $ruleOptions = [System.Text.StringBuilder]::new()
    foreach ($rule in (Get-AuditRuleCatalog).Values) {
        $count = @($Result.Findings | Where-Object { $_.RuleId -eq $rule.RuleId }).Count
        [void]$ruleOptions.AppendLine(('<option value="{0}">{0} - {1} ({2})</option>' -f (& $enc $rule.RuleId), (& $enc $rule.Title), $count))
    }

    $cards = [System.Text.StringBuilder]::new()
    foreach ($sev in 'Critical', 'High', 'Medium', 'Low') {
        [void]$cards.AppendLine(('<button type="button" class="card {0}" data-toggle-sev="{0}" aria-pressed="true"><span class="num">{1}</span><span class="lbl">{2}</span></button>' -f $sev.ToLowerInvariant(), $Result.Summary[$sev], $sev))
    }

    $p = $Result.Parameters
    $paramText = 'Stale after {0} days | password age {1} days | never logged on after {2} days | privileged groups: {3}' -f $p.StaleDays, $p.PasswordAgeDays, $p.NeverLoggedOnDays, ($p.PrivilegedGroups -join ', ')

    $empty = ''
    if (@($Result.Findings).Count -eq 0) { $empty = '<p class="empty">No findings. Nice and clean.</p>' }

    $template = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AD access audit - {{DOMAIN}}</title>
<style>
:root{--bg:#f6f7f9;--panel:#fff;--text:#1d2330;--muted:#5d6678;--border:#dde1e8;--accent:#2457c5;
--critical:#b3261e;--high:#d9570d;--medium:#a87900;--low:#2f6fb3;}
[data-theme="dark"]{--bg:#12151b;--panel:#1b2029;--text:#e6e9ef;--muted:#9aa3b5;--border:#2c3340;--accent:#7aa2ff;
--critical:#ff6b61;--high:#ff9a52;--medium:#e2b93b;--low:#6fa8ff;}
*{box-sizing:border-box}
body{margin:0;font:14px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif;background:var(--bg);color:var(--text)}
header{padding:24px 32px 8px;display:flex;flex-wrap:wrap;gap:12px;align-items:flex-start;justify-content:space-between}
h1{margin:0;font-size:22px}
.muted{color:var(--muted)}.small{font-size:12px}
main{padding:8px 32px 32px}
.meta{margin:4px 0 0}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:16px 0}
.card{background:var(--panel);border:1px solid var(--border);border-left:6px solid;border-radius:8px;padding:14px 16px;text-align:left;cursor:pointer;color:var(--text);font:inherit}
.card .num{display:block;font-size:28px;font-weight:700}
.card .lbl{color:var(--muted)}
.card[aria-pressed="false"]{opacity:.45}
.card.critical{border-left-color:var(--critical)}.card.high{border-left-color:var(--high)}
.card.medium{border-left-color:var(--medium)}.card.low{border-left-color:var(--low)}
.controls{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}
input,select,.btn{background:var(--panel);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:7px 10px;font:inherit}
input{flex:1;min-width:220px}
.btn{cursor:pointer}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border);border-radius:8px;overflow:hidden}
th,td{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:top;text-align:left}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
tr.hidden{display:none}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600;color:#fff}
.badge.critical{background:var(--critical)}.badge.high{background:var(--high)}
.badge.medium{background:var(--medium)}.badge.low{background:var(--low)}
[data-theme="dark"] .badge{color:#12151b}
.rule{font-family:Consolas,monospace;font-size:12px;color:var(--accent)}
details summary{cursor:pointer;color:var(--accent)}
details p{margin:6px 0}
.empty{padding:24px;text-align:center}
footer{padding:0 32px 24px;font-size:12px;color:var(--muted)}
@media print{.controls,#theme{display:none}tr.hidden{display:table-row}details{display:block}}
</style>
</head>
<body>
<header>
<div>
<h1>Active Directory access audit</h1>
<p class="meta muted">Domain <strong>{{DOMAIN}}</strong> | reference date {{REFDATE}} | {{ACCOUNTS}} accounts scanned | {{TOTAL}} findings</p>
<p class="meta muted small">{{SOURCE}}</p>
</div>
<button type="button" class="btn" id="theme">Toggle dark/light</button>
</header>
<main>
<section class="cards" aria-label="Findings by severity">
{{CARDS}}
</section>
<div class="controls">
<input type="search" id="q" placeholder="Filter by account, name, group or text" aria-label="Filter">
<select id="rule" aria-label="Rule"><option value="">All rules</option>
{{RULES}}
</select>
<button type="button" class="btn" id="reset">Reset filters</button>
</div>
<p class="muted small" id="count"></p>
<table>
<thead><tr><th>Severity</th><th>Account</th><th>Finding</th><th>Details</th></tr></thead>
<tbody id="rows">
{{ROWS}}
</tbody>
</table>
{{EMPTY}}
</main>
<footer>{{PARAMS}}<br>Generated {{GENERATED}} by ad-access-audit {{VERSION}} (read-only, nothing was changed in the directory).</footer>
<script>
(function(){
var root=document.documentElement;
function store(k,v){try{if(v===undefined){return localStorage.getItem(k);}localStorage.setItem(k,v);}catch(e){return null;}}
var saved=store('aaa-theme');
var dark=saved?saved==='dark':(window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches);
root.setAttribute('data-theme',dark?'dark':'light');
document.getElementById('theme').addEventListener('click',function(){
var next=root.getAttribute('data-theme')==='dark'?'light':'dark';root.setAttribute('data-theme',next);store('aaa-theme',next);});
var rows=Array.prototype.slice.call(document.querySelectorAll('#rows tr'));
var cards=Array.prototype.slice.call(document.querySelectorAll('[data-toggle-sev]'));
var q=document.getElementById('q'),rule=document.getElementById('rule'),count=document.getElementById('count');
function apply(){
var on={};cards.forEach(function(c){on[c.getAttribute('data-toggle-sev').toLowerCase()]=c.getAttribute('aria-pressed')==='true';});
var text=q.value.trim().toLowerCase(),r=rule.value,shown=0;
rows.forEach(function(tr){
var ok=on[tr.getAttribute('data-sev')]&&(!r||tr.getAttribute('data-rule')===r)&&(!text||tr.getAttribute('data-search').indexOf(text)>-1);
tr.className=ok?'':'hidden';if(ok){shown++;}});
count.textContent='Showing '+shown+' of '+rows.length+' findings';}
cards.forEach(function(c){c.addEventListener('click',function(){c.setAttribute('aria-pressed',c.getAttribute('aria-pressed')==='true'?'false':'true');apply();});});
q.addEventListener('input',apply);rule.addEventListener('change',apply);
document.getElementById('reset').addEventListener('click',function(){q.value='';rule.value='';cards.forEach(function(c){c.setAttribute('aria-pressed','true');});apply();});
apply();
})();
</script>
</body>
</html>
'@

    $values = [ordered]@{
        '{{DOMAIN}}'    = & $enc $Result.Domain
        '{{REFDATE}}'   = & $enc $Result.ReferenceDate
        '{{GENERATED}}' = & $enc $Result.GeneratedAt
        '{{ACCOUNTS}}'  = [string]$Result.AccountsScanned
        '{{TOTAL}}'     = [string]@($Result.Findings).Count
        '{{SOURCE}}'    = & $enc $Result.Source
        '{{VERSION}}'   = & $enc $Result.ToolVersion
        '{{PARAMS}}'    = & $enc $paramText
        '{{CARDS}}'     = $cards.ToString()
        '{{RULES}}'     = $ruleOptions.ToString()
        '{{EMPTY}}'     = $empty
        # Rows go last so text from the directory is never scanned for placeholders.
        '{{ROWS}}'      = $rows.ToString()
    }

    $html = $template
    foreach ($key in $values.Keys) {
        $html = $html.Replace($key, $values[$key])
    }
    return $html
}
