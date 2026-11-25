# Contributing

Thanks for taking the time to help.

1. Open an issue first for new rules or behavior changes, so we can agree on the severity and wording.
2. Keep the module **read-only**. Only `Get-*` cmdlets from the ActiveDirectory module are allowed, and a test enforces it.
3. Every new rule needs: an entry in `Get-AuditRuleCatalog`, a case in `tools/build-sample.ps1` and tests in `tests/AdAccessAudit.Tests.ps1`.
4. Use only fictitious data in samples, tests and issues (domain `exemplo.local` or `exemplo.test`). Never paste a real snapshot.
5. Before opening a pull request, run:

   ```powershell
   ./tools/build-sample.ps1   # if you changed rules or the sample
   ./tools/test.ps1           # PSScriptAnalyzer + Pester 5
   ```

The code must keep working on Windows PowerShell 5.1 and PowerShell 7+.
