## What and why

<!-- What does this change do, and why? Link the issue it closes, if any: "Closes #123". -->

## Checklist

- [ ] The test suite passes on Windows PowerShell 5.1: `powershell -NoProfile -File tests/Run-Tests.ps1` (CI also runs it on PowerShell 7). Never add `-ExecutionPolicy`.
- [ ] The antivirus hygiene check below finds nothing new in `.ps1`, `.psm1` and `.psd1` files.
- [ ] Script files stay plain ASCII, with no encoded payload, no dynamic code execution and no character-code tricks; command names and flags that rules look for live as separate tokens in `src/Data/*.json`.
- [ ] Every new or changed rule has at least one **positive** test (a risky configuration is reported) and one **negative** test (a close, safe configuration is not).
- [ ] The behavior of each new rule is backed by official documentation in its references, or the rule has medium confidence and says what remains to be verified.
- [ ] No real secret anywhere: fixtures and tests use only synthetic values marked `FAKE`, with no real token, internal host name, user name or personal path.
- [ ] The README and the help text are updated if the command-line behavior changed.

<details>
<summary>Antivirus hygiene check</summary>

Some endpoint protection products flag PowerShell code that merely looks like malware. Run this from the repository root in Windows PowerShell 5.1. The only expected matches are the two named character constants in `src/Core/Model.ps1` and the CSP hash encoding in `src/Output/Html.ps1`.

```powershell
Get-ChildItem -LiteralPath . -Recurse -File |
  Where-Object { $_.Extension -in '.ps1', '.psm1', '.psd1' } |
  Select-String -Pattern '(?i)encodedcommand|\s-enc\b|base64|invoke-expression|\biex\b|downloadstring|downloadfile|webclient|urlcache|bitsadmin|scriptblock\]::create|\[char\]\s*0x|-bxor|executionpolicy|add-type|-comobject|start-process|::unescape'
```

</details>
