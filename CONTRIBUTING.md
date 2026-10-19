# Contributing to Airworthy

Thank you for helping make AI agent configurations safer. Bug reports, new rules, better fixes,
fixture cases, harness support and documentation are all welcome.

- **Bugs and ideas:** open an issue. Attach a *synthetic* configuration that reproduces the
  problem, never a real one with real secrets, user names or internal URLs. Run Airworthy with
  `-Redact` before you paste any output.
- **Vulnerabilities in Airworthy itself:** do not open a public issue; follow [SECURITY.md](SECURITY.md).
- **Design:** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) describes the data model, discovery,
  effective settings, scoring, the engine and the output security model.

By contributing, you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE), as section 5 of the license describes.

## Development setup

You need:

- Windows 10 or 11 with **Windows PowerShell 5.1** (built in);
- Git;
- an editor. VS Code with the PowerShell extension works well.

That is all: Airworthy has no module, package or binary dependency, and the tests use a small
built-in framework, not Pester. PowerShell 7 is optional; the CI runs the suite on both.

```powershell
git clone https://github.com/toonight/Airworthy.git
cd Airworthy
powershell -NoProfile -File .\tests\Run-Tests.ps1
```

A `git clone` does not mark files as downloaded from the internet, so a `RemoteSigned` execution
policy runs them as they are. If your policy is `Restricted`, set `RemoteSigned` for your own
account (`Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`) or ask your
administrator. Never pass an execution-policy flag on the command line, and never add one to a
script, a test or the CI.

## Repository layout

```
airworthy.ps1            command-line wrapper (exit codes)
Airworthy.psd1 / .psm1   module manifest and loader; Invoke-Airworthy is the only export
src/Core/                parsers, model, discovery, settings, redaction, scoring, engine
src/Rules/               one file per harness or area, each registering its rules
src/Data/                rule data (command names, flags, keywords) as JSON tokens
src/Output/              Console, JSON, SARIF, Markdown and HTML renderers
src/Output/Html/         report.css, report.js and body.html, inlined into the HTML report
tests/                   *.Tests.ps1, the test framework, the runner and fixtures/
examples/                reports generated from the test fixtures
docs/                    architecture
assets/                  logo and banners
.github/                 CI workflow, Dependabot, issue and pull request templates
```

## PowerShell 5.1 compatibility rules

Airworthy must run on the Windows PowerShell 5.1 that ships with Windows. Do **not** use:

- the ternary operator `? :`, the null operators `??`, `??=` and `?.`;
- the pipeline chain operators `&&` and `||`;
- `ConvertFrom-Json -AsHashtable` (use `ConvertFrom-AwJsonc`, which returns hashtables);
- `Join-Path` with more than two arguments (nest calls or use `[System.IO.Path]::Combine`);
- `ForEach-Object -Parallel`, `clean {}` blocks, or `[ordered]` casts of existing objects;
- any type that is not in .NET Framework 4.x.

And always:

- **`Set-StrictMode -Version 2.0`** applies to the module: read optional members with
  `Get-AwMemberValue` instead of `$obj.Missing`.
- **No network calls, no external modules, no binaries.**
- **Encoding.** Read files with `[System.IO.File]::ReadAllText($path)` and write UTF-8 without
  BOM: `[System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))`.
- **Naming.** Internal functions use the `Aw` prefix (`Get-AwSetting`, `New-AwFinding`). Only
  `Invoke-Airworthy` is exported. Public and important internal functions get comment-based help.
- **Determinism.** The same input must give the same output, apart from the scan timestamp: sort
  keys and lists with ordinal comparers.
- **On Windows PowerShell 5.1**, `Get-ChildItem -LiteralPath <dir> -Recurse -Include ...` ignores
  `-Include`. Filter on `$_.Extension` instead.

## Treat every scanned file as hostile

A repository can be crafted to attack the tool that analyzes it. Code that reads scanned content must:

- go through the discovery helpers, which skip files over 2 MB, enforce a read budget per analysis
  and refuse symbolic links or junctions that leave the analyzed root;
- never throw on bad input: unreadable or invalid files become `AW-CORE-001` findings, and the engine
  turns an exception in a rule into an `AW-CORE-002` finding;
- use linear regexes (bounded or atomic quantifiers, token-boundary lookbehinds) and cap the matches
  examined per file. Patterns that come *from* scanned files (terminal regexes, globs) must be built
  with `New-AwUntrustedRegex` and run with `Test-AwUntrustedMatch`, which apply a match timeout;
- never put a secret in full in a finding: mask values with `Hide-AwSecret`;
- leave rendering to the output layer, which escapes everything for its format.

## Antivirus hygiene (mandatory)

Airworthy is meant to run on locked-down corporate workstations, where endpoint protection inspects
every PowerShell script that loads. A security tool that looks for risky commands can easily *look*
like malware to a heuristic scanner, even when every line is harmless. The rules below keep the
code clean for those scanners. They apply to every `.ps1`, `.psm1` and `.psd1` file: the tool, the
tests **and** comments.

### Forbidden in script files

1. **Encoded payloads.** No base64 string of any kind, and no encoded-command flag followed by a value.
2. **Download-and-execute fragments,** written whole or assembled from pieces: dynamic expression
   evaluation (`Invoke-Expression` and its alias), web client download methods, the `certutil`
   URL-cache and `bitsadmin` transfer switches, BITS transfers, execution-policy overrides, or a
   pipe into an expression evaluator.
3. **Obfuscation techniques, even harmless ones:** strings built from `[char]` codes or by
   `-join` over code arrays, `-bxor`, string reversal, command names built with `-f` or `+`,
   backticks inside words, and `[regex]::Unescape` used to produce characters.
4. **Dynamic execution:** `[scriptblock]::Create`, `Invoke-Expression`, `Add-Type`,
   `New-Object -ComObject` and `Start-Process`, in the tool and in the tests.
5. **Non-ASCII characters.** Windows PowerShell 5.1 reads BOM-less files as ANSI. The only
   exceptions are two named constants defined once in `src/Core/Model.ps1`: `$script:AwEllipsis`
   and `$script:AwBom`.

### What to do instead

- **Rule data goes in JSON.** Command names, flags and keywords that rules look for live in
  `src/Data/*.json` and are loaded with `Read-AwDataFile`. Store them as **separate tokens**, never
  as command lines, for example `{ "programs": ["powershell", "pwsh"], "fileFlags": ["file", "f"] }`.
  No URLs and no payloads.
- **Invisible and bidirectional characters.** In regexes, use .NET escapes inside single-quoted
  strings, for example `'[\u200B-\u200D\u2060\uFEFF\u202A-\u202E\u2066-\u2069]'` and
  `'\uDB40[\uDC00-\uDC7F]'` for Unicode tag characters. Test strings that contain such characters
  come from JSON fixtures written with `\uXXXX` escapes.
- **Risky test inputs** (settings, MCP arguments) go in JSON fixtures: command names and flags
  only, no encoded payload and no real download URL. Use placeholders such as `"PAYLOAD"`,
  `.invalid` domains and values marked `FAKE`.
- **Hostile HTML fixtures** use benign markers, such as `</script><i>AW-XSS-MARKER</i>` or
  `javascript:void(0)`, never real script payloads.
- **Never write ad-hoc runner scripts** to work around a problem: run the tests with
  `tests/Run-Tests.ps1`.

### Check before every pull request

Run this from the repository root, in Windows PowerShell 5.1:

```powershell
Get-ChildItem -LiteralPath . -Recurse -File |
    Where-Object { '.ps1', '.psm1', '.psd1' -contains $_.Extension } |
    Select-String -Pattern '(?i)encodedcommand|\s-enc\b|base64|invoke-expression|\biex\b|downloadstring|downloadfile|webclient|urlcache|bitsadmin|scriptblock\]::create|\[char\]\s*0x|-bxor|executionpolicy|add-type|-comobject|start-process|::unescape'
```

It must report exactly **three** lines and nothing else: the two named character constants in
`src/Core/Model.ps1`, and the single `[Convert]::ToBase64String($hash)` in `src/Output/Html.ps1`
that encodes the Content-Security-Policy hash of the HTML report. Also check that script files
stay ASCII-only, for example with:

```powershell
Get-ChildItem -LiteralPath . -Recurse -File |
    Where-Object { '.ps1', '.psm1', '.psd1' -contains $_.Extension } |
    Select-String -Pattern '[^\x00-\x7F]'
```

which must report nothing.

JSON data files and fixtures may hold bare command or flag tokens, but never a full command line,
an encoded payload or a download URL.

If your antivirus quarantines or blocks a file while you work, stop and open an issue with the file
name and the detection name. Do not recreate the file, do not work around the detection, and do not
add an antivirus exclusion: the code has to change instead.

## Adding a rule

### 1. Choose the ID and the file

Rule IDs follow `AW-<AREA>-<NNN>`:

| Area | File | Harness |
| --- | --- | --- |
| `VSC` | `src/Rules/VSCode.Settings.ps1` | `vscode-copilot` |
| `AGT` | `src/Rules/AgentFiles.ps1` | `generic` or `vscode-copilot` |
| `SEC` | `src/Rules/Secrets.ps1` | `generic` |
| `MCP` | `src/Rules/Mcp.ps1` | `mcp` |
| `CC` | `src/Rules/ClaudeCode.ps1` | `claude-code` |
| `CLI` | `src/Rules/CopilotCli.ps1` | `copilot-cli` |
| `CDX` | `src/Rules/Codex.ps1` | `codex` |
| `CORE` | reserved for the engine | |

Take the next free number in the area. Never reuse or renumber an ID: users suppress, track and
search findings by ID. `Register-AwRule` refuses an ID that does not match
`^AW-(CORE|VSC|AGT|SEC|MCP|CC|CLI|CDX)-[0-9]{3}$`, a duplicate, and the reserved `AW-CORE-*` IDs.

### 2. Register it

```powershell
Register-AwRule -Id 'AW-CLI-006' -Title 'Short statement of the risky configuration' `
    -Severity 'medium' -Category 'sandbox-network' -Harness 'copilot-cli' `
    -Description 'What the rule checks, why it matters, and what it does not cover.' `
    -Fix 'The concrete change: the setting and the value to use.' `
    -References @('OWASP-ASI02', 'https://docs.github.com/en/copilot/...') `
    -Confidence 'high' -Check {
        param($Ctx)
        $artifact = @($Ctx.CopilotCli | Where-Object { $_.Scope -eq 'project' }) | Select-Object -First 1
        if ($null -eq $artifact -or $null -eq $artifact.Data) { return }
        if ($artifact.Data['someKey'] -ne $true) { return }
        New-AwFinding -RuleId 'AW-CLI-006' -Evidence 'someKey = true (repository settings)' `
            -Location @{ Path = $artifact.Path; Line = (Find-AwLineNumber -Text $artifact.Raw -Needle '"someKey"'); Key = 'someKey' }
    }
```

- **Severity:** `critical`, `high`, `medium`, `low` or `info`; the scoring weights are 40, 20, 8, 3
  and 0. Keep `critical` for settings that remove the human from the loop or hand out code
  execution, and `info` for context that should not change the score.
- **Category:** `approvals`, `sandbox-network`, `mcp-supply-chain`, `agent-files`, `secrets` or
  `observability`.
- **Harness:** the rule is evaluated only when that harness is detected, or always for `generic`.
- **References:** OWASP Agentic Top 10 IDs (`OWASP-ASI01` to `OWASP-ASI10`) and official
  documentation URLs only.
- **Confidence:** `high` when the behavior the rule relies on is confirmed in the official
  documentation; `medium` when the documentation is incomplete, ambiguous or contradictory. A
  `medium` rule says in its description what remains to be verified. Confidence becomes the SARIF
  `precision` of the rule.
- **Check** receives the analysis context (see the architecture document) and returns findings
  created with `New-AwFinding`. Use `Get-AwSetting` for effective VS Code values; Codex CLI rules
  read the parsed TOML files of `$Ctx.Codex` (scopes `user`, `project`, `profile` and `managed`),
  whose MCP servers are also in `$Ctx.McpFiles`. The engine fills
  any field you omit from the rule metadata. A finding may override the severity when the context
  makes it worse or milder; say so in the description.
- **Evidence** is short, shows the offending key and value, and never contains a full secret
  (`Hide-AwSecret`).
- **Data:** new command names, flags or keywords go in the matching `src/Data/<area>.json` file,
  as separate tokens (see [Antivirus hygiene](#antivirus-hygiene-mandatory)).

### 3. Test it

Every rule needs at least one **positive** test (the rule fires, with the expected severity,
location and evidence) and one **negative** test (the rule stays silent on a close, safe or default
configuration), in the matching `tests/<Area>.Tests.ps1` file.

- Fixtures live in `tests/fixtures/<area>/` and are **synthetic**: no real secrets, user names,
  hosts or paths. Fake secrets match the real format and say `FAKE`, for example
  `ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE12`.
- Tests never read the real user profile: always pass `-NoUserProfile`, or `-UserProfilePath`
  with a fixture folder.
- Internal functions are reachable through the module scope:
  `& (Get-Module Airworthy) { param($p) New-AwContext -Path $p -NoUserProfile } $fixture`.
- Some test files check rule coverage. In `tests/VSCode.Tests.ps1`, use `Assert-VscFires` and
  `Assert-VscSilent` and add the new ID to the coverage list; in `tests/ClaudeCode.Tests.ps1`,
  extend the ID range of the coverage test. In `tests/Codex.Tests.ps1`, `New-CdxCase` builds a
  temporary project, user profile and `requirements.toml` from TOML text and `Invoke-CdxCheck`
  runs one rule on it; the engine tests of the `tests/fixtures/codex/` and shared fixtures list
  every `AW-CDX` finding they expect.
- If the rule fires on the shared `insecure`, `mixed` or `hardened` fixtures, check that the
  integration tests still hold (`insecure` grades F, `mixed` sits in between, `hardened` grades A
  or B) and regenerate the examples (below).

### 4. Document it

- Regenerate the full rules table of the README from the module, never by hand:

  ```powershell
  Import-Module .\Airworthy.psd1 -Force
  & (Get-Module Airworthy) { Get-AwRules } | Format-Table Id, Severity, Harness, Title -AutoSize
  ```

- Add the rule to its category table in the README, and update the rule counts and badge.
- Add a line to [CHANGELOG.md](CHANGELOG.md) under an `Unreleased` section at the top (create it if it doesn't exist yet).

## Running the tests

```powershell
powershell -NoProfile -File .\tests\Run-Tests.ps1                  # every tests/*.Tests.ps1
powershell -NoProfile -File .\tests\Run-Tests.ps1 -Name VSCode     # one file (wildcards work)
powershell -NoProfile -File .\tests\Run-Tests.ps1 -Name Core,Jsonc # several files
```

The runner imports the module afresh for each test file, prints every result and a summary, and
exits with code 1 when a test fails. The framework (`tests/TestFramework.ps1`) provides `Describe`,
`It`, `Assert-Equal`, `Assert-True`, `Assert-False`, `Assert-Contains`, `Assert-NotContains`,
`Assert-Throws`, `Assert-Match` and `Assert-NotMatch`. Lines that start with `Airworthy:` during
the run come from tests that check error handling and exit codes: they are expected.

## Regenerating the examples

```powershell
.\airworthy.ps1 -Path .\tests\fixtures\insecure -NoUserProfile -Redact -Format Json,Sarif,Markdown,Html -OutFile .\examples\airworthy-insecure -Quiet
.\airworthy.ps1 -Path .\tests\fixtures\hardened -NoUserProfile -Redact -Format Html -OutFile .\examples\airworthy-hardened -Quiet
```

Always use `-NoUserProfile -Redact` for anything you commit, and check that no absolute path or
user name appears in the output.

## Pull request checklist

- [ ] The change does what its title says, and nothing else.
- [ ] `tests/Run-Tests.ps1` passes on Windows PowerShell 5.1 (the CI also runs it on PowerShell 7).
- [ ] The antivirus-hygiene check reports only the three allowed lines, and script files are ASCII-only.
- [ ] New or changed rules have positive and negative tests, synthetic fixtures and an accurate `Confidence`.
- [ ] The README and the CHANGELOG are updated when behavior or rules change.
- [ ] No real secret, user name, internal host name or local path in code, fixtures, examples or docs.
