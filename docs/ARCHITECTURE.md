# Airworthy architecture

This document describes how Airworthy is built: the layout, the data model, how it discovers
files and works out effective settings, how it scores, and how each output format stays safe with
hostile input. It is the reference for contributors; [CONTRIBUTING.md](../CONTRIBUTING.md) has the
day-to-day rules.

## Principles

- **Static and offline.** Airworthy reads files. It never runs an agent, an MCP server, a hook or
  any command it finds, and it makes no network call.
- **Hostile input.** Every scanned file may have been crafted against the tool. A bad file never
  stops the analysis: it becomes a finding.
- **No dependency.** Windows PowerShell 5.1 and .NET Framework 4.x only. No external module,
  package or binary, and no Pester.
- **Deterministic.** The same input gives the same output, apart from the scan timestamp.
- **Antivirus-friendly.** Script files are ASCII-only and hold no encoded payload, no dynamic
  execution and no download code. The command names that rules look for live in JSON data files.

## Layout

```
airworthy.ps1                 wrapper: imports the module, calls Invoke-Airworthy, exits with its code
Airworthy.psd1                manifest (version, exported function, metadata)
Airworthy.psm1                loader: dot-sources src/Core/*.ps1, then src/Rules/*.ps1, then src/Output/*.ps1
src/Core/Jsonc.ps1            JSONC parser
src/Core/Toml.ps1             TOML parser for Codex CLI configuration files
src/Core/Frontmatter.ps1      YAML frontmatter parser for agent files
src/Core/Model.ps1            constants, rule registry, findings, untrusted-regex helpers, data files
src/Core/Discovery.ps1        file discovery and the analysis context
src/Core/Settings.ps1         VS Code defaults and effective settings
src/Core/Redact.ps1           secret masking, path display and -Redact helpers
src/Core/Scoring.ps1          category scores, overall score and grade
src/Core/Engine.ps1           Invoke-Airworthy
src/Rules/*.ps1               rules: VSCode.Settings, AgentFiles, Secrets, Mcp, ClaudeCode, CopilotCli, Codex
src/Data/*.json               rule data: command names, flags and keywords, as separate tokens
src/Output/*.ps1              Console, Json, Sarif, Markdown, Html renderers
src/Output/Html/              report.css, report.js and body.html, inlined into the HTML report
tests/                        TestFramework.ps1, Run-Tests.ps1, *.Tests.ps1 and fixtures/
```

Each folder is loaded in alphabetical order. A file of `src/Core` that fails to load stops the
module. A file of `src/Rules` or `src/Output` that fails to load is recorded, reported as an
`AW-CORE-002` finding, and the rest of the tool keeps working.

## Data model (`src/Core/Model.ps1`)

### Constants

| Name | Value |
| --- | --- |
| Severities | `critical`, `high`, `medium`, `low`, `info` |
| Severity weights | critical 40, high 20, medium 8, low 3, info 0 |
| Categories (weight) | `approvals` (25), `sandbox-network` (20), `mcp-supply-chain` (20), `agent-files` (15), `secrets` (15), `observability` (5) |
| Harnesses | `vscode-copilot`, `claude-code`, `copilot-cli`, `codex`, `mcp`, `generic` |
| Confidence | `high`, `medium` (and `low`, unused so far) |
| Rule IDs | `^AW-(CORE\|VSC\|AGT\|SEC\|MCP\|CC\|CLI\|CDX)-[0-9]{3}$` |

### Rules

A rule is registered once, when its file loads:

```powershell
Register-AwRule -Id 'AW-VSC-001' -Title 'Global auto-approval of tools enabled' `
    -Severity 'critical' -Category 'approvals' -Harness 'vscode-copilot' `
    -Description '...' -Fix '...' -References @('OWASP-ASI02', 'https://code.visualstudio.com/...') `
    -Confidence 'high' -Check { param($Ctx) ... }
```

`Register-AwRule` validates every field and refuses duplicate IDs and the reserved `AW-CORE-*` IDs.
`Get-AwRules` returns the registered rules sorted by ID. `Check` receives the analysis context and
returns zero or more findings.

`AW-CORE-001` (unreadable or invalid file) and `AW-CORE-002` (rule or file failure, patterns not
evaluated) are built into the engine. They are `info` findings and are not registered rules, so
they never make a category applicable.

### Findings

`New-AwFinding -RuleId <id> [-Severity] [-Title] [-Evidence] [-Location] [-Fix] [-Harness] [-Data]`
returns an object with exactly these properties:

```
RuleId, Title, Severity, Category, Harness, Description, Evidence,
Location { Path; Line; Key }, Fix, References (string[]), Confidence
```

Missing fields come from the rule metadata. `Line` is best effort: `Find-AwLineNumber` returns
the 1-based line of the first occurrence of a needle, or nothing. **Evidence never contains a
secret in full.** An optional `Data` property may carry structured details, also without secrets.

### Rule data files

`Read-AwDataFile -Name <name>` loads `src/Data/<name>.json` with the JSONC parser. These files
hold the program names, flags and keywords the rules match, as separate tokens. They never hold a
full command line, a URL or a payload. A missing or invalid data file makes the rule file that
needs it fail to load, which is reported as `AW-CORE-002`.

## Parsers

### JSONC (`ConvertFrom-AwJsonc`)

- A tokenizer (one regex, matched contiguously, with atomic trivia) feeds an **iterative**
  parser, so deep nesting cannot overflow the call stack.
- `//` and `/* */` comments outside strings, and trailing commas, are accepted.
- Objects become **case-sensitive** hashtables, arrays become `object[]`. Duplicate keys: the
  last one wins. Maximum depth: 64.
- Invalid input throws a clear error with its line number, which discovery turns into `AW-CORE-001`.

### TOML (`ConvertFrom-AwToml`)

- Parses TOML 1.0 for the Codex CLI configuration files: comments; bare, quoted and dotted keys;
  `[table]` and `[[array.of.tables]]` headers; inline tables; multi-line arrays with comments and
  trailing commas; basic, literal and multi-line strings with their escapes; decimal,
  hexadecimal, octal and binary integers with underscores; floats (including `inf` and `nan`);
  booleans; and offset or local date-times, dates and times.
- Tables become **case-sensitive** hashtables and arrays (and arrays of tables) `object[]`, as with
  the JSONC parser, so the rules read both formats the same way. Integers are `[long]`, floats
  `[double]`, booleans `[bool]`. Dates and times stay `[string]`, with their original text, so no
  conversion depends on the culture or the .NET version. Newlines in multi-line strings become LF.
- A **linear scanner** reads the text once. Its regexes are runs of character classes, anchored
  with `\G` or matched against one bounded token, with every repetition atomic, so no input can
  make them backtrack. Arrays and inline tables use an explicit stack.
- What TOML forbids is an error, not "last one wins": a duplicate key, a table defined twice, a
  key reused as a table, an invalid escape or an unterminated string. Errors are
  `FormatException`s with `Data['Line']` and `Data['Column']`; discovery masks token-like words in
  the message and turns it into `AW-CORE-001`.
- Bounded for hostile files: 2 MB of text, 64 nested tables and arrays below the root table, and
  a budget of 20,000 parse steps (about one per key part, value, header, string and escape), which
  bounds the parse time whatever the document holds.

### Frontmatter (`Read-AwFrontmatter`)

- Returns `@{ Frontmatter = <hashtable>; Body = <string> }`. A file without `---` frontmatter
  has an empty hashtable and its whole text as the body.
- Supports the YAML subset agent files use: `key: value`, quoted strings, booleans, null,
  numbers, flow lists and maps, block lists, nested maps, lists of maps and block scalars
  (`|` and `>`).
- Never throws. What it does not understand is skipped and listed in the `__errors` key, which
  discovery reports as `AW-CORE-001`.
- Bounded for hostile files: depth 16, 2000 lines, 65,536 characters, and key patterns that
  cannot backtrack.

## Discovery (`New-AwContext`)

```powershell
New-AwContext -Path <root> [-UserSettingsPath <file>] [-UserProfilePath <dir>] [-NoUserProfile]
```

Discovery looks only at known locations. With `-NoUserProfile`, nothing outside the root is read,
except a file given explicitly with `-UserSettingsPath`. Otherwise the user profile is the real
one, or `-UserProfilePath`. `-UserSettingsPath` forces the VS Code user settings file in both cases.

### The context

| Property | Content |
| --- | --- |
| `Root` | Absolute path of the analyzed folder. |
| `IsWindows` | Whether the host is Windows. |
| `UserProfile` | Profile folder, or `$null` with `-NoUserProfile`. |
| `Harnesses` | Detected harnesses (see below). |
| `VSCode` | `UserSettings`, `WorkspaceSettings`, `WorkspaceFiles` and `Effective` (the merged settings). |
| `McpFiles` | MCP artifacts of every client, each with `Data.Servers` (name to server), including the `mcp_servers` tables of Codex config files. |
| `AgentFiles` | Custom agents, chat modes, instructions, prompt files, `AGENTS.md`, Claude agents and `CLAUDE.md`. |
| `Hooks` | `.github/hooks/*.json`, `~/.copilot/hooks/*.json`, Claude Code project settings that declare hooks, and the Codex project `.codex/hooks.json`. |
| `ClaudeSettings` | Claude Code settings with their scope: `project`, `local`, `user`, `managed`. |
| `CopilotCli` | Copilot CLI settings with their scope: `project`, `local`, `user`. |
| `Codex` | Codex CLI config files (parsed TOML) with their scope: `user`, `project`, `profile`, `managed` (`requirements.toml`). |
| `CodexRules` | Codex project `.codex/rules/*.rules` files, as text (`Data` is `$null`: the Starlark files are never evaluated). |
| `TextFiles` | Files to scan for secrets: every artifact above plus the root `.env*` files. |
| `Errors` | `AW-CORE-001` findings produced during discovery. |

An **artifact** is `{ Path; Scope; Harness; Raw; Data }`, where `Raw` is the file text and `Data`
the parsed JSONC, or TOML for Codex files (`$null` when the file is invalid). An **agent file** is
`{ Path; Kind; Scope; Frontmatter; Body; Raw }`. Absent data is `$null` or an empty array, never a
missing property.

### Locations

| Harness | Analyzed folder | User profile |
| --- | --- | --- |
| VS Code | `.vscode/settings.json`, `*.code-workspace` (`settings` key), `.vscode/mcp.json`, `.github/agents/*.agent.md`, `.github/chatmodes/*.chatmode.md`, `.github/copilot-instructions.md`, `.github/instructions/*.instructions.md`, `.github/prompts/*.prompt.md`, `.github/hooks/*.json` | `Code/User` and `Code - Insiders/User`: `settings.json` and `mcp.json` |
| Claude Code | `.claude/settings.json`, `.claude/settings.local.json`, `.claude/agents/*.md`, `CLAUDE.md`, `.mcp.json` | `~/.claude/settings.json`, `~/.claude.json` (`mcpServers` and `projects.*.mcpServers`), and the machine-wide `managed-settings.json` (real profile only: `%ProgramFiles%\ClaudeCode\` on Windows) |
| Copilot CLI | `.github/copilot/settings.json`, `.github/copilot/settings.local.json`, `.github/mcp.json` | `~/.copilot/config.json`, `~/.copilot/settings.json`, `~/.copilot/mcp-config.json`, `~/.copilot/agents/*.agent.md`, `~/.copilot/hooks/*.json` |
| Codex CLI | `.codex/config.toml`, `.codex/hooks.json`, `.codex/rules/*.rules` | In each Codex home: `config.toml` and the profile files `<name>.config.toml`; the machine-wide `requirements.toml` (real profile only: `%ProgramData%\OpenAI\Codex\` on Windows, `/etc/codex/` elsewhere) |
| Any | `AGENTS.md`, root `.env*` files | |

MCP server lists are normalized from the `servers` key (VS Code), the `mcpServers` key
(Claude Code and Copilot CLI) or the `mcp_servers` tables (Codex CLI, user, project and profile
files). Codex servers keep their `command`, `args`, `env` and `url` keys, which have the same
meaning, and their `http_headers` table is read as `headers`, so the `AW-MCP` rules apply to them
unchanged.

#### Codex CLI

- **Codex homes.** `<profile>/.codex` is always a Codex home. With the real profile only, the
  `CODEX_HOME` environment variable adds a first home when it names an existing absolute folder;
  `<profile>/.codex` is still read after it. With `-UserProfilePath`, `CODEX_HOME` is ignored, so
  tests never depend on the machine.
- **Profile files.** Only `<name>.config.toml` files whose name has letters, digits, `-` and `_`
  are read, with the `profile` scope. They apply only with `--profile <name>`, so the rules check
  each one with the layers it applies with (see Effective settings).
- **requirements.toml** is read with the `managed` scope, on the real machine only.
  `$script:AwCodexRequirementsOverride` replaces its location in tests.
- **Hooks and rules.** The project `.codex/hooks.json` joins `Hooks` with the `codex` harness;
  the `[hooks]` tables of the project `config.toml` are read from `Codex`. The project
  `.codex/rules/*.rules` files go to `CodexRules` as text.
- Every Codex file goes through the same helpers as the other files: size limit, read budget,
  link checks, and `AW-CORE-001` for a file that cannot be read or parsed.

### Harness detection

- `vscode-copilot`: a `.vscode/` folder, `.github/agents`, `chatmodes`, `prompts` or
  `instructions` folders, `.github/copilot-instructions.md`, a `*.code-workspace` file, or VS Code
  user settings.
- `claude-code`: a `.claude/` folder or `CLAUDE.md`, or `~/.claude/` in the profile.
- `copilot-cli`: `.github/copilot/`, or `~/.copilot/` in the profile.
- `codex`: a `.codex/` folder, a Codex config file that was read, or a Codex home folder in the
  profile.
- `mcp`: at least one MCP configuration file.

Rules of the `generic` harness always run; the others run only when their harness is detected.

### Limits

| Limit | Value | When it is reached |
| --- | --- | --- |
| File size | 2 MB | The file is skipped (`AW-CORE-001`). |
| Read budget per analysis | 32 MB | Further files are skipped (`AW-CORE-001`). |
| Files per pattern | 500 | Only the first 500, sorted by name, are analyzed. |
| Text files for the secret scan | 500 | Only the first 500 are kept. |
| Links | | A symbolic link or junction anywhere between the root and a file that resolves outside the root, to a network share or to a volume, makes the file skipped. Profile files are allowed outside the root by design. |

## Effective settings

### VS Code (`src/Core/Settings.ps1`)

- `$script:AwVSCodeDefaults` holds the documented defaults of the settings the rules read. A
  default that the documentation contradicts is commented as such.
- Layers merge in the order **default < user < workspace file (`*.code-workspace`) < workspace
  (`.vscode/settings.json`)**.
- Object settings (for example `chat.tools.terminal.autoApprove`) merge **key by key**, as VS Code
  merges user and workspace objects; other values are replaced. The `Source` of a merged entry is
  the highest layer that contributed.
- Nested notation (`{ "chat": { "tools": { ... } } }`) is flattened into dotted keys, without
  flattening below a known object-valued setting.
- `Get-AwSetting -Ctx $ctx -Key <key>` returns `{ Key; Value; Source; Path; IsDefault; Layers }`,
  where `Layers` lists every layer that sets the key, in order.

### Claude Code and Copilot CLI

- Claude Code scalar settings follow the documented precedence **managed > local > project > user**.
  Rules also apply the documented exceptions, such as a managed Boolean that always wins, or
  permission modes that recent Claude Code versions ignore when they come from project or local
  settings.
- Copilot CLI settings follow **local > repository > user**.

### Codex CLI

- Rules that depend on a combination of settings, such as `approval_policy = "never"` with full
  access (`AW-CDX-002`), network access in the `workspace-write` sandbox (`AW-CDX-003`) or a
  permission profile network without the network proxy (`AW-CDX-004`), stack the project
  `.codex/config.toml` over each user config file: **project > user**. A value then counts only
  where it decides. A user file also applies alone, in the folders that have no project config.
- Profile files apply only to the sessions started with `--profile`, so they are not merged into
  those stacks. Each one gets its own stacks (`AW-CDX-004`, `AW-CDX-014`), in the documented
  precedence **project > profile > user**: the profile over the user `config.toml` of its own
  Codex home, alone and under each project config.
- **Sandbox model.** Permission profiles (`default_permissions`, `[permissions]`) and the older
  sandbox settings (`sandbox_mode`, `[sandbox_workspace_write]`) do not compose. In a stack, the
  older settings apply when any file sets `sandbox_mode`, and permission profiles otherwise when a
  file sets `default_permissions`; a managed `allowed_permission_profiles` table selects permission
  profiles in every case. Full access is then the highest `sandbox_mode` or the highest
  `default_permissions` of the system in use, and `[sandbox_workspace_write]` counts only with
  the older settings.
- **Network proxy.** It runs when the highest file that decides sets
  `features.network_proxy = true` or `features.network_proxy.enabled = true` (a table without
  `enabled` does not start it), or when `requirements.toml` sets `experimental_network.enabled = true`.
- The other rules report a risky value in every file that sets it, since each file applies to
  some sessions.
- `requirements.toml` limits are applied on top: a value outside `allowed_sandbox_modes`,
  `allowed_approval_policies`, `allowed_web_search_modes` or `allowed_permission_profiles` lowers
  the matching finding to `info`, and `allow_managed_hooks_only = true` or `features.hooks = false`
  silences the project hooks rule.
- TOML keys and values are compared ordinally, as Codex does: a `Sandbox_Mode` key is not
  `sandbox_mode`.

### Agent files

- A custom agent's `tools` list grants its tools; a missing list or `'*'` grants every tool.
- In a Local harness session, the `tools` of a prompt file take precedence over the tools of the
  custom agent it runs with, so a prompt file can widen an agent's tool set.

Command-line flags (such as the Codex `--yolo`, `--sandbox` or `-c key=value`) and permissions
granted during a session are invisible to a static analysis.

## Redaction (`src/Core/Redact.ps1`)

- `Hide-AwSecret` keeps the first 4 and last 2 characters plus the length of a value of 12
  characters or more (`ghp_…34 (40 chars)`), and returns `****` otherwise.
- `Hide-AwSecretsInText` masks any remaining token-like word (20 or more letters, digits or
  underscores, with at least one letter and one digit). Every output applies it to titles and
  evidence as a last line of defense.
- `Get-AwDisplayPath` shows a path relative to the root when it is inside it.
- With `-Redact`, the engine replaces the absolute root by its folder name (`Get-AwPathLabel`),
  the profile by `~` and the user name by `%USERNAME%`, in paths, titles, evidence and keys
  (`Hide-AwPrivateText`). Path options (`OutFile`, `UserProfilePath`, `UserSettingsPath`) are
  reduced the same way, and to their file name when they stay absolute (`Hide-AwOptionPath`).
  Other absolute paths in findings are left as they are.

## Scoring (`Get-AwScore`)

1. Each category starts at 100.
2. Per rule, findings are sorted by weight: the first removes its full weight, each further one
   25% of its own weight, and the total for the rule is capped at twice the weight of the first.
3. A category score has a floor of 0.
4. A category applies when at least one rule of the category targets a detected harness or the
   `generic` harness.
5. The overall score is the weighted average of the applicable categories, rounded half away from
   zero; 100 when no category applies.
6. Any `critical` finding caps the overall score at 69.
7. Grades: A from 90, B from 80, C from 70, D from 60, F below 60.

The result is `{ Score; Grade; Categories; Counts }`, where each category has its title, score,
applicability and number of findings, and `Counts` has the number of findings per severity.

## Engine (`Invoke-Airworthy`)

```powershell
Invoke-Airworthy -Path <dir> [-Format Console,Json,Sarif,Markdown,Html] [-OutFile <base>]
    [-UserSettingsPath <file>] [-UserProfilePath <dir>] [-NoUserProfile] [-Redact]
    [-MinSeverity <sev>] [-FailOn <sev>] [-PassThru] [-Quiet]
```

1. Build the context with `New-AwContext`.
2. Select the applicable rules: the `generic` ones and those of the detected harnesses.
3. Run each rule. An exception, or an object that is not a finding, becomes an `AW-CORE-002`
   finding; the analysis goes on. Missing finding fields are filled from the rule metadata.
4. Patterns taken from scanned files run with a 50 ms match timeout. A pattern that timed out is
   not run again, and after 20 timeouts in one analysis no such pattern runs any more. Anything
   not evaluated is reported in one `AW-CORE-002` finding.
5. Remove duplicate findings, and sort them by severity, rule, path, line, key and evidence with an
   ordinal comparer.
6. Score every finding. `-MinSeverity` then filters what is reported; it never changes the score.
7. Set `ExitCode` to 1 when `-FailOn` is given and a finding (reported or not) reaches it.
8. Apply `-Redact`, then render each requested format with `ConvertTo-Aw<Format>`. With
   `-OutFile <base>`, files are written as UTF-8 without BOM to `<base>.json`, `.sarif`, `.md`
   and `.html`; without it, the texts go to the pipeline. A renderer that fails produces a warning,
   and the other formats are still written.

The result object is:

```
Tool { Name; Version }, ScannedAt (ISO 8601 UTC), Root, Harnesses, Score, Findings,
Rules (metadata of the applicable rules), Errors (AW-CORE findings), Options, ExitCode
```

The `airworthy.ps1` wrapper exits with `ExitCode`, or with 2 when the analysis cannot run.

## Output security model

Every value that comes from a scanned file, including keys, paths, server names and evidence, is
treated as attacker-controlled text in every format.

| Format | Protection |
| --- | --- |
| **Console** | Plain text with ASCII framing, so it reads the same in a console and a CI log. Line breaks become spaces, control and invisible format characters (bidirectional overrides, zero-width characters) become `?`, and long values are cut. |
| **JSON** | A built-in deterministic writer with a fixed property order. It escapes control characters, `<`, `>`, `&`, `'`, U+2028, U+2029 and lone surrogates. Rule check code and internals are never written. |
| **SARIF 2.1.0** | Plain-text messages, with `](` broken up so that scanned text cannot create an embedded link. `helpUri` only takes `http(s)` references. Descriptions are cut to GitHub's limits. Paths inside the root are relative to `SRCROOT`; with `-Redact`, base URIs carry no absolute path. |
| **Markdown** | Scanned values go into code spans, other text is backslash-escaped (including `<`, `>`, `|` and `[`), and only well-formed `http(s)` references become links, so a value can neither inject HTML nor change the structure of the document. |
| **HTML** | See below. |

### The HTML report

The report is one self-contained file, built from `report.css`, `report.js` and `body.html`:

1. **Inert data.** The report model is embedded as JSON in a
   `<script type="application/json">` element. Every character outside a small set of safe
   printable ASCII characters is escaped (`\"`, `\\` or `\uXXXX`), including `<`, `>`, `&`, `:`,
   `'` and every control or non-ASCII character. The data can therefore never close its
   element, open a tag or a comment, or spell a URL scheme.
2. **Text only.** The single renderer script parses that JSON and builds the page with
   `createElement` and `textContent`. It never uses `innerHTML` or string-built markup.
   Invisible, bidirectional, Unicode tag characters and lone surrogates are shown as `[U+XXXX]`,
   so hostile text can neither hide content nor reorder it.
3. **Strict CSP.** A `Content-Security-Policy` meta element sets `default-src 'none'`, allows the
   inline stylesheet and the renderer script only by their SHA-256 hashes (computed when the
   report is written), and sets `base-uri 'none'` and `form-action 'none'`. Nothing else can run,
   style the page or load, and the page makes no network request.
4. **Safe links.** A reference becomes a link only if it is an `https` URL, without credentials,
   on an allowlist of documentation hosts; links carry `rel="noopener noreferrer"`, and the page
   sends no referrer.
5. **Asset guard.** The CSS and JavaScript assets are refused if they contain a sequence that
   could end their own element.

The only thing the page stores is the light or dark theme choice, in the browser's local storage.

## Tests

- `tests/TestFramework.ps1` is a minimal framework (`Describe`, `It` and `Assert-*` helpers), so
  the suite needs no Pester.
- `tests/Run-Tests.ps1` runs every `tests/*.Tests.ps1` file after a fresh `Import-Module`, prints
  a summary and exits with 1 when anything fails. `-Name` filters the files.
- Tests reach internal functions through the module scope: `& (Get-Module Airworthy) { ... }`.
- Fixtures are synthetic. Fake secrets match the real formats and are marked `FAKE`. Tests always
  pass `-NoUserProfile` or point `-UserProfilePath` at a fixture, so they never read a real profile.
- The shared fixtures cover the whole tool, Codex CLI included: `insecure` (grade F), `mixed` (in
  between) and `hardened` (grade A or B).
- `tests/Security.Tests.ps1` attacks the tool itself: a hostile repository whose values try to
  inject markup and scripts into the HTML report, secret masking in every format, embedded links
  in SARIF, junctions and link targets that leave the root, ReDoS with 2 MB lines and hostile
  patterns, malformed and oversized files, and reads outside the root with `-NoUserProfile`.
- The CI workflow (`.github/workflows/ci.yml`) runs the suite on Windows PowerShell 5.1 and
  PowerShell 7, and checks the `-FailOn high` exit codes on the `hardened` and `insecure` fixtures.
