# Changelog

All notable changes to Airworthy are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-19

OpenAI Codex CLI support.

### Added

- **Codex CLI harness (`codex`).** Discovery of the user `~/.codex/config.toml` (and, for the
  real profile only, `$CODEX_HOME/config.toml`), the project `.codex/config.toml`, the profile
  files `<codex home>/<name>.config.toml`, the machine-wide `requirements.toml` (real machine only),
  the project `.codex/hooks.json` and the project `.codex/rules/*.rules`. The project config
  overrides the user config, a profile is evaluated over the user config of its Codex home and
  under the project config (project > profile > user), and a value that `requirements.toml` does
  not allow lowers the matching finding to `info`.
- **14 Codex rules** (`AW-CDX-001` to `AW-CDX-014`): the sandbox turned off
  (`danger-full-access`), `approval_policy = "never"` (critical when the sandbox is off too),
  network access in the `workspace-write` sandbox, permission profiles with unrestricted network,
  writable roots or permission entries over the home folder or a drive root, the `dangerously_*`
  network proxy options, every environment variable passed to commands, MCP servers and tools that
  run without a prompt, client secrets and bearer tokens stored in a config file, trust given to a
  folder that is too broad, live web search, project hooks, project rules that allow commands
  outside the sandbox, and profiles that weaken the sandbox or the approvals. Airworthy now has
  **85 rules**: 61 with `high` confidence and 24 with `medium`. On a hostile file, each rule lists
  at most 20 findings of one kind per file (the score does not change) and its line lookups stay
  linear.
- **Codex MCP servers through the MCP rules.** The `[mcp_servers.<id>]` tables of Codex config
  files are normalized like the MCP files of the other clients (`http_headers` is read as
  `headers`), so `AW-MCP-001` to `AW-MCP-006` apply to them.
- **TOML parser** (`ConvertFrom-AwToml`, TOML 1.0) with no dependency: bare, quoted and dotted
  keys, tables, arrays of tables, inline tables, multi-line arrays, the four string kinds, integers
  in every base, floats, booleans, and dates and times kept as strings. A linear scanner and an
  explicit stack keep hostile files cheap: 2 MB of text, 64 nested levels and a budget of parse
  steps. Invalid TOML becomes an `AW-CORE-001` finding with its line number.
- **HTML report:** a "Codex CLI" harness label and filter, and `learn.chatgpt.com` on the
  allowlist of documentation links.
- **Tests and fixtures:** Codex and TOML test files, synthetic Codex fixtures, and a
  `.codex/config.toml` in the shared `insecure`, `mixed` and `hardened` fixtures.

### Changed

- Version 0.2.0. The module manifest mentions Codex CLI and has the `codex` tag.
- The `AW-CORE-001` description mentions TOML files.
- The example reports are regenerated with the Codex findings: the `insecure` fixture now scores
  14 (grade F) and `hardened` still scores 98 (grade A).

### Fixed

- **`AW-SEC-009` false positive on Codex MCP servers:** the values of `env_http_headers` (for
  example `"X-Api-Key" = "DOCS_API_KEY"`), `bearer_token_env_var` and `env_vars` are environment
  variable names, not secrets, and are no longer reported. A value that is not a valid variable
  name, or that also appears elsewhere in the file (a literal `http_headers` value, for example),
  still is.
- **JSON writer:** a hashtable whose values all had the same type (all strings, for example) could
  be written with its keys sorted but its values left in their original order, because PowerShell
  sorted a converted copy of the values. The key names are now sorted alone and each value is read
  by its key. The reports themselves use ordered dictionaries, so the bug was latent, but any
  hashtable given to the writer was exposed.
- **`AW-CDX-004`** also reports a permission profile whose network is enabled while the network
  proxy is off (`features.network_proxy` or `features.network_proxy.enabled` not true in the layers
  where the profile applies, and no managed `experimental_network.enabled = true`): commands then
  have direct, unrestricted network access and the domain rules are not enforced.
- **Codex sandbox model:** permission profiles and the older sandbox settings do not compose.
  Following the documentation, `sandbox_mode` in any loaded config file now takes precedence over
  `default_permissions` (before, the highest layer that set either one decided), and a managed
  `allowed_permission_profiles` table selects permission profiles. `AW-CDX-003` is silent when the
  layers use permission profiles, since Codex then ignores `[sandbox_workspace_write]`, and the
  full-access combination of `AW-CDX-002` follows the same model.
- **`AW-CDX-014` across layers:** a profile is no longer checked on its own but with the layers it
  applies with: the user `config.toml` of its Codex home below it and the project
  `.codex/config.toml` above it. `approval_policy = "never"` in one of these files with full access
  in another is now reported as high, and the evidence names the other file; a profile setting
  that applies in none of these combinations (a `default_permissions` that a `sandbox_mode` of the
  user config overrides, for example) is no longer listed.
- **PowerShell 7** (follow-up to 0.1.0):
  - with `-Redact`, the label of a root on a network share (`\\server\share`) was `.` instead of
    the share name, because .NET Core sees that path as a root without a file name;
  - displayed paths are normalized only when they contain `.` or `..` segments: on .NET Core,
    the normalization turned `/` into `\` inside names and changed hostile values in the reports;
  - the SARIF test reads `endTimeUtc` from the raw text, because `ConvertFrom-Json` in
    PowerShell 7 converts ISO 8601 strings to dates.

## [0.1.0] - 2026-10-18

First public version.

### Added

- **Command-line tool and module.** `airworthy.ps1` and the `Airworthy` module, whose only export
  is `Invoke-Airworthy`. Options: `-Path`, `-Format`, `-OutFile`, `-NoUserProfile`,
  `-UserProfilePath`, `-UserSettingsPath`, `-Redact`, `-MinSeverity`, `-FailOn`, `-PassThru` and
  `-Quiet`. Exit codes 0 (no finding at the `-FailOn` level), 1 (findings at or above it) and 2
  (the analysis could not run).
- **Discovery** of the custom harness configuration of a folder and, unless `-NoUserProfile`, of the
  user profile: VS Code GitHub Copilot settings, workspace files, MCP files, custom agents, chat
  modes, instructions, prompt files and hook files; Claude Code project, local, user and managed
  settings, agents, `CLAUDE.md` and `.mcp.json`; Copilot CLI settings, MCP configuration, agents and
  hooks; `AGENTS.md` and root `.env*` files.
- **Effective settings.** VS Code layers (default < user < workspace file < workspace) with
  key-by-key merging of object settings and nested-notation flattening; Claude Code precedence
  (managed > local > project > user) and Copilot CLI precedence (local > repository > user); prompt
  file tools over custom agent tools.
- **71 rules** in six weighted categories (approvals and terminal, sandbox and network, MCP and
  supply chain, agent files and instructions, secrets, audit and observability): 27 VS Code
  (`AW-VSC`), 13 agent file (`AW-AGT`), 10 secret (`AW-SEC`), 6 MCP (`AW-MCP`), 10 Claude Code
  (`AW-CC`) and 5 Copilot CLI (`AW-CLI`) rules. Each rule has a fix, references to the OWASP Top 10
  for Agentic Applications and the official documentation, and a confidence level.
- **Scoring** from 0 to 100 with grades A to F: severity weights, a per-rule cap, weighted
  categories that apply only to the detected harnesses, and a cap at 69 when a critical finding
  exists.
- **Outputs:** a colored console summary, deterministic JSON, SARIF 2.1.0 for GitHub code scanning
  (`security-severity`, precision, help and tags), Markdown, and a self-contained offline HTML report
  with a score gauge, category scores, filters, search, sorting, expandable findings, a rules table,
  and light and dark themes.
- **`-Redact`** for shareable reports: the analyzed folder by its name only, the user profile as
  `~` and the user name masked, in every format, and a SARIF file without absolute base URIs.
- **Hardening against hostile repositories:** JSONC and YAML frontmatter parsers with depth and
  size limits, a 2 MB file limit, a 32 MB read budget per analysis, file count caps, link and
  junction checks, linear regexes with match timeouts for patterns taken from scanned files,
  secrets masked in every output, and an HTML report with inert JSON data, `textContent` rendering
  and a hash-based Content-Security-Policy.
- **Antivirus-friendly code:** ASCII-only scripts with no encoded payload, no dynamic execution and
  no download code; rule keywords live as tokens in `src/Data/*.json`.
- **Test suite** of more than 600 tests on Windows PowerShell 5.1, with its own minimal framework,
  synthetic fixtures, positive and negative tests for the rules, and a dedicated security suite.
- **CI:** a GitHub Actions workflow that runs the test suite on Windows PowerShell 5.1 and
  PowerShell 7, and checks the `-FailOn` exit codes on the shared fixtures; Dependabot updates for
  the pinned actions; issue and pull request templates.
- Example reports generated from the test fixtures in `examples/`.
- Documentation: README, contributing guide, architecture, security policy, Apache-2.0 license.

[0.2.0]: https://github.com/toonight/Airworthy
[0.1.0]: https://github.com/toonight/Airworthy
