# Changelog

All notable changes to Airworthy are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

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

[0.1.0]: https://github.com/toonight/Airworthy
