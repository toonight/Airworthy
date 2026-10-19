# Security policy

Airworthy analyzes configuration files that may have been written by an attacker. A bug that lets
a repository take control of the tool, or of the reports it writes, is a security issue, and we
want to hear about it.

## Supported versions

Airworthy is young: only the latest release line receives security fixes.

| Version | Supported |
| --- | --- |
| 0.2.x (and `main`) | ✅ |
| 0.1.x and earlier snapshots | ❌ |

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a vulnerability.**

Report it privately through GitHub:

1. Open the repository's **Security** tab (named **Security and quality** in the current GitHub
   interface; if you cannot see it, look in the **⋯** menu).
2. Click **Report a vulnerability**. The form is also at
   <https://github.com/toonight/Airworthy/security/advisories/new>.
3. Fill in the form and click **Submit report**. The report stays private between you and the maintainers.

Please include:

- the Airworthy version or commit, and the output of `$PSVersionTable.PSVersion`;
- the command line you ran;
- a **synthetic** configuration that reproduces the issue, with fake secrets only;
- what happens, what you expected, and the impact you see.

> [!NOTE]
> **Maintainer:** private vulnerability reporting must be enabled for the button to appear. In the
> repository, go to **Settings**, then **Advanced Security** (in the "Security and quality" section
> of the sidebar), and click **Enable** next to **Private vulnerability reporting**.

## Scope

In scope: anything a scanned repository, user profile or configuration file can do to Airworthy
or to the people who read its reports, in particular:

- **Hostile repository input.** A crafted file that makes Airworthy run code, crash or hang, or
  that hides a risky setting from it on purpose through a parser flaw.
- **HTML report XSS.** Any way for scanned content to run script, inject markup or styles, load a
  remote resource, create a dangerous link or get around the Content-Security-Policy of the report.
- **Other output injection.** Scanned content that creates links or markup in the Markdown or SARIF
  output, or breaks the structure of the JSON or SARIF file.
- **ReDoS and resource exhaustion.** Inputs that make a regex, a parser or discovery run for a long
  time or use a lot of memory, despite the file size limits, the read budget and the match timeouts.
- **Path escape.** Reading a file outside the analyzed folder (through symbolic links, junctions,
  `..`, network or device paths), or anything at all outside it with `-NoUserProfile`; writing
  anywhere other than the `-OutFile` you asked for.
- **Secret leakage.** A secret shown in full, or recoverable, in any output format.
- **Antivirus hygiene.** A code path that makes endpoint protection flag Airworthy itself.

## Out of scope

- Vulnerabilities in VS Code, GitHub Copilot, Claude Code, Copilot CLI, Codex CLI, MCP servers or
  other products: report them to their vendors.
- Rules that miss a risky setting or flag a safe one, outside the hostile-input cases above:
  open a regular issue.
- Paths that `-Redact` documents it does not mask (absolute paths outside the analyzed folder and
  the user profile).
- Attacks that need write access to the Airworthy installation, a modified copy of the tool, or
  changes to the PowerShell execution policy or the system.
- Denial of service that needs input far beyond the documented limits, or a slow machine.
- Reports from automated scanners without a working proof of concept.

## Response targets

This is a volunteer project, so these are best-effort targets, not guarantees:

| Step | Target |
| --- | --- |
| Acknowledge the report | 7 days |
| Initial assessment | 14 days |
| Fix or mitigation for a confirmed issue | 90 days, sooner for critical issues |

We will keep you informed, agree on a disclosure date with you, publish a GitHub security advisory
when the fix is released, and credit you unless you prefer to stay anonymous.

## Security design

How Airworthy protects itself and its users (details in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)):

- **Static and offline.** It reads files only. It never runs an agent, an MCP server, a hook or a
  command it finds, and it makes no network call and sends no telemetry.
- **Hostile input everywhere.** Files over 2 MB are skipped, each analysis has a 32 MB read
  budget, discovery caps the number of files, and links or junctions that leave the analyzed folder
  are not followed. Invalid files and failing rules become findings instead of stopping the analysis.
- **Bounded regexes.** Built-in patterns are linear and capped per file. Patterns taken from scanned
  files run with a 50 ms timeout and a global budget.
- **Least reads.** With `-NoUserProfile`, only the analyzed folder is read (plus a
  `-UserSettingsPath` file you name). Otherwise only known agent configuration files of the
  profile, and the machine-wide Claude Code managed settings and Codex `requirements.toml`, are
  read as well.
- **Secrets masked.** Evidence never contains a full secret, and every output masks any remaining
  token-like value again before writing.
- **Safe outputs.** The HTML report embeds the results as inert, escaped JSON, renders them with
  `textContent` only, and enforces a Content-Security-Policy with `default-src 'none'` and SHA-256
  hashes for its single script and stylesheet. Markdown escapes scanned text, SARIF messages cannot
  carry embedded links, and the console shows control and bidirectional characters as `?`.
- **Privacy option.** `-Redact` hides the analyzed folder's path, the user profile and the user
  name in every output.
- **Antivirus-friendly code.** ASCII-only scripts, no encoded commands, no dynamic code execution
  and no download code; risky command names live as plain tokens in JSON data files.
- **Tested.** A dedicated security test suite runs a hostile repository through every output and
  checks the limits above.
