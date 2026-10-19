# VS Code GitHub Copilot settings rules (AW-VSC-*): approvals, terminal, edits, URLs, sandbox and
# network, MCP settings, hooks, Workspace Trust and telemetry.
# Every rule reads effective values with Get-AwSetting (default < user < workspaceFile < workspace).
# Official pages read on 2026-10-18; uncertain semantics are flagged with Confidence 'medium'.

$script:AwVscDocs = @{
    Settings  = 'https://code.visualstudio.com/docs/copilot/reference/copilot-settings'
    Security  = 'https://code.visualstudio.com/docs/copilot/security'
    Approvals = 'https://code.visualstudio.com/docs/agents/run/approvals'
    Sandbox   = 'https://code.visualstudio.com/docs/agents/run/agent-sandboxing'
    Edits     = 'https://code.visualstudio.com/docs/copilot/chat/review-code-edits'
    Mcp       = 'https://code.visualstudio.com/docs/copilot/customization/mcp-servers'
    Hooks     = 'https://code.visualstudio.com/docs/copilot/customization/hooks'
    GhHooks   = 'https://docs.github.com/en/copilot/reference/hooks-reference'
    Trust     = 'https://code.visualstudio.com/docs/editing/workspaces/workspace-trust'
}

# Hostile files can hold huge objects: only the first entries of an object setting are analyzed.
$script:AwVscMaxEntries = 1000
$script:AwVscRegexCache = New-Object System.Collections.Hashtable -ArgumentList @([System.StringComparer]::Ordinal)

# Command names and flags come from src/Data/vscode.json, as separate tokens (CONTRIBUTING.md, Antivirus hygiene).
$script:AwVscTerminalData = (Read-AwDataFile -Name 'vscode')['terminal']
if ($script:AwVscTerminalData -isnot [System.Collections.IDictionary]) { throw 'src/Data/vscode.json: missing "terminal" object.' }

# Synthetic command lines. A rule that approves both probes approves any command (catch-all).
$script:AwVscProbeCommands = [string[]]@($script:AwVscTerminalData['catchAllProbes'])
# Commands that download, execute or publish code: label -> probe command lines. Each probe is the
# tokens of one form plus a neutral placeholder argument, so it never holds a URL or a payload.
$script:AwVscRiskyCommands = [ordered]@{}
foreach ($awVscEntry in @($script:AwVscTerminalData['riskyCommands'])) {
    $awVscProbes = foreach ($awVscForm in @($awVscEntry['forms'])) {
        (@($awVscForm) + @([string]$script:AwVscTerminalData['placeholderArgument'])) -join ' '
    }
    $script:AwVscRiskyCommands[[string]$awVscEntry['label']] = [string[]]@($awVscProbes)
}
# Windows download and exfiltration commands that should always require approval (labels above).
$script:AwVscExfilCommands = [string[]]@($script:AwVscTerminalData['approvalRequired'])
foreach ($awVscEntry in $script:AwVscExfilCommands) {
    if (-not $script:AwVscRiskyCommands.Contains($awVscEntry)) { throw "src/Data/vscode.json: approvalRequired label '$awVscEntry' is not in riskyCommands." }
}
# Entries suggested by the AW-VSC-006 fix, written as settings.json syntax.
$script:AwVscExfilFixText = (@($script:AwVscTerminalData['approvalRequiredFixKeys'] | ForEach-Object {
    '"' + ([string]$_).Replace('\', '\\').Replace('"', '\"') + '": false'
}) -join ', ')
Remove-Variable -Name awVscEntry, awVscProbes, awVscForm -ErrorAction SilentlyContinue

# Workspace-relative sample paths of files that steer or extend the agent (control files).
$script:AwVscControlFiles = @(
    '.vscode/settings.json', '.vscode/tasks.json', '.vscode/mcp.json', '.github/agents/reviewer.agent.md',
    'docs/helper.agent.md', '.github/copilot-instructions.md', '.github/instructions/tests.instructions.md',
    '.github/prompts/release.prompt.md', '.github/workflows/ci.yml', '.github/hooks/policy.json',
    '.git/config', '.git/hooks/pre-commit', '.mcp.json', '.env', '.env.local', '.claude/settings.json',
    'AGENTS.md', 'CLAUDE.md'
)
# A pattern that matches both probe paths applies to any file in the workspace.
$script:AwVscProbeFiles = @('awprobe.txt', 'src/awprobe/deep/file.bin')

# Credential folders the sandbox should deny (label -> canonical targets; one covered target is enough).
$script:AwVscCredentialDirs = [ordered]@{
    '~/.ssh'   = @('~/.ssh')
    '~/.aws'   = @('~/.aws')
    '~/.azure' = @('~/.azure')
    'GitHub CLI config' = @('~/.config/gh', '~/appdata/roaming/gh', '~/appdata/roaming/github cli')
}

# --- Generic helpers ------------------------------------------------------------------------

function Test-AwVscTrue {
    param($Value)
    return ($Value -is [bool] -and $Value)
}

function Test-AwVscKind {
    # True when Value has the JSON type that VS Code expects for the setting.
    param($Value, [string]$Kind)
    switch ($Kind) {
        'bool'   { return ($Value -is [bool]) }
        'string' { return ($Value -is [string]) }
        'number' { return ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) }
        'object' { return ($Value -is [System.Collections.IDictionary]) }
        'array'  { return ($Value -is [System.Array]) }
    }
    return ($null -ne $Value)
}

function Get-AwVscSetting {
    <#
    Effective setting with a typed value. VS Code ignores a value of the wrong type, so the
    documented default is used instead (Valid = $false). $null when the key is unknown.
    #>
    param($Ctx, [string]$Key, [string]$Kind = 'any')
    $s = Get-AwSetting -Ctx $Ctx -Key $Key
    if ($null -eq $s) { return $null }
    $value = $s.Value
    $valid = Test-AwVscKind $value $Kind
    if (-not $valid) {
        $value = $null
        if ($script:AwVSCodeDefaults.ContainsKey($Key) -and (Test-AwVscKind $script:AwVSCodeDefaults[$Key] $Kind)) {
            $value = $script:AwVSCodeDefaults[$Key]
        }
    }
    [pscustomobject]@{ Key = $Key; Setting = $s; Value = $value; Valid = $valid }
}

function Get-AwVscSortedKeys {
    # Ordinal-sorted keys of a map, capped; returned as ONE array (use it in foreach, not in a pipeline).
    param($Map)
    $keys = [string[]]@($Map.Keys)
    [Array]::Sort($keys, [StringComparer]::Ordinal)
    if ($keys.Count -gt $script:AwVscMaxEntries) { $keys = $keys[0..($script:AwVscMaxEntries - 1)] }
    return ,$keys
}

function Format-AwVscValue {
    # Short JSON-like rendering of a value for evidence.
    param($Value, [int]$Depth = 0)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' }; return 'false' }
    if ($Value -is [string]) { return '"' + $Value + '"' }
    if ($Value -is [System.Collections.IDictionary]) {
        if ($Depth -ge 2) { return '{...}' }
        $parts = foreach ($k in (Get-AwVscSortedKeys $Value)) { '"' + $k + '": ' + (Format-AwVscValue $Value[$k] ($Depth + 1)) }
        return '{' + (@($parts) -join ', ') + '}'
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        if ($Depth -ge 2) { return '[...]' }
        $parts = foreach ($v in $Value) { Format-AwVscValue $v ($Depth + 1) }
        return '[' + (@($parts) -join ', ') + ']'
    }
    return [string]$Value
}

function Limit-AwVscText {
    param([string]$Text, [int]$Max = 400)
    if ($Text.Length -le $Max) { return $Text }
    return $Text.Substring(0, $Max - 3) + '...'
}

function Join-AwVscQuoted {
    # 'a', 'b' (at most 12 items, then a count).
    param([string[]]$Items)
    $list = @($Items)
    $shown = @($list | Select-Object -First 12 | ForEach-Object { "'" + $_ + "'" })
    $text = $shown -join ', '
    if ($list.Count -gt 12) { $text += " (+$($list.Count - 12) more)" }
    return $text
}

# --- Locating settings in files -------------------------------------------------------------

function Get-AwVscLineAt {
    # 1-based line of Index in Text, counted on 16K-character chunks as in Get-AwCdxLineAt. It runs once
    # per located finding: a regex over the whole prefix built one Match per line, and PowerShell 7.3+
    # logs every .NET method call made from script with the full text of its string arguments.
    param([string]$Text, [int]$Index)
    if ($Index -le 0) { return 1 }
    $line = 1
    for ($at = 0; $at -lt $Index; $at += 16384) {
        $chunk = $Text.Substring($at, [Math]::Min(16384, $Index - $at))
        $line += $chunk.Length - $chunk.Replace("`n", '').Length
    }
    return $line
}

function Find-AwVscSettingIndex {
    # Index of a setting key in a settings file, in dotted or nested notation, or -1.
    param([string]$Text, [string]$Key)
    $i = $Text.IndexOf('"' + $Key + '"', [StringComparison]::Ordinal)
    if ($i -ge 0) { return $i }
    $pos = 0
    $i = -1
    foreach ($seg in $Key.Split('.')) {
        $j = $Text.IndexOf('"' + $seg + '"', $pos, [StringComparison]::Ordinal)
        if ($j -lt 0) { return -1 }
        $i = $j
        $pos = $j + $seg.Length + 2
    }
    return $i
}

function Find-AwVscLine {
    # Best-effort 1-based line of a setting (and of one of its entries), or $null.
    param([string]$Text, [string]$Key, [string]$EntryKey)
    # $Text.Length, not IsNullOrEmpty($Text): this runs once per finding on a whole settings file.
    if ($Text.Length -eq 0) { return $null }
    $i = Find-AwVscSettingIndex -Text $Text -Key $Key
    if ($EntryKey) {
        $needle = '"' + $EntryKey.Replace('\', '\\').Replace('"', '\"') + '"'
        $j = $Text.IndexOf($needle, [Math]::Max($i, 0), [StringComparison]::Ordinal)
        if ($j -ge 0) { $i = $j }
    }
    if ($i -lt 0) { return $null }
    return Get-AwVscLineAt -Text $Text -Index $i
}

function Get-AwVscEntryLayer {
    # Highest-precedence layer whose object value defines EntryKey; the setting itself otherwise.
    param($Setting, [string]$EntryKey)
    $found = $null
    foreach ($l in @(Get-AwMemberValue $Setting 'Layers')) {
        if ($null -ne $l -and $l.Value -is [System.Collections.IDictionary] -and $l.Value.Contains($EntryKey)) { $found = $l }
    }
    if ($found) { return $found }
    return [pscustomobject]@{ Source = $Setting.Source; Path = $Setting.Path; Value = $Setting.Value }
}

function Get-AwVscSourceLabel {
    param($Ctx, [string]$Source, [string]$Path)
    $label = switch ($Source) {
        'user'          { 'user settings' }
        'workspaceFile' { 'workspace file' }
        'workspace'     { 'workspace settings' }
        default         { [string]$Source }
    }
    return $label + ' ' + (Get-AwDisplayPath -Path $Path -Ctx $Ctx)
}

function Get-AwVscFallbackPath {
    # File where a default-valued setting would be fixed: workspace settings first.
    param($Ctx)
    $vs = Get-AwMemberValue $Ctx 'VSCode'
    foreach ($a in @((Get-AwMemberValue $vs 'WorkspaceSettings')) + @(Get-AwMemberValue $vs 'WorkspaceFiles') + @((Get-AwMemberValue $vs 'UserSettings'))) {
        if ($null -ne $a -and $a.Path) { return $a.Path }
    }
    return $null
}

function New-AwVscFinding {
    # Finding for a setting (or one entry of an object setting), located in the file that sets it.
    param($Ctx, [string]$RuleId, $Info, [string]$Evidence, [string]$Severity, [string]$Title, [string]$EntryKey)
    $s = $Info.Setting
    $origin = $s
    if ($EntryKey) { $origin = Get-AwVscEntryLayer -Setting $s -EntryKey $EntryKey }
    $path = $origin.Path
    $line = $null
    if ($path -and $origin.Source -ne 'default') {
        $raw = Get-AwFileText -Ctx $Ctx -Path $path
        $line = Find-AwVscLine -Text $raw -Key $s.Key -EntryKey $EntryKey
        $where = Get-AwVscSourceLabel -Ctx $Ctx -Source $origin.Source -Path $path
        if ($Info.Valid -or $EntryKey) { $note = "set in $where" }
        else { $note = "the value in $where has the wrong type and is ignored, so the default applies" }
    } else {
        $path = Get-AwVscFallbackPath -Ctx $Ctx
        $note = 'default value, not set in any settings file'
    }
    $text = (Limit-AwVscText $Evidence) + " ($note)"
    $params = @{ RuleId = $RuleId; Evidence = (Hide-AwSecretsInText $text); Location = @{ Path = $path; Line = $line; Key = $s.Key } }
    if ($Severity) { $params['Severity'] = $Severity }
    if ($Title) { $params['Title'] = $Title }
    New-AwFinding @params
}

function New-AwVscSettingFinding {
    # Shortcut: 'key = value' evidence plus an optional detail.
    param($Ctx, [string]$RuleId, $Info, [string]$Detail, [string]$Severity, [string]$Title)
    $ev = $Info.Key + ' = ' + (Format-AwVscValue $Info.Value)
    if ($Detail) { $ev += '; ' + $Detail }
    New-AwVscFinding -Ctx $Ctx -RuleId $RuleId -Info $Info -Evidence $ev -Severity $Severity -Title $Title
}

# --- Regex and glob helpers -----------------------------------------------------------------

function New-AwVscRegex {
    # Terminal regexes and globs come from the scanned files: they get the short timeout of
    # New-AwUntrustedRegex, and Test-AwVscRegexMatch stops running one that timed out.
    param([string]$Pattern, [System.Text.RegularExpressions.RegexOptions]$Options)
    $cacheKey = [string][int]$Options + ':' + $Pattern
    if ($script:AwVscRegexCache.ContainsKey($cacheKey)) { return $script:AwVscRegexCache[$cacheKey] }
    $rx = New-AwUntrustedRegex -Pattern $Pattern -Options $Options
    if ($script:AwVscRegexCache.Count -lt 5000) { $script:AwVscRegexCache[$cacheKey] = $rx }
    return $rx
}

function Test-AwVscRegexKey {
    # True for a '/pattern/flags' terminal rule key.
    param([string]$Key)
    if ($Key.Length -lt 2 -or $Key[0] -ne [char]'/') { return $false }
    $end = $Key.LastIndexOf('/')
    return ($end -gt 0 -and $Key.Substring($end + 1) -cmatch '^[dgimsuvy]*$')
}

function ConvertTo-AwVscRegex {
    # .NET regex for a '/pattern/flags' key; $null when it does not compile (it then matches nothing).
    param([string]$Key)
    $end = $Key.LastIndexOf('/')
    $flags = $Key.Substring($end + 1)
    $opts = [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    if ($flags.Contains('i')) { $opts = $opts -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase }
    if ($flags.Contains('m')) { $opts = $opts -bor [System.Text.RegularExpressions.RegexOptions]::Multiline }
    if ($flags.Contains('s')) { $opts = $opts -bor [System.Text.RegularExpressions.RegexOptions]::Singleline }
    return New-AwVscRegex -Pattern $Key.Substring(1, $end - 1) -Options $opts
}

function Test-AwVscRegexMatch {
    # A pattern that cannot be evaluated in time counts as not matching (the engine reports it).
    param($Regex, [string]$Text)
    return ((Test-AwUntrustedMatch -Regex $Regex -Text $Text) -eq $true)
}

function ConvertTo-AwVscGlobRegex {
    # Regex for a workspace-relative glob: ** (any segments), *, ?, {a,b} and [...] classes.
    param([string]$Glob)
    $g = $Glob.Replace('\', '/')
    while ($g.StartsWith('./')) { $g = $g.Substring(2) }
    $g = $g.TrimStart('/')
    $sb = New-Object System.Text.StringBuilder
    $inBrace = $false
    $i = 0
    while ($i -lt $g.Length) {
        $c = $g[$i]
        if ($c -eq [char]'*') {
            if ($i + 1 -lt $g.Length -and $g[$i + 1] -eq [char]'*') {
                # A run of three or more stars means the same as '**'; collapsing it keeps the regex
                # from backtracking exponentially on a hostile glob.
                $segmentStart = ($i -eq 0 -or $g[$i - 1] -eq [char]'/')
                $j = $i
                while ($j -lt $g.Length -and $g[$j] -eq [char]'*') { $j++ }
                if ($segmentStart -and $j -lt $g.Length -and $g[$j] -eq [char]'/') {
                    [void]$sb.Append('(?:[^/]*/)*'); $i = $j + 1; continue
                }
                [void]$sb.Append('.*'); $i = $j; continue
            }
            [void]$sb.Append('[^/]*'); $i++; continue
        }
        if ($c -eq [char]'?') { [void]$sb.Append('[^/]'); $i++; continue }
        if ($c -eq [char]'{' -and -not $inBrace) { [void]$sb.Append('(?:'); $inBrace = $true; $i++; continue }
        if ($c -eq [char]'}' -and $inBrace) { [void]$sb.Append(')'); $inBrace = $false; $i++; continue }
        if ($c -eq [char]',' -and $inBrace) { [void]$sb.Append('|'); $i++; continue }
        if ($c -eq [char]'[') {
            $close = $g.IndexOf(']', $i + 1)
            if ($close -gt $i + 1) {
                $body = $g.Substring($i + 1, $close - $i - 1)
                if ($body.StartsWith('!')) { $body = '^' + $body.Substring(1) }
                [void]$sb.Append('[' + $body.Replace('\', '\\').Replace('[', '\[') + ']')
                $i = $close + 1; continue
            }
        }
        [void]$sb.Append([regex]::Escape([string]$c))
        $i++
    }
    if ($inBrace) { return $null }
    $opts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    return New-AwVscRegex -Pattern ('^' + $sb.ToString() + '$') -Options $opts
}

# --- Terminal rules -------------------------------------------------------------------------

function Get-AwVscTerminalRules {
    # Effective terminal auto-approve rules with their decision (Approve) and origin layer.
    param($Ctx)
    $s = Get-AwSetting -Ctx $Ctx -Key 'chat.tools.terminal.autoApprove'
    if ($null -eq $s -or $s.Value -isnot [System.Collections.IDictionary]) { return }
    $ignoreDefaults = Get-AwVscSetting $Ctx 'chat.tools.terminal.ignoreDefaultAutoApproveRules' 'bool'
    $skipDefaults = ($null -ne $ignoreDefaults -and (Test-AwVscTrue $ignoreDefaults.Value))
    foreach ($k in (Get-AwVscSortedKeys $s.Value)) {
        $v = $s.Value[$k]
        $approve = $null
        if ($v -is [bool]) { $approve = $v }
        elseif ($v -is [System.Collections.IDictionary] -and $v['approve'] -is [bool]) { $approve = $v['approve'] }
        if ($null -eq $approve -or $k.Trim().Length -eq 0) { continue }
        $layer = Get-AwVscEntryLayer -Setting $s -EntryKey $k
        if ($skipDefaults -and $layer.Source -eq 'default') { continue }
        $isRegex = Test-AwVscRegexKey $k
        $rx = $null
        if ($isRegex) { $rx = ConvertTo-AwVscRegex $k }
        [pscustomobject]@{ Key = $k; Approve = $approve; IsRegex = $isRegex; Regex = $rx; Source = $layer.Source; Setting = $s }
    }
}

function Test-AwVscTerminalMatch {
    # Regex keys match anywhere unless anchored; plain names match the start of the command line.
    param($Rule, [string]$CommandLine)
    if ($Rule.IsRegex) { return (Test-AwVscRegexMatch $Rule.Regex $CommandLine) }
    $k = $Rule.Key.Trim()
    if (-not $CommandLine.StartsWith($k, [StringComparison]::OrdinalIgnoreCase)) { return $false }
    return ($CommandLine.Length -eq $k.Length -or [char]::IsWhiteSpace($CommandLine[$k.Length]))
}

function Test-AwVscCommandDenied {
    # True when a false (approval-required) rule matches one of the command lines.
    param([object[]]$Rules, [string[]]$CommandLines)
    foreach ($cmd in $CommandLines) {
        foreach ($r in $Rules) { if (-not $r.Approve -and (Test-AwVscTerminalMatch $r $cmd)) { return $true } }
    }
    return $false
}

function Get-AwVscRuleClass {
    # 'catch-all', 'broad' (a regex matching 3+ risky tools) or 'narrow' for an allow rule.
    param($Rule)
    $hits = 0
    foreach ($p in $script:AwVscProbeCommands) { if (Test-AwVscTerminalMatch $Rule $p) { $hits++ } }
    if ($hits -eq $script:AwVscProbeCommands.Count) { return 'catch-all' }
    if ($Rule.IsRegex) {
        $tools = 0
        foreach ($name in $script:AwVscRiskyCommands.Keys) {
            foreach ($cmd in $script:AwVscRiskyCommands[$name]) {
                if (Test-AwVscTerminalMatch $Rule $cmd) { $tools++; break }
            }
        }
        if ($tools -ge 3) { return 'broad' }
    }
    return 'narrow'
}

function Test-AwVscTerminalAutoApproveOn {
    param($Ctx)
    $info = Get-AwVscSetting $Ctx 'chat.tools.terminal.enableAutoApprove' 'bool'
    return ($null -ne $info -and (Test-AwVscTrue $info.Value))
}

function Test-AwVscSandboxOn {
    param($Ctx)
    $info = Get-AwVscSetting $Ctx 'chat.agent.sandbox.enabled' 'any'
    if ($null -eq $info) { return $false }
    $v = $info.Setting.Value
    return ((Test-AwVscTrue $v) -or ($v -is [string] -and $v -ceq 'on'))
}

# --- Path helpers ---------------------------------------------------------------------------

function ConvertTo-AwVscHomePath {
    # Lower-case, forward slashes, home folder as '~' (for comparing configured paths).
    param([string]$Path, $Ctx)
    $p = $Path.Trim().Replace('\', '/').ToLowerInvariant()
    $userProfile = [string](Get-AwMemberValue $Ctx 'UserProfile')
    if ($userProfile) {
        $up = $userProfile.Replace('\', '/').TrimEnd('/').ToLowerInvariant()
        if ($p -eq $up -or $p.StartsWith($up + '/')) { $p = '~' + $p.Substring($up.Length) }
    }
    $p = [regex]::Replace($p, '^(%userprofile%|\$home|\$\{env:userprofile\}|\$env:userprofile|\$\{env:home\}|\$\{userhome\}|%homedrive%%homepath%)', '~')
    $p = [regex]::Replace($p, '^(%appdata%|\$\{env:appdata\}|\$env:appdata)', '~/appdata/roaming')
    $p = [regex]::Replace($p, '^([a-z]:/users/[^/]+|/home/[^/]+|/users/[^/]+)(?=/|$)', '~')
    if ($p.Length -gt 1) { $p = $p.TrimEnd('/') }
    return $p
}

function Test-AwVscPathCovers {
    # True when Denied equals Target or is one of its parent folders.
    param([string]$Denied, [string]$Target)
    if ($Denied -eq $Target) { return $true }
    return $Target.StartsWith($Denied.TrimEnd('/') + '/')
}

function Test-AwVscBroadFolder {
    # Drive roots, the file system root and the home folder.
    param([string]$Path, $Ctx)
    $p = ConvertTo-AwVscHomePath -Path $Path -Ctx $Ctx
    return ($p -match '^([a-z]:/?|/|~|[a-z]:/users|/home|/users)$')
}

function Test-AwVscLocalEndpoint {
    param([string]$Url)
    [uri]$u = $null
    if (-not [System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$u)) { return $false }
    $h = $u.Host.ToLowerInvariant().Trim([char[]]@('[', ']'))
    return ($h -eq 'localhost' -or $h -eq '::1' -or $h -match '^127\.' -or $h.EndsWith('.localhost'))
}

function Get-AwVscUrlScope {
    # 'any' host, 'subdomain' wildcard, 'path' wildcard on one host, or 'exact'.
    param([string]$Pattern)
    $p = $Pattern.Trim()
    $rest = $p
    $m = [regex]::Match($p, '^[A-Za-z*][A-Za-z0-9+.*-]*://')
    if ($m.Success) { $rest = $p.Substring($m.Length) }
    $slash = $rest.IndexOf('/')
    $hostPart = $rest
    $pathPart = ''
    if ($slash -ge 0) { $hostPart = $rest.Substring(0, $slash); $pathPart = $rest.Substring($slash) }
    $at = $hostPart.LastIndexOf('@')
    if ($at -ge 0) { $hostPart = $hostPart.Substring($at + 1) }
    $hostPart = [regex]::Replace($hostPart, ':[0-9*]*$', '')
    if ($hostPart -eq '' -or $hostPart -match '^[*.]+$') { return 'any' }
    if ($hostPart.Contains('*')) {
        $fixed = $hostPart.Substring($hostPart.LastIndexOf('*') + 1).Trim('.')
        if (@($fixed.Split('.') | Where-Object { $_ }).Count -lt 2) { return 'any' }
        return 'subdomain'
    }
    if ($pathPart.Contains('*') -or ($m.Success -and $m.Value.Contains('*'))) { return 'path' }
    return 'exact'
}

function Get-AwVscHookEvents {
    # 'event (n)' list for a hook file, or $null when it defines no hook (or is not valid JSON).
    param($Artifact)
    $data = Get-AwMemberValue $Artifact 'Data'
    if ($null -eq $data) { return $null }
    $hooks = $data['hooks']
    if ($hooks -isnot [System.Collections.IDictionary]) { return $null }
    $parts = foreach ($e in (Get-AwVscSortedKeys $hooks)) { '{0} ({1})' -f $e, @($hooks[$e]).Count }
    if (@($parts).Count -eq 0) { return $null }
    return (@($parts) -join ', ')
}

function Get-AwVscMcpServerCount {
    # MCP servers VS Code loads: .vscode/mcp.json, root .mcp.json and the user mcp.json.
    param($Ctx)
    $count = 0
    $files = New-Object System.Collections.Generic.List[string]
    $rootMcp = [System.IO.Path]::Combine([string]$Ctx.Root, '.mcp.json')
    foreach ($a in @(Get-AwMemberValue $Ctx 'McpFiles')) {
        if ($null -eq $a) { continue }
        $isVscode = ($a.Harness -eq 'vscode-copilot') -or [string]::Equals($a.Path, $rootMcp, $script:AwPathComparison)
        if (-not $isVscode -or $null -eq $a.Data -or $a.Data['Servers'] -isnot [System.Collections.IDictionary]) { continue }
        $n = $a.Data['Servers'].Count
        if ($n -gt 0) { $count += $n; $files.Add((Get-AwDisplayPath -Path $a.Path -Ctx $Ctx)) }
    }
    return [pscustomobject]@{ Count = $count; Files = $files.ToArray() }
}

# --- Rules ----------------------------------------------------------------------------------

$docs = $script:AwVscDocs

Register-AwRule -Id 'AW-VSC-001' -Title 'Global auto-approval of tools enabled' `
    -Severity 'critical' -Category 'approvals' -Harness 'vscode-copilot' `
    -Description 'chat.tools.global.autoApprove = true auto-approves every tool call (terminal, file edits, MCP tools, URL fetches) in every workspace, so an instruction injected through a file, a web page or a tool output runs with no human in the loop. The settings reference warns that it disables critical security protections.' `
    -Fix 'Set "chat.tools.global.autoApprove": false. In managed environments, deploy the ChatToolsAutoApprove policy so that it cannot be turned back on.' `
    -References @('OWASP-ASI02', 'OWASP-ASI01', $docs.Settings, $docs.Approvals, $docs.Security) `
    -Confidence 'high' -Check {
        param($Ctx)
        $info = Get-AwVscSetting $Ctx 'chat.tools.global.autoApprove' 'bool'
        if ($null -eq $info -or -not (Test-AwVscTrue $info.Value)) { return }
        New-AwVscSettingFinding -Ctx $Ctx -RuleId 'AW-VSC-001' -Info $info
    }

Register-AwRule -Id 'AW-VSC-002' -Title 'Default permission level skips approvals' `
    -Severity 'high' -Category 'approvals' -Harness 'vscode-copilot' `
    -Description 'chat.permissions.default sets the permission level of new chat sessions. "autoApprove" (Allow all) runs every tool call without confirmation; "autopilot" also auto-approves all tools and keeps retrying on errors. Confidence is medium: the value is only the default of new sessions (users can change it per session and an enterprise policy can force Manual permissions), and how it combines with the Copilot harness permissions object is not fully documented.' `
    -Fix 'Set "chat.permissions.default": "default" (Manual permissions). The ChatToolsAutoApprove policy (false) hides Allow all and Assisted permissions.' `
    -References @('OWASP-ASI02', $docs.Settings, $docs.Approvals, $docs.Security) `
    -Confidence 'medium' -Check {
        param($Ctx)
        $info = Get-AwVscSetting $Ctx 'chat.permissions.default' 'string'
        if ($null -eq $info -or @('autoApprove', 'autopilot') -cnotcontains [string]$info.Value) { return }
        $mode = if ($info.Value -ceq 'autopilot') { 'Autopilot: tools auto-approved, retries on errors' } else { 'Allow all: no confirmation for any tool call' }
        New-AwVscSettingFinding -Ctx $Ctx -RuleId 'AW-VSC-002' -Info $info -Detail $mode
    }

Register-AwRule -Id 'AW-VSC-003' -Title 'Terminal command auto-approval enabled' `
    -Severity 'high' -Category 'approvals' -Harness 'vscode-copilot' `
    -Description 'chat.tools.terminal.enableAutoApprove = true (the default) runs terminal commands that match an allow rule without confirmation. The documentation calls command matching best effort, with known limits on shell aliases, quote concatenation and complex shell syntax. Severity is critical when a catch-all allow rule exists, or when Airworthy runs on Windows and chat.agent.sandbox.enabled is not "on": Windows sandboxing is Experimental and Local harness terminal commands are not sandboxed there, so a parser bypass runs with your full rights. Airworthy assumes the agent runs on the scanned machine.' `
    -Fix 'For sensitive agents set "chat.tools.terminal.enableAutoApprove": false (policy ChatToolsTerminalEnableAutoApprove). Otherwise keep only narrow read-only allow rules and turn on the agent sandbox ("chat.agent.sandbox.enabled": "on").' `
    -References @('OWASP-ASI05', 'OWASP-ASI02', $docs.Settings, $docs.Approvals, $docs.Security) `
    -Confidence 'high' -Check {
        param($Ctx)
        $info = Get-AwVscSetting $Ctx 'chat.tools.terminal.enableAutoApprove' 'bool'
        if ($null -eq $info -or -not (Test-AwVscTrue $info.Value)) { return }
        $reasons = New-Object System.Collections.Generic.List[string]
        $catchAll = @(Get-AwVscTerminalRules $Ctx | Where-Object { $_.Approve -and (Get-AwVscRuleClass $_) -eq 'catch-all' } | ForEach-Object { $_.Key })
        if ($catchAll.Count -gt 0) { $reasons.Add('catch-all allow rule ' + (Join-AwVscQuoted $catchAll)) }
        if ((Get-AwMemberValue $Ctx 'IsWindows') -and -not (Test-AwVscSandboxOn $Ctx)) {
            $reasons.Add('Windows host and chat.agent.sandbox.enabled is not "on", so approved commands run unsandboxed')
        }
        $sev = if ($reasons.Count -gt 0) { 'critical' } else { 'high' }
        New-AwVscSettingFinding -Ctx $Ctx -RuleId 'AW-VSC-003' -Info $info -Detail ($reasons -join '; ') -Severity $sev
    }

Register-AwRule -Id 'AW-VSC-004' -Title 'Catch-all or broad terminal allow rule' `
    -Severity 'critical' -Category 'approvals' -Harness 'vscode-copilot' `
    -Description 'A regex rule set to true in chat.tools.terminal.autoApprove matches any command (for example "/.*/"), so every command without a false rule is auto-approved (critical). A broad regex that matches three or more interpreters, downloaders or publishing commands has nearly the same effect (high). Airworthy tests each rule against synthetic command lines with .NET regex; a JavaScript-only regex feature makes the rule count as non-matching. Reported only while terminal auto-approval is on.' `
    -Fix 'Remove catch-all and broad regexes. Allow only exact read-only commands, for example "/^git (status|diff|log)\\b/": true.' `
    -References @('OWASP-ASI05', 'OWASP-ASI02', $docs.Settings, $docs.Approvals) `
    -Confidence 'high' -Check {
        param($Ctx)
        if (-not (Test-AwVscTerminalAutoApproveOn $Ctx)) { return }
        foreach ($r in @(Get-AwVscTerminalRules $Ctx | Where-Object { $_.Approve })) {
            $class = Get-AwVscRuleClass $r
            if ($class -eq 'narrow') { continue }
            $info = [pscustomobject]@{ Key = $r.Setting.Key; Setting = $r.Setting; Value = $r.Setting.Value; Valid = $true }
            if ($class -eq 'catch-all') {
                New-AwVscFinding -Ctx $Ctx -RuleId 'AW-VSC-004' -Info $info -EntryKey $r.Key -Severity 'critical' `
                    -Evidence ('chat.tools.terminal.autoApprove "' + $r.Key + '": true approves any command line')
            } else {
                New-AwVscFinding -Ctx $Ctx -RuleId 'AW-VSC-004' -Info $info -EntryKey $r.Key -Severity 'high' -Title 'Broad terminal allow rule' `
                    -Evidence ('chat.tools.terminal.autoApprove "' + $r.Key + '": true matches several risky commands (interpreters, downloaders or git push)')
            }
        }
    }

Register-AwRule -Id 'AW-VSC-005' -Title 'Risky command auto-approved in the terminal' `
    -Severity 'high' -Category 'approvals' -Harness 'vscode-copilot' `
    -Description ('An allow rule (true) in chat.tools.terminal.autoApprove matches a command that can download, execute or publish code: ' +
        (@($script:AwVscRiskyCommands.Keys) -join ', ') + '. One injected instruction can then exfiltrate data or run a payload with no approval. A false rule matching the same command takes precedence, as documented, and suppresses the finding. Reported only while terminal auto-approval is on; catch-all and broad rules are reported by AW-VSC-004.') `
    -Fix 'Remove the allow rule, or set the command to false so that it always requires approval (for example "npx": false, "git push": false).' `
    -References @('OWASP-ASI05', 'OWASP-ASI02', $docs.Settings, $docs.Approvals) `
    -Confidence 'high' -Check {
        param($Ctx)
        if (-not (Test-AwVscTerminalAutoApproveOn $Ctx)) { return }
        $rules = @(Get-AwVscTerminalRules $Ctx)
        foreach ($r in @($rules | Where-Object { $_.Approve })) {
            if ((Get-AwVscRuleClass $r) -ne 'narrow') { continue }
            $risky = New-Object System.Collections.Generic.List[string]
            foreach ($name in $script:AwVscRiskyCommands.Keys) {
                $samples = [string[]]$script:AwVscRiskyCommands[$name]
                $hit = @($samples | Where-Object { Test-AwVscTerminalMatch $r $_ })
                if ($hit.Count -gt 0 -and -not (Test-AwVscCommandDenied -Rules $rules -CommandLines $hit)) { $risky.Add($name) }
            }
            if ($risky.Count -eq 0) { continue }
            $info = [pscustomobject]@{ Key = $r.Setting.Key; Setting = $r.Setting; Value = $r.Setting.Value; Valid = $true }
            New-AwVscFinding -Ctx $Ctx -RuleId 'AW-VSC-005' -Info $info -EntryKey $r.Key `
                -Evidence ('chat.tools.terminal.autoApprove "' + $r.Key + '": true auto-approves ' + (Join-AwVscQuoted $risky.ToArray()))
        }
    }

Register-AwRule -Id 'AW-VSC-006' -Title 'Windows exfiltration commands lack approval-required rules' `
    -Severity 'medium' -Category 'approvals' -Harness 'vscode-copilot' `
    -Description ('While terminal auto-approval is on, the built-in approval-required rules cover only rm, rmdir, del, kill, curl, wget, eval, chmod, chown and Remove-Item. Windows download and exfiltration commands (' +
        ($script:AwVscExfilCommands -join ', ') + ') have no false entry, so any allow rule that matches them approves them silently. A false entry only FORCES APPROVAL: it does not block the command; only a PreToolUse hook that returns "deny" blocks it. Severity is low with built-in allow rules only, medium when custom allow rules exist. Confidence is medium: whether the built-in "curl" rule also matches curl.exe, and whether plain command names match case-insensitively, is not documented.') `
    -Fix ('Add approval-required entries to chat.tools.terminal.autoApprove: ' + $script:AwVscExfilFixText +
        '. To block a command, add a PreToolUse hook that returns permissionDecision "deny".') `
    -References @('OWASP-ASI05', 'OWASP-ASI02', $docs.Approvals, $docs.Settings, $docs.Hooks) `
    -Confidence 'medium' -Check {
        param($Ctx)
        if (-not (Test-AwVscTerminalAutoApproveOn $Ctx)) { return }
        $rules = @(Get-AwVscTerminalRules $Ctx)
        $missing = @($script:AwVscExfilCommands | Where-Object {
            -not (Test-AwVscCommandDenied -Rules $rules -CommandLines ([string[]]$script:AwVscRiskyCommands[$_]))
        })
        if ($missing.Count -eq 0) { return }
        $custom = @($rules | Where-Object { $_.Approve -and $_.Source -ne 'default' })
        $sev = if ($custom.Count -gt 0) { 'medium' } else { 'low' }
        $info = Get-AwVscSetting $Ctx 'chat.tools.terminal.autoApprove' 'object'
        if ($null -eq $info) {
            $info = Get-AwVscSetting $Ctx 'chat.tools.terminal.enableAutoApprove' 'bool'
        }
        New-AwVscFinding -Ctx $Ctx -RuleId 'AW-VSC-006' -Info $info -Severity $sev `
            -Evidence ('chat.tools.terminal.autoApprove has no approval-required (false) entry for ' + (Join-AwVscQuoted $missing) +
                "; $($custom.Count) custom allow rule(s). A false entry only forces approval, it does not block")
    }

Register-AwRule -Id 'AW-VSC-007' -Title 'Built-in terminal approval rules ignored' `
    -Severity 'high' -Category 'approvals' -Harness 'vscode-copilot' `
    -Description 'chat.tools.terminal.ignoreDefaultAutoApproveRules = true drops the built-in rules, including the approval-required rules for rm, del, curl, wget, eval and Remove-Item, which the documentation says are designed to protect against dangerous commands. Reported only while terminal auto-approval is on.' `
    -Fix 'Set "chat.tools.terminal.ignoreDefaultAutoApproveRules": false.' `
    -References @('OWASP-ASI05', $docs.Settings, $docs.Approvals) `
    -Confidence 'high' -Check {
        param($Ctx)
        if (-not (Test-AwVscTerminalAutoApproveOn $Ctx)) { return }
        $info = Get-AwVscSetting $Ctx 'chat.tools.terminal.ignoreDefaultAutoApproveRules' 'bool'
        if ($null -eq $info -or -not (Test-AwVscTrue $info.Value)) { return }
        New-AwVscSettingFinding -Ctx $Ctx -RuleId 'AW-VSC-007' -Info $info -Detail 'built-in deny rules such as rm, curl and Remove-Item no longer apply'
    }

Register-AwRule -Id 'AW-VSC-008' -Title 'Terminal prompts answered automatically' `
    -Severity 'medium' -Category 'approvals' -Harness 'vscode-copilot' `
    -Description 'chat.tools.terminal.autoReplyToPrompts = true answers interactive terminal prompts (confirmations, overwrite or install questions) with a default reply, which removes a last-chance confirmation from commands the agent runs.' `
    -Fix 'Set "chat.tools.terminal.autoReplyToPrompts": false.' `
    -References @('OWASP-ASI09', 'OWASP-ASI02', $docs.Settings) `
    -Confidence 'high' -Check {
        param($Ctx)
        $info = Get-AwVscSetting $Ctx 'chat.tools.terminal.autoReplyToPrompts' 'bool'
        if ($null -eq $info -or -not (Test-AwVscTrue $info.Value)) { return }
        New-AwVscSettingFinding -Ctx $Ctx -RuleId 'AW-VSC-008' -Info $info
    }

Register-AwRule -Id 'AW-VSC-009' -Title 'Edit auto-approval covers agent control files' `
    -Severity 'high' -Category 'approvals' -Harness 'vscode-copilot' `
    -Description 'A true pattern in chat.tools.edits.autoApprove lets the agent edit matching files without approval. When it covers control files (.vscode settings and tasks, mcp.json, agent, instruction and prompt files, .github/workflows, .github/hooks, .git, .env*), an injected instruction can grant itself more rights or plant code that runs later: the CVE-2025-53773 class of attack (high). A broad pattern such as "**" or "**/*" whose control files all have a false entry still auto-approves build and hook scripts (medium). Confidence is medium: the documentation does not say how overlapping patterns are resolved (Airworthy assumes a false pattern wins, as in the documented example) or whether patterns match the full workspace-relative path.' `
    -Fix 'Remove broad true patterns and add false entries for control files: "**/.vscode/**", "**/*.agent.md", "**/.github/agents/**", "**/.github/copilot-instructions.md", "**/.github/instructions/**", "**/.github/prompts/**", "**/.github/workflows/**", "**/.github/hooks/**", "**/.git/**", "**/mcp.json", "**/.mcp.json" and "**/.env*" set to false.' `
    -References @('OWASP-ASI03', 'OWASP-ASI06', $docs.Edits, $docs.Settings, $docs.Security) `
    -Confidence 'medium' -Check {
        param($Ctx)
        $info = Get-AwVscSetting $Ctx 'chat.tools.edits.autoApprove' 'object'
        if ($null -eq $info -or $info.Value -isnot [System.Collections.IDictionary]) { return }
        $entries = @(foreach ($k in (Get-AwVscSortedKeys $info.Value)) {
            $v = $info.Value[$k]
            if ($v -is [bool]) { [pscustomobject]@{ Key = $k; Approve = $v; Regex = (ConvertTo-AwVscGlobRegex $k) } }
        })
        $deny = @($entries | Where-Object { -not $_.Approve })
        foreach ($e in @($entries | Where-Object { $_.Approve })) {
            $covered = @(foreach ($f in $script:AwVscControlFiles) {
                if ((Test-AwVscRegexMatch $e.Regex $f) -and @($deny | Where-Object { Test-AwVscRegexMatch $_.Regex $f }).Count -eq 0) { $f }
            })
            $broad = @($script:AwVscProbeFiles | Where-Object { Test-AwVscRegexMatch $e.Regex $_ }).Count -eq $script:AwVscProbeFiles.Count
            $prefix = 'chat.tools.edits.autoApprove "' + $e.Key + '": true'
            if ($covered.Count -gt 0) {
                $what = if ($broad) { ' is a broad pattern and auto-approves edits to ' } else { ' auto-approves edits to ' }
                New-AwVscFinding -Ctx $Ctx -RuleId 'AW-VSC-009' -Info $info -EntryKey $e.Key -Evidence ($prefix + $what + (Join-AwVscQuoted $covered))
            } elseif ($broad) {
                New-AwVscFinding -Ctx $Ctx -RuleId 'AW-VSC-009' -Info $info -EntryKey $e.Key -Severity 'medium' -Title 'Broad edit auto-approval pattern' `
                    -Evidence ($prefix + ' matches every file; control files have false entries, but build and hook scripts are auto-approved')
            }
        }
    }

Register-AwRule -Id 'AW-VSC-010' -Title 'Wildcard URL auto-approval' `
    -Severity 'high' -Category 'sandbox-network' -Harness 'vscode-copilot' `
    -Description 'Wildcard entries in chat.tools.urls.autoApprove approve fetch requests, responses, or both, without review. An any-host wildcard ("*", "https://*", "*.com") lets an injected instruction send data to any server and feeds untrusted pages to the model (high); a subdomain wildcard (medium) or a path wildcard on one host (low) extends trust to content that other people may control. Confidence is medium: the exact wildcard matching rules are not fully documented.' `
    -Fix 'List exact URLs only. Prefer {"approveRequest": true, "approveResponse": false} so that fetched content is still reviewed, and remove "*", "https://*" and top-level-domain wildcards.' `
    -References @('OWASP-ASI01', 'OWASP-ASI02', $docs.Approvals, $docs.Settings, $docs.Security) `
    -Confidence 'medium' -Check {
        param($Ctx)
        $info = Get-AwVscSetting $Ctx 'chat.tools.urls.autoApprove' 'any'
        if ($null -eq $info) { return }
        $v = $info.Setting.Value
        $entries = New-Object System.Collections.ArrayList
        if ($v -is [System.Collections.IDictionary]) {
            foreach ($k in (Get-AwVscSortedKeys $v)) {
                $e = $v[$k]
                if ($e -is [bool]) { [void]$entries.Add(@($k, $e, $e)) }
                elseif ($e -is [System.Collections.IDictionary]) { [void]$entries.Add(@($k, (Test-AwVscTrue $e['approveRequest']), (Test-AwVscTrue $e['approveResponse']))) }
            }
        } elseif ($v -is [System.Array]) {
            foreach ($k in @($v | Select-Object -First $script:AwVscMaxEntries)) { if ($k -is [string]) { [void]$entries.Add(@($k, $true, $true)) } }
        }
        $severity = @{ any = 'high'; subdomain = 'medium'; path = 'low' }
        $info = [pscustomobject]@{ Key = $info.Key; Setting = $info.Setting; Value = $v; Valid = $true }
        foreach ($e in $entries) {
            $pattern = [string]$e[0]
            if (-not ($e[1] -or $e[2])) { continue }
            $scope = Get-AwVscUrlScope $pattern
            if (-not $severity.ContainsKey($scope)) { continue }
            $steps = if ($e[1] -and $e[2]) { 'requests and responses' } elseif ($e[1]) { 'requests' } else { 'responses' }
            $label = @{ any = 'any host'; subdomain = 'every subdomain'; path = 'every path of the host' }[$scope]
            New-AwVscFinding -Ctx $Ctx -RuleId 'AW-VSC-010' -Info $info -EntryKey $pattern -Severity $severity[$scope] `
                -Evidence ('chat.tools.urls.autoApprove "' + $pattern + '" auto-approves ' + $steps + ' for ' + $label)
        }
    }

Register-AwRule -Id 'AW-VSC-011' -Title 'Terminal risk assessment disabled' `
    -Severity 'low' -Category 'approvals' -Harness 'vscode-copilot' `
    -Description 'chat.tools.riskAssessment.enabled = false removes the AI-generated risk badge from terminal command confirmations. The badge helps the person who approves, but it is NOT a security boundary (model-based risk assessments can make mistakes), hence the low severity.' `
    -Fix 'Set "chat.tools.riskAssessment.enabled": true, and keep human approval as the real control.' `
    -References @('OWASP-ASI09', $docs.Settings, $docs.Security) `
    -Confidence 'high' -Check {
        param($Ctx)
        $info = Get-AwVscSetting $Ctx 'chat.tools.riskAssessment.enabled' 'bool'
        if ($null -eq $info -or $info.Value -isnot [bool] -or $info.Value) { return }
        New-AwVscSettingFinding -Ctx $Ctx -RuleId 'AW-VSC-011' -Info $info -Detail 'the risk badge is an aid, not a security boundary'
    }

Register-AwRule -Id 'AW-VSC-012' -Title 'Agent sandbox disabled' `
    -Severity 'high' -Category 'sandbox-network' -Harness 'vscode-copilot' `
    -Description 'chat.agent.sandbox.enabled is not "on" (the documented default is "off"), so terminal commands and the MCP and language servers started by the agent run with your full user rights, file system and network. Confidence is medium: the security page says Copilot harness sessions are sandboxed by default while the settings and sandboxing pages document "off"; Windows support is Experimental and Local harness sessions use a different sandbox. Even when on, the sandbox is not a VM or a user-account boundary.' `
    -Fix 'Set "chat.agent.sandbox.enabled": "on" (Copilot harness), or require it with Copilot managed settings. On Windows, prefer a dev container or WSL2 for agent work.' `
    -References @('OWASP-ASI05', 'OWASP-ASI03', $docs.Sandbox, $docs.Settings, $docs.Security) `
    -Confidence 'medium' -Check {
        param($Ctx)
        $info = Get-AwVscSetting $Ctx 'chat.agent.sandbox.enabled' 'any'
        if ($null -eq $info -or (Test-AwVscSandboxOn $Ctx)) { return }
        $detail = ''
        if (Get-AwMemberValue $Ctx 'IsWindows') { $detail = 'Windows host: sandbox support is Experimental and Local harness terminal commands are not sandboxed' }
        $info = [pscustomobject]@{ Key = $info.Key; Setting = $info.Setting; Value = $info.Setting.Value; Valid = $true }
        New-AwVscSettingFinding -Ctx $Ctx -RuleId 'AW-VSC-012' -Info $info -Detail $detail
    }

Register-AwRule -Id 'AW-VSC-013' -Title 'Unrestricted network egress' `
    -Severity 'medium' -Category 'sandbox-network' -Harness 'vscode-copilot' `
    -Description 'chat.agent.sandbox.network.allowNetwork = true (default) with no chat.agent.sandbox.network.allowedDomains, and chat.agent.networkFilter off with no chat.agent.allowedNetworkDomains: sandboxed commands, the fetch tool and the integrated browser can reach any host, the usual exfiltration path of prompt-injection attacks. Confidence is medium: the documentation does not say whether a non-empty allowedDomains blocks every other destination (check with /sandbox policy).' `
    -Fix 'Set "chat.agent.sandbox.network.allowNetwork": false, or keep it true with a narrow "chat.agent.sandbox.network.allowedDomains" list; also set "chat.agent.networkFilter": true with a narrow "chat.agent.allowedNetworkDomains".' `
    -References @('OWASP-ASI02', 'OWASP-ASI05', $docs.Sandbox, $docs.Settings) `
    -Confidence 'medium' -Check {
        param($Ctx)
        $info = Get-AwVscSetting $Ctx 'chat.agent.sandbox.network.allowNetwork' 'bool'
        if ($null -eq $info -or -not (Test-AwVscTrue $info.Value)) { return }
        $filter = Get-AwVscSetting $Ctx 'chat.agent.networkFilter' 'bool'
        if ($null -ne $filter -and (Test-AwVscTrue $filter.Value)) { return }
        foreach ($key in @('chat.agent.sandbox.network.allowedDomains', 'chat.agent.allowedNetworkDomains')) {
            $list = Get-AwVscSetting $Ctx $key 'array'
            if ($null -ne $list -and @($list.Value | Where-Object { $_ -is [string] -and $_.Trim() }).Count -gt 0) { return }
        }
        $state = if (Test-AwVscSandboxOn $Ctx) { 'sandbox on' } else { 'sandbox off' }
        New-AwVscSettingFinding -Ctx $Ctx -RuleId 'AW-VSC-013' -Info $info `
            -Detail "chat.agent.networkFilter is off and no allowed domains are listed ($state)"
    }

Register-AwRule -Id 'AW-VSC-014' -Title 'Commands may leave the sandbox' `
    -Severity 'medium' -Category 'sandbox-network' -Harness 'vscode-copilot' `
    -Description 'chat.agent.sandbox.allowUnsandboxedCommands = true (default) lets the agent ask to run a blocked command outside the sandbox; after one approval (or one for the whole session) the command runs with your full rights. Approval fatigue and misleading requests make this an easy escape. Reported only when the sandbox is on.' `
    -Fix 'Set "chat.agent.sandbox.allowUnsandboxedCommands": false; such requests then fail instead of offering "Allow Outside Sandbox".' `
    -References @('OWASP-ASI05', 'OWASP-ASI09', $docs.Sandbox, $docs.Settings) `
    -Confidence 'high' -Check {
        param($Ctx)
        if (-not (Test-AwVscSandboxOn $Ctx)) { return }
        $info = Get-AwVscSetting $Ctx 'chat.agent.sandbox.allowUnsandboxedCommands' 'bool'
        if ($null -eq $info -or -not (Test-AwVscTrue $info.Value)) { return }
        New-AwVscSettingFinding -Ctx $Ctx -RuleId 'AW-VSC-014' -Info $info
    }

Register-AwRule -Id 'AW-VSC-015' -Title 'Sandbox grants developer-tool access' `
    -Severity 'medium' -Category 'sandbox-network' -Harness 'vscode-copilot' `
    -Description 'chat.agent.sandbox.fileSystem.allowDevToolAccess = true (default) gives sandboxed processes read access to tool directories on PATH, toolchains and developer-tool configuration and caches, which can include registry tokens, plus read/write access to shared build caches. Reported only when the sandbox is on.' `
    -Fix 'Set "chat.agent.sandbox.fileSystem.allowDevToolAccess": false, then grant the few paths a build needs with "readonlyPaths".' `
    -References @('OWASP-ASI03', $docs.Sandbox, $docs.Settings) `
    -Confidence 'high' -Check {
        param($Ctx)
        if (-not (Test-AwVscSandboxOn $Ctx)) { return }
        $info = Get-AwVscSetting $Ctx 'chat.agent.sandbox.fileSystem.allowDevToolAccess' 'bool'
        if ($null -eq $info -or -not (Test-AwVscTrue $info.Value)) { return }
        New-AwVscSettingFinding -Ctx $Ctx -RuleId 'AW-VSC-015' -Info $info -Detail 'developer-tool configuration and caches can hold registry tokens'
    }

Register-AwRule -Id 'AW-VSC-016' -Title 'Credentials injected into the sandbox' `
    -Severity 'medium' -Category 'sandbox-network' -Harness 'vscode-copilot' `
    -Description 'chat.agent.sandbox.credentials.authenticategit and authenticategh = true (defaults) give sandboxed processes your HTTPS Git credentials and your GitHub CLI account. The documentation warns that such a process can act with the permissions of the associated account: push code, open pull requests, read private repositories. Reported only when the sandbox is on.' `
    -Fix 'Set "chat.agent.sandbox.credentials.authenticategit": false and "chat.agent.sandbox.credentials.authenticategh": false unless the task needs them; when it does, use a fine-grained, short-lived token.' `
    -References @('OWASP-ASI03', $docs.Sandbox, $docs.Settings) `
    -Confidence 'high' -Check {
        param($Ctx)
        if (-not (Test-AwVscSandboxOn $Ctx)) { return }
        $what = [ordered]@{
            'chat.agent.sandbox.credentials.authenticategit' = 'your HTTPS Git credentials'
            'chat.agent.sandbox.credentials.authenticategh'  = 'your GitHub CLI account'
        }
        foreach ($key in $what.Keys) {
            $info = Get-AwVscSetting $Ctx $key 'bool'
            if ($null -eq $info -or -not (Test-AwVscTrue $info.Value)) { continue }
            New-AwVscSettingFinding -Ctx $Ctx -RuleId 'AW-VSC-016' -Info $info -Detail ('sandboxed processes get ' + $what[$key])
        }
    }

Register-AwRule -Id 'AW-VSC-017' -Title 'Credential folders not denied in the sandbox' `
    -Severity 'medium' -Category 'sandbox-network' -Harness 'vscode-copilot' `
    -Description 'chat.agent.sandbox.fileSystem.userConfiguredPaths.deniedPaths does not list ~/.ssh, ~/.aws, ~/.azure or the GitHub CLI configuration (~/.config/gh, %APPDATA%\GitHub CLI). deniedPaths takes precedence over every other grant, so listing them is cheap defense in depth. Severity is medium when developer-tool access is on, low otherwise. Reported only when the sandbox is on. Confidence is medium: whether the sandbox can read these folders by default, and whether ~ and environment variables are expanded, is not documented.' `
    -Fix 'Add "deniedPaths": ["~/.ssh", "~/.aws", "~/.azure", "~/.config/gh", "%APPDATA%/GitHub CLI"] to chat.agent.sandbox.fileSystem.userConfiguredPaths (use absolute paths of the machine that runs the agent if ~ is not expanded).' `
    -References @('OWASP-ASI03', $docs.Sandbox, $docs.Settings) `
    -Confidence 'medium' -Check {
        param($Ctx)
        if (-not (Test-AwVscSandboxOn $Ctx)) { return }
        $info = Get-AwVscSetting $Ctx 'chat.agent.sandbox.fileSystem.userConfiguredPaths' 'object'
        if ($null -eq $info) { return }
        $denied = @()
        if ($info.Value -is [System.Collections.IDictionary] -and $info.Value['deniedPaths'] -is [System.Array]) {
            $denied = @($info.Value['deniedPaths'] | Where-Object { $_ -is [string] -and $_.Trim() } | ForEach-Object { ConvertTo-AwVscHomePath -Path $_ -Ctx $Ctx })
        }
        $missing = @(foreach ($label in $script:AwVscCredentialDirs.Keys) {
            $ok = $false
            foreach ($t in $script:AwVscCredentialDirs[$label]) { foreach ($d in $denied) { if (Test-AwVscPathCovers $d $t) { $ok = $true } } }
            if (-not $ok) { $label }
        })
        if ($missing.Count -eq 0) { return }
        $devTools = Get-AwVscSetting $Ctx 'chat.agent.sandbox.fileSystem.allowDevToolAccess' 'bool'
        $sev = if ($null -ne $devTools -and (Test-AwVscTrue $devTools.Value)) { 'medium' } else { 'low' }
        New-AwVscFinding -Ctx $Ctx -RuleId 'AW-VSC-017' -Info $info -Severity $sev `
            -Evidence ('chat.agent.sandbox.fileSystem.userConfiguredPaths.deniedPaths does not cover ' + (Join-AwVscQuoted $missing))
    }

Register-AwRule -Id 'AW-VSC-018' -Title 'Sandboxed commands auto-approved with open network' `
    -Severity 'high' -Category 'sandbox-network' -Harness 'vscode-copilot' `
    -Description 'chat.agent.sandbox.allowAutoApprove = true (Local harness, default) auto-approves terminal commands that run inside the sandbox, while chat.agent.sandbox.network.allowNetwork = true leaves egress open: the sandbox is then the only barrier, and it does not stop data from leaving. Severity is medium when allowedDomains restricts destinations. Reported only when the sandbox is on. Confidence is medium: allowAutoApprove applies to the Local harness sandbox, whose Windows support is being retired, and its interaction with the network settings is not fully documented.' `
    -Fix 'Set "chat.agent.sandbox.allowAutoApprove": false, or "chat.agent.sandbox.network.allowNetwork": false.' `
    -References @('OWASP-ASI02', 'OWASP-ASI05', $docs.Settings, $docs.Sandbox) `
    -Confidence 'medium' -Check {
        param($Ctx)
        if (-not (Test-AwVscSandboxOn $Ctx)) { return }
        $info = Get-AwVscSetting $Ctx 'chat.agent.sandbox.allowAutoApprove' 'bool'
        if ($null -eq $info -or -not (Test-AwVscTrue $info.Value)) { return }
        $net = Get-AwVscSetting $Ctx 'chat.agent.sandbox.network.allowNetwork' 'bool'
        if ($null -eq $net -or -not (Test-AwVscTrue $net.Value)) { return }
        $domains = Get-AwVscSetting $Ctx 'chat.agent.sandbox.network.allowedDomains' 'array'
        $restricted = ($null -ne $domains -and @($domains.Value | Where-Object { $_ -is [string] -and $_.Trim() }).Count -gt 0)
        $sev = if ($restricted) { 'medium' } else { 'high' }
        $detail = 'chat.agent.sandbox.network.allowNetwork = true'
        if ($restricted) { $detail += ' (destinations limited by allowedDomains)' } else { $detail += ' with no allowedDomains' }
        New-AwVscSettingFinding -Ctx $Ctx -RuleId 'AW-VSC-018' -Info $info -Detail $detail -Severity $sev
    }

Register-AwRule -Id 'AW-VSC-019' -Title 'Read access outside the workspace' `
    -Severity 'medium' -Category 'sandbox-network' -Harness 'vscode-copilot' `
    -Description 'github.copilot.chat.additionalReadAccessFolders grants the built-in agent tools read-only access to folders outside the workspace. Anything there (keys, tokens, other projects) can be read and then leaked by an injected instruction. A drive root, the file system root or the home folder is high.' `
    -Fix 'Set "github.copilot.chat.additionalReadAccessFolders": [], or list a few specific folders that hold no secrets.' `
    -References @('OWASP-ASI03', 'OWASP-ASI02', $docs.Settings, $docs.Security) `
    -Confidence 'high' -Check {
        param($Ctx)
        $info = Get-AwVscSetting $Ctx 'github.copilot.chat.additionalReadAccessFolders' 'array'
        if ($null -eq $info) { return }
        $folders = @($info.Value | Where-Object { $_ -is [string] -and $_.Trim() } | Select-Object -First $script:AwVscMaxEntries)
        if ($folders.Count -eq 0) { return }
        $broad = @($folders | Where-Object { Test-AwVscBroadFolder -Path $_ -Ctx $Ctx })
        $sev = if ($broad.Count -gt 0) { 'high' } else { 'medium' }
        $detail = if ($broad.Count -gt 0) { 'includes a drive root or the home folder: ' + (Join-AwVscQuoted $broad) } else { '' }
        New-AwVscSettingFinding -Ctx $Ctx -RuleId 'AW-VSC-019' -Info $info -Detail $detail -Severity $sev
    }

Register-AwRule -Id 'AW-VSC-020' -Title 'High agent request limit' `
    -Severity 'low' -Category 'approvals' -Harness 'vscode-copilot' `
    -Description 'chat.agent.maxRequests (default 25) is the number of requests the agent makes before it asks you to continue. A value above 100 lets a hijacked or looping agent run long chains of tool calls between human check-ins; 1000 or more is medium.' `
    -Fix 'Keep "chat.agent.maxRequests" between 25 and 100, sized to the task.' `
    -References @('OWASP-ASI08', 'OWASP-ASI10', $docs.Settings) `
    -Confidence 'high' -Check {
        param($Ctx)
        $info = Get-AwVscSetting $Ctx 'chat.agent.maxRequests' 'number'
        if ($null -eq $info -or $null -eq $info.Value -or [double]$info.Value -le 100) { return }
        $sev = if ([double]$info.Value -ge 1000) { 'medium' } else { 'low' }
        New-AwVscSettingFinding -Ctx $Ctx -RuleId 'AW-VSC-020' -Info $info -Detail 'default 25' -Severity $sev
    }

Register-AwRule -Id 'AW-VSC-021' -Title 'MCP server discovery from other applications' `
    -Severity 'medium' -Category 'mcp-supply-chain' -Harness 'vscode-copilot' `
    -Description 'chat.mcp.discovery.enabled imports MCP server configurations from other applications (Claude Desktop, Copilot CLI, Cursor, Windsurf). Servers that were never reviewed for VS Code become available to the agent; VS Code only shows a trust dialog when such a server first starts or its configuration changes.' `
    -Fix 'Set "chat.mcp.discovery.enabled": false and declare the servers you need explicitly in mcp.json after review.' `
    -References @('OWASP-ASI04', $docs.Mcp, $docs.Settings) `
    -Confidence 'high' -Check {
        param($Ctx)
        $info = Get-AwVscSetting $Ctx 'chat.mcp.discovery.enabled' 'any'
        if ($null -eq $info) { return }
        $v = $info.Setting.Value
        $on = Test-AwVscTrue $v
        if (-not $on -and $v -is [System.Collections.IDictionary]) {
            foreach ($app in (Get-AwVscSortedKeys $v)) { if (Test-AwVscTrue $v[$app]) { $on = $true } }
        }
        if (-not $on) { return }
        $info = [pscustomobject]@{ Key = $info.Key; Setting = $info.Setting; Value = $v; Valid = $true }
        New-AwVscSettingFinding -Ctx $Ctx -RuleId 'AW-VSC-021' -Info $info
    }

Register-AwRule -Id 'AW-VSC-022' -Title 'MCP servers start automatically' `
    -Severity 'low' -Category 'mcp-supply-chain' -Harness 'vscode-copilot' `
    -Description 'chat.mcp.autostart = "newAndOutdated" (default) or "onlyNew" starts MCP servers automatically when you send a chat message. Workspace servers (.vscode/mcp.json, .mcp.json) inherit Workspace Trust and start without a separate MCP prompt, so a new (or, with newAndOutdated, changed) server pulled with the repository runs code on the next message. Reported only when MCP servers are configured. Confidence is medium: the setting is Experimental.' `
    -Fix 'Set "chat.mcp.autostart": "never" and start servers manually after reviewing configuration changes.' `
    -References @('OWASP-ASI04', $docs.Mcp, $docs.Settings) `
    -Confidence 'medium' -Check {
        param($Ctx)
        $info = Get-AwVscSetting $Ctx 'chat.mcp.autostart' 'string'
        if ($null -eq $info -or @('newAndOutdated', 'onlyNew') -cnotcontains [string]$info.Value) { return }
        $servers = Get-AwVscMcpServerCount -Ctx $Ctx
        if ($servers.Count -eq 0) { return }
        New-AwVscSettingFinding -Ctx $Ctx -RuleId 'AW-VSC-022' -Info $info `
            -Detail ('{0} MCP server(s) in {1}' -f $servers.Count, ($servers.Files -join ', '))
    }

Register-AwRule -Id 'AW-VSC-023' -Title 'MCP server pre-authorized for sampling' `
    -Severity 'medium' -Category 'mcp-supply-chain' -Harness 'vscode-copilot' `
    -Description 'chat.mcp.serverSampling pre-authorizes MCP servers to request model completions (sampling) through your Copilot account. A malicious or compromised server can spend your quota and push its own prompts into a model call; a "*" model list is the widest grant. Confidence is medium: the value format is not described on the settings page.' `
    -Fix 'Set "chat.mcp.serverSampling": {} unless a reviewed server needs sampling; then allow one specific model for that server only.' `
    -References @('OWASP-ASI04', 'OWASP-ASI02', $docs.Settings, $docs.Mcp) `
    -Confidence 'medium' -Check {
        param($Ctx)
        $info = Get-AwVscSetting $Ctx 'chat.mcp.serverSampling' 'object'
        if ($null -eq $info -or $info.Value -isnot [System.Collections.IDictionary]) { return }
        foreach ($server in (Get-AwVscSortedKeys $info.Value)) {
            $cfg = $info.Value[$server]
            $models = @()
            if ($cfg -is [System.Collections.IDictionary] -and $cfg['allowedModels'] -is [System.Array]) {
                $models = @($cfg['allowedModels'] | Where-Object { $_ -is [string] -and $_.Trim() })
            } elseif (-not (Test-AwVscTrue $cfg)) { continue }
            if ($cfg -is [System.Collections.IDictionary] -and $models.Count -eq 0) { continue }
            $what = if ($models -contains '*') { 'any model ("*")' } elseif ($models.Count -gt 0) { Join-AwVscQuoted $models } else { 'sampling' }
            New-AwVscFinding -Ctx $Ctx -RuleId 'AW-VSC-023' -Info $info -EntryKey $server `
                -Evidence ('chat.mcp.serverSampling "' + $server + '" may request completions from ' + $what)
        }
    }

Register-AwRule -Id 'AW-VSC-024' -Title 'Agent OpenTelemetry disabled' `
    -Severity 'low' -Category 'observability' -Harness 'vscode-copilot' `
    -Description 'github.copilot.chat.otel.enabled = false (default): agent sessions, tool calls and model requests are not exported as OpenTelemetry traces, so there is no local audit trail to investigate an incident. Observability only, hence low.' `
    -Fix 'Set "github.copilot.chat.otel.enabled": true with "github.copilot.chat.otel.otlpEndpoint" pointing to a local or approved collector.' `
    -References @('OWASP-ASI10', 'OWASP-ASI08', $docs.Settings) `
    -Confidence 'high' -Check {
        param($Ctx)
        $info = Get-AwVscSetting $Ctx 'github.copilot.chat.otel.enabled' 'bool'
        if ($null -eq $info -or $info.Value -isnot [bool] -or $info.Value) { return }
        New-AwVscSettingFinding -Ctx $Ctx -RuleId 'AW-VSC-024' -Info $info
    }

Register-AwRule -Id 'AW-VSC-025' -Title 'Prompt content captured in telemetry' `
    -Severity 'medium' -Category 'secrets' -Harness 'vscode-copilot' `
    -Description 'github.copilot.chat.otel.captureContent = true, with OpenTelemetry enabled, puts full prompts, responses and tool data in spans; the settings page warns that they may include sensitive information such as secrets and personal data. Severity is high when the OTLP collector is not on the local machine.' `
    -Fix 'Set "github.copilot.chat.otel.captureContent": false outside an isolated test environment, and keep "github.copilot.chat.otel.otlpEndpoint" on localhost.' `
    -References @('OWASP-ASI03', $docs.Settings) `
    -Confidence 'high' -Check {
        param($Ctx)
        $enabled = Get-AwVscSetting $Ctx 'github.copilot.chat.otel.enabled' 'bool'
        if ($null -eq $enabled -or -not (Test-AwVscTrue $enabled.Value)) { return }
        $info = Get-AwVscSetting $Ctx 'github.copilot.chat.otel.captureContent' 'bool'
        if ($null -eq $info -or -not (Test-AwVscTrue $info.Value)) { return }
        $exporter = Get-AwVscSetting $Ctx 'github.copilot.chat.otel.exporterType' 'string'
        $type = if ($null -ne $exporter -and $exporter.Value) { [string]$exporter.Value } else { 'otlp-http' }
        $sev = 'medium'
        $detail = "exporter $type"
        if ($type -like 'otlp*') {
            $endpoint = Get-AwVscSetting $Ctx 'github.copilot.chat.otel.otlpEndpoint' 'string'
            $url = if ($null -ne $endpoint -and $endpoint.Value) { [string]$endpoint.Value } else { 'http://localhost:4318' }
            $detail = 'collector ' + $url
            if (-not (Test-AwVscLocalEndpoint $url)) { $sev = 'high'; $detail += ' is not a local address' }
        }
        New-AwVscSettingFinding -Ctx $Ctx -RuleId 'AW-VSC-025' -Info $info -Detail $detail -Severity $sev
    }

Register-AwRule -Id 'AW-VSC-026' -Title 'Workspace Trust disabled' `
    -Severity 'high' -Category 'mcp-supply-chain' -Harness 'vscode-copilot' `
    -Description 'security.workspace.trust.enabled = false turns off Workspace Trust. Restricted Mode normally disables agents in an untrusted folder and blocks its workspace MCP servers and hook files until you trust it; without it, the agent configuration of a freshly cloned repository is live at once. Confidence is medium: whether VS Code honors this setting at workspace scope is not documented.' `
    -Fix 'Remove the setting or set "security.workspace.trust.enabled": true (the default). Open unknown repositories in Restricted Mode and trust them only after reviewing their agent configuration.' `
    -References @('OWASP-ASI04', $docs.Trust, $docs.Security, $docs.Mcp) `
    -Confidence 'medium' -Check {
        param($Ctx)
        $info = Get-AwVscSetting $Ctx 'security.workspace.trust.enabled' 'bool'
        if ($null -eq $info -or -not $info.Valid -or $info.Value) { return }
        New-AwVscSettingFinding -Ctx $Ctx -RuleId 'AW-VSC-026' -Info $info
    }

Register-AwRule -Id 'AW-VSC-027' -Title 'Repository hook file runs in the Local harness' `
    -Severity 'medium' -Category 'mcp-supply-chain' -Harness 'vscode-copilot' `
    -Description 'chat.useHooks = true (default) makes the Local harness run the commands of workspace hook files (.github/hooks/*.json, and .claude/settings*.json when chat.useClaudeHooks is on) with your rights. Hooks are executable code: a repository can plant one that runs on agent events as soon as the folder is trusted, a supply-chain risk. Severity is high when Workspace Trust is disabled.' `
    -Fix 'Review every hook file and the scripts it calls, protect them with CODEOWNERS and "**/.github/hooks/**": false in chat.tools.edits.autoApprove, or set "chat.useHooks": false where repository hooks are not needed.' `
    -References @('OWASP-ASI04', 'OWASP-ASI05', $docs.Hooks, $docs.GhHooks, $docs.Settings) `
    -Confidence 'high' -Check {
        param($Ctx)
        $info = Get-AwVscSetting $Ctx 'chat.useHooks' 'bool'
        if ($null -eq $info -or -not (Test-AwVscTrue $info.Value)) { return }
        $claude = Get-AwVscSetting $Ctx 'chat.useClaudeHooks' 'bool'
        $useClaude = ($null -ne $claude -and (Test-AwVscTrue $claude.Value))
        $trust = Get-AwVscSetting $Ctx 'security.workspace.trust.enabled' 'bool'
        $noTrust = ($null -ne $trust -and $trust.Valid -and -not $trust.Value)
        $hookDir = [System.IO.Path]::Combine([System.IO.Path]::Combine([string]$Ctx.Root, '.github'), 'hooks')
        $claudeDir = [System.IO.Path]::Combine([string]$Ctx.Root, '.claude')
        foreach ($h in @(Get-AwMemberValue $Ctx 'Hooks')) {
            if ($null -eq $h -or -not $h.Path) { continue }
            $dir = [System.IO.Path]::GetDirectoryName($h.Path)
            $isWorkspace = [string]::Equals($dir, $hookDir, $script:AwPathComparison)
            $isClaude = $useClaude -and [string]::Equals($dir, $claudeDir, $script:AwPathComparison)
            if (-not ($isWorkspace -or $isClaude)) { continue }
            $events = Get-AwVscHookEvents $h
            if (-not $events) { continue }
            $setting = 'chat.useHooks = true'
            if ($info.Setting.IsDefault) { $setting += ' (default)' }
            if ($isClaude) { $setting += ', chat.useClaudeHooks = true' }
            $ev = $setting + '; workspace hook file ' + (Get-AwDisplayPath -Path $h.Path -Ctx $Ctx) + ' runs commands on: ' + $events
            if ($noTrust) { $ev += '; Workspace Trust is disabled' }
            New-AwFinding -RuleId 'AW-VSC-027' -Severity $(if ($noTrust) { 'high' } else { 'medium' }) `
                -Evidence (Hide-AwSecretsInText (Limit-AwVscText $ev)) `
                -Location @{ Path = $h.Path; Line = (Find-AwLineNumber -Text $h.Raw -Needle '"hooks"'); Key = 'hooks' }
        }
    }

Remove-Variable -Name docs
