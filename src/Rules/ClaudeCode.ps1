# Claude Code rules (AW-CC-0xx), applied to Ctx.ClaudeSettings: .claude/settings.json [project],
# .claude/settings.local.json [local], ~/.claude/settings.json [user], managed-settings.json [managed].
# Sources (read 2026-10-18): code.claude.com/docs/en/permissions, /permission-modes, /settings,
# /settings-reference, /sandboxing, /hooks and /mcp.
# Keys are case-sensitive, as in Claude Code: a hostile "Permissions" key never hides "permissions".

# Precedence of scalar settings, highest first. Command-line arguments are invisible to a static scan.
$script:AwCcScopeRank = @{ managed = 4; local = 3; project = 2; user = 1 }

$script:AwCcDocs = @{
    Permissions = 'https://code.claude.com/docs/en/permissions'
    Modes       = 'https://code.claude.com/docs/en/permission-modes'
    Settings    = 'https://code.claude.com/docs/en/settings-reference'
    Mcp         = 'https://code.claude.com/docs/en/mcp'
    Hooks       = 'https://code.claude.com/docs/en/hooks'
    Sandboxing  = 'https://code.claude.com/docs/en/sandboxing'
}

# Runner programs, helper keys and sandbox keys live in src/Data/claudecode.json, as separate tokens
# (CONTRIBUTING.md, Antivirus hygiene). The file is read on first use.
$script:AwCcDataPath = [System.IO.Path]::Combine([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'Data'), 'claudecode.json')
$script:AwCcData = $null

# ---------------------------------------------------------------------------------------------
# Helpers (evidence masking: Format-AwCommandSnippet, and data lists: Get-AwMcpDataList, in Mcp.ps1)
# ---------------------------------------------------------------------------------------------

function Get-AwCcData {
    # Parsed src/Data/claudecode.json, cached. Throws when the file is missing or invalid (the engine reports AW-CORE-002).
    if ($null -eq $script:AwCcData) {
        $data = ConvertFrom-AwJsonc -Text ([System.IO.File]::ReadAllText($script:AwCcDataPath))
        if ($data -isnot [System.Collections.IDictionary]) { throw "Invalid rule data file: $script:AwCcDataPath" }
        $script:AwCcData = $data
    }
    return $script:AwCcData
}

function Get-AwCcArtifacts {
    # Parsed Claude Code settings files, highest precedence first (stable within a scope).
    param($Ctx)
    $list = @(@($Ctx.ClaudeSettings) | Where-Object { $null -ne $_ -and $_.Data -is [System.Collections.IDictionary] })
    if ($list.Count -eq 0) { return }
    $ranked = for ($i = 0; $i -lt $list.Count; $i++) {
        $rank = $script:AwCcScopeRank[[string]$list[$i].Scope]
        [pscustomobject]@{ Artifact = $list[$i]; Rank = $(if ($null -eq $rank) { 0 } else { $rank }); Index = $i }
    }
    @($ranked) | Sort-Object -Property @{ Expression = 'Rank'; Descending = $true }, @{ Expression = 'Index'; Descending = $false } |
        ForEach-Object { $_.Artifact }
}

function Get-AwCcValue {
    # Value at a path of nested objects ('permissions.defaultMode'), or $null. Arrays are returned whole.
    # Claude Code settings are nested JSON: a literal "permissions.defaultMode" key is not a setting.
    param($Data, [string]$Path)
    $node = $Data
    foreach ($part in $Path.Split('.')) {
        if ($node -isnot [System.Collections.IDictionary] -or -not $node.Contains($part)) { return $null }
        $node = $node[$part]
    }
    return ,$node
}

function Get-AwCcStrings {
    # The string items of an array setting.
    param($Data, [string]$Path)
    $value = Get-AwCcValue -Data $Data -Path $Path
    if ($value -is [System.Array]) { foreach ($item in $value) { if ($item -is [string]) { $item } } }
}

function Get-AwCcEffective {
    # The highest-precedence file that sets Path to a value of the given type: { Value; Artifact }, or $null.
    # A value of another type is rejected by Claude Code, so the next file applies.
    param($Ctx, [string]$Path, [type]$Type = [object], [string[]]$Scopes)
    foreach ($a in @(Get-AwCcArtifacts $Ctx)) {
        if ($Scopes -and $Scopes -notcontains [string]$a.Scope) { continue }
        $value = Get-AwCcValue -Data $a.Data -Path $Path
        if ($null -ne $value -and $value -is $Type) { return [pscustomobject]@{ Value = $value; Artifact = $a } }
    }
    return $null
}

function Test-AwCcAnyEquals {
    # True when any settings file (of the given scopes) sets one of Paths to exactly Value (case-sensitive for strings).
    param($Ctx, [string[]]$Paths, $Value, [string[]]$Scopes)
    foreach ($a in @(Get-AwCcArtifacts $Ctx)) {
        if ($Scopes -and $Scopes -notcontains [string]$a.Scope) { continue }
        foreach ($p in $Paths) {
            $v = Get-AwCcValue -Data $a.Data -Path $p
            if ($null -eq $v -or $v.GetType() -ne $Value.GetType()) { continue }
            if (($Value -is [string] -and $v -ceq $Value) -or ($Value -isnot [string] -and $v -eq $Value)) { return $true }
        }
    }
    return $false
}

function Get-AwCcStartMode {
    # The permissions.defaultMode that decides how a terminal session starts: { Value; Artifact; Honored }, or $null.
    # 'auto' and 'bypassPermissions' do not take effect from project or local settings (Honored = $false).
    param($Ctx)
    $mode = Get-AwCcEffective $Ctx 'permissions.defaultMode' ([string])
    if ($null -eq $mode) { return $null }
    $ignored = @(Get-AwMcpDataList (Get-AwCcData) 'projectIgnoredModes')
    $honored = -not ((@('project', 'local') -contains [string]$mode.Artifact.Scope) -and ($ignored -ccontains $mode.Value))
    [pscustomobject]@{ Value = $mode.Value; Artifact = $mode.Artifact; Honored = $honored }
}

function Test-AwCcAutoModeOff {
    # True when a settings file sets disableAutoMode (documented top level and under permissions) to "disable".
    param($Ctx)
    return (Test-AwCcAnyEquals $Ctx @('disableAutoMode', 'permissions.disableAutoMode') 'disable')
}

function ConvertFrom-AwCcRule {
    # 'Tool' or 'Tool(specifier)' -> { Tool; Spec }. Spec is $null for a bare tool name.
    param([string]$Text)
    $t = $Text.Trim()
    $open = $t.IndexOf('(')
    if ($open -lt 0 -or -not $t.EndsWith(')')) { return [pscustomobject]@{ Tool = $t; Spec = $null } }
    [pscustomobject]@{ Tool = $t.Substring(0, $open).Trim(); Spec = $t.Substring($open + 1, $t.Length - $open - 2) }
}

function Get-AwCcPermissionRules {
    # Every rule of a permission list ('allow', 'ask', 'deny') from every settings file.
    param($Ctx, [string]$List)
    foreach ($a in @(Get-AwCcArtifacts $Ctx)) {
        foreach ($text in @(Get-AwCcStrings -Data $a.Data -Path "permissions.$List")) {
            $rule = ConvertFrom-AwCcRule $text
            [pscustomobject]@{ Text = $text; Tool = $rule.Tool; Spec = $rule.Spec; Artifact = $a }
        }
    }
}

function Test-AwCcWholeTool {
    # True for a rule that matches every use of the tool: 'Bash', 'Bash(*)', 'Bash(:*)'.
    param($Rule)
    if ($null -eq $Rule.Spec) { return $true }
    $s = $Rule.Spec.Trim()
    return ($s -eq '' -or $s -eq '*' -or $s -eq ':*')
}

function Test-AwCcToolDenied {
    # True when a deny rule removes the whole tool: its bare name, Tool(*), or a bare tool-name glob ('*', 'B*').
    param([object[]]$Deny, [string]$Tool)
    foreach ($r in $Deny) {
        if ($r.Tool -ceq $Tool -and (Test-AwCcWholeTool $r)) { return $true }
        if ($null -eq $r.Spec -and $r.Tool.Contains('*') -and $r.Tool -cmatch '^[A-Za-z0-9_*]+$' -and $Tool -clike $r.Tool) { return $true }
    }
    return $false
}

function Test-AwCcRunnerProgram {
    # True for an interpreter or runner name from the data file (case-insensitive, optional directory and .exe).
    param([string]$Word)
    $w = $Word.ToLowerInvariant()
    $slash = $w.LastIndexOfAny([char[]]@('\', '/'))
    if ($slash -ge 0) { $w = $w.Substring($slash + 1) }
    if ($w.EndsWith('.exe')) { $w = $w.Substring(0, $w.Length - 4) }
    if ($w -eq '') { return $false }
    $data = Get-AwCcData
    if (@(Get-AwMcpDataList $data 'runnerPrograms') -contains $w) { return $true }
    foreach ($v in @(Get-AwMcpDataList $data 'versionedPrograms')) {
        if ($w.Length -gt $v.Length -and $w.StartsWith($v, [StringComparison]::Ordinal) -and $w.Substring($v.Length) -match '^[0-9.]+$') { return $true }
    }
    return $false
}

function Test-AwCcRunnerSpec {
    # True for a rule specifier that lets an interpreter or runner run anything: 'python *', 'python3:*', 'node*',
    # 'docker run *', 'sudo bash *', 'bash -c *'. Only options may sit between the runner and the final wildcard.
    param([string]$Spec)
    $s = $Spec.Trim()
    if (-not $s.EndsWith('*')) { return $false }
    $head = if ($s.EndsWith(':*')) { $s.Substring(0, $s.Length - 2) } else { $s.Substring(0, $s.Length - 1) }
    $words = @($head.Trim() -split '\s+' | Where-Object { $_ -ne '' })
    $data = Get-AwCcData
    if ($words.Count -gt 0 -and @(Get-AwMcpDataList $data 'privilegePrefixes') -contains $words[0]) { $words = @($words | Select-Object -Skip 1) }
    if ($words.Count -eq 0) { return $false }
    $used = 0
    if (Test-AwCcRunnerProgram $words[0]) {
        $used = 1
    } elseif ($words.Count -ge 2) {
        foreach ($pair in @($data['runnerSubcommands'])) {
            $p = @($pair)
            if ($p.Count -eq 2 -and $words[0] -eq [string]$p[0] -and $words[1] -eq [string]$p[1]) { $used = 2; break }
        }
    }
    if ($used -eq 0) { return $false }
    for ($i = $used; $i -lt $words.Count; $i++) { if (-not $words[$i].StartsWith('-')) { return $false } }
    return $true
}

function ConvertTo-AwCcGlobRegex {
    # gitignore-style glob to a regex fragment: ** crosses directories, * and ? stay within one.
    param([string]$Glob)
    $sb = New-Object System.Text.StringBuilder
    $i = 0
    while ($i -lt $Glob.Length) {
        $c = [string]$Glob[$i]
        if ($c -eq '*') {
            if ($i + 1 -lt $Glob.Length -and $Glob[$i + 1] -eq [char]'*') {
                # A run of three or more stars means the same as '**'. Collapsing it keeps a hostile
                # rule such as Read(*****...x) from backtracking exponentially.
                $j = $i
                while ($j -lt $Glob.Length -and $Glob[$j] -eq [char]'*') { $j++ }
                if ($j -lt $Glob.Length -and $Glob[$j] -eq [char]'/') { [void]$sb.Append('(?:.*/)?'); $i = $j + 1; continue }
                [void]$sb.Append('.*'); $i = $j; continue
            }
            [void]$sb.Append('[^/]*')
        } elseif ($c -eq '?') {
            [void]$sb.Append('[^/]')
        } else {
            [void]$sb.Append([regex]::Escape($c))
        }
        $i++
    }
    $sb.ToString()
}

function Test-AwCcReadRuleCovers {
    # True when a Read deny rule blocks a sample path of the target ('env' = .env in the project, 'ssh' = ~/.ssh).
    param($Rule, [string]$Target)
    if ($Rule.Tool -ceq '*') { return $true }
    if ($null -eq $Rule.Spec) { return $true }
    $spec = $Rule.Spec.Trim().Replace('\', '/')
    if ($spec -eq '' -or $spec -eq '*' -or $spec -eq '**' -or $spec -eq '//**') { return $true }
    $samples = @()
    $pattern = $spec
    if ($spec.StartsWith('//')) {
        $samples = if ($Target -eq 'env') { @('//c/work/app/.env', '//home/dev/app/.env') } else { @('//c/Users/dev/.ssh/id_rsa', '//home/dev/.ssh/id_rsa', '//Users/dev/.ssh/id_rsa') }
    } elseif ($spec.StartsWith('~/')) {
        $samples = if ($Target -eq 'ssh') { @('~/.ssh', '~/.ssh/id_rsa') } else { @() }
    } else {
        # In user settings a /path rule is anchored at ~/.claude, so it never covers the project.
        if ($spec.StartsWith('/') -and $Rule.Artifact.Scope -eq 'user') { return $false }
        if ($Target -ne 'env') { return $false }
        $pattern = $spec -replace '^(\./|/)', ''
        # A pattern without an inner slash matches at any depth (gitignore).
        if ($pattern.TrimEnd('/') -notmatch '/') { $pattern = '**/' + $pattern }
        $samples = @('.env', 'app/.env')
    }
    # The rule comes from a scanned file: the match runs with a timeout, and a rule that cannot be
    # evaluated in time does not count as protection.
    $rx = New-AwUntrustedRegex -Pattern ('^' + (ConvertTo-AwCcGlobRegex $pattern.TrimEnd('/')) + '(?:/.*)?$') `
        -Options ([System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
    foreach ($s in $samples) {
        if ((Test-AwUntrustedMatch -Regex $rx -Text $s) -eq $true) { return $true }
    }
    return $false
}

function Get-AwCcCommandHooks {
    # Hook handlers that run a command or call a URL: { Event; Matcher; Type; Text }.
    param($Hooks)
    if ($Hooks -isnot [System.Collections.IDictionary]) { return }
    $events = [string[]]@($Hooks.Keys)
    [Array]::Sort($events, [StringComparer]::Ordinal)
    foreach ($hookEvent in $events) {
        $groups = $Hooks[$hookEvent]
        if ($groups -isnot [System.Array]) { continue }
        foreach ($group in $groups) {
            if ($group -isnot [System.Collections.IDictionary]) { continue }
            $matcher = if ($group['matcher'] -is [string]) { $group['matcher'] } else { '' }
            $handlers = $group['hooks']
            if ($handlers -isnot [System.Array]) { continue }
            foreach ($h in $handlers) {
                if ($h -isnot [System.Collections.IDictionary]) { continue }
                $type = if ($h['type'] -is [string]) { $h['type'] } else { $null }
                $command = if ($h['command'] -is [string]) { $h['command'] } else { $null }
                $url = if ($h['url'] -is [string]) { $h['url'] } else { $null }
                if ($type -ceq 'command' -or ($null -eq $type -and $command)) {
                    # A command hook may pass its arguments separately ("args").
                    $text = [string]$command
                    if ($h['args'] -is [System.Array]) {
                        $argv = @($h['args'] | Where-Object { $_ -is [string] } | Select-Object -First 64)
                        if ($argv.Count -gt 0) { $text = ($text + ' ' + ($argv -join ' ')).Trim() }
                    }
                    [pscustomobject]@{ Event = $hookEvent; Matcher = $matcher; Type = 'command'; Text = $text }
                } elseif ($type -ceq 'http') {
                    [pscustomobject]@{ Event = $hookEvent; Matcher = $matcher; Type = 'http'; Text = [string]$url }
                }
            }
        }
    }
}

function Get-AwCcSandboxState {
    # How the sandbox keys combine across scopes (code.claude.com/docs/en/sandboxing):
    # - a managed Boolean always wins;
    # - allowUnsandboxedCommands = false in user or managed settings holds over a project or local true;
    # - the sandbox is admin-required when managed settings set allowUnsandboxedCommands = false or
    #   network.allowManagedDomainsOnly = true; repository files then cannot loosen it.
    param($Ctx)
    $managedOnly = @('managed')
    $adminRequired = (Test-AwCcAnyEquals $Ctx @('sandbox.allowUnsandboxedCommands') $false $managedOnly) -or
                     (Test-AwCcAnyEquals $Ctx @('sandbox.network.allowManagedDomainsOnly') $true $managedOnly)
    $bool = {
        param([string]$Key)
        $m = Get-AwCcEffective $Ctx "sandbox.$Key" ([bool]) $managedOnly
        if ($m) { return $m }
        $e = Get-AwCcEffective $Ctx "sandbox.$Key" ([bool])
        # Under an admin-required sandbox, a repository false is ignored when the user's settings say true.
        if ($e -and -not $e.Value -and $adminRequired -and @('project', 'local') -contains [string]$e.Artifact.Scope) {
            $u = Get-AwCcEffective $Ctx "sandbox.$Key" ([bool]) @('user')
            if ($u -and $u.Value) { return $u }
        }
        return $e
    }
    $unsandboxed = Get-AwCcEffective $Ctx 'sandbox.allowUnsandboxedCommands' ([bool]) $managedOnly
    if ($null -eq $unsandboxed) {
        $userFalse = Get-AwCcEffective $Ctx 'sandbox.allowUnsandboxedCommands' ([bool]) @('user')
        $unsandboxed = if ($userFalse -and -not $userFalse.Value) { $userFalse } else { Get-AwCcEffective $Ctx 'sandbox.allowUnsandboxedCommands' ([bool]) }
    }
    [pscustomobject]@{
        AdminRequired = $adminRequired
        Enabled       = (& $bool 'enabled')
        FailIfUnavailable = (& $bool 'failIfUnavailable')
        Unsandboxed   = $unsandboxed
        StrictAllowlist = (Test-AwCcAnyEquals $Ctx @('sandbox.network.strictAllowlist') $true @('managed', 'user'))
    }
}

function New-AwCcFinding {
    param([string]$RuleId, $Artifact, [string]$Needle, [string]$Key, [string]$Evidence, [string]$Severity, [string]$Title)
    $p = @{
        RuleId   = $RuleId
        Evidence = $Evidence
        Location = @{ Path = $Artifact.Path; Line = (Find-AwLineNumber -Text $Artifact.Raw -Needle $Needle); Key = $Key }
    }
    if ($Severity) { $p['Severity'] = $Severity }
    if ($Title) { $p['Title'] = $Title }
    New-AwFinding @p
}

function Get-AwCcScopeLabel {
    param($Artifact)
    switch ([string]$Artifact.Scope) {
        'project' { 'project settings' }
        'local'   { 'local settings' }
        'user'    { 'user settings' }
        'managed' { 'managed settings' }
        default   { 'settings' }
    }
}

# ---------------------------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------------------------

Register-AwRule -Id 'AW-CC-001' -Title 'Claude Code starts in bypassPermissions mode' `
    -Severity 'critical' -Category 'approvals' -Harness 'claude-code' `
    -Description 'permissions.defaultMode = "bypassPermissions" skips every permission prompt (apart from the few actions no mode auto-approves), including writes to protected paths such as .git and .claude. Any prompt injection then runs commands, edits files and reaches the network with no human check. The documentation reserves this mode for isolated containers or VMs. The value that decides is the highest-precedence one (managed > local > project > user). From user or managed settings it is critical. Since v2.1.257 the value does not take effect from project or local settings (the session starts in Manual mode), but earlier versions apply it, so a repository that sets it is reported as medium. The rule is silent when permissions.disableBypassPermissionsMode = "disable" is set in any settings file, since the mode can then not be entered.' `
    -Fix 'Set "permissions": { "defaultMode": "default" } (or "plan"), and add "disableBypassPermissionsMode": "disable" under permissions, ideally in managed settings. Remove the value from .claude/settings.json and .claude/settings.local.json. Use bypassPermissions only inside a disposable container or VM.' `
    -References @('OWASP-ASI02', 'OWASP-ASI09', $script:AwCcDocs.Permissions, $script:AwCcDocs.Modes, $script:AwCcDocs.Settings) `
    -Confidence 'high' -Check {
        param($Ctx)
        $mode = Get-AwCcStartMode $Ctx
        if ($null -eq $mode -or $mode.Value -cne 'bypassPermissions') { return }
        if (Test-AwCcAnyEquals $Ctx @('permissions.disableBypassPermissionsMode') 'disable') { return }
        $where = Get-AwCcScopeLabel $mode.Artifact
        if ($mode.Honored) {
            New-AwCcFinding 'AW-CC-001' $mode.Artifact '"defaultMode"' 'permissions.defaultMode' ('permissions.defaultMode = "bypassPermissions" ({0})' -f $where)
        } else {
            New-AwCcFinding 'AW-CC-001' $mode.Artifact '"defaultMode"' 'permissions.defaultMode' `
                ('permissions.defaultMode = "bypassPermissions" ({0}): ignored by Claude Code v2.1.257 and later, applied by earlier versions' -f $where) -Severity 'medium'
        }
    }

Register-AwRule -Id 'AW-CC-002' -Title 'Claude Code starts in a mode that auto-approves actions' `
    -Severity 'medium' -Category 'approvals' -Harness 'claude-code' `
    -Description 'permissions.defaultMode = "acceptEdits" accepts file edits, and common file-system commands such as mkdir, mv and cp, in the working directories without asking; a prompt injection can then rewrite code, scripts and agent instructions silently. Auto mode (reported as low) replaces prompts by a background classifier, which is not a human review. Since v2.1.283 auto mode is also the built-in starting mode of terminal and VS Code sessions when no settings file sets defaultMode, and an "auto" value in project or local settings does not take effect, so the built-in default applies. The value that decides follows the documented precedence (managed > local > project > user); the rule is silent for auto mode when disableAutoMode = "disable" is set in any settings file. The VS Code extension reads its starting mode from its own settings, which are not analyzed.' `
    -Fix 'Set "permissions": { "defaultMode": "default" } and approve edits as they come, or use "plan" to review first. To keep auto mode out of reach, set "disableAutoMode": "disable" (also accepted under permissions), ideally in managed settings.' `
    -References @('OWASP-ASI02', 'OWASP-ASI09', $script:AwCcDocs.Modes, $script:AwCcDocs.Permissions, $script:AwCcDocs.Settings) `
    -Confidence 'high' -Check {
        param($Ctx)
        $artifacts = @(Get-AwCcArtifacts $Ctx)
        if ($artifacts.Count -eq 0) { return }
        $mode = Get-AwCcStartMode $Ctx
        if ($null -ne $mode -and $mode.Value -ceq 'acceptEdits') {
            New-AwCcFinding 'AW-CC-002' $mode.Artifact '"defaultMode"' 'permissions.defaultMode' ('permissions.defaultMode = "acceptEdits" ({0})' -f (Get-AwCcScopeLabel $mode.Artifact))
            return
        }
        if (Test-AwCcAutoModeOff $Ctx) { return }
        $builtIn = 'the built-in default applies, which is auto mode in Claude Code v2.1.283 and later: a classifier, not a person, approves actions'
        if ($null -eq $mode) {
            $at = @($artifacts | Where-Object { $_.Scope -eq 'project' }) + $artifacts
            New-AwCcFinding 'AW-CC-002' $at[0] '"permissions"' 'permissions.defaultMode' `
                ('permissions.defaultMode is not set in the {0} analyzed settings file(s): {1}' -f $artifacts.Count, $builtIn) -Severity 'low'
        } elseif ($mode.Value -ceq 'auto') {
            $where = Get-AwCcScopeLabel $mode.Artifact
            $text = 'permissions.defaultMode = "auto" ({0}) does not take effect there; {1}' -f $where, $builtIn
            if ($mode.Honored) { $text = 'permissions.defaultMode = "auto" ({0}): a classifier, not a person, approves actions' -f $where }
            New-AwCcFinding 'AW-CC-002' $mode.Artifact '"defaultMode"' 'permissions.defaultMode' $text -Severity 'low'
        }
    }

Register-AwRule -Id 'AW-CC-003' -Title 'Every shell command is pre-approved' `
    -Severity 'critical' -Category 'approvals' -Harness 'claude-code' `
    -Description 'A permissions.allow rule that matches every Bash or PowerShell command ("Bash", "Bash(*)", "PowerShell(*)") lets Claude run any command without a prompt, which makes prompt injection equivalent to code execution. Rules that allow an interpreter or a runner with a wildcard ("Bash(python *)", "Bash(bash -c *)", "Bash(npx *)"; the list is in src/Data/claudecode.json) or put the wildcard before the program ("Bash(* --help)") are just as broad and are reported as high. Allow rules in a project file apply once the folder is trusted. Rules are ignored when a deny rule removes the whole tool (its name, Tool(*), or a tool-name glob such as "*").' `
    -Fix 'Replace broad rules with exact commands or narrow prefixes, for example "Bash(npm run test *)" and "Bash(git status)", and add deny rules for network and destructive commands. Use the sandbox (sandbox.enabled) for OS-level enforcement.' `
    -References @('OWASP-ASI02', 'OWASP-ASI05', $script:AwCcDocs.Permissions) `
    -Confidence 'high' -Check {
        param($Ctx)
        $deny = @(Get-AwCcPermissionRules $Ctx 'deny')
        foreach ($r in @(Get-AwCcPermissionRules $Ctx 'allow')) {
            if ($r.Tool -cne 'Bash' -and $r.Tool -cne 'PowerShell') { continue }
            if (Test-AwCcToolDenied $deny $r.Tool) { continue }
            $severity = $null
            $why = $null
            if (Test-AwCcWholeTool $r) {
                $why = 'every {0} command runs without approval' -f $r.Tool
            } else {
                $spec = $r.Spec.Trim()
                if ($spec.StartsWith('*')) { $severity = 'high'; $why = 'the wildcard stands for the program, so any program matches' }
                elseif (Test-AwCcRunnerSpec $spec) { $severity = 'high'; $why = 'an interpreter or runner with a wildcard runs arbitrary code' }
            }
            if (-not $why) { continue }
            New-AwCcFinding 'AW-CC-003' $r.Artifact ('"' + $r.Text + '"') 'permissions.allow' `
                ("permissions.allow contains '{0}' in {1}: {2}" -f (Format-AwCommandSnippet $r.Text 80), (Get-AwCcScopeLabel $r.Artifact), $why) -Severity $severity
        }
    }

Register-AwRule -Id 'AW-CC-004' -Title 'Web fetches to any domain are pre-approved' `
    -Severity 'medium' -Category 'sandbox-network' -Harness 'claude-code' `
    -Description 'A permissions.allow rule "WebFetch" (bare), "WebFetch(domain:*)" or a whole top-level domain ("WebFetch(domain:*.com)") lets Claude fetch any URL without a prompt. A prompt injection can then send data out in the URL, or pull more instructions from a site it chooses. WebFetch(domain:*) also opens every host to sandboxed commands. Rules are ignored when a deny rule removes WebFetch.' `
    -Fix 'Allow only the domains you need, for example "WebFetch(domain:docs.example.com)", and keep a "WebFetch" ask or deny rule for the rest.' `
    -References @('OWASP-ASI02', 'OWASP-ASI01', $script:AwCcDocs.Permissions) `
    -Confidence 'high' -Check {
        param($Ctx)
        $deny = @(Get-AwCcPermissionRules $Ctx 'deny')
        if (Test-AwCcToolDenied $deny 'WebFetch') { return }
        if (@($deny | Where-Object { $_.Tool -ceq 'WebFetch' -and $null -ne $_.Spec -and $_.Spec.Trim() -eq 'domain:*' }).Count -gt 0) { return }
        foreach ($r in @(Get-AwCcPermissionRules $Ctx 'allow')) {
            if ($r.Tool -cne 'WebFetch') { continue }
            $spec = if ($null -eq $r.Spec) { $null } else { $r.Spec.Trim() }
            $broad = ($null -eq $spec) -or ($spec -eq '' -or $spec -eq '*') -or ($spec -match '^(?i)domain:\s*(\*|\*\.\*|\*\.[a-z0-9-]+)\.?$')
            if (-not $broad) { continue }
            New-AwCcFinding 'AW-CC-004' $r.Artifact ('"' + $r.Text + '"') 'permissions.allow' `
                ("permissions.allow contains '{0}' in {1}: no domain restriction" -f (Format-AwCommandSnippet $r.Text 80), (Get-AwCcScopeLabel $r.Artifact))
        }
    }

Register-AwRule -Id 'AW-CC-005' -Title 'No deny rule protects secret files' `
    -Severity 'low' -Category 'secrets' -Harness 'claude-code' `
    -Description 'Checks the merged permissions.deny rules for a Read rule that covers .env files in the project and, when the user or managed settings are analyzed, ~/.ssh. Without them Claude can read these files with its file tools and send their content to the model or to a tool. Read deny rules also block Edit and Write on the same paths. They do not stop every subprocess (use the sandbox for that), but they are the documented way to exclude sensitive files.' `
    -Fix 'Add deny rules such as "Read(./.env)", "Read(./.env.*)" and "Read(./secrets/**)" to .claude/settings.json, and "Read(~/.ssh/**)" (plus your cloud and token stores) to ~/.claude/settings.json or managed settings.' `
    -References @('OWASP-ASI03', $script:AwCcDocs.Permissions, $script:AwCcDocs.Settings) `
    -Confidence 'high' -Check {
        param($Ctx)
        $artifacts = @(Get-AwCcArtifacts $Ctx)
        if ($artifacts.Count -eq 0) { return }
        $readDeny = @(Get-AwCcPermissionRules $Ctx 'deny' | Where-Object { $_.Tool -ceq 'Read' -or ($_.Tool -ceq '*' -and $null -eq $_.Spec) })
        $covers = { param($Target) foreach ($r in $readDeny) { if (Test-AwCcReadRuleCovers $r $Target) { return $true } }; return $false }
        if (-not (& $covers 'env')) {
            $at = @($artifacts | Where-Object { $_.Scope -eq 'project' }) + @($artifacts | Where-Object { $_.Scope -eq 'local' }) + $artifacts
            New-AwCcFinding 'AW-CC-005' $at[0] '"permissions"' 'permissions.deny' 'no permissions.deny Read rule covers .env files'
        }
        $profileLevel = @($artifacts | Where-Object { $_.Scope -eq 'managed' -or $_.Scope -eq 'user' })
        if ($profileLevel.Count -gt 0 -and -not (& $covers 'ssh')) {
            $at = @($profileLevel | Where-Object { $_.Scope -eq 'user' }) + $profileLevel
            New-AwCcFinding 'AW-CC-005' $at[0] '"permissions"' 'permissions.deny' 'no permissions.deny Read rule covers ~/.ssh'
        }
    }

Register-AwRule -Id 'AW-CC-006' -Title 'Every project MCP server is approved automatically' `
    -Severity 'high' -Category 'mcp-supply-chain' -Harness 'claude-code' `
    -Description 'enableAllProjectMcpServers = true approves every server in the project .mcp.json without a prompt, including servers added later by a commit or a pull request. Each server is code that runs, or a remote service that is called, with your rights. In a trusted folder the highest-precedence Boolean decides. In a folder you have not trusted, Claude Code ignores the value in the shared project file, but a true in user or managed settings is enough on its own, even when a higher-precedence file sets false. A disabledMcpjsonServers entry still rejects a server.' `
    -Fix 'Remove enableAllProjectMcpServers (or set it to false) and approve servers one by one, or list them in enabledMcpjsonServers. Reject unwanted ones with disabledMcpjsonServers. Never set it to true in ~/.claude/settings.json, where it covers every repository you open.' `
    -References @('OWASP-ASI04', $script:AwCcDocs.Mcp, $script:AwCcDocs.Settings) `
    -Confidence 'high' -Check {
        param($Ctx)
        $winner = Get-AwCcEffective $Ctx 'enableAllProjectMcpServers' ([bool])
        $profileTrue = $null
        foreach ($a in @(Get-AwCcArtifacts $Ctx)) {
            if ($a.Scope -ne 'user' -and $a.Scope -ne 'managed') { continue }
            $v = Get-AwCcValue -Data $a.Data -Path 'enableAllProjectMcpServers'
            if ($v -is [bool] -and $v) { $profileTrue = $a; break }
        }
        $trusted = ($null -ne $winner -and $winner.Value)
        if (-not $trusted -and $null -eq $profileTrue) { return }
        $servers = 0
        foreach ($f in @($Ctx.McpFiles)) {
            if ($f -and $f.Scope -eq 'project' -and $f.Harness -eq 'claude-code' -and $f.Data -is [System.Collections.IDictionary] -and $f.Data['Servers'] -is [System.Collections.IDictionary]) {
                $servers += $f.Data['Servers'].Count
            }
        }
        if ($trusted) {
            New-AwCcFinding 'AW-CC-006' $winner.Artifact '"enableAllProjectMcpServers"' 'enableAllProjectMcpServers' `
                ('enableAllProjectMcpServers = true ({0}); .mcp.json currently declares {1} server(s)' -f (Get-AwCcScopeLabel $winner.Artifact), $servers)
        } else {
            New-AwCcFinding 'AW-CC-006' $profileTrue '"enableAllProjectMcpServers"' 'enableAllProjectMcpServers' `
                ('enableAllProjectMcpServers = true ({0}) approves .mcp.json servers in folders you have not trusted, although {1} sets false; .mcp.json currently declares {2} server(s)' -f (Get-AwCcScopeLabel $profileTrue), (Get-AwCcScopeLabel $winner.Artifact), $servers)
        }
    }

Register-AwRule -Id 'AW-CC-007' -Title 'Project settings run commands (hooks or helpers)' `
    -Severity 'medium' -Category 'mcp-supply-chain' -Harness 'claude-code' `
    -Description 'Lists what the committed .claude/settings.json makes Claude Code execute: hooks of type command (and http hooks, which send event data to a URL), a command status line or file suggestion, and helper commands (apiKeyHelper, awsAuthRefresh, awsCredentialExport, otelHeadersHelper; the list is in src/Data/claudecode.json). Anyone who can change the repository can change these commands, and they run with your rights. Hooks and helpers are used once a parent folder is trusted, and in claude -p runs that never show the trust dialog. The rule is silent for hooks, the status line and the file suggestion when disableAllHooks (after precedence) or the managed allowManagedHooksOnly turns them off.' `
    -Fix 'Review every command and the scripts it calls, protect .claude/ with CODEOWNERS and required reviews, keep personal hooks in ~/.claude/settings.json, and set "allowManagedHooksOnly": true in managed settings where repository hooks are not needed. Before claude -p in a repository you did not write, pass --settings ''{"disableAllHooks": true}'' or --setting-sources user.' `
    -References @('OWASP-ASI04', 'OWASP-ASI05', $script:AwCcDocs.Hooks, $script:AwCcDocs.Permissions, $script:AwCcDocs.Settings) `
    -Confidence 'high' -Check {
        param($Ctx)
        $data = Get-AwCcData
        $artifacts = @(Get-AwCcArtifacts $Ctx)
        $disabled = Get-AwCcEffective $Ctx 'disableAllHooks' ([bool])
        $hooksOff = ($null -ne $disabled -and $disabled.Value)
        $managedOnly = Test-AwCcAnyEquals $Ctx @('allowManagedHooksOnly') $true @('managed')
        $gated = $hooksOff -or $managedOnly
        $limit = 20
        foreach ($a in @($artifacts | Where-Object { $_.Scope -eq 'project' })) {
            $items = New-Object System.Collections.ArrayList
            if (-not $gated) {
                foreach ($h in @(Get-AwCcCommandHooks (Get-AwCcValue -Data $a.Data -Path 'hooks'))) {
                    $what = if ($h.Matcher) { '{0} [{1}]' -f $h.Event, $h.Matcher } else { $h.Event }
                    [void]$items.Add(@{ Needle = '"' + $h.Event + '"'; Key = 'hooks.' + $h.Event; Text = ('hook {0} {1}: {2}' -f $what, $h.Type, (Format-AwCommandSnippet $h.Text)) })
                }
                foreach ($key in @(Get-AwMcpDataList $data 'commandObjectKeys')) {
                    $obj = Get-AwCcValue -Data $a.Data -Path $key
                    if ($obj -is [System.Collections.IDictionary] -and $obj['type'] -ceq 'command' -and $obj['command'] -is [string] -and $obj['command'].Trim() -ne '') {
                        [void]$items.Add(@{ Needle = '"' + $key + '"'; Key = $key; Text = ('{0} command: {1}' -f $key, (Format-AwCommandSnippet $obj['command'])) })
                    }
                }
            }
            foreach ($helper in @(Get-AwMcpDataList $data 'helperCommandKeys')) {
                $cmd = Get-AwCcValue -Data $a.Data -Path $helper
                if ($cmd -is [string] -and $cmd.Trim() -ne '') {
                    [void]$items.Add(@{ Needle = '"' + $helper + '"'; Key = $helper; Text = ('{0} runs: {1}' -f $helper, (Format-AwCommandSnippet $cmd)) })
                }
            }
            for ($i = 0; $i -lt [Math]::Min($items.Count, $limit); $i++) {
                $text = $items[$i].Text
                if ($i -eq $limit - 1 -and $items.Count -gt $limit) { $text += (' (and {0} more)' -f ($items.Count - $limit)) }
                New-AwCcFinding 'AW-CC-007' $a $items[$i].Needle $items[$i].Key $text
            }
        }
    }

Register-AwRule -Id 'AW-CC-008' -Title 'Project settings disable or weaken the sandbox' `
    -Severity 'medium' -Category 'sandbox-network' -Harness 'claude-code' `
    -Description 'Project settings take precedence over user settings, so a committed .claude/settings.json can turn off or loosen a sandbox that a developer enabled for every project in ~/.claude/settings.json. The rule flags, in project settings: sandbox.enabled = false, sandbox.allowUnsandboxedCommands = true, sandbox.excludedCommands entries that cover any command or an interpreter, sandbox.network.allowedDomains entries that allow every host, and the documented weakening switches (enableWeakerNestedSandbox, enableWeakerNetworkIsolation, network.allowAllUnixSockets, network.allowLocalBinding). It follows the documented exceptions: a managed Boolean wins, a false allowUnsandboxedCommands in user or managed settings holds over the project, network.strictAllowlist in user or managed settings ignores repository domains, and an admin-required sandbox (managed allowUnsandboxedCommands = false or network.allowManagedDomainsOnly = true) ignores the repository values that loosen it.' `
    -Fix 'Remove the sandbox overrides from .claude/settings.json and keep sandbox choices in user or managed settings. Admins can require the sandbox in managed settings (sandbox.enabled, sandbox.allowUnsandboxedCommands = false, sandbox.failIfUnavailable = true).' `
    -References @('OWASP-ASI05', $script:AwCcDocs.Sandboxing, $script:AwCcDocs.Settings) `
    -Confidence 'high' -Check {
        param($Ctx)
        $state = Get-AwCcSandboxState $Ctx
        $managedSets = { param([string]$Key) $null -ne (Get-AwCcEffective $Ctx "sandbox.$Key" ([bool]) @('managed')) }
        $userEnabled = Get-AwCcEffective $Ctx 'sandbox.enabled' ([bool]) @('user')
        $userStrict = Test-AwCcAnyEquals $Ctx @('sandbox.allowUnsandboxedCommands') $false @('user')
        foreach ($a in @(Get-AwCcArtifacts $Ctx | Where-Object { $_.Scope -eq 'project' })) {
            $enabled = Get-AwCcValue -Data $a.Data -Path 'sandbox.enabled'
            if ($enabled -is [bool] -and -not $enabled -and -not (& $managedSets 'enabled') -and
                -not ($state.AdminRequired -and $userEnabled -and $userEnabled.Value)) {
                New-AwCcFinding 'AW-CC-008' $a '"enabled"' 'sandbox.enabled' 'sandbox.enabled = false in project settings'
            }
            $unsandboxed = Get-AwCcValue -Data $a.Data -Path 'sandbox.allowUnsandboxedCommands'
            if ($unsandboxed -is [bool] -and $unsandboxed -and -not (& $managedSets 'allowUnsandboxedCommands') -and -not $userStrict) {
                New-AwCcFinding 'AW-CC-008' $a '"allowUnsandboxedCommands"' 'sandbox.allowUnsandboxedCommands' 'sandbox.allowUnsandboxedCommands = true in project settings'
            }
            if ($state.AdminRequired) { continue }
            foreach ($c in @(Get-AwCcStrings -Data $a.Data -Path 'sandbox.excludedCommands')) {
                $s = $c.Trim()
                if ($s -eq '*' -or $s -eq ':*' -or $s.StartsWith('*') -or (Test-AwCcRunnerSpec $s)) {
                    New-AwCcFinding 'AW-CC-008' $a ('"' + $c + '"') 'sandbox.excludedCommands' ("sandbox.excludedCommands contains '{0}' in project settings" -f (Format-AwCommandSnippet $c 80))
                }
            }
            if (-not $state.StrictAllowlist) {
                foreach ($d in @(Get-AwCcStrings -Data $a.Data -Path 'sandbox.network.allowedDomains')) {
                    if ($d.Trim() -match '^\*(:\d+)?$') {
                        New-AwCcFinding 'AW-CC-008' $a ('"' + $d + '"') 'sandbox.network.allowedDomains' ("sandbox.network.allowedDomains contains '{0}' in project settings" -f (Format-AwCommandSnippet $d 80))
                    }
                }
            }
            foreach ($flag in @(Get-AwMcpDataList (Get-AwCcData) 'sandboxWeakeningFlags')) {
                $v = Get-AwCcValue -Data $a.Data -Path ('sandbox.' + $flag)
                if ($v -is [bool] -and $v -and -not (& $managedSets $flag)) {
                    $leaf = $flag.Substring($flag.LastIndexOf('.') + 1)
                    New-AwCcFinding 'AW-CC-008' $a ('"' + $leaf + '"') ('sandbox.' + $flag) ('sandbox.{0} = true in project settings' -f $flag)
                }
            }
        }
    }

Register-AwRule -Id 'AW-CC-009' -Title 'Sandboxed commands can still run outside the sandbox' `
    -Severity 'low' -Category 'sandbox-network' -Harness 'claude-code' `
    -Description 'When the Bash sandbox is enabled, sandbox.allowUnsandboxedCommands defaults to true: after the sandbox blocks a command, Claude can retry it outside the sandbox with the dangerouslyDisableSandbox parameter (through the regular permission flow, and without a prompt in bypassPermissions mode or when an allow rule matches). Without sandbox.failIfUnavailable = true, Claude Code also runs commands unsandboxed when the sandbox cannot start, which is always the case on native Windows. The effective values follow the documented exceptions: a managed Boolean wins, and a false allowUnsandboxedCommands in user settings holds over a project or local true.' `
    -Fix 'Set "sandbox": { "allowUnsandboxedCommands": false, "failIfUnavailable": true } (strict sandbox mode), ideally in managed settings. On Windows, run Claude Code in WSL2 or a container to get a sandbox.' `
    -References @('OWASP-ASI05', $script:AwCcDocs.Sandboxing, $script:AwCcDocs.Settings) `
    -Confidence 'high' -Check {
        param($Ctx)
        $state = Get-AwCcSandboxState $Ctx
        if ($null -eq $state.Enabled -or -not $state.Enabled.Value) { return }
        if ($null -ne $state.Unsandboxed -and -not $state.Unsandboxed.Value) { return }
        $failText = if ($null -ne $state.FailIfUnavailable -and $state.FailIfUnavailable.Value) { 'true' } else { 'not set (false)' }
        $source = if ($null -eq $state.Unsandboxed) { 'default true' } else { 'set in ' + (Get-AwCcScopeLabel $state.Unsandboxed.Artifact) }
        New-AwCcFinding 'AW-CC-009' $state.Enabled.Artifact '"sandbox"' 'sandbox.allowUnsandboxedCommands' `
            ('sandbox.enabled = true ({0}); sandbox.allowUnsandboxedCommands = true ({1}); sandbox.failIfUnavailable {2}' -f (Get-AwCcScopeLabel $state.Enabled.Artifact), $source, $failText)
    }

Register-AwRule -Id 'AW-CC-010' -Title 'bypassPermissions mode is not disabled' `
    -Severity 'info' -Category 'approvals' -Harness 'claude-code' `
    -Description 'No analyzed settings file sets permissions.disableBypassPermissionsMode = "disable", so anyone can start Claude Code with --dangerously-skip-permissions or switch to bypassPermissions mode. The key works from any scope but is meant for managed settings, which this analysis reads only from the real machine; check them before acting on this finding.' `
    -Fix 'Set "permissions": { "disableBypassPermissionsMode": "disable" } in managed settings (or in your own user settings to lock yourself out of bypass mode).' `
    -References @('OWASP-ASI02', $script:AwCcDocs.Permissions, $script:AwCcDocs.Settings) `
    -Confidence 'high' -Check {
        param($Ctx)
        $artifacts = @(Get-AwCcArtifacts $Ctx)
        if ($artifacts.Count -eq 0) { return }
        if (Test-AwCcAnyEquals $Ctx @('permissions.disableBypassPermissionsMode') 'disable') { return }
        $at = @($artifacts | Where-Object { $_.Scope -eq 'project' }) + $artifacts
        New-AwCcFinding 'AW-CC-010' $at[0] '"permissions"' 'permissions.disableBypassPermissionsMode' `
            ('permissions.disableBypassPermissionsMode is not set in the {0} analyzed settings file(s)' -f $artifacts.Count)
    }
