# Tests for src/Rules/ClaudeCode.ps1 (AW-CC-001 to AW-CC-010). Every secret below is FAKE.
$aw = Get-Module Airworthy
$fixtures = Join-Path $PSScriptRoot 'fixtures'
$area = Join-Path $fixtures 'claudecode'
$tmp = Join-Path $area ('_tmp-' + [guid]::NewGuid().ToString('N'))
$utf8 = New-Object System.Text.UTF8Encoding($false)

# Permission rule texts for AW-CC-003 and AW-CC-008 come from a JSON fixture (CONTRIBUTING.md, Antivirus hygiene).
$cases = & $aw { param($p) ConvertFrom-AwJsonc -Text ([System.IO.File]::ReadAllText($p)) } (Join-Path $area 'rules\allow-rules.json')

function New-CcTree {
    # A temporary folder holding the given files (relative path -> text).
    param([hashtable]$Files)
    $root = Join-Path $tmp ([guid]::NewGuid().ToString('N').Substring(0, 12))
    [void][System.IO.Directory]::CreateDirectory($root)
    foreach ($rel in $Files.Keys) {
        $p = Join-Path $root $rel
        [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $p))
        [System.IO.File]::WriteAllText($p, $Files[$rel], $utf8)
    }
    return $root
}

function Invoke-CcRule {
    # Runs one rule on settings given as JSON text: project (.claude/settings.json), local, user and managed.
    param([string]$RuleId, [string]$Project, [string]$Local, [string]$User, [string]$Managed, [hashtable]$Extra = @{})
    $files = @{}
    foreach ($k in $Extra.Keys) { $files[$k] = $Extra[$k] }
    if ($Project) { $files['.claude\settings.json'] = $Project }
    if ($Local) { $files['.claude\settings.local.json'] = $Local }
    $root = New-CcTree $files
    $userDir = $null
    $managedFile = $null
    if ($User -or $Managed) {
        $userFiles = @{ 'placeholder.txt' = 'synthetic' }
        if ($User) { $userFiles['.claude\settings.json'] = $User }
        $userDir = New-CcTree $userFiles
    }
    if ($Managed) {
        $managedFile = Join-Path (New-CcTree @{ 'managed-settings.json' = $Managed }) 'managed-settings.json'
    }
    & $aw {
        param($id, $r, $u, $m)
        if (-not $script:AwRules.ContainsKey($id)) { throw "Rule $id is not registered" }
        $script:AwManagedSettingsOverride = if ($m) { @($m) } else { $null }
        try {
            $ctx = if ($u) { New-AwContext -Path $r -UserProfilePath $u } else { New-AwContext -Path $r -NoUserProfile }
            @(& $script:AwRules[$id].Check $ctx)
        } finally {
            $script:AwManagedSettingsOverride = $null
        }
    } $RuleId $root $userDir $managedFile
}

function Get-Count([string]$RuleId, [string]$Project, [string]$Local, [string]$User, [string]$Managed) {
    @(Invoke-CcRule -RuleId $RuleId -Project $Project -Local $Local -User $User -Managed $Managed).Count
}

function Get-Allow([string[]]$Allow, [string[]]$Deny = @()) {
    # Project settings with these allow and deny rules.
    $q = { param($list) ($list | ForEach-Object { '"' + $_.Replace('\', '\\').Replace('"', '\"') + '"' }) -join ', ' }
    '{ "permissions": { "allow": [' + (& $q $Allow) + '], "deny": [' + (& $q $Deny) + '] } }'
}

function Get-Excluded([string[]]$Commands) {
    # Project settings that exclude these commands from the sandbox.
    '{ "sandbox": { "excludedCommands": [' + (($Commands | ForEach-Object { '"' + $_ + '"' }) -join ', ') + '] } }'
}

try {
    Describe 'Claude Code rules: registration and data' {
        It 'registers AW-CC-001 to AW-CC-010 with complete metadata' {
            $rules = @(& $aw { Get-AwRules } | Where-Object { $_.Id -like 'AW-CC-*' })
            Assert-Equal 10 $rules.Count
            Assert-Equal 'AW-CC-001' $rules[0].Id
            Assert-Equal 'AW-CC-010' $rules[9].Id
            foreach ($r in $rules) {
                Assert-Equal 'claude-code' $r.Harness $r.Id
                Assert-True ($r.Description.Length -gt 80) $r.Id
                Assert-True (@($r.References | Where-Object { $_ -like 'OWASP-ASI*' }).Count -ge 1) $r.Id
                Assert-True (@($r.References | Where-Object { $_ -like 'https://code.claude.com/*' }).Count -ge 1) $r.Id
            }
            $sev = @{}; foreach ($r in $rules) { $sev[$r.Id] = $r.Severity }
            Assert-Equal 'critical' $sev['AW-CC-001']
            Assert-Equal 'medium' $sev['AW-CC-002']
            Assert-Equal 'critical' $sev['AW-CC-003']
            Assert-Equal 'medium' $sev['AW-CC-004']
            Assert-Equal 'low' $sev['AW-CC-005']
            Assert-Equal 'high' $sev['AW-CC-006']
            Assert-Equal 'medium' $sev['AW-CC-007']
            Assert-Equal 'medium' $sev['AW-CC-008']
            Assert-Equal 'low' $sev['AW-CC-009']
            Assert-Equal 'info' $sev['AW-CC-010']
        }
        It 'reads runner programs and setting keys from src/Data/claudecode.json' {
            $d = & $aw { Get-AwCcData }
            Assert-True ($d -is [System.Collections.IDictionary])
            foreach ($k in @('runnerPrograms', 'runnerSubcommands', 'helperCommandKeys', 'commandObjectKeys', 'sandboxWeakeningFlags', 'projectIgnoredModes')) { Assert-True ($d.Contains($k)) $k }
            Assert-Contains @(& $aw { Get-AwMcpDataList (Get-AwCcData) 'helperCommandKeys' }) 'apiKeyHelper'
        }
    }

    Describe 'AW-CC-001 bypassPermissions mode' {
        $bypass = '{ "permissions": { "defaultMode": "bypassPermissions" } }'
        $safe = '{ "permissions": { "defaultMode": "default" } }'
        It 'flags bypassPermissions from user settings as critical, with its location' {
            $f = @(Invoke-CcRule 'AW-CC-001' -User ('{|  "permissions": {|    "defaultMode": "bypassPermissions"|  }|}'.Replace('|', [Environment]::NewLine)))
            Assert-Equal 1 $f.Count
            Assert-Equal 'critical' $f[0].Severity
            Assert-Equal 'permissions.defaultMode = "bypassPermissions" (user settings)' $f[0].Evidence
            Assert-Equal 3 $f[0].Location.Line
            Assert-Equal 'permissions.defaultMode' $f[0].Location.Key
            Assert-Match $f[0].Location.Path '\.claude\\settings\.json$'
            $m = @(Invoke-CcRule 'AW-CC-001' -Local $safe -Managed $bypass)
            Assert-Equal 1 $m.Count
            Assert-Equal 'critical' $m[0].Severity
            Assert-Match $m[0].Evidence '\(managed settings\)'
        }
        It 'reports a project or local value as medium: ignored since v2.1.257, applied before' {
            $p = @(Invoke-CcRule 'AW-CC-001' -Project $bypass)
            Assert-Equal 1 $p.Count
            Assert-Equal 'medium' $p[0].Severity
            Assert-Equal 'permissions.defaultMode = "bypassPermissions" (project settings): ignored by Claude Code v2.1.257 and later, applied by earlier versions' $p[0].Evidence
            $l = @(Invoke-CcRule 'AW-CC-001' -Project $safe -Local $bypass)
            Assert-Equal 1 $l.Count
            Assert-Equal 'medium' $l[0].Severity
        }
        It 'follows the documented precedence: managed > local > project > user' {
            Assert-Equal 0 (Get-Count 'AW-CC-001' -Project $safe -User $bypass)
            Assert-Equal 0 (Get-Count 'AW-CC-001' -Project $bypass -Local $safe)
            Assert-Equal 0 (Get-Count 'AW-CC-001' -Project $bypass -Managed $safe)
        }
        It 'skips a value of the wrong type in a higher file' {
            $f = @(Invoke-CcRule 'AW-CC-001' -Project '{ "permissions": { "defaultMode": ["plan"] } }' -User $bypass)
            Assert-Equal 1 $f.Count
            Assert-Equal 'critical' $f[0].Severity
        }
        It 'is silent when bypass mode is disabled in any scope' {
            Assert-Equal 0 (Get-Count 'AW-CC-001' -User '{ "permissions": { "defaultMode": "bypassPermissions", "disableBypassPermissionsMode": "disable" } }')
            Assert-Equal 0 (Get-Count 'AW-CC-001' -User $bypass -Project '{ "permissions": { "disableBypassPermissionsMode": "disable" } }')
            Assert-Equal 0 (Get-Count 'AW-CC-001' -Project $bypass -Managed '{ "permissions": { "disableBypassPermissionsMode": "disable" } }')
        }
        It 'is silent for other modes, wrong case and lookalike keys' {
            foreach ($p in @(
                '{ "permissions": { "defaultMode": "default" } }',
                '{ "permissions": { "defaultMode": "plan" } }',
                '{ "permissions": { "defaultMode": "BypassPermissions" } }',
                '{ "Permissions": { "defaultMode": "bypassPermissions" } }',
                '{ "permissions": { "defaultMode": ["bypassPermissions"] } }',
                '{ "defaultMode": "bypassPermissions" }',
                '{ "permissions.defaultMode": "bypassPermissions" }'
            )) { Assert-Equal 0 (Get-Count 'AW-CC-001' -User $p) $p }
        }
    }

    Describe 'AW-CC-002 auto-approving modes' {
        It 'flags acceptEdits from any scope as medium' {
            $a = @(Invoke-CcRule 'AW-CC-002' -Local '{ "permissions": { "defaultMode": "acceptEdits" } }')
            Assert-Equal 1 $a.Count
            Assert-Equal 'medium' $a[0].Severity
            Assert-Equal 'permissions.defaultMode = "acceptEdits" (local settings)' $a[0].Evidence
            Assert-Equal 1 (Get-Count 'AW-CC-002' -Project '{ "permissions": { "defaultMode": "acceptEdits" } }')
        }
        It 'flags auto mode from user settings as low' {
            $b = @(Invoke-CcRule 'AW-CC-002' -User '{ "permissions": { "defaultMode": "auto" } }')
            Assert-Equal 1 $b.Count
            Assert-Equal 'low' $b[0].Severity
            Assert-Equal 'permissions.defaultMode = "auto" (user settings): a classifier, not a person, approves actions' $b[0].Evidence
        }
        It 'reports the built-in auto default when no file sets defaultMode, or a project sets "auto"' {
            $n = @(Invoke-CcRule 'AW-CC-002' -Project '{ }')
            Assert-Equal 1 $n.Count
            Assert-Equal 'low' $n[0].Severity
            Assert-Match $n[0].Evidence '^permissions\.defaultMode is not set in the 1 analyzed settings file\(s\): the built-in default applies, which is auto mode in Claude Code v2\.1\.283'
            $p = @(Invoke-CcRule 'AW-CC-002' -Project '{ "permissions": { "defaultMode": "auto" } }' -User '{ "permissions": { "defaultMode": "default" } }')
            Assert-Equal 1 $p.Count
            Assert-Match $p[0].Evidence '^permissions\.defaultMode = "auto" \(project settings\) does not take effect there; the built-in default applies'
        }
        It 'is silent for safe modes, a disabled auto mode, bypass (AW-CC-001) and without settings' {
            foreach ($p in @(
                '{ "permissions": { "defaultMode": "default" } }',
                '{ "permissions": { "defaultMode": "manual" } }',
                '{ "permissions": { "defaultMode": "plan" } }',
                '{ "permissions": { "defaultMode": "dontAsk" } }',
                '{ "permissions": { "defaultMode": "bypassPermissions" } }',
                '{ "permissions": { "defaultMode": "auto" }, "disableAutoMode": "disable" }',
                '{ "permissions": { "defaultMode": "auto", "disableAutoMode": "disable" } }',
                '{ "disableAutoMode": "disable" }'
            )) { Assert-Equal 0 (Get-Count 'AW-CC-002' -Project $p) $p }
            Assert-Equal 0 (Get-Count 'AW-CC-002' -User '{ "permissions": { "defaultMode": "auto" } }' -Managed '{ "permissions": { "disableAutoMode": "disable" } }')
            Assert-Equal 0 (Get-Count 'AW-CC-002')
        }
    }

    Describe 'AW-CC-003 broad shell allow rules' {
        It 'flags rules that match every command as critical' {
            foreach ($rule in @($cases['critical'])) {
                $f = @(Invoke-CcRule 'AW-CC-003' -Project (Get-Allow @($rule)))
                Assert-Equal 1 $f.Count $rule
                Assert-Equal 'critical' $f[0].Severity $rule
            }
        }
        It 'flags interpreters, runners and a leading wildcard as high' {
            Assert-True (@($cases['high']).Count -ge 10) 'fixture size'
            foreach ($rule in @($cases['high'])) {
                $f = @(Invoke-CcRule 'AW-CC-003' -Project (Get-Allow @($rule)))
                Assert-Equal 1 $f.Count $rule
                Assert-Equal 'high' $f[0].Severity $rule
            }
        }
        It 'shows the rule, its file and its line' {
            $f = @(Invoke-CcRule 'AW-CC-003' -Project ('{ "permissions": {| "allow": [|  "Bash(npm test)",|  "Bash(*)"| ] } }'.Replace('|', [Environment]::NewLine)))
            Assert-Equal "permissions.allow contains 'Bash(*)' in project settings: every Bash command runs without approval" $f[0].Evidence
            Assert-Equal 4 $f[0].Location.Line
            $u = @(Invoke-CcRule 'AW-CC-003' -User (Get-Allow @('Bash')))
            Assert-Match $u[0].Evidence 'in user settings'
        }
        It 'accepts narrow rules and rules of other tools' {
            Assert-Equal 0 (Get-Count 'AW-CC-003' -Project (Get-Allow @($cases['silent'])))
        }
        It 'is silent when a deny rule removes the tool, including a tool-name glob' {
            Assert-Equal 0 (Get-Count 'AW-CC-003' -Project (Get-Allow @('Bash(*)') @('Bash')))
            Assert-Equal 0 (Get-Count 'AW-CC-003' -Project (Get-Allow @('Bash(*)')) -User (Get-Allow @() @('Bash(*)')))
            Assert-Equal 0 (Get-Count 'AW-CC-003' -Project (Get-Allow @('Bash(*)', 'PowerShell') @('*')))
            Assert-Equal 0 (Get-Count 'AW-CC-003' -Project (Get-Allow @('Bash(*)') @('B*')))
            Assert-Equal 1 (Get-Count 'AW-CC-003' -Project (Get-Allow @('Bash(*)') @('Bash(rm *)')))
            Assert-Equal 1 (Get-Count 'AW-CC-003' -Project (Get-Allow @('PowerShell') @('Bash')))
            Assert-Equal 1 (Get-Count 'AW-CC-003' -Project (Get-Allow @('Bash(*)') @('[')))
        }
    }

    Describe 'AW-CC-004 unrestricted web fetch' {
        It 'flags WebFetch without a domain restriction' {
            foreach ($rule in @('WebFetch', 'WebFetch(domain:*)', 'WebFetch(domain:*.com)', 'WebFetch(*)')) {
                $f = @(Invoke-CcRule 'AW-CC-004' -Project (Get-Allow @($rule)))
                Assert-Equal 1 $f.Count $rule
                Assert-Equal 'medium' $f[0].Severity
            }
        }
        It 'accepts specific domains and is silent when WebFetch is denied' {
            Assert-Equal 0 (Get-Count 'AW-CC-004' -Project (Get-Allow @('WebFetch(domain:docs.example.invalid)', 'WebFetch(domain:*.github.com)')))
            Assert-Equal 0 (Get-Count 'AW-CC-004' -Project (Get-Allow @('WebFetch') @('WebFetch')))
            Assert-Equal 0 (Get-Count 'AW-CC-004' -Project (Get-Allow @('WebFetch')) -Managed (Get-Allow @() @('WebFetch(domain:*)')))
        }
    }

    Describe 'AW-CC-005 deny rules for secret files' {
        It 'flags settings with no Read deny rule for .env' {
            $f = @(Invoke-CcRule 'AW-CC-005' -Project (Get-Allow @() @('Bash(curl *)', 'Edit(./.env)', 'Read(./.env.*)')))
            Assert-Equal 1 $f.Count
            Assert-Equal 'no permissions.deny Read rule covers .env files' $f[0].Evidence
            Assert-Equal 'low' $f[0].Severity
        }
        It 'accepts the usual .env deny patterns' {
            foreach ($rule in @('Read(./.env)', 'Read(.env)', 'Read(.env*)', 'Read(*.env)', 'Read(**/.env)', 'Read(//**/.env)', 'Read(./**)', 'Read', 'Read(/.env)')) {
                Assert-Equal 0 (Get-Count 'AW-CC-005' -Project (Get-Allow @() @($rule))) $rule
            }
            Assert-Equal 0 (Get-Count 'AW-CC-005' -Local (Get-Allow @() @('Read(./.env)')))
        }
        It 'does not count a user-settings /path rule, which is anchored at ~/.claude' {
            $f = @(Invoke-CcRule 'AW-CC-005' -Project '{ }' -User (Get-Allow @() @('Read(/.env)', 'Read(~/.ssh/**)')))
            Assert-Equal @('no permissions.deny Read rule covers .env files') @($f | ForEach-Object { $_.Evidence })
        }
        It 'checks ~/.ssh only when user or managed settings are analyzed' {
            $project = Get-Allow @() @('Read(./.env)')
            Assert-Equal 0 (Get-Count 'AW-CC-005' -Project $project)
            $f = @(Invoke-CcRule 'AW-CC-005' -Project $project -User '{ "permissions": { } }')
            Assert-Equal 1 $f.Count
            Assert-Equal 'no permissions.deny Read rule covers ~/.ssh' $f[0].Evidence
            Assert-Match $f[0].Location.Path ([regex]::Escape('.claude\settings.json') + '$')
            foreach ($rule in @('Read(~/.ssh/**)', 'Read(~/.ssh)', 'Read(//**/.ssh/**)', 'Read(~/**)')) {
                Assert-Equal 0 (Get-Count 'AW-CC-005' -Project $project -User (Get-Allow @() @($rule))) $rule
            }
            Assert-Equal 0 (Get-Count 'AW-CC-005' -Project $project -Managed (Get-Allow @() @('Read(~/.ssh/**)')))
            Assert-Equal 1 (Get-Count 'AW-CC-005' -Project $project -User (Get-Allow @() @('Read(**/.ssh/**)')))
        }
        It 'is silent when there is no Claude Code settings file' {
            Assert-Equal 0 (Get-Count 'AW-CC-005')
        }
    }

    Describe 'AW-CC-006 automatic approval of project MCP servers' {
        It 'flags enableAllProjectMcpServers = true with the server count' {
            $f = @(Invoke-CcRule 'AW-CC-006' -Project '{ "enableAllProjectMcpServers": true }' -Extra @{ '.mcp.json' = '{ "mcpServers": { "a": { "command": "node" }, "b": { "command": "node" } } }' })
            Assert-Equal 1 $f.Count
            Assert-Equal 'enableAllProjectMcpServers = true (project settings); .mcp.json currently declares 2 server(s)' $f[0].Evidence
            Assert-Equal 'high' $f[0].Severity
        }
        It 'follows precedence and ignores non-boolean values' {
            Assert-Equal 1 (Get-Count 'AW-CC-006' -User '{ "enableAllProjectMcpServers": true }')
            Assert-Equal 0 (Get-Count 'AW-CC-006' -Project '{ "enableAllProjectMcpServers": true }' -Local '{ "enableAllProjectMcpServers": false }')
            Assert-Equal 0 (Get-Count 'AW-CC-006' -Project '{ "enableAllProjectMcpServers": "true" }')
            Assert-Equal 0 (Get-Count 'AW-CC-006' -Project '{ "enableAllProjectMcpServers": false, "enabledMcpjsonServers": ["docs"] }')
            Assert-Equal 1 (Get-Count 'AW-CC-006' -Project '{ "enableAllProjectMcpServers": "yes" }' -Local '{ "enableAllProjectMcpServers": true }')
        }
        It 'flags a user or managed true that applies in untrusted folders despite a higher false' {
            $f = @(Invoke-CcRule 'AW-CC-006' -Project '{ "enableAllProjectMcpServers": false }' -User '{ "enableAllProjectMcpServers": true }')
            Assert-Equal 1 $f.Count
            Assert-Match $f[0].Evidence '^enableAllProjectMcpServers = true \(user settings\) approves \.mcp\.json servers in folders you have not trusted, although project settings sets false'
            Assert-Equal 1 (Get-Count 'AW-CC-006' -Local '{ "enableAllProjectMcpServers": false }' -Managed '{ "enableAllProjectMcpServers": true }')
        }
    }

    Describe 'AW-CC-007 commands run by project settings' {
        $commands = '{ "hooks": { "PostToolUse": [ { "matcher": "Edit|Write", "hooks": [ { "type": "command", "command": "npm run lint" }, { "type": "prompt", "prompt": "Check it" } ] } ],' +
                    ' "Stop": [ { "hooks": [ { "type": "http", "url": "https://hooks.example.invalid/stop" } ] } ] },' +
                    ' "statusLine": { "type": "command", "command": "bash statusline.sh" }, "apiKeyHelper": "node get-key.js", "awsAuthRefresh": "aws sso login" }'
        It 'lists command and http hooks, the status line and helper commands' {
            $f = @(Invoke-CcRule 'AW-CC-007' -Project $commands)
            $ev = @($f | ForEach-Object { $_.Evidence })
            Assert-Equal 5 $f.Count
            Assert-Contains $ev 'hook PostToolUse [Edit|Write] command: npm run lint'
            Assert-Contains $ev 'hook Stop http: https://hooks.example.invalid/stop'
            Assert-Contains $ev 'statusLine command: bash statusline.sh'
            Assert-Contains $ev 'apiKeyHelper runs: node get-key.js'
            Assert-Contains $ev 'awsAuthRefresh runs: aws sso login'
            Assert-Contains @($f | ForEach-Object { $_.Location.Key }) 'hooks.PostToolUse'
        }
        It 'lists the file suggestion, the other helpers and hook arguments' {
            $p = '{ "fileSuggestion": { "type": "command", "command": "./index.sh" }, "awsCredentialExport": "./aws-grant.sh", "otelHeadersHelper": "./otel.sh",' +
                 ' "hooks": { "SessionStart": [ { "hooks": [ { "type": "command", "command": "node", "args": ["hook.js", "--fast"] }, { "type": "mcp_tool", "server": "s", "tool": "t" } ] } ] } }'
            $ev = @(Invoke-CcRule 'AW-CC-007' -Project $p | ForEach-Object { $_.Evidence })
            Assert-Equal 4 $ev.Count
            Assert-Contains $ev 'fileSuggestion command: ./index.sh'
            Assert-Contains $ev 'awsCredentialExport runs: ./aws-grant.sh'
            Assert-Contains $ev 'otelHeadersHelper runs: ./otel.sh'
            Assert-Contains $ev 'hook SessionStart command: node hook.js --fast'
        }
        It 'masks secrets in hook commands' {
            $f = @(Invoke-CcRule 'AW-CC-007' -Project '{ "hooks": { "Stop": [ { "hooks": [ { "type": "command", "command": "example-notify -H token:FAKE0123456789abcdefghij" } ] } ] } }')
            Assert-NotMatch $f[0].Evidence 'FAKE0123456789abcdefghij'
            $g = @(Invoke-CcRule 'AW-CC-007' -Project '{ "hooks": { "Stop": [ { "hooks": [ { "type": "command", "command": "example-notify -H \"Authorization: Bearer FAKE-x1\"" } ] } ] }, "apiKeyHelper": "echo --api-key=FAKE-k2" }')
            Assert-NotMatch (($g | ForEach-Object { $_.Evidence }) -join "`n") 'FAKE-x1|FAKE-k2'
        }
        It 'ignores local and user settings' {
            Assert-Equal 0 (Get-Count 'AW-CC-007' -Local $commands -User $commands)
        }
        It 'honors disableAllHooks after precedence and the managed allowManagedHooksOnly' {
            $off = @(Invoke-CcRule 'AW-CC-007' -Project $commands -Local '{ "disableAllHooks": true }')
            Assert-Equal @('apiKeyHelper runs: node get-key.js', 'awsAuthRefresh runs: aws sso login') @($off | ForEach-Object { $_.Evidence })
            # A project false overrides a user true.
            Assert-Equal 5 (Get-Count 'AW-CC-007' -Project ($commands.TrimEnd('}') + ', "disableAllHooks": false }') -User '{ "disableAllHooks": true }')
            Assert-Equal 2 (Get-Count 'AW-CC-007' -Project $commands -User '{ "disableAllHooks": true }')
            # allowManagedHooksOnly also narrows the status line and the file suggestion to managed settings.
            $managed = @(Invoke-CcRule 'AW-CC-007' -Project $commands -Managed '{ "allowManagedHooksOnly": true }')
            Assert-Equal @('apiKeyHelper runs: node get-key.js', 'awsAuthRefresh runs: aws sso login') @($managed | ForEach-Object { $_.Evidence })
            Assert-Equal 5 (Get-Count 'AW-CC-007' -Project $commands -User '{ "allowManagedHooksOnly": true }')
        }
        It 'caps the number of findings for one file' {
            $groups = (1..30 | ForEach-Object { '{ "hooks": [ { "type": "command", "command": "echo ' + $_ + '" } ] }' }) -join ', '
            $f = @(Invoke-CcRule 'AW-CC-007' -Project ('{ "hooks": { "PreToolUse": [ ' + $groups + ' ] } }'))
            Assert-Equal 20 $f.Count
            Assert-Match $f[19].Evidence '\(and 10 more\)$'
        }
        It 'is silent without commands' {
            Assert-Equal 0 (Get-Count 'AW-CC-007' -Project '{ "hooks": { "Stop": [ { "hooks": [ { "type": "prompt", "prompt": "x" } ] } ] }, "statusLine": { "type": "static" }, "apiKeyHelper": " " }')
            Assert-Equal 0 (Get-Count 'AW-CC-007' -Project '{ "hooks": "PAYLOAD", "statusLine": "PAYLOAD", "fileSuggestion": { "type": "command", "command": 7 } }')
        }
    }

    Describe 'AW-CC-008 sandbox weakened by project settings' {
        $weak = '{ "sandbox": { "enabled": false, "allowUnsandboxedCommands": true, "excludedCommands": ["docker *", "*", "python *"], "enableWeakerNestedSandbox": true,' +
                ' "network": { "allowedDomains": ["*.example.invalid", "*"], "allowLocalBinding": true, "allowAllUnixSockets": false } } }'
        It 'flags each weakening in project settings' {
            $f = @(Invoke-CcRule 'AW-CC-008' -Project $weak)
            $ev = @($f | ForEach-Object { $_.Evidence })
            Assert-Equal 7 $f.Count
            Assert-Contains $ev 'sandbox.enabled = false in project settings'
            Assert-Contains $ev 'sandbox.allowUnsandboxedCommands = true in project settings'
            Assert-Contains $ev "sandbox.excludedCommands contains '*' in project settings"
            Assert-Contains $ev "sandbox.excludedCommands contains 'python *' in project settings"
            Assert-Contains $ev "sandbox.network.allowedDomains contains '*' in project settings"
            Assert-Contains $ev 'sandbox.enableWeakerNestedSandbox = true in project settings'
            Assert-Contains $ev 'sandbox.network.allowLocalBinding = true in project settings'
            Assert-Contains @($f | ForEach-Object { $_.Location.Key }) 'sandbox.network.allowLocalBinding'
        }
        It 'flags broad excluded commands from the fixture and accepts narrow ones' {
            foreach ($c in @($cases['excludedBroad'])) { Assert-Equal 1 (Get-Count 'AW-CC-008' -Project (Get-Excluded @($c))) $c }
            Assert-Equal 0 (Get-Count 'AW-CC-008' -Project (Get-Excluded @($cases['excludedNarrow'])))
        }
        It 'ignores local and user settings and safe values' {
            Assert-Equal 0 (Get-Count 'AW-CC-008' -Local '{ "sandbox": { "enabled": false } }' -User '{ "sandbox": { "enabled": false } }')
            Assert-Equal 0 (Get-Count 'AW-CC-008' -Project '{ "sandbox": { "enabled": true, "allowUnsandboxedCommands": false, "excludedCommands": ["docker *"], "network": { "allowedDomains": ["api.example.invalid"] } } }')
        }
        It 'follows the documented exceptions: managed values, user strict mode and the admin-required sandbox' {
            # A managed Boolean wins, and a user or managed allowUnsandboxedCommands = false holds over the project.
            Assert-Equal 5 (Get-Count 'AW-CC-008' -Project $weak -Managed '{ "sandbox": { "enabled": true, "network": { "allowLocalBinding": false } } }')
            Assert-Equal 6 (Get-Count 'AW-CC-008' -Project $weak -User '{ "sandbox": { "allowUnsandboxedCommands": false } }')
            # network.strictAllowlist in user or managed settings ignores repository domains.
            Assert-Equal 6 (Get-Count 'AW-CC-008' -Project $weak -User '{ "sandbox": { "network": { "strictAllowlist": true } } }')
            # Admin-required sandbox: repository loosening is ignored; a repository false is ignored when the user says true.
            $admin = @(Invoke-CcRule 'AW-CC-008' -Project $weak -User '{ "sandbox": { "enabled": true } }' -Managed '{ "sandbox": { "allowUnsandboxedCommands": false } }')
            Assert-Equal 0 $admin.Count
            $domains = @(Invoke-CcRule 'AW-CC-008' -Project $weak -Managed '{ "sandbox": { "network": { "allowManagedDomainsOnly": true } } }')
            Assert-Equal @('sandbox.enabled = false in project settings', 'sandbox.allowUnsandboxedCommands = true in project settings') @($domains | ForEach-Object { $_.Evidence })
        }
    }

    Describe 'AW-CC-009 sandbox escape hatch' {
        It 'flags an enabled sandbox that still allows unsandboxed retries' {
            $f = @(Invoke-CcRule 'AW-CC-009' -User '{ "sandbox": { "enabled": true } }')
            Assert-Equal 1 $f.Count
            Assert-Equal 'sandbox.enabled = true (user settings); sandbox.allowUnsandboxedCommands = true (default true); sandbox.failIfUnavailable not set (false)' $f[0].Evidence
            $g = @(Invoke-CcRule 'AW-CC-009' -Local '{ "sandbox": { "enabled": true, "allowUnsandboxedCommands": true, "failIfUnavailable": true } }')
            Assert-Match $g[0].Evidence 'set in local settings\); sandbox.failIfUnavailable true$'
        }
        It 'is silent in strict mode or without the sandbox' {
            Assert-Equal 0 (Get-Count 'AW-CC-009' -Project '{ "sandbox": { "enabled": true, "allowUnsandboxedCommands": false } }')
            Assert-Equal 0 (Get-Count 'AW-CC-009' -Project '{ "sandbox": { "enabled": true } }' -Managed '{ "sandbox": { "allowUnsandboxedCommands": false } }')
            Assert-Equal 0 (Get-Count 'AW-CC-009' -Project '{ "sandbox": { "enabled": false } }' -User '{ "sandbox": { "enabled": true } }')
            Assert-Equal 0 (Get-Count 'AW-CC-009' -Project '{ "sandbox": { "enabled": "yes" } }')
        }
        It 'keeps a user false over a project true, and a managed Boolean over everything' {
            Assert-Equal 0 (Get-Count 'AW-CC-009' -Project '{ "sandbox": { "enabled": true, "allowUnsandboxedCommands": true } }' -User '{ "sandbox": { "allowUnsandboxedCommands": false } }')
            Assert-Equal 1 (Get-Count 'AW-CC-009' -Project '{ "sandbox": { "enabled": false } }' -Managed '{ "sandbox": { "enabled": true } }')
            Assert-Equal 1 (Get-Count 'AW-CC-009' -Project '{ "sandbox": { "enabled": true, "allowUnsandboxedCommands": false } }' -Managed '{ "sandbox": { "allowUnsandboxedCommands": true } }')
        }
    }

    Describe 'AW-CC-010 bypass mode not disabled' {
        It 'reports settings without the lock' {
            $f = @(Invoke-CcRule 'AW-CC-010' -Project '{ "permissions": { "defaultMode": "default" } }' -User '{ }')
            Assert-Equal 1 $f.Count
            Assert-Equal 'info' $f[0].Severity
            Assert-Equal 'permissions.disableBypassPermissionsMode is not set in the 2 analyzed settings file(s)' $f[0].Evidence
            Assert-Equal 1 (Get-Count 'AW-CC-010' -Project '{ "permissions": { "disableBypassPermissionsMode": "Disable" } }')
        }
        It 'is silent when any scope sets the lock, or without settings' {
            $lock = '{ "permissions": { "disableBypassPermissionsMode": "disable" } }'
            Assert-Equal 0 (Get-Count 'AW-CC-010' -Project $lock)
            Assert-Equal 0 (Get-Count 'AW-CC-010' -Project '{ }' -User $lock)
            Assert-Equal 0 (Get-Count 'AW-CC-010' -Project '{ }' -Managed $lock)
            Assert-Equal 0 (Get-Count 'AW-CC-010')
        }
    }

    Describe 'Claude Code rules: fixtures' {
        It 'reports every issue of the claudecode/project-insecure fixture' {
            $r = Invoke-Airworthy -Path (Join-Path $area 'project-insecure') -NoUserProfile -PassThru -Quiet
            $mine = @($r.Findings | Where-Object { $_.RuleId -like 'AW-CC-*' })
            Assert-Equal @('AW-CC-003', 'AW-CC-003', 'AW-CC-006', 'AW-CC-002', 'AW-CC-004', 'AW-CC-007', 'AW-CC-007', 'AW-CC-007', 'AW-CC-007',
                           'AW-CC-008', 'AW-CC-008', 'AW-CC-008', 'AW-CC-008', 'AW-CC-005', 'AW-CC-010') @($mine | ForEach-Object { $_.RuleId })
            Assert-Equal @('critical', 'high') @($mine | Where-Object { $_.RuleId -eq 'AW-CC-003' } | ForEach-Object { $_.Severity })
            Assert-Contains @($mine | ForEach-Object { $_.Evidence }) 'hook PreToolUse [Bash] command: node .claude/hooks/check.js --strict'
            Assert-Contains @($mine | ForEach-Object { $_.Evidence }) 'sandbox.enableWeakerNetworkIsolation = true in project settings'
        }
        It 'is silent on the claudecode/project-hardened fixture' {
            $r = Invoke-Airworthy -Path (Join-Path $area 'project-hardened') -NoUserProfile -PassThru -Quiet
            Assert-Equal 0 @($r.Findings | Where-Object { $_.RuleId -like 'AW-CC-*' }).Count
        }
        It 'combines the project with the user profile and managed settings' {
            $root = Join-Path $area 'project-hardened'
            $userDir = Join-Path $area 'profile'
            $r = Invoke-Airworthy -Path $root -UserProfilePath $userDir -PassThru -Quiet
            # The project's plan mode, lock and strict sandbox win over the user's settings; the user's Bash(*) still applies.
            Assert-Equal @('AW-CC-003') @($r.Findings | Where-Object { $_.RuleId -like 'AW-CC-*' } | ForEach-Object { $_.RuleId })
            & $aw { param($p) $script:AwManagedSettingsOverride = @($p) } (Join-Path $area 'managed\managed-settings.json')
            try {
                $m = Invoke-Airworthy -Path (Join-Path $fixtures 'insecure') -UserProfilePath $userDir -PassThru -Quiet
            } finally { & $aw { $script:AwManagedSettingsOverride = $null } }
            $mine = @($m.Findings | Where-Object { $_.RuleId -like 'AW-CC-*' } | ForEach-Object { $_.RuleId })
            Assert-NotContains $mine 'AW-CC-001'
            Assert-NotContains $mine 'AW-CC-007'
            Assert-NotContains $mine 'AW-CC-010'
            Assert-Contains $mine 'AW-CC-003'
        }
        It 'reports the shared fixtures as expected' {
            $i = Invoke-Airworthy -Path (Join-Path $fixtures 'insecure') -NoUserProfile -PassThru -Quiet
            $mine = @($i.Findings | Where-Object { $_.RuleId -like 'AW-CC-*' })
            Assert-Equal @('AW-CC-003', 'AW-CC-006', 'AW-CC-001', 'AW-CC-004', 'AW-CC-007', 'AW-CC-005', 'AW-CC-010') @($mine | ForEach-Object { $_.RuleId })
            Assert-Equal 'medium' @($mine | Where-Object { $_.RuleId -eq 'AW-CC-001' })[0].Severity
            $h = Invoke-Airworthy -Path (Join-Path $fixtures 'hardened') -NoUserProfile -PassThru -Quiet
            Assert-Equal 0 @($h.Findings | Where-Object { $_.RuleId -like 'AW-CC-*' }).Count
            $m = Invoke-Airworthy -Path (Join-Path $fixtures 'mixed') -NoUserProfile -PassThru -Quiet
            Assert-Equal @('AW-CC-002', 'AW-CC-005', 'AW-CC-010') @($m.Findings | Where-Object { $_.RuleId -like 'AW-CC-*' } | ForEach-Object { $_.RuleId })
        }
    }

    Describe 'Claude Code rules: hostile input' {
        It 'ignores malformed values without failing' {
            $hostile = '{ "permissions": { "defaultMode": { "x": 1 }, "allow": "Bash(*)", "deny": [1, null, {"a": "Read"}] },' +
                       ' "hooks": [ "PAYLOAD" ], "sandbox": "off", "enableAllProjectMcpServers": [true], "statusLine": [], "apiKeyHelper": 7, "fileSuggestion": "PAYLOAD" }'
            foreach ($id in @('AW-CC-001', 'AW-CC-003', 'AW-CC-004', 'AW-CC-006', 'AW-CC-007', 'AW-CC-008', 'AW-CC-009')) {
                Assert-Equal 0 (Get-Count $id -Project $hostile) $id
            }
            Assert-Equal 1 (Get-Count 'AW-CC-005' -Project $hostile)
            # An invalid defaultMode is rejected, so the built-in default applies.
            $d = @(Invoke-CcRule 'AW-CC-002' -Project $hostile)
            Assert-Equal 1 $d.Count
            Assert-Match $d[0].Evidence '^permissions\.defaultMode is not set'
        }
        It 'skips invalid JSON files (reported by AW-CORE-001)' {
            foreach ($id in @('AW-CC-001', 'AW-CC-002', 'AW-CC-005', 'AW-CC-010')) { Assert-Equal 0 (Get-Count $id -Project '{ "permissions": ') $id }
        }
        It 'reports a missing data file as a rule failure, not a crash' {
            & $aw { param($dir) $script:AwCcSavedDataPath = $script:AwCcDataPath; $script:AwCcDataPath = [System.IO.Path]::Combine($dir, 'no-such-data.json'); $script:AwCcData = $null } $area
            try {
                $r = Invoke-Airworthy -Path (Join-Path $area 'project-insecure') -NoUserProfile -PassThru -Quiet
                Assert-True (@($r.Findings | Where-Object { $_.RuleId -eq 'AW-CORE-002' -and $_.Location.Key -eq 'AW-CC-003' }).Count -eq 1)
                Assert-Equal 1 @($r.Findings | Where-Object { $_.RuleId -eq 'AW-CC-004' }).Count
            } finally {
                & $aw { $script:AwCcDataPath = $script:AwCcSavedDataPath; $script:AwCcData = $null }
            }
        }
        It 'runs through the engine without a rule failure' {
            $r = Invoke-Airworthy -Path (Join-Path $area 'project-insecure') -UserProfilePath (Join-Path $area 'profile') -PassThru -Quiet
            Assert-Equal 0 @($r.Findings | Where-Object { $_.RuleId -eq 'AW-CORE-002' -and $_.Location.Key -like 'AW-CC-*' }).Count
        }
    }

    Describe 'Claude Code rules: coverage' {
        It 'has a positive and a negative test for every AW-CC rule' {
            $text = [System.IO.File]::ReadAllText((Join-Path (Split-Path -Parent $fixtures) 'ClaudeCode.Tests.ps1'))
            foreach ($n in 1..10) {
                $id = 'AW-CC-{0:D3}' -f $n
                $q = [regex]::Escape($id)
                Assert-True ($text -match ("Describe '" + $q + " ")) ($id + ' section')
                Assert-True ($text -match ("Invoke-CcRule '" + $q + "'")) ($id + ' positive')
                Assert-True ($text -match ("Assert-Equal 0 \(Get-Count '" + $q + "'")) ($id + ' negative')
            }
        }
    }
} finally {
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force }
}
