# Tests for src/Rules/CopilotCli.ps1 (AW-CLI-001 to AW-CLI-005).
$aw = Get-Module Airworthy
$fixtures = Join-Path $PSScriptRoot 'fixtures'
$area = Join-Path $fixtures 'copilotcli'
$tmp = Join-Path $area ('_tmp-' + [guid]::NewGuid().ToString('N'))
$utf8 = New-Object System.Text.UTF8Encoding($false)

function New-CliTree {
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

function Invoke-CliRule {
    # Runs one rule on JSON text for .github/copilot/settings.json (Repo), ~/.copilot/config.json and ~/.copilot/settings.json.
    param([string]$RuleId, [string]$Repo, [string]$Config, [string]$Settings, [string]$UserDir)
    $files = @{ 'README.md' = 'synthetic' }
    if ($Repo) { $files['.github\copilot\settings.json'] = $Repo }
    $root = New-CliTree $files
    if (-not $UserDir -and ($Config -or $Settings)) {
        $userFiles = @{ 'placeholder.txt' = 'synthetic' }
        if ($Config) { $userFiles['.copilot\config.json'] = $Config }
        if ($Settings) { $userFiles['.copilot\settings.json'] = $Settings }
        $UserDir = New-CliTree $userFiles
    }
    & $aw {
        param($id, $r, $u)
        if (-not $script:AwRules.ContainsKey($id)) { throw "Rule $id is not registered" }
        $ctx = if ($u) { New-AwContext -Path $r -UserProfilePath $u } else { New-AwContext -Path $r -NoUserProfile }
        @(& $script:AwRules[$id].Check $ctx)
    } $RuleId $root $UserDir
}

function ConvertTo-JsonList([string[]]$Items) {
    '[' + (($Items | ForEach-Object { '"' + $_.Replace('\', '\\') + '"' }) -join ', ') + ']'
}

try {
    Describe 'Copilot CLI rules: registration' {
        It 'registers AW-CLI-001 to AW-CLI-005 with complete metadata' {
            $rules = @(& $aw { Get-AwRules } | Where-Object { $_.Id -like 'AW-CLI-*' })
            Assert-Equal @('AW-CLI-001', 'AW-CLI-002', 'AW-CLI-003', 'AW-CLI-004', 'AW-CLI-005') @($rules | ForEach-Object { $_.Id })
            foreach ($r in $rules) {
                Assert-Equal 'copilot-cli' $r.Harness $r.Id
                Assert-True ($r.Description.Length -gt 80) $r.Id
                Assert-True (@($r.References | Where-Object { $_ -like 'OWASP-ASI*' }).Count -ge 1) $r.Id
                Assert-True (@($r.References | Where-Object { $_ -like 'https://docs.github.com/*' }).Count -ge 1) $r.Id
            }
            Assert-Equal @('high', 'medium', 'medium', 'medium', 'info') @($rules | ForEach-Object { $_.Severity })
            Assert-Equal @('medium', 'medium', 'high', 'high', 'high') @($rules | ForEach-Object { $_.Confidence })
        }
    }

    Describe 'AW-CLI-001 broad trusted folders' {
        It 'flags the home directory, profile folders and roots' {
            $broad = @('C:\Users\FAKEUSER', 'C:/Users/FAKEUSER/', 'D:\', 'E:', '/', '/home/dev', '/Users/dev', '/root', '~', '%USERPROFILE%', 'C:\Users', '/home', '\\fileserver\share')
            $f = @(Invoke-CliRule 'AW-CLI-001' -Config ('{ "trusted_folders": ' + (ConvertTo-JsonList $broad) + ' }'))
            Assert-Equal $broad.Count $f.Count
            Assert-Equal "trusted_folders contains 'C:\Users\FAKEUSER' (the home directory)" $f[0].Evidence
            Assert-Equal "trusted_folders contains 'D:\' (a drive root)" $f[2].Evidence
            Assert-Equal "trusted_folders contains 'C:\Users' (the folder of all user profiles)" $f[10].Evidence
            Assert-Equal 'trusted_folders' $f[0].Location.Key
            Assert-Match $f[0].Location.Path '\.copilot\\config\.json$'
        }
        It 'flags the analyzed user profile itself and the camelCase key' {
            $userDir = New-CliTree @{ 'placeholder.txt' = 'synthetic' }
            $json = '{ "trustedFolders": ' + (ConvertTo-JsonList @($userDir, (Join-Path $userDir 'src'))) + ' }'
            [void][System.IO.Directory]::CreateDirectory((Join-Path $userDir '.copilot'))
            [System.IO.File]::WriteAllText((Join-Path $userDir '.copilot\config.json'), $json, $utf8)
            $f = @(Invoke-CliRule 'AW-CLI-001' -UserDir $userDir)
            Assert-Equal 1 $f.Count
            Assert-Match $f[0].Evidence '^trustedFolders contains .* \(the home directory\)$'
        }
        It 'accepts project folders and ignores malformed entries' {
            $ok = @('D:\work\project', 'C:\Users\dev\src\app', '/home/dev/project', '/Users/dev/code/app', 'C:\Program Files\Tool')
            Assert-Equal 0 @(Invoke-CliRule 'AW-CLI-001' -Config ('{ "trusted_folders": ' + (ConvertTo-JsonList $ok) + ' }')).Count
            Assert-Equal 0 @(Invoke-CliRule 'AW-CLI-001' -Config '{ "trusted_folders": [1, null, {"p": "/"}, ["/"], ""] }').Count
            Assert-Equal 0 @(Invoke-CliRule 'AW-CLI-001' -Config '{ "trusted_folders": "/" }').Count
            Assert-Equal 0 @(Invoke-CliRule 'AW-CLI-001' -Config '{ "Trusted_Folders": ["/"] }').Count
        }
    }

    Describe 'AW-CLI-002 allowedUrls for every host' {
        It 'flags entries that match any host' {
            foreach ($u in @('*', 'https://*', 'http://*/*', '*://*', '*.*', '*.com', 'https://*.org/', '*:443')) {
                $f = @(Invoke-CliRule 'AW-CLI-002' -Settings ('{ "allowedUrls": ["docs.github.com", "' + $u + '"] }'))
                Assert-Equal 1 $f.Count $u
                Assert-Equal ("allowedUrls contains '{0}' (any host)" -f $u) $f[0].Evidence
            }
        }
        It 'accepts specific hosts and ignores repository settings' {
            Assert-Equal 0 @(Invoke-CliRule 'AW-CLI-002' -Settings '{ "allowedUrls": ["docs.github.com", "*.github.com", "https://api.example.invalid/*"] }').Count
            Assert-Equal 0 @(Invoke-CliRule 'AW-CLI-002' -Repo '{ "allowedUrls": ["*"] }').Count
            Assert-Equal 0 @(Invoke-CliRule 'AW-CLI-002' -Config '{ "allowedUrls": ["*"] }').Count
            Assert-Equal 0 @(Invoke-CliRule 'AW-CLI-002' -Settings '{ "allowedUrls": "*", "deniedUrls": ["*"] }').Count
        }
    }

    Describe 'AW-CLI-003 repository hooks' {
        It 'flags command and http hooks of the repository settings' {
            $f = @(Invoke-CliRule 'AW-CLI-003' -Repo ([System.IO.File]::ReadAllText((Join-Path $area 'repo-hooks\.github\copilot\settings.json'))))
            Assert-Equal @('hook preToolUse command: ./scripts/check-tool.sh', 'hook sessionStart http: https://hooks.example.invalid/session') @($f | ForEach-Object { $_.Evidence })
            Assert-Equal 'hooks.preToolUse' $f[0].Location.Key
            Assert-Equal 4 $f[0].Location.Line
        }
        It 'reads every command field and both file shapes' {
            $repo = '{ "hooks": { "version": 1, "hooks": { "postToolUse": [ { "command": "npm run lint" }, { "type": "command", "powershell": "./x.ps1" }, { "exec": "./bin/check" },' +
                    ' { "matcher": "shell", "hooks": [ { "type": "command", "bash": "./y.sh" } ] }, { "type": "prompt", "prompt": "Review it" } ] } } }'
            $f = @(Invoke-CliRule 'AW-CLI-003' -Repo $repo)
            Assert-Equal 4 $f.Count
            Assert-Equal 'hook postToolUse command: npm run lint' $f[0].Evidence
        }
        It 'honors disableAllHooks with repository precedence' {
            $hooks = '"hooks": { "sessionStart": [ { "type": "command", "bash": "./start.sh" } ] }'
            Assert-Equal 0 @(Invoke-CliRule 'AW-CLI-003' -Repo ('{ "disableAllHooks": true, ' + $hooks + ' }')).Count
            Assert-Equal 0 @(Invoke-CliRule 'AW-CLI-003' -Repo ('{ ' + $hooks + ' }') -Settings '{ "disableAllHooks": true }').Count
            Assert-Equal 1 @(Invoke-CliRule 'AW-CLI-003' -Repo ('{ "disableAllHooks": false, ' + $hooks + ' }') -Settings '{ "disableAllHooks": true }').Count
        }
        It 'masks secrets in hook commands' {
            $f = @(Invoke-CliRule 'AW-CLI-003' -Repo '{ "hooks": { "sessionStart": [ { "type": "command", "bash": "TOKEN=FAKE-t1 ./start.sh --password FAKE-p2" } ] } }')
            Assert-Equal 1 $f.Count
            Assert-NotMatch $f[0].Evidence 'FAKE-t1|FAKE-p2'
        }
        It 'ignores user hooks and entries without a command' {
            Assert-Equal 0 @(Invoke-CliRule 'AW-CLI-003' -Settings '{ "hooks": { "sessionStart": [ { "type": "command", "bash": "./start.sh" } ] } }').Count
            Assert-Equal 0 @(Invoke-CliRule 'AW-CLI-003' -Repo '{ "hooks": { "sessionStart": [ { "type": "command", "bash": " " }, { "cwd": "." }, "./x.sh" ], "x": "y" } }').Count
            Assert-Equal 0 @(Invoke-CliRule 'AW-CLI-003' -Repo '{ "hooks": ["./x.sh"] }').Count
        }
    }

    Describe 'AW-CLI-004 plain-text token storage' {
        It 'flags storeTokenPlaintext = true in user settings' {
            $f = @(Invoke-CliRule 'AW-CLI-004' -Settings ('{|  "storeTokenPlaintext": true|}'.Replace('|', [Environment]::NewLine)))
            Assert-Equal 1 $f.Count
            Assert-Equal 'storeTokenPlaintext = true (user settings)' $f[0].Evidence
            Assert-Equal 2 $f[0].Location.Line
        }
        It 'is silent otherwise' {
            Assert-Equal 0 @(Invoke-CliRule 'AW-CLI-004' -Settings '{ "storeTokenPlaintext": false }').Count
            Assert-Equal 0 @(Invoke-CliRule 'AW-CLI-004' -Settings '{ "storeTokenPlaintext": "true" }').Count
            Assert-Equal 0 @(Invoke-CliRule 'AW-CLI-004' -Repo '{ "storeTokenPlaintext": true }').Count
            Assert-Equal 0 @(Invoke-CliRule 'AW-CLI-004' -Config '{ "storeTokenPlaintext": true }').Count
        }
    }

    Describe 'AW-CLI-005 allow-all mode not disabled' {
        It 'reports user settings without the lock' {
            $f = @(Invoke-CliRule 'AW-CLI-005' -Settings '{ "model": "auto" }')
            Assert-Equal 1 $f.Count
            Assert-Equal 'info' $f[0].Severity
            Assert-Equal 1 @(Invoke-CliRule 'AW-CLI-005' -Settings '{ "permissions": { "disableBypassPermissionsMode": "Disable" } }').Count
        }
        It 'is silent with the lock or without user settings' {
            Assert-Equal 0 @(Invoke-CliRule 'AW-CLI-005' -Settings '{ "permissions": { "disableBypassPermissionsMode": "disable" } }').Count
            Assert-Equal 0 @(Invoke-CliRule 'AW-CLI-005' -Settings '{ "permissions": { "disableBypassPermissionsMode": "allow-auto-only" } }').Count
            Assert-Equal 0 @(Invoke-CliRule 'AW-CLI-005' -Settings '{ "permissions.disableBypassPermissionsMode": "disable" }').Count
            Assert-Equal 0 @(Invoke-CliRule 'AW-CLI-005' -Repo '{ "model": "auto" }').Count
            Assert-Equal 0 @(Invoke-CliRule 'AW-CLI-005' -Config '{ "trusted_folders": [] }').Count
        }
    }

    Describe 'Copilot CLI rules: fixtures' {
        It 'reports the copilotcli/profile-insecure fixture' {
            $r = Invoke-Airworthy -Path (Join-Path $area 'repo-hooks') -UserProfilePath (Join-Path $area 'profile-insecure') -PassThru -Quiet
            $mine = @($r.Findings | Where-Object { $_.RuleId -like 'AW-CLI-*' })
            Assert-Contains $r.Harnesses 'copilot-cli'
            Assert-Equal @('AW-CLI-001', 'AW-CLI-001', 'AW-CLI-001', 'AW-CLI-002', 'AW-CLI-002', 'AW-CLI-003', 'AW-CLI-003', 'AW-CLI-004', 'AW-CLI-005') @($mine | ForEach-Object { $_.RuleId })
        }
        It 'masks the user name with -Redact' {
            $r = Invoke-Airworthy -Path (Join-Path $area 'repo-hooks') -UserProfilePath (Join-Path $area 'profile-insecure') -Redact -PassThru -Quiet
            $f = @($r.Findings | Where-Object { $_.RuleId -eq 'AW-CLI-004' })[0]
            Assert-Equal '~\.copilot\settings.json' $f.Location.Path
        }
        It 'reports only the repository hooks with the hardened profile' {
            $r = Invoke-Airworthy -Path (Join-Path $area 'repo-hooks') -UserProfilePath (Join-Path $area 'profile-hardened') -PassThru -Quiet
            Assert-Equal @('AW-CLI-003', 'AW-CLI-003') @($r.Findings | Where-Object { $_.RuleId -like 'AW-CLI-*' } | ForEach-Object { $_.RuleId })
        }
        It 'is silent on the shared fixtures without a user profile' {
            foreach ($name in @('insecure', 'hardened', 'mixed')) {
                $r = Invoke-Airworthy -Path (Join-Path $fixtures $name) -NoUserProfile -PassThru -Quiet
                Assert-Equal 0 @($r.Findings | Where-Object { $_.RuleId -like 'AW-CLI-*' }).Count $name
            }
        }
        It 'runs through the engine without a rule failure' {
            $r = Invoke-Airworthy -Path (Join-Path $area 'repo-hooks') -UserProfilePath (Join-Path $area 'profile-insecure') -PassThru -Quiet
            Assert-Equal 0 @($r.Findings | Where-Object { $_.RuleId -eq 'AW-CORE-002' -and $_.Location.Key -like 'AW-CLI-*' }).Count
        }
    }
} finally {
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force }
}
