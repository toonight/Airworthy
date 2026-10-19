# Tests for src/Rules/VSCode.Settings.ps1 (AW-VSC-*). Every rule has positive and negative tests,
# recorded in $coverage and checked at the end. Fixtures live in tests/fixtures/vscode/.
$aw = Get-Module Airworthy
$fixtures = Join-Path $PSScriptRoot 'fixtures'
$vsc = Join-Path $fixtures 'vscode'
$layersUser = Join-Path $vsc 'layers-user\settings.json'
$tmp = Join-Path $vsc ('_tmp-' + [guid]::NewGuid().ToString('N'))
$coverage = @{}
# Expected command names live in a JSON fixture, not in this script (CONTRIBUTING.md, Antivirus hygiene).
$expected = & $aw { param($p) ConvertFrom-AwJsonc -Text ([System.IO.File]::ReadAllText($p)) } (Join-Path $vsc 'expectations.json')

function Get-VscContext {
    # Context for a fixture folder (never the real user profile). -OnWindows forces the host OS.
    param([string]$Name, [string]$UserSettings, $OnWindows)
    $ctx = & $aw {
        param($p, $u)
        if ($u) { New-AwContext -Path $p -NoUserProfile -UserSettingsPath $u } else { New-AwContext -Path $p -NoUserProfile }
    } (Join-Path $vsc $Name) $UserSettings
    if ($null -ne $OnWindows) { $ctx.IsWindows = [bool]$OnWindows }
    return $ctx
}

function Invoke-VscRule {
    param([string]$Id, $Ctx)
    $out = & $aw {
        param($id, $c)
        $rule = $script:AwRules[$id]
        if ($null -eq $rule) { throw "Rule $id is not registered." }
        @(& $rule.Check $c)
    } $Id $Ctx
    return ,@($out | Where-Object { $null -ne $_ })
}

function Assert-VscFires {
    # Runs one rule and checks that it fires (optionally: count and severity of every finding).
    param([string]$Id, $Ctx, [int]$Count = 0, [string]$Severity)
    $coverage["$Id+"] = $true
    $f = Invoke-VscRule $Id $Ctx
    Assert-True ($f.Count -gt 0) "$Id should fire"
    if ($Count -gt 0) { Assert-Equal $Count $f.Count "$Id finding count" }
    foreach ($x in $f) {
        Assert-Equal $Id $x.RuleId
        if ($Severity) { Assert-Equal $Severity $x.Severity "$Id severity ($($x.Evidence))" }
    }
    return ,$f
}

function Assert-VscSilent {
    param([string]$Id, $Ctx)
    $coverage["$Id-"] = $true
    $f = Invoke-VscRule $Id $Ctx
    Assert-Equal 0 $f.Count ("$Id should not fire: " + (@($f | ForEach-Object { $_.Evidence }) -join ' | '))
}

function Get-FixtureLine([string]$File, [string]$Needle) {
    $m = Select-String -LiteralPath $File -SimpleMatch -Pattern $Needle | Select-Object -First 1
    if ($m) { return $m.LineNumber }
    return $null
}

function Select-Evidence($Findings, [string]$Text) {
    return ,@($Findings | Where-Object { $_.Evidence.Contains($Text) })
}

function New-VscCase {
    # A temporary workspace whose .vscode/settings.json holds Settings (removed by the line lookup tests).
    param([string]$Settings)
    $root = Join-Path $tmp ([guid]::NewGuid().ToString('N').Substring(0, 12))
    $dir = Join-Path $root '.vscode'
    [void][System.IO.Directory]::CreateDirectory($dir)
    [System.IO.File]::WriteAllText((Join-Path $dir 'settings.json'), $Settings, (New-Object System.Text.UTF8Encoding($false)))
    return $root
}

function Invoke-VscScan {
    param([string]$Path, [string]$UserProfilePath, [switch]$Redact)
    if ($UserProfilePath) { return Invoke-Airworthy -Path $Path -UserProfilePath $UserProfilePath -Redact:$Redact -PassThru -Quiet }
    return Invoke-Airworthy -Path $Path -NoUserProfile -Redact:$Redact -PassThru -Quiet
}

Describe 'AW-VSC rule metadata' {
    $rules = @(& $aw { Get-AwRules } | Where-Object { $_.Id -like 'AW-VSC-*' })

    It 'registers at least 20 VS Code rules, all for the vscode-copilot harness' {
        Assert-True ($rules.Count -ge 20) "only $($rules.Count) rules"
        foreach ($r in $rules) { Assert-Equal 'vscode-copilot' $r.Harness $r.Id }
    }

    It 'maps every rule to an OWASP ASI reference and an official documentation URL' {
        foreach ($r in $rules) {
            Assert-True (@($r.References | Where-Object { $_ -cmatch '^OWASP-ASI(0[1-9]|10)$' }).Count -gt 0) "$($r.Id) has no OWASP ASI reference"
            $official = @($r.References | Where-Object { $_ -match '^https://(code\.visualstudio\.com|docs\.github\.com)/' })
            Assert-True ($official.Count -gt 0) "$($r.Id) has no official documentation URL"
        }
    }

    It 'gives every rule a description and a concrete fix' {
        foreach ($r in $rules) {
            Assert-True ($r.Description.Length -gt 60) "$($r.Id) description"
            Assert-Match $r.Fix '"[a-z/*]' "$($r.Id) fix should give a concrete value"
        }
    }

    It 'explains what is uncertain in every medium-confidence rule' {
        foreach ($r in @($rules | Where-Object { $_.Confidence -eq 'medium' })) {
            Assert-Match $r.Description 'Confidence is medium' $r.Id
        }
        Assert-True (@($rules | Where-Object { $_.Confidence -eq 'medium' }).Count -ge 5)
    }

    It 'loads its command tokens from src/Data/vscode.json, with no URL or payload in the probes' {
        $d = & $aw { @{ Risky = $script:AwVscRiskyCommands; Exfil = $script:AwVscExfilCommands; Probes = $script:AwVscProbeCommands } }
        Assert-True ($d.Risky.Count -ge 15) "only $($d.Risky.Count) risky commands"
        Assert-True (@($d.Exfil).Count -ge 8) 'approval-required commands'
        foreach ($name in $d.Exfil) { Assert-True $d.Risky.Contains($name) $name }
        foreach ($name in $d.Risky.Keys) {
            foreach ($line in $d.Risky[$name]) { Assert-Match $line '^[A-Za-z0-9.-]+( [A-Za-z0-9.-]+)* awprobe$' "$name probe" }
        }
        Assert-Equal 2 @($d.Probes).Count
    }
}

Describe 'AW-VSC-001 global auto-approval' {
    It 'fires (critical) with the workspace file, line and source' {
        $f = Assert-VscFires 'AW-VSC-001' (Get-VscContext 'approvals-risky') -Count 1 -Severity 'critical'
        $file = Join-Path $vsc 'approvals-risky\.vscode\settings.json'
        Assert-Equal $file $f[0].Location.Path
        Assert-Equal (Get-FixtureLine $file '"chat.tools.global.autoApprove"') $f[0].Location.Line
        Assert-Equal 'chat.tools.global.autoApprove' $f[0].Location.Key
        Assert-Match $f[0].Evidence '^chat\.tools\.global\.autoApprove = true \(set in workspace settings \.vscode\\settings\.json\)$'
    }
    It 'fires from the user layer and points at the user settings file' {
        $f = Assert-VscFires 'AW-VSC-001' (Get-VscContext 'layers' -UserSettings $layersUser) -Count 1
        Assert-Equal $layersUser $f[0].Location.Path
        Assert-Equal (Get-FixtureLine $layersUser '"chat.tools.global.autoApprove"') $f[0].Location.Line
        Assert-Match $f[0].Evidence 'set in user settings'
    }
    It 'stays silent on defaults and ignores a non-boolean value' {
        Assert-VscSilent 'AW-VSC-001' (Get-VscContext 'defaults')
        Assert-VscSilent 'AW-VSC-001' (Get-VscContext 'hostile')
    }
}

Describe 'AW-VSC-002 default permission level' {
    It 'fires for autopilot and for Allow all' {
        $f = Assert-VscFires 'AW-VSC-002' (Get-VscContext 'approvals-risky') -Count 1 -Severity 'high'
        Assert-Match $f[0].Evidence 'Autopilot'
        $ctx = & $aw { param($p) New-AwContext -Path $p -NoUserProfile } (Join-Path $fixtures 'insecure')
        $f = Assert-VscFires 'AW-VSC-002' $ctx -Count 1
        Assert-Match $f[0].Evidence '"autoApprove"; Allow all'
    }
    It 'stays silent on defaults and on an invalid value' {
        Assert-VscSilent 'AW-VSC-002' (Get-VscContext 'defaults')
        Assert-VscSilent 'AW-VSC-002' (Get-VscContext 'hostile')
    }
}

Describe 'AW-VSC-003 terminal auto-approval' {
    It 'is critical on Windows when the sandbox is off, even with default values' {
        $f = Assert-VscFires 'AW-VSC-003' (Get-VscContext 'defaults' -OnWindows $true) -Count 1 -Severity 'critical'
        Assert-Match $f[0].Evidence 'Windows host'
        Assert-Match $f[0].Evidence 'default value, not set in any settings file'
        Assert-Equal (Join-Path $vsc 'defaults\.vscode\settings.json') $f[0].Location.Path
        Assert-Equal $null $f[0].Location.Line
    }
    It 'is high on another OS with only built-in rules' {
        Assert-VscFires 'AW-VSC-003' (Get-VscContext 'defaults' -OnWindows $false) -Severity 'high' | Out-Null
    }
    It 'is critical with a catch-all rule, whatever the OS' {
        $f = Assert-VscFires 'AW-VSC-003' (Get-VscContext 'terminal-catchall' -OnWindows $false) -Severity 'critical'
        Assert-Match $f[0].Evidence "catch-all allow rule '/\.\*/'"
    }
    It 'is high on Windows when the sandbox is on and rules are not catch-all' {
        Assert-VscFires 'AW-VSC-003' (Get-VscContext 'terminal-broad' -OnWindows $true) -Severity 'high' | Out-Null
    }
    It 'stays silent when terminal auto-approval is disabled' {
        Assert-VscSilent 'AW-VSC-003' (Get-VscContext 'terminal-off' -OnWindows $true)
    }
}

Describe 'AW-VSC-004 catch-all and broad terminal rules' {
    It 'reports a catch-all regex as critical, on its own line' {
        $f = Assert-VscFires 'AW-VSC-004' (Get-VscContext 'terminal-catchall') -Count 1 -Severity 'critical'
        Assert-Equal (Get-FixtureLine (Join-Path $vsc 'terminal-catchall\.vscode\settings.json') '"/.*/"') $f[0].Location.Line
    }
    It 'reports a broad regex as high' {
        $f = Assert-VscFires 'AW-VSC-004' (Get-VscContext 'terminal-broad') -Count 1 -Severity 'high'
        Assert-Equal 'Broad terminal allow rule' $f[0].Title
    }
    It 'stays silent with narrow rules or when auto-approval is off' {
        Assert-VscSilent 'AW-VSC-004' (Get-VscContext 'approvals-risky')
        Assert-VscSilent 'AW-VSC-004' (Get-VscContext 'hardened-terminal')
        Assert-VscSilent 'AW-VSC-004' (Get-VscContext 'terminal-off')
    }
}

Describe 'AW-VSC-005 risky commands auto-approved' {
    It 'reports every risky allow rule, including the object form' {
        $exp = $expected['approvalsRisky']
        Assert-Equal 11 @($exp['riskyAllowKeys']).Count
        $f = Assert-VscFires 'AW-VSC-005' (Get-VscContext 'approvals-risky') -Count 11 -Severity 'high'
        foreach ($k in @($exp['riskyAllowKeys'])) {
            Assert-Equal 1 (Select-Evidence $f ('autoApprove "' + $k + '"')).Count "missing $k"
        }
        Assert-True ((Select-Evidence $f '"powershell"')[0].Evidence.Contains("'" + $exp['powershellLabel'] + "'")) 'powershell label'
        Assert-Equal 0 (Select-Evidence $f '"ls"').Count
        $file = Join-Path $vsc 'approvals-risky\.vscode\settings.json'
        Assert-Equal (Get-FixtureLine $file '"git push"') (Select-Evidence $f '"git push"')[0].Location.Line
    }
    It 'follows the layer that set each entry (user and nested workspace notation)' {
        $f = Assert-VscFires 'AW-VSC-005' (Get-VscContext 'layers' -UserSettings $layersUser) -Count 2
        $npx = (Select-Evidence $f '"npx"')[0]
        Assert-Equal $layersUser $npx.Location.Path
        $push = (Select-Evidence $f '"git push"')[0]
        $ws = Join-Path $vsc 'layers\.vscode\settings.json'
        Assert-Equal $ws $push.Location.Path
        Assert-Equal (Get-FixtureLine $ws '"git push"') $push.Location.Line
    }
    It 'lets a false rule take precedence, and leaves catch-all and broad rules to AW-VSC-004' {
        Assert-VscSilent 'AW-VSC-005' (Get-VscContext 'hardened-terminal')
        Assert-VscSilent 'AW-VSC-005' (Get-VscContext 'terminal-catchall')
        Assert-VscSilent 'AW-VSC-005' (Get-VscContext 'terminal-broad')
        Assert-VscSilent 'AW-VSC-005' (Get-VscContext 'terminal-off')
    }
}

Describe 'AW-VSC-006 missing approval-required rules' {
    It 'is medium with custom allow rules and says that false does not block' {
        $f = Assert-VscFires 'AW-VSC-006' (Get-VscContext 'approvals-risky') -Count 1 -Severity 'medium'
        foreach ($name in @($expected['approvalsRisky']['missingApproval'])) {
            Assert-True ($f[0].Evidence.Contains("'" + $name + "'")) "missing $name"
        }
        Assert-Match $f[0].Evidence 'only forces approval, it does not block'
        Assert-Match $f[0].Description 'FORCES APPROVAL'
    }
    It 'is low with the built-in rules only' {
        Assert-VscFires 'AW-VSC-006' (Get-VscContext 'defaults') -Severity 'low' | Out-Null
    }
    It 'stays silent when every command has a false entry, or auto-approval is off' {
        Assert-VscSilent 'AW-VSC-006' (Get-VscContext 'hardened-terminal')
        Assert-VscSilent 'AW-VSC-006' (Get-VscContext 'terminal-off')
    }
}

Describe 'AW-VSC-007 built-in rules ignored' {
    It 'fires while auto-approval is on' {
        Assert-VscFires 'AW-VSC-007' (Get-VscContext 'approvals-risky') -Count 1 -Severity 'high' | Out-Null
    }
    It 'stays silent on defaults and when auto-approval is off' {
        Assert-VscSilent 'AW-VSC-007' (Get-VscContext 'defaults')
        Assert-VscSilent 'AW-VSC-007' (Get-VscContext 'terminal-off')
    }
}

Describe 'AW-VSC-008 automatic replies to terminal prompts' {
    It 'fires when enabled' {
        Assert-VscFires 'AW-VSC-008' (Get-VscContext 'approvals-risky') -Count 1 -Severity 'medium' | Out-Null
    }
    It 'stays silent on defaults and when disabled' {
        Assert-VscSilent 'AW-VSC-008' (Get-VscContext 'defaults')
        Assert-VscSilent 'AW-VSC-008' (Get-VscContext 'hardened-terminal')
    }
}

Describe 'AW-VSC-009 edit auto-approval of control files' {
    It 'reports each true pattern that covers control files, honoring false entries' {
        $f = Assert-VscFires 'AW-VSC-009' (Get-VscContext 'edits-control') -Count 2 -Severity 'high'
        $md = (Select-Evidence $f '"**/*.md"')[0]
        Assert-Match $md.Evidence 'copilot-instructions\.md'
        Assert-Match $md.Evidence "'AGENTS\.md'"
        Assert-NotMatch $md.Evidence 'reviewer\.agent\.md'
        Assert-Match (Select-Evidence $f '".github/workflows/**"')[0].Evidence 'ci\.yml'
        Assert-Equal 0 (Select-Evidence $f '"src/**"').Count
    }
    It 'reports a broad pattern as high when control files are exposed' {
        $ctx = & $aw { param($p) New-AwContext -Path $p -NoUserProfile } (Join-Path $fixtures 'insecure')
        $f = Assert-VscFires 'AW-VSC-009' $ctx -Count 1 -Severity 'high'
        Assert-Match $f[0].Evidence 'broad pattern'
    }
    It 'reports a broad pattern as medium when every control file is protected' {
        $f = Assert-VscFires 'AW-VSC-009' (Get-VscContext 'edits-broad') -Count 1 -Severity 'medium'
        Assert-Equal 'Broad edit auto-approval pattern' $f[0].Title
    }
    It 'stays silent on narrow patterns and on defaults' {
        Assert-VscSilent 'AW-VSC-009' (Get-VscContext 'edits-safe')
        Assert-VscSilent 'AW-VSC-009' (Get-VscContext 'defaults')
    }
    It 'converts globs like VS Code (** spans folders, * stays in one segment)' {
        $m = & $aw {
            $t = { param($g, $p) $rx = ConvertTo-AwVscGlobRegex $g; [bool]($rx -and $rx.IsMatch($p)) }
            @((& $t '**/.vscode/**' '.vscode/settings.json'), (& $t '**/.vscode/**' 'a/b/.vscode/x.json'),
              (& $t '*' 'src/a.txt'), (& $t '*.{md,txt}' 'README.md'), (& $t '.github/workflows/**' '.github/workflows/ci.yml'),
              (& $t '**/.env*' 'pkg/.env.local'), (& $t 'src/**' 'docs/a.md'), (& $t '{a,b' 'a'))
        }
        Assert-Equal @($true, $true, $false, $true, $true, $true, $false, $false) $m
    }
}

Describe 'AW-VSC-010 wildcard URL auto-approval' {
    It 'grades any-host, subdomain and path wildcards' {
        $f = Assert-VscFires 'AW-VSC-010' (Get-VscContext 'urls') -Count 4
        Assert-Equal 'high' (Select-Evidence $f '"https://*" ')[0].Severity
        Assert-Equal 'medium' (Select-Evidence $f '"https://*.example.com/*"')[0].Severity
        Assert-Match (Select-Evidence $f '"https://*.example.com/*"')[0].Evidence 'auto-approves requests for'
        Assert-Equal 'low' (Select-Evidence $f '"https://docs.example.com/*"')[0].Severity
        $io = (Select-Evidence $f '"*.io"')[0]
        Assert-Equal 'high' $io.Severity
        Assert-Match $io.Evidence 'auto-approves responses'
        Assert-Equal 0 (Select-Evidence $f 'exact.example.com').Count
        Assert-Equal 0 (Select-Evidence $f 'blocked').Count
    }
    It 'handles the array form' {
        $f = Assert-VscFires 'AW-VSC-010' (Get-VscContext 'urls-array') -Count 1 -Severity 'high'
        Assert-Match $f[0].Evidence '"\*" auto-approves requests and responses for any host'
    }
    It 'locates an entry set in a .code-workspace file' {
        $f = Assert-VscFires 'AW-VSC-010' (Get-VscContext 'layers') -Count 1
        $wf = Join-Path $vsc 'layers\layers.code-workspace'
        Assert-Equal $wf $f[0].Location.Path
        Assert-Equal (Get-FixtureLine $wf '"https://*"') $f[0].Location.Line
        Assert-Match $f[0].Evidence 'set in workspace file layers\.code-workspace'
    }
    It 'stays silent on defaults and on an invalid value' {
        Assert-VscSilent 'AW-VSC-010' (Get-VscContext 'defaults')
        Assert-VscSilent 'AW-VSC-010' (Get-VscContext 'hostile')
    }
}

Describe 'AW-VSC-011 risk assessment' {
    It 'fires (low) when disabled and says it is not a boundary' {
        $f = Assert-VscFires 'AW-VSC-011' (Get-VscContext 'approvals-risky') -Count 1 -Severity 'low'
        Assert-Match $f[0].Description 'NOT a security boundary'
    }
    It 'stays silent on defaults and when enabled' {
        Assert-VscSilent 'AW-VSC-011' (Get-VscContext 'defaults')
        Assert-VscSilent 'AW-VSC-011' (Get-VscContext 'hardened-terminal')
    }
}

Describe 'AW-VSC-012 sandbox disabled' {
    It 'fires on the default value, with the Windows note on Windows' {
        $f = Assert-VscFires 'AW-VSC-012' (Get-VscContext 'defaults' -OnWindows $true) -Count 1 -Severity 'high'
        Assert-Match $f[0].Evidence '^chat\.agent\.sandbox\.enabled = "off"; Windows host'
        $f = Assert-VscFires 'AW-VSC-012' (Get-VscContext 'defaults' -OnWindows $false) -Count 1
        Assert-NotMatch $f[0].Evidence 'Windows'
    }
    It 'treats an invalid value as off' {
        Assert-VscFires 'AW-VSC-012' (Get-VscContext 'hostile') -Count 1 | Out-Null
    }
    It 'stays silent when the sandbox is on' {
        Assert-VscSilent 'AW-VSC-012' (Get-VscContext 'hardened-terminal')
        Assert-VscSilent 'AW-VSC-012' (Get-VscContext 'sandbox-open')
    }
}

Describe 'AW-VSC-013 unrestricted network egress' {
    It 'fires with open network, no filter and no allowed domains' {
        $f = Assert-VscFires 'AW-VSC-013' (Get-VscContext 'sandbox-open') -Count 1 -Severity 'medium'
        Assert-Match $f[0].Evidence 'sandbox on'
        Assert-VscFires 'AW-VSC-013' (Get-VscContext 'defaults') -Count 1 | Out-Null
    }
    It 'stays silent when egress is off, filtered, or limited to domains' {
        Assert-VscSilent 'AW-VSC-013' (Get-VscContext 'hardened-terminal')
        Assert-VscSilent 'AW-VSC-013' (Get-VscContext 'misc-safe')
        Assert-VscSilent 'AW-VSC-013' (Get-VscContext 'sandbox-domains')
    }
}

Describe 'AW-VSC-014 unsandboxed commands' {
    It 'fires when the sandbox is on and the escape is allowed' {
        Assert-VscFires 'AW-VSC-014' (Get-VscContext 'sandbox-open') -Count 1 -Severity 'medium' | Out-Null
    }
    It 'stays silent when disallowed, or when the sandbox is off' {
        Assert-VscSilent 'AW-VSC-014' (Get-VscContext 'hardened-terminal')
        Assert-VscSilent 'AW-VSC-014' (Get-VscContext 'defaults')
    }
}

Describe 'AW-VSC-015 developer-tool access' {
    It 'fires when the sandbox is on and access is granted' {
        Assert-VscFires 'AW-VSC-015' (Get-VscContext 'sandbox-open') -Count 1 -Severity 'medium' | Out-Null
    }
    It 'stays silent when access is off, or when the sandbox is off' {
        Assert-VscSilent 'AW-VSC-015' (Get-VscContext 'sandbox-domains')
        Assert-VscSilent 'AW-VSC-015' (Get-VscContext 'defaults')
    }
}

Describe 'AW-VSC-016 credentials in the sandbox' {
    It 'reports git and gh credentials separately' {
        $f = Assert-VscFires 'AW-VSC-016' (Get-VscContext 'sandbox-open') -Count 2 -Severity 'medium'
        Assert-Equal 1 (Select-Evidence $f 'authenticategit = true').Count
        Assert-Equal 1 (Select-Evidence $f 'authenticategh = true').Count
    }
    It 'stays silent when both are off, or when the sandbox is off' {
        Assert-VscSilent 'AW-VSC-016' (Get-VscContext 'hardened-terminal')
        Assert-VscSilent 'AW-VSC-016' (Get-VscContext 'defaults')
    }
}

Describe 'AW-VSC-017 credential folders not denied' {
    It 'is medium with developer-tool access and lists every missing folder' {
        $f = Assert-VscFires 'AW-VSC-017' (Get-VscContext 'sandbox-open') -Count 1 -Severity 'medium'
        foreach ($label in @('~/.ssh', '~/.aws', '~/.azure', 'GitHub CLI config')) { Assert-Match $f[0].Evidence ([regex]::Escape("'$label'")) }
    }
    It 'is low without developer-tool access and omits denied folders' {
        $f = Assert-VscFires 'AW-VSC-017' (Get-VscContext 'sandbox-domains') -Count 1 -Severity 'low'
        Assert-NotMatch $f[0].Evidence '~/\.ssh'
        Assert-Match $f[0].Evidence '~/\.aws'
    }
    It 'stays silent when every folder is denied (~, %USERPROFILE% and %APPDATA% forms), or the sandbox is off' {
        Assert-VscSilent 'AW-VSC-017' (Get-VscContext 'hardened-terminal')
        Assert-VscSilent 'AW-VSC-017' (Get-VscContext 'defaults')
    }
    It 'normalizes home folder spellings' {
        $p = & $aw {
            $c = [pscustomobject]@{ UserProfile = 'C:\Users\fake-user' }
            @((ConvertTo-AwVscHomePath '%USERPROFILE%\.aws' $c), (ConvertTo-AwVscHomePath 'C:\Users\fake-user\.ssh\' $c),
              (ConvertTo-AwVscHomePath '/home/fake/.azure' $c), (ConvertTo-AwVscHomePath '$HOME/.config/gh' $c),
              (ConvertTo-AwVscHomePath '%APPDATA%\GitHub CLI' $c))
        }
        Assert-Equal @('~/.aws', '~/.ssh', '~/.azure', '~/.config/gh', '~/appdata/roaming/github cli') $p
    }
}

Describe 'AW-VSC-018 sandbox auto-approval with open network' {
    It 'is high with open egress and medium with allowed domains' {
        Assert-VscFires 'AW-VSC-018' (Get-VscContext 'sandbox-open') -Count 1 -Severity 'high' | Out-Null
        $f = Assert-VscFires 'AW-VSC-018' (Get-VscContext 'sandbox-domains') -Count 1 -Severity 'medium'
        Assert-Match $f[0].Evidence 'allowedDomains'
    }
    It 'stays silent when either side is closed, or the sandbox is off' {
        Assert-VscSilent 'AW-VSC-018' (Get-VscContext 'hardened-terminal')
        Assert-VscSilent 'AW-VSC-018' (Get-VscContext 'defaults')
    }
}

Describe 'AW-VSC-019 read access outside the workspace' {
    It 'is high for a drive root and medium for a specific folder' {
        $f = Assert-VscFires 'AW-VSC-019' (Get-VscContext 'misc-risky') -Count 1 -Severity 'high'
        Assert-Match $f[0].Evidence "drive root or the home folder: 'C:/'"
        Assert-VscFires 'AW-VSC-019' (Get-VscContext 'sandbox-domains') -Count 1 -Severity 'medium' | Out-Null
    }
    It 'stays silent when empty or invalid' {
        Assert-VscSilent 'AW-VSC-019' (Get-VscContext 'misc-safe')
        Assert-VscSilent 'AW-VSC-019' (Get-VscContext 'hostile')
    }
}

Describe 'AW-VSC-020 agent request limit' {
    It 'is low above 100 and medium from 1000' {
        Assert-VscFires 'AW-VSC-020' (Get-VscContext 'approvals-risky') -Count 1 -Severity 'low' | Out-Null
        Assert-VscFires 'AW-VSC-020' (Get-VscContext 'misc-risky') -Count 1 -Severity 'medium' | Out-Null
    }
    It 'stays silent at 100, when a workspace value overrides the user value, and for a string' {
        Assert-VscSilent 'AW-VSC-020' (Get-VscContext 'misc-safe')
        Assert-VscSilent 'AW-VSC-020' (Get-VscContext 'layers' -UserSettings $layersUser)
        Assert-VscSilent 'AW-VSC-020' (Get-VscContext 'hostile')
    }
}

Describe 'AW-VSC-021 MCP discovery' {
    It 'fires for true and for the per-application object form' {
        Assert-VscFires 'AW-VSC-021' (Get-VscContext 'misc-risky') -Count 1 -Severity 'medium' | Out-Null
        Assert-VscFires 'AW-VSC-021' (Get-VscContext 'mcp-objects') -Count 1 | Out-Null
    }
    It 'stays silent when off or invalid' {
        Assert-VscSilent 'AW-VSC-021' (Get-VscContext 'misc-safe')
        Assert-VscSilent 'AW-VSC-021' (Get-VscContext 'hostile')
    }
}

Describe 'AW-VSC-022 MCP autostart' {
    It 'fires when servers are configured and autostart is not never' {
        $f = Assert-VscFires 'AW-VSC-022' (Get-VscContext 'misc-risky') -Count 1 -Severity 'low'
        Assert-Match $f[0].Evidence '1 MCP server\(s\) in \.vscode\\mcp\.json'
        $f = Assert-VscFires 'AW-VSC-022' (Get-VscContext 'mcp-objects') -Count 1
        Assert-Match $f[0].Evidence '"newAndOutdated"; 2 MCP server'
    }
    It 'stays silent with never, or without any MCP server' {
        Assert-VscSilent 'AW-VSC-022' (Get-VscContext 'misc-safe')
        Assert-VscSilent 'AW-VSC-022' (Get-VscContext 'defaults')
    }
}

Describe 'AW-VSC-023 MCP sampling' {
    It 'fires for a server allowed to sample any model' {
        $f = Assert-VscFires 'AW-VSC-023' (Get-VscContext 'misc-risky') -Count 1 -Severity 'medium'
        Assert-Match $f[0].Evidence '"Workspace: docs" may request completions from any model'
    }
    It 'stays silent when empty, without models, or invalid' {
        Assert-VscSilent 'AW-VSC-023' (Get-VscContext 'misc-safe')
        Assert-VscSilent 'AW-VSC-023' (Get-VscContext 'mcp-objects')
        Assert-VscSilent 'AW-VSC-023' (Get-VscContext 'hostile')
    }
}

Describe 'AW-VSC-024 OpenTelemetry disabled' {
    It 'fires (low, observability) on the default and when set to false' {
        $f = Assert-VscFires 'AW-VSC-024' (Get-VscContext 'defaults') -Count 1 -Severity 'low'
        Assert-Equal 'observability' $f[0].Category
        Assert-VscFires 'AW-VSC-024' (Get-VscContext 'otel-capture-off') -Count 1 | Out-Null
    }
    It 'stays silent when enabled' {
        Assert-VscSilent 'AW-VSC-024' (Get-VscContext 'misc-safe')
    }
}

Describe 'AW-VSC-025 prompt content in telemetry' {
    It 'is high with a remote collector and medium with a local one' {
        $f = Assert-VscFires 'AW-VSC-025' (Get-VscContext 'misc-risky') -Count 1 -Severity 'high'
        Assert-Match $f[0].Evidence 'collector https://collector\.example\.invalid:4318 is not a local address'
        Assert-VscFires 'AW-VSC-025' (Get-VscContext 'otel-local') -Count 1 -Severity 'medium' | Out-Null
    }
    It 'stays silent when capture is off, or OpenTelemetry is off' {
        Assert-VscSilent 'AW-VSC-025' (Get-VscContext 'misc-safe')
        Assert-VscSilent 'AW-VSC-025' (Get-VscContext 'otel-capture-off')
    }
}

Describe 'AW-VSC-026 Workspace Trust disabled' {
    It 'fires when explicitly false' {
        Assert-VscFires 'AW-VSC-026' (Get-VscContext 'misc-risky') -Count 1 -Severity 'high' | Out-Null
    }
    It 'stays silent when true, absent or not a boolean' {
        Assert-VscSilent 'AW-VSC-026' (Get-VscContext 'misc-safe')
        Assert-VscSilent 'AW-VSC-026' (Get-VscContext 'defaults')
        Assert-VscSilent 'AW-VSC-026' (Get-VscContext 'hostile')
    }
}

Describe 'AW-VSC-027 repository hook files' {
    It 'is high for workspace and Claude hook files when Workspace Trust is off' {
        $f = Assert-VscFires 'AW-VSC-027' (Get-VscContext 'misc-risky') -Count 2 -Severity 'high'
        $planted = (Select-Evidence $f 'planted.json')[0]
        Assert-Match $planted.Evidence 'chat\.useHooks = true \(default\); workspace hook file \.github\\hooks\\planted\.json runs commands on: preToolUse \(1\), sessionStart \(1\); Workspace Trust is disabled'
        Assert-Equal (Join-Path $vsc 'misc-risky\.github\hooks\planted.json') $planted.Location.Path
        Assert-Equal 3 $planted.Location.Line
        Assert-Match (Select-Evidence $f 'settings.json')[0].Evidence 'chat\.useClaudeHooks = true.*PreToolUse \(1\)'
    }
    It 'is medium otherwise, and skips empty or invalid hook files and Claude hooks by default' {
        $f = Assert-VscFires 'AW-VSC-027' (Get-VscContext 'hooks-trusted') -Count 1 -Severity 'medium'
        Assert-Match $f[0].Evidence 'format\.json'
    }
    It 'stays silent when hooks are disabled or absent' {
        Assert-VscSilent 'AW-VSC-027' (Get-VscContext 'misc-safe')
        Assert-VscSilent 'AW-VSC-027' (Get-VscContext 'defaults')
    }
}

Describe 'AW-VSC robustness' {
    It 'runs every rule on hostile values without throwing' {
        $ctx = Get-VscContext 'hostile'
        foreach ($r in @(& $aw { Get-AwRules } | Where-Object { $_.Id -like 'AW-VSC-*' })) {
            try { Invoke-VscRule $r.Id $ctx | Out-Null } catch { throw "$($r.Id) threw: $($_.Exception.Message)" }
        }
    }
    It 'never produces a rule failure (AW-CORE-002) for the VS Code rules' {
        foreach ($name in @('hostile', 'approvals-risky', 'misc-risky', 'sandbox-open', 'layers', 'hooks-trusted')) {
            $r = Invoke-VscScan -Path (Join-Path $vsc $name)
            $fail = @($r.Findings | Where-Object { $_.RuleId -eq 'AW-CORE-002' -and "$($_.Title) $($_.Location.Key)" -match 'AW-VSC' })
            Assert-Equal 0 $fail.Count ("$name : " + (@($fail | ForEach-Object { $_.Evidence }) -join ' | '))
        }
    }
    It 'keeps evidence short and treats markup in keys as plain text' {
        $f = Invoke-VscRule 'AW-VSC-005' (Get-VscContext 'hostile')
        Assert-Equal 0 $f.Count
        foreach ($name in @('approvals-risky', 'edits-control', 'insecure')) {
            $path = if ($name -eq 'insecure') { Join-Path $fixtures 'insecure' } else { Join-Path $vsc $name }
            foreach ($x in @((Invoke-VscScan -Path $path).Findings | Where-Object { $_.RuleId -like 'AW-VSC-*' })) {
                Assert-True ($x.Evidence.Length -le 600) "$($x.RuleId) evidence is $($x.Evidence.Length) chars"
            }
        }
    }
    It 'is deterministic' {
        $a = @((Invoke-VscScan -Path (Join-Path $fixtures 'insecure')).Findings | Where-Object { $_.RuleId -like 'AW-VSC-*' } | ForEach-Object { "$($_.RuleId)|$($_.Severity)|$($_.Location.Line)|$($_.Evidence)" })
        $b = @((Invoke-VscScan -Path (Join-Path $fixtures 'insecure')).Findings | Where-Object { $_.RuleId -like 'AW-VSC-*' } | ForEach-Object { "$($_.RuleId)|$($_.Severity)|$($_.Location.Line)|$($_.Evidence)" })
        Assert-Equal $a $b
    }
}

Describe 'AW-VSC end-to-end on the shared fixtures' {
    It 'flags the insecure fixture broadly' {
        $ids = @((Invoke-VscScan -Path (Join-Path $fixtures 'insecure')).Findings | ForEach-Object { $_.RuleId } | Sort-Object -Unique)
        foreach ($id in @('AW-VSC-001', 'AW-VSC-002', 'AW-VSC-003', 'AW-VSC-004', 'AW-VSC-005', 'AW-VSC-006', 'AW-VSC-007', 'AW-VSC-008',
                          'AW-VSC-009', 'AW-VSC-010', 'AW-VSC-011', 'AW-VSC-012', 'AW-VSC-013', 'AW-VSC-019', 'AW-VSC-020',
                          'AW-VSC-021', 'AW-VSC-022', 'AW-VSC-023', 'AW-VSC-025')) {
            Assert-Contains $ids $id
        }
    }
    It 'raises nothing above medium on the hardened fixture' {
        $f = @((Invoke-VscScan -Path (Join-Path $fixtures 'hardened')).Findings | Where-Object { $_.RuleId -like 'AW-VSC-*' })
        Assert-Equal 0 @($f | Where-Object { $_.Severity -eq 'critical' -or $_.Severity -eq 'high' }).Count (($f | ForEach-Object { $_.RuleId }) -join ',')
        Assert-Equal @('AW-VSC-027') @($f | ForEach-Object { $_.RuleId })
    }
    It 'reads nested notation and the workspace file of the mixed fixture' {
        $f = @((Invoke-VscScan -Path (Join-Path $fixtures 'mixed')).Findings | Where-Object { $_.RuleId -like 'AW-VSC-*' })
        Assert-Equal 1 @($f | Where-Object { $_.RuleId -eq 'AW-VSC-005' -and $_.Evidence.Contains('"npx"') }).Count
        Assert-Equal 1 @($f | Where-Object { $_.RuleId -eq 'AW-VSC-009' -and $_.Evidence.Contains('"**/*.md"') }).Count
        Assert-Equal 0 @($f | Where-Object { $_.RuleId -eq 'AW-VSC-004' -or $_.RuleId -eq 'AW-VSC-013' -or $_.RuleId -eq 'AW-VSC-020' }).Count
    }
    It 'reports user-profile settings from a fixture profile, and -Redact hides the profile path' {
        $profileDir = Join-Path $fixtures 'profile-insecure'
        $r = Invoke-VscScan -Path (Join-Path $vsc 'defaults') -UserProfilePath $profileDir
        $g = @($r.Findings | Where-Object { $_.RuleId -eq 'AW-VSC-001' })
        Assert-Equal 1 $g.Count
        Assert-Match $g[0].Evidence ([regex]::Escape($profileDir))
        Assert-Contains @($r.Findings | ForEach-Object { $_.RuleId }) 'AW-VSC-004'
        $r = Invoke-VscScan -Path (Join-Path $vsc 'defaults') -UserProfilePath $profileDir -Redact
        $g = @($r.Findings | Where-Object { $_.RuleId -eq 'AW-VSC-001' })
        Assert-NotMatch $g[0].Evidence ([regex]::Escape($profileDir))
        Assert-Match $g[0].Evidence 'set in user settings ~\\AppData\\Roaming\\Code\\User\\settings\.json'
    }
}

Describe 'AW-VSC line lookups' {
    try {
        It 'counts newlines exactly across 16K chunk edges (Get-AwVscLineAt)' {
            # LF every 7 characters (after a CR every other time), a 20,000-character line and a run of
            # blank lines, so that chunk edges fall on, next to and between newlines.
            $text = ("ab`r`ncd`n" * 6000) + ('x' * 20000) + "`n" + ("`n" * 40000) + 'end'
            $idx = @(1, 2, 3, 6, 7, 16383, 16384, 16385, 32767, 32768, 32769, 41999, 42000, 62000, 62001, 62002, 90000, ($text.Length - 1), $text.Length)
            $got = & $aw { param($t, $list) foreach ($i in $list) { Get-AwVscLineAt -Text $t -Index $i } } $text $idx
            $want = foreach ($i in $idx) { ($text.Substring(0, $i) -split "`n").Count }
            Assert-Equal @($want) @($got)
        }
        It 'returns line 1 at or before the start of the text, and on a text without newlines (Get-AwVscLineAt)' {
            Assert-Equal 1 (& $aw { Get-AwVscLineAt -Text "a`nb" -Index 0 })
            Assert-Equal 1 (& $aw { Get-AwVscLineAt -Text "a`nb" -Index -3 })
            Assert-Equal 1 (& $aw { Get-AwVscLineAt -Text ('x' * 40000) -Index 39999 })
        }
        It 'finds a setting and one of its entries, in dotted or nested notation (Find-AwVscLine)' {
            $text = "{`n  // c`n  `"chat.tools.urls.autoApprove`": {`n    `"a`": true,`n    `"https://*`": true`n  },`n  `"chat`": { `"agent`": {`n    `"maxRequests`": 500 } }`n}"
            Assert-Equal 3 (& $aw { param($t) Find-AwVscLine -Text $t -Key 'chat.tools.urls.autoApprove' } $text)
            Assert-Equal 5 (& $aw { param($t) Find-AwVscLine -Text $t -Key 'chat.tools.urls.autoApprove' -EntryKey 'https://*' } $text)
            Assert-Equal 3 (& $aw { param($t) Find-AwVscLine -Text $t -Key 'chat.tools.urls.autoApprove' -EntryKey 'missing' } $text)
            Assert-Equal 8 (& $aw { param($t) Find-AwVscLine -Text $t -Key 'chat.agent.maxRequests' } $text)
        }
        It 'returns $null for an empty or missing text, or a setting that is not in it (Find-AwVscLine)' {
            Assert-Equal $null (& $aw { Find-AwVscLine -Text '' -Key 'chat.agent.maxRequests' })
            Assert-Equal $null (& $aw { Find-AwVscLine -Text $null -Key 'chat.agent.maxRequests' -EntryKey 'x' })
            Assert-Equal $null (& $aw { Find-AwVscLine -Text '{ "chat.agent.other": 1 }' -Key 'chat.agent.maxRequests' })
        }
        It 'locates entries after 1.5 MB of padding on their exact lines, in under 2 seconds' {
            # 224,694 short comment lines (CR LF line ends), then URL entries, one per line. Every
            # finding used to count the newlines of the whole padding with a regex.
            $pad = 224694
            $entries = foreach ($k in 0..99) { '    "https://h{0:d4}.example.invalid/*": true' -f $k }
            $text = "{`r`n" + ("  //x`r`n" * $pad) + "  `"chat.tools.urls.autoApprove`": {`r`n" + ($entries -join ",`r`n") + "`r`n  }`r`n}`r`n"
            $ctx = & $aw { param($p) New-AwContext -Path $p -NoUserProfile } (New-VscCase $text)
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $f = Invoke-VscRule 'AW-VSC-010' $ctx
            $ms = $sw.ElapsedMilliseconds
            Assert-Equal @(0..99 | ForEach-Object { $pad + 3 + $_ }) @($f | ForEach-Object { $_.Location.Line })
            Assert-Match $f[0].Evidence '^chat\.tools\.urls\.autoApprove "https://h0000\.example\.invalid/\*" auto-approves requests and responses for every path of the host'
            Assert-Match $f[99].Evidence '"https://h0099\.'
            Assert-True ($ms -lt 2000) "AW-VSC-010 took $ms ms"
        }
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force }
    }
}

Describe 'AW-VSC coverage' {
    It 'has a positive and a negative test for every AW-VSC rule' {
        $ids = @(& $aw { Get-AwRules } | Where-Object { $_.Id -like 'AW-VSC-*' } | ForEach-Object { $_.Id })
        $missing = @(foreach ($id in $ids) { foreach ($s in @('+', '-')) { if (-not $coverage.ContainsKey("$id$s")) { "$id$s" } } })
        Assert-Equal 0 $missing.Count ('missing: ' + ($missing -join ', '))
    }
}
