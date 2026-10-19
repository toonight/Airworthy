# Tests for src/Core: model, frontmatter, settings, discovery, scoring, redaction and engine.
$aw = Get-Module Airworthy
$fixtures = Join-Path $PSScriptRoot 'fixtures'
$insecure = Join-Path $fixtures 'insecure'
$hardened = Join-Path $fixtures 'hardened'
$mixed = Join-Path $fixtures 'mixed'
$profileInsecure = Join-Path $fixtures 'profile-insecure'
$edge = Join-Path $fixtures 'core\edge'
$profileFull = Join-Path $fixtures 'core\profile-full'
$tmp = Join-Path $fixtures ('core\_tmp-' + [guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($tmp)
$utf8 = New-Object System.Text.UTF8Encoding($false)

function New-TestFile([string]$Path, [string]$Text) {
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { [void][System.IO.Directory]::CreateDirectory($dir) }
    [System.IO.File]::WriteAllText($Path, $Text, $utf8)
}

function Get-TestContext {
    param([string]$Path, [string]$UserProfilePath, [string]$UserSettingsPath)
    & $aw {
        param($p, $u, $s)
        if ($u) { New-AwContext -Path $p -UserProfilePath $u -UserSettingsPath $s }
        else { New-AwContext -Path $p -NoUserProfile -UserSettingsPath $s }
    } $Path $UserProfilePath $UserSettingsPath
}

function Read-TestFrontmatter([string]$Text) { & $aw { param($t) Read-AwFrontmatter -Text $t } $Text }

function Get-TestScore($Findings, $Rules, $Harnesses) {
    & $aw { param($f, $r, $h) Get-AwScore -Findings $f -Rules $r -Harnesses $h } @($Findings) @($Rules) @($Harnesses)
}
function New-TestRule([string]$Id, [string]$Category, [string]$Harness = 'generic') {
    [pscustomobject]@{ Id = $Id; Category = $Category; Harness = $Harness; Severity = 'high' }
}
function New-TestFinding([string]$RuleId, [string]$Severity, [string]$Category) {
    [pscustomobject]@{ RuleId = $RuleId; Severity = $Severity; Category = $Category }
}

# Test-only rules. AW-CORE-000 is the sample rule; the others exercise error paths.
function Register-SampleRule {
    & $aw {
        Register-AwRule -Id 'AW-CORE-000' -Title 'Sample: global tool auto-approval enabled' `
            -Severity 'high' -Category 'approvals' -Harness 'vscode-copilot' `
            -Description 'Test-only sample rule: flags chat.tools.global.autoApprove = true.' `
            -Fix 'Set chat.tools.global.autoApprove to false.' `
            -References @('OWASP-ASI02', 'https://code.visualstudio.com/docs/copilot/reference/copilot-settings') `
            -Confidence 'high' -Check {
                param($Ctx)
                $s = Get-AwSetting -Ctx $Ctx -Key 'chat.tools.global.autoApprove'
                if ($null -eq $s -or $s.Value -ne $true) { return }
                $raw = $null
                foreach ($a in @($Ctx.VSCode.UserSettings, $Ctx.VSCode.WorkspaceSettings)) { if ($a -and $a.Path -eq $s.Path) { $raw = $a.Raw } }
                New-AwFinding -RuleId 'AW-CORE-000' -Evidence 'chat.tools.global.autoApprove = true' `
                    -Location @{ Path = $s.Path; Line = (Find-AwLineNumber -Text $raw -Needle '"chat.tools.global.autoApprove"'); Key = 'chat.tools.global.autoApprove' }
            }
    }
}
function Register-TestRule([string]$Id, [string]$Severity, [string]$Kind, [string]$Harness = 'generic') {
    & $aw {
        param($id, $sev, $kind, $harness)
        # Plain script blocks, written here so they are bound to the module scope. Their findings
        # carry no RuleId: the engine fills it in from the rule that produced them.
        $checks = @{
            'throw'     = { param($Ctx) throw 'synthetic failure ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234' }
            'string'    = { param($Ctx) 'not a finding' }
            'partial'   = { param($Ctx) @{ Evidence = 'partial evidence'; Location = @{ Path = $Ctx.Root; Line = 'x' } } }
            'duplicate' = { param($Ctx) 1..3 | ForEach-Object { [pscustomobject]@{ Evidence = 'same'; Location = @{ Path = $Ctx.Root } } } }
            'one'       = { param($Ctx) [pscustomobject]@{ Evidence = 'one'; Location = @{ Path = $Ctx.Root } } }
            'roottext'  = {
                param($Ctx)
                $file = [System.IO.Path]::Combine($Ctx.Root, '.mcp.json')
                [pscustomobject]@{ Title = "Cannot read $file"; Evidence = "cannot read $file"; Location = @{ Path = $file; Key = $Ctx.Root } }
            }
            'profile'   = {
                param($Ctx)
                if ($Ctx.VSCode.UserSettings) {
                    [pscustomobject]@{ Evidence = ('user file ' + $Ctx.VSCode.UserSettings.Path); Location = @{ Path = $Ctx.VSCode.UserSettings.Path } }
                }
            }
        }
        Register-AwRule -Id $id -Title "Test rule $id" -Severity $sev -Category 'secrets' -Harness $harness `
            -Description 'Test-only rule.' -Fix 'None.' -Check $checks[$kind]
    } $Id $Severity $Kind $Harness
}
function Remove-TestRules { & $aw { foreach ($id in @($script:AwRules.Keys)) { if ($id -like 'AW-CORE-*') { $script:AwRules.Remove($id) } } } }
function Save-Registry { & $aw { $script:SavedRules = $script:AwRules.Clone(); $script:AwRules.Clear() } }
function Restore-Registry { & $aw { $script:AwRules.Clear(); foreach ($k in $script:SavedRules.Keys) { $script:AwRules[$k] = $script:SavedRules[$k] } } }

try {

Describe 'Module' {
    It 'imports and exports only Invoke-Airworthy' {
        Assert-Equal @('Invoke-Airworthy') @((Get-Command -Module Airworthy).Name)
    }
    It 'loads every source file without error' {
        $errors = & $aw { @($script:AwLoadErrors) }
        Assert-Equal 0 @($errors).Count (($errors | ForEach-Object { "$($_.File): $($_.Message)" }) -join '; ')
    }
    It 'has a manifest for Windows PowerShell 5.1, version 0.2.0' {
        $m = Import-PowerShellDataFile (Join-Path (Split-Path -Parent $PSScriptRoot) 'Airworthy.psd1')
        Assert-Equal '0.2.0' $m.ModuleVersion
        Assert-Equal '5.1' $m.PowerShellVersion
        Assert-Equal @('Invoke-Airworthy') @($m.FunctionsToExport)
        Assert-Equal 'Airworthy.psm1' $m.RootModule
        Assert-Equal 'Toonight' $m.Author
        Assert-Equal 'https://github.com/toonight/Airworthy' $m.PrivateData.PSData.ProjectUri
        foreach ($tag in @('vscode', 'claude-code', 'copilot-cli', 'codex', 'mcp')) { Assert-Contains $m.PrivateData.PSData.Tags $tag }
        Assert-Equal '0.2.0' (& $aw { $script:AwToolVersion })
        Assert-Equal 'Airworthy' (& $aw { $script:AwToolName })
    }
    It 'exposes the contract constants' {
        $c = & $aw { @{ Sev = $script:AwSeverities; W = $script:AwSeverityWeight; Cat = $script:AwCategories; H = $script:AwHarnesses } }
        Assert-Equal @('critical', 'high', 'medium', 'low', 'info') $c.Sev
        Assert-Equal 40 $c.W.critical; Assert-Equal 20 $c.W.high; Assert-Equal 8 $c.W.medium; Assert-Equal 3 $c.W.low; Assert-Equal 0 $c.W.info
        Assert-Equal @('approvals', 'sandbox-network', 'mcp-supply-chain', 'agent-files', 'secrets', 'observability') @($c.Cat.Keys)
        Assert-Equal @(25, 20, 20, 15, 15, 5) @($c.Cat.Values | ForEach-Object { $_.Weight })
        Assert-Equal @('vscode-copilot', 'claude-code', 'copilot-cli', 'codex', 'mcp', 'generic') $c.H
    }
}

Describe 'Model: rule registry' {
    It 'registers rules and returns them sorted by Id' {
        Register-TestRule 'AW-CORE-902' 'low' 'one'
        Register-TestRule 'AW-CORE-901' 'low' 'one'
        Register-SampleRule
        $ids = @(& $aw { Get-AwRules } | Where-Object { $_.Id -like 'AW-CORE-*' } | ForEach-Object { $_.Id })
        Assert-Equal @('AW-CORE-000', 'AW-CORE-901', 'AW-CORE-902') $ids
        $rule = & $aw { Get-AwRules } | Where-Object { $_.Id -eq 'AW-CORE-000' }
        Assert-True ($rule.Check -is [scriptblock])
        Assert-True ($rule.References -is [string[]])
        Assert-Equal 'high' $rule.Confidence
        Remove-TestRules
    }
    $bad = @(
        @{ Name = 'a malformed Id';       Args = @{ Id = 'VSC-1' } }
        @{ Name = 'an unknown area';      Args = @{ Id = 'AW-XYZ-001' } }
        @{ Name = 'an unknown severity';  Args = @{ Severity = 'severe' } }
        @{ Name = 'an unknown category';  Args = @{ Category = 'network' } }
        @{ Name = 'a wrongly cased category'; Args = @{ Category = 'Approvals' } }
        @{ Name = 'an unknown harness';   Args = @{ Harness = 'cursor' } }
        @{ Name = 'an unknown confidence'; Args = @{ Confidence = 'certain' } }
        @{ Name = 'a reserved engine Id'; Args = @{ Id = 'AW-CORE-001' } }
    )
    foreach ($b in $bad) {
        It "rejects $($b.Name)" {
            Assert-Throws {
                & $aw {
                    param($override)
                    $p = @{ Id = 'AW-CORE-950'; Title = 't'; Severity = 'low'; Category = 'secrets'; Harness = 'generic'; Description = 'd'; Fix = 'f'; Check = { } }
                    foreach ($k in $override.Keys) { $p[$k] = $override[$k] }
                    Register-AwRule @p
                } $b.Args
            } -ExpectedMessage 'Register-AwRule'
            Remove-TestRules
        }
    }
    It 'rejects a duplicate Id' {
        Register-TestRule 'AW-CORE-903' 'low' 'one'
        Assert-Throws { Register-TestRule 'AW-CORE-903' 'low' 'one' } -ExpectedMessage 'already registered'
        Remove-TestRules
    }
}

Describe 'Model: New-AwFinding' {
    Register-SampleRule
    It 'returns exactly the contract properties, filled from the rule' {
        $f = & $aw { New-AwFinding -RuleId 'AW-CORE-000' -Evidence 'e' -Location @{ Path = 'C:\x\settings.json'; Line = 12; Key = 'k' } }
        Assert-Equal @('RuleId', 'Title', 'Severity', 'Category', 'Harness', 'Description', 'Evidence', 'Location', 'Fix', 'References', 'Confidence') @($f.PSObject.Properties.Name)
        Assert-Equal 'Sample: global tool auto-approval enabled' $f.Title
        Assert-Equal 'high' $f.Severity
        Assert-Equal 'approvals' $f.Category
        Assert-Equal 'vscode-copilot' $f.Harness
        Assert-Equal 'Set chat.tools.global.autoApprove to false.' $f.Fix
        Assert-True ($f.References -is [string[]])
        Assert-Equal 2 $f.References.Count
        Assert-Equal 'high' $f.Confidence
        Assert-Equal @('Path', 'Line', 'Key') @($f.Location.PSObject.Properties.Name)
        Assert-Equal 'C:\x\settings.json' $f.Location.Path
        Assert-Equal 12 $f.Location.Line
        Assert-Equal 'k' $f.Location.Key
    }
    It 'applies overrides' {
        $f = & $aw { New-AwFinding -RuleId 'AW-CORE-000' -Severity 'critical' -Title 'T' -Fix 'F' -Harness 'mcp' -Evidence 'e' }
        Assert-Equal 'critical' $f.Severity; Assert-Equal 'T' $f.Title; Assert-Equal 'F' $f.Fix; Assert-Equal 'mcp' $f.Harness
        Assert-Equal 'approvals' $f.Category
    }
    It 'normalizes a missing or invalid location' {
        $f = & $aw { New-AwFinding -RuleId 'AW-CORE-000' }
        Assert-Equal $null $f.Location.Path; Assert-Equal $null $f.Location.Line; Assert-Equal $null $f.Location.Key
        Assert-Equal $null $f.Evidence
        $g = & $aw { New-AwFinding -RuleId 'AW-CORE-000' -Location ([pscustomobject]@{ Path = 'p'; Line = 0 }) }
        Assert-Equal 'p' $g.Location.Path; Assert-Equal $null $g.Location.Line
        $h = & $aw { New-AwFinding -RuleId 'AW-CORE-000' -Location @{ Line = '7' } }
        Assert-Equal 7 $h.Location.Line
    }
    It 'adds Data only when it is given' {
        $f = & $aw { New-AwFinding -RuleId 'AW-CORE-000' -Data @{ Server = 'x' } }
        Assert-Equal 'x' $f.Data.Server
        Assert-Equal 12 @($f.PSObject.Properties).Count
    }
    It 'keeps the shape for an unknown rule' {
        $f = & $aw { New-AwFinding -RuleId 'AW-ZZZ-999' -Evidence 'e' }
        Assert-Equal 11 @($f.PSObject.Properties).Count
        Assert-Equal $null $f.Category
        Assert-Equal 0 $f.References.Count
    }
    It 'fills the built-in AW-CORE-001 metadata' {
        $f = & $aw { New-AwFinding -RuleId 'AW-CORE-001' -Evidence 'bad file' }
        Assert-Equal 'info' $f.Severity
        Assert-Equal 'observability' $f.Category
        Assert-Equal 'Unreadable or invalid file' $f.Title
    }
    It 'rejects an invalid severity override' {
        Assert-Throws { & $aw { New-AwFinding -RuleId 'AW-CORE-000' -Severity 'severe' } } -ExpectedMessage 'invalid severity'
    }
    Remove-TestRules
}

Describe 'Model: Find-AwLineNumber' {
    It 'returns the 1-based line of the first occurrence' {
        $text = "{`n  `"a`": 1,`n  `"b`": 2,`n  `"b2`": 3`n}"
        Assert-Equal 1 (& $aw { param($t) Find-AwLineNumber -Text $t -Needle '{' } $text)
        Assert-Equal 3 (& $aw { param($t) Find-AwLineNumber -Text $t -Needle '"b' } $text)
        Assert-Equal 4 (& $aw { param($t) Find-AwLineNumber -Text $t -Needle '"b2"' } $text)
    }
    It 'handles CRLF and a needle at the very start of a line' {
        Assert-Equal 3 (& $aw { Find-AwLineNumber -Text "a`r`nb`r`nneedle" -Needle 'needle' })
    }
    It 'returns $null when absent or empty' {
        Assert-Equal $null (& $aw { Find-AwLineNumber -Text 'abc' -Needle 'z' })
        Assert-Equal $null (& $aw { Find-AwLineNumber -Text '' -Needle 'z' })
        Assert-Equal $null (& $aw { Find-AwLineNumber -Text 'abc' -Needle '' })
        Assert-Equal $null (& $aw { Find-AwLineNumber -Text $null -Needle 'a' })
    }
}

Describe 'Model: Read-AwDataFile' {
    It 'loads a rule data file as hashtables' {
        $d = & $aw { Read-AwDataFile -Name 'vscode' }
        Assert-True ($d -is [hashtable])
        Assert-True ($d['terminal'] -is [hashtable])
    }
    It 'rejects a missing file and a name that is not a plain file name' {
        Assert-Throws { & $aw { Read-AwDataFile -Name 'no-such-data-file' } } -ExpectedMessage 'not found'
        Assert-Throws { & $aw { Read-AwDataFile -Name '..\Airworthy' } } | Out-Null
    }
    It 'keeps the data files free of URLs and encoded-looking payloads' {
        $dir = Join-Path (Split-Path -Parent $PSScriptRoot) 'src\Data'
        foreach ($file in @(Get-ChildItem -LiteralPath $dir -Filter '*.json' -File)) {
            $text = [System.IO.File]::ReadAllText($file.FullName)
            Assert-NotMatch $text '(?i)\b[a-z][a-z0-9+.-]*://' "$($file.Name) contains a URL"
            Assert-NotMatch $text '[A-Za-z0-9+/]{40,}={0,2}' "$($file.Name) contains a long encoded-looking token"
        }
    }
}

Describe 'Redact' {
    $ellipsis = & $aw { $script:AwEllipsis }
    It 'masks a long secret, keeping 4 + 2 characters and the length' {
        $s = & $aw { Hide-AwSecret -Value 'ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234' }
        Assert-Equal ('ghp_' + $ellipsis + '34 (40 chars)') $s
        Assert-Equal ('abcd' + $ellipsis + 'kl (12 chars)') (& $aw { Hide-AwSecret -Value 'abcdefghijkl' })
    }
    It 'fully masks short or empty values' {
        Assert-Equal '****' (& $aw { Hide-AwSecret -Value 'abcdefghijk' })
        Assert-Equal '****' (& $aw { Hide-AwSecret -Value '' })
        Assert-Equal '****' (& $aw { Hide-AwSecret -Value $null })
    }
    It 'masks token-like words in free text and keeps ordinary text' {
        $t = & $aw { Hide-AwSecretsInText -Text 'failed with ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234 on chat.tools.terminal.enableAutoApprove' }
        Assert-NotMatch $t 'FAKEFAKEFAKEFAKE'
        Assert-Match $t 'chat\.tools\.terminal\.enableAutoApprove'
        Assert-Match $t '^failed with ghp_'
    }
    It 'shows paths relative to the root' {
        $ctx = [pscustomobject]@{ Root = 'D:\repo'; UserProfile = 'C:\Users\alice' }
        Assert-Equal '.vscode\settings.json' (& $aw { param($c) Get-AwDisplayPath -Path 'D:\repo\.vscode\settings.json' -Ctx $c } $ctx)
        Assert-Equal '.' (& $aw { param($c) Get-AwDisplayPath -Path 'D:\repo' -Ctx $c } $ctx)
        Assert-Equal 'D:\repository\x.json' (& $aw { param($c) Get-AwDisplayPath -Path 'D:\repository\x.json' -Ctx $c } $ctx)
        Assert-Equal 'C:\Users\alice\x.json' (& $aw { param($c) Get-AwDisplayPath -Path 'C:\Users\alice\x.json' -Ctx $c } $ctx)
    }
    It 'replaces the profile with ~ and masks the user name with -Redact' {
        $ctx = [pscustomobject]@{ Root = 'D:\repo'; UserProfile = 'C:\Users\alice' }
        Assert-Equal '~\AppData\Roaming\Code\User\settings.json' (& $aw { param($c) Get-AwDisplayPath -Path 'C:\Users\alice\AppData\Roaming\Code\User\settings.json' -Ctx $c -Redact } $ctx)
        Assert-Equal 'E:\backup\%USERNAME%\y.json' (& $aw { param($c) Get-AwDisplayPath -Path 'E:\backup\alice\y.json' -Ctx $c -Redact } $ctx)
        Assert-Equal 'E:\alicea\y.json' (& $aw { param($c) Get-AwDisplayPath -Path 'E:\alicea\y.json' -Ctx $c -Redact } $ctx)
        Assert-Equal '.vscode\a.json' (& $aw { param($c) Get-AwDisplayPath -Path 'D:\repo\.vscode\a.json' -Ctx $c -Redact } $ctx)
    }
    It 'redacts the profile path and user name in free text' {
        $t = & $aw { Hide-AwUserInText -Text 'cannot read C:\Users\alice\.claude.json for alice' -UserProfile 'C:\Users\alice' }
        Assert-Equal 'cannot read ~\.claude.json for %USERNAME%' $t
    }
    It 'labels a path by its leaf folder name, with the user name masked' {
        Assert-Equal 'my-repo' (& $aw { Get-AwPathLabel -Path 'D:\src\my-repo' })
        Assert-Equal 'my-repo' (& $aw { Get-AwPathLabel -Path 'D:\src\my-repo\' })
        Assert-Equal 'share' (& $aw { Get-AwPathLabel -Path '\\fileserver\share' })
        Assert-Equal '.' (& $aw { Get-AwPathLabel -Path 'D:\' })
        Assert-Equal '%USERNAME%' (& $aw { Get-AwPathLabel -Path 'C:\Users\alice' -UserProfile 'C:\Users\alice' })
        Assert-Equal '' (& $aw { Get-AwPathLabel -Path '' })
    }
    It 'replaces the absolute root in free text with its label, with either separator' {
        $t = & $aw { Hide-AwRootInText -Text "Access to the path 'D:\src\my-repo\.vscode\settings.json' is denied; see D:/src/my-repo/.mcp.json." -Root 'D:\src\my-repo' -Label 'my-repo' }
        Assert-Equal "Access to the path 'my-repo\.vscode\settings.json' is denied; see my-repo/.mcp.json." $t
        Assert-Equal 'my-repo' (& $aw { Hide-AwRootInText -Text 'D:\src\my-repo' -Root 'D:\src\my-repo\' -Label 'my-repo' })
        $other = 'D:\src\my-repo2\x, D:\src\my-repo-old and XD:\src\my-repo'
        Assert-Equal $other (& $aw { param($t) Hide-AwRootInText -Text $t -Root 'D:\src\my-repo' -Label 'my-repo' } $other)
        Assert-Equal 'in a$1b\x' (& $aw { Hide-AwRootInText -Text 'in D:\w\a$1b\x' -Root 'D:\w\a$1b' -Label 'a$1b' })
        Assert-Equal 'no root' (& $aw { Hide-AwRootInText -Text 'no root' -Root '' -Label 'x' })
        if (& $aw { $script:AwIsWindowsOS }) {
            Assert-Equal 'see my-repo\x' (& $aw { Hide-AwRootInText -Text 'see d:\SRC\My-Repo\x' -Root 'D:\src\my-repo' -Label 'my-repo' })
        }
    }
    It 'redacts path options: root label, ~ for the profile, leaf name for any other absolute path' {
        $ctx = [pscustomobject]@{ Root = 'D:\src\my-repo'; UserProfile = 'C:\Users\alice' }
        $out = & $aw {
            param($c)
            foreach ($p in @('D:\src\my-repo\out\report', 'C:\Users\alice', 'C:\Users\alice\reports\scan', 'E:\private\reports\scan', 'out\report', '')) {
                [string](Hide-AwOptionPath -Path $p -Ctx $c -RootLabel 'my-repo')
            }
        } $ctx
        Assert-Equal @('my-repo\out\report', '~', '~\reports\scan', 'scan', 'out\report', '') @($out)
    }
}

Describe 'Frontmatter: structure' {
    It 'returns an empty map and the whole text without frontmatter' {
        $r = Read-TestFrontmatter "# Title`nbody"
        Assert-Equal 0 $r.Frontmatter.Count
        Assert-Equal "# Title`nbody" $r.Body
        Assert-True ($r.Frontmatter -is [hashtable])
    }
    It 'requires the opening --- on the first line' {
        $r = Read-TestFrontmatter "`n---`na: 1`n---`nbody"
        Assert-Equal 0 $r.Frontmatter.Count
        Assert-Equal "`n---`na: 1`n---`nbody" $r.Body
    }
    It 'splits frontmatter and body, keeping later --- lines in the body' {
        $r = Read-TestFrontmatter "---`na: 1`n---`nline 1`n---`nline 2`n"
        Assert-Equal 1 $r.Frontmatter['a']
        Assert-Equal "line 1`n---`nline 2`n" $r.Body
    }
    It 'handles CRLF line endings and a BOM' {
        $bom = & $aw { [string]$script:AwBom }
        $r = Read-TestFrontmatter ($bom + "---`r`ndescription: 'x'`r`ntools: ['a', 'b']`r`n---`r`nBody`r`n")
        Assert-Equal 'x' $r.Frontmatter['description']
        Assert-Equal @('a', 'b') $r.Frontmatter['tools']
        Assert-Equal "Body`r`n" $r.Body
    }
    It 'accepts an empty frontmatter block' {
        $r = Read-TestFrontmatter "---`n---`nbody"
        Assert-Equal 0 $r.Frontmatter.Count
        Assert-Equal 'body' $r.Body
    }
    It 'treats an unterminated frontmatter as body and records it' {
        $r = Read-TestFrontmatter "---`ntools: ['*']`nno closing line"
        Assert-False $r.Frontmatter.ContainsKey('tools')
        Assert-Match ($r.Frontmatter['__errors'] -join ' ') 'not closed'
        Assert-Equal "---`ntools: ['*']`nno closing line" $r.Body
    }
    It 'never throws on null or empty input' {
        Assert-Equal 0 (Read-TestFrontmatter $null).Frontmatter.Count
        Assert-Equal '' (Read-TestFrontmatter '').Body
    }
}

Describe 'Frontmatter: values' {
    It 'parses scalars: strings, booleans, numbers, null' {
        $lines = @(
            "plain: hello world", "single: 'it''s'", 'double: "a\"b\tc"', "t: true", "f: False", "i: 42", "neg: -3",
            "d: 1.5", "n: null", "tilde: ~", "empty:", "url: https://example.invalid/a#frag", "colon: use this: carefully"
        )
        $fm = (Read-TestFrontmatter ("---`n" + ($lines -join "`n") + "`n---`n")).Frontmatter
        Assert-Equal 'hello world' $fm['plain']
        Assert-Equal "it's" $fm['single']
        Assert-Equal "a`"b`tc" $fm['double']
        Assert-Equal $true $fm['t']; Assert-Equal $false $fm['f']
        Assert-True ($fm['i'] -is [int]); Assert-Equal 42 $fm['i']; Assert-Equal (-3) $fm['neg']
        Assert-Equal 1.5 $fm['d']
        Assert-True ($fm.ContainsKey('n') -and $null -eq $fm['n'])
        Assert-Equal $null $fm['tilde']
        Assert-True ($fm.ContainsKey('empty') -and $null -eq $fm['empty'])
        Assert-Equal 'https://example.invalid/a#frag' $fm['url']
        Assert-Equal 'use this: carefully' $fm['colon']
        Assert-False $fm.ContainsKey('__errors')
    }
    It 'strips comments but keeps # inside quotes' {
        $fm = (Read-TestFrontmatter "---`n# full line comment`na: value # trailing`nb: 'x # y' # c`nc: C#`n---`n").Frontmatter
        Assert-Equal 'value' $fm['a']
        Assert-Equal 'x # y' $fm['b']
        Assert-Equal 'C#' $fm['c']
        Assert-Equal 3 $fm.Count
    }
    It 'parses inline lists with quotes, commas inside quotes and a trailing comma' {
        $fm = (Read-TestFrontmatter "---`ntools: ['*']`nb: [`"a, b`", 'c', d, ]`nempty: []`nnums: [1, true, null]`n---`n").Frontmatter
        Assert-Equal @('*') $fm['tools']
        Assert-True ($fm['tools'] -is [object[]])
        Assert-Equal @('a, b', 'c', 'd') $fm['b']
        Assert-Equal 0 $fm['empty'].Count
        Assert-True ($fm['empty'] -is [object[]])
        Assert-Equal 3 $fm['nums'].Count
        Assert-Equal 1 $fm['nums'][0]; Assert-Equal $true $fm['nums'][1]; Assert-Equal $null $fm['nums'][2]
    }
    It 'parses an inline list split over several lines' {
        $fm = (Read-TestFrontmatter "---`ntools: [`n  'search',`n  'fetch'`n]`nmodel: x`n---`n").Frontmatter
        Assert-Equal @('search', 'fetch') $fm['tools']
        Assert-Equal 'x' $fm['model']
    }
    It 'parses inline maps' {
        $fm = (Read-TestFrontmatter "---`nm: { a: 1, b: 'x y', c: [1, 2] }`n---`n").Frontmatter
        Assert-Equal 1 $fm['m']['a']; Assert-Equal 'x y' $fm['m']['b']; Assert-Equal @(1, 2) $fm['m']['c']
    }
    It 'parses block lists, indented or not' {
        $fm = (Read-TestFrontmatter "---`ntools:`n  - search`n  - 'github/*'`nother:`n- a`n- b`nafter: 1`n---`n").Frontmatter
        Assert-Equal @('search', 'github/*') $fm['tools']
        Assert-Equal @('a', 'b') $fm['other']
        Assert-Equal 1 $fm['after']
    }
    It 'parses a list of maps (handoffs)' {
        $text = "---`nhandoffs:`n  - label: Start`n    agent: impl`n    prompt: 'Go: now'`n    send: false`n  - label: Ship`n    send: true`nname: x`n---`n"
        $fm = (Read-TestFrontmatter $text).Frontmatter
        Assert-Equal 2 $fm['handoffs'].Count
        Assert-True ($fm['handoffs'][0] -is [hashtable])
        Assert-Equal 'Start' $fm['handoffs'][0]['label']
        Assert-Equal 'impl' $fm['handoffs'][0]['agent']
        Assert-Equal 'Go: now' $fm['handoffs'][0]['prompt']
        Assert-Equal $false $fm['handoffs'][0]['send']
        Assert-Equal $true $fm['handoffs'][1]['send']
        Assert-Equal 'x' $fm['name']
    }
    It 'parses nested maps' {
        $fm = (Read-TestFrontmatter "---`nmeta:`n  owner: team-a`n  level: 2`n  tags: [x]`ntop: y`n---`n").Frontmatter
        Assert-True ($fm['meta'] -is [hashtable])
        Assert-Equal 'team-a' $fm['meta']['owner']; Assert-Equal 2 $fm['meta']['level']; Assert-Equal @('x') $fm['meta']['tags']
        Assert-Equal 'y' $fm['top']
    }
    It 'parses deeper structures such as hooks' {
        $text = "---`nhooks:`n  PreToolUse:`n    - type: command`n      command: ./check.sh`n---`n"
        $fm = (Read-TestFrontmatter $text).Frontmatter
        Assert-Equal 'command' $fm['hooks']['PreToolUse'][0]['type']
        Assert-Equal './check.sh' $fm['hooks']['PreToolUse'][0]['command']
    }
    It 'parses literal and folded block scalars' {
        $text = "---`nlit: |`n  line one`n  # not a comment`n`n  line three`nfold: >-`n  a`n  b`n`n  c`nnext: 1`n---`n"
        $fm = (Read-TestFrontmatter $text).Frontmatter
        Assert-Equal "line one`n# not a comment`n`nline three`n" $fm['lit']
        Assert-Equal "a b`nc" $fm['fold']
        Assert-Equal 1 $fm['next']
    }
    It 'joins a plain scalar continued on deeper lines' {
        $fm = (Read-TestFrontmatter "---`ndescription: A long`n  description here`nx: 1`n---`n").Frontmatter
        Assert-Equal 'A long description here' $fm['description']
        Assert-Equal 1 $fm['x']
    }
    It 'keeps keys case-sensitive and lets the last duplicate win' {
        $fm = (Read-TestFrontmatter "---`ntools: [a]`nTools: [b]`ntools: [c]`n---`n").Frontmatter
        Assert-Equal @('c') $fm['tools']
        Assert-Equal @('b') $fm['Tools']
    }
    It 'parses quoted keys' {
        $fm = (Read-TestFrontmatter "---`n`"my key`": 1`n'other': 2`n---`n").Frontmatter
        Assert-Equal 1 $fm['my key']; Assert-Equal 2 $fm['other']
    }
}

Describe 'Frontmatter: unsupported or hostile YAML' {
    It 'records anchors, aliases and tags without throwing, and keeps the rest' {
        $fm = (Read-TestFrontmatter "---`na: &anchor x`nb: *anchor`nc: !!str 5`ntools: ['read']`n---`n").Frontmatter
        Assert-Equal @('read') $fm['tools']
        Assert-True ($fm['__errors'].Count -ge 3)
        Assert-Match ($fm['__errors'] -join ' ') 'line 2: unsupported YAML'
    }
    It 'records lines it cannot parse' {
        $fm = (Read-TestFrontmatter "---`njust some text`n  weird: indent`ntools: [x]`n---`n").Frontmatter
        Assert-Equal @('x') $fm['tools']
        Assert-Match ($fm['__errors'] -join ' ') 'line 2'
    }
    It 'records unterminated quotes and flow lists' {
        $fm = (Read-TestFrontmatter "---`na: 'open`nb: [1, 2`nc: ok`n---`n").Frontmatter
        Assert-True ($fm.ContainsKey('__errors'))
        Assert-Equal "'open" $fm['a']
    }
    It 'records tabs used for indentation' {
        $fm = (Read-TestFrontmatter "---`nm:`n`ta: 1`n---`n").Frontmatter
        Assert-Match ($fm['__errors'] -join ' ') 'tab'
    }
    It 'ignores a frontmatter that is a list' {
        $fm = (Read-TestFrontmatter "---`n- a`n- b`n---`n").Frontmatter
        Assert-Equal 1 $fm.Count
        Assert-Match ($fm['__errors'] -join ' ') 'list'
    }
    It 'bounds very long and very deep frontmatter' {
        $long = "---`n" + (("k: v`n") * 2500) + "---`nbody"
        $r = Read-TestFrontmatter $long
        Assert-Match ($r.Frontmatter['__errors'] -join ' ') 'longer than 2000 lines'
        Assert-Equal 'body' $r.Body
        $deep = "---`n" + ((0..40 | ForEach-Object { (' ' * $_) + "k${_}:" }) -join "`n") + "`n---`n"
        $d = Read-TestFrontmatter $deep
        Assert-Match ($d.Frontmatter['__errors'] -join ' ') 'too deep'
    }
}

Describe 'Settings: defaults and Get-AwSetting' {
    It 'contains the verified VS Code defaults' {
        $d = & $aw { $script:AwVSCodeDefaults }
        Assert-Equal 'default' $d['chat.permissions.default']
        Assert-Equal $false $d['chat.tools.global.autoApprove']
        Assert-Equal $true $d['chat.tools.terminal.enableAutoApprove']
        Assert-Equal $false $d['chat.tools.terminal.ignoreDefaultAutoApproveRules']
        Assert-Equal 'outsideWorkspace' $d['chat.tools.terminal.blockDetectedFileWrites']
        Assert-Equal $true $d['chat.agent.sandbox.network.allowNetwork']
        Assert-Equal $true $d['chat.agent.sandbox.allowUnsandboxedCommands']
        Assert-Equal 'newAndOutdated' $d['chat.mcp.autostart']
        Assert-Equal 25 $d['chat.agent.maxRequests']
        Assert-Equal 'http://localhost:4318' $d['github.copilot.chat.otel.otlpEndpoint']
        $keys = [string[]]@($d['chat.tools.terminal.autoApprove'].Keys)
        [Array]::Sort($keys, [StringComparer]::Ordinal)
        Assert-Equal @('/^Remove-Item\b/i', 'chmod', 'chown', 'curl', 'del', 'eval', 'kill', 'rm', 'rmdir', 'wget') $keys
    }
    It 'returns the default entry when no file sets the key' {
        $empty = Join-Path $tmp 'empty-root'
        [void][System.IO.Directory]::CreateDirectory($empty)
        $ctx = Get-TestContext $empty
        $s = & $aw { param($c) Get-AwSetting -Ctx $c -Key 'chat.tools.terminal.enableAutoApprove' } $ctx
        Assert-Equal 'chat.tools.terminal.enableAutoApprove' $s.Key
        Assert-Equal $true $s.Value
        Assert-Equal 'default' $s.Source
        Assert-Equal $true $s.IsDefault
        Assert-Equal $null $s.Path
        Assert-Equal 1 @($s.Layers).Count
        Assert-Equal $null (& $aw { param($c) Get-AwSetting -Ctx $c -Key 'no.such.setting' } $ctx)
    }
}

Describe 'Settings: layered merge' {
    function Merge-TestLayers([object[]]$Layers) { & $aw { param($l) Get-AwEffectiveSettings -Layers $l } $Layers }
    It 'applies default < user < workspaceFile < workspace' {
        $e = Merge-TestLayers @(
            @{ Source = 'user'; Path = 'u.json'; Settings = @{ 'chat.agent.maxRequests' = 10; 'only.user' = 1 } },
            @{ Source = 'workspaceFile'; Path = 'w.code-workspace'; Settings = @{ 'chat.agent.maxRequests' = 20 } },
            @{ Source = 'workspace'; Path = 's.json'; Settings = @{ 'chat.agent.maxRequests' = 30 } }
        )
        $m = $e['chat.agent.maxRequests']
        Assert-Equal 30 $m.Value
        Assert-Equal 'workspace' $m.Source
        Assert-Equal 's.json' $m.Path
        Assert-False $m.IsDefault
        Assert-Equal @('default', 'user', 'workspaceFile', 'workspace') @($m.Layers | ForEach-Object { $_.Source })
        Assert-Equal @(25, 10, 20, 30) @($m.Layers | ForEach-Object { $_.Value })
        Assert-Equal 'user' $e['only.user'].Source
        Assert-Equal @('user') @($e['only.user'].Layers | ForEach-Object { $_.Source })
        Assert-Equal 'default' $e['chat.useHooks'].Source
    }
    It 'merges object settings by key, including the defaults' {
        $e = Merge-TestLayers @(
            @{ Source = 'user'; Path = 'u'; Settings = @{ 'chat.tools.terminal.autoApprove' = @{ 'rm' = $true; 'ls' = $true } } },
            @{ Source = 'workspace'; Path = 'w'; Settings = @{ 'chat.tools.terminal.autoApprove' = @{ 'ls' = $false; 'npx' = $true } } }
        )
        $v = $e['chat.tools.terminal.autoApprove']
        Assert-Equal 'workspace' $v.Source
        Assert-Equal $true $v.Value['rm']
        Assert-Equal $false $v.Value['ls']
        Assert-Equal $true $v.Value['npx']
        Assert-Equal $false $v.Value['curl']
        Assert-Equal 3 @($v.Layers).Count
    }
    It 'merges nested objects deeply and replaces arrays' {
        $e = Merge-TestLayers @(
            @{ Source = 'user'; Path = 'u'; Settings = @{ 'chat.tools.urls.autoApprove' = @{ 'https://a.invalid/*' = @{ approveRequest = $true; approveResponse = $false } }; 'chat.agent.allowedNetworkDomains' = @('a', 'b') } },
            @{ Source = 'workspace'; Path = 'w'; Settings = @{ 'chat.tools.urls.autoApprove' = @{ 'https://a.invalid/*' = @{ approveResponse = $true } }; 'chat.agent.allowedNetworkDomains' = @('c') } }
        )
        $u = $e['chat.tools.urls.autoApprove'].Value['https://a.invalid/*']
        Assert-Equal $true $u['approveRequest']
        Assert-Equal $true $u['approveResponse']
        Assert-Equal @('c') $e['chat.agent.allowedNetworkDomains'].Value
    }
    It 'replaces a value whose type changes' {
        $e = Merge-TestLayers @(
            @{ Source = 'user'; Path = 'u'; Settings = @{ 'chat.tools.edits.autoApprove' = $true } }
        )
        Assert-Equal $true $e['chat.tools.edits.autoApprove'].Value
    }
    It 'does not mutate the parsed files or the defaults' {
        $user = @{ 'chat.tools.terminal.autoApprove' = @{ 'rm' = $true } }
        [void](Merge-TestLayers @(@{ Source = 'user'; Path = 'u'; Settings = $user }))
        $e = Merge-TestLayers @(@{ Source = 'workspace'; Path = 'w'; Settings = @{ 'chat.tools.terminal.autoApprove' = @{ 'x' = $true } } })
        Assert-Equal 1 $user['chat.tools.terminal.autoApprove'].Count
        Assert-Equal $false $e['chat.tools.terminal.autoApprove'].Value['rm']
        $d = & $aw { $script:AwVSCodeDefaults['chat.tools.terminal.autoApprove'] }
        Assert-Equal 10 $d.Count
    }
    It 'keeps setting keys case-sensitive' {
        $e = Merge-TestLayers @(@{ Source = 'workspace'; Path = 'w'; Settings = (& $aw { ConvertFrom-AwJsonc -Text '{"Chat.Tools.Global.AutoApprove": true}' }) })
        Assert-Equal $false $e['chat.tools.global.autoApprove'].Value
        Assert-Equal $true $e['Chat.Tools.Global.AutoApprove'].Value
    }
}

Describe 'Settings: nested notation' {
    function Flatten([string]$Json) { & $aw { param($j) ConvertTo-AwFlatSettings -Settings (ConvertFrom-AwJsonc -Text $j) } $Json }
    It 'flattens nested objects into dotted keys' {
        $f = Flatten '{"chat":{"tools":{"global":{"autoApprove":true}},"agent":{"maxRequests":5}},"github":{"copilot":{"chat":{"otel":{"enabled":true}}}}}'
        Assert-Equal $true $f['chat.tools.global.autoApprove']
        Assert-Equal 5 $f['chat.agent.maxRequests']
        Assert-Equal $true $f['github.copilot.chat.otel.enabled']
        Assert-False $f.ContainsKey('chat')
    }
    It 'stops at object-valued settings' {
        $f = Flatten '{"chat":{"tools":{"terminal":{"autoApprove":{"npx":true,"/a.b/":false}},"urls":{"autoApprove":{"https://x.invalid/*":true}}}}}'
        Assert-Equal $true $f['chat.tools.terminal.autoApprove']['npx']
        Assert-Equal $false $f['chat.tools.terminal.autoApprove']['/a.b/']
        Assert-Equal $true $f['chat.tools.urls.autoApprove']['https://x.invalid/*']
        Assert-False $f.ContainsKey('chat.tools.terminal.autoApprove.npx')
    }
    It 'keeps dotted keys and language overrides whole' {
        $f = Flatten '{"chat.tools.terminal.autoApprove":{"a":true},"[python]":{"editor.tabSize":4},"files.exclude":{"**/.git":true}}'
        Assert-Equal $true $f['chat.tools.terminal.autoApprove']['a']
        Assert-Equal 4 $f['[python]']['editor.tabSize']
        Assert-Equal $true $f['files.exclude']['**/.git']
    }
    It 'merges the dotted and nested forms of the same object setting' {
        $f = Flatten '{"chat.tools.terminal.autoApprove":{"a":true},"chat":{"tools":{"terminal":{"autoApprove":{"b":true}}}}}'
        Assert-Equal $true $f['chat.tools.terminal.autoApprove']['a']
        Assert-Equal $true $f['chat.tools.terminal.autoApprove']['b']
    }
}

Describe 'Settings: effective values from the fixtures' {
    It 'merges the user profile and the workspace (insecure + profile-insecure)' {
        $ctx = Get-TestContext $insecure $profileInsecure
        $e = $ctx.VSCode.Effective
        Assert-Equal 'workspace' $e['chat.tools.global.autoApprove'].Source
        Assert-Equal @('default', 'user', 'workspace') @($e['chat.tools.global.autoApprove'].Layers | ForEach-Object { $_.Source })
        Assert-Equal 500 $e['chat.agent.maxRequests'].Value
        Assert-Equal 14 $e['editor.fontSize'].Value
        Assert-Equal 'user' $e['editor.fontSize'].Source
        Assert-Equal $ctx.VSCode.UserSettings.Path $e['editor.fontSize'].Path
        $t = $e['chat.tools.terminal.autoApprove'].Value
        Assert-Equal $true $t['/.*/']; Assert-Equal $true $t['npx']; Assert-Equal $false $t['rm']
    }
    It 'lets the workspace override the user profile (hardened + profile-insecure)' {
        $ctx = Get-TestContext $hardened $profileInsecure
        $g = & $aw { param($c) Get-AwSetting -Ctx $c -Key 'chat.tools.global.autoApprove' } $ctx
        Assert-Equal $false $g.Value
        Assert-Equal 'workspace' $g.Source
        Assert-Equal $true $g.Layers[1].Value
    }
    It 'flattens nested notation and merges the workspace file (mixed)' {
        $e = (Get-TestContext $mixed).VSCode.Effective
        Assert-Equal 50 $e['chat.agent.maxRequests'].Value
        Assert-Equal @('default', 'workspaceFile', 'workspace') @($e['chat.agent.maxRequests'].Layers | ForEach-Object { $_.Source })
        Assert-Equal $false $e['chat.tools.global.autoApprove'].Value
        Assert-Equal $false $e['chat.agent.sandbox.network.allowNetwork'].Value
        Assert-Equal 'workspaceFile' $e['chat.agent.sandbox.network.allowNetwork'].Source
        $t = $e['chat.tools.terminal.autoApprove'].Value
        Assert-Equal $true $t['make']; Assert-Equal $true $t['npm test']; Assert-Equal $false $t['rm']
    }
}

Describe 'Discovery: shared fixtures' {
    It 'returns every contract property for insecure (no user profile)' {
        $ctx = Get-TestContext $insecure
        Assert-Equal @('Root', 'IsWindows', 'UserProfile', 'Harnesses', 'VSCode', 'McpFiles', 'AgentFiles', 'Hooks', 'ClaudeSettings', 'CopilotCli', 'Codex', 'CodexRules', 'TextFiles', 'Errors') @($ctx.PSObject.Properties.Name)
        Assert-Equal @('UserSettings', 'WorkspaceSettings', 'WorkspaceFiles', 'Effective') @($ctx.VSCode.PSObject.Properties.Name)
        Assert-Equal ([System.IO.Path]::GetFullPath($insecure)) $ctx.Root
        Assert-True ($ctx.IsWindows -is [bool])
        Assert-Equal $null $ctx.UserProfile
        Assert-Equal @('vscode-copilot', 'claude-code', 'codex', 'mcp') $ctx.Harnesses
        Assert-Equal $null $ctx.VSCode.UserSettings
        Assert-Equal 0 @($ctx.VSCode.WorkspaceFiles).Count
        Assert-True ($ctx.VSCode.WorkspaceFiles -is [array])
        Assert-Equal 0 @($ctx.CopilotCli).Count
        Assert-True ($ctx.CopilotCli -is [array])
        Assert-Equal 0 @($ctx.Errors).Count
    }
    It 'reads the workspace settings as an artifact' {
        $a = (Get-TestContext $insecure).VSCode.WorkspaceSettings
        Assert-Equal @('Path', 'Scope', 'Harness', 'Raw', 'Data') @($a.PSObject.Properties.Name)
        Assert-Equal (Join-Path $insecure '.vscode\settings.json') $a.Path
        Assert-Equal 'workspace' $a.Scope
        Assert-Equal 'vscode-copilot' $a.Harness
        Assert-Match $a.Raw 'Synthetic INSECURE'
        Assert-Equal $true $a.Data['chat.tools.global.autoApprove']
    }
    It 'normalizes the MCP servers of each client' {
        $mcp = @((Get-TestContext $insecure).McpFiles)
        Assert-Equal 3 $mcp.Count
        $vs = $mcp | Where-Object { $_.Path -like '*\.vscode\mcp.json' }
        Assert-Equal 'vscode-copilot' $vs.Harness; Assert-Equal 'workspace' $vs.Scope
        Assert-Equal @('fetch-anything', 'remote-tools') @($vs.Data.Servers.Keys | Sort-Object)
        Assert-Equal 'npx' $vs.Data.Servers['fetch-anything']['command']
        $cc = $mcp | Where-Object { $_.Path -like '*\.mcp.json' }
        Assert-Equal 'claude-code' $cc.Harness; Assert-Equal 'project' $cc.Scope
        Assert-Equal @('git-tools', 'shell') @($cc.Data.Servers.Keys | Sort-Object)
        $cdx = $mcp | Where-Object { $_.Path -like '*\.codex\config.toml' }
        Assert-Equal 'codex' $cdx.Harness; Assert-Equal 'project' $cdx.Scope
        Assert-Equal @('repo-tools', 'tracker') @($cdx.Data.Servers.Keys | Sort-Object)
        Assert-Equal 'npx' $cdx.Data.Servers['repo-tools']['command']
    }
    It 'finds agent files with their kind and frontmatter' {
        $agents = @((Get-TestContext $insecure).AgentFiles)
        Assert-Equal @('agent', 'copilot-instructions') @($agents | ForEach-Object { $_.Kind })
        Assert-Equal @('Path', 'Kind', 'Scope', 'Frontmatter', 'Body', 'Raw') @($agents[0].PSObject.Properties.Name)
        Assert-Equal @('*') $agents[0].Frontmatter['tools']
        Assert-Equal $true $agents[0].Frontmatter['handoffs'][0]['send']
        Assert-Match $agents[0].Body 'fully autonomous'
        Assert-Equal 0 $agents[1].Frontmatter.Count
        Assert-Match $agents[1].Body 'skip all approval prompts'
    }
    It 'lists Claude settings and the hooks they contain' {
        $ctx = Get-TestContext $insecure
        Assert-Equal 1 @($ctx.ClaudeSettings).Count
        Assert-Equal 'project' $ctx.ClaudeSettings[0].Scope
        Assert-Equal 'bypassPermissions' $ctx.ClaudeSettings[0].Data['permissions']['defaultMode']
        Assert-Equal 1 @($ctx.Hooks).Count
        Assert-True ([object]::ReferenceEquals($ctx.Hooks[0], $ctx.ClaudeSettings[0]))
    }
    It 'lists text files as absolute paths inside the root' {
        $ctx = Get-TestContext $insecure
        Assert-Equal 7 @($ctx.TextFiles).Count
        foreach ($t in $ctx.TextFiles) {
            Assert-True ([System.IO.Path]::IsPathRooted($t)) $t
            Assert-True ($t.StartsWith($ctx.Root, [StringComparison]::OrdinalIgnoreCase)) $t
        }
        Assert-Equal 1 @($ctx.TextFiles | Where-Object { $_ -like '*\.mcp.json' }).Count
    }
    It 'reads the fake user profile when asked (profile-insecure)' {
        $ctx = Get-TestContext $insecure $profileInsecure
        Assert-Equal ([System.IO.Path]::GetFullPath($profileInsecure)) $ctx.UserProfile
        Assert-Equal (Join-Path $profileInsecure 'AppData\Roaming\Code\User\settings.json') $ctx.VSCode.UserSettings.Path
        Assert-Equal 'user' $ctx.VSCode.UserSettings.Scope
        Assert-Equal @('project', 'user') @($ctx.ClaudeSettings | ForEach-Object { $_.Scope })
        Assert-Equal 1 @($ctx.Hooks).Count
        Assert-Equal 9 @($ctx.TextFiles).Count
    }
    It 'finds Copilot hooks (hardened)' {
        $ctx = Get-TestContext $hardened
        $h = @($ctx.Hooks | Where-Object { $_.Path -like '*\.github\hooks\policy.json' })
        Assert-Equal 1 $h.Count
        Assert-Equal 'copilot-cli' $h[0].Harness
        Assert-Equal 'project' $h[0].Scope
        Assert-Equal 1 $h[0].Data['version']
        Assert-Equal 0 @($ctx.Errors).Count
    }
    It 'finds workspace files, prompts, instructions and local Claude settings (mixed)' {
        $ctx = Get-TestContext $mixed
        Assert-Equal 1 @($ctx.VSCode.WorkspaceFiles).Count
        Assert-Equal 'workspace' $ctx.VSCode.WorkspaceFiles[0].Scope
        Assert-Equal @('agent', 'instructions', 'prompt', 'claude-md') @($ctx.AgentFiles | ForEach-Object { $_.Kind })
        Assert-Equal @('search', 'editFiles', 'github/*') $ctx.AgentFiles[0].Frontmatter['tools']
        Assert-Equal 'local' $ctx.ClaudeSettings[0].Scope
        Assert-Equal 0 @($ctx.Hooks).Count
        Assert-Equal 3 $ctx.McpFiles[0].Data.Servers.Count
    }
    It 'never reads outside the root with -NoUserProfile' {
        foreach ($root in @($insecure, $hardened, $mixed)) {
            $ctx = Get-TestContext $root
            foreach ($p in $ctx.TextFiles) { Assert-True ($p.StartsWith($ctx.Root, [StringComparison]::OrdinalIgnoreCase)) $p }
        }
    }
}

Describe 'Discovery: edge cases' {
    $ctx = Get-TestContext $edge
    $errorText = ($ctx.Errors | ForEach-Object { "$($_.Location.Path) :: $($_.Evidence)" }) -join "`n"
    It 'reports invalid JSON as AW-CORE-001 with its line, and keeps the raw text' {
        $e = @($ctx.Errors | Where-Object { $_.Location.Path -like '*\.vscode\settings.json' })
        Assert-Equal 1 $e.Count $errorText
        Assert-Equal 'AW-CORE-001' $e[0].RuleId
        Assert-Equal 'info' $e[0].Severity
        Assert-Equal 3 $e[0].Location.Line
        Assert-Match $e[0].Evidence "Expected ':'"
        Assert-Equal $null $ctx.VSCode.WorkspaceSettings.Data
        Assert-Match $ctx.VSCode.WorkspaceSettings.Raw 'maxRequests'
    }
    It 'reports a configuration whose top level is not an object' {
        $e = @($ctx.Errors | Where-Object { $_.Location.Path -like '*\.vscode\mcp.json' })
        Assert-Equal 1 $e.Count $errorText
        Assert-Match $e[0].Evidence 'not an object'
        $a = $ctx.McpFiles | Where-Object { $_.Path -like '*\.vscode\mcp.json' }
        Assert-Equal $null $a.Data
    }
    It 'skips an MCP server that is not an object' {
        $a = $ctx.McpFiles | Where-Object { $_.Path -like '*\.mcp.json' }
        Assert-Equal @('good') @($a.Data.Servers.Keys)
        Assert-Match $errorText "server 'bad' is not an object"
    }
    It 'reports unsupported frontmatter but keeps the agent file' {
        $odd = $ctx.AgentFiles | Where-Object { $_.Path -like '*odd.agent.md' }
        Assert-Equal @('read') $odd.Frontmatter['tools']
        Assert-True $odd.Frontmatter.ContainsKey('__errors')
        Assert-Match $errorText 'odd\.agent\.md :: Frontmatter partially parsed'
    }
    It 'treats an empty settings file as an empty object' {
        $c = $ctx.ClaudeSettings | Where-Object { $_.Path -like '*\.claude\settings.json' }
        Assert-True ($c.Data -is [hashtable])
        Assert-Equal 0 $c.Data.Count
        Assert-NotMatch $errorText '\.claude\\settings\.json'
    }
    It 'classifies every kind of agent file' {
        $kinds = @{}
        foreach ($a in $ctx.AgentFiles) { $kinds[$a.Kind] = $a.Scope }
        Assert-Equal 'workspace' $kinds['chatmode']
        Assert-Equal 'project' $kinds['claude-agent']
        Assert-Equal 'workspace' $kinds['agents-md']
        Assert-Equal 'workspace' $kinds['agent']
    }
    It 'detects the Copilot CLI project settings' {
        Assert-Contains $ctx.Harnesses 'copilot-cli'
        Assert-Equal 'project' $ctx.CopilotCli[0].Scope
        Assert-Equal 'copilot-cli' $ctx.CopilotCli[0].Harness
    }
    It 'adds .env files at the root to the text files' {
        Assert-Equal 1 @($ctx.TextFiles | Where-Object { $_ -like '*\.env.example' }).Count
    }
    It 'uses the workspace file when the workspace settings are invalid' {
        $m = $ctx.VSCode.Effective['chat.agent.maxRequests']
        Assert-Equal 40 $m.Value
        Assert-Equal 'workspaceFile' $m.Source
    }
    It 'returns file text through Get-AwFileText' {
        $env = @($ctx.TextFiles | Where-Object { $_ -like '*\.env.example' })[0]
        Assert-Match (& $aw { param($c, $p) Get-AwFileText -Ctx $c -Path $p } $ctx $env) 'FAKE-placeholder'
        $agents = Join-Path $edge 'AGENTS.md'
        Assert-Match (& $aw { param($c, $p) Get-AwFileText -Ctx $c -Path $p } $ctx $agents) 'Run the tests'
        Assert-Equal $null (& $aw { param($c, $p) Get-AwFileText -Ctx $c -Path $p } $ctx (Join-Path $edge 'missing.txt'))
    }
}

Describe 'Discovery: user profile and machine-wide files' {
    $empty = Join-Path $tmp 'empty-root'
    [void][System.IO.Directory]::CreateDirectory($empty)
    $ctx = Get-TestContext $empty $profileFull
    It 'detects the harnesses from the profile alone' {
        Assert-Equal @('vscode-copilot', 'claude-code', 'copilot-cli', 'mcp') $ctx.Harnesses
        Assert-Equal 60 $ctx.VSCode.Effective['chat.agent.maxRequests'].Value
    }
    It 'reads the user MCP files of every client' {
        $names = @()
        foreach ($a in $ctx.McpFiles) { foreach ($k in $a.Data.Servers.Keys) { $names += "$($a.Harness)/$($a.Scope)/$k" } }
        $names = @($names | Sort-Object)
        Assert-Equal @(
            'claude-code/user/alpha-db (project: D:/work/alpha)',
            'claude-code/user/user-search',
            'copilot-cli/user/cli-tool',
            'vscode-copilot/user/insiders-tool',
            'vscode-copilot/user/user-docs'
        ) $names
    }
    It 'reads Copilot CLI agents, hooks and settings from the profile' {
        $agent = @($ctx.AgentFiles | Where-Object { $_.Scope -eq 'user' })
        Assert-Equal 1 $agent.Count
        Assert-Equal 'agent' $agent[0].Kind
        Assert-Equal @('shell') $agent[0].Frontmatter['tools']
        Assert-Equal 1 @($ctx.Hooks | Where-Object { $_.Scope -eq 'user' -and $_.Harness -eq 'copilot-cli' }).Count
        Assert-Equal @('config.json', 'settings.json') @($ctx.CopilotCli | ForEach-Object { Split-Path $_.Path -Leaf })
        Assert-Equal @('user') @($ctx.ClaudeSettings | ForEach-Object { $_.Scope })
    }
    It 'reads managed Claude settings only from the configured machine path' {
        $managed = Join-Path $fixtures 'core\managed\managed-settings.json'
        & $aw { param($p) $script:AwManagedSettingsOverride = @($p) } $managed
        try {
            $c = Get-TestContext $empty $profileFull
            $m = @($c.ClaudeSettings | Where-Object { $_.Scope -eq 'managed' })
            Assert-Equal 1 $m.Count
            Assert-Equal 'disable' $m[0].Data['permissions']['disableBypassPermissionsMode']
            $n = Get-TestContext $empty
            Assert-Equal 0 @($n.ClaudeSettings).Count
        } finally {
            & $aw { $script:AwManagedSettingsOverride = $null }
        }
    }
    It 'forces the user settings file with -UserSettingsPath, even without a profile' {
        $forced = Join-Path $profileInsecure 'AppData\Roaming\Code\User\settings.json'
        $c = Get-TestContext $empty '' $forced
        Assert-Equal $null $c.UserProfile
        Assert-Equal $forced $c.VSCode.UserSettings.Path
        Assert-Equal @('vscode-copilot') $c.Harnesses
        Assert-Equal 200 $c.VSCode.Effective['chat.agent.maxRequests'].Value
    }
    It 'rejects invalid paths' {
        Assert-Throws { Get-TestContext (Join-Path $tmp 'missing') } -ExpectedMessage 'not a directory'
        Assert-Throws { Get-TestContext $empty (Join-Path $tmp 'missing-profile') } -ExpectedMessage 'not a directory'
        Assert-Throws { Get-TestContext $empty '' (Join-Path $tmp 'missing.json') } -ExpectedMessage 'does not exist'
    }
}

Describe 'Discovery: hostile files' {
    It 'skips files larger than 2 MB' {
        $root = Join-Path $tmp 'big'
        New-TestFile (Join-Path $root '.vscode\settings.json') ('{"a":"' + ('x' * (2MB + 10)) + '"}')
        $ctx = Get-TestContext $root
        Assert-Equal $null $ctx.VSCode.WorkspaceSettings
        Assert-Match (@($ctx.Errors)[0].Evidence) 'larger than 2 MB'
        Assert-Contains $ctx.Harnesses 'vscode-copilot'
    }
    It 'does not follow a junction that leaves the root' {
        $outside = Join-Path $tmp 'outside'
        New-TestFile (Join-Path $outside 'settings.json') '{"chat.tools.global.autoApprove": true}'
        New-TestFile (Join-Path $outside 'secret.md') 'outside content'
        $root = Join-Path $tmp 'linked'
        [void][System.IO.Directory]::CreateDirectory($root)
        $link = Join-Path $root '.vscode'
        $agentsLink = Join-Path $root '.github'
        try {
            New-Item -ItemType Junction -Path $link -Target $outside | Out-Null
            [void][System.IO.Directory]::CreateDirectory((Join-Path $root 'real'))
            New-TestFile (Join-Path $root 'real\copilot-instructions.md') 'inside content'
            New-Item -ItemType Junction -Path $agentsLink -Target (Join-Path $root 'real') | Out-Null
        } catch {
            Write-Host "      (skipped: cannot create a junction here: $($_.Exception.Message))" -ForegroundColor Yellow
            return
        }
        try {
            $ctx = Get-TestContext $root
            Assert-Equal $null $ctx.VSCode.WorkspaceSettings
            Assert-Match (($ctx.Errors | ForEach-Object { $_.Evidence }) -join ' ') 'leads outside the analyzed root'
            $inside = @($ctx.AgentFiles | Where-Object { $_.Kind -eq 'copilot-instructions' })
            Assert-Equal 1 $inside.Count
            Assert-Match $inside[0].Body 'inside content'
        } finally {
            [System.IO.Directory]::Delete($link)
            [System.IO.Directory]::Delete($agentsLink)
        }
        Assert-True (Test-Path (Join-Path $outside 'settings.json')) 'the junction target must survive the cleanup'
    }
    It 'enforces the total read budget' {
        & $aw { $script:SavedBudget = $script:AwMaxTotalBytes; $script:AwMaxTotalBytes = 600 }
        try {
            $ctx = Get-TestContext $insecure
            Assert-Match (($ctx.Errors | ForEach-Object { $_.Evidence }) -join ' ') 'read budget'
        } finally {
            & $aw { $script:AwMaxTotalBytes = $script:SavedBudget }
        }
    }
    It 'caps the number of files per folder' {
        $root = Join-Path $tmp 'many'
        foreach ($i in 1..3) { New-TestFile (Join-Path $root ".github\prompts\p$i.prompt.md") "---`ntools: []`n---`nx" }
        & $aw { $script:SavedGlob = $script:AwMaxFilesPerGlob; $script:AwMaxFilesPerGlob = 2 }
        try {
            $ctx = Get-TestContext $root
            Assert-Equal 2 @($ctx.AgentFiles).Count
            Assert-Match (@($ctx.Errors)[0].Evidence) 'More than 2 files'
        } finally {
            & $aw { $script:AwMaxFilesPerGlob = $script:SavedGlob }
        }
    }
}

Describe 'Scoring' {
    It 'scores 100 / A with no finding and no applicable category' {
        $s = Get-TestScore @() @() @()
        Assert-Equal @('Score', 'Grade', 'Categories', 'Counts') @($s.PSObject.Properties.Name)
        Assert-Equal 100 $s.Score; Assert-Equal 'A' $s.Grade
        Assert-Equal @('approvals', 'sandbox-network', 'mcp-supply-chain', 'agent-files', 'secrets', 'observability') @($s.Categories.Keys)
        Assert-Equal @('Title', 'Score', 'Applicable', 'Findings') @($s.Categories['approvals'].Keys)
        Assert-Equal 'Approvals and terminal' $s.Categories['approvals'].Title
        Assert-Equal $false $s.Categories['approvals'].Applicable
        Assert-Equal @('critical', 'high', 'medium', 'low', 'info') @($s.Counts.Keys)
    }
    It 'removes the severity weight for a first finding' {
        $s = Get-TestScore @(New-TestFinding 'R1' 'high' 'approvals') @(New-TestRule 'R1' 'approvals') @()
        Assert-Equal 80 $s.Categories['approvals'].Score
        Assert-Equal 1 $s.Categories['approvals'].Findings
        Assert-Equal 80 $s.Score; Assert-Equal 'B' $s.Grade
        Assert-Equal 1 $s.Counts['high']
    }
    It 'removes 25% for each further finding of the same rule, capped at 2x' {
        $three = @(1..3 | ForEach-Object { New-TestFinding 'R1' 'high' 'approvals' })
        Assert-Equal 70 (Get-TestScore $three @(New-TestRule 'R1' 'approvals') @()).Score
        $ten = @(1..10 | ForEach-Object { New-TestFinding 'R1' 'high' 'approvals' })
        Assert-Equal 60 (Get-TestScore $ten @(New-TestRule 'R1' 'approvals') @()).Score
    }
    It 'uses the highest severity first when a rule mixes severities' {
        $f = @((New-TestFinding 'R1' 'medium' 'approvals'), (New-TestFinding 'R1' 'high' 'approvals'))
        Assert-Equal 78 (Get-TestScore $f @(New-TestRule 'R1' 'approvals') @()).Categories['approvals'].Score
    }
    It 'adds up different rules and floors a category at 0' {
        $rules = @((New-TestRule 'R1' 'approvals'), (New-TestRule 'R2' 'approvals'), (New-TestRule 'R3' 'approvals'))
        $two = @((New-TestFinding 'R1' 'high' 'approvals'), (New-TestFinding 'R2' 'high' 'approvals'))
        Assert-Equal 60 (Get-TestScore $two $rules @()).Score
        $crit = @((New-TestFinding 'R1' 'critical' 'approvals'), (New-TestFinding 'R2' 'critical' 'approvals'), (New-TestFinding 'R3' 'critical' 'approvals'))
        $s = Get-TestScore $crit $rules @()
        Assert-Equal 0 $s.Categories['approvals'].Score
        Assert-Equal 0 $s.Score; Assert-Equal 'F' $s.Grade
    }
    It 'averages applicable categories with their weights' {
        $rules = @((New-TestRule 'R1' 'approvals'), (New-TestRule 'S1' 'secrets'))
        $s = Get-TestScore @(New-TestFinding 'R1' 'high' 'approvals') $rules @()
        Assert-Equal 88 $s.Score     # (80*25 + 100*15) / 40 = 87.5, rounded half away from zero
        Assert-Equal 'B' $s.Grade
    }
    It 'caps the score at 69 when a critical finding exists' {
        $rules = @((New-TestRule 'R1' 'approvals'), (New-TestRule 'S1' 'secrets'))
        $s = Get-TestScore @(New-TestFinding 'S1' 'critical' 'secrets') $rules @()
        Assert-Equal 60 $s.Categories['secrets'].Score
        Assert-Equal 69 $s.Score      # 85 before the cap
        Assert-Equal 'D' $s.Grade
    }
    It 'ignores categories whose rules target an undetected harness' {
        $rules = @((New-TestRule 'R1' 'approvals' 'vscode-copilot'), (New-TestRule 'M1' 'mcp-supply-chain' 'mcp'))
        $s = Get-TestScore @(New-TestFinding 'M1' 'high' 'mcp-supply-chain') $rules @('vscode-copilot')
        Assert-Equal $true $s.Categories['approvals'].Applicable
        Assert-Equal $false $s.Categories['mcp-supply-chain'].Applicable
        Assert-Equal 80 $s.Categories['mcp-supply-chain'].Score
        Assert-Equal 100 $s.Score
        $t = Get-TestScore @(New-TestFinding 'M1' 'high' 'mcp-supply-chain') $rules @('vscode-copilot', 'mcp')
        Assert-Equal 91 $t.Score      # (100*25 + 80*20) / 45 = 91.1
    }
    It 'makes a category applicable through a generic rule' {
        $s = Get-TestScore @(New-TestFinding 'G1' 'medium' 'secrets') @(New-TestRule 'G1' 'secrets' 'generic') @()
        Assert-Equal $true $s.Categories['secrets'].Applicable
        Assert-Equal 92 $s.Score
    }
    It 'counts info findings without deducting points' {
        $s = Get-TestScore @((New-TestFinding 'I1' 'info' 'observability'), (New-TestFinding 'I1' 'info' 'observability')) @(New-TestRule 'I1' 'observability') @()
        Assert-Equal 100 $s.Score
        Assert-Equal 2 $s.Counts['info']
        Assert-Equal 2 $s.Categories['observability'].Findings
    }
    It 'rounds fractional deductions half away from zero' {
        $f = @(1..3 | ForEach-Object { New-TestFinding 'L1' 'low' 'secrets' })   # 3 + 0.75 + 0.75 = 4.5
        $s = Get-TestScore $f @(New-TestRule 'L1' 'secrets') @()
        Assert-Equal 96 $s.Categories['secrets'].Score
        Assert-Equal 96 $s.Score
    }
    It 'maps scores to grades at the documented thresholds' {
        $grades = & $aw { @(100, 90, 89, 80, 79, 70, 69, 60, 59, 0) | ForEach-Object { Get-AwGrade -Score $_ } }
        Assert-Equal @('A', 'A', 'B', 'B', 'C', 'C', 'D', 'D', 'F', 'F') @($grades)
    }
}

Describe 'Engine: result contract' {
    It 'returns a well-formed result for insecure before any production rule exists' {
        Save-Registry
        try {
            $r = Invoke-Airworthy -Path $insecure -NoUserProfile -PassThru -Quiet
        } finally { Restore-Registry }
        Assert-Equal @('Tool', 'ScannedAt', 'Root', 'Harnesses', 'Score', 'Findings', 'Rules', 'Errors', 'Options', 'ExitCode') @($r.PSObject.Properties.Name)
        Assert-Equal 'Airworthy' $r.Tool.Name
        Assert-Equal '0.2.0' $r.Tool.Version
        Assert-Match $r.ScannedAt '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
        Assert-Equal ([System.IO.Path]::GetFullPath($insecure)) $r.Root
        Assert-Equal @('vscode-copilot', 'claude-code', 'codex', 'mcp') $r.Harnesses
        Assert-Equal 100 $r.Score.Score
        Assert-Equal 'A' $r.Score.Grade
        Assert-True ($r.Findings -is [array]); Assert-Equal 0 $r.Findings.Count
        Assert-True ($r.Rules -is [array]); Assert-Equal 0 $r.Rules.Count
        Assert-True ($r.Errors -is [array]); Assert-Equal 0 $r.Errors.Count
        Assert-Equal @('Console') $r.Options.Format
        Assert-Equal 'info' $r.Options.MinSeverity
        Assert-Equal $true $r.Options.NoUserProfile
        Assert-Equal 0 $r.ExitCode
    }
    It 'returns well-formed findings with the registered rules' {
        $r = Invoke-Airworthy -Path $insecure -NoUserProfile -PassThru -Quiet
        $sev = @('critical', 'high', 'medium', 'low', 'info')
        foreach ($f in $r.Findings) {
            Assert-Equal 11 @($f.PSObject.Properties | Where-Object { $_.Name -ne 'Data' }).Count $f.RuleId
            Assert-Contains $sev $f.Severity
            Assert-True ($f.Location.PSObject.Properties['Path'] -ne $null) $f.RuleId
            Assert-True ($f.References -is [string[]]) $f.RuleId
        }
        foreach ($rule in $r.Rules) { Assert-Equal $null $rule.PSObject.Properties['Check'] }
    }
    It 'runs the AW-CORE-000 sample rule end to end' {
        Save-Registry
        Register-SampleRule
        try {
            $r = Invoke-Airworthy -Path $insecure -NoUserProfile -PassThru -Quiet
            $h = Invoke-Airworthy -Path $hardened -NoUserProfile -PassThru -Quiet
            $p = Invoke-Airworthy -Path $hardened -UserProfilePath $profileInsecure -PassThru -Quiet
        } finally { Restore-Registry }
        Assert-Equal 1 $r.Findings.Count
        $f = $r.Findings[0]
        Assert-Equal 'AW-CORE-000' $f.RuleId
        Assert-Equal 'high' $f.Severity
        Assert-Equal (Join-Path $insecure '.vscode\settings.json') $f.Location.Path
        Assert-Equal 5 $f.Location.Line
        Assert-Equal 'chat.tools.global.autoApprove' $f.Location.Key
        Assert-Equal @('AW-CORE-000') @($r.Rules | ForEach-Object { $_.Id })
        Assert-Equal 80 $r.Score.Categories['approvals'].Score
        Assert-Equal 80 $r.Score.Score
        Assert-Equal 'B' $r.Score.Grade
        Assert-Equal 0 $h.Findings.Count
        Assert-Equal 100 $h.Score.Score
        Assert-Equal 0 $p.Findings.Count
    }
}

Describe 'Engine: options' {
    Save-Registry
    Register-SampleRule
    try {
        It 'sets ExitCode with -FailOn' {
            Assert-Equal 1 (Invoke-Airworthy -Path $insecure -NoUserProfile -FailOn high -PassThru -Quiet).ExitCode
            Assert-Equal 1 (Invoke-Airworthy -Path $insecure -NoUserProfile -FailOn low -PassThru -Quiet).ExitCode
            Assert-Equal 0 (Invoke-Airworthy -Path $insecure -NoUserProfile -FailOn critical -PassThru -Quiet).ExitCode
            Assert-Equal 0 (Invoke-Airworthy -Path $hardened -NoUserProfile -FailOn info -PassThru -Quiet).ExitCode
        }
        It 'filters reported findings with -MinSeverity but scores every finding' {
            $r = Invoke-Airworthy -Path $insecure -NoUserProfile -MinSeverity critical -PassThru -Quiet
            Assert-Equal 0 $r.Findings.Count
            Assert-Equal 80 $r.Score.Score
            Assert-Equal 1 $r.Score.Counts['high']
            Assert-Equal 'critical' $r.Options.MinSeverity
        }
        It 'is deterministic apart from ScannedAt' {
            $a = Invoke-Airworthy -Path $mixed -NoUserProfile -PassThru -Quiet
            $b = Invoke-Airworthy -Path $mixed -NoUserProfile -PassThru -Quiet
            $a.ScannedAt = $null; $b.ScannedAt = $null
            Assert-Equal ($a | ConvertTo-Json -Depth 10) ($b | ConvertTo-Json -Depth 10)
        }
        It 'redacts paths and the user name with -Redact' {
            Register-TestRule 'AW-CORE-907' 'medium' 'profile'
            $r = Invoke-Airworthy -Path $hardened -UserProfilePath $profileInsecure -Redact -PassThru -Quiet
            $f = @($r.Findings | Where-Object { $_.RuleId -eq 'AW-CORE-907' })[0]
            Assert-Equal '~\AppData\Roaming\Code\User\settings.json' $f.Location.Path
            Assert-Equal 'user file ~\AppData\Roaming\Code\User\settings.json' $f.Evidence
            Assert-NotMatch $f.Evidence ([regex]::Escape($profileInsecure))
            Assert-Equal $true $r.Options.Redact
            Assert-Equal '~' $r.Options.UserProfilePath
            $s = Invoke-Airworthy -Path $insecure -NoUserProfile -Redact -PassThru -Quiet
            Assert-Equal '.vscode\settings.json' @($s.Findings | Where-Object { $_.RuleId -eq 'AW-CORE-000' })[0].Location.Path
        }
        It 'replaces the absolute root with its leaf folder name with -Redact' {
            Register-TestRule 'AW-CORE-908' 'low' 'roottext'
            $plain = Invoke-Airworthy -Path $insecure -NoUserProfile -PassThru -Quiet
            Assert-Equal $insecure $plain.Root
            $r = Invoke-Airworthy -Path $insecure -NoUserProfile -Redact -OutFile (Join-Path $tmp 'redact-out\report') -PassThru -Quiet
            Assert-Equal 'insecure' $r.Root
            Assert-Equal 'report' $r.Options.OutFile
            $f = @($r.Findings | Where-Object { $_.RuleId -eq 'AW-CORE-908' })[0]
            Assert-Equal '.mcp.json' $f.Location.Path
            Assert-Equal 'insecure' $f.Location.Key
            Assert-Equal 'cannot read insecure\.mcp.json' $f.Evidence
            Assert-Equal 'Cannot read insecure\.mcp.json' $f.Title
            foreach ($x in @($r.Findings)) {
                foreach ($t in @($x.Location.Path, $x.Location.Key, $x.Evidence, $x.Title)) {
                    Assert-False ([string]$t).Contains($fixtures) "$($x.RuleId): $t"
                }
            }
            $p = Invoke-Airworthy -Path $hardened -UserProfilePath $profileInsecure -UserSettingsPath (Join-Path $profileInsecure 'AppData\Roaming\Code\User\settings.json') -Redact -PassThru -Quiet
            Assert-Equal 'hardened' $p.Root
            Assert-Equal '~' $p.Options.UserProfilePath
            Assert-Equal '~\AppData\Roaming\Code\User\settings.json' $p.Options.UserSettingsPath
        }
    } finally { Restore-Registry }
}

Describe 'Engine: robustness' {
    Save-Registry
    try {
        It 'turns a rule exception into AW-CORE-002 and keeps going' {
            Register-TestRule 'AW-CORE-901' 'high' 'throw'
            Register-TestRule 'AW-CORE-902' 'low' 'one'
            $r = Invoke-Airworthy -Path $insecure -NoUserProfile -PassThru -Quiet
            $fail = @($r.Findings | Where-Object { $_.RuleId -eq 'AW-CORE-002' })
            Assert-Equal 1 $fail.Count
            Assert-Equal 'info' $fail[0].Severity
            Assert-Equal 'Rule failed: AW-CORE-901' $fail[0].Title
            Assert-Equal 'AW-CORE-901' $fail[0].Location.Key
            Assert-Match $fail[0].Evidence 'synthetic failure'
            Assert-NotMatch $fail[0].Evidence 'FAKEFAKEFAKEFAKE'
            Assert-Equal 1 @($r.Findings | Where-Object { $_.RuleId -eq 'AW-CORE-902' }).Count
            Assert-Equal 1 @($r.Errors | Where-Object { $_.RuleId -eq 'AW-CORE-002' }).Count
            Assert-Contains @($r.Rules | ForEach-Object { $_.Id }) 'AW-CORE-002'
            Remove-TestRules
        }
        It 'reports invalid rule output and completes partial findings' {
            Register-TestRule 'AW-CORE-903' 'high' 'string'
            Register-TestRule 'AW-CORE-904' 'medium' 'partial'
            $r = Invoke-Airworthy -Path $insecure -NoUserProfile -PassThru -Quiet
            Assert-Match (@($r.Findings | Where-Object { $_.RuleId -eq 'AW-CORE-002' })[0].Evidence) 'not a finding'
            $p = @($r.Findings | Where-Object { $_.RuleId -eq 'AW-CORE-904' })[0]
            Assert-Equal 'medium' $p.Severity
            Assert-Equal 'secrets' $p.Category
            Assert-Equal 'Test rule AW-CORE-904' $p.Title
            Assert-Equal 'partial evidence' $p.Evidence
            Assert-Equal $null $p.Location.Line
            Assert-Equal 11 @($p.PSObject.Properties).Count
            Remove-TestRules
        }
        It 'collapses identical findings and sorts by severity then rule' {
            Register-TestRule 'AW-CORE-905' 'low' 'duplicate'
            Register-TestRule 'AW-CORE-906' 'critical' 'one'
            Register-TestRule 'AW-CORE-908' 'critical' 'one'
            $r = Invoke-Airworthy -Path $insecure -NoUserProfile -PassThru -Quiet
            Assert-Equal @('AW-CORE-906', 'AW-CORE-908', 'AW-CORE-905') @($r.Findings | ForEach-Object { $_.RuleId })
            Assert-True ($r.Score.Score -le 69)
            Remove-TestRules
        }
        It 'includes discovery errors in Findings and Errors' {
            $r = Invoke-Airworthy -Path $edge -NoUserProfile -PassThru -Quiet
            $core = @($r.Findings | Where-Object { $_.RuleId -eq 'AW-CORE-001' })
            Assert-True ($core.Count -ge 4)
            Assert-Equal $core.Count @($r.Errors).Count
            Assert-Contains @($r.Rules | ForEach-Object { $_.Id }) 'AW-CORE-001'
            Assert-Equal 100 $r.Score.Score
        }
        It 'reports files that failed to load as AW-CORE-002' {
            & $aw { $script:AwLoadErrors = @([pscustomobject]@{ File = 'src/Rules/Broken.ps1'; Message = 'boom' }) }
            try {
                $r = Invoke-Airworthy -Path $hardened -NoUserProfile -PassThru -Quiet
            } finally { & $aw { $script:AwLoadErrors = @() } }
            $f = @($r.Findings | Where-Object { $_.RuleId -eq 'AW-CORE-002' })
            Assert-Equal 1 $f.Count
            Assert-Match $f[0].Title 'Broken\.ps1'
            Assert-Equal 'boom' $f[0].Evidence
        }
    } finally { Restore-Registry }
}

Describe 'Engine: rendering' {
    Save-Registry
    $names = @('ConvertTo-AwConsole', 'ConvertTo-AwJson', 'ConvertTo-AwSarif', 'ConvertTo-AwMarkdown', 'ConvertTo-AwHtml')
    & $aw {
        param($n)
        $script:SavedRenderers = @{}
        foreach ($x in $n) { $f = Get-Item "function:$x" -ErrorAction SilentlyContinue; if ($f) { $script:SavedRenderers[$x] = $f.ScriptBlock } }
    } $names
    $restore = {
        & $aw {
            param($n)
            foreach ($x in $n) {
                if ($script:SavedRenderers.ContainsKey($x)) { Set-Item "function:script:$x" -Value $script:SavedRenderers[$x] }
                elseif (Test-Path "function:$x") { Remove-Item "function:$x" }
            }
        } $names
    }
    try {
        It 'warns when a renderer is not loaded' {
            & $aw { Remove-Item function:ConvertTo-AwJson -ErrorAction SilentlyContinue }
            $base = Join-Path $tmp 'missing-renderer'
            $w = $null
            Invoke-Airworthy -Path $hardened -NoUserProfile -Format Json -OutFile $base -Quiet -WarningVariable w -WarningAction SilentlyContinue
            Assert-Match ($w -join ' ') 'Json format is not available'
            Assert-False (Test-Path "$base.json")
        }
        It 'writes each requested format to <OutFile>.<ext> as UTF-8 without BOM' {
            & $aw {
                Set-Item function:script:ConvertTo-AwJson -Value { param($Result) '{"grade":"' + $Result.Score.Grade + '"}' }
                Set-Item function:script:ConvertTo-AwMarkdown -Value { param($Result) "# Score`n" + $Result.Score.Score }
                Set-Item function:script:ConvertTo-AwSarif -Value { param($Result) 'sarif' }
                Set-Item function:script:ConvertTo-AwHtml -Value { param($Result) '<p>' + $script:AwEllipsis + '</p>' }
            }
            $base = Join-Path $tmp 'out\report'
            Invoke-Airworthy -Path $hardened -NoUserProfile -Format Json, Sarif, Markdown, Html -OutFile $base -Quiet
            Assert-Equal '{"grade":"A"}' ([System.IO.File]::ReadAllText("$base.json"))
            Assert-Equal "# Score`n100" ([System.IO.File]::ReadAllText("$base.md"))
            Assert-Equal 'sarif' ([System.IO.File]::ReadAllText("$base.sarif"))
            $bytes = [System.IO.File]::ReadAllBytes("$base.html")
            Assert-False ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB) 'no BOM expected'
            Assert-Equal ('<p>' + (& $aw { $script:AwEllipsis }) + '</p>') ([System.IO.File]::ReadAllText("$base.html"))
        }
        It 'strips a known extension from -OutFile' {
            $base = Join-Path $tmp 'out\single.json'
            Invoke-Airworthy -Path $hardened -NoUserProfile -Format Json -OutFile $base -Quiet
            Assert-True (Test-Path $base)
            Assert-False (Test-Path "$base.json")
        }
        It 'writes the text to the pipeline without -OutFile, before the -PassThru result' {
            $out = @(Invoke-Airworthy -Path $hardened -NoUserProfile -Format Json -PassThru -Quiet)
            Assert-Equal 2 $out.Count
            Assert-Equal '{"grade":"A"}' $out[0]
            Assert-Equal 'Airworthy' $out[1].Tool.Name
        }
        It 'calls the console renderer unless -Quiet' {
            & $aw {
                $script:ConsoleCalls = 0
                Set-Item function:script:ConvertTo-AwConsole -Value { param($Result) $script:ConsoleCalls++ }
            }
            Invoke-Airworthy -Path $hardened -NoUserProfile | Out-Null
            Invoke-Airworthy -Path $hardened -NoUserProfile -Quiet | Out-Null
            Assert-Equal 1 (& $aw { $script:ConsoleCalls })
        }
        It 'keeps the result when a renderer throws' {
            & $aw { Set-Item function:script:ConvertTo-AwMarkdown -Value { param($Result) throw 'renderer bug' } }
            $w = $null
            $r = Invoke-Airworthy -Path $hardened -NoUserProfile -Format Markdown -OutFile (Join-Path $tmp 'out\bug') -PassThru -Quiet -WarningVariable w -WarningAction SilentlyContinue
            Assert-Match ($w -join ' ') 'renderer bug'
            Assert-Equal 'A' $r.Score.Grade
        }
    } finally {
        & $restore
        Restore-Registry
    }
}

} finally {
    Remove-TestRules
    if (Test-Path -LiteralPath $tmp) {
        # Junctions are removed above; a plain recursive delete is safe here.
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
