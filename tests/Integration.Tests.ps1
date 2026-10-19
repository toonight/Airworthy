# End-to-end tests: the shared fixtures through Invoke-Airworthy and the airworthy.ps1 wrapper,
# every output format, and the exit codes. Fixtures are synthetic and the real user profile is never
# read: every run passes -NoUserProfile or points -UserProfilePath at a fixture folder.
$repoRoot = Split-Path -Parent $PSScriptRoot
$wrapper = Join-Path $repoRoot 'airworthy.ps1'
$fixtures = Join-Path $PSScriptRoot 'fixtures'
$insecure = Join-Path $fixtures 'insecure'
$hardened = Join-Path $fixtures 'hardened'
$mixed = Join-Path $fixtures 'mixed'
$profileInsecure = Join-Path $fixtures 'profile-insecure'
$cliLocal = Join-Path $fixtures 'integration\cli-local'
$cliRepoHooks = Join-Path $fixtures 'copilotcli\repo-hooks'
$tmp = Join-Path $fixtures ('integration\_tmp-' + [guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($tmp)

$findingProperties = @('RuleId', 'Title', 'Severity', 'Category', 'Harness', 'Description', 'Evidence', 'Location', 'Fix', 'References', 'Confidence')

function Invoke-AwFixture {
    param([string]$Path, [hashtable]$Options = @{})
    Invoke-Airworthy -Path $Path -NoUserProfile -PassThru -Quiet @Options
}

function Get-AwRuleIds {
    param($Result)
    @($Result.Findings | ForEach-Object { $_.RuleId })
}

function Test-AwNoBom {
    param([string]$File)
    $bytes = [System.IO.File]::ReadAllBytes($File)
    return -not ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191)
}

function Remove-AwScanTime {
    param([string]$Json)
    return ($Json -replace '"ScannedAt":\s*"[^"]*"', '"ScannedAt": ""')
}

try {
    Describe 'Integration: shared fixtures' {
        $ri = Invoke-AwFixture $insecure
        $rh = Invoke-AwFixture $hardened
        $rm = Invoke-AwFixture $mixed

        It 'scores the insecure fixture F' {
            Assert-Equal 'F' $ri.Score.Grade
            Assert-True ($ri.Score.Score -lt 60) "score $($ri.Score.Score)"
            Assert-True ($ri.Score.Counts['critical'] -gt 0)
            Assert-True ($ri.Score.Score -le 69) 'the critical cap applies'
        }
        It 'scores the hardened fixture A or B, with nothing above medium' {
            Assert-Contains @('A', 'B') $rh.Score.Grade
            Assert-True ($rh.Score.Score -ge 80) "score $($rh.Score.Score)"
            Assert-Equal 0 @($rh.Findings | Where-Object { @('critical', 'high') -contains $_.Severity }).Count
        }
        It 'scores the mixed fixture between the insecure and the hardened ones' {
            Assert-True ($ri.Score.Score -lt $rm.Score.Score) "insecure $($ri.Score.Score), mixed $($rm.Score.Score)"
            Assert-True ($rm.Score.Score -lt $rh.Score.Score) "mixed $($rm.Score.Score), hardened $($rh.Score.Score)"
            Assert-NotContains @('A', 'F') $rm.Score.Grade
        }
        It 'detects VS Code Copilot, Claude Code, Codex CLI and MCP in each fixture' {
            foreach ($r in @($ri, $rh, $rm)) {
                foreach ($h in @('vscode-copilot', 'claude-code', 'codex', 'mcp')) { Assert-Contains $r.Harnesses $h $r.Root }
                Assert-NotContains $r.Harnesses 'copilot-cli' $r.Root
            }
        }
        It 'parses every file and runs every rule without a failure' {
            foreach ($r in @($ri, $rh, $rm)) {
                Assert-Equal 0 @($r.Errors).Count $r.Root
                Assert-Equal 0 @($r.Findings | Where-Object { $_.RuleId -like 'AW-CORE-*' }).Count $r.Root
            }
        }
        It 'reports findings from every rule area on the insecure fixture' {
            $ids = Get-AwRuleIds $ri
            foreach ($area in @('VSC', 'AGT', 'SEC', 'MCP', 'CC', 'CDX')) {
                Assert-True (@($ids | Where-Object { $_ -like "AW-$area-*" }).Count -gt 0) $area
            }
        }
        It 'returns complete findings, sorted by severity' {
            foreach ($r in @($ri, $rh, $rm)) {
                $ranks = @()
                foreach ($f in @($r.Findings)) {
                    $names = @($f.PSObject.Properties | ForEach-Object { $_.Name } | Where-Object { $_ -ne 'Data' })
                    Assert-Equal $findingProperties $names $f.RuleId
                    Assert-True ([string]$f.Fix -ne '') "$($f.RuleId) has a fix"
                    Assert-True (@($f.References).Count -gt 0) "$($f.RuleId) has references"
                    $ranks += @{ critical = 4; high = 3; medium = 2; low = 1; info = 0 }[$f.Severity]
                }
                for ($i = 1; $i -lt $ranks.Count; $i++) { Assert-True ($ranks[$i - 1] -ge $ranks[$i]) "order at $i" }
            }
        }
        It 'keeps the category and severity counts consistent with the findings' {
            foreach ($r in @($ri, $rh, $rm)) {
                $total = @($r.Findings).Count
                $byCategory = 0
                foreach ($c in $r.Score.Categories.Keys) { $byCategory += $r.Score.Categories[$c].Findings }
                $bySeverity = 0
                foreach ($s in $r.Score.Counts.Keys) { $bySeverity += $r.Score.Counts[$s] }
                Assert-Equal $total $byCategory $r.Root
                Assert-Equal $total $bySeverity $r.Root
            }
        }
        It 'gives the same output twice, apart from the scan time' {
            $a = Invoke-Airworthy -Path $mixed -NoUserProfile -Format Json -Quiet
            $b = Invoke-Airworthy -Path $mixed -NoUserProfile -Format Json -Quiet
            Assert-True ($a -is [string])
            Assert-Equal (Remove-AwScanTime $a) (Remove-AwScanTime $b)
        }
    }

    Describe 'Integration: rule catalog' {
        $rules = @(& (Get-Module Airworthy) { Get-AwRules })
        It 'registers about 40 rules or more, each with complete metadata' {
            Assert-True ($rules.Count -ge 40) "$($rules.Count) rules"
            foreach ($rule in $rules) {
                Assert-Match $rule.Id '^AW-(VSC|AGT|SEC|MCP|CC|CLI|CDX)-[0-9]{3}$'
                foreach ($field in @('Title', 'Severity', 'Category', 'Harness', 'Description', 'Fix', 'Confidence')) {
                    Assert-True ([string]$rule.$field -ne '') "$($rule.Id) $field"
                }
                Assert-True (@($rule.References | Where-Object { $_ -match '^(OWASP-ASI[0-9]{2}|https://)' }).Count -gt 0) "$($rule.Id) references"
            }
        }
    }

    Describe 'Integration: output formats' {
        It 'writes the four files with -Format Json,Sarif,Markdown,Html -OutFile' {
            $base = Join-Path $tmp 'insecure-report'
            $r = Invoke-Airworthy -Path $insecure -NoUserProfile -Format Json, Sarif, Markdown, Html -OutFile $base -PassThru -Quiet
            foreach ($ext in @('.json', '.sarif', '.md', '.html')) {
                $file = $base + $ext
                Assert-True (Test-Path -LiteralPath $file) $ext
                Assert-True ((New-Object System.IO.FileInfo -ArgumentList $file).Length -gt 1000) "$ext is not empty"
                Assert-True (Test-AwNoBom $file) "$ext has no BOM"
            }
            $aw = Get-Module Airworthy
            $json = & $aw { param($p) ConvertFrom-AwJsonc -Text ([System.IO.File]::ReadAllText($p)) } ($base + '.json')
            Assert-Equal 'Airworthy' $json['Tool']['Name']
            Assert-Equal $r.Score.Score $json['Score']['Score']
            Assert-Equal $r.Score.Grade $json['Score']['Grade']
            Assert-Equal @($r.Findings).Count @($json['Findings']).Count

            $sarif = & $aw { param($p) ConvertFrom-AwJsonc -Text ([System.IO.File]::ReadAllText($p)) } ($base + '.sarif')
            Assert-Equal '2.1.0' $sarif['version']
            Assert-Match $sarif['$schema'] 'sarif-2\.1\.0'
            Assert-Equal 1 @($sarif['runs']).Count
            $run = $sarif['runs'][0]
            Assert-Equal 'Airworthy' $run['tool']['driver']['name']
            Assert-Equal @($r.Findings).Count @($run['results']).Count
            foreach ($res in @($run['results'])) {
                Assert-Equal $res['ruleId'] $run['tool']['driver']['rules'][[int]$res['ruleIndex']]['id']
                Assert-Contains @('error', 'warning', 'note', 'none') $res['level']
            }

            $md = [System.IO.File]::ReadAllText($base + '.md')
            Assert-Match $md '^# Airworthy report'
            Assert-Match $md ('Score: ' + $r.Score.Score + '/100, grade ' + $r.Score.Grade)

            $html = [System.IO.File]::ReadAllText($base + '.html')
            Assert-Match $html '^<!DOCTYPE html>'
            Assert-Match $html 'http-equiv="Content-Security-Policy" content="default-src ''none'';'
            Assert-Match $html '<script type="application/json" id="aw-data">'
            Assert-NotMatch $html '(?i)<(script|link|img|iframe)\b[^>]*\b(src|href)\s*=\s*["'']?(https?:)?//'
            foreach ($text in @($md, $html, [System.IO.File]::ReadAllText($base + '.json'), [System.IO.File]::ReadAllText($base + '.sarif'))) {
                Assert-False $text.Contains('FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234') 'the fake token is masked'
                Assert-False $text.Contains('FAKE-tracker-secret-FAKE-0007') 'the fake Codex client secret is masked'
            }
        }
        It 'strips a known extension from -OutFile' {
            $base = Join-Path $tmp 'named'
            Invoke-Airworthy -Path $hardened -NoUserProfile -Format Markdown, Html -OutFile ($base + '.json') -Quiet
            Assert-True (Test-Path -LiteralPath ($base + '.md'))
            Assert-True (Test-Path -LiteralPath ($base + '.html'))
            Assert-False (Test-Path -LiteralPath ($base + '.json.md'))
        }
        It 'writes the formats to the pipeline without -OutFile, before the result' {
            $out = @(Invoke-Airworthy -Path $hardened -NoUserProfile -Format Json, Sarif, Markdown, Html -PassThru -Quiet)
            Assert-Equal 5 $out.Count
            for ($i = 0; $i -lt 4; $i++) { Assert-True ($out[$i] -is [string]) "item $i" }
            Assert-Match $out[0] '^\{'
            Assert-Match $out[1] '"version": "2\.1\.0"'
            Assert-Match $out[2] '^# Airworthy report'
            Assert-Match $out[3] '^<!DOCTYPE html>'
            Assert-Equal 'Airworthy' $out[4].Tool.Name
        }
        It 'prints the console report unless -Quiet' {
            $records = @(Invoke-Airworthy -Path $insecure -NoUserProfile 6>&1)
            $text = (@($records | ForEach-Object { if ($_.PSObject.Properties['MessageData']) { [string]$_.MessageData.Message } else { [string]$_ } }) -join "`n")
            Assert-Match $text 'Airworthy 0\.2\.0'
            Assert-Match $text 'grade F'
            Assert-Match $text 'AW-VSC-001'
            $quiet = @(Invoke-Airworthy -Path $insecure -NoUserProfile -Quiet 6>&1)
            Assert-Equal 0 $quiet.Count
        }
        It 'filters the reported findings with -MinSeverity but scores every finding' {
            $all = Invoke-AwFixture $insecure
            $high = Invoke-AwFixture $insecure @{ MinSeverity = 'high' }
            Assert-Equal $all.Score.Score $high.Score.Score
            Assert-True (@($high.Findings).Count -lt @($all.Findings).Count)
            Assert-Equal 0 @($high.Findings | Where-Object { @('critical', 'high') -notcontains $_.Severity }).Count
        }
        It 'hides the fixture user profile with -Redact' {
            $r = Invoke-Airworthy -Path $insecure -UserProfilePath $profileInsecure -Redact -Format Json -OutFile (Join-Path $tmp 'redacted') -PassThru -Quiet
            $fromProfile = @($r.Findings | Where-Object { [string]$_.Location.Path -like '~*' })
            Assert-True ($fromProfile.Count -gt 0) 'profile findings are reported'
            $text = [System.IO.File]::ReadAllText((Join-Path $tmp 'redacted.json'))
            Assert-False $text.Contains('profile-insecure') 'the profile folder name is not written'
        }
        It 'shows only the leaf folder name of the root with -Redact, in every format' {
            $aw = Get-Module Airworthy
            $base = Join-Path $tmp 'redacted-all'
            $r = Invoke-Airworthy -Path $insecure -NoUserProfile -Redact -Format Json, Sarif, Markdown, Html -OutFile $base -PassThru -Quiet
            Assert-Equal 'insecure' $r.Root
            # The folder above the root, as each format can write it: raw, JSON-escaped, HTML-escaped, file URI.
            $parent = Split-Path -Parent $insecure
            $forms = @($parent, $parent.Replace('\', '/'), $parent.Replace('\', '\\'), $parent.Replace('\', '\\').Replace(':', ':'),
                (& $aw { param($p) ConvertTo-AwFileUri $p } $parent))
            $texts = @{}
            foreach ($ext in @('.json', '.sarif', '.md', '.html')) {
                $text = [System.IO.File]::ReadAllText($base + $ext)
                $texts[$ext] = $text
                foreach ($form in $forms) { Assert-True ($text.IndexOf($form, [StringComparison]::OrdinalIgnoreCase) -lt 0) "$ext contains '$form'" }
                Assert-False ($text.Contains('file://') -or $text.Contains('file://')) "$ext has no file URI"
            }
            $json = & $aw { param($t) ConvertFrom-AwJsonc -Text $t } $texts['.json']
            Assert-Equal 'insecure' $json['Root']
            Assert-Equal 'redacted-all' $json['Options']['OutFile']
            $run = (& $aw { param($t) ConvertFrom-AwJsonc -Text $t } $texts['.sarif'])['runs'][0]
            Assert-False $run['originalUriBaseIds']['SRCROOT'].Contains('uri') 'SRCROOT has no absolute URI'
            foreach ($res in @($run['results'])) {
                foreach ($loc in @($res['locations'])) {
                    if ($null -eq $loc) { continue }
                    Assert-Equal 'SRCROOT' $loc['physicalLocation']['artifactLocation']['uriBaseId'] $res['ruleId']
                }
            }
            Assert-Match $texts['.md'] '\| Root \| `insecure` \|'
            Assert-True $texts['.html'].Contains('"root":"insecure"') 'the HTML model holds the leaf name'
            $records = @(Invoke-Airworthy -Path $insecure -NoUserProfile -Redact 6>&1)
            $console = (@($records | ForEach-Object { if ($_.PSObject.Properties['MessageData']) { [string]$_.MessageData.Message } else { [string]$_ } }) -join '')
            Assert-Match $console 'Root\s+insecure'
            Assert-False $console.Contains($parent) 'the console header has no absolute root'
        }
    }

    Describe 'Integration: exit codes' {
        It 'sets ExitCode from -FailOn' {
            Assert-Equal 1 (Invoke-AwFixture $insecure @{ FailOn = 'high' }).ExitCode
            Assert-Equal 1 (Invoke-AwFixture $insecure @{ FailOn = 'critical' }).ExitCode
            Assert-Equal 0 (Invoke-AwFixture $insecure).ExitCode
            Assert-Equal 1 (Invoke-AwFixture $mixed @{ FailOn = 'high' }).ExitCode
            Assert-Equal 0 (Invoke-AwFixture $hardened @{ FailOn = 'high' }).ExitCode
            Assert-Equal 0 (Invoke-AwFixture $hardened @{ FailOn = 'critical' }).ExitCode
            Assert-Equal 1 (Invoke-AwFixture $hardened @{ FailOn = 'medium' }).ExitCode
        }
        It 'counts findings hidden by -MinSeverity for -FailOn' {
            $r = Invoke-AwFixture $hardened @{ FailOn = 'medium'; MinSeverity = 'critical' }
            Assert-Equal 0 @($r.Findings).Count
            Assert-Equal 1 $r.ExitCode
        }
    }

    Describe 'Integration: Copilot CLI project files' {
        It 'reads .github/mcp.json and .github/copilot/settings.local.json' {
            $ctx = & (Get-Module Airworthy) { param($p) New-AwContext -Path $p -NoUserProfile } $cliLocal
            Assert-Equal @('project', 'local') @($ctx.CopilotCli | ForEach-Object { $_.Scope })
            $mcp = @($ctx.McpFiles | Where-Object { $_.Path -like '*\.github\mcp.json' })
            Assert-Equal 1 $mcp.Count
            Assert-Equal 'copilot-cli' $mcp[0].Harness
            Assert-Equal @('search') @($mcp[0].Data['Servers'].Keys)
            Assert-Contains $ctx.Harnesses 'copilot-cli'
            Assert-Contains $ctx.Harnesses 'mcp'
        }
        It 'reports the servers of .github/mcp.json' {
            $r = Invoke-AwFixture $cliLocal
            $f = @($r.Findings | Where-Object { $_.RuleId -eq 'AW-MCP-001' })
            Assert-Equal 1 $f.Count
            Assert-Match $f[0].Location.Path '\.github\\mcp\.json$'
        }
        It 'lets settings.local.json turn the repository hooks off' {
            Assert-Equal 0 @(Get-AwRuleIds (Invoke-AwFixture $cliLocal) | Where-Object { $_ -eq 'AW-CLI-003' }).Count
            Assert-Equal 2 @(Get-AwRuleIds (Invoke-AwFixture $cliRepoHooks) | Where-Object { $_ -eq 'AW-CLI-003' }).Count
        }
    }

    # The wrapper re-imports the module, so these tests come last.
    Describe 'Integration: airworthy.ps1 wrapper' {
        It 'exits with 1 when -FailOn is reached, and 0 otherwise' {
            & $wrapper -Path $insecure -NoUserProfile -FailOn high -Quiet
            Assert-Equal 1 $LASTEXITCODE
            & $wrapper -Path $hardened -NoUserProfile -FailOn high -Quiet
            Assert-Equal 0 $LASTEXITCODE
            & $wrapper -Path $insecure -NoUserProfile -Quiet
            Assert-Equal 0 $LASTEXITCODE
        }
        It 'exits with 2 when the analysis cannot run' {
            & $wrapper -Path (Join-Path $tmp 'missing-folder') -NoUserProfile -Quiet
            Assert-Equal 2 $LASTEXITCODE
            & $wrapper -Path $hardened -NoUserProfile -FailOn 'severe' -Quiet
            Assert-Equal 2 $LASTEXITCODE
            & $wrapper -Path $hardened -NoUserProfile -Format 'Json,Pdf' -Quiet
            Assert-Equal 2 $LASTEXITCODE
        }
        It 'accepts a comma-separated -Format, as powershell.exe -File passes it' {
            $base = Join-Path $tmp 'wrapper-report'
            & $wrapper -Path $insecure -NoUserProfile -Format 'Json,Sarif,Markdown,Html' -OutFile $base -Quiet
            Assert-Equal 0 $LASTEXITCODE
            foreach ($ext in @('.json', '.sarif', '.md', '.html')) { Assert-True (Test-Path -LiteralPath ($base + $ext)) $ext }
        }
        It 'returns the rendered text, and the result only with -PassThru' {
            $out = @(& $wrapper -Path $hardened -NoUserProfile -Format Json)
            Assert-Equal 1 $out.Count
            Assert-True ($out[0] -is [string])
            $out = @(& $wrapper -Path $hardened -NoUserProfile -Format Json -PassThru)
            Assert-Equal 2 $out.Count
            Assert-Equal 'A' $out[1].Score.Grade
        }
        It 'forwards -UserProfilePath, -Redact and -MinSeverity' {
            $out = @(& $wrapper -Path $insecure -UserProfilePath $profileInsecure -Redact -MinSeverity high -PassThru -Quiet)
            Assert-Equal 1 $out.Count
            $r = $out[0]
            Assert-True $r.Options.Redact
            Assert-Equal 'high' $r.Options.MinSeverity
            Assert-Equal 0 @($r.Findings | Where-Object { @('critical', 'high') -notcontains $_.Severity }).Count
            Assert-True (@($r.Findings | Where-Object { [string]$_.Location.Path -like '~*' }).Count -gt 0)
        }
        It 'is plain ASCII' {
            Assert-Equal 0 @([System.IO.File]::ReadAllBytes($wrapper) | Where-Object { $_ -gt 127 }).Count
        }
    }
} finally {
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force }
}
