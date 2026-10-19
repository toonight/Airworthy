# Tests for src/Output/Html.ps1: document structure, inert data embedding, CSP hashes and renderer safety.
# Every result here is synthetic: nothing is read from disk except the module and the test fixtures.
$aw = Get-Module Airworthy
$moduleRoot = Split-Path -Parent $PSScriptRoot
$insecure = Join-Path $PSScriptRoot 'fixtures\insecure'
$tmp = Join-Path $PSScriptRoot ('fixtures\html\_tmp-' + [guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($tmp)

# Hostile values (benign markers only), special characters, expected escapes and the API names the
# renderer must never use live in fixtures/html/vectors.json as JSON escapes, so this script holds none.
$vectors = & $aw { param($p) ConvertFrom-AwJsonc -Text ([System.IO.File]::ReadAllText($p)) } (Join-Path $PSScriptRoot 'fixtures\html\vectors.json')
$Hostile = $vectors['hostile']
$ScriptOpen = '<script>'
$ScriptClose = '</script>'
$StyleOpen = '<style>'
$StyleClose = '</style>'
$DataOpen = '<script type="application/json" id="aw-data">'
$Root = 'C:\FAKE\repo'
$CategoryIds = @('approvals', 'sandbox-network', 'mcp-supply-chain', 'agent-files', 'secrets', 'observability')

function New-TestFinding {
    param([string]$RuleId, [string]$Severity, [string]$Category, [string]$Text, $Path, $Line, [string[]]$References)
    [pscustomobject]@{
        RuleId = $RuleId; Title = "Title $Text"; Severity = $Severity; Category = $Category; Harness = 'vscode-copilot'
        Description = "Description $Text"; Evidence = "Evidence $Text"
        Location = [pscustomobject]@{ Path = $Path; Line = $Line; Key = "chat.key.$Text" }
        Fix = "Fix $Text"; References = $References; Confidence = 'medium'
    }
}

function New-TestOptions {
    [ordered]@{ Format = [string[]]@('Html'); OutFile = $null; MinSeverity = 'info'; FailOn = 'high'; Redact = $false
                NoUserProfile = $true; UserProfilePath = $null; UserSettingsPath = $null }
}

function New-TestResult {
    param([string]$Text = 'plain', [string]$Grade = 'F', [string]$RootPath = $Root)
    $findings = @(
        (New-TestFinding 'AW-VSC-001' 'critical' 'approvals' $Text ($RootPath + '\.vscode\settings' + $Text + '.json') 12 `
            @('https://code.visualstudio.com/docs/copilot/security', $vectors['badReference'], 'https://unlisted.example/x', 'OWASP-ASI02'))
        (New-TestFinding 'AW-MCP-001' $vectors['badSeverity'] 'mcp-supply-chain' $Text 'D:\elsewhere\mcp.json' $null `
            @('https://modelcontextprotocol.io/specification'))
        (New-TestFinding 'AW-SEC-001' 'low' 'secrets' $Text $null $null @())
    )
    $core = [pscustomobject]@{
        RuleId = 'AW-CORE-001'; Title = "Unreadable file $Text"; Severity = 'info'; Category = 'observability'; Harness = 'generic'
        Description = 'd'; Evidence = "Invalid JSON $Text"; Location = [pscustomobject]@{ Path = ($RootPath + '\.mcp.json'); Line = $null; Key = $null }
        Fix = 'f'; References = @(); Confidence = 'high'
    }
    $categories = [ordered]@{}
    foreach ($id in $CategoryIds) {
        $categories[$id] = [ordered]@{ Title = "Category $id"; Score = 50; Applicable = ($id -ne 'agent-files'); Findings = 1 }
    }
    [pscustomobject]@{
        Tool      = [ordered]@{ Name = 'Airworthy'; Version = '0.2.0' }
        ScannedAt = '2026-10-18T12:00:00Z'
        Root      = $RootPath
        Harnesses = [string[]]@('vscode-copilot', 'mcp', $Text)
        Score     = [pscustomobject]@{ Score = 41; Grade = $Grade; Categories = $categories
                                       Counts = [ordered]@{ critical = 1; high = 0; medium = 0; low = 1; info = 2 } }
        Findings  = @($findings + $core)
        Rules     = @(
            [pscustomobject]@{ Id = 'AW-VSC-001'; Title = "Rule $Text"; Severity = 'critical'; Category = 'approvals'; Harness = 'vscode-copilot'
                               Description = 'd'; Fix = 'f'; References = [string[]]@(); Confidence = 'high' }
            [pscustomobject]@{ Id = 'AW-MCP-001'; Title = 'MCP rule'; Severity = 'high'; Category = 'mcp-supply-chain'; Harness = 'mcp'
                               Description = 'd'; Fix = 'f'; References = [string[]]@(); Confidence = 'medium' }
        )
        Errors    = @($core)
        Options   = New-TestOptions
        ExitCode  = 1
    }
}

function New-EmptyResult {
    # A clean analysis: no finding, no applicable rule, no error.
    $categories = [ordered]@{}
    foreach ($id in $CategoryIds) { $categories[$id] = [ordered]@{ Title = "Category $id"; Score = 100; Applicable = $false; Findings = 0 } }
    [pscustomobject]@{
        Tool      = [ordered]@{ Name = 'Airworthy'; Version = '0.2.0' }
        ScannedAt = '2026-10-18T12:00:00Z'
        Root      = $Root
        Harnesses = [string[]]@()
        Score     = [pscustomobject]@{ Score = 100; Grade = 'A'; Categories = $categories
                                       Counts = [ordered]@{ critical = 0; high = 0; medium = 0; low = 0; info = 0 } }
        Findings  = @()
        Rules     = @()
        Errors    = @()
        Options   = New-TestOptions
        ExitCode  = 0
    }
}

function ConvertTo-TestHtml($Result) { & $aw { param($r) ConvertTo-AwHtml $r } $Result }
function Get-CspHash([string]$Text) { & $aw { param($t) Get-AwHtmlCspHash -Text $t } $Text }
function Get-Sha256Hex([string]$Text) {
    [byte[]]$digest = & $aw { param($t) Get-AwHtmlSha256 -Text $t } $Text
    [BitConverter]::ToString($digest).Replace('-', '')
}
function Get-Block([string]$Html, [string]$OpenTag, [string]$CloseTag) {
    $start = $Html.IndexOf($OpenTag, [StringComparison]::Ordinal)
    if ($start -lt 0) { throw "No block opened by $OpenTag" }
    $start += $OpenTag.Length
    $end = $Html.IndexOf($CloseTag, $start, [StringComparison]::Ordinal)
    if ($end -lt 0) { throw "Unclosed block opened by $OpenTag" }
    $Html.Substring($start, $end - $start)
}
function Get-DataBlock([string]$Html) { Get-Block $Html $DataOpen $ScriptClose }
function Get-RendererScript([string]$Html) { Get-Block $Html $ScriptOpen $ScriptClose }
function Get-StyleSheet([string]$Html) { Get-Block $Html $StyleOpen $StyleClose }
function Get-Csp([string]$Html) { [regex]::Match($Html, '<meta http-equiv="Content-Security-Policy" content="([^"]*)">').Groups[1].Value }
function Read-TestData([string]$Html) { & $aw { param($t) ConvertFrom-AwJsonc -Text $t } (Get-DataBlock $Html) }
function Remove-DataBlock([string]$Html) { $Html.Replace((Get-DataBlock $Html), '') }
function Get-Tags([string]$Html, [string]$Name) {
    @([regex]::Matches($Html, ('<' + $Name + '\b[^>]*>|</' + $Name + '\s*>'), 'IgnoreCase') | ForEach-Object { $_.Value })
}
function Test-Has([string]$Text, [string]$Needle) { $Text.IndexOf($Needle, [StringComparison]::OrdinalIgnoreCase) -ge 0 }
# Expected JSON escape text from a fixture value in which '~' stands for the backslash.
function Get-Escaped([string]$Value) { $Value.Replace('~', '\') }
# True when the text holds only printable ASCII (and line feeds when -AllowLineFeed).
function Test-PrintableAscii([string]$Text, [switch]$AllowLineFeed) {
    if ($AllowLineFeed) { return ($Text -cnotmatch '[^\n\x20-\x7E]') }
    return ($Text -cnotmatch '[^\x20-\x7E]')
}

try {
    $plain = ConvertTo-TestHtml (New-TestResult)
    $hostileHtml = ConvertTo-TestHtml (New-TestResult -Text $Hostile -Grade $vectors['badGrade'])
    $emptyHtml = ConvertTo-TestHtml (New-EmptyResult)
    $allHtml = @($plain, $hostileHtml, $emptyHtml)

    Describe 'Html: document structure' {
        It 'returns one string holding a complete HTML document' {
            $out = @(ConvertTo-TestHtml (New-TestResult))
            Assert-Equal 1 $out.Count
            Assert-True ($out[0] -is [string])
            Assert-True ($out[0].StartsWith('<!DOCTYPE html>')) 'doctype first'
            Assert-True ($out[0].TrimEnd().EndsWith('</html>')) 'ends with the html end tag'
        }
        It 'declares UTF-8, the CSP and no-referrer before any style or script' {
            $charset = $plain.IndexOf('<meta charset="utf-8">')
            $csp = $plain.IndexOf('<meta http-equiv="Content-Security-Policy"')
            $referrer = $plain.IndexOf('<meta name="referrer" content="no-referrer">')
            $first = [Math]::Min($plain.IndexOf('<style'), $plain.IndexOf('<script'))
            Assert-True ($charset -ge 0 -and $charset -lt 200) 'charset within the first bytes'
            Assert-True ($csp -gt $charset -and $csp -lt $first) 'CSP before the first style or script'
            Assert-True ($referrer -gt 0 -and $referrer -lt $first) 'referrer policy before the first style or script'
        }
        It 'contains exactly two balanced script elements, with hostile data and with no findings' {
            foreach ($html in $allHtml) {
                $tags = Get-Tags $html 'script'
                Assert-Equal 4 $tags.Count
                Assert-Equal $ScriptOpen $tags[0]
                Assert-Equal $ScriptClose $tags[1]
                Assert-Equal $DataOpen $tags[2]
                Assert-Equal $ScriptClose $tags[3]
            }
        }
        It 'contains exactly one style element and no style attribute' {
            foreach ($html in $allHtml) {
                Assert-Equal 2 (Get-Tags $html 'style').Count
                Assert-NotMatch (Remove-DataBlock $html) '\sstyle\s*='
            }
        }
        It 'has the elements the renderer fills' {
            foreach ($id in @('aw-data', 'aw-theme', 'aw-gauge', 'aw-arc', 'aw-grade', 'aw-categories', 'aw-chips', 'aw-search',
                              'aw-category', 'aw-harness', 'aw-sort', 'aw-findings', 'aw-rules', 'aw-coverage', 'aw-status',
                              'aw-filters', 'aw-empty', 'aw-notes')) {
                Assert-Match $plain ('id="' + $id + '"')
            }
        }
        It 'labels the controls for assistive technology' {
            foreach ($id in @('aw-search', 'aw-category', 'aw-harness', 'aw-sort')) { Assert-Match $plain ('<label for="' + $id + '">') }
            Assert-Match $plain 'role="group" aria-label="Filter by severity"'
            Assert-Match $plain 'role="status" aria-live="polite"'
            Assert-Match $plain 'id="aw-theme" aria-pressed="false"'
            Assert-Match $plain '<html lang="en">'
        }
        It 'styles light, dark, print and reduced-motion modes' {
            Assert-Match $plain '@media \(prefers-color-scheme: dark\)'
            Assert-Match $plain ':root\[data-theme="dark"\]'
            Assert-Match $plain '@media print'
            Assert-Match $plain '@media \(prefers-reduced-motion: reduce\)'
        }
        It 'uses LF line endings only' {
            Assert-NotMatch $hostileHtml '\r'
        }
        It 'loads nothing from outside the file' {
            foreach ($html in $allHtml) {
                $markup = (Remove-DataBlock $html).Replace((Get-RendererScript $html), '')
                foreach ($marker in $vectors['externalMarkers']) { Assert-False (Test-Has $markup $marker) "markup has '$marker'" }
            }
            $renderer = Get-RendererScript $plain
            foreach ($api in $vectors['networkApis']) { Assert-False (Test-Has $renderer $api) "renderer has '$api'" }
        }
        It 'is deterministic' {
            Assert-Equal $plain (ConvertTo-TestHtml (New-TestResult))
        }
    }

    Describe 'Html: Content-Security-Policy' {
        It 'computes a correct SHA-256 digest (known answer for "abc")' {
            Assert-Equal $vectors['sha256AbcHex'] (Get-Sha256Hex 'abc')
        }
        It 'formats the digest as a CSP hash source' {
            $h = Get-CspHash 'abc'
            Assert-Match $h "^'sha256-[A-Za-z0-9+/]{43}='$"
            Assert-Equal $h (Get-CspHash 'abc')
            Assert-False ($h -ceq (Get-CspHash 'abd')) 'different text, different hash'
        }
        It 'allows only the inline stylesheet and renderer script, by their SHA-256 hashes' {
            foreach ($html in $allHtml) {
                $expected = "default-src 'none'; style-src " + (Get-CspHash (Get-StyleSheet $html)) + '; script-src ' +
                    (Get-CspHash (Get-RendererScript $html)) + "; base-uri 'none'; form-action 'none'"
                Assert-Equal $expected (Get-Csp $html)
            }
        }
        It 'allows no inline code, no eval and no network or data source' {
            $csp = Get-Csp $plain
            Assert-Match $csp "^default-src 'none';"
            Assert-NotMatch $csp 'unsafe-|https?:|data:|blob:|\*'
        }
        It 'keeps the same script, stylesheet and policy whatever the data' {
            foreach ($html in @($hostileHtml, $emptyHtml)) {
                Assert-Equal (Get-RendererScript $plain) (Get-RendererScript $html)
                Assert-Equal (Get-StyleSheet $plain) (Get-StyleSheet $html)
                Assert-Equal (Get-Csp $plain) (Get-Csp $html)
            }
        }
    }

    Describe 'Html: hostile data stays inert' {
        $data = Get-DataBlock $hostileHtml
        It 'leaves no tag, comment, entity, URL scheme or line separator raw in the data block' {
            Assert-Equal 10 @($vectors['rawInData']).Count
            $i = 0
            foreach ($bad in $vectors['rawInData']) {
                $i++
                Assert-False (Test-Has $data $bad) "raw sequence #$i of rawInData in the data block"
            }
        }
        It 'writes them as JSON escapes' {
            foreach ($code in $vectors['escapedCodes']) { Assert-True ($data.Contains('\u' + $code)) "missing escape for U+$code" }
        }
        It 'writes the data block in printable ASCII only' {
            Assert-True (Test-PrintableAscii $data)
        }
        It 'round-trips every hostile value exactly' {
            $d = Read-TestData $hostileHtml
            $f = $d['findings'][0]
            Assert-Equal "Title $Hostile" $f['title']
            Assert-Equal "Evidence $Hostile" $f['evidence']
            Assert-Equal "Description $Hostile" $f['description']
            Assert-Equal "Fix $Hostile" $f['fix']
            Assert-Equal "chat.key.$Hostile" $f['key']
            Assert-Equal ('.vscode\settings' + $Hostile + '.json') $f['path']
            Assert-Contains $f['references'] $vectors['badReference']
            Assert-Equal "Rule $Hostile" $d['rules'][0]['title']
            Assert-Equal "Unreadable file $Hostile" $d['errors'][0]['title']
            Assert-Contains $d['harnesses'] $Hostile
        }
        It 'round-trips a hostile root folder' {
            $rootHostile = 'C:\FAKE\' + $Hostile
            $html = ConvertTo-TestHtml (New-TestResult -RootPath $rootHostile)
            Assert-Equal $rootHostile (Read-TestData $html)['root']
            Assert-Equal 4 (Get-Tags $html 'script').Count
        }
        It 'keeps hostile text out of the markup' {
            $static = Remove-DataBlock $hostileHtml
            foreach ($needle in $vectors['rawOutsideData']) { Assert-False (Test-Has $static $needle) "'$needle' outside the data block" }
        }
        It 'normalizes severity and grade to known values' {
            $d = Read-TestData $hostileHtml
            Assert-Equal 'info' $d['findings'][1]['severity']
            Assert-Equal '' $d['score']['grade']
            Assert-Equal 'F' (Read-TestData $plain)['score']['grade']
        }
        It 'masks a token-like value left in evidence or titles' {
            $fake = $vectors['fakeToken']
            $r = New-TestResult
            $r.Findings[0].Evidence = "token = $fake"
            $r.Findings[0].Title = "Token $fake"
            $r.Errors[0].Evidence = "Invalid JSON near $fake"
            $html = ConvertTo-TestHtml $r
            Assert-False (Test-Has $html $fake) 'the full token is not in the page'
            $d = Read-TestData $html
            Assert-Equal (& $aw { param($t) Hide-AwSecretsInText $t } "token = $fake") $d['findings'][0]['evidence']
            Assert-True ($d['findings'][0]['title'].StartsWith('Token ghp_')) 'title keeps the token prefix only'
        }
    }

    Describe 'Html: renderer script' {
        $renderer = Get-RendererScript $plain
        $style = Get-StyleSheet $plain
        It 'never uses innerHTML, anywhere in the page' {
            Assert-Equal 'innerHTML' $vectors['forbiddenApis'][0]
            foreach ($html in $allHtml) { Assert-False (Test-Has $html 'innerHTML') }
        }
        It 'never uses other markup-parsing or code-evaluating APIs' {
            foreach ($api in $vectors['forbiddenApis']) { Assert-False (Test-Has $renderer $api) "found '$api'" }
            # Case-sensitive, so that the keyword 'function' and the word 'evaluated' do not count.
            foreach ($name in $vectors['forbiddenCalls']) {
                Assert-False ([regex]::IsMatch($renderer, '(?<![\w$.])' + $name + '\s*\(')) "calls $name"
                Assert-False ([regex]::IsMatch($renderer, '\.' + $name + '\s*\(')) "calls .$name"
            }
        }
        It 'builds the DOM with createElement and textContent' {
            Assert-Match $renderer 'createElement\('
            Assert-Match $renderer '\.textContent = visible\('
        }
        It 'is ASCII and holds nothing that could end or confuse its element' {
            foreach ($text in @($renderer, $style)) {
                Assert-True (Test-PrintableAscii $text -AllowLineFeed)
                Assert-False ($text.Contains('</'))
                Assert-False ($text.Contains('<!--'))
                Assert-False (Test-Has $text '<script')
                Assert-False (Test-Has $text '<style')
            }
        }
        It 'creates links only for https URLs checked with the URL constructor' {
            Assert-Match $renderer 'new URL\(ref\)'
            Assert-Match $renderer "u\.protocol !== 'https:'"
            Assert-Match $renderer "setAttribute\('href', href\)"
            Assert-NotMatch $renderer '\.href\s*='
            Assert-Equal 1 ([regex]::Matches($renderer, "setAttribute\('href'")).Count
        }
        It 'reads and writes localStorage only inside try blocks' {
            $lines = @($renderer -split "`n" | Where-Object { $_ -match 'localStorage' })
            Assert-Equal 2 $lines.Count
            foreach ($l in $lines) { Assert-Match $l 'try \{' }
        }
        It 'derives class names only from allowlisted values' {
            $assignments = @([regex]::Matches($renderer, "el\('[a-z0-9]+', '[^']*' \+ [^,)]+") | ForEach-Object { $_.Value })
            Assert-True ($assignments.Count -ge 3) 'dynamic class names are present'
            foreach ($a in $assignments) { Assert-Match $a "\+ (f\.severity|s)$" }
        }
        It 'sets only allowlisted attributes, none of them an event handler or a style' {
            $names = @([regex]::Matches($renderer, "setAttribute\('([a-z-]+)'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
            foreach ($n in $names) {
                Assert-Contains @('aria-controls', 'aria-expanded', 'aria-hidden', 'aria-label', 'aria-pressed', 'data-label',
                                  'data-theme', 'datetime', 'href', 'referrerpolicy', 'rel', 'role', 'scope', 'target') $n
            }
        }
    }

    Describe 'Html: report model' {
        $d = Read-TestData $plain
        It 'shows paths relative to the root and keeps outside paths absolute' {
            Assert-Equal '.vscode\settingsplain.json' $d['findings'][0]['path']
            Assert-Equal 'D:\elsewhere\mcp.json' $d['findings'][1]['path']
            Assert-Equal $null $d['findings'][2]['path']
        }
        It 'keeps lines as numbers or null' {
            Assert-Equal 12 $d['findings'][0]['line']
            Assert-Equal $null $d['findings'][1]['line']
        }
        It 'keeps reference lists as arrays, even with one or zero items' {
            Assert-Equal 1 @($d['findings'][1]['references']).Count
            Assert-True ($d['findings'][1]['references'] -is [array]) 'one reference stays an array'
            Assert-True ($d['findings'][2]['references'] -is [array]) 'no reference is an empty array'
            Assert-True ((Get-DataBlock $plain).Contains('"references":[]')) 'empty list written as []'
        }
        It 'copies score, counts, categories, rules, errors and options' {
            Assert-Equal 41 $d['score']['score']
            Assert-Equal 1 $d['counts']['critical']
            Assert-Equal 2 $d['counts']['info']
            Assert-Equal 6 @($d['categories']).Count
            Assert-Equal 'approvals' $d['categories'][0]['id']
            Assert-Equal 25 $d['categories'][0]['weight']
            Assert-False $d['categories'][3]['applicable']
            Assert-Equal 2 @($d['rules']).Count
            Assert-Equal 'AW-CORE-001' $d['errors'][0]['ruleId']
            Assert-Equal '.mcp.json' $d['errors'][0]['path']
            Assert-Equal 'high' $d['options']['failOn']
            Assert-Equal 1 $d['options']['exitCode']
            Assert-Equal '0.2.0' $d['tool']['version']
        }
        It 'keeps the order of the findings' {
            Assert-Equal 'AW-VSC-001,AW-MCP-001,AW-SEC-001,AW-CORE-001' ((@($d['findings']) | ForEach-Object { $_['ruleId'] }) -join ',')
        }
        It 'renders a result with no findings, no rules and no errors' {
            $block = Get-DataBlock $emptyHtml
            foreach ($list in @('"findings":[]', '"rules":[]', '"errors":[]', '"harnesses":[]')) { Assert-True ($block.Contains($list)) "missing $list" }
            $m = Read-TestData $emptyHtml
            Assert-Equal 'A' $m['score']['grade']
            Assert-Equal 100 $m['score']['score']
            Assert-Equal 0 $m['counts']['critical']
            Assert-Equal 6 @($m['categories']).Count
            Assert-Equal 0 $m['options']['exitCode']
        }
        It 'renders a minimal or null result without failing' {
            foreach ($r in @([pscustomobject]@{ Root = 'C:\FAKE' }, $null)) {
                $html = ConvertTo-TestHtml $r
                $m = Read-TestData $html
                Assert-Equal 0 @($m['findings']).Count
                Assert-Equal 0 @($m['rules']).Count
                Assert-Equal '' $m['score']['grade']
                Assert-Equal 'Airworthy' $m['tool']['name']
                Assert-Equal 4 (Get-Tags $html 'script').Count
            }
        }
        It 'escapes non-ASCII text, surrogate pairs included, and round-trips it' {
            $html = ConvertTo-TestHtml (New-TestResult -Text $vectors['nonAscii'])
            Assert-True (Test-PrintableAscii (Get-DataBlock $html))
            Assert-True ((Get-DataBlock $html).Contains('"Title ' + (Get-Escaped $vectors['nonAsciiEscaped']) + '"'))
            Assert-Equal ('Title ' + $vectors['nonAscii']) (Read-TestData $html)['findings'][0]['title']
        }
        It 'escapes control characters' {
            $html = ConvertTo-TestHtml (New-TestResult -Text $vectors['controls'])
            Assert-True ((Get-DataBlock $html).Contains('"Title ' + (Get-Escaped $vectors['controlsEscaped']) + '"'))
            Assert-Equal ('Title ' + $vectors['controls']) (Read-TestData $html)['findings'][0]['title']
        }
    }

    Describe 'Html: source and asset files' {
        $assetDir = Join-Path $moduleRoot 'src\Output\Html'
        It 'are plain ASCII, so Windows PowerShell 5.1 and every browser read them the same without a BOM' {
            foreach ($file in @((Join-Path $moduleRoot 'src\Output\Html.ps1'), (Join-Path $assetDir 'report.js'),
                                (Join-Path $assetDir 'report.css'), (Join-Path $assetDir 'body.html'),
                                (Join-Path $PSScriptRoot 'Html.Tests.ps1'), (Join-Path $PSScriptRoot 'fixtures\html\vectors.json'))) {
                $text = [System.IO.File]::ReadAllText($file)
                Assert-True (Test-PrintableAscii ($text -replace '[\r\n\t]', '')) $file
            }
        }
        It 'inlines report.js and report.css exactly, with LF line endings' {
            $js = [System.IO.File]::ReadAllText((Join-Path $assetDir 'report.js')) -replace '\r\n?', "`n"
            $css = [System.IO.File]::ReadAllText((Join-Path $assetDir 'report.css')) -replace '\r\n?', "`n"
            Assert-Equal ("`n" + $js) (Get-RendererScript $plain)
            Assert-Equal ("`n" + $css) (Get-StyleSheet $plain)
        }
        It 'fails with a clear message when an asset is missing' {
            $err = Assert-Throws {
                & $aw {
                    $saved = $script:AwHtmlAssetDir
                    $script:AwHtmlAssetDir = 'C:\FAKE\missing-assets'
                    $script:AwHtmlAssets = @{}
                    try { ConvertTo-AwHtml $null } finally { $script:AwHtmlAssetDir = $saved; $script:AwHtmlAssets = @{} }
                }
            }
            Assert-Match $err.Message 'src/Output/Html/report\.css is missing'
        }
        It 'refuses an asset that would end its own element' {
            [System.IO.File]::WriteAllText((Join-Path $tmp 'report.css'), ('p { color: red; } ' + $StyleClose))
            $err = Assert-Throws {
                & $aw {
                    param($dir)
                    $saved = $script:AwHtmlAssetDir
                    $script:AwHtmlAssetDir = $dir
                    $script:AwHtmlAssets = @{}
                    try { ConvertTo-AwHtml $null } finally { $script:AwHtmlAssetDir = $saved; $script:AwHtmlAssets = @{} }
                } $tmp
            }
            Assert-Match $err.Message 'report\.css contains a sequence that would end its element'
        }
    }

    Describe 'Html: engine integration' {
        It 'writes <OutFile>.html as UTF-8 without BOM, with matching CSP hashes' {
            $base = Join-Path $tmp 'report'
            Invoke-Airworthy -Path $insecure -NoUserProfile -Format Html -OutFile $base -Quiet -WarningAction SilentlyContinue
            $file = "$base.html"
            Assert-True (Test-Path -LiteralPath $file)
            $bytes = [System.IO.File]::ReadAllBytes($file)
            Assert-False ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) 'no BOM'
            $html = [System.IO.File]::ReadAllText($file)
            $csp = Get-Csp $html
            Assert-True ($csp.Contains('script-src ' + (Get-CspHash (Get-RendererScript $html)))) 'script hash of the written file'
            Assert-True ($csp.Contains('style-src ' + (Get-CspHash (Get-StyleSheet $html)))) 'style hash of the written file'
            Assert-Equal 4 (Get-Tags $html 'script').Count
            $d = Read-TestData $html
            Assert-Equal 'vscode-copilot' $d['harnesses'][0]
            Assert-True (@($d['findings']).Count -gt 0) 'the insecure fixture has findings'
        }
        It 'keeps a hostile repository inert from the scan to the page' {
            $repo = Join-Path $PSScriptRoot 'fixtures\html\hostile-repo'
            $html = @(Invoke-Airworthy -Path $repo -NoUserProfile -Format Html -Quiet -WarningAction SilentlyContinue)[0]
            Assert-Equal 4 (Get-Tags $html 'script').Count
            Assert-Equal 2 (Get-Tags $html 'style').Count
            Assert-False (Test-Has (Remove-DataBlock $html) 'AW-XSS-MARKER') 'marker outside the data block'
            $data = Get-DataBlock $html
            Assert-True (Test-PrintableAscii $data) 'data block in printable ASCII'
            Assert-True ($data.Contains('AW-XSS-MARKER')) 'hostile text reached the report data'
            foreach ($bad in $vectors['rawInData']) { Assert-False (Test-Has $data $bad) 'raw hostile sequence in the data block' }
        }
        It 'returns the HTML on the pipeline without -OutFile' {
            $out = @(Invoke-Airworthy -Path $insecure -NoUserProfile -Format Html -Quiet -WarningAction SilentlyContinue)
            Assert-Equal 1 $out.Count
            Assert-True ($out[0].StartsWith('<!DOCTYPE html>'))
        }
    }
} finally {
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}
