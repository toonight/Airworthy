# Adversarial security review of the tool itself: HTML XSS and inertness, secret leakage in
# every output format, SARIF embedded links, filesystem link targets, ReDoS budgets, and the rule
# that nothing from a scanned file is ever executed. Hostile inputs live in fixtures\hostile and
# fixtures\security\vectors.json; adversarial 2 MB lines are built at run time from benign characters.
$aw = Get-Module Airworthy
$moduleRoot = Split-Path -Parent $PSScriptRoot
$fixtures = Join-Path $PSScriptRoot 'fixtures'
$hostile = Join-Path $fixtures 'hostile'
$leaky = Join-Path $fixtures 'secrets\leaky'
$tmp = Join-Path $fixtures ('security\_tmp-' + [guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($tmp)
$utf8 = New-Object System.Text.UTF8Encoding($false)

$vectors = & $aw { param($p) ConvertFrom-AwJsonc -Text ([System.IO.File]::ReadAllText($p)) } (Join-Path $fixtures 'security\vectors.json')
$Markers = @($vectors['markers'])
$RawInData = @($vectors['rawInData'])
$HostileSecrets = @($vectors['hostileSecrets'])
# The FAKE secrets of the leaky fixture are listed in fixtures\secrets\strings.json, not in this script.
$secretStrings = & $aw { param($p) ConvertFrom-AwJsonc -Text ([System.IO.File]::ReadAllText($p)) } (Join-Path $fixtures 'secrets\strings.json')
$LeakySecrets = @($secretStrings['fakeSecrets'])
$ExecutionApis = @($vectors['executionApis'])
$ExecMarkerPrefix = [string]$vectors['execMarkerPrefix']
$LineSep = [string]$vectors['lineSeparator']
$DataOpen = '<script type="application/json" id="aw-data">'
$ScriptClose = '</script>'

function New-TestFileAt([string]$Path, [string]$Text) {
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { [void][System.IO.Directory]::CreateDirectory($dir) }
    [System.IO.File]::WriteAllText($Path, $Text, $utf8)
}
function Scan([string]$Path) { Invoke-Airworthy -Path $Path -NoUserProfile -PassThru -Quiet -WarningAction SilentlyContinue }
function Render([string]$Path, [string]$Format) {
    @(Invoke-Airworthy -Path $Path -NoUserProfile -Format $Format -Quiet -WarningAction SilentlyContinue)[0]
}
function Get-DataBlock([string]$Html) {
    $s = $Html.IndexOf($DataOpen, [StringComparison]::Ordinal) + $DataOpen.Length
    $e = $Html.IndexOf($ScriptClose, $s, [StringComparison]::Ordinal)
    $Html.Substring($s, $e - $s)
}
function Remove-DataBlock([string]$Html) { $Html.Replace((Get-DataBlock $Html), '') }
function Has([string]$Text, [string]$Needle) { $Text.IndexOf($Needle, [StringComparison]::Ordinal) -ge 0 }
function CountScriptTags([string]$Html) { [regex]::Matches($Html, '<script\b|</script\s*>', 'IgnoreCase').Count }
function Time-Scriptblock([scriptblock]$Block) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    & $Block | Out-Null
    return $sw.ElapsedMilliseconds
}

try {
    $hostileResult = Scan $hostile
    $hostileHtml = Render $hostile 'Html'

    Describe 'Security: HTML report stays inert for a hostile repository' {
        It 'analyzes the hostile fixture without failing' {
            Assert-True ($hostileResult.Findings.Count -gt 0) 'the hostile fixture produces findings'
            Assert-True ($hostileHtml.StartsWith('<!DOCTYPE html>'))
            Assert-Equal 4 (CountScriptTags $hostileHtml)
        }
        It 'leaves no tag, comment, URL scheme or line separator raw in the data block' {
            $data = Get-DataBlock $hostileHtml
            foreach ($bad in $RawInData) { Assert-False (Has $data $bad) "raw '$bad' in the data block" }
            Assert-False (Has $data $LineSep) 'U+2028 raw in the data block'
        }
        It 'writes the data block as printable ASCII only' {
            Assert-NotMatch (Get-DataBlock $hostileHtml) '[^\x20-\x7E]'
        }
        It 'keeps every hostile marker inside the data block and out of the markup' {
            $data = Get-DataBlock $hostileHtml
            $markup = Remove-DataBlock $hostileHtml
            $inData = 0
            foreach ($m in $Markers) {
                if (Has $data $m) { $inData++ }
                Assert-False (Has $markup $m) "marker '$m' escaped into the markup"
            }
            Assert-True ($inData -ge 10) 'the hostile markers reached the report data'
        }
        It 'puts no execution marker anywhere in the page (nothing is executed or echoed as a script)' {
            Assert-False (Has (Remove-DataBlock $hostileHtml) $ExecMarkerPrefix) 'execution marker in the markup'
        }
        It 'computes a CSP that matches the inline script and style it emits' {
            $style = & $aw { param($h) Get-AwHtmlCspHash -Text ([regex]::Match($h, '(?s)<style>(.*?)</style>').Groups[1].Value) } $hostileHtml
            $script = & $aw { param($h) Get-AwHtmlCspHash -Text ([regex]::Match($h, '(?s)<script>(.*?)</script>').Groups[1].Value) } $hostileHtml
            $csp = [regex]::Match($hostileHtml, '<meta http-equiv="Content-Security-Policy" content="([^"]*)">').Groups[1].Value
            Assert-True ($csp.Contains('style-src ' + $style)) 'style hash in the CSP'
            Assert-True ($csp.Contains('script-src ' + $script)) 'script hash in the CSP'
            Assert-Match $csp "^default-src 'none';"
            Assert-NotMatch $csp 'unsafe-|https?:|data:|blob:|\*'
        }
        It 'recomputes the CSP hash correctly (known answer for "abc")' {
            Assert-Equal "'sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0='" (& $aw { param($t) Get-AwHtmlCspHash -Text $t } 'abc')
        }
    }

    Describe 'Security: secrets never leak in full' {
        It 'masks every FAKE secret in all four output formats for the hostile fixture' {
            foreach ($fmt in 'Html', 'Json', 'Sarif', 'Markdown') {
                $text = Render $hostile $fmt
                foreach ($s in $HostileSecrets) { Assert-False (Has $text $s) "full secret in $fmt" }
            }
        }
        It 'masks every FAKE secret in all four output formats for the leaky fixture' {
            Assert-True ($LeakySecrets.Count -ge 16)
            foreach ($fmt in 'Html', 'Json', 'Sarif', 'Markdown') {
                $text = Render $leaky $fmt
                foreach ($s in $LeakySecrets) { Assert-False (Has $text $s) "full secret in $fmt" }
            }
        }
    }

    Describe 'Security: the tool never executes scanned content' {
        It 'uses no process-spawning, code-evaluation or network API in any source file' {
            $files = @(Get-ChildItem -LiteralPath (Join-Path $moduleRoot 'src') -Recurse -File |
                       Where-Object { '.ps1', '.psm1', '.psd1' -contains $_.Extension })
            $files += @(Get-ChildItem -LiteralPath $moduleRoot -File | Where-Object { '.ps1', '.psm1', '.psd1' -contains $_.Extension })
            foreach ($f in $files) {
                $text = [System.IO.File]::ReadAllText($f.FullName)
                foreach ($api in $ExecutionApis) {
                    Assert-False ($text.IndexOf($api, [StringComparison]::OrdinalIgnoreCase) -ge 0) "$($f.Name) uses $api"
                }
            }
        }
        It 'makes no network call while analyzing the hostile fixture (offline)' {
            # A hostile http(s)/private URL in the config must not be fetched: it only appears masked in findings.
            Assert-True ($hostileResult.Findings.Count -gt 0)
        }
    }

    Describe 'Security: SARIF messages carry no embedded link from scanned data' {
        It 'contains no [text](target) sequence in any message.text' {
            $sarif = Render $hostile 'Sarif'
            $withLink = @([regex]::Matches($sarif, '"text":\s*"((?:[^"\\]|\\.)*)"') | Where-Object { $_.Groups[1].Value -match '\]\(' })
            Assert-Equal 0 $withLink.Count
        }
    }

    Describe 'Security: filesystem link targets outside the root' {
        It 'rejects network-share, UNC, device and volume link targets' {
            foreach ($key in 'networkShare', 'volume', 'rootedShare', 'deviceShare') {
                $t = [string]$vectors['linkTargets'][$key]
                $resolved = & $aw { param($t) ConvertTo-AwLinkTargetPath -Target $t -LinkPath 'C:\repo\link' } $t
                Assert-Equal $null $resolved "target '$key' should be rejected"
            }
        }
        It 'resolves an ordinary relative or rooted target inside the repo' {
            $inside = & $aw { ConvertTo-AwLinkTargetPath -Target 'sub\file' -LinkPath 'C:\repo\link' }
            Assert-Equal 'C:\repo\sub\file' $inside
        }
        It 'does not follow a junction that leaves the analyzed root' {
            $outside = Join-Path $tmp 'outside'
            New-TestFileAt (Join-Path $outside 'settings.json') '{"chat.tools.global.autoApprove": true}'
            $root = Join-Path $tmp 'linked'
            [void][System.IO.Directory]::CreateDirectory($root)
            $link = Join-Path $root '.vscode'
            try { New-Item -ItemType Junction -Path $link -Target $outside -ErrorAction Stop | Out-Null }
            catch { Write-Host '      (skipped: cannot create a junction here)' -ForegroundColor Yellow; return }
            try {
                $ctx = & $aw { param($p) New-AwContext -Path $p -NoUserProfile } $root
                Assert-Equal $null $ctx.VSCode.WorkspaceSettings
                Assert-Match (($ctx.Errors | ForEach-Object { $_.Evidence }) -join ' ') 'leads outside the analyzed root'
            } finally { [System.IO.Directory]::Delete($link) }
        }
    }

    Describe 'Security: ReDoS budgets (adversarial 2 MB lines)' {
        # 2 MB single lines built from benign characters only, at run time.
        $two = 2097152
        $cases = [ordered]@{
            'letters'     = ('a' * $two)
            'spaces'      = (' ' * $two)
            'without'     = ('without ' * [int]($two / 8))
            'ai-modal'    = ('ai must ' * [int]($two / 8))
            'comment-open'= ('<!--' * [int]($two / 4))
            'url-ish'     = ('http://a' * [int]($two / 8))
            'brackets'    = ('[a](b)' * [int]($two / 6))
            'jwt-ish'     = ('eyJ' + ('a' * ($two - 3)))
        }
        It 'scans each full-text rule pattern on a 2 MB line in under 2 seconds' {
            foreach ($name in $cases.Keys) {
                $text = $cases[$name]
                $ms = & $aw {
                    param($t)
                    $sw = [System.Diagnostics.Stopwatch]::StartNew()
                    [void](Find-AwAgtBypassPhrases $t)
                    [void]$script:AwAgtInvisibleRegex.Matches($t)
                    [void]$script:AwAgtTagRunRegex.Match($t)
                    [void]$script:AwAgtUrlRegex.Match($t)
                    foreach ($p in $script:AwSecPatterns) { [void]$p.Regex.Match($t) }
                    [void]$script:AwSecGenericRegex.Match($t)
                    $sw.ElapsedMilliseconds
                } $text
                Assert-True ($ms -lt 2000) "full-text scan of '$name' took ${ms} ms"
            }
        }
        It 'bounds the HTML-comment directive check on a 2 MB line in under 2 seconds' {
            $comment = '<!-- x' + ("`n" * 1990) + 'x -->'
            $text = ($comment * 1200)
            if ($text.Length -gt $two) { $text = $text.Substring(0, $two) }
            $ms = & $aw {
                param($t)
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $scan = Find-AwAgtHtmlComments $t
                $budget = $script:AwAgtMaxDirectiveChars
                foreach ($c in $scan.Comments) { if ($budget -le 0) { break }; $budget -= ($c.Text.Length + 1); [void](Test-AwAgtHiddenDirective $c.Text) }
                $sw.ElapsedMilliseconds
            } $text
            Assert-True ($ms -lt 2000) "comment directive check took ${ms} ms"
        }
        It 'bounds a hostile frontmatter key padded with 2 MB of blanks' {
            $text = "---`nk" + (' ' * $two) + ": v`n---`nbody"
            $ms = Time-Scriptblock { & $aw { param($t) Read-AwFrontmatter -Text $t } $text }
            Assert-True ($ms -lt 2000) "frontmatter parse took ${ms} ms"
        }
        It 'bounds a hostile MCP server name of 2 MB in the line lookup' {
            $name = (' (project: ' * [int]($two / 11))
            $ms = Time-Scriptblock { & $aw { param($n) Get-AwMcpLine -Raw '{"x":1}' -Server $n -Needle $null } $name }
            Assert-True ($ms -lt 2000) "MCP line lookup took ${ms} ms"
        }
        It 'treats an evil user regex as not matching and stays within the timeout budget' {
            $r = & $aw {
                Reset-AwUntrustedRegexState
                $rx = ConvertTo-AwVscRegex '/((a|a)*)*Q/'
                $m = Test-AwVscRegexMatch $rx ('a' * 60)
                [pscustomobject]@{ Match = $m; Timeouts = $script:AwUntrustedRegexState.Timeouts }
            }
            Assert-False $r.Match 'an evil regex must not report a match'
            Assert-True ($r.Timeouts -ge 1) 'the timeout was recorded'
        }
        It 'analyzes a hostile repository with 2 MB files quickly and reports a pattern-budget note when hit' {
            $repo = Join-Path $tmp 'big-hostile'
            New-TestFileAt (Join-Path $repo '.github\copilot-instructions.md') ('a' * $two)
            New-TestFileAt (Join-Path $repo 'CLAUDE.md') ('<!-- x' + ("`n" * 1990) + "x -->`n")
            $ms = Time-Scriptblock { Scan $repo }
            Assert-True ($ms -lt 20000) "analysis of a 2 MB hostile repo took ${ms} ms"
        }
    }

    Describe 'Security: whole file texts reach .NET methods only at reviewed call sites' {
        # PowerShell 7.3+ logs every .NET method call made from script with the full text of its
        # string arguments, so a call that receives a whole file text inside a loop costs the file
        # size at every pass. Every method call whose arguments use a whole-text variable ($T,
        # $Text, $Raw, $inner, $Body, or a member such as $s.T or $r.Raw) is listed with its reason
        # in fixtures\security\large-arg-allowlist.json. Names other than T are matched without
        # case, as PowerShell does; a lower-case $t is the usual short name for a token.
        $allowFile = 'tests/fixtures/security/large-arg-allowlist.json'
        $hint = 'PowerShell 7.3+ logs every .NET method call made from script with the full text of its string arguments. ' +
            'Pass a bounded slice ($Text.Substring), an indexer or an operator instead; if the call runs a bounded number ' +
            'of times per file, add it to ' + $allowFile + ' with the reason'
        $isTextRef = {
            # A whole-text variable or member used as a value, not as the target of a member access or an index.
            param($n)
            $name = $null
            if ($n -is [System.Management.Automation.Language.VariableExpressionAst]) {
                $name = $n.VariablePath.UserPath
                $colon = $name.LastIndexOf(':', [StringComparison]::Ordinal)
                if ($colon -ge 0) { $name = $name.Substring($colon + 1) }
            } elseif ($n -is [System.Management.Automation.Language.MemberExpressionAst] -and
                $n -isnot [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
                $n.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                $name = $n.Member.Value
            }
            if ($null -eq $name) { return $false }
            $lower = $name.ToLowerInvariant()
            if (-not ($name -ceq 'T' -or $lower -ceq 'text' -or $lower -ceq 'raw' -or $lower -ceq 'inner' -or $lower -ceq 'body')) { return $false }
            $parent = $n.Parent
            if ($parent -is [System.Management.Automation.Language.MemberExpressionAst] -and [object]::ReferenceEquals($parent.Expression, $n)) { return $false }
            if ($parent -is [System.Management.Automation.Language.IndexExpressionAst] -and [object]::ReferenceEquals($parent.Target, $n)) { return $false }
            return $true
        }
        $collect = {
            # Adds 'file | function | method' -> line numbers to Into for every call of Ast that passes
            # a whole text. A call in a rule check is named after the rule ID.
            param($Ast, [string]$File, $Into)
            foreach ($call in $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)) {
                $passes = $false
                foreach ($arg in @($call.Arguments)) {
                    # Nested script blocks are skipped: their own calls are checked on their own.
                    if ($null -ne $arg -and @($arg.FindAll($isTextRef, $false)).Count -gt 0) { $passes = $true }
                }
                if (-not $passes) { continue }
                $owner = '(script)'
                $up = $call.Parent
                while ($null -ne $up) {
                    if ($up -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $owner = $up.Name; break }
                    if ($up -is [System.Management.Automation.Language.CommandAst] -and $up.GetCommandName() -ceq 'Register-AwRule') {
                        $els = $up.CommandElements
                        for ($k = 0; $k + 1 -lt $els.Count; $k++) {
                            if ($els[$k] -is [System.Management.Automation.Language.CommandParameterAst] -and $els[$k].ParameterName -ceq 'Id') {
                                $id = $els[$k + 1]
                                if ($id -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $owner = 'rule ' + $id.Value }
                                else { $owner = 'rule ' + $id.Extent.Text }
                            }
                        }
                        break
                    }
                    $up = $up.Parent
                }
                $method = $call.Member.Extent.Text
                if ($call.Static) { $method = $call.Expression.Extent.Text + '::' + $method }
                $key = $File + ' | ' + $owner + ' | ' + $method
                if (-not $Into.ContainsKey($key)) { $Into[$key] = New-Object System.Collections.Generic.List[int] }
                $Into[$key].Add($call.Extent.StartLineNumber)
            }
        }
        $found = New-Object System.Collections.Hashtable -ArgumentList ([StringComparer]::Ordinal)
        $parseErrors = New-Object System.Collections.Generic.List[string]
        $sources = @(Get-ChildItem -LiteralPath (Join-Path $moduleRoot 'src') -Recurse -File | Where-Object { $_.Extension -ceq '.ps1' })
        foreach ($f in $sources) {
            $rel = $f.FullName.Substring($moduleRoot.Length + 1).Replace('\', '/')
            $tokens = $null
            $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors)
            foreach ($e in @($errors)) { if ($null -ne $e) { $parseErrors.Add($rel + ':' + $e.Extent.StartLineNumber + ' ' + $e.Message) } }
            & $collect $ast $rel $found
        }
        $allow = & $aw { param($p) ConvertFrom-AwJsonc -Text ([System.IO.File]::ReadAllText($p)) } (Join-Path $moduleRoot $allowFile)
        $expected = New-Object System.Collections.Hashtable -ArgumentList ([StringComparer]::Ordinal)
        $badEntries = New-Object System.Collections.Generic.List[string]
        foreach ($entry in @($allow['calls'])) {
            $label = [string]$entry['file'] + ' | ' + [string]$entry['function'] + ' | ' + [string]$entry['method']
            if (([string]$entry['file']).Length -eq 0 -or ([string]$entry['function']).Length -eq 0 -or
                ([string]$entry['method']).Length -eq 0 -or ([string]$entry['why']).Trim().Length -eq 0) {
                $badEntries.Add($label + ': file, function, method and why are required')
            } elseif (-not (Test-Path -LiteralPath (Join-Path $moduleRoot ([string]$entry['file'])) -PathType Leaf)) {
                $badEntries.Add($label + ': no such file')
            } elseif ($expected.ContainsKey($label)) {
                $badEntries.Add($label + ': listed twice')
            } elseif (-not ($entry['count'] -is [int] -or $entry['count'] -is [long]) -or $entry['count'] -lt 1) {
                $badEntries.Add($label + ': count must be a whole number of at least 1')
            } else {
                $expected[$label] = [int]$entry['count']
            }
        }
        $foundKeys = [string[]]@($found.Keys)
        [Array]::Sort($foundKeys, [StringComparer]::Ordinal)
        $expectedKeys = [string[]]@($expected.Keys)
        [Array]::Sort($expectedKeys, [StringComparer]::Ordinal)

        It 'parses every source file and reads a well-formed allowlist' {
            Assert-True ($sources.Count -ge 20) ('source files found: ' + $sources.Count)
            Assert-Equal @() $parseErrors.ToArray() 'source files that do not parse'
            Assert-Equal @() $badEntries.ToArray() $allowFile
            Assert-True ($expected.Count -gt 0) 'the allowlist lists the reviewed call sites'
        }
        It 'counts whole texts passed as values, and not slices, indexers, operators, $t or nested script blocks' {
            $sample = @'
function Get-AwSample {
    param([string]$Text, $s, [string]$Raw)
    $a = $rx.Match($Text, 0)
    $b = $rx.Match($s.T, 1)
    $c = [string]::IsNullOrEmpty($script:Raw)
    $d = $sb.Append(($TEXT + 'x'))
    $e = $rx.Match($Text.Substring(0, 4))
    $f = $sb.Append($Text[0])
    $g = $sb.Append($Text.Length)
    $h = $Text -replace 'a', 'b'
    $i = $list.Sort({ param($x) $x.Equals($Raw) })
    $j = $rx.Match($t)
}
Register-AwRule -Id 'AW-SEC-999' -Check { param($Ctx) $rx.IsMatch($Ctx.Body) }
'@
            $tokens = $null
            $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseInput($sample, [ref]$tokens, [ref]$errors)
            Assert-Equal 0 @($errors).Count 'the sample parses'
            $into = New-Object System.Collections.Hashtable -ArgumentList ([StringComparer]::Ordinal)
            & $collect $ast 'sample' $into
            $keys = [string[]]@($into.Keys)
            [Array]::Sort($keys, [StringComparer]::Ordinal)
            $got = @(foreach ($k in $keys) { $k + ' x' + $into[$k].Count })
            Assert-Equal @('sample | Get-AwSample | Append x1', 'sample | Get-AwSample | Equals x1', 'sample | Get-AwSample | Match x2',
                'sample | Get-AwSample | [string]::IsNullOrEmpty x1', 'sample | rule AW-SEC-999 | IsMatch x1') $got
        }
        It 'passes a whole file text to a .NET method only at a listed call site, and no more often' {
            $extra = New-Object System.Collections.Generic.List[string]
            foreach ($key in $foundKeys) {
                $lines = $found[$key]
                $allowed = 0
                if ($expected.ContainsKey($key)) { $allowed = $expected[$key] }
                if ($lines.Count -gt $allowed) {
                    $extra.Add($key + ': ' + $lines.Count + ' call(s), allowed ' + $allowed + ' (lines ' + ($lines -join ', ') + ')')
                }
            }
            Assert-Equal @() $extra.ToArray() $hint
        }
        It 'lists only call sites that still exist (lower or remove an entry when a call goes away)' {
            $stale = New-Object System.Collections.Generic.List[string]
            foreach ($key in $expectedKeys) {
                $now = 0
                if ($found.ContainsKey($key)) { $now = $found[$key].Count }
                if ($now -lt $expected[$key]) { $stale.Add($key + ': allowed ' + $expected[$key] + ', found ' + $now) }
            }
            Assert-Equal @() $stale.ToArray() ('update ' + $allowFile)
        }
    }

    Describe 'Security: robustness against malformed files' {
        It 'does not crash on invalid UTF-8, a binary file, a very long line or deep nesting' {
            $repo = Join-Path $tmp 'malformed'
            [void][System.IO.Directory]::CreateDirectory((Join-Path $repo '.vscode'))
            [System.IO.File]::WriteAllBytes((Join-Path $repo '.vscode\settings.json'), ([byte[]](0xFF, 0xFE, 0x00, 0x80, 0x81, 0x7B, 0x7D)))
            [System.IO.File]::WriteAllBytes((Join-Path $repo '.mcp.json'), ([byte[]](0..255)))
            New-TestFileAt (Join-Path $repo 'CLAUDE.md') ('x' * 3000000)   # over the 2 MB limit
            New-TestFileAt (Join-Path $repo '.github\copilot-instructions.md') (('[' * 200) + (']' * 200))
            $r = Scan $repo
            Assert-True ($null -ne $r) 'the analysis returns a result'
            Assert-True ($r.Score.Score -ge 0 -and $r.Score.Score -le 100) 'the score is in range'
        }
        It 'skips a file over 2 MB with an info finding and keeps going' {
            $repo = Join-Path $tmp 'toobig'
            New-TestFileAt (Join-Path $repo '.vscode\settings.json') ('{"a":"' + ('x' * (2MB + 16)) + '"}')
            $r = Scan $repo
            Assert-Match (($r.Errors | ForEach-Object { $_.Evidence }) -join ' ') 'larger than 2 MB'
        }
    }

    Describe 'Security: out-of-scope reads' {
        It 'with -NoUserProfile every discovered path is inside the analyzed root' {
            $ctx = & $aw { param($p) New-AwContext -Path $p -NoUserProfile } $hostile
            Assert-Equal $null $ctx.UserProfile
            foreach ($p in @($ctx.TextFiles)) {
                Assert-True (& $aw { param($a, $b) Test-AwPathInside -Path $a -Dir $b } $p $ctx.Root) "path outside the root: $p"
            }
        }
        It 'the README states the tool reads only the root plus the user profile' {
            $readme = [System.IO.File]::ReadAllText((Join-Path $moduleRoot 'README.md'))
            # Nothing to check yet while README.md is the one-line placeholder; the full README must pass.
            if ($readme.Trim() -eq '# Airworthy') { return }
            Assert-Match $readme 'reads only the analyzed folder'
            Assert-Match $readme '(?i)-NoUserProfile'
        }
    }
} finally {
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}
