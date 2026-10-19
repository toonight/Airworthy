# Tests for src/Output: Console, JSON, SARIF and Markdown renderers.
# Results are synthetic: paths are plain strings and are never read from disk. Hostile values
# (control characters, markup, a fake token) come from fixtures/output/hostile.json, so that this
# script stays plain. The engine tests run a test-only rule with -NoUserProfile.
$aw = Get-Module Airworthy
$fixtures = Join-Path $PSScriptRoot 'fixtures'
$insecure = Join-Path $fixtures 'insecure'
$fakeRoot = 'C:\FakeAwRoot\repo'
$fakeProfile = 'C:\FakeAwProfile\FAKEUSER'
$urlRef = 'https://code.visualstudio.com/docs/copilot/security'
$LF = "`n"

$h = @{}
$hostileJson = [System.IO.File]::ReadAllText((Join-Path $fixtures 'output\hostile.json')) | ConvertFrom-Json
foreach ($p in $hostileJson.PSObject.Properties) { $h[$p.Name] = [string]$p.Value }
$fakeSecret = $h.secret
# The halves of a valid surrogate pair, used alone.
$highHalf = $h.surrogateText.Substring(4, 1)
$lowHalf = $h.surrogateText.Substring(5, 1)

function Test-LoneSurrogate([string]$Text) {
    # True when the text has a surrogate that is not part of a valid pair.
    for ($i = 0; $i -lt $Text.Length; $i++) {
        if ([char]::IsHighSurrogate($Text[$i]) -and $i + 1 -lt $Text.Length -and [char]::IsLowSurrogate($Text[$i + 1])) { $i++; continue }
        if ([char]::IsSurrogate($Text[$i])) { return $true }
    }
    return $false
}

function New-TestFinding {
    param(
        [string]$RuleId = 'AW-VSC-001', [string]$Severity = 'high', [string]$Title = 'Test finding',
        [string]$Path, $Line, [string]$Key, [string]$Evidence,
        [string]$Category = 'approvals', [string]$Harness = 'vscode-copilot', [string]$Fix = 'Apply the fix.',
        [string[]]$References = @('OWASP-ASI02', $urlRef), [string]$Confidence = 'high', $Data
    )
    $f = [pscustomobject]@{
        RuleId      = $RuleId
        Title       = $Title
        Severity    = $Severity
        Category    = $Category
        Harness     = $Harness
        Description = "Description of $RuleId."
        Evidence    = $(if ($Evidence) { $Evidence } else { $null })
        Location    = [pscustomobject]@{ Path = $(if ($Path) { $Path } else { $null }); Line = $Line; Key = $(if ($Key) { $Key } else { $null }) }
        Fix         = $Fix
        References  = [string[]]$References
        Confidence  = $Confidence
    }
    if ($null -ne $Data) { $f | Add-Member -NotePropertyName 'Data' -NotePropertyValue $Data }
    $f
}

function New-TestRule {
    param(
        [string]$Id, [string]$Severity = 'high', [string]$Category = 'approvals', [string]$Harness = 'vscode-copilot',
        [string]$Title, [string[]]$References = @('OWASP-ASI02', $urlRef), [string]$Confidence = 'high', [string]$Description
    )
    [pscustomobject]@{
        Id          = $Id
        Title       = $(if ($Title) { $Title } else { "Rule $Id" })
        Severity    = $Severity
        Category    = $Category
        Harness     = $Harness
        Description = $(if ($Description) { $Description } else { "Description of $Id." })
        Fix         = "Fix for $Id."
        References  = [string[]]$References
        Confidence  = $Confidence
    }
}

function Get-TestRank([string]$Severity) { & $aw { param($s) Get-AwSeverityRank $s } $Severity }

function New-TestResult {
    # Builds a result shaped like the engine's, with the real Get-AwScore.
    param(
        [object[]]$Findings = @(), [object[]]$Rules = @(), [string]$Root = $fakeRoot,
        [string[]]$Harnesses = @('vscode-copilot', 'claude-code'), [string]$MinSeverity = 'info',
        [switch]$Redact, [string]$FailOn, [int]$ExitCode = 0
    )
    $all = @($Findings | Where-Object { $null -ne $_ })
    $rules = @($Rules | Where-Object { $null -ne $_ })
    $score = & $aw { param($f, $r, $x) Get-AwScore -Findings $f -Rules $r -Harnesses $x } $all $rules $Harnesses
    $min = Get-TestRank $MinSeverity
    [pscustomobject]@{
        Tool      = [ordered]@{ Name = 'Airworthy'; Version = '0.2.0' }
        ScannedAt = '2026-10-18T12:00:00Z'
        Root      = $Root
        Harnesses = [string[]]$Harnesses
        Score     = $score
        Findings  = @($all | Where-Object { (Get-TestRank $_.Severity) -ge $min })
        Rules     = $rules
        Errors    = @($all | Where-Object { $_.RuleId -like 'AW-CORE-*' })
        Options   = [ordered]@{
            Format = [string[]]@('Console'); OutFile = $null; MinSeverity = $MinSeverity
            FailOn = $(if ($FailOn) { $FailOn } else { $null }); Redact = [bool]$Redact
            NoUserProfile = $true; UserProfilePath = $null; UserSettingsPath = $null
        }
        ExitCode  = $ExitCode
    }
}

function Get-ConsoleLines($Result, [string]$MinSeverity) {
    @(& $aw {
        param($r, $m)
        if ($m) { ConvertTo-AwConsole $r -MinSeverity $m -NoColor } else { ConvertTo-AwConsole $r -NoColor }
    } $Result $MinSeverity)
}
function Get-ConsoleText($Result, [string]$MinSeverity) { (Get-ConsoleLines $Result $MinSeverity) -join $LF }
function Get-JsonText($Result) { & $aw { param($r) ConvertTo-AwJson $r } $Result }
function Get-SarifText($Result) { & $aw { param($r) ConvertTo-AwSarif $r } $Result }
function Get-MarkdownText($Result) { & $aw { param($r) ConvertTo-AwMarkdown $r } $Result }
function Get-Names($Object) { @($Object.PSObject.Properties | ForEach-Object { $_.Name }) }

# A result with one finding per severity, inside and outside the root.
$evalRules = @(
    (New-TestRule -Id 'AW-VSC-001' -Severity 'critical' -Title 'Global auto-approval of tools enabled'),
    (New-TestRule -Id 'AW-AGT-002' -Severity 'high' -Category 'agent-files' -Title 'Agent can run any tool'),
    (New-TestRule -Id 'AW-CC-003' -Severity 'medium' -Category 'sandbox-network' -Harness 'claude-code' -References @('OWASP-ASI05') -Confidence 'medium'),
    (New-TestRule -Id 'AW-SEC-004' -Severity 'low' -Category 'secrets' -Harness 'generic' -References @())
)
$agentPath = $fakeRoot + '\.github\agents\' + $h.agentFile
$mainFindings = @(
    (New-TestFinding -RuleId 'AW-VSC-001' -Severity 'critical' -Title 'Global auto-approval of tools enabled' -Path "$fakeRoot\.vscode\settings.json" -Line 12 -Key 'chat.tools.global.autoApprove' -Evidence 'chat.tools.global.autoApprove = true'),
    (New-TestFinding -RuleId 'AW-AGT-002' -Severity 'high' -Title 'Agent can run any tool' -Category 'agent-files' -Path $agentPath -Key 'frontmatter.tools' -Evidence "tools: ['*']"),
    (New-TestFinding -RuleId 'AW-CC-003' -Severity 'medium' -Title 'Bash allowed without sandbox' -Category 'sandbox-network' -Harness 'claude-code' -Path "$fakeProfile\.claude\settings.json" -Line 3 -Evidence 'permissions.allow = Bash(*)' -References @('OWASP-ASI05') -Confidence 'medium'),
    (New-TestFinding -RuleId 'AW-MCP-009' -Severity 'low' -Title 'MCP server not pinned' -Category 'mcp-supply-chain' -Harness 'mcp' -Path "$fakeRoot\.mcp.json" -Line 4 -Evidence 'npx -y some-server' -References @()),
    (New-TestFinding -RuleId 'AW-CORE-002' -Severity 'info' -Title 'Rule failed: AW-VSC-999' -Category 'observability' -Harness 'generic' -Key 'AW-VSC-999' -Evidence 'RuntimeException: boom' -References @())
)
$mainResult = New-TestResult -Findings $mainFindings -Rules $evalRules -FailOn 'high' -ExitCode 1

Describe 'Shared output helpers' {
    It 'reduces file text to one printable line' {
        Assert-Equal $h.safeTextExpected (& $aw { param($t) Get-AwSafeText $t } $h.safeTextInput)
    }
    It 'cuts long text without splitting a surrogate pair' {
        Assert-Equal 'abcd...' (& $aw { param($t) Get-AwShortText $t -MaxLength 8 } $h.surrogateText)
        Assert-Equal 'abc...' (& $aw { Get-AwShortText 'abcdefgh' -MaxLength 6 })
        Assert-Equal 'abc' (& $aw { Get-AwShortText 'abc' -MaxLength 6 })
    }
    It 'returns categories in canonical order even from a plain hashtable' {
        $cats = @{
            'secrets'   = @{ Title = 'Secrets'; Score = 50; Applicable = $true; Findings = 2 }
            'zz-extra'  = @{ Title = 'Extra'; Score = 10; Applicable = $true; Findings = 1 }
            'approvals' = @{ Title = 'Approvals and terminal'; Score = 100; Applicable = $false; Findings = 0 }
        }
        $r = [pscustomobject]@{ Score = [pscustomobject]@{ Categories = $cats } }
        $rows = @(& $aw { param($x) Get-AwOutputCategories $x } $r)
        Assert-Equal @('approvals', 'secrets', 'zz-extra') @($rows | ForEach-Object { $_.Name })
        Assert-Equal 25 $rows[0].Weight
        Assert-Equal 0 $rows[2].Weight
    }
    It 'shows paths relative to the root and keeps other paths absolute' {
        $get = { param($f) & $aw { param($r, $x) Get-AwOutputLocation -Result $r -Finding $x } $mainResult $f }
        Assert-Equal 'a\b.json:7' (& $get (New-TestFinding -Path "$fakeRoot\a\b.json" -Line 7))
        Assert-Equal "$fakeProfile\x.json" (& $get (New-TestFinding -Path "$fakeProfile\x.json"))
        Assert-Equal $null (& $get (New-TestFinding))
    }
}

Describe 'ConvertTo-AwJson' {
    It 'returns one string that ConvertFrom-Json parses' {
        $json = Get-JsonText $mainResult
        Assert-True ($json -is [string])
        $p = $json | ConvertFrom-Json
        Assert-Equal 'Airworthy' $p.Tool.Name
        Assert-Equal $mainResult.Score.Grade $p.Score.Grade
        Assert-Equal 5 @($p.Findings).Count
    }
    It 'writes the result fields in a fixed order' {
        $p = (Get-JsonText $mainResult) | ConvertFrom-Json
        Assert-Equal @('Tool', 'ScannedAt', 'Root', 'Harnesses', 'Score', 'Findings', 'Rules', 'Errors', 'Options', 'ExitCode') (Get-Names $p)
        Assert-Equal @('Score', 'Grade', 'Categories', 'Counts') (Get-Names $p.Score)
        Assert-Equal 1 $p.ExitCode
        Assert-Equal 'high' $p.Options.FailOn
    }
    It 'writes each finding with exactly the contract properties' {
        $p = (Get-JsonText $mainResult) | ConvertFrom-Json
        $expected = @('RuleId', 'Title', 'Severity', 'Category', 'Harness', 'Description', 'Evidence', 'Location', 'Fix', 'References', 'Confidence')
        foreach ($f in $p.Findings) { Assert-Equal $expected (Get-Names $f) }
        Assert-Equal @('Path', 'Line', 'Key') (Get-Names $p.Findings[0].Location)
        Assert-Equal 12 $p.Findings[0].Location.Line
        Assert-Equal "$fakeRoot\.vscode\settings.json" $p.Findings[0].Location.Path
        Assert-Equal @('Id', 'Title', 'Severity', 'Category', 'Harness', 'Description', 'Fix', 'References', 'Confidence') (Get-Names $p.Rules[0])
        Assert-Equal 'AW-CORE-002' $p.Errors[0].RuleId
    }
    It 'adds Data only to the findings that have it' {
        $f = New-TestFinding -Evidence 'x' -Data @{ server = 'demo'; count = 2 }
        $p = (Get-JsonText (New-TestResult -Findings @($f, (New-TestFinding)))) | ConvertFrom-Json
        Assert-Equal 'demo' $p.Findings[0].Data.server
        Assert-Equal 2 $p.Findings[0].Data.count
        Assert-False (@(Get-Names $p.Findings[1]) -contains 'Data')
    }
    It 'is deterministic and sorts hashtable keys' {
        $d1 = @{}; $d1['zeta'] = 1; $d1['alpha'] = 2; $d1['Mid'] = @{ b = 1; a = 2 }
        $d2 = @{}; $d2['Mid'] = @{ a = 2; b = 1 }; $d2['alpha'] = 2; $d2['zeta'] = 1
        $j1 = Get-JsonText (New-TestResult -Findings @((New-TestFinding -Data $d1)))
        $j2 = Get-JsonText (New-TestResult -Findings @((New-TestFinding -Data $d2)))
        Assert-Equal $j1 $j2
        Assert-Equal $j1 (Get-JsonText (New-TestResult -Findings @((New-TestFinding -Data $d1))))
        Assert-Match $j1 '"Data": \{\s*"Mid": \{\s*"a": 2,\s*"b": 1\s*\},\s*"alpha": 2,\s*"zeta": 1\s*\}'
    }
    It 'keeps each value with its key when it sorts a hashtable whose values all have one type' {
        # Regression: names and values used to be sorted as two parallel arrays, and PowerShell
        # sorted a converted copy of the values when they were all strings (or all numbers).
        $strings = @{}; $strings['zeta'] = 'value-of-zeta'; $strings['alpha'] = 'value-of-alpha'; $strings['Mid'] = 'value-of-Mid'; $strings['beta'] = 'value-of-beta'
        $text = & $aw { param($t) ConvertTo-AwJsonText -InputObject $t -Compress } $strings
        Assert-Equal '{"Mid":"value-of-Mid","alpha":"value-of-alpha","beta":"value-of-beta","zeta":"value-of-zeta"}' $text
        $back = & $aw { param($t) ConvertFrom-AwJsonc -Text $t } $text
        Assert-Equal 4 $back.Count
        foreach ($k in $strings.Keys) { Assert-Equal $strings[$k] $back[$k] $k }
        $numbers = @{ c = 3; a = 1; b = 2 }
        Assert-Equal '{"a":1,"b":2,"c":3}' (& $aw { param($t) ConvertTo-AwJsonText -InputObject $t -Compress } $numbers)
        $flags = @{ off = $false; on = $true }
        Assert-Equal '{"off":false,"on":true}' (& $aw { param($t) ConvertTo-AwJsonText -InputObject $t -Compress } $flags)
    }
    It 'keeps the order of ordered dictionaries and mixed-type hashtables' {
        $ordered = [ordered]@{ zeta = 'z'; alpha = 'a' }
        Assert-Equal '{"zeta":"z","alpha":"a"}' (& $aw { param($t) ConvertTo-AwJsonText -InputObject $t -Compress } $ordered)
        $mixed = @{ zeta = 'z'; alpha = 1; mid = $null; beta = @('x') }
        Assert-Equal '{"alpha":1,"beta":["x"],"mid":null,"zeta":"z"}' (& $aw { param($t) ConvertTo-AwJsonText -InputObject $t -Compress } $mixed)
        Assert-Equal '{}' (& $aw { ConvertTo-AwJsonText -InputObject @{} -Compress })
    }
    It 'keeps one-element and empty arrays as arrays' {
        $json = Get-JsonText (New-TestResult -Findings @((New-TestFinding -References @('OWASP-ASI02'))) -Harnesses @())
        Assert-Match $json '"References": \[\s*"OWASP-ASI02"\s*\]'
        Assert-Match $json '"Harnesses": \[\]'
        Assert-Match $json '"Errors": \[\]'
    }
    It 'escapes control and HTML-sensitive characters and round-trips them' {
        $json = Get-JsonText (New-TestResult -Findings @((New-TestFinding -Evidence $h.jsonEvidence)))
        Assert-NotMatch $json "[<>&']"
        Assert-NotMatch $json '[\x00-\x09\x0B-\x1F\x7F-\x9F\p{Zl}\p{Zp}]'
        Assert-True ($json.Contains('\"q\" \\ \r\n\t'))
        Assert-Equal $h.jsonEvidence ($json | ConvertFrom-Json).Findings[0].Evidence
    }
    It 'escapes surrogates that are not part of a valid pair' {
        $pair = $highHalf + $lowHalf
        $evidence = 'a' + $highHalf + 'b ' + $lowHalf + $pair
        Assert-True (Test-LoneSurrogate $evidence)
        $json = Get-JsonText (New-TestResult -Findings @((New-TestFinding -Evidence $evidence)))
        Assert-False (Test-LoneSurrogate $json)
        $back = & $aw { param($t) (ConvertFrom-AwJsonc -Text $t)['Findings'][0]['Evidence'] } $json
        Assert-Equal $evidence $back
        Assert-Equal ('"' + $pair + '"') (& $aw { param($t) ConvertTo-AwJsonText -InputObject $t } $pair)
    }
    It 'masks a token left unmasked in a title, evidence or Data' {
        $f = New-TestFinding -Title "Token $fakeSecret in config" -Evidence "env.TOKEN = $fakeSecret" -Data @{ value = $fakeSecret; nested = @{ list = @($fakeSecret, 'ok') } }
        $json = Get-JsonText (New-TestResult -Findings @($f))
        Assert-False ($json.Contains('FAKEFAKEFAKEFAKE'))
        $p = $json | ConvertFrom-Json
        Assert-Match $p.Findings[0].Evidence '^env\.TOKEN = ghp_.12 \(42 chars\)$'
        Assert-Equal 'ok' $p.Findings[0].Data.nested.list[1]
    }
    It 'never writes rule check script blocks or unknown result properties' {
        $rule = New-TestRule -Id 'AW-VSC-001'
        $rule | Add-Member -NotePropertyName 'Check' -NotePropertyValue { 'CHECK_BODY_MARKER' }
        $r = New-TestResult -Findings @((New-TestFinding)) -Rules @($rule)
        $r | Add-Member -NotePropertyName 'Context' -NotePropertyValue @{ Raw = 'RAW_FILE_MARKER' }
        $r.Findings[0] | Add-Member -NotePropertyName 'Internal' -NotePropertyValue 'INTERNAL_MARKER'
        $json = Get-JsonText $r
        Assert-NotMatch $json 'CHECK_BODY_MARKER|RAW_FILE_MARKER|INTERNAL_MARKER|"Check"|"Context"'
        Assert-Equal 'null' (& $aw { ConvertTo-AwJsonText -InputObject { 'code' } })
    }
    It 'writes numbers with the invariant culture' {
        $saved = [System.Threading.Thread]::CurrentThread.CurrentCulture
        try {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = New-Object System.Globalization.CultureInfo('fr-FR')
            $text = & $aw { ConvertTo-AwJsonText -InputObject ([ordered]@{ a = 9.5; b = [decimal]2.25; c = 1234567; d = [double]::NaN }) -Compress }
            Assert-Equal '{"a":9.5,"b":2.25,"c":1234567,"d":null}' $text
        } finally {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = $saved
        }
    }
    It 'writes the categories in canonical order with weights, and counts in severity order' {
        $p = (Get-JsonText $mainResult) | ConvertFrom-Json
        Assert-Equal @('approvals', 'sandbox-network', 'mcp-supply-chain', 'agent-files', 'secrets', 'observability') (Get-Names $p.Score.Categories)
        Assert-Equal @('Title', 'Weight', 'Score', 'Applicable', 'Findings') (Get-Names $p.Score.Categories.approvals)
        Assert-Equal 25 $p.Score.Categories.approvals.Weight
        Assert-Equal @('critical', 'high', 'medium', 'low', 'info') (Get-Names $p.Score.Counts)
        Assert-Equal 1 $p.Score.Counts.critical
    }
    It 'cuts nesting deeper than 32 levels instead of failing' {
        $deep = @{ leaf = 'x' }
        for ($i = 0; $i -lt 40; $i++) { $deep = @{ next = $deep } }
        $json = Get-JsonText (New-TestResult -Findings @((New-TestFinding -Data $deep)))
        $p = $json | ConvertFrom-Json
        Assert-True ($null -ne $p.Findings[0].Data.next)
        Assert-NotMatch $json '"leaf"'
    }
    It 'handles an empty result' {
        $json = Get-JsonText (New-TestResult -Harnesses @())
        $p = $json | ConvertFrom-Json
        Assert-Match $json '"Findings": \[\]'
        Assert-Match $json '"Rules": \[\]'
        Assert-Equal 100 $p.Score.Score
        Assert-Equal 'A' $p.Score.Grade
    }
}

Describe 'ConvertTo-AwSarif' {
    $sarifText = Get-SarifText $mainResult
    $sarif = $sarifText | ConvertFrom-Json
    $run = $sarif.runs[0]
    $rulesById = @{}
    foreach ($d in $run.tool.driver.rules) { $rulesById[$d.id] = $d }

    It 'declares SARIF 2.1.0 with the schemastore schema and one run' {
        Assert-Equal 'https://json.schemastore.org/sarif-2.1.0.json' $sarif.'$schema'
        Assert-Equal '2.1.0' $sarif.version
        Assert-Equal 1 @($sarif.runs).Count
        Assert-Equal @('$schema', 'version', 'runs') (Get-Names $sarif)
    }
    It 'describes the tool driver' {
        $driver = $run.tool.driver
        Assert-Equal 'Airworthy' $driver.name
        Assert-Equal '0.2.0' $driver.version
        Assert-Equal 'https://github.com/toonight/Airworthy' $driver.informationUri
        Assert-True $run.invocations[0].executionSuccessful
        # Read the raw text: ConvertFrom-Json in PowerShell 7 turns ISO 8601 strings into DateTime.
        Assert-Match $sarifText '"endTimeUtc"\s*:\s*"2026-10-18T12:00:00Z"'
    }
    It 'lists every evaluated rule once, sorted, plus the rules that only appear in findings' {
        $ids = @($run.tool.driver.rules | ForEach-Object { $_.id })
        Assert-Equal @('AW-AGT-002', 'AW-CC-003', 'AW-CORE-002', 'AW-MCP-009', 'AW-SEC-004', 'AW-VSC-001') $ids
    }
    It 'fills each rule descriptor from the rule metadata' {
        $d = $rulesById['AW-VSC-001']
        Assert-Equal 'GlobalAutoApprovalOfToolsEnabled' $d.name
        Assert-Equal 'Global auto-approval of tools enabled' $d.shortDescription.text
        Assert-Equal 'Description of AW-VSC-001.' $d.fullDescription.text
        Assert-Equal 'Fix for AW-VSC-001.' $d.help.text
        Assert-Equal $urlRef $d.helpUri
        Assert-Equal @('approvals', 'vscode-copilot', 'OWASP-ASI02') @($d.properties.tags)
        Assert-Equal 'high' $d.properties.precision
        Assert-Equal 'medium' $rulesById['AW-CC-003'].properties.precision
    }
    It 'omits helpUri when no reference is a URL' {
        $d = $rulesById['AW-CC-003']
        Assert-False (@(Get-Names $d) -contains 'helpUri')
        Assert-Equal @('sandbox-network', 'claude-code', 'OWASP-ASI05') @($d.properties.tags)
        Assert-Equal @('secrets', 'generic') @($rulesById['AW-SEC-004'].properties.tags)
    }
    It 'maps rule severities to security-severity strings and default levels' {
        $expected = @{
            'AW-VSC-001' = @('9.5', 'error'); 'AW-AGT-002' = @('8.0', 'error'); 'AW-CC-003' = @('5.5', 'warning')
            'AW-SEC-004' = @('3.0', 'note'); 'AW-CORE-002' = @('0.0', 'note')
        }
        foreach ($id in $expected.Keys) {
            $d = $rulesById[$id]
            Assert-Equal $expected[$id][0] $d.properties.'security-severity' $id
            Assert-True ($d.properties.'security-severity' -is [string]) $id
            Assert-Equal $expected[$id][1] $d.defaultConfiguration.level $id
        }
        Assert-Match $sarifText '"security-severity": "9\.5"'
    }
    It 'maps finding severities to result levels, in finding order' {
        Assert-Equal @('AW-VSC-001', 'AW-AGT-002', 'AW-CC-003', 'AW-MCP-009', 'AW-CORE-002') @($run.results | ForEach-Object { $_.ruleId })
        Assert-Equal @('error', 'error', 'warning', 'note', 'note') @($run.results | ForEach-Object { $_.level })
    }
    It 'points every ruleIndex at the rule with the same id' {
        foreach ($res in $run.results) { Assert-Equal $res.ruleId $run.tool.driver.rules[$res.ruleIndex].id }
    }
    It 'builds message.text from the title and the evidence' {
        Assert-Equal 'Global auto-approval of tools enabled. Evidence: chat.tools.global.autoApprove = true' $run.results[0].message.text
        $noEvidence = (Get-SarifText (New-TestResult -Findings @((New-TestFinding -Title 'Only a title')))) | ConvertFrom-Json
        Assert-Equal 'Only a title' $noEvidence.runs[0].results[0].message.text
    }
    It 'uses relative POSIX URIs against SRCROOT inside the root, with startLine when known' {
        $loc = $run.results[0].locations[0].physicalLocation
        Assert-Equal '.vscode/settings.json' $loc.artifactLocation.uri
        Assert-Equal 'SRCROOT' $loc.artifactLocation.uriBaseId
        Assert-Equal 12 $loc.region.startLine
        Assert-False (@(Get-Names $run.results[1].locations[0].physicalLocation) -contains 'region')
        Assert-Equal 1 @($run.results[0].locations).Count
    }
    It 'percent-encodes URI path segments' {
        Assert-Equal '.github/agents/my%20agent%231%C3%A9.agent.md' $run.results[1].locations[0].physicalLocation.artifactLocation.uri
    }
    It 'declares SRCROOT as the absolute root URI ending with a slash' {
        Assert-Equal 'file:///C:/FakeAwRoot/repo/' $run.originalUriBaseIds.SRCROOT.uri
        Assert-False (@(Get-Names $run.originalUriBaseIds) -contains 'USERHOME')
    }
    It 'uses an absolute file URI for a file outside the root' {
        $art = $run.results[2].locations[0].physicalLocation.artifactLocation
        Assert-Equal 'file:///C:/FakeAwProfile/FAKEUSER/.claude/settings.json' $art.uri
        Assert-False (@(Get-Names $art) -contains 'uriBaseId')
        Assert-Equal 3 $run.results[2].locations[0].physicalLocation.region.startLine
    }
    It 'omits locations for a finding without a path and keeps its key' {
        $res = $run.results[4]
        Assert-False (@(Get-Names $res) -contains 'locations')
        Assert-Equal 'AW-VSC-999' $res.properties.key
        Assert-Equal 'info' $res.properties.severity
    }
    It 'converts drive, UNC and POSIX paths to file URIs' {
        $uris = & $aw {
            @(
                (ConvertTo-AwFileUri 'C:\a b\c%d.txt'),
                (ConvertTo-AwFileUri '\\server\share\a b.txt'),
                (ConvertTo-AwFileUri '/home/u/x.json'),
                (ConvertTo-AwFileUri 'C:\' -Directory),
                (ConvertTo-AwFileUri 'D:\repo' -Directory),
                (ConvertTo-AwFileUri '\\?\C:\long\path.txt')
            )
        }
        Assert-Equal @('file:///C:/a%20b/c%25d.txt', 'file://server/share/a%20b.txt', 'file:///home/u/x.json', 'file:///C:/', 'file:///D:/repo/', 'file:///C:/long/path.txt') @($uris)
        Assert-Equal 'a%3Ab/c' (& $aw { ConvertTo-AwRelativeUri 'a:b\c' })
    }
    It 'withholds the root and the user profile when the result is redacted' {
        $findings = @(
            (New-TestFinding -Path '.vscode\settings.json' -Line 2),
            (New-TestFinding -RuleId 'AW-CC-003' -Path '~\.claude\settings.json' -Line 5 -Harness 'claude-code'),
            (New-TestFinding -RuleId 'AW-CC-004' -Path 'D:\%USERNAME%\tools\x.json' -Harness 'claude-code')
        )
        $text = Get-SarifText (New-TestResult -Findings $findings -Root 'repo' -Redact)
        $r = ($text | ConvertFrom-Json).runs[0]
        $arts = @($r.results | ForEach-Object { $_.locations[0].physicalLocation.artifactLocation })
        Assert-Equal '.vscode/settings.json' $arts[0].uri
        Assert-Equal 'SRCROOT' $arts[0].uriBaseId
        Assert-Equal '.claude/settings.json' $arts[1].uri
        Assert-Equal 'USERHOME' $arts[1].uriBaseId
        Assert-Equal 'file:///D:/%25USERNAME%25/tools/x.json' $arts[2].uri
        Assert-False (@(Get-Names $r.originalUriBaseIds.SRCROOT) -contains 'uri')
        Assert-False (@(Get-Names $r.originalUriBaseIds.USERHOME) -contains 'uri')
        Assert-NotMatch $text 'FakeAw|FAKEUSER|file:///C:'
    }
    It 'masks a token left in evidence' {
        $text = Get-SarifText (New-TestResult -Findings @((New-TestFinding -Evidence "key $fakeSecret")))
        Assert-False ($text.Contains('FAKEFAKEFAKEFAKE'))
        Assert-Match $text 'Evidence: key ghp_'
    }
    It 'truncates descriptions to the 1024 characters GitHub accepts' {
        $rule = New-TestRule -Id 'AW-VSC-001' -Description ('x' * 2000) -Title ('T' * 1500)
        $d = ((Get-SarifText (New-TestResult -Rules @($rule))) | ConvertFrom-Json).runs[0].tool.driver.rules[0]
        Assert-Equal 1024 $d.fullDescription.text.Length
        Assert-Equal 1024 $d.shortDescription.text.Length
        Assert-Equal 255 $d.name.Length
    }
    It 'produces a valid log for an empty result' {
        $text = Get-SarifText (New-TestResult -Harnesses @())
        $r = ($text | ConvertFrom-Json).runs[0]
        Assert-Match $text '"results": \[\]'
        Assert-Match $text '"rules": \[\]'
        Assert-Equal 'file:///C:/FakeAwRoot/repo/' $r.originalUriBaseIds.SRCROOT.uri
    }
}

Describe 'ConvertTo-AwMarkdown' {
    $md = Get-MarkdownText $mainResult
    $mdLines = @($md -split '\n')

    It 'starts with a title and a summary table with the score and grade' {
        Assert-Equal '# Airworthy report' $mdLines[0]
        $s = $mainResult.Score
        Assert-Contains $mdLines "**Score: $($s.Score)/100, grade $($s.Grade)**"
        Assert-Contains $mdLines '| Item | Value |'
        Assert-Contains $mdLines "| Grade | $($s.Grade) |"
        Assert-Contains $mdLines '| Findings | 1 critical, 1 high, 1 medium, 1 low, 1 info |'
        Assert-Contains $mdLines '| Root | `C:\FakeAwRoot\repo` |'
        Assert-Contains $mdLines '| Harnesses | vscode-copilot, claude-code |'
        Assert-Contains $mdLines '| FailOn | high: failed (exit code 1) |'
        Assert-True ($md.EndsWith($LF))
    }
    It 'lists every category, with n/a for the categories that do not apply' {
        $s = $mainResult.Score.Categories
        Assert-Contains $mdLines "| Approvals and terminal | 25 | $($s['approvals'].Score) | 1 |"
        Assert-Contains $mdLines '| MCP and supply chain | 20 | n/a | 1 |'
        Assert-Contains $mdLines "| Secrets | 15 | $($s['secrets'].Score) | 0 |"
    }
    It 'groups the findings by severity, most severe first' {
        $order = @('### Critical (1)', '### High (1)', '### Medium (1)', '### Low (1)', '### Info (1)') | ForEach-Object { [array]::IndexOf($mdLines, $_) }
        foreach ($i in $order) { Assert-True ($i -gt 0) }
        Assert-Equal (@($order | Sort-Object)) @($order)
    }
    It 'shows the rule ID, title, location, evidence and fix of each finding' {
        Assert-Contains $mdLines '#### AW-VSC-001: Global auto-approval of tools enabled'
        Assert-Contains $mdLines '- **Location:** `.vscode\settings.json:12`, key `chat.tools.global.autoApprove`'
        Assert-Contains $mdLines '- **Evidence:** `chat.tools.global.autoApprove = true`'
        Assert-Contains $mdLines '- **Fix:** Apply the fix.'
        Assert-Contains $mdLines ('- **References:** OWASP-ASI02, ' + $h.vscodeLink)
        Assert-Contains $mdLines '- **Location:** `C:\FakeAwProfile\FAKEUSER\.claude\settings.json:3`'
        Assert-Contains $mdLines '- **Location:** key `AW-VSC-999`'
    }
    It 'lists the rules evaluated with their finding counts' {
        Assert-Contains $mdLines '## Rules evaluated'
        Assert-Contains $mdLines '| AW-VSC-001 | Global auto-approval of tools enabled | critical | approvals | vscode-copilot | high | 1 |'
        Assert-Contains $mdLines '| AW-SEC-004 | Rule AW-SEC-004 | low | secrets | generic | high | 0 |'
        Assert-Match $md '4 rules were evaluated'
    }
    It 'renders hostile values as literal text' {
        $f = New-TestFinding -Title $h.mdTitle -Evidence $h.mdEvidence -Path ($fakeRoot + '\' + $h.backtickFile) -Fix $h.mdFix
        $lines = @((Get-MarkdownText (New-TestResult -Findings @($f))) -split '\n')
        Assert-Contains $lines ('#### AW-VSC-001: ' + $h.mdTitleExpected)
        Assert-Contains $lines ('- **Evidence:** ' + $h.mdEvidenceExpected)
        Assert-Contains $lines $h.backtickLocation
        Assert-Contains $lines ('- **Fix:** ' + $h.mdFixExpected)
        Assert-Equal 0 @($lines | Where-Object { $_ -match '^#+ Injected' }).Count
    }
    It 'escapes pipes in table cells' {
        $lines = @((Get-MarkdownText (New-TestResult -Root '/tmp/a|b' -Rules @((New-TestRule -Id 'AW-VSC-001' -Title 'A | B')))) -split '\n')
        Assert-Contains $lines '| Root | `/tmp/a\|b` |'
        Assert-Equal 1 @($lines | Where-Object { $_.StartsWith('| AW-VSC-001 | A \| B |') }).Count
    }
    It 'renders URL references as autolinks and anything else as text' {
        $f = New-TestFinding -References @('https://docs.github.com/en/copilot', 'ftp://x.test/file', $h.badUrl, 'OWASP-ASI01')
        $lines = @((Get-MarkdownText (New-TestResult -Findings @($f))) -split '\n')
        Assert-Contains $lines ('- **References:** ' + $h.docsLink + ', ftp://x.test/file, ' + $h.badUrlExpected + ', OWASP-ASI01')
    }
    It 'says when there are no findings' {
        $lines = @((Get-MarkdownText (New-TestResult -Harnesses @())) -split '\n')
        Assert-Contains $lines 'No findings at or above info.'
        Assert-Contains $lines 'No rule applied to the detected harnesses.'
    }
    It 'tells how many findings -MinSeverity hides' {
        $text = Get-MarkdownText (New-TestResult -Findings $mainFindings -Rules $evalRules -MinSeverity 'high')
        Assert-Match $text '\| Shown \| 2 at or above high \(3 hidden by -MinSeverity\) \|'
        Assert-Match $text '_3 lower-severity findings are not shown'
        Assert-NotMatch $text '### Medium'
    }
    It 'masks a token left in evidence' {
        $text = Get-MarkdownText (New-TestResult -Findings @((New-TestFinding -Evidence "key $fakeSecret")))
        Assert-False ($text.Contains('FAKEFAKEFAKEFAKE'))
    }
}

Describe 'ConvertTo-AwConsole' {
    $lines = Get-ConsoleLines $mainResult
    $text = $lines -join $LF

    It 'prints the score, grade and severity counts' {
        $s = $mainResult.Score
        Assert-Match $lines[0] '^Airworthy 0\.2\.0'
        Assert-Contains $lines "  Score      $($s.Score)/100  grade $($s.Grade)"
        Assert-Contains $lines '  Findings   1 critical, 1 high, 1 medium, 1 low, 1 info'
        Assert-Contains $lines '  Root       C:\FakeAwRoot\repo'
    }
    It 'draws a text bar per applicable category and n/a otherwise' {
        Assert-Equal '[--------------------]' (& $aw { Get-AwTextBar 0 })
        Assert-Equal '[####################]' (& $aw { Get-AwTextBar 100 })
        Assert-Equal '[########------------]' (& $aw { Get-AwTextBar 42 })
        Assert-Equal '[#########-----------]' (& $aw { Get-AwTextBar 45 })
        $approvals = $mainResult.Score.Categories['approvals'].Score
        $bar = & $aw { param($s) Get-AwTextBar $s } $approvals
        Assert-Contains $lines ('  ' + 'Approvals and terminal'.PadRight(30) + $bar + ' ' + ([string]$approvals).PadLeft(3) + '  1 finding')
        Assert-Contains $lines ('  ' + 'MCP and supply chain'.PadRight(30) + 'n/a (not applicable to the detected harnesses)')
    }
    It 'groups the findings by severity with rule ID, title, path:line and fix' {
        $order = @('  CRITICAL (1)', '  HIGH (1)', '  MEDIUM (1)', '  LOW (1)', '  INFO (1)') | ForEach-Object { [array]::IndexOf($lines, $_) }
        foreach ($i in $order) { Assert-True ($i -gt 0) }
        Assert-Equal (@($order | Sort-Object)) @($order)
        $i = [array]::IndexOf($lines, '    AW-VSC-001  Global auto-approval of tools enabled')
        Assert-True ($i -gt 0)
        Assert-Equal '        .vscode\settings.json:12' $lines[$i + 1]
        Assert-Equal '        Evidence: chat.tools.global.autoApprove = true' $lines[$i + 2]
        Assert-Equal '        Fix: Apply the fix.' $lines[$i + 3]
        Assert-Contains $lines "        $fakeProfile\.claude\settings.json:3"
    }
    It 'shows the key only when the evidence does not name it' {
        Assert-Contains $lines ('        .github\agents\' + $h.agentFile + ' [frontmatter.tools]')
        Assert-Contains $lines '        [AW-VSC-999]'
        Assert-NotMatch $text 'settings\.json:12 \['
    }
    It 'respects -MinSeverity and says how many findings are hidden' {
        $t = Get-ConsoleText $mainResult -MinSeverity 'high'
        Assert-Match $t 'AW-VSC-001'
        Assert-Match $t 'AW-AGT-002'
        Assert-NotMatch $t 'AW-CC-003|AW-MCP-009|AW-CORE-002|MEDIUM \('
        Assert-Match $t "3 findings below 'high' not shown"
    }
    It 'uses the MinSeverity option of the result by default' {
        $r = New-TestResult -Findings $mainFindings -Rules $evalRules
        $r.Options.MinSeverity = 'critical'
        $t = Get-ConsoleText $r
        Assert-Match $t 'AW-VSC-001'
        Assert-NotMatch $t 'AW-AGT-002'
        Assert-Match $t "4 findings below 'critical' not shown"
    }
    It 'strips terminal control characters and line breaks from file values' {
        $f = New-TestFinding -Title $h.consoleTitle -Evidence $h.consoleEvidence -Path ($fakeRoot + '\' + $h.consolePath)
        $out = Get-ConsoleLines (New-TestResult -Findings @($f))
        $t = $out -join $LF
        Assert-NotMatch $t '[\x00-\x09\x0B-\x1F]'
        Assert-Equal 1 @($out | Where-Object { $_ -match '^\s+Fix: ' }).Count
        Assert-Match $t 'Bad\?\[1m\?end'
        Assert-Match $t 'Evidence: \?\[31mred\?\[0m\s+Fix: forged'
        Assert-Contains $out '        a b.json'
    }
    It 'cuts very long values' {
        $out = Get-ConsoleLines (New-TestResult -Findings @((New-TestFinding -Evidence ('v' * 5000))))
        $line = @($out | Where-Object { $_ -match 'Evidence: ' })[0]
        Assert-True ($line.Length -lt 330) "length $($line.Length)"
        Assert-True ($line.EndsWith('...'))
    }
    It 'masks a token left in evidence' {
        $t = Get-ConsoleText (New-TestResult -Findings @((New-TestFinding -Evidence "key $fakeSecret")))
        Assert-False ($t.Contains('FAKEFAKEFAKEFAKE'))
    }
    It 'reports the FailOn status' {
        Assert-Contains $lines 'FailOn high: failed (exit code 1).'
        Assert-Match (Get-ConsoleText (New-TestResult -FailOn 'critical')) 'FailOn critical: passed\.'
    }
    It 'says when there are no findings' {
        $t = Get-ConsoleText (New-TestResult -Harnesses @())
        Assert-Match $t "No findings at or above 'info'\."
        Assert-Match $t '\(none detected\)'
    }
    It 'writes colored text to the host and nothing to the pipeline' {
        $records = @(& $aw { param($r) ConvertTo-AwConsole $r 6>&1 } $mainResult)
        Assert-True ($records.Count -gt 10)
        Assert-Equal 0 @($records | Where-Object { $_ -isnot [System.Management.Automation.InformationRecord] }).Count
        $critical = @($records | Where-Object { $_.MessageData.Message -eq '  CRITICAL (1)' })
        Assert-Equal 1 $critical.Count
        Assert-Equal 'Magenta' ([string]$critical[0].MessageData.ForegroundColor)
        $fix = @($records | Where-Object { $_.MessageData.Message -eq 'Apply the fix.' })
        Assert-Equal 'Green' ([string]$fix[0].MessageData.ForegroundColor)
    }
}

Describe 'Rendering through Invoke-Airworthy' {
    $tmp = Join-Path $fixtures ('output\_tmp-' + [guid]::NewGuid().ToString('N'))
    & $aw {
        param($token)
        $script:SavedRules = $script:AwRules.Clone()
        $script:AwRules.Clear()
        $check = { param($Ctx) New-AwFinding -RuleId 'AW-CORE-000' -Evidence ('token ' + $script:OutputTestToken) -Location @{ Path = (Join-Path $Ctx.Root '.vscode\settings.json'); Line = 2; Key = 'output.test' } }
        $script:OutputTestToken = $token
        Register-AwRule -Id 'AW-CORE-000' -Title 'Output test rule' -Severity 'high' -Category 'secrets' -Harness 'generic' -Description 'Test-only rule for the output tests.' -Fix 'None.' -References @('OWASP-ASI03', 'https://genai.owasp.org') -Check $check
    } $fakeSecret
    try {
        It 'writes the JSON, SARIF and Markdown files' {
            $base = Join-Path $tmp 'report'
            $r = Invoke-Airworthy -Path $insecure -NoUserProfile -Format Json, Sarif, Markdown -OutFile $base -PassThru -Quiet
            foreach ($ext in @('.json', '.sarif', '.md')) { Assert-True (Test-Path -LiteralPath ($base + $ext)) $ext }
            $json = [System.IO.File]::ReadAllText($base + '.json') | ConvertFrom-Json
            Assert-Equal @($r.Findings).Count @($json.Findings).Count
            $sarif = [System.IO.File]::ReadAllText($base + '.sarif') | ConvertFrom-Json
            $results = @($sarif.runs[0].results)
            Assert-Equal @($r.Findings).Count $results.Count
            $hit = @($results | Where-Object { $_.ruleId -eq 'AW-CORE-000' })[0]
            Assert-Equal '.vscode/settings.json' $hit.locations[0].physicalLocation.artifactLocation.uri
            Assert-Equal 'error' $hit.level
            foreach ($res in $results) { Assert-Equal $res.ruleId $sarif.runs[0].tool.driver.rules[$res.ruleIndex].id }
            Assert-Match ([System.IO.File]::ReadAllText($base + '.md')) '#### AW-CORE-000: Output test rule'
            foreach ($ext in @('.json', '.sarif', '.md')) {
                Assert-False ([System.IO.File]::ReadAllText($base + $ext).Contains('FAKEFAKEFAKEFAKE')) $ext
            }
        }
        It 'returns the rendered texts before the result without -OutFile' {
            $out = @(Invoke-Airworthy -Path $insecure -NoUserProfile -Format Markdown, Json -PassThru)
            Assert-Equal 3 $out.Count
            Assert-True ($out[0] -is [string])
            Assert-Equal 'Airworthy' ($out[0] | ConvertFrom-Json).Tool.Name
            Assert-Match $out[1] '^# Airworthy report'
            Assert-Equal 'Airworthy' $out[2].Tool.Name
        }
        It 'prints the console summary to the host' {
            $records = @(Invoke-Airworthy -Path $insecure -NoUserProfile 6>&1)
            $text = (@($records | ForEach-Object { $_.MessageData.Message }) -join '')
            Assert-Match $text 'AW-CORE-000  Output test rule'
            Assert-Match $text 'Score      '
        }
    } finally {
        & $aw { $script:AwRules.Clear(); foreach ($k in $script:SavedRules.Keys) { $script:AwRules[$k] = $script:SavedRules[$k] } }
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force }
    }
}
