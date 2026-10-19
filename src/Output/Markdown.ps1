# Markdown output: a readable report (summary, categories, findings with fixes, rules evaluated).
# Values from scanned files go into code spans; other text is backslash-escaped, so a hostile
# value can neither inject HTML nor change the structure of the document.

$script:AwMarkdownMaxText = 2000
$script:AwMarkdownUrlPattern = '^https?://[A-Za-z0-9\-._~:/?#\[\]@!$&''()*+,;=%]+$'

function ConvertTo-AwMdText {
    # Plain inline text: one line, Markdown and HTML-sensitive punctuation escaped.
    param([AllowNull()] [AllowEmptyString()] [string]$Text, [int]$MaxLength = $script:AwMarkdownMaxText)
    $t = Get-AwSafeText $Text -MaxLength $MaxLength
    return [regex]::Replace($t, '[\\`*_\[\]<>|~&#!]', '\$0')
}

function ConvertTo-AwMdCode {
    # Inline code span that holds any text literally. In a table cell, pipes are escaped too.
    param([AllowNull()] [AllowEmptyString()] [string]$Text, [int]$MaxLength = $script:AwMarkdownMaxText, [switch]$InTable)
    $t = Get-AwSafeText $Text -MaxLength $MaxLength
    if ($t -eq '') { return '' }
    if ($InTable) { $t = $t.Replace('|', '\|') }
    $longest = 0
    foreach ($m in [regex]::Matches($t, '`+')) { if ($m.Length -gt $longest) { $longest = $m.Length } }
    $fence = '`' * ($longest + 1)
    if ($t.StartsWith('`') -or $t.EndsWith('`')) { $t = " $t " }
    return $fence + $t + $fence
}

function ConvertTo-AwMdReference {
    # A web reference as an autolink when it is a plain http(s) URL, otherwise as text.
    param([string]$Reference)
    if ($Reference -match $script:AwMarkdownUrlPattern) { return "<$Reference>" }
    return (ConvertTo-AwMdText $Reference)
}

function ConvertTo-AwMarkdown {
    <#
    .SYNOPSIS
    Renders a Airworthy result as a Markdown report.
    .DESCRIPTION
    The report has a summary table (score, grade, counts, root, harnesses), the category
    scores, the findings grouped by severity with location, evidence, fix and references, and
    the list of rules evaluated. Paths inside the analyzed root are shown relative to it.
    Text from scanned files is kept on one line and rendered literally (code spans or
    escaped text), so the report stays safe to preview even for a hostile repository.
    .PARAMETER Result
    The result object returned by Invoke-Airworthy -PassThru.
    .EXAMPLE
    ConvertTo-AwMarkdown $result | Set-Content -Encoding UTF8 report.md
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0)] $Result)

    $md = New-Object System.Collections.Generic.List[string]
    $options = Get-AwMemberValue $Result 'Options'
    $minSeverity = Get-AwOutputText $options 'MinSeverity'
    if ((Get-AwSeverityRank $minSeverity) -lt 0) { $minSeverity = 'info' }
    $tool = Get-AwMemberValue $Result 'Tool'
    $toolName = Get-AwOutputText $tool 'Name'; if (-not $toolName) { $toolName = $script:AwToolName }
    $toolVersion = Get-AwOutputText $tool 'Version'; if (-not $toolVersion) { $toolVersion = $script:AwToolVersion }
    $score = Get-AwMemberValue $Result 'Score'
    $scoreValue = Get-AwOutputText $score 'Score'; if (-not $scoreValue) { $scoreValue = '?' }
    $grade = Get-AwOutputText $score 'Grade'; if (-not $grade) { $grade = '?' }
    $counts = Get-AwOutputCounts $Result
    $findings = @(Get-AwOutputFindings -Result $Result -MinSeverity $minSeverity)
    $total = 0
    foreach ($s in $script:AwSeverities) { $total += $counts[$s] }
    $hidden = [Math]::Max(0, $total - $findings.Count)

    # Summary
    $md.Add("# $(ConvertTo-AwMdText $toolName) report")
    $md.Add('')
    $md.Add("**Score: $(ConvertTo-AwMdText $scoreValue)/100, grade $(ConvertTo-AwMdText $grade)**")
    $md.Add('')
    $md.Add('| Item | Value |')
    $md.Add('| --- | --- |')
    $md.Add("| Score | $(ConvertTo-AwMdText $scoreValue) / 100 |")
    $md.Add("| Grade | $(ConvertTo-AwMdText $grade) |")
    $md.Add('| Findings | ' + (@(foreach ($s in $script:AwSeverities) { "$($counts[$s]) $s" }) -join ', ') + ' |')
    $shownText = "$($findings.Count) at or above $minSeverity"
    if ($hidden -gt 0) { $shownText += " ($hidden hidden by -MinSeverity)" }
    $md.Add("| Shown | $shownText |")
    $harnesses = @(Get-AwOutputList $Result 'Harnesses' | ForEach-Object { ConvertTo-AwMdText ([string]$_) -MaxLength 40 })
    $md.Add('| Harnesses | ' + $(if ($harnesses.Count -gt 0) { $harnesses -join ', ' } else { 'none detected' }) + ' |')
    $md.Add("| Root | $(ConvertTo-AwMdCode (Get-AwOutputText $Result 'Root') -InTable) |")
    $scannedAt = Get-AwOutputText $Result 'ScannedAt'
    if ($scannedAt) { $md.Add("| Scanned at | $(ConvertTo-AwMdText $scannedAt) |") }
    $md.Add("| Tool | $(ConvertTo-AwMdText "$toolName $toolVersion") |")
    if ([bool](Get-AwMemberValue $options 'Redact')) { $md.Add('| Redacted | yes |') }
    $failOn = Get-AwOutputText $options 'FailOn'
    if ($failOn) {
        $status = if ((Get-AwOutputText $Result 'ExitCode') -eq '1') { 'failed (exit code 1)' } else { 'passed' }
        $md.Add("| FailOn | $(ConvertTo-AwMdText $failOn): $status |")
    }

    # Categories
    $categories = @(Get-AwOutputCategories $Result)
    if ($categories.Count -gt 0) {
        $md.Add('')
        $md.Add('## Categories')
        $md.Add('')
        $md.Add('| Category | Weight | Score | Findings |')
        $md.Add('| --- | ---: | ---: | ---: |')
        foreach ($c in $categories) {
            $cell = if ($c.Applicable) { [string]$c.Score } else { 'n/a' }
            $md.Add("| $(ConvertTo-AwMdText $c.Title) | $($c.Weight) | $cell | $($c.Findings) |")
        }
        if (@($categories | Where-Object { -not $_.Applicable }).Count -gt 0) {
            $md.Add('')
            $md.Add('Categories marked n/a have no rule for the detected harnesses and do not count in the score.')
        }
    }

    # Findings, grouped by severity
    $md.Add('')
    $md.Add('## Findings')
    $md.Add('')
    if ($findings.Count -eq 0) {
        $md.Add("No findings at or above $minSeverity.")
    }
    foreach ($sev in $script:AwSeverities) {
        $group = @($findings | Where-Object { [string](Get-AwMemberValue $_ 'Severity') -eq $sev })
        if ($group.Count -eq 0) { continue }
        $md.Add("### $($sev.Substring(0, 1).ToUpperInvariant() + $sev.Substring(1)) ($($group.Count))")
        $md.Add('')
        foreach ($f in $group) {
            $md.Add("#### $(ConvertTo-AwMdText (Get-AwOutputText $f 'RuleId') -MaxLength 40): $(ConvertTo-AwMdText (Get-AwOutputTitle $f))")
            $md.Add('')
            $where = Get-AwOutputLocation -Result $Result -Finding $f
            $key = Get-AwOutputText (Get-AwMemberValue $f 'Location') 'Key'
            $parts = New-Object System.Collections.Generic.List[string]
            if ($where) { $parts.Add((ConvertTo-AwMdCode $where)) }
            if ($key) { $parts.Add('key ' + (ConvertTo-AwMdCode $key)) }
            if ($parts.Count -gt 0) { $md.Add('- **Location:** ' + ($parts -join ', ')) }
            $evidence = Get-AwOutputEvidence $f
            if ($evidence) { $md.Add('- **Evidence:** ' + (ConvertTo-AwMdCode $evidence)) }
            $fix = Get-AwOutputText $f 'Fix'
            if ($fix) { $md.Add('- **Fix:** ' + (ConvertTo-AwMdText $fix)) }
            $description = Get-AwOutputText $f 'Description'
            if ($description) { $md.Add('- **Why it matters:** ' + (ConvertTo-AwMdText $description)) }
            $category = Get-AwCategoryTitle (Get-AwOutputText $f 'Category')
            $details = New-Object System.Collections.Generic.List[string]
            if ($category) { $details.Add('category ' + (ConvertTo-AwMdText $category)) }
            $harness = Get-AwOutputText $f 'Harness'
            if ($harness) { $details.Add('harness ' + (ConvertTo-AwMdText $harness)) }
            $confidence = Get-AwOutputText $f 'Confidence'
            if ($confidence) { $details.Add('confidence ' + (ConvertTo-AwMdText $confidence)) }
            if ($details.Count -gt 0) { $md.Add('- **Details:** ' + ($details -join ', ')) }
            $refs = @(Get-AwOutputList $f 'References' | ForEach-Object { ConvertTo-AwMdReference ([string]$_) })
            if ($refs.Count -gt 0) { $md.Add('- **References:** ' + ($refs -join ', ')) }
            $md.Add('')
        }
    }
    if ($hidden -gt 0) {
        $md.Add("_$hidden lower-severity findings are not shown (-MinSeverity $minSeverity). They still count in the score._")
        $md.Add('')
    }

    # Rules evaluated
    $rules = @(Get-AwOutputList $Result 'Rules')
    $md.Add('## Rules evaluated')
    $md.Add('')
    if ($rules.Count -eq 0) {
        $md.Add('No rule applied to the detected harnesses.')
    } else {
        $perRule = @{}
        foreach ($f in $findings) {
            $id = Get-AwOutputText $f 'RuleId'
            if ($id) { $perRule[$id] = 1 + $(if ($perRule.ContainsKey($id)) { $perRule[$id] } else { 0 }) }
        }
        $evaluated = if ($rules.Count -eq 1) { '1 rule was' } else { "$($rules.Count) rules were" }
        $md.Add("$evaluated evaluated for the detected harnesses. The Findings column counts the findings shown above.")
        $md.Add('')
        $md.Add('| Rule | Title | Severity | Category | Harness | Confidence | Findings |')
        $md.Add('| --- | --- | --- | --- | --- | --- | ---: |')
        foreach ($r in $rules) {
            $id = Get-AwOutputText $r 'Id'
            $n = if ($id -and $perRule.ContainsKey($id)) { $perRule[$id] } else { 0 }
            $cells = @(
                (ConvertTo-AwMdText $id -MaxLength 40),
                (ConvertTo-AwMdText (Get-AwOutputText $r 'Title') -MaxLength 300),
                (ConvertTo-AwMdText (Get-AwOutputText $r 'Severity')),
                (ConvertTo-AwMdText (Get-AwOutputText $r 'Category')),
                (ConvertTo-AwMdText (Get-AwOutputText $r 'Harness')),
                (ConvertTo-AwMdText (Get-AwOutputText $r 'Confidence')),
                [string]$n
            )
            $md.Add('| ' + ($cells -join ' | ') + ' |')
        }
    }

    $md.Add('')
    $md.Add('---')
    $md.Add('')
    $md.Add("Generated offline by $(ConvertTo-AwMdText "$toolName $toolVersion"). Static analysis only: no agent, MCP server or hook was run.")
    return (($md -join "`n") + "`n")
}
