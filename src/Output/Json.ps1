# JSON output (ConvertTo-AwJson), the deterministic JSON writer used by the JSON and SARIF
# outputs, and small helpers shared by the Console, Markdown, JSON and SARIF renderers.

$script:AwInvariant = [System.Globalization.CultureInfo]::InvariantCulture
$script:AwJsonMaxDepth = 32
$script:AwJsonIntegerTypes = @([byte], [sbyte], [int16], [uint16], [int32], [uint32], [int64], [uint64], [decimal])

# Characters escaped in JSON strings: control characters (Cc), quote, backslash, the
# HTML-sensitive < > & ', U+2028 (Zl), U+2029 (Zp) and surrogates (Cs) that are not part of a
# valid pair. Two surrogates in a row are captured together so that a valid pair stays as is.
$script:AwJsonEscapeRegex = New-Object System.Text.RegularExpressions.Regex -ArgumentList '(\p{Cs}\p{Cs})|[\p{Cc}"\\<>&''\p{Zl}\p{Zp}\p{Cs}]'
$script:AwJsonEscapeEvaluator = [System.Text.RegularExpressions.MatchEvaluator] {
    param($m)
    $v = $m.Value
    if ($m.Groups[1].Success) {
        if ([char]::IsSurrogatePair($v[0], $v[1])) { return $v }
        return (ConvertTo-AwJsonCharEscape $v[0]) + (ConvertTo-AwJsonCharEscape $v[1])
    }
    return (ConvertTo-AwJsonCharEscape $v[0])
}

# Line breaks become spaces; other control and invisible format characters (bidirectional
# overrides, zero-width characters) become '?'.
$script:AwBreakRegex = New-Object System.Text.RegularExpressions.Regex -ArgumentList '[\r\n\t\p{Zl}\p{Zp}]+'
$script:AwUnsafeCharRegex = New-Object System.Text.RegularExpressions.Regex -ArgumentList '[\p{Cc}\p{Cf}]'

function ConvertTo-AwJsonCharEscape {
    # JSON escape of one character: the short form when there is one, \uXXXX otherwise.
    param([char]$Char)
    switch ([int]$Char) {
        0x22 { return '\"' }
        0x5C { return '\\' }
        0x0A { return '\n' }
        0x0D { return '\r' }
        0x09 { return '\t' }
    }
    return ('\u{0:x4}' -f [int]$Char)
}

#region Shared output helpers

function Get-AwOutputText {
    # A member as a string, or $null when it is absent or $null.
    param($Object, [string]$Name)
    $v = Get-AwMemberValue $Object $Name
    if ($null -eq $v) { return $null }
    return [string]$v
}

function Get-AwOutputList {
    # A member as a list without $null items (empty when absent). Callers wrap the call in @().
    param($Object, [string]$Name)
    @(Get-AwMemberValue $Object $Name | Where-Object { $null -ne $_ })
}

function Get-AwOutputLine {
    # Location.Line of a finding as a positive integer, or $null.
    param($Finding)
    $line = Get-AwMemberValue (Get-AwMemberValue $Finding 'Location') 'Line'
    $n = 0
    if ($null -ne $line -and [int]::TryParse([string]$line, [ref]$n) -and $n -gt 0) { return $n }
    return $null
}

function Get-AwOutputEvidence {
    # Evidence with any remaining token-like value masked (last line of defense), or $null.
    param($Finding)
    $e = Get-AwOutputText $Finding 'Evidence'
    if ([string]::IsNullOrEmpty($e)) { return $null }
    return (Hide-AwSecretsInText $e)
}

function Get-AwOutputTitle {
    # Title with token-like values masked; the rule ID when the title is empty.
    param($Finding)
    $t = Get-AwOutputText $Finding 'Title'
    if ([string]::IsNullOrEmpty($t)) { return (Get-AwOutputText $Finding 'RuleId') }
    return (Hide-AwSecretsInText $t)
}

function Get-AwSafeText {
    # One printable line: trimmed, line breaks as spaces, control and bidi characters as '?',
    # cut to MaxLength characters (0 = no limit).
    param([AllowNull()] [AllowEmptyString()] [string]$Text, [int]$MaxLength = 0)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $t = $script:AwUnsafeCharRegex.Replace($script:AwBreakRegex.Replace($Text, ' '), '?').Trim()
    return (Get-AwShortText -Text $t -MaxLength $MaxLength)
}

function Get-AwShortText {
    # Text cut to MaxLength characters, ending with '...' when cut (0 = no limit).
    param([AllowNull()] [AllowEmptyString()] [string]$Text, [int]$MaxLength = 0)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    if ($MaxLength -le 3 -or $Text.Length -le $MaxLength) { return $Text }
    $cut = $MaxLength - 3
    if ([char]::IsHighSurrogate($Text[$cut - 1])) { $cut-- }
    return $Text.Substring(0, $cut) + '...'
}

function Get-AwOutputPath {
    # Display form of a path: relative to the root when inside it, redacted when the result is.
    param($Result, [AllowNull()] [AllowEmptyString()] [string]$Path)
    if ([string]::IsNullOrEmpty($Path)) { return $null }
    $redact = [bool](Get-AwMemberValue (Get-AwMemberValue $Result 'Options') 'Redact')
    return (Get-AwDisplayPath -Path $Path -Ctx $Result -Redact:$redact)
}

function Get-AwOutputLocation {
    # 'path:line' (or 'path') for display, or $null when the finding has no path.
    param($Result, $Finding)
    $path = Get-AwOutputText (Get-AwMemberValue $Finding 'Location') 'Path'
    if ([string]::IsNullOrEmpty($path)) { return $null }
    $display = Get-AwOutputPath -Result $Result -Path $path
    $line = Get-AwOutputLine $Finding
    if ($null -ne $line) { return "${display}:$line" }
    return $display
}

function Get-AwOutputFindings {
    # Findings at or above MinSeverity (default: the result's MinSeverity option), in result order.
    param($Result, [string]$MinSeverity)
    if (-not $MinSeverity) { $MinSeverity = Get-AwOutputText (Get-AwMemberValue $Result 'Options') 'MinSeverity' }
    $min = Get-AwSeverityRank $MinSeverity
    $all = @(Get-AwOutputList $Result 'Findings')
    if ($min -le 0) { return $all }
    @($all | Where-Object { (Get-AwSeverityRank ([string](Get-AwMemberValue $_ 'Severity'))) -ge $min })
}

function Get-AwOutputCounts {
    # Finding counts per severity, over every finding (the score's Counts), in severity order.
    param($Result)
    $counts = Get-AwMemberValue (Get-AwMemberValue $Result 'Score') 'Counts'
    $out = [ordered]@{}
    foreach ($s in $script:AwSeverities) {
        $n = 0
        [void][int]::TryParse([string](Get-AwMemberValue $counts $s), [ref]$n)
        $out[$s] = $n
    }
    return $out
}

function Get-AwMemberNames {
    # Keys of a dictionary or property names of an object, as strings.
    param($Object)
    if ($null -eq $Object) { return @() }
    if ($Object -is [System.Collections.IDictionary]) { return @(foreach ($k in $Object.Keys) { [string]$k }) }
    return @(foreach ($p in $Object.PSObject.Properties) { $p.Name })
}

function Get-AwOutputCategories {
    # Category rows { Name; Title; Weight; Score; Applicable; Findings }: the known categories in
    # their canonical order, then any other category name in ordinal order.
    param($Result)
    $cats = Get-AwMemberValue (Get-AwMemberValue $Result 'Score') 'Categories'
    $present = @(Get-AwMemberNames $cats)
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($c in $script:AwCategories.Keys) { if ($present -contains $c) { $names.Add($c) } }
    $extra = [string[]]@($present | Where-Object { -not $script:AwCategories.Contains($_) })
    [Array]::Sort($extra, [StringComparer]::Ordinal)
    foreach ($c in $extra) { $names.Add($c) }

    foreach ($name in $names) {
        $entry = Get-AwMemberValue $cats $name
        $known = $script:AwCategories.Contains($name)
        $title = Get-AwOutputText $entry 'Title'
        if (-not $title) { $title = if ($known) { $script:AwCategories[$name].Title } else { $name } }
        $score = 0; $count = 0
        [void][int]::TryParse([string](Get-AwMemberValue $entry 'Score'), [ref]$score)
        [void][int]::TryParse([string](Get-AwMemberValue $entry 'Findings'), [ref]$count)
        [pscustomobject]@{
            Name       = $name
            Title      = $title
            Weight     = $(if ($known) { [int]$script:AwCategories[$name].Weight } else { 0 })
            Score      = $score
            Applicable = [bool](Get-AwMemberValue $entry 'Applicable')
            Findings   = $count
        }
    }
}

function Get-AwCategoryTitle {
    # Display title of a category name.
    param([string]$Category)
    if ($Category -and $script:AwCategories.Contains($Category)) { return $script:AwCategories[$Category].Title }
    return $Category
}

#endregion

#region JSON writer

function Add-AwJsonValue {
    param([System.Text.StringBuilder]$Builder, [AllowNull()] $Value, [int]$Level, [bool]$Compress)
    if ($null -eq $Value -or $Value -is [scriptblock]) { [void]$Builder.Append('null'); return }
    if ($Value -is [string] -or $Value -is [char]) {
        [void]$Builder.Append('"').Append($script:AwJsonEscapeRegex.Replace([string]$Value, $script:AwJsonEscapeEvaluator)).Append('"')
        return
    }
    if ($Value -is [bool]) { [void]$Builder.Append($(if ($Value) { 'true' } else { 'false' })); return }
    if ($Value -is [double] -or $Value -is [single]) {
        $d = [double]$Value
        if ([double]::IsNaN($d) -or [double]::IsInfinity($d)) { [void]$Builder.Append('null') }
        else { [void]$Builder.Append($d.ToString('R', $script:AwInvariant)) }
        return
    }
    if ($script:AwJsonIntegerTypes -contains $Value.GetType()) {
        [void]$Builder.Append(([System.IFormattable]$Value).ToString($null, $script:AwInvariant))
        return
    }
    if ($Value -is [datetime]) {
        $iso = $Value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", $script:AwInvariant)
        Add-AwJsonValue -Builder $Builder -Value $iso -Level $Level -Compress $Compress
        return
    }
    if ($Value -is [enum]) { Add-AwJsonValue -Builder $Builder -Value $Value.ToString() -Level $Level -Compress $Compress; return }
    # Depth guard against cycles and hostile nesting.
    if ($Level -ge $script:AwJsonMaxDepth) { [void]$Builder.Append('null'); return }

    $inner = if ($Compress) { '' } else { "`n" + ('  ' * ($Level + 1)) }
    $outer = if ($Compress) { '' } else { "`n" + ('  ' * $Level) }

    $isMap = $Value -is [System.Collections.IDictionary] -or $Value -is [System.Management.Automation.PSCustomObject]
    if ($isMap) {
        $names = New-Object System.Collections.Generic.List[string]
        $values = New-Object System.Collections.Generic.List[object]
        if ($Value -is [System.Collections.Hashtable]) {
            # Unordered dictionaries get their key names sorted, so that the output is stable, and
            # each value is then read by its key. Sorting names and values as two parallel arrays is
            # not safe: when every value has the same type, PowerShell passes the sort a converted
            # copy of the values, so only the names move.
            $keysByName = New-Object 'System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[object]]' -ArgumentList ([StringComparer]::Ordinal)
            foreach ($k in $Value.Keys) {
                $name = [string]$k
                if (-not $keysByName.ContainsKey($name)) { $keysByName[$name] = New-Object System.Collections.Generic.List[object] }
                $keysByName[$name].Add($k)
            }
            $sorted = [string[]]@($keysByName.Keys)
            [Array]::Sort($sorted, [StringComparer]::Ordinal)
            foreach ($name in $sorted) {
                foreach ($k in $keysByName[$name]) { $names.Add($name); $values.Add($Value.get_Item($k)) }
            }
        } elseif ($Value -is [System.Collections.IDictionary]) {
            foreach ($e in $Value.GetEnumerator()) { $names.Add([string]$e.Key); $values.Add($e.Value) }
        } else {
            foreach ($p in $Value.PSObject.Properties) { $names.Add($p.Name); $values.Add($p.Value) }
        }
        $n = $names.ToArray(); $v = $values.ToArray()
        if ($n.Count -eq 0) { [void]$Builder.Append('{}'); return }
        [void]$Builder.Append('{')
        for ($i = 0; $i -lt $n.Count; $i++) {
            if ($i -gt 0) { [void]$Builder.Append(',') }
            [void]$Builder.Append($inner)
            Add-AwJsonValue -Builder $Builder -Value $n[$i] -Level ($Level + 1) -Compress $Compress
            [void]$Builder.Append($(if ($Compress) { ':' } else { ': ' }))
            Add-AwJsonValue -Builder $Builder -Value $v[$i] -Level ($Level + 1) -Compress $Compress
        }
        [void]$Builder.Append($outer).Append('}')
        return
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = New-Object System.Collections.Generic.List[object]
        foreach ($x in $Value) { $items.Add($x) }
        if ($items.Count -eq 0) { [void]$Builder.Append('[]'); return }
        [void]$Builder.Append('[')
        for ($i = 0; $i -lt $items.Count; $i++) {
            if ($i -gt 0) { [void]$Builder.Append(',') }
            [void]$Builder.Append($inner)
            Add-AwJsonValue -Builder $Builder -Value $items[$i] -Level ($Level + 1) -Compress $Compress
        }
        [void]$Builder.Append($outer).Append(']')
        return
    }
    Add-AwJsonValue -Builder $Builder -Value ([string]$Value) -Level $Level -Compress $Compress
}

function ConvertTo-AwJsonText {
    # Serializes dictionaries, objects, arrays and scalars to JSON, the same way on every
    # PowerShell version: ordered dictionaries and objects keep their order, hashtable keys are
    # sorted (ordinal), numbers use the invariant culture, < > & ' are escaped (safe to embed in
    # HTML), script blocks are never serialized, and nesting deeper than 32 levels becomes null.
    param([AllowNull()] $InputObject, [switch]$Compress)
    $sb = New-Object System.Text.StringBuilder
    Add-AwJsonValue -Builder $sb -Value $InputObject -Level 0 -Compress ([bool]$Compress)
    return $sb.ToString()
}

#endregion

#region Result data

function ConvertTo-AwMaskedData {
    # Copy of finding Data with token-like values masked in every string.
    param($Value, [int]$Level = 0)
    if ($null -eq $Value -or $Value -is [scriptblock]) { return $null }
    if ($Value -is [string] -or $Value -is [char]) { return (Hide-AwSecretsInText ([string]$Value)) }
    if ($Value -is [ValueType]) { return $Value }
    if ($Level -ge $script:AwJsonMaxDepth) { return $null }
    if ($Value -is [System.Collections.IDictionary] -or $Value -is [System.Management.Automation.PSCustomObject]) {
        $copy = [ordered]@{}
        $names = [string[]]@(Get-AwMemberNames $Value)
        if ($Value -is [System.Collections.Hashtable]) { [Array]::Sort($names, [StringComparer]::Ordinal) }
        foreach ($k in $names) { $copy[$k] = ConvertTo-AwMaskedData -Value (Get-AwMemberValue $Value $k) -Level ($Level + 1) }
        return $copy
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        return , @(foreach ($x in $Value) { , (ConvertTo-AwMaskedData -Value $x -Level ($Level + 1)) })
    }
    return (Hide-AwSecretsInText ([string]$Value))
}

function ConvertTo-AwFindingData {
    # Ordered copy of a finding with exactly the contract properties (plus Data when present).
    param($Finding)
    $loc = Get-AwMemberValue $Finding 'Location'
    $data = [ordered]@{
        RuleId      = Get-AwOutputText $Finding 'RuleId'
        Title       = Get-AwOutputTitle $Finding
        Severity    = Get-AwOutputText $Finding 'Severity'
        Category    = Get-AwOutputText $Finding 'Category'
        Harness     = Get-AwOutputText $Finding 'Harness'
        Description = Get-AwOutputText $Finding 'Description'
        Evidence    = Get-AwOutputEvidence $Finding
        Location    = [ordered]@{
            Path = Get-AwOutputText $loc 'Path'
            Line = Get-AwOutputLine $Finding
            Key  = Get-AwOutputText $loc 'Key'
        }
        Fix         = Get-AwOutputText $Finding 'Fix'
        References  = [string[]]@(Get-AwOutputList $Finding 'References')
        Confidence  = Get-AwOutputText $Finding 'Confidence'
    }
    $extra = Get-AwMemberValue $Finding 'Data'
    if ($null -ne $extra) { $data['Data'] = ConvertTo-AwMaskedData -Value $extra }
    return $data
}

function ConvertTo-AwRuleData {
    # Ordered rule metadata (never the Check script block). -Id overrides the rule's own Id.
    param($Rule, [string]$Id)
    if (-not $Id) { $Id = Get-AwOutputText $Rule 'Id' }
    [ordered]@{
        Id          = $Id
        Title       = Get-AwOutputText $Rule 'Title'
        Severity    = Get-AwOutputText $Rule 'Severity'
        Category    = Get-AwOutputText $Rule 'Category'
        Harness     = Get-AwOutputText $Rule 'Harness'
        Description = Get-AwOutputText $Rule 'Description'
        Fix         = Get-AwOutputText $Rule 'Fix'
        References  = [string[]]@(Get-AwOutputList $Rule 'References')
        Confidence  = Get-AwOutputText $Rule 'Confidence'
    }
}

function ConvertTo-AwResultData {
    # Whitelisted, ordered copy of a result: the document written by ConvertTo-AwJson.
    param($Result)
    $tool = Get-AwMemberValue $Result 'Tool'
    $score = Get-AwMemberValue $Result 'Score'
    $toolName = Get-AwOutputText $tool 'Name'
    $toolVersion = Get-AwOutputText $tool 'Version'

    $categories = [ordered]@{}
    foreach ($c in @(Get-AwOutputCategories $Result)) {
        $categories[$c.Name] = [ordered]@{
            Title = $c.Title; Weight = $c.Weight; Score = $c.Score; Applicable = $c.Applicable; Findings = $c.Findings
        }
    }
    $scoreValue = $null; $n = 0
    if ([int]::TryParse([string](Get-AwMemberValue $score 'Score'), [ref]$n)) { $scoreValue = $n }

    $exitCode = 0
    [void][int]::TryParse([string](Get-AwMemberValue $Result 'ExitCode'), [ref]$exitCode)

    [ordered]@{
        Tool      = [ordered]@{
            Name    = $(if ($toolName) { $toolName } else { $script:AwToolName })
            Version = $(if ($toolVersion) { $toolVersion } else { $script:AwToolVersion })
        }
        ScannedAt = Get-AwOutputText $Result 'ScannedAt'
        Root      = Get-AwOutputText $Result 'Root'
        Harnesses = [string[]]@(Get-AwOutputList $Result 'Harnesses')
        Score     = [ordered]@{
            Score      = $scoreValue
            Grade      = Get-AwOutputText $score 'Grade'
            Categories = $categories
            Counts     = Get-AwOutputCounts $Result
        }
        Findings  = @(foreach ($f in @(Get-AwOutputList $Result 'Findings')) { ConvertTo-AwFindingData $f })
        Rules     = @(foreach ($r in @(Get-AwOutputList $Result 'Rules')) { ConvertTo-AwRuleData $r })
        Errors    = @(foreach ($f in @(Get-AwOutputList $Result 'Errors')) { ConvertTo-AwFindingData $f })
        Options   = Get-AwMemberValue $Result 'Options'
        ExitCode  = $exitCode
    }
}

#endregion

function ConvertTo-AwJson {
    <#
    .SYNOPSIS
    Renders a Airworthy result as stable, indented JSON text.
    .DESCRIPTION
    Writes the documented result fields only (Tool, ScannedAt, Root, Harnesses, Score,
    Findings, Rules, Errors, Options, ExitCode), in a fixed order, with sorted hashtable keys.
    Rule check script blocks and analysis internals are never written. Token-like values left
    in finding titles, evidence or Data are masked as a last line of defense.
    The built-in writer gives the same output on Windows PowerShell 5.1 and PowerShell 7, and
    never truncates silently the way ConvertTo-Json does past its -Depth.
    .PARAMETER Result
    The result object returned by Invoke-Airworthy -PassThru.
    .EXAMPLE
    ConvertTo-AwJson $result | Set-Content -Encoding UTF8 report.json
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0)] $Result)
    return (ConvertTo-AwJsonText -InputObject (ConvertTo-AwResultData -Result $Result))
}
