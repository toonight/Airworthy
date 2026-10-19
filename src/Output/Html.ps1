# HTML output: one self-contained, offline report file built from the assets in src/Output/Html/
# (report.css, report.js, body.html), which are inlined into the page.
# Findings carry attacker-controlled text from the scanned files, so the page treats all of it as data:
# - the report model is embedded as JSON in a script element of type application/json, with every
#   character that could close the element, open a tag or comment, or spell a URL scheme escaped;
# - the single inline renderer script (report.js) builds the DOM with createElement and textContent only;
# - a Content-Security-Policy allows that script and the inline stylesheet by their SHA-256 digests,
#   and blocks every other script, style and load.

$script:AwHtmlAssetDir = Join-Path $PSScriptRoot 'Html'
$script:AwHtmlAssets = @{}

# Characters kept as they are in JSON strings: printable ASCII except " & ' : < > and the backslash.
# Everything else (controls, U+2028, U+2029, any non-ASCII character) becomes a \uXXXX escape.
$script:AwHtmlJsonUnsafe = New-Object System.Text.RegularExpressions.Regex -ArgumentList @(
    '[^\x20\x21\x23-\x25\x28-\x39\x3B\x3D\x3F-\x5B\x5D-\x7E]',
    [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
)
$script:AwHtmlJsonShortEscapes = @{ 0x22 = '\"'; 0x5C = '\\'; 0x0A = '\n'; 0x0D = '\r'; 0x09 = '\t' }
$script:AwHtmlJsonEscape = [System.Text.RegularExpressions.MatchEvaluator] {
    param($m)
    $code = [int][char]$m.Value
    if ($script:AwHtmlJsonShortEscapes.ContainsKey($code)) { return $script:AwHtmlJsonShortEscapes[$code] }
    return ('\u' + $code.ToString('x4', [System.Globalization.CultureInfo]::InvariantCulture))
}

function Get-AwHtmlAsset {
    # Text of a report asset, with LF line endings (the HTML parser applies the same normalization
    # before the browser hashes an inline element).
    param([string]$Name)
    if (-not $script:AwHtmlAssets.ContainsKey($Name)) {
        $path = Join-Path $script:AwHtmlAssetDir $Name
        if (-not [System.IO.File]::Exists($path)) { throw "Airworthy: the HTML report asset src/Output/Html/$Name is missing." }
        $text = [System.IO.File]::ReadAllText($path) -replace '\r\n?', "`n"
        # An asset must never be able to end its own element or open a comment inside it.
        if ($Name -ne 'body.html' -and ($text.Contains('</') -or $text.Contains('<!--'))) {
            throw "Airworthy: the HTML report asset src/Output/Html/$Name contains a sequence that would end its element."
        }
        $script:AwHtmlAssets[$Name] = $text
    }
    return $script:AwHtmlAssets[$Name]
}

function ConvertTo-AwHtmlJsonString {
    # JSON string literal that stays inert inside a script element.
    param([AllowNull()] [AllowEmptyString()] [string]$Value)
    return '"' + $script:AwHtmlJsonUnsafe.Replace($Value, $script:AwHtmlJsonEscape) + '"'
}

function Add-AwHtmlJsonValue {
    param([System.Text.StringBuilder]$Builder, [AllowNull()] $Value, [int]$Depth)
    if ($Depth -gt 32) { throw 'ConvertTo-AwHtml: the report model is nested too deeply.' }
    if ($null -eq $Value) { [void]$Builder.Append('null'); return }
    if ($Value -is [string] -or $Value -is [char]) { [void]$Builder.Append((ConvertTo-AwHtmlJsonString ([string]$Value))); return }
    if ($Value -is [bool]) { [void]$Builder.Append($(if ($Value) { 'true' } else { 'false' })); return }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [byte] -or
        $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [uint64] -or $Value -is [sbyte]) {
        [void]$Builder.Append($Value.ToString([System.Globalization.CultureInfo]::InvariantCulture))
        return
    }
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) {
        $d = [double]$Value
        if ([double]::IsNaN($d) -or [double]::IsInfinity($d)) { [void]$Builder.Append('null') }
        else { [void]$Builder.Append($d.ToString('R', [System.Globalization.CultureInfo]::InvariantCulture)) }
        return
    }
    if ($Value -is [System.Collections.IDictionary]) {
        [void]$Builder.Append('{')
        $first = $true
        foreach ($k in $Value.Keys) {
            if (-not $first) { [void]$Builder.Append(',') }
            $first = $false
            [void]$Builder.Append((ConvertTo-AwHtmlJsonString ([string]$k))).Append(':')
            Add-AwHtmlJsonValue -Builder $Builder -Value $Value[$k] -Depth ($Depth + 1)
        }
        [void]$Builder.Append('}')
        return
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        [void]$Builder.Append('[')
        $first = $true
        foreach ($item in $Value) {
            if (-not $first) { [void]$Builder.Append(',') }
            $first = $false
            Add-AwHtmlJsonValue -Builder $Builder -Value $item -Depth ($Depth + 1)
        }
        [void]$Builder.Append(']')
        return
    }
    [void]$Builder.Append((ConvertTo-AwHtmlJsonString ([string]$Value)))
}

function ConvertTo-AwHtmlJson {
    # Minimal JSON writer for the report model (dictionaries, lists, strings, numbers, booleans).
    param([AllowNull()] $Value)
    $sb = New-Object System.Text.StringBuilder
    Add-AwHtmlJsonValue -Builder $sb -Value $Value -Depth 0
    return $sb.ToString()
}

function Get-AwHtmlSha256 {
    # SHA-256 digest (bytes) of the UTF-8 encoding of a text.
    param([AllowNull()] [AllowEmptyString()] [string]$Text)
    $ErrorActionPreference = 'Stop'
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($Text)
    # The CryptoServiceProvider class also works when Windows enforces FIPS mode.
    $sha = $null
    try { $sha = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider } catch { $sha = [System.Security.Cryptography.SHA256]::Create() }
    try { return ,$sha.ComputeHash($bytes) } finally { $sha.Dispose() }
}

function Get-AwHtmlCspHash {
    # CSP hash source ('sha256-...') for the exact text of an inline script or style element.
    param([AllowNull()] [AllowEmptyString()] [string]$Text)
    [byte[]]$hash = Get-AwHtmlSha256 -Text $Text
    return ("'sha256-" + [Convert]::ToBase64String($hash) + "'")
}

function ConvertTo-AwHtmlText {
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return ((@($Value) | ForEach-Object { [string]$_ }) -join ', ')
    }
    return [string]$Value
}

function ConvertTo-AwHtmlMaskedText {
    # Text with any remaining token-like value masked (last line of defense, as in the other outputs).
    param([AllowNull()] $Value)
    $t = ConvertTo-AwHtmlText $Value
    if ([string]::IsNullOrEmpty($t)) { return $t }
    return [string](Hide-AwSecretsInText $t)
}

function ConvertTo-AwHtmlInt {
    param([AllowNull()] $Value)
    $d = 0.0
    if ($null -ne $Value -and [double]::TryParse([string]$Value, [System.Globalization.NumberStyles]::Float,
            [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d) -and [Math]::Abs($d) -lt 1e9) {
        return [int][Math]::Round($d, [MidpointRounding]::AwayFromZero)
    }
    return 0
}

function Get-AwHtmlEntries {
    # Name/value pairs of a dictionary or an object, in their own order.
    param([AllowNull()] $Object)
    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($k in $Object.Keys) { [pscustomobject]@{ Name = [string]$k; Value = $Object[$k] } }
    } elseif ($Object -is [System.Management.Automation.PSCustomObject]) {
        foreach ($p in $Object.PSObject.Properties) { [pscustomobject]@{ Name = $p.Name; Value = $p.Value } }
    }
}

function Get-AwHtmlPath {
    # Display path (relative to the root when inside it, redacted when the result is); never throws.
    param([AllowNull()] $Path, $Result)
    $p = ConvertTo-AwHtmlText $Path
    if (-not $p) { return $null }
    $redact = ((Get-AwMemberValue (Get-AwMemberValue $Result 'Options') 'Redact') -eq $true)
    try { return [string](Get-AwDisplayPath -Path $p -Ctx $Result -Redact:$redact) } catch { return $p }
}

function Get-AwHtmlSeverity {
    param([AllowNull()] $Value)
    $s = [string]$Value
    if ($script:AwSeverities -ccontains $s) { return $s }
    return 'info'
}

function ConvertTo-AwHtmlFinding {
    param($Finding, $Result)
    $loc = Get-AwMemberValue $Finding 'Location'
    $line = ConvertTo-AwHtmlInt (Get-AwMemberValue $loc 'Line')
    $refs = @(@(Get-AwMemberValue $Finding 'References') | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { [string]$_ })
    [ordered]@{
        ruleId      = ConvertTo-AwHtmlText (Get-AwMemberValue $Finding 'RuleId')
        title       = ConvertTo-AwHtmlMaskedText (Get-AwMemberValue $Finding 'Title')
        severity    = Get-AwHtmlSeverity (Get-AwMemberValue $Finding 'Severity')
        category    = ConvertTo-AwHtmlText (Get-AwMemberValue $Finding 'Category')
        harness     = ConvertTo-AwHtmlText (Get-AwMemberValue $Finding 'Harness')
        description = ConvertTo-AwHtmlText (Get-AwMemberValue $Finding 'Description')
        evidence    = ConvertTo-AwHtmlMaskedText (Get-AwMemberValue $Finding 'Evidence')
        path        = Get-AwHtmlPath -Path (Get-AwMemberValue $loc 'Path') -Result $Result
        line        = $(if ($line -gt 0) { $line } else { $null })
        key         = ConvertTo-AwHtmlText (Get-AwMemberValue $loc 'Key')
        fix         = ConvertTo-AwHtmlText (Get-AwMemberValue $Finding 'Fix')
        references  = $refs
        confidence  = ConvertTo-AwHtmlText (Get-AwMemberValue $Finding 'Confidence')
    }
}

function Get-AwHtmlModel {
    # The view model embedded in the page: only what the renderer shows, with normalized types.
    param([AllowNull()] $Result)
    $tool = Get-AwMemberValue $Result 'Tool'
    $score = Get-AwMemberValue $Result 'Score'
    $options = Get-AwMemberValue $Result 'Options'

    $grade = [string](Get-AwMemberValue $score 'Grade')
    if (@('A', 'B', 'C', 'D', 'F') -cnotcontains $grade) { $grade = '' }
    $scoreValue = [Math]::Min(100, [Math]::Max(0, (ConvertTo-AwHtmlInt (Get-AwMemberValue $score 'Score'))))

    $counts = [ordered]@{}
    $countSource = Get-AwMemberValue $score 'Counts'
    foreach ($s in $script:AwSeverities) { $counts[$s] = [Math]::Max(0, (ConvertTo-AwHtmlInt (Get-AwMemberValue $countSource $s))) }

    $categories = New-Object System.Collections.ArrayList
    foreach ($entry in @(Get-AwHtmlEntries (Get-AwMemberValue $score 'Categories'))) {
        if ($null -eq $entry) { continue }
        $c = $entry.Value
        $meta = $null
        if ($script:AwCategories.Contains($entry.Name)) { $meta = $script:AwCategories[$entry.Name] }
        $title = ConvertTo-AwHtmlText (Get-AwMemberValue $c 'Title')
        if (-not $title -and $meta) { $title = $meta.Title }
        [void]$categories.Add([ordered]@{
            id         = $entry.Name
            title      = $title
            score      = [Math]::Min(100, [Math]::Max(0, (ConvertTo-AwHtmlInt (Get-AwMemberValue $c 'Score'))))
            applicable = ((Get-AwMemberValue $c 'Applicable') -eq $true)
            findings   = ConvertTo-AwHtmlInt (Get-AwMemberValue $c 'Findings')
            weight     = $(if ($meta) { [int]$meta.Weight } else { 0 })
        })
    }

    $findings = New-Object System.Collections.ArrayList
    foreach ($f in @(Get-AwMemberValue $Result 'Findings')) {
        if ($null -ne $f) { [void]$findings.Add((ConvertTo-AwHtmlFinding -Finding $f -Result $Result)) }
    }

    $errors = New-Object System.Collections.ArrayList
    foreach ($e in @(Get-AwMemberValue $Result 'Errors')) {
        if ($null -eq $e) { continue }
        [void]$errors.Add([ordered]@{
            ruleId   = ConvertTo-AwHtmlText (Get-AwMemberValue $e 'RuleId')
            title    = ConvertTo-AwHtmlMaskedText (Get-AwMemberValue $e 'Title')
            evidence = ConvertTo-AwHtmlMaskedText (Get-AwMemberValue $e 'Evidence')
            path     = Get-AwHtmlPath -Path (Get-AwMemberValue (Get-AwMemberValue $e 'Location') 'Path') -Result $Result
        })
    }

    $rules = New-Object System.Collections.ArrayList
    foreach ($r in @(Get-AwMemberValue $Result 'Rules')) {
        if ($null -eq $r) { continue }
        [void]$rules.Add([ordered]@{
            id         = ConvertTo-AwHtmlText (Get-AwMemberValue $r 'Id')
            title      = ConvertTo-AwHtmlText (Get-AwMemberValue $r 'Title')
            severity   = Get-AwHtmlSeverity (Get-AwMemberValue $r 'Severity')
            category   = ConvertTo-AwHtmlText (Get-AwMemberValue $r 'Category')
            harness    = ConvertTo-AwHtmlText (Get-AwMemberValue $r 'Harness')
            confidence = ConvertTo-AwHtmlText (Get-AwMemberValue $r 'Confidence')
        })
    }

    $harnesses = @(@(Get-AwMemberValue $Result 'Harnesses') | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { [string]$_ })
    $failOn = [string](Get-AwMemberValue $options 'FailOn')
    $name = ConvertTo-AwHtmlText (Get-AwMemberValue $tool 'Name')
    $version = ConvertTo-AwHtmlText (Get-AwMemberValue $tool 'Version')

    [ordered]@{
        tool       = [ordered]@{
            name    = $(if ($name) { $name } else { $script:AwToolName })
            version = $(if ($version) { $version } else { $script:AwToolVersion })
        }
        scannedAt  = ConvertTo-AwHtmlText (Get-AwMemberValue $Result 'ScannedAt')
        root       = ConvertTo-AwHtmlText (Get-AwMemberValue $Result 'Root')
        harnesses  = $harnesses
        score      = [ordered]@{ score = $scoreValue; grade = $grade }
        counts     = $counts
        categories = $categories.ToArray()
        findings   = $findings.ToArray()
        rules      = $rules.ToArray()
        errors     = $errors.ToArray()
        options    = [ordered]@{
            minSeverity = Get-AwHtmlSeverity (Get-AwMemberValue $options 'MinSeverity')
            failOn      = $(if ($script:AwSeverities -ccontains $failOn) { $failOn } else { $null })
            redact      = ((Get-AwMemberValue $options 'Redact') -eq $true)
            exitCode    = ConvertTo-AwHtmlInt (Get-AwMemberValue $Result 'ExitCode')
        }
    }
}

function ConvertTo-AwHtml {
    <#
    .SYNOPSIS
    Renders a Airworthy result as a self-contained, offline HTML report and returns it as a string.
    .DESCRIPTION
    The page has a score gauge, category scores, severity chips, filters, search, sorting,
    expandable findings, a table of the rules evaluated, light and dark themes and print styles.
    It loads nothing from the network. The result is embedded as inert JSON (every character
    that could end the script element, start a tag or spell a URL scheme is escaped), the
    renderer builds the DOM with textContent only, and a Content-Security-Policy allows only that
    renderer script and the inline stylesheet, by SHA-256 digests computed here.
    .PARAMETER Result
    The result object returned by Invoke-Airworthy -PassThru.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true, Position = 0)] [AllowNull()] $Result)
    $ErrorActionPreference = 'Stop'

    # The element texts are hashed exactly as they are written between the tags.
    $style = "`n" + (Get-AwHtmlAsset 'report.css')
    $renderer = "`n" + (Get-AwHtmlAsset 'report.js')
    $body = Get-AwHtmlAsset 'body.html'
    $json = ConvertTo-AwHtmlJson (Get-AwHtmlModel -Result $Result)
    $csp = "default-src 'none'; style-src " + (Get-AwHtmlCspHash -Text $style) + '; script-src ' +
        (Get-AwHtmlCspHash -Text $renderer) + "; base-uri 'none'; form-action 'none'"

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<!DOCTYPE html>`n<html lang=""en"">`n<head>`n<meta charset=""utf-8"">`n")
    [void]$sb.Append('<meta http-equiv="Content-Security-Policy" content="').Append($csp).Append(""">`n")
    [void]$sb.Append("<meta name=""referrer"" content=""no-referrer"">`n")
    [void]$sb.Append("<meta name=""viewport"" content=""width=device-width, initial-scale=1"">`n")
    [void]$sb.Append("<meta name=""color-scheme"" content=""light dark"">`n")
    [void]$sb.Append("<title>Airworthy report</title>`n")
    [void]$sb.Append('<style>').Append($style).Append("</style>`n")
    [void]$sb.Append('<script>').Append($renderer).Append("</script>`n</head>`n")
    [void]$sb.Append($body)
    [void]$sb.Append('<script type="application/json" id="aw-data">').Append($json).Append("</script>`n</body>`n</html>`n")
    return $sb.ToString()
}
