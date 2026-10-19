# SARIF 2.1.0 output (OASIS SARIF v2.1.0, with the properties GitHub code scanning reads).

$script:AwSarifSchema = 'https://json.schemastore.org/sarif-2.1.0.json'
$script:AwSarifInformationUri = 'https://github.com/toonight/Airworthy'
$script:AwSarifLevel = @{ critical = 'error'; high = 'error'; medium = 'warning'; low = 'note'; info = 'note' }
# GitHub code scanning: > 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low, 0.0 none.
$script:AwSarifSecuritySeverity = @{ critical = '9.5'; high = '8.0'; medium = '5.5'; low = '3.0'; info = '0.0' }
$script:AwSarifPrecision = @('high', 'medium', 'low')
# GitHub limits shortDescription and fullDescription to 1024 characters, rule names to 255.
$script:AwSarifMaxDescription = 1024

function ConvertTo-AwUriSegment {
    # Percent-encodes one path segment (UTF-8, upper-case hex); only RFC 3986 unreserved characters stay.
    param([AllowEmptyString()] [string]$Segment)
    if ($Segment -cmatch '^[A-Za-z0-9._~-]*$') { return $Segment }
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in [System.Text.Encoding]::UTF8.GetBytes($Segment)) {
        $c = [char]$b
        if ($b -lt 128 -and ([char]::IsLetterOrDigit($c) -or '-._~'.IndexOf($c) -ge 0)) { [void]$sb.Append($c) }
        else { [void]$sb.Append('%').Append($b.ToString('X2', $script:AwInvariant)) }
    }
    return $sb.ToString()
}

function ConvertTo-AwRelativeUri {
    # Relative path ('a\b c.json') as a relative URI reference ('a/b%20c.json').
    param([string]$Path)
    return ((@($Path -split '[\\/]') | ForEach-Object { ConvertTo-AwUriSegment $_ }) -join '/')
}

function Test-AwAbsolutePath {
    # Drive path (C:\...), UNC path (\\server\...) or POSIX absolute path (/...). No file system access.
    param([string]$Path)
    return ($Path -match '^(?:[A-Za-z]:[\\/]|[\\/]{2}[^\\/]|/)')
}

function ConvertTo-AwFileUri {
    # Absolute path as a file URI: file:///C:/a%20b/c, file://server/share/x, file:///home/x.
    param([string]$Path, [switch]$Directory)
    $p = $Path
    if ($p.StartsWith('\\?\UNC\')) { $p = '\\' + $p.Substring(8) }
    elseif ($p.StartsWith('\\?\') -or $p.StartsWith('\\.\')) { $p = $p.Substring(4) }
    $p = $p.Replace('\', '/')
    if ($p -match '^//([^/]+)(/.*)?$') {
        $prefix = 'file://' + (ConvertTo-AwUriSegment $Matches[1]); $rest = [string]$Matches[2]
    } elseif ($p -match '^([A-Za-z]):(/.*)?$') {
        $prefix = 'file:///' + $Matches[1] + ':'; $rest = [string]$Matches[2]
    } elseif ($p.StartsWith('/')) {
        $prefix = 'file://'; $rest = $p
    } else {
        return $null
    }
    $uri = $prefix + ((@($rest -split '/') | ForEach-Object { ConvertTo-AwUriSegment $_ }) -join '/')
    if ($Directory -and -not $uri.EndsWith('/')) { $uri += '/' }
    return $uri
}

function Get-AwSarifArtifactLocation {
    # artifactLocation of a finding path: relative to SRCROOT when inside the root, relative to
    # USERHOME for a redacted profile path ('~\...'), otherwise an absolute file URI.
    param([string]$Path, [string]$Root, [bool]$Redact)
    if ([string]::IsNullOrEmpty($Path)) { return $null }
    if (Test-AwAbsolutePath $Path) {
        if (Test-AwAbsolutePath $Root) {
            $rel = Get-AwRelativePath -Path $Path -Base $Root
            if ($null -ne $rel) { return [ordered]@{ uri = (ConvertTo-AwRelativeUri $rel); uriBaseId = 'SRCROOT' } }
        }
        $uri = ConvertTo-AwFileUri $Path
        if ($uri) { return [ordered]@{ uri = $uri } }
    }
    if ($Redact -and ($Path -eq '~' -or $Path -match '^~[\\/]')) {
        $rest = if ($Path.Length -gt 2) { $Path.Substring(2) } else { '.' }
        return [ordered]@{ uri = (ConvertTo-AwRelativeUri $rest); uriBaseId = 'USERHOME' }
    }
    # Already relative (in-root paths of a redacted result): relative to the root.
    return [ordered]@{ uri = (ConvertTo-AwRelativeUri $Path); uriBaseId = 'SRCROOT' }
}

function ConvertTo-AwSarifRuleName {
    # PascalCase identifier from a rule title ('Global auto-approval' -> 'GlobalAutoApproval').
    param([string]$Title, [string]$Id)
    $words = @([regex]::Split([string]$Title, '[^A-Za-z0-9]+') | Where-Object { $_ })
    $name = [string]::Join('', [string[]]@(foreach ($w in $words) { $w.Substring(0, 1).ToUpperInvariant() + $w.Substring(1) }))
    if (-not $name) { $name = $Id -replace '[^A-Za-z0-9]', '' }
    if ($name.Length -gt 255) { $name = $name.Substring(0, 255) }
    return $name
}

function ConvertTo-AwSarifRule {
    # reportingDescriptor for one rule (ordered rule data from ConvertTo-AwRuleData).
    param($Rule)
    $severity = [string]$Rule.Severity
    $title = if ($Rule.Title) { [string]$Rule.Title } else { [string]$Rule.Id }
    $description = if ($Rule.Description) { [string]$Rule.Description } else { $title }
    $help = if ($Rule.Fix) { [string]$Rule.Fix } else { $description }
    $refs = @($Rule.References | Where-Object { $_ })

    $descriptor = [ordered]@{
        id               = [string]$Rule.Id
        name             = ConvertTo-AwSarifRuleName -Title $title -Id ([string]$Rule.Id)
        shortDescription = [ordered]@{ text = (Get-AwShortText $title -MaxLength $script:AwSarifMaxDescription) }
        fullDescription  = [ordered]@{ text = (Get-AwShortText $description -MaxLength $script:AwSarifMaxDescription) }
        help             = [ordered]@{ text = $help }
    }
    $helpUri = @($refs | Where-Object { $_ -match '^https?://\S+$' } | Select-Object -First 1)
    if ($helpUri.Count -gt 0) { $descriptor['helpUri'] = [string]$helpUri[0] }
    if ($script:AwSarifLevel.ContainsKey($severity)) {
        $descriptor['defaultConfiguration'] = [ordered]@{ level = $script:AwSarifLevel[$severity] }
    }

    $tags = New-Object System.Collections.Generic.List[string]
    foreach ($t in @([string]$Rule.Category, [string]$Rule.Harness) + @($refs | Where-Object { $_ -match '^OWASP-' })) {
        if ($t -and -not $tags.Contains($t) -and $tags.Count -lt 20) { $tags.Add($t) }
    }
    $props = [ordered]@{ tags = $tags.ToArray() }
    if ($script:AwSarifSecuritySeverity.ContainsKey($severity)) { $props['security-severity'] = $script:AwSarifSecuritySeverity[$severity] }
    if ($script:AwSarifPrecision -contains [string]$Rule.Confidence) { $props['precision'] = [string]$Rule.Confidence }
    $descriptor['properties'] = $props
    return $descriptor
}

function ConvertTo-AwSarif {
    <#
    .SYNOPSIS
    Renders a Airworthy result as a SARIF 2.1.0 log (JSON text).
    .DESCRIPTION
    One run: tool.driver with every evaluated rule (id, name, descriptions, help = fix,
    helpUri, tags = category, harness and OWASP IDs, security-severity, precision), and one
    result per reported finding (ruleId, ruleIndex, level, message = title + evidence,
    location). Levels: critical and high = error, medium = warning, low and info = note.
    Paths inside the analyzed root are relative POSIX URIs against the SRCROOT base. Other
    paths, such as the user profile, are absolute file:/// URIs. In a redacted result, the
    SRCROOT base has no absolute URI and profile paths are relative to a USERHOME base without
    one either, as SARIF allows.
    .PARAMETER Result
    The result object returned by Invoke-Airworthy -PassThru.
    .EXAMPLE
    ConvertTo-AwSarif $result | Set-Content -Encoding UTF8 report.sarif
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0)] $Result)

    $redact = [bool](Get-AwMemberValue (Get-AwMemberValue $Result 'Options') 'Redact')
    $root = Get-AwOutputText $Result 'Root'
    $findings = @(Get-AwOutputList $Result 'Findings')

    # Rule descriptors: the evaluated rules, plus any rule that only appears in a finding, by Id.
    $ruleById = New-AwOrdinalHashtable
    foreach ($r in @(Get-AwOutputList $Result 'Rules')) {
        $id = Get-AwOutputText $r 'Id'
        if ($id -and -not $ruleById.ContainsKey($id)) { $ruleById[$id] = ConvertTo-AwRuleData -Rule $r }
    }
    foreach ($f in $findings) {
        $id = Get-AwOutputText $f 'RuleId'
        if (-not $id -or $ruleById.ContainsKey($id)) { continue }
        $meta = Get-AwRuleMetadata -Id $id
        $ruleById[$id] = ConvertTo-AwRuleData -Rule $(if ($meta) { $meta } else { $f }) -Id $id
    }
    $ids = [string[]]@($ruleById.Keys)
    [Array]::Sort($ids, [StringComparer]::Ordinal)
    $ruleIndex = New-AwOrdinalHashtable
    $descriptors = New-Object System.Collections.Generic.List[object]
    foreach ($id in $ids) {
        $ruleIndex[$id] = $descriptors.Count
        $descriptors.Add((ConvertTo-AwSarifRule -Rule $ruleById[$id]))
    }

    $usesUserHome = $false
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($f in $findings) {
        $id = Get-AwOutputText $f 'RuleId'
        $severity = Get-AwOutputText $f 'Severity'
        $text = Get-AwSafeText (Get-AwOutputTitle $f)
        $evidence = Get-AwSafeText (Get-AwOutputEvidence $f) -MaxLength 1000
        if ($evidence) { $text = $text.TrimEnd('.') + '. Evidence: ' + $evidence }
        # SARIF plain-text messages may hold embedded links, [text](URI) (SARIF 2.1.0, 3.11.6), that
        # viewers can render as links. Text from a scanned file must not create one.
        $text = $text.Replace('](', '] (')

        $res = [ordered]@{ ruleId = $id }
        if ($id -and $ruleIndex.ContainsKey($id)) { $res['ruleIndex'] = $ruleIndex[$id] }
        $res['level'] = $(if ($script:AwSarifLevel.ContainsKey([string]$severity)) { $script:AwSarifLevel[[string]$severity] } else { 'warning' })
        $res['message'] = [ordered]@{ text = $text }

        $loc = Get-AwMemberValue $f 'Location'
        $artifact = Get-AwSarifArtifactLocation -Path (Get-AwOutputText $loc 'Path') -Root $root -Redact $redact
        if ($artifact) {
            if ($artifact['uriBaseId'] -eq 'USERHOME') { $usesUserHome = $true }
            $physical = [ordered]@{ artifactLocation = $artifact }
            $line = Get-AwOutputLine $f
            if ($null -ne $line) { $physical['region'] = [ordered]@{ startLine = $line } }
            $res['locations'] = @([ordered]@{ physicalLocation = $physical })
        }

        $props = [ordered]@{ severity = $severity; category = (Get-AwOutputText $f 'Category'); harness = (Get-AwOutputText $f 'Harness'); confidence = (Get-AwOutputText $f 'Confidence') }
        $key = Get-AwOutputText $loc 'Key'
        if ($key) { $props['key'] = $key }
        $res['properties'] = $props
        $results.Add($res)
    }

    # URI bases. SARIF lets a producer omit the absolute URI of a base, which -Redact relies on.
    $bases = [ordered]@{}
    if (Test-AwAbsolutePath $root) {
        $bases['SRCROOT'] = [ordered]@{ uri = (ConvertTo-AwFileUri $root -Directory); description = [ordered]@{ text = 'The analyzed folder.' } }
    } else {
        $bases['SRCROOT'] = [ordered]@{ description = [ordered]@{ text = 'The analyzed folder (absolute path withheld).' } }
    }
    if ($usesUserHome) {
        $bases['USERHOME'] = [ordered]@{ description = [ordered]@{ text = 'The user profile folder (absolute path withheld).' } }
    }

    $tool = Get-AwMemberValue $Result 'Tool'
    $toolName = Get-AwOutputText $tool 'Name'; if (-not $toolName) { $toolName = $script:AwToolName }
    $toolVersion = Get-AwOutputText $tool 'Version'; if (-not $toolVersion) { $toolVersion = $script:AwToolVersion }

    $invocation = [ordered]@{ executionSuccessful = $true }
    $scannedAt = Get-AwOutputText $Result 'ScannedAt'
    if ($scannedAt -match '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$') { $invocation['endTimeUtc'] = $scannedAt }

    $score = Get-AwMemberValue $Result 'Score'
    $runProps = [ordered]@{
        score     = Get-AwMemberValue $score 'Score'
        grade     = Get-AwOutputText $score 'Grade'
        harnesses = [string[]]@(Get-AwOutputList $Result 'Harnesses')
    }

    $run = [ordered]@{
        tool               = [ordered]@{
            driver = [ordered]@{
                name            = $toolName
                version         = $toolVersion
                semanticVersion = $toolVersion
                informationUri  = $script:AwSarifInformationUri
                rules           = $descriptors.ToArray()
            }
        }
        invocations        = @($invocation)
        originalUriBaseIds = $bases
        results            = $results.ToArray()
        properties         = $runProps
    }
    $log = [ordered]@{
        '$schema' = $script:AwSarifSchema
        version   = '2.1.0'
        runs      = @($run)
    }
    return (ConvertTo-AwJsonText -InputObject $log)
}
