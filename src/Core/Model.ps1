# Data model: constants, rule registry and findings.

$script:AwToolName    = 'Airworthy'
$script:AwToolVersion = '0.1.0'

$script:AwSeverities     = @('critical','high','medium','low','info')
$script:AwSeverityWeight = @{ critical = 40; high = 20; medium = 8; low = 3; info = 0 }
$script:AwSeverityRank   = @{ critical = 4; high = 3; medium = 2; low = 1; info = 0 }
$script:AwCategories = [ordered]@{
    'approvals'        = @{ Title = 'Approvals and terminal';        Weight = 25 }
    'sandbox-network'  = @{ Title = 'Sandbox and network';           Weight = 20 }
    'mcp-supply-chain' = @{ Title = 'MCP and supply chain';          Weight = 20 }
    'agent-files'      = @{ Title = 'Agent files and instructions';  Weight = 15 }
    'secrets'          = @{ Title = 'Secrets';                       Weight = 15 }
    'observability'    = @{ Title = 'Audit and observability';       Weight = 5 }
}
$script:AwHarnesses   = @('vscode-copilot','claude-code','copilot-cli','mcp','generic')
$script:AwConfidences = @('high','medium','low')
$script:AwRuleIdPattern = '^AW-(CORE|VSC|AGT|SEC|MCP|CC|CLI)-[0-9]{3}$'

# The only non-ASCII characters the code needs, defined once (see CONTRIBUTING.md, Antivirus hygiene).
$script:AwEllipsis = [string][char]0x2026
$script:AwBom      = [char]0xFEFF

# Registered rules, keyed by Id.
$script:AwRules = @{}

# Errors raised while dot-sourcing rule or output files (filled by the psm1).
if (-not (Test-Path variable:script:AwLoadErrors)) { $script:AwLoadErrors = @() }

# Built-in findings emitted by the engine itself. They are not registered rules,
# so they never make a category applicable.
$script:AwCoreRules = @{
    'AW-CORE-001' = [pscustomobject]@{
        Id = 'AW-CORE-001'; Title = 'Unreadable or invalid file'; Severity = 'info'
        Category = 'observability'; Harness = 'generic'
        Description = 'A configuration file could not be read or parsed (invalid JSON or YAML, too large, or a link that leaves the analyzed root). Its content was not analyzed, so the score may miss issues in it.'
        Fix = 'Fix the syntax of the file, or check why it cannot be read. Files larger than 2 MB and links outside the analyzed root are skipped on purpose.'
        References = [string[]]@(); Confidence = 'high'
    }
    'AW-CORE-002' = [pscustomobject]@{
        Id = 'AW-CORE-002'; Title = 'Rule failed'; Severity = 'info'
        Category = 'observability'; Harness = 'generic'
        Description = 'A rule raised an error or returned an invalid result. The configuration it checks was not fully analyzed.'
        Fix = 'Report the error to the Airworthy maintainers, with the rule ID and a synthetic file that reproduces it.'
        References = [string[]]@(); Confidence = 'high'
    }
}

function Register-AwRule {
    <#
    .SYNOPSIS
    Registers a rule in the Airworthy rule registry.
    .DESCRIPTION
    Validates the rule metadata and stores it. Check receives the context built by
    New-AwContext and returns zero or more findings created with New-AwFinding.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Id,
        [Parameter(Mandatory)] [string]$Title,
        [Parameter(Mandatory)] [string]$Severity,
        [Parameter(Mandatory)] [string]$Category,
        [Parameter(Mandatory)] [string]$Harness,
        [Parameter(Mandatory)] [string]$Description,
        [Parameter(Mandatory)] [string]$Fix,
        [string[]]$References = @(),
        [string]$Confidence = 'high',
        [Parameter(Mandatory)] [scriptblock]$Check
    )
    if ($Id -cnotmatch $script:AwRuleIdPattern) { throw "Register-AwRule: invalid rule Id '$Id' (expected AW-<AREA>-<NNN>)." }
    if ($script:AwCoreRules.ContainsKey($Id)) { throw "Register-AwRule: '$Id' is reserved for the engine." }
    if ($script:AwRules.ContainsKey($Id)) { throw "Register-AwRule: rule '$Id' is already registered." }
    if ($script:AwSeverities -cnotcontains $Severity) { throw "Register-AwRule: invalid severity '$Severity' for $Id." }
    if (([string[]]@($script:AwCategories.Keys)) -cnotcontains $Category) { throw "Register-AwRule: invalid category '$Category' for $Id." }
    if ($script:AwHarnesses -cnotcontains $Harness) { throw "Register-AwRule: invalid harness '$Harness' for $Id." }
    if ($script:AwConfidences -cnotcontains $Confidence) { throw "Register-AwRule: invalid confidence '$Confidence' for $Id." }

    $script:AwRules[$Id] = [pscustomobject]@{
        Id          = $Id
        Title       = $Title
        Severity    = $Severity
        Category    = $Category
        Harness     = $Harness
        Description = $Description
        Fix         = $Fix
        References  = [string[]]@($References | Where-Object { $_ })
        Confidence  = $Confidence
        Check       = $Check
    }
}

function Get-AwRules {
    <#
    .SYNOPSIS
    Returns every registered rule (with its Check scriptblock), sorted by Id.
    #>
    [CmdletBinding()]
    param()
    $ids = [string[]]@($script:AwRules.Keys)
    [Array]::Sort($ids, [StringComparer]::Ordinal)
    foreach ($id in $ids) { $script:AwRules[$id] }
}

function Get-AwRuleMetadata {
    # Rule (registered or built-in) for an Id, or $null.
    param([string]$Id)
    if (-not $Id) { return $null }
    if ($script:AwRules.ContainsKey($Id)) { return $script:AwRules[$Id] }
    if ($script:AwCoreRules.ContainsKey($Id)) { return $script:AwCoreRules[$Id] }
    return $null
}

function ConvertTo-AwLocation {
    # Normalizes a hashtable or object into the Location shape { Path; Line; Key }.
    param($Location)
    $path = $null; $line = $null; $key = $null
    if ($null -ne $Location) {
        if ($Location -is [System.Collections.IDictionary]) {
            if ($Location.Contains('Path')) { $path = $Location['Path'] }
            if ($Location.Contains('Line')) { $line = $Location['Line'] }
            if ($Location.Contains('Key'))  { $key  = $Location['Key'] }
        } else {
            $props = $Location.PSObject.Properties
            if ($props['Path']) { $path = $Location.Path }
            if ($props['Line']) { $line = $Location.Line }
            if ($props['Key'])  { $key  = $Location.Key }
        }
    }
    $lineValue = $null
    if ($null -ne $line) {
        $n = 0
        if ([int]::TryParse([string]$line, [ref]$n) -and $n -gt 0) { $lineValue = $n }
    }
    [pscustomobject]@{
        Path = $(if ($null -ne $path -and "$path" -ne '') { [string]$path } else { $null })
        Line = $lineValue
        Key  = $(if ($null -ne $key -and "$key" -ne '') { [string]$key } else { $null })
    }
}

function New-AwFinding {
    <#
    .SYNOPSIS
    Creates a finding. Missing fields are taken from the rule metadata.
    .DESCRIPTION
    Evidence must never contain a secret in full: mask values with Hide-AwSecret.
    -Data is attached as an extra 'Data' property only when it is given; it must not
    contain secrets either.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$RuleId,
        [string]$Severity,
        [string]$Title,
        [string]$Evidence,
        $Location,
        [string]$Fix,
        [string]$Harness,
        [System.Collections.IDictionary]$Data
    )
    $rule = Get-AwRuleMetadata -Id $RuleId
    if ($Severity -and $script:AwSeverities -cnotcontains $Severity) { throw "New-AwFinding: invalid severity '$Severity'." }
    if ($Harness -and $script:AwHarnesses -cnotcontains $Harness) { throw "New-AwFinding: invalid harness '$Harness'." }

    # A typed variable keeps a one-element array as string[] ($(...) would unroll it).
    [string[]]$refs = @()
    if ($rule) { $refs = @($rule.References) }
    $finding = [pscustomobject]@{
        RuleId      = $RuleId
        Title       = $(if ($Title) { $Title } elseif ($rule) { $rule.Title } else { $null })
        Severity    = $(if ($Severity) { $Severity } elseif ($rule) { $rule.Severity } else { $null })
        Category    = $(if ($rule) { $rule.Category } else { $null })
        Harness     = $(if ($Harness) { $Harness } elseif ($rule) { $rule.Harness } else { $null })
        Description = $(if ($rule) { $rule.Description } else { $null })
        Evidence    = $(if ($Evidence) { $Evidence } else { $null })
        Location    = ConvertTo-AwLocation -Location $Location
        Fix         = $(if ($Fix) { $Fix } elseif ($rule) { $rule.Fix } else { $null })
        References  = $refs
        Confidence  = $(if ($rule) { $rule.Confidence } else { $null })
    }
    if ($PSBoundParameters.ContainsKey('Data') -and $null -ne $Data) {
        $finding | Add-Member -NotePropertyName 'Data' -NotePropertyValue $Data
    }
    $finding
}

function Find-AwLineNumber {
    <#
    .SYNOPSIS
    Returns the 1-based line of the first occurrence of Needle in Text, or $null.
    #>
    [CmdletBinding()]
    param([string]$Text, [string]$Needle)
    if ([string]::IsNullOrEmpty($Text) -or [string]::IsNullOrEmpty($Needle)) { return $null }
    $index = $Text.IndexOf($Needle, [StringComparison]::Ordinal)
    if ($index -lt 0) { return $null }
    $line = 1
    $pos = $Text.IndexOf("`n", 0, $index, [StringComparison]::Ordinal)
    while ($pos -ge 0) {
        $line++
        $start = $pos + 1
        if ($start -ge $index) { break }
        $pos = $Text.IndexOf("`n", $start, $index - $start, [StringComparison]::Ordinal)
    }
    return $line
}

# Patterns taken from scanned files (VS Code terminal regexes, edit globs, Claude Code permission
# globs) are hostile input. They run with a short timeout; a pattern that timed out is not run
# again, and once AwUntrustedTimeoutBudget timeouts happened in an analysis no such pattern runs any
# more. The engine resets this state for each analysis and reports what was not evaluated (AW-CORE-002).
$script:AwUntrustedRegexTimeout  = [TimeSpan]::FromMilliseconds(50)
$script:AwUntrustedTimeoutBudget = 20
$script:AwUntrustedRegexState    = $null

function Reset-AwUntrustedRegexState {
    $script:AwUntrustedRegexState = @{ Timeouts = 0; Skipped = 0; Failed = (New-Object System.Collections.Hashtable) }
}

function New-AwUntrustedRegex {
    # Regex for a pattern from a scanned file, with the short match timeout; $null when it does not compile.
    param([string]$Pattern, [System.Text.RegularExpressions.RegexOptions]$Options = [System.Text.RegularExpressions.RegexOptions]::None)
    try {
        return (New-Object System.Text.RegularExpressions.Regex -ArgumentList @($Pattern, $Options, $script:AwUntrustedRegexTimeout))
    } catch {
        return $null
    }
}

function Test-AwUntrustedMatch {
    # IsMatch for a regex made by New-AwUntrustedRegex: $true or $false, or $null when it could not
    # be evaluated (it timed out, now or earlier in the analysis, or the timeout budget is used up).
    param($Regex, [AllowEmptyString()] [string]$Text)
    if ($null -eq $Regex) { return $false }
    if ($null -eq $script:AwUntrustedRegexState) { Reset-AwUntrustedRegexState }
    $state = $script:AwUntrustedRegexState
    if ($state.Failed.ContainsKey($Regex)) { return $null }
    if ($state.Timeouts -ge $script:AwUntrustedTimeoutBudget) {
        $state.Failed[$Regex] = $true
        $state.Skipped++
        return $null
    }
    try {
        return $Regex.IsMatch($Text)
    } catch {
        # The .NET exception reaches PowerShell wrapped in a MethodInvocationException.
        $state.Timeouts++
        $state.Failed[$Regex] = $true
        return $null
    }
}

function Get-AwSeverityRank {
    # 4 (critical) .. 0 (info); -1 for an unknown severity.
    param([string]$Severity)
    if ($Severity -and $script:AwSeverityRank.ContainsKey($Severity)) { return [int]$script:AwSeverityRank[$Severity] }
    return -1
}

function Read-AwDataFile {
    <#
    .SYNOPSIS
    Loads a rule data file, src/Data/<Name>.json, as nested hashtables and arrays.
    .DESCRIPTION
    Command names, flags and patterns that rules look for live in JSON data files, stored as
    separate tokens, so that no PowerShell source file holds literals that look like malware
    (CONTRIBUTING.md, Antivirus hygiene). Throws when the file is missing or is not a JSON object, so the
    rule file that needs it fails to load visibly (AW-CORE-002).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [ValidatePattern('^[A-Za-z0-9_-]+$')] [string]$Name)
    $root = [string]$script:AwModuleRoot
    if (-not $root) { $root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
    $path = [System.IO.Path]::Combine([System.IO.Path]::Combine([System.IO.Path]::Combine($root, 'src'), 'Data'), $Name + '.json')
    if (-not [System.IO.File]::Exists($path)) { throw "Read-AwDataFile: data file src/Data/$Name.json not found." }
    $data = ConvertFrom-AwJsonc -Text ([System.IO.File]::ReadAllText($path))
    if ($data -isnot [System.Collections.IDictionary]) { throw "Read-AwDataFile: src/Data/$Name.json must contain a JSON object." }
    return $data
}
