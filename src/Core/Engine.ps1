# Engine: runs the applicable rules, scores the findings, renders the requested formats.

$script:AwFormatExtensions = [ordered]@{ Console = $null; Json = '.json'; Sarif = '.sarif'; Markdown = '.md'; Html = '.html' }

function ConvertTo-AwRuleMetadata {
    # Rule metadata without the Check scriptblock (safe to serialize).
    param($Rule)
    [pscustomobject]@{
        Id = $Rule.Id; Title = $Rule.Title; Severity = $Rule.Severity; Category = $Rule.Category
        Harness = $Rule.Harness; Description = $Rule.Description; Fix = $Rule.Fix
        References = [string[]]@($Rule.References); Confidence = $Rule.Confidence
    }
}

function New-AwRuleFailure {
    param([string]$RuleId, [string]$Message)
    if ($Message.Length -gt 400) { $Message = $Message.Substring(0, 400) + '...' }
    New-AwFinding -RuleId 'AW-CORE-002' -Title "Rule failed: $RuleId" -Evidence (Hide-AwSecretsInText $Message) `
        -Location @{ Path = $null; Key = $RuleId }
}

function ConvertTo-AwCompleteFinding {
    # Returns a finding with every contract property, filling gaps from the rule metadata.
    # Returns $null when the item is not a finding at all.
    param($Item, $Rule)
    if ($null -eq $Item -or $Item -is [string] -or $Item -is [ValueType]) { return $null }
    if ($Item -isnot [System.Collections.IDictionary] -and $Item -isnot [System.Management.Automation.PSCustomObject]) { return $null }
    $get = { param($n) Get-AwMemberValue $Item $n }

    $ruleId = [string](& $get 'RuleId')
    if (-not $ruleId) { $ruleId = $Rule.Id }
    $meta = Get-AwRuleMetadata -Id $ruleId
    if ($null -eq $meta) { $meta = $Rule }

    $severity = [string](& $get 'Severity')
    if ($script:AwSeverities -cnotcontains $severity) { $severity = $meta.Severity }
    $harness = [string](& $get 'Harness')
    if ($script:AwHarnesses -cnotcontains $harness) { $harness = $meta.Harness }
    $confidence = [string](& $get 'Confidence')
    if ($script:AwConfidences -cnotcontains $confidence) { $confidence = $meta.Confidence }
    $refs = [string[]]@(& $get 'References' | Where-Object { $_ })
    if ($refs.Count -eq 0) { $refs = [string[]]@($meta.References) }
    $pick = { param($n) $v = & $get $n; if ($null -ne $v -and "$v" -ne '') { [string]$v } else { $meta.$n } }

    $finding = [pscustomobject]@{
        RuleId      = $ruleId
        Title       = & $pick 'Title'
        Severity    = $severity
        Category    = $meta.Category
        Harness     = $harness
        Description = & $pick 'Description'
        Evidence    = $(if ($null -ne (& $get 'Evidence')) { [string](& $get 'Evidence') } else { $null })
        Location    = ConvertTo-AwLocation -Location (& $get 'Location')
        Fix         = & $pick 'Fix'
        References  = $refs
        Confidence  = $confidence
    }
    $data = & $get 'Data'
    if ($null -ne $data) { $finding | Add-Member -NotePropertyName 'Data' -NotePropertyValue $data }
    return $finding
}

function Get-AwFindingSortKey {
    param($Finding)
    $sep = "`0"
    $line = if ($null -ne $Finding.Location.Line) { '{0:D10}' -f [int]$Finding.Location.Line } else { '0000000000' }
    return ((4 - (Get-AwSeverityRank $Finding.Severity)).ToString() + $sep + $Finding.RuleId + $sep +
            [string]$Finding.Location.Path + $sep + $line + $sep + [string]$Finding.Location.Key + $sep + [string]$Finding.Evidence)
}

function Invoke-AwRules {
    # Runs each rule; exceptions and invalid output become AW-CORE-002 findings.
    param($Ctx, [object[]]$Rules)
    $out = New-Object System.Collections.ArrayList
    foreach ($rule in $Rules) {
        try {
            $produced = @(& $rule.Check $Ctx)
        } catch {
            $where = ''
            if ($_.InvocationInfo -and $_.InvocationInfo.ScriptName) {
                $where = ' (at ' + [System.IO.Path]::GetFileName($_.InvocationInfo.ScriptName) + ':' + $_.InvocationInfo.ScriptLineNumber + ')'
            }
            [void]$out.Add((New-AwRuleFailure -RuleId $rule.Id -Message ($_.Exception.GetType().Name + ': ' + $_.Exception.Message + $where)))
            continue
        }
        foreach ($item in $produced) {
            if ($null -eq $item) { continue }
            $f = ConvertTo-AwCompleteFinding -Item $item -Rule $rule
            if ($null -eq $f) {
                [void]$out.Add((New-AwRuleFailure -RuleId $rule.Id -Message ('The rule returned an object that is not a finding: ' + $item.GetType().Name)))
            } else {
                [void]$out.Add($f)
            }
        }
    }
    return ,$out.ToArray()
}

function Write-AwRenderedFormats {
    # Renders each requested format with its ConvertTo-Aw* function, when that function is loaded.
    param($Result, [string[]]$Formats, [string]$OutFile, [bool]$Quiet)
    $base = $null
    if ($OutFile) {
        $base = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
        $base = $base -replace '\.(json|sarif|md|html)$', ''
    }
    foreach ($fmt in $script:AwFormatExtensions.Keys) {
        if ($Formats -notcontains $fmt) { continue }
        if ($fmt -eq 'Console' -and $Quiet) { continue }
        $fn = "ConvertTo-Aw$fmt"
        if (-not (Get-Command -Name $fn -CommandType Function -ErrorAction SilentlyContinue)) {
            Write-Warning "Airworthy: the $fmt format is not available ($fn is not loaded)."
            continue
        }
        if ($fmt -eq 'Console') {
            & $fn $Result | Out-Host
            continue
        }
        try {
            $text = [string]((& $fn $Result) -join [Environment]::NewLine)
        } catch {
            Write-Warning "Airworthy: rendering the $fmt format failed: $($_.Exception.Message)"
            continue
        }
        if ($base) {
            $file = $base + $script:AwFormatExtensions[$fmt]
            $dir = [System.IO.Path]::GetDirectoryName($file)
            if ($dir -and -not [System.IO.Directory]::Exists($dir)) { [void][System.IO.Directory]::CreateDirectory($dir) }
            [System.IO.File]::WriteAllText($file, $text, (New-Object System.Text.UTF8Encoding($false)))
            Write-Verbose "Airworthy: wrote $file"
        } else {
            Write-Output $text
        }
    }
}

function Invoke-Airworthy {
    <#
    .SYNOPSIS
    Statically analyzes the AI agent harness configuration of a folder and scores its security.
    .DESCRIPTION
    Reads VS Code GitHub Copilot, Claude Code, Copilot CLI and MCP configuration files under
    -Path (and in the user profile unless -NoUserProfile), runs the security rules, and
    reports a score (0-100), a grade (A-F), findings and fixes. Fully offline: it never runs
    an agent, an MCP server or a hook, and makes no network call.
    .PARAMETER Path
    Folder to analyze (default: current folder).
    .PARAMETER Format
    One or more of Console (default), Json, Sarif, Markdown, Html.
    .PARAMETER OutFile
    Base file name without extension. Writes <base>.json, .sarif, .md and .html for the
    requested formats. Without it, non-console formats are written to the pipeline.
    .PARAMETER UserSettingsPath
    VS Code user settings.json to use instead of the one found in the user profile.
    .PARAMETER UserProfilePath
    Folder to use as the user profile (for example a test fixture).
    .PARAMETER NoUserProfile
    Do not read anything from the user profile or machine-wide locations.
    .PARAMETER Redact
    Show the analyzed folder by its name only (never its absolute path), replace the user
    profile with '~' and mask the user name in paths, evidence and options, in every output.
    .PARAMETER MinSeverity
    Only report findings at or above this severity. The score always uses every finding.
    .PARAMETER FailOn
    Set ExitCode to 1 when a finding at or above this severity exists (for CI).
    .PARAMETER PassThru
    Return the result object.
    .PARAMETER Quiet
    Do not print the console report.
    .EXAMPLE
    Invoke-Airworthy -Path . -Format Console,Html -OutFile .\airworthy-report
    .EXAMPLE
    $r = Invoke-Airworthy -Path .\repo -NoUserProfile -FailOn high -PassThru -Quiet; exit $r.ExitCode
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)] [string]$Path = '.',
        [ValidateSet('Console', 'Json', 'Sarif', 'Markdown', 'Html')] [string[]]$Format = @('Console'),
        [string]$OutFile,
        [string]$UserSettingsPath,
        [string]$UserProfilePath,
        [switch]$NoUserProfile,
        [switch]$Redact,
        [ValidateSet('critical', 'high', 'medium', 'low', 'info')] [string]$MinSeverity = 'info',
        [ValidateSet('critical', 'high', 'medium', 'low', 'info')] [string]$FailOn,
        [switch]$PassThru,
        [switch]$Quiet
    )
    $ErrorActionPreference = 'Stop'

    $ctx = New-AwContext -Path $Path -UserSettingsPath $UserSettingsPath -UserProfilePath $UserProfilePath -NoUserProfile:$NoUserProfile
    $applicable = @(Get-AwRules | Where-Object { $_.Harness -eq 'generic' -or $ctx.Harnesses -contains $_.Harness })

    $all = New-Object System.Collections.ArrayList
    foreach ($e in $ctx.Errors) { [void]$all.Add($e) }
    foreach ($le in @($script:AwLoadErrors)) {
        if ($null -eq $le) { continue }
        [void]$all.Add((New-AwFinding -RuleId 'AW-CORE-002' -Title "File failed to load: $($le.File)" `
            -Evidence (Hide-AwSecretsInText $le.Message) -Location @{ Path = $null; Key = $le.File }))
    }
    Reset-AwUntrustedRegexState
    foreach ($f in (Invoke-AwRules -Ctx $ctx -Rules $applicable)) { [void]$all.Add($f) }
    $patternState = $script:AwUntrustedRegexState
    if ($patternState.Timeouts -gt 0 -or $patternState.Skipped -gt 0) {
        [void]$all.Add((New-AwFinding -RuleId 'AW-CORE-002' -Title 'Patterns from the scanned files were not fully evaluated' `
            -Evidence ('{0} pattern(s) taken from the scanned files (terminal regexes or globs) took more than {1} ms to match and {2} more were not run; they were treated as not matching, so findings that depend on them may be missing.' -f
                $patternState.Timeouts, [int]$script:AwUntrustedRegexTimeout.TotalMilliseconds, $patternState.Skipped) `
            -Location @{ Path = $null; Key = 'patterns' }))
    }

    # De-duplicate, then sort deterministically: severity, rule, path, line, key, evidence.
    $unique = @{}
    $keys = New-Object System.Collections.Generic.List[string]
    foreach ($f in $all) {
        $k = Get-AwFindingSortKey $f
        if (-not $unique.ContainsKey($k)) { $unique[$k] = $f; $keys.Add($k) }
    }
    $keyArray = $keys.ToArray()
    [Array]::Sort($keyArray, [StringComparer]::Ordinal)
    $findings = @(foreach ($k in $keyArray) { $unique[$k] })

    $score = Get-AwScore -Findings $findings -Rules $applicable -Harnesses $ctx.Harnesses

    $exitCode = 0
    if ($FailOn) {
        $threshold = Get-AwSeverityRank $FailOn
        if (@($findings | Where-Object { (Get-AwSeverityRank $_.Severity) -ge $threshold }).Count -gt 0) { $exitCode = 1 }
    }

    $root = $ctx.Root
    $optProfile = $UserProfilePath
    $optSettings = $UserSettingsPath
    $optOut = $OutFile
    if ($Redact) {
        # The absolute root is never written: it becomes its leaf folder name in every output.
        $rootLabel = Get-AwPathLabel -Path $ctx.Root -UserProfile $ctx.UserProfile
        foreach ($f in $findings) {
            $f.Location.Path = Get-AwDisplayPath -Path $f.Location.Path -Ctx $ctx -Redact
            $f.Location.Key = Hide-AwPrivateText -Text $f.Location.Key -Ctx $ctx -RootLabel $rootLabel
            $f.Evidence = Hide-AwPrivateText -Text $f.Evidence -Ctx $ctx -RootLabel $rootLabel
            $f.Title = Hide-AwPrivateText -Text $f.Title -Ctx $ctx -RootLabel $rootLabel
        }
        $root = $rootLabel
        $optProfile = Hide-AwOptionPath -Path $optProfile -Ctx $ctx -RootLabel $rootLabel
        $optSettings = Hide-AwOptionPath -Path $optSettings -Ctx $ctx -RootLabel $rootLabel
        $optOut = Hide-AwOptionPath -Path $optOut -Ctx $ctx -RootLabel $rootLabel
    }

    $minRank = Get-AwSeverityRank $MinSeverity
    $reported = @($findings | Where-Object { (Get-AwSeverityRank $_.Severity) -ge $minRank })
    $errors = @($findings | Where-Object { $_.RuleId -like 'AW-CORE-*' })

    $rulesMeta = New-Object System.Collections.ArrayList
    foreach ($r in $applicable) { [void]$rulesMeta.Add((ConvertTo-AwRuleMetadata $r)) }
    foreach ($coreId in @('AW-CORE-001', 'AW-CORE-002')) {
        if (@($findings | Where-Object { $_.RuleId -eq $coreId }).Count -gt 0) {
            [void]$rulesMeta.Add((ConvertTo-AwRuleMetadata $script:AwCoreRules[$coreId]))
        }
    }

    $formats = @($script:AwFormatExtensions.Keys | Where-Object { $Format -contains $_ })
    $result = [pscustomobject]@{
        Tool      = [ordered]@{ Name = $script:AwToolName; Version = $script:AwToolVersion }
        ScannedAt = [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
        Root      = $root
        Harnesses = [string[]]@($ctx.Harnesses)
        Score     = $score
        Findings  = $reported
        Rules     = $rulesMeta.ToArray()
        Errors    = $errors
        Options   = [ordered]@{
            Format           = [string[]]$formats
            OutFile          = $(if ($optOut) { $optOut } else { $null })
            MinSeverity      = $MinSeverity
            FailOn           = $(if ($FailOn) { $FailOn } else { $null })
            Redact           = [bool]$Redact
            NoUserProfile    = [bool]$NoUserProfile
            UserProfilePath  = $(if ($optProfile) { $optProfile } else { $null })
            UserSettingsPath = $(if ($optSettings) { $optSettings } else { $null })
        }
        ExitCode  = $exitCode
    }

    Write-AwRenderedFormats -Result $result -Formats $formats -OutFile $OutFile -Quiet ([bool]$Quiet)
    if ($PassThru) { $result }
}
