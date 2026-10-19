# Console output: a compact, colored text summary of a result. ASCII only, so that it reads
# the same in a Windows PowerShell 5.1 console and in a CI log.

$script:AwConsoleSeverityColor = @{ critical = 'Magenta'; high = 'Red'; medium = 'Yellow'; low = 'Cyan'; info = 'Gray' }
$script:AwConsoleMaxText = 300
$script:AwConsoleBarWidth = 20

function New-AwConsoleSegment {
    param([string]$Text, [string]$Color)
    [pscustomobject]@{ Text = $Text; Color = $(if ($Color) { $Color } else { $null }) }
}

function Add-AwConsoleLine {
    # Appends one line made of segments: strings (default color) or New-AwConsoleSegment objects.
    param([System.Collections.Generic.List[object]]$Lines, [object[]]$Segments = @())
    $segs = foreach ($s in $Segments) {
        if ($null -eq $s) { continue }
        if ($s -is [string]) { New-AwConsoleSegment -Text $s } else { $s }
    }
    $Lines.Add([pscustomobject]@{ Segments = [object[]]@($segs) })
}

function Get-AwGradeColor {
    param([string]$Grade)
    switch ($Grade) { 'A' { 'Green' } 'B' { 'Green' } 'C' { 'Yellow' } 'D' { 'DarkYellow' } default { 'Red' } }
}

function Get-AwScoreColor {
    param([int]$Score)
    if ($Score -ge 90) { return 'Green' }
    if ($Score -ge 70) { return 'Yellow' }
    return 'Red'
}

function Get-AwTextBar {
    # '[#####---------------]' for a 0-100 score.
    param([int]$Score, [int]$Width = $script:AwConsoleBarWidth)
    $s = [Math]::Max(0, [Math]::Min(100, $Score))
    $filled = [int][Math]::Round($s * $Width / 100.0, [MidpointRounding]::AwayFromZero)
    return '[' + ('#' * $filled) + ('-' * ($Width - $filled)) + ']'
}

function Get-AwConsoleLines {
    # Builds the console report as lines of colored segments.
    param($Result, [string]$MinSeverity)
    $lines = New-Object System.Collections.Generic.List[object]
    $max = $script:AwConsoleMaxText
    $options = Get-AwMemberValue $Result 'Options'
    if (-not $MinSeverity) { $MinSeverity = Get-AwOutputText $options 'MinSeverity' }
    if ((Get-AwSeverityRank $MinSeverity) -lt 0) { $MinSeverity = 'info' }

    $tool = Get-AwMemberValue $Result 'Tool'
    $toolName = Get-AwOutputText $tool 'Name'; if (-not $toolName) { $toolName = $script:AwToolName }
    $toolVersion = Get-AwOutputText $tool 'Version'; if (-not $toolVersion) { $toolVersion = $script:AwToolVersion }
    $score = Get-AwMemberValue $Result 'Score'
    $scoreValue = Get-AwOutputText $score 'Score'; if (-not $scoreValue) { $scoreValue = '?' }
    $grade = Get-AwOutputText $score 'Grade'; if (-not $grade) { $grade = '?' }
    $harnesses = @(Get-AwOutputList $Result 'Harnesses' | ForEach-Object { Get-AwSafeText ([string]$_) -MaxLength 40 })
    $harnessText = if ($harnesses.Count -gt 0) { $harnesses -join ', ' } else { '(none detected)' }

    Add-AwConsoleLine $lines @((New-AwConsoleSegment "$toolName $toolVersion" 'White'), '  agent harness security score')
    Add-AwConsoleLine $lines @('  Root       ', (Get-AwSafeText (Get-AwOutputText $Result 'Root') -MaxLength $max))
    Add-AwConsoleLine $lines @('  Harnesses  ', $harnessText)
    Add-AwConsoleLine $lines @('  Score      ', (New-AwConsoleSegment "$scoreValue/100  grade $grade" (Get-AwGradeColor $grade)))

    $counts = Get-AwOutputCounts $Result
    $countSegs = New-Object System.Collections.Generic.List[object]
    $countSegs.Add('  Findings   ')
    $first = $true
    foreach ($s in $script:AwSeverities) {
        if (-not $first) { $countSegs.Add(', ') }
        $first = $false
        $color = if ($counts[$s] -gt 0) { $script:AwConsoleSeverityColor[$s] } else { 'DarkGray' }
        $countSegs.Add((New-AwConsoleSegment "$($counts[$s]) $s" $color))
    }
    Add-AwConsoleLine $lines $countSegs.ToArray()

    $categories = @(Get-AwOutputCategories $Result)
    if ($categories.Count -gt 0) {
        Add-AwConsoleLine $lines
        Add-AwConsoleLine $lines @((New-AwConsoleSegment 'Categories' 'White'))
        foreach ($c in $categories) {
            $label = '  ' + (Get-AwSafeText $c.Title -MaxLength 30).PadRight(30)
            if (-not $c.Applicable) {
                Add-AwConsoleLine $lines @($label, (New-AwConsoleSegment 'n/a (not applicable to the detected harnesses)' 'DarkGray'))
                continue
            }
            $color = Get-AwScoreColor $c.Score
            $suffix = if ($c.Findings -eq 1) { '  1 finding' } elseif ($c.Findings -gt 1) { "  $($c.Findings) findings" } else { '' }
            Add-AwConsoleLine $lines @($label, (New-AwConsoleSegment ((Get-AwTextBar $c.Score) + ' ' + ([string]$c.Score).PadLeft(3)) $color), $suffix)
        }
    }

    $shown = @(Get-AwOutputFindings -Result $Result -MinSeverity $MinSeverity)
    Add-AwConsoleLine $lines
    if ($shown.Count -eq 0) {
        Add-AwConsoleLine $lines @((New-AwConsoleSegment "No findings at or above '$MinSeverity'." 'Green'))
    } else {
        Add-AwConsoleLine $lines @((New-AwConsoleSegment 'Findings' 'White'))
        foreach ($sev in $script:AwSeverities) {
            $group = @($shown | Where-Object { [string](Get-AwMemberValue $_ 'Severity') -eq $sev })
            if ($group.Count -eq 0) { continue }
            $color = $script:AwConsoleSeverityColor[$sev]
            Add-AwConsoleLine $lines @((New-AwConsoleSegment "  $($sev.ToUpperInvariant()) ($($group.Count))" $color))
            foreach ($f in $group) {
                $ruleId = Get-AwSafeText (Get-AwOutputText $f 'RuleId') -MaxLength 40
                Add-AwConsoleLine $lines @('    ', (New-AwConsoleSegment $ruleId $color), '  ', (Get-AwSafeText (Get-AwOutputTitle $f) -MaxLength $max))
                $where = Get-AwOutputLocation -Result $Result -Finding $f
                $evidence = Get-AwSafeText (Get-AwOutputEvidence $f) -MaxLength $max
                $key = Get-AwSafeText (Get-AwOutputText (Get-AwMemberValue $f 'Location') 'Key') -MaxLength 120
                # The key is shown only when the evidence does not already name it.
                if ($key -and $evidence.IndexOf($key, [StringComparison]::Ordinal) -lt 0) {
                    $where = if ($where) { "$where [$key]" } else { "[$key]" }
                }
                if ($where) { Add-AwConsoleLine $lines @('        ', (New-AwConsoleSegment (Get-AwSafeText $where -MaxLength $max) 'DarkCyan')) }
                if ($evidence) { Add-AwConsoleLine $lines @('        Evidence: ', $evidence) }
                $fix = Get-AwSafeText (Get-AwOutputText $f 'Fix') -MaxLength $max
                if ($fix) { Add-AwConsoleLine $lines @('        Fix: ', (New-AwConsoleSegment $fix 'Green')) }
            }
        }
    }

    $total = 0
    foreach ($s in $script:AwSeverities) { $total += $counts[$s] }
    $hidden = $total - $shown.Count
    $failOn = Get-AwOutputText $options 'FailOn'
    if ($hidden -gt 0 -or $failOn) { Add-AwConsoleLine $lines }
    if ($hidden -gt 0) {
        $noun = if ($hidden -eq 1) { 'finding' } else { 'findings' }
        Add-AwConsoleLine $lines @((New-AwConsoleSegment "$hidden $noun below '$MinSeverity' not shown (-MinSeverity)." 'DarkGray'))
    }
    if ($failOn) {
        $exitCode = Get-AwOutputText $Result 'ExitCode'
        if ($exitCode -eq '1') {
            Add-AwConsoleLine $lines @((New-AwConsoleSegment "FailOn ${failOn}: failed (exit code 1)." 'Red'))
        } else {
            Add-AwConsoleLine $lines @((New-AwConsoleSegment "FailOn ${failOn}: passed." 'Green'))
        }
    }
    return $lines.ToArray()
}

function ConvertTo-AwConsole {
    <#
    .SYNOPSIS
    Writes a compact, colored summary of a Airworthy result to the host.
    .DESCRIPTION
    Shows the score and grade, one text bar per category, then the findings grouped by
    severity with rule ID, title, location (path:line, relative to the analyzed root when
    inside it), evidence and fix. Findings below -MinSeverity are left out; by default the
    result's own MinSeverity option is used. Text from scanned files is reduced to printable
    single lines, so a hostile file cannot inject terminal escape sequences.
    .PARAMETER Result
    The result object returned by Invoke-Airworthy -PassThru.
    .PARAMETER MinSeverity
    Only show findings at or above this severity.
    .PARAMETER NoColor
    Return the lines as strings instead of writing them to the host in color.
    .EXAMPLE
    ConvertTo-AwConsole $result -MinSeverity high
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)] $Result,
        [ValidateSet('critical', 'high', 'medium', 'low', 'info')] [string]$MinSeverity,
        [switch]$NoColor
    )
    foreach ($line in @(Get-AwConsoleLines -Result $Result -MinSeverity $MinSeverity)) {
        if ($NoColor) {
            [string]::Join('', [string[]]@(foreach ($s in $line.Segments) { $s.Text }))
            continue
        }
        foreach ($s in $line.Segments) {
            if ($s.Color) { Write-Host $s.Text -NoNewline -ForegroundColor $s.Color }
            else { Write-Host $s.Text -NoNewline }
        }
        Write-Host ''
    }
}
