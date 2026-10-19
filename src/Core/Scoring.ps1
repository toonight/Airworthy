# Scoring: category scores, weighted overall score, critical cap and grade.

function Get-AwGrade {
    param([int]$Score)
    if ($Score -ge 90) { return 'A' }
    if ($Score -ge 80) { return 'B' }
    if ($Score -ge 70) { return 'C' }
    if ($Score -ge 60) { return 'D' }
    return 'F'
}

function Get-AwScore {
    <#
    .SYNOPSIS
    Computes the score (0-100), grade (A-F), per-category scores and severity counts.
    .DESCRIPTION
    Per rule: the first finding removes weight(severity), each further finding 25% of that
    weight, capped at 2x the weight. Categories start at 100 (floor 0). A category applies
    when one of its rules targets a detected harness or 'generic'. The overall score is the
    weighted average of the applicable categories (100 when none applies), capped at 69
    when a critical finding exists.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] [AllowEmptyCollection()] [object[]]$Findings = @(),
        [AllowNull()] [AllowEmptyCollection()] [object[]]$Rules = @(),
        [AllowNull()] [AllowEmptyCollection()] [string[]]$Harnesses = @()
    )
    $findings = @($Findings | Where-Object { $null -ne $_ })
    $rules = @($Rules | Where-Object { $null -ne $_ })
    $harnessList = @($Harnesses | Where-Object { $_ })

    $counts = [ordered]@{}
    foreach ($s in $script:AwSeverities) { $counts[$s] = 0 }
    foreach ($f in $findings) {
        $sev = [string]$f.Severity
        if ($counts.Contains($sev)) { $counts[$sev] = $counts[$sev] + 1 }
    }

    $ruleCategory = @{}
    foreach ($r in $rules) { $ruleCategory[[string]$r.Id] = [string]$r.Category }

    # Group findings by rule, in a stable order.
    $byRule = @{}
    foreach ($f in $findings) {
        $id = [string]$f.RuleId
        if (-not $byRule.ContainsKey($id)) { $byRule[$id] = New-Object System.Collections.ArrayList }
        [void]$byRule[$id].Add($f)
    }

    $deduction = @{}
    $findingCount = @{}
    foreach ($c in $script:AwCategories.Keys) { $deduction[$c] = 0.0; $findingCount[$c] = 0 }

    $ids = [string[]]@($byRule.Keys); [Array]::Sort($ids, [StringComparer]::Ordinal)
    foreach ($id in $ids) {
        $group = @($byRule[$id])
        $category = if ($ruleCategory.ContainsKey($id)) { $ruleCategory[$id] } else { [string]$group[0].Category }
        if (-not $deduction.ContainsKey($category)) { continue }
        $findingCount[$category] += $group.Count
        $weights = @($group | ForEach-Object {
            $w = $script:AwSeverityWeight[[string]$_.Severity]
            if ($null -eq $w) { 0 } else { [double]$w }
        } | Sort-Object -Descending)
        $first = [double]$weights[0]
        $total = $first
        for ($k = 1; $k -lt $weights.Count; $k++) { $total += 0.25 * [double]$weights[$k] }
        $deduction[$category] += [Math]::Min($total, 2 * $first)
    }

    $applicable = @{}
    foreach ($c in $script:AwCategories.Keys) { $applicable[$c] = $false }
    foreach ($r in $rules) {
        $h = [string]$r.Harness
        if (($h -eq 'generic' -or $harnessList -contains $h) -and $applicable.ContainsKey([string]$r.Category)) {
            $applicable[[string]$r.Category] = $true
        }
    }

    $categories = [ordered]@{}
    $weightedSum = 0.0
    $weightTotal = 0.0
    foreach ($c in $script:AwCategories.Keys) {
        $raw = [Math]::Max(0.0, 100.0 - $deduction[$c])
        $categories[$c] = [ordered]@{
            Title      = $script:AwCategories[$c].Title
            Score      = [int][Math]::Round($raw, [MidpointRounding]::AwayFromZero)
            Applicable = [bool]$applicable[$c]
            Findings   = [int]$findingCount[$c]
        }
        if ($applicable[$c]) {
            $weightedSum += $raw * $script:AwCategories[$c].Weight
            $weightTotal += $script:AwCategories[$c].Weight
        }
    }

    $score = 100
    if ($weightTotal -gt 0) { $score = [int][Math]::Round($weightedSum / $weightTotal, [MidpointRounding]::AwayFromZero) }
    if ($counts['critical'] -gt 0 -and $score -gt 69) { $score = 69 }

    [pscustomobject]@{
        Score      = $score
        Grade      = Get-AwGrade -Score $score
        Categories = $categories
        Counts     = $counts
    }
}
