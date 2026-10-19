# Minimal test framework (no Pester dependency; only Pester 3.4 is available on Windows PowerShell 5.1).
# Dot-source this file, or let tests/Run-Tests.ps1 do it. It provides:
#   Describe 'name' { ... }   It 'name' { ... }
#   Assert-Equal $expected $actual [-Message]   Assert-True $cond   Assert-False $cond
#   Assert-Contains $collection $item   Assert-NotContains $collection $item
#   Assert-Throws { ... } [-ExpectedMessage <regex>]   Assert-Match $text $regex   Assert-NotMatch $text $regex
# State lives in a dynamic module so that every test file, whatever its scope, reports to one place.

$awTestModule = New-Module -Name AwTestFramework -ScriptBlock {
    $script:Results = New-Object System.Collections.ArrayList
    $script:DescribeStack = New-Object System.Collections.Generic.List[string]
    $script:CurrentFile = ''

    function Format-AwTestValue {
        param($Value)
        if ($null -eq $Value) { return '$null' }
        if ($Value -is [string]) { return "'$Value'" }
        if ($Value -is [bool]) { return '$' + $Value.ToString().ToLowerInvariant() }
        if ($Value -is [System.Collections.IDictionary]) {
            $parts = foreach ($k in $Value.Keys) { "$k=" + (Format-AwTestValue $Value[$k]) }
            return '@{' + ($parts -join '; ') + '}'
        }
        if ($Value -is [System.Collections.IEnumerable]) {
            $parts = foreach ($v in $Value) { Format-AwTestValue $v }
            return '@(' + ($parts -join ', ') + ')'
        }
        return [string]$Value
    }

    function Test-AwTestEqual {
        param($Expected, $Actual)
        if ($null -eq $Expected -or $null -eq $Actual) { return ($null -eq $Expected -and $null -eq $Actual) }
        if ($Expected -is [System.Collections.IDictionary]) {
            if ($Actual -isnot [System.Collections.IDictionary] -or $Actual.Count -ne $Expected.Count) { return $false }
            foreach ($k in $Expected.Keys) {
                if (-not $Actual.Contains($k)) { return $false }
                if (-not (Test-AwTestEqual $Expected[$k] $Actual[$k])) { return $false }
            }
            return $true
        }
        $expEnum = $Expected -is [System.Collections.IEnumerable] -and $Expected -isnot [string]
        $actEnum = $Actual -is [System.Collections.IEnumerable] -and $Actual -isnot [string]
        if ($expEnum -or $actEnum) {
            if (-not ($expEnum -and $actEnum)) { return $false }
            $e = @($Expected); $a = @($Actual)
            if ($e.Count -ne $a.Count) { return $false }
            for ($i = 0; $i -lt $e.Count; $i++) { if (-not (Test-AwTestEqual $e[$i] $a[$i])) { return $false } }
            return $true
        }
        $numeric = @([byte], [sbyte], [int16], [uint16], [int], [uint32], [long], [uint64], [single], [double], [decimal])
        if (($numeric -contains $Expected.GetType()) -and ($numeric -contains $Actual.GetType())) {
            return ([decimal]$Expected -eq [decimal]$Actual)
        }
        if ($Expected.GetType() -ne $Actual.GetType()) { return $false }
        if ($Expected -is [string]) { return [string]::Equals($Expected, $Actual, [StringComparison]::Ordinal) }
        return $Expected.Equals($Actual)
    }

    function New-AwAssertionError {
        param([string]$What, [string]$Message)
        $text = $What
        if ($Message) { $text = "$text ($Message)" }
        return (New-Object System.Exception -ArgumentList $text)
    }

    function Describe {
        param([Parameter(Mandatory, Position = 0)] [string]$Name, [Parameter(Mandatory, Position = 1)] [scriptblock]$Fixture)
        $script:DescribeStack.Add($Name)
        Write-Host ('  ' * $script:DescribeStack.Count) -NoNewline
        Write-Host $Name -ForegroundColor Cyan
        try {
            & $Fixture | Out-Null
        } catch {
            Add-AwTestResult -Name '(Describe block)' -Passed $false -Message $_.Exception.Message -Where (Get-AwTestLocation $_)
        } finally {
            $script:DescribeStack.RemoveAt($script:DescribeStack.Count - 1)
        }
    }

    function It {
        param([Parameter(Mandatory, Position = 0)] [string]$Name, [Parameter(Mandatory, Position = 1)] [scriptblock]$Test)
        try {
            & $Test | Out-Null
            Add-AwTestResult -Name $Name -Passed $true
        } catch {
            Add-AwTestResult -Name $Name -Passed $false -Message $_.Exception.Message -Where (Get-AwTestLocation $_)
        }
    }

    function Get-AwTestLocation {
        # First stack frame inside a *.Tests.ps1 file, as 'File.Tests.ps1:42'.
        param($ErrorRecord)
        $m = [regex]::Match([string]$ErrorRecord.ScriptStackTrace, '([^\\/]+\.Tests\.ps1): line (\d+)')
        if ($m.Success) { return "$($m.Groups[1].Value):$($m.Groups[2].Value)" }
        return ''
    }

    function Add-AwTestResult {
        param([string]$Name, [bool]$Passed, [string]$Message = '', [string]$Where = '')
        $full = (@($script:DescribeStack) + $Name) -join ' > '
        [void]$script:Results.Add([pscustomobject]@{ File = $script:CurrentFile; Name = $full; Passed = $Passed; Message = $Message; Where = $Where })
        $indent = '  ' * ($script:DescribeStack.Count + 1)
        if ($Passed) {
            Write-Host "$indent[PASS] $Name" -ForegroundColor DarkGreen
        } else {
            Write-Host "$indent[FAIL] $Name" -ForegroundColor Red
            Write-Host "$indent       $Message $Where" -ForegroundColor Red
        }
    }

    function Set-AwTestFile { param([string]$Name) $script:CurrentFile = $Name }
    function Get-AwTestResults { return ,$script:Results.ToArray() }
    function Reset-AwTestResults { $script:Results.Clear() }

    function Assert-Equal {
        param([Parameter(Position = 0)] [AllowNull()] $Expected, [Parameter(Position = 1)] [AllowNull()] $Actual, [Parameter(Position = 2)] [string]$Message)
        if (-not (Test-AwTestEqual $Expected $Actual)) {
            throw (New-AwAssertionError ("Expected " + (Format-AwTestValue $Expected) + " but got " + (Format-AwTestValue $Actual)) $Message)
        }
    }

    function Assert-True {
        param([Parameter(Position = 0)] [AllowNull()] $Condition, [Parameter(Position = 1)] [string]$Message)
        if (-not $Condition) { throw (New-AwAssertionError ('Expected a true condition but got ' + (Format-AwTestValue $Condition)) $Message) }
    }

    function Assert-False {
        param([Parameter(Position = 0)] [AllowNull()] $Condition, [Parameter(Position = 1)] [string]$Message)
        if ($Condition) { throw (New-AwAssertionError ('Expected a false condition but got ' + (Format-AwTestValue $Condition)) $Message) }
    }

    function Assert-Contains {
        param([Parameter(Position = 0)] [AllowNull()] $Collection, [Parameter(Position = 1)] [AllowNull()] $Item, [Parameter(Position = 2)] [string]$Message)
        if (@($Collection) -notcontains $Item) {
            throw (New-AwAssertionError ('Expected the collection to contain ' + (Format-AwTestValue $Item) + '; it has ' + (Format-AwTestValue @($Collection))) $Message)
        }
    }

    function Assert-NotContains {
        param([Parameter(Position = 0)] [AllowNull()] $Collection, [Parameter(Position = 1)] [AllowNull()] $Item, [Parameter(Position = 2)] [string]$Message)
        if (@($Collection) -contains $Item) {
            throw (New-AwAssertionError ('Expected the collection not to contain ' + (Format-AwTestValue $Item)) $Message)
        }
    }

    function Assert-Throws {
        # Returns the caught exception so that tests can inspect it.
        param([Parameter(Mandatory, Position = 0)] [scriptblock]$ScriptBlock, [string]$ExpectedMessage, [string]$Message)
        $caught = $null
        try { & $ScriptBlock | Out-Null } catch { $caught = $_.Exception }
        if ($null -eq $caught) { throw (New-AwAssertionError 'Expected an exception but none was thrown' $Message) }
        if ($ExpectedMessage -and $caught.Message -notmatch $ExpectedMessage) {
            throw (New-AwAssertionError ("Expected an exception matching '$ExpectedMessage' but got '" + $caught.Message + "'") $Message)
        }
        return $caught
    }

    function Assert-Match {
        param([Parameter(Position = 0)] [AllowNull()] $Text, [Parameter(Position = 1)] [string]$Pattern, [Parameter(Position = 2)] [string]$Message)
        if ([string]$Text -notmatch $Pattern) { throw (New-AwAssertionError ("Expected " + (Format-AwTestValue ([string]$Text)) + " to match /$Pattern/") $Message) }
    }

    function Assert-NotMatch {
        param([Parameter(Position = 0)] [AllowNull()] $Text, [Parameter(Position = 1)] [string]$Pattern, [Parameter(Position = 2)] [string]$Message)
        if ([string]$Text -match $Pattern) { throw (New-AwAssertionError ("Expected " + (Format-AwTestValue ([string]$Text)) + " not to match /$Pattern/") $Message) }
    }

    Export-ModuleMember -Function Describe, It, Assert-Equal, Assert-True, Assert-False, Assert-Contains, Assert-NotContains,
        Assert-Throws, Assert-Match, Assert-NotMatch, Set-AwTestFile, Get-AwTestResults, Reset-AwTestResults, Add-AwTestResult
}
Import-Module $awTestModule -Global -Force -DisableNameChecking
Remove-Variable -Name awTestModule
