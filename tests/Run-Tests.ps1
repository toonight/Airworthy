<#
.SYNOPSIS
    Runs the Airworthy test suite (tests/*.Tests.ps1) with the project's own minimal test framework.
.PARAMETER Name
    Optional wildcard filter on test file names without the .Tests.ps1 suffix, for example 'VSCode' or 'Core','Jsonc'.
    A comma-separated value ('Core,Jsonc') also works, as powershell.exe -File passes it as one string.
#>
param([string[]]$Name = @('*'))

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Name = @($Name | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if ($Name.Count -eq 0) { $Name = @('*') }

$testsDir = $PSScriptRoot
$manifest = Join-Path (Split-Path -Parent $testsDir) 'Airworthy.psd1'
. (Join-Path $testsDir 'TestFramework.ps1')
Reset-AwTestResults

$files = @(Get-ChildItem -LiteralPath $testsDir -Filter '*.Tests.ps1' -File | Sort-Object -Property Name | Where-Object {
    $short = $_.Name -replace '\.Tests\.ps1$', ''
    @($Name | Where-Object { $short -like $_ }).Count -gt 0
})

$started = Get-Date
foreach ($file in $files) {
    Write-Host ''
    Write-Host "== $($file.Name)" -ForegroundColor White
    Set-AwTestFile $file.Name
    try {
        Import-Module $manifest -Force -DisableNameChecking
        & $file.FullName
    } catch {
        Add-AwTestResult -Name '(test file stopped)' -Passed $false -Message $_.Exception.Message -Where $_.InvocationInfo.PositionMessage
    }
}

# Get-AwTestResults returns one array (unary comma): assign it first, so @() does not wrap it again.
$results = Get-AwTestResults
$results = @($results)
$failed = @($results | Where-Object { -not $_.Passed })
$elapsed = [int]((Get-Date) - $started).TotalSeconds

Write-Host ''
if ($failed.Count -gt 0) {
    Write-Host 'Failures:' -ForegroundColor Red
    foreach ($f in $failed) { Write-Host "  [$($f.File)] $($f.Name): $($f.Message) $($f.Where)" -ForegroundColor Red }
    Write-Host ''
}
Write-Host ("Test files: {0}  Tests: {1}  Passed: {2}  Failed: {3}  ({4}s)" -f $files.Count, $results.Count, ($results.Count - $failed.Count), $failed.Count, $elapsed)
if ($failed.Count -gt 0 -or $files.Count -eq 0) { exit 1 }
exit 0
