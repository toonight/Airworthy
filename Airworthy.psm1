# Airworthy module: loads src/Core, then src/Rules, then src/Output (alphabetical order in each).
Set-StrictMode -Version 2.0

$script:AwModuleRoot = $PSScriptRoot
$script:AwLoadErrors = @()

foreach ($area in @('Core', 'Rules', 'Output')) {
    $dir = Join-Path (Join-Path $PSScriptRoot 'src') $area
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
    foreach ($file in @(Get-ChildItem -LiteralPath $dir -Filter '*.ps1' -File | Sort-Object -Property Name)) {
        if ($area -eq 'Core') {
            . $file.FullName
            continue
        }
        # A broken rule or output file must not disable the whole tool: record it and go on.
        try {
            . $file.FullName
        } catch {
            $script:AwLoadErrors += [pscustomobject]@{ File = "src/$area/$($file.Name)"; Message = $_.Exception.Message }
            Write-Warning "Airworthy: failed to load src/$area/$($file.Name): $($_.Exception.Message)"
        }
    }
}

Remove-Variable -Name area, dir, file -ErrorAction SilentlyContinue
Export-ModuleMember -Function 'Invoke-Airworthy'
