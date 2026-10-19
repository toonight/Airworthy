<#
.SYNOPSIS
    Airworthy: offline static security score for AI agent harness configurations.
.DESCRIPTION
    Command-line wrapper around Invoke-Airworthy. It imports the Airworthy module from
    this folder, forwards the parameters, and exits with the result's exit code.

    It reads the VS Code GitHub Copilot, Claude Code, Copilot CLI and MCP configuration files
    under -Path (and in the user profile unless -NoUserProfile), and reports a score (0-100),
    a grade (A-F), the findings and how to fix them. It is fully offline: it never runs an
    agent, an MCP server or a hook, and it makes no network call.

    Exit codes:
      0  the analysis ran, and no finding reached the -FailOn severity (or -FailOn was not given)
      1  -FailOn was given and at least one finding is at or above that severity
      2  the analysis could not run (for example, the path is not a folder or an option is invalid)
.PARAMETER Path
    Folder to analyze. Default: the current folder.
.PARAMETER Format
    One or more of Console (default), Json, Sarif, Markdown, Html. A comma-separated value
    such as "Json,Sarif" is accepted, which is what powershell.exe -File passes.
.PARAMETER OutFile
    Base file name without extension. Writes <base>.json, <base>.sarif, <base>.md and
    <base>.html for the requested formats. Without it, these formats go to the pipeline.
.PARAMETER UserSettingsPath
    VS Code user settings.json to use instead of the one found in the user profile.
.PARAMETER UserProfilePath
    Folder to use as the user profile instead of the real one (for example a test fixture).
.PARAMETER NoUserProfile
    Read nothing from the user profile or from machine-wide locations: analyze -Path only.
.PARAMETER Redact
    Show the analyzed folder by its name only (never its absolute path), replace the user
    profile with '~' and mask the user name in paths, evidence and options, in every output.
    Use it for reports that you share.
.PARAMETER MinSeverity
    Only report findings at or above this severity: critical, high, medium, low or info (default).
    The score always uses every finding.
.PARAMETER FailOn
    Exit with code 1 when a finding at or above this severity exists (for CI): critical, high,
    medium, low or info. Findings hidden by -MinSeverity count too.
.PARAMETER PassThru
    Also return the result object.
.PARAMETER Quiet
    Do not print the console report.
.EXAMPLE
    .\airworthy.ps1 -Path C:\src\my-repo
.EXAMPLE
    .\airworthy.ps1 -Path . -Format Console,Html -OutFile .\airworthy-report
.EXAMPLE
    powershell -NoProfile -File .\airworthy.ps1 -Path . -NoUserProfile -Format Sarif -OutFile .\out\airworthy -FailOn high -Quiet
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)] [string]$Path = '.',
    [string[]]$Format = @('Console'),
    [string]$OutFile,
    [string]$UserSettingsPath,
    [string]$UserProfilePath,
    [switch]$NoUserProfile,
    [switch]$Redact,
    # Values are validated by Invoke-Airworthy, so that an invalid value also exits with code 2.
    [string]$MinSeverity = 'info',
    [string]$FailOn,
    [switch]$PassThru,
    [switch]$Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$exitCode = 2
try {
    Import-Module -Name (Join-Path $PSScriptRoot 'Airworthy.psd1') -Force

    $arguments = @{}
    foreach ($name in @($PSBoundParameters.Keys)) { $arguments[$name] = $PSBoundParameters[$name] }
    $arguments['Format'] = [string[]]@($Format | ForEach-Object { ([string]$_).Split(',') } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $arguments['PassThru'] = $true

    # Rendered texts (without -OutFile) come first on the pipeline, then the result object.
    $result = $null
    foreach ($item in @(Invoke-Airworthy @arguments)) {
        $isResult = ($item -is [System.Management.Automation.PSCustomObject]) -and
            ($null -ne $item.PSObject.Properties['ExitCode']) -and ($null -ne $item.PSObject.Properties['Score'])
        if (-not $isResult) {
            $item
            continue
        }
        $result = $item
        if ($PassThru) { $item }
    }
    if ($null -eq $result) { throw 'Invoke-Airworthy returned no result.' }
    $exitCode = [int]$result.ExitCode
} catch {
    $message = [string]$_.Exception.Message
    if ($message -notmatch '^Airworthy') { $message = 'Airworthy: ' + $message }
    $host.UI.WriteErrorLine($message)
    $exitCode = 2
}
exit $exitCode
