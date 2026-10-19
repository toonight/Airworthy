# VS Code effective settings: documented defaults, nested-key flattening and layered merge.

# Documented defaults. Source: https://code.visualstudio.com/docs/copilot/reference/copilot-settings
# (read 2026-10-18).
$script:AwVSCodeDefaults = New-Object System.Collections.Hashtable -ArgumentList @([System.StringComparer]::Ordinal)
$d = $script:AwVSCodeDefaults

# Approvals
$d['chat.permissions.default']               = 'default'
$d['chat.tools.global.autoApprove']          = $false
$d['chat.tools.eligibleForAutoApproval']     = @()
$d['chat.tools.urls.autoApprove']            = @()
$d['chat.tools.riskAssessment.enabled']      = $true    # not a security boundary (docs)
# Insiders defaults to true, Stable to false; Assisted is not available in Local harness sessions.
$d['chat.assistedPermissions.enabled']       = $false

# Terminal
$d['chat.tools.terminal.enableAutoApprove']             = $true
$d['chat.tools.terminal.ignoreDefaultAutoApproveRules'] = $false
$d['chat.tools.terminal.autoApprove'] = @{
    'rm' = $false; 'rmdir' = $false; 'del' = $false; 'kill' = $false; 'curl' = $false
    'wget' = $false; 'eval' = $false; 'chmod' = $false; 'chown' = $false; '/^Remove-Item\b/i' = $false
}
$d['chat.tools.terminal.blockDetectedFileWrites']  = 'outsideWorkspace'
$d['chat.tools.terminal.autoReplyToPrompts']       = $false
$d['chat.tools.terminal.enforceTimeoutFromModel']  = $true

# Edits and file access
$d['chat.tools.edits.autoApprove']                    = @{}
$d['github.copilot.chat.additionalReadAccessFolders'] = @()

# Sandbox and network. The settings page documents 'off' for chat.agent.sandbox.enabled,
# while the security page says Copilot harness sessions are sandboxed by default (the two pages disagree).
$d['chat.agent.sandbox.enabled']                          = 'off'
$d['chat.agent.sandbox.network.allowNetwork']             = $true
$d['chat.agent.sandbox.network.allowLocalNetwork']        = $false
$d['chat.agent.sandbox.allowUnsandboxedCommands']         = $true
$d['chat.agent.sandbox.allowAutoApprove']                 = $true
$d['chat.agent.sandbox.fileSystem.allowDevToolAccess']    = $true
$d['chat.agent.sandbox.fileSystem.userConfiguredPaths']   = @{ 'readwritePaths' = @(); 'readonlyPaths' = @(); 'deniedPaths' = @() }
$d['chat.agent.sandbox.mcpServers']                       = $true    # macOS and Linux only
$d['chat.agent.sandbox.lspServers']                       = $true
$d['chat.agent.sandbox.credentials.authenticategit']      = $true
$d['chat.agent.sandbox.credentials.authenticategh']       = $true
$d['chat.agent.sandbox.allowNetwork']                     = $true    # deprecated
$d['chat.agent.sandbox.retryWithAllowNetworkRequests']    = $true    # deprecated
$d['chat.agent.networkFilter']                            = $false
$d['chat.agent.allowedNetworkDomains']                    = @()

# MCP
$d['chat.mcp.autostart']         = 'newAndOutdated'
$d['chat.mcp.discovery.enabled'] = $false
$d['chat.mcp.serverSampling']    = @{}

# Hooks, loops, telemetry
$d['chat.useHooks']                           = $true    # Local harness only
$d['chat.useClaudeHooks']                     = $false
$d['chat.agent.maxRequests']                  = 25
$d['github.copilot.chat.otel.enabled']        = $false
$d['github.copilot.chat.otel.otlpEndpoint']   = 'http://localhost:4318'
$d['github.copilot.chat.otel.captureContent'] = $false
Remove-Variable -Name d

# Settings whose value is an object even without a documented default here.
# Nested notation is never flattened below these keys. The urls and eligibleForAutoApproval
# settings are documented with a [] default but used in object form ({ "<url>": true }).
$script:AwVSCodeObjectSettings = @(
    'chat.tools.urls.autoApprove', 'chat.tools.eligibleForAutoApproval',
    'chat.agent.sandbox.fileSystem.linux', 'chat.agent.sandbox.fileSystem.mac', 'chat.agent.sandbox.fileSystem.windows',
    'chat.tools.terminal.autoApprove', 'chat.tools.edits.autoApprove', 'chat.mcp.serverSampling',
    'chat.agent.sandbox.fileSystem.userConfiguredPaths', 'github.copilot.enable', 'mcp'
)

function Copy-AwValue {
    # Deep copy of hashtables and arrays, so merging never mutates parsed files or defaults.
    param($Value)
    if ($Value -is [System.Collections.IDictionary]) {
        $copy = New-AwOrdinalHashtable
        foreach ($k in $Value.Keys) { $copy[$k] = Copy-AwValue $Value[$k] }
        return ,$copy
    }
    if ($Value -is [System.Array]) {
        $list = New-Object System.Collections.ArrayList
        foreach ($item in $Value) { [void]$list.Add((Copy-AwValue $item)) }
        return ,$list.ToArray()
    }
    return $Value
}

function Merge-AwObject {
    # Deep merge as VS Code does: objects merge key by key, anything else is replaced.
    param([System.Collections.IDictionary]$Base, [System.Collections.IDictionary]$Overlay)
    $result = Copy-AwValue $Base
    foreach ($k in $Overlay.Keys) {
        $ov = $Overlay[$k]
        if ($result.Contains($k) -and $result[$k] -is [System.Collections.IDictionary] -and $ov -is [System.Collections.IDictionary]) {
            $result[$k] = Merge-AwObject -Base $result[$k] -Overlay $ov
        } else {
            $result[$k] = Copy-AwValue $ov
        }
    }
    return ,$result
}

function Test-AwObjectSetting {
    param([string]$Key)
    if ($script:AwVSCodeObjectSettings -ccontains $Key) { return $true }
    return ($script:AwVSCodeDefaults.ContainsKey($Key) -and $script:AwVSCodeDefaults[$Key] -is [System.Collections.IDictionary])
}

function ConvertTo-AwFlatSettings {
    <#
    .SYNOPSIS
    Flattens nested notation ({"chat": {"tools": {...}}}) into dotted setting keys.
    .DESCRIPTION
    Dotted top-level keys are kept as they are. Nested objects are flattened until a known
    object-valued setting is reached. Language overrides ("[python]") are kept whole.
    #>
    param([System.Collections.IDictionary]$Settings)
    $flat = New-AwOrdinalHashtable
    if ($null -eq $Settings) { return ,$flat }
    $queue = New-Object System.Collections.Queue
    foreach ($k in $Settings.Keys) { $queue.Enqueue(@($k, $Settings[$k], 0)) }
    while ($queue.Count -gt 0) {
        $item = $queue.Dequeue()
        $key = [string]$item[0]; $value = $item[1]; $depth = [int]$item[2]
        $isNestingSegment = ($depth -gt 0 -or -not $key.Contains('.')) -and -not $key.StartsWith('[')
        if ($value -is [System.Collections.IDictionary] -and $isNestingSegment -and -not (Test-AwObjectSetting $key) -and $depth -lt 16) {
            foreach ($child in $value.Keys) { $queue.Enqueue(@("$key.$child", $value[$child], ($depth + 1))) }
            continue
        }
        # The same object setting written in both dotted and nested form: merge both.
        if ($flat.ContainsKey($key) -and $flat[$key] -is [System.Collections.IDictionary] -and $value -is [System.Collections.IDictionary]) {
            $flat[$key] = Merge-AwObject -Base $flat[$key] -Overlay $value
        } else {
            $flat[$key] = $value
        }
    }
    return ,$flat
}

function Get-AwEffectiveSettings {
    <#
    .SYNOPSIS
    Merges VS Code setting layers in order default < user < workspaceFile < workspace.
    .DESCRIPTION
    Each layer is @{ Source; Path; Settings (hashtable) }. Returns a case-sensitive hashtable
    key -> { Key; Value; Source; Path; IsDefault; Layers }. Layers lists, in order, every
    layer where the key is present ({ Source; Path; Value }).
    #>
    param([object[]]$Layers = @())
    $all = New-Object System.Collections.ArrayList
    [void]$all.Add(@{ Source = 'default'; Path = $null; Settings = $script:AwVSCodeDefaults })
    foreach ($l in $Layers) { if ($null -ne $l) { [void]$all.Add($l) } }

    $state = New-AwOrdinalHashtable
    foreach ($layer in $all) {
        $flat = if ($layer.Source -eq 'default') { $layer.Settings } else { ConvertTo-AwFlatSettings -Settings $layer.Settings }
        $keys = [string[]]@($flat.Keys)
        [Array]::Sort($keys, [StringComparer]::Ordinal)
        foreach ($key in $keys) {
            $value = $flat[$key]
            if (-not $state.ContainsKey($key)) {
                $state[$key] = @{ Value = (Copy-AwValue $value); Source = $layer.Source; Path = $layer.Path; Layers = (New-Object System.Collections.ArrayList) }
            } else {
                $entry = $state[$key]
                if ($entry.Value -is [System.Collections.IDictionary] -and $value -is [System.Collections.IDictionary]) {
                    $entry.Value = Merge-AwObject -Base $entry.Value -Overlay $value
                } else {
                    $entry.Value = Copy-AwValue $value
                }
                $entry.Source = $layer.Source
                $entry.Path = $layer.Path
            }
            [void]$state[$key].Layers.Add([pscustomobject]@{ Source = $layer.Source; Path = $layer.Path; Value = (Copy-AwValue $value) })
        }
    }

    $effective = New-AwOrdinalHashtable
    foreach ($key in $state.Keys) {
        $e = $state[$key]
        $effective[$key] = [pscustomobject]@{
            Key       = $key
            Value     = $e.Value
            Source    = $e.Source
            Path      = $e.Path
            IsDefault = ($e.Source -eq 'default')
            Layers    = $e.Layers.ToArray()
        }
    }
    return ,$effective
}

function Get-AwSetting {
    <#
    .SYNOPSIS
    Returns the effective VS Code setting entry for Key, or $null when it is set nowhere and has no default.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Ctx, [Parameter(Mandatory)] [string]$Key)
    $vs = Get-AwMemberValue $Ctx 'VSCode'
    $effective = Get-AwMemberValue $vs 'Effective'
    if ($null -ne $effective -and $effective.Contains($Key)) { return $effective[$Key] }
    if ($script:AwVSCodeDefaults.ContainsKey($Key)) {
        $v = $script:AwVSCodeDefaults[$Key]
        return [pscustomobject]@{
            Key = $Key; Value = (Copy-AwValue $v); Source = 'default'; Path = $null; IsDefault = $true
            Layers = @([pscustomobject]@{ Source = 'default'; Path = $null; Value = (Copy-AwValue $v) })
        }
    }
    return $null
}
