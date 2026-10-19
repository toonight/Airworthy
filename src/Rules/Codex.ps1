# Codex CLI rules (AW-CDX-0xx), applied to Ctx.Codex: ~/.codex/config.toml (or $CODEX_HOME) [user],
# the .codex/config.toml of the root and of the folders below it [project], <codex home>/<name>.config.toml
# [profile], the machine-wide requirements.toml [managed] and the Unix /etc/codex/config.toml [system];
# to the project .codex/hooks.json in Ctx.Hooks, and to the project .codex/rules/*.rules files in
# Ctx.CodexRules. The MCP servers of Codex files are checked by the AW-MCP rules: discovery maps them
# into Ctx.McpFiles.
# Sources (read 2026-10-19): learn.chatgpt.com/docs/config-file/config-reference, /config-basic and
# /config-advanced, /agent-approvals-security, /permissions, /extend/mcp, /hooks,
# /agent-configuration/rules and /enterprise/managed-configuration. Only documented keys are checked.
# TOML keys and values are case-sensitive: a hostile "Sandbox_Mode" key never hides sandbox_mode.

$script:AwCdxDocs = @{
    Reference   = 'https://learn.chatgpt.com/docs/config-file/config-reference'
    Basics      = 'https://learn.chatgpt.com/docs/config-file/config-basic'
    Advanced    = 'https://learn.chatgpt.com/docs/config-file/config-advanced'
    Security    = 'https://learn.chatgpt.com/docs/agent-approvals-security'
    Permissions = 'https://learn.chatgpt.com/docs/permissions'
    Mcp         = 'https://learn.chatgpt.com/docs/extend/mcp'
    Hooks       = 'https://learn.chatgpt.com/docs/hooks'
    Rules       = 'https://learn.chatgpt.com/docs/agent-configuration/rules'
    Managed     = 'https://learn.chatgpt.com/docs/enterprise/managed-configuration'
}

# Setting values and key names live in src/Data/codex.json (CONTRIBUTING.md, Antivirus hygiene).
$script:AwCdxData = Read-AwDataFile -Name 'codex'
$script:AwCdxMaxPerFile = 20     # findings listed per file and kind (hooks, rules, tools, paths, servers...)
$script:AwCdxMaxRuleCalls = 200  # prefix_rule calls examined per rules file
$script:AwCdxMaxPathLength = 4096
# Line lookups (Get-AwCdxLine): longest key searched, and characters searched after a header.
$script:AwCdxMaxLineKey = 64
$script:AwCdxLineWindow = 65536
$script:AwCdxRxBlank = New-Object System.Text.RegularExpressions.Regex -ArgumentList '\G[ \t]*'

# ---------------------------------------------------------------------------------------------
# Helpers (evidence masking: Format-AwCommandSnippet, secret tests: Test-AwMcpReference and
# Test-AwMcpPlaceholder, in Mcp.ps1)
# ---------------------------------------------------------------------------------------------

function Get-AwCdxDataText {
    param([string]$Key)
    $v = $script:AwCdxData[$Key]
    if ($v -is [string]) { return $v }
    return ''
}

function Get-AwCdxDataList {
    # The string items of a list of the data file. Call it inside @().
    param([string]$Key)
    foreach ($item in @($script:AwCdxData[$Key])) { if ($item -is [string]) { $item } }
}

function Get-AwCdxValue {
    # Value at a path of nested tables (@('sandbox_workspace_write', 'network_access')), or $null.
    # Arrays are returned whole.
    param($Data, [string[]]$Path)
    $node = $Data
    foreach ($part in $Path) {
        if ($node -isnot [System.Collections.IDictionary] -or -not $node.Contains($part)) { return $null }
        $node = $node[$part]
    }
    return ,$node
}

function Test-AwCdxTrue {
    param($Value)
    return ($Value -is [bool] -and $Value)
}

function Test-AwCdxString {
    # True when Value is a string equal to Expected (ordinal, as Codex compares enum values).
    param($Value, [string]$Expected)
    return ($Value -is [string] -and [string]::Equals($Value, $Expected, [StringComparison]::Ordinal))
}

function Get-AwCdxSortedKeys {
    param($Map)
    if ($Map -isnot [System.Collections.IDictionary]) { return ,[string[]]@() }
    $keys = [string[]]@($Map.Keys)
    [Array]::Sort($keys, [StringComparer]::Ordinal)
    return ,$keys
}

function Get-AwCdxArtifacts {
    # Parsed Codex config files of the given scopes, in discovery order (active user config first).
    param($Ctx, [string[]]$Scopes)
    foreach ($a in @(Get-AwMemberValue $Ctx 'Codex')) {
        if ($null -eq $a -or $a.Data -isnot [System.Collections.IDictionary]) { continue }
        if ($Scopes -and $Scopes -notcontains [string]$a.Scope) { continue }
        $a
    }
}

function Get-AwCdxRequirements {
    # The parsed requirements.toml, or $null.
    param($Ctx)
    foreach ($a in @(Get-AwCdxArtifacts $Ctx @('managed'))) { return $a }
    return $null
}

function Get-AwCdxProfileName {
    # 'yolo' for <codex home>/yolo.config.toml.
    param($Artifact)
    $p = [string]$Artifact.Path
    $leaf = $p.Substring($p.LastIndexOfAny([char[]]@('\', '/')) + 1)
    if ($leaf.EndsWith('.config.toml', [StringComparison]::OrdinalIgnoreCase)) { return $leaf.Substring(0, $leaf.Length - 12) }
    return $leaf
}

function Get-AwCdxProjectFolder {
    # The folder whose .codex folder holds a project config file ('<folder>' for <folder>/.codex/config.toml).
    param($Artifact)
    return (Get-AwCdxDirectory (Get-AwCdxDirectory ([string]$Artifact.Path)))
}

function Get-AwCdxScopeLabel {
    # Who set a value, for evidence: 'user config', 'project config' (the root one), "project
    # config in 'packages/app'" (a nested one, relative to the root), 'system config'...
    param($Artifact, $Ctx)
    switch ([string]$Artifact.Scope) {
        'user'    { return 'user config' }
        'project' {
            $root = [string](Get-AwMemberValue $Ctx 'Root')
            if ($root) {
                $rel = Get-AwRelativePath -Path (Get-AwCdxProjectFolder $Artifact) -Base $root
                if ($null -ne $rel -and $rel -ne '.') {
                    if ($script:AwIsWindowsOS) { $rel = $rel.Replace('\', '/') }
                    return ("project config in '{0}'" -f (Format-AwCommandSnippet $rel 120))
                }
            }
            return 'project config'
        }
        'profile' { return ("profile '{0}'" -f (Get-AwCdxProfileName $Artifact)) }
        'managed' { return 'requirements.toml' }
        'system'  { return 'system config' }
    }
    return [string]$Artifact.Scope
}

function Format-AwCdxKey {
    # A TOML key part for evidence and locations: bare when it can be, quoted otherwise; cut and masked.
    param([string]$Name)
    if ($Name -cmatch '^[A-Za-z0-9_-]{1,64}$') { return $Name }
    return ('"' + (Format-AwCommandSnippet $Name 80) + '"')
}

function Get-AwCdxLineAt {
    # 1-based line of Index in Text. Newlines are counted by string methods on 16K-character
    # chunks (small enough to stay off the large object heap), not one loop iteration per line:
    # a file of a million blank lines would otherwise cost a million iterations per finding.
    # Text is never an argument of a .NET method (its Length is tested, not IsNullOrEmpty):
    # PowerShell 7.3+ logs the full text of those arguments, once per finding here.
    param([string]$Text, [int]$Index)
    if ($Index -le 0 -or $Text.Length -eq 0) { return 1 }
    if ($Index -gt $Text.Length) { $Index = $Text.Length }
    $line = 1
    for ($at = 0; $at -lt $Index; $at += 16384) {
        $chunk = $Text.Substring($at, [Math]::Min(16384, $Index - $at))
        $line += $chunk.Length - $chunk.Replace("`n", '').Length
    }
    return $line
}

function Test-AwCdxRoom {
    <#
    True while a rule may report one more finding of a kind in a file (Shown: a hashtable the check
    creates; kind and path -> count). At most AwCdxMaxPerFile, as for hooks, rules and tool
    overrides: a hostile file with thousands of entries would otherwise cost a line lookup each.
    The score does not change: the findings of one kind in one file share a severity, and a rule
    deducts at most twice its weight, which five findings already reach.
    #>
    param([hashtable]$Shown, $Artifact, [string]$Kind)
    $k = $Kind + '|' + [string]$Artifact.Path
    $n = 0
    if ($Shown.ContainsKey($k)) { $n = [int]$Shown[$k] }
    if ($n -ge $script:AwCdxMaxPerFile) { return $false }
    $Shown[$k] = $n + 1
    return $true
}

function Get-AwCdxLine {
    <#
    Best-effort line of a setting in a TOML file: the first of Headers that occurs (a table header
    or a dotted key), then the first Key after it. Without a header, Key at the start of a line.
    $null when nothing is found. Keys can come from the scanned file (paths of AW-CDX-005): a key
    longer than AwCdxMaxLineKey or with spaces around it is not searched, and the search after a
    header stops after AwCdxLineWindow characters, so a lookup cannot turn quadratic. Raw is tested
    by its Length, as in Get-AwCdxLineAt.
    #>
    param([string]$Raw, [string[]]$Headers, [string]$Key)
    if ($Raw.Length -eq 0) { return $null }
    if (-not [string]::IsNullOrEmpty($Key) -and ($Key.Length -gt $script:AwCdxMaxLineKey -or $Key.Trim().Length -ne $Key.Length)) { $Key = $null }
    $from = -1
    foreach ($h in @($Headers)) {
        if ([string]::IsNullOrEmpty($h)) { continue }
        $i = $Raw.IndexOf($h, [StringComparison]::Ordinal)
        if ($i -ge 0) { $from = $i; break }
    }
    if ($from -lt 0) {
        if ([string]::IsNullOrEmpty($Key)) { return $null }
        $m = [regex]::Match($Raw, '(?m)^(?>[ \t]*)' + [regex]::Escape($Key) + '(?>[ \t]*)=')
        if ($m.Success) { return (Get-AwCdxLineAt $Raw $m.Index) }
        $k = $Raw.IndexOf($Key, [StringComparison]::Ordinal)
        if ($k -ge 0) { return (Get-AwCdxLineAt $Raw $k) }
        return $null
    }
    if (-not [string]::IsNullOrEmpty($Key)) {
        $count = [Math]::Min($Raw.Length - $from, $script:AwCdxLineWindow)
        $k = $Raw.IndexOf($Key, $from, $count, [StringComparison]::Ordinal)
        if ($k -ge 0) { return (Get-AwCdxLineAt $Raw $k) }
    }
    return (Get-AwCdxLineAt $Raw $from)
}

function New-AwCdxFinding {
    param([string]$RuleId, $Artifact, [string]$Key, [string]$Evidence, [string]$Severity, [string[]]$Headers, [string]$LineKey)
    $location = @{ Path = $Artifact.Path; Line = (Get-AwCdxLine -Raw $Artifact.Raw -Headers $Headers -Key $LineKey); Key = $Key }
    if ($Severity) { return (New-AwFinding -RuleId $RuleId -Severity $Severity -Evidence $Evidence -Location $location) }
    New-AwFinding -RuleId $RuleId -Evidence $Evidence -Location $location
}

function Get-AwCdxDirectory {
    # Folder part of a discovered file path ('' when there is none).
    param([string]$Path)
    $i = $Path.LastIndexOfAny([char[]]@('\', '/'))
    if ($i -lt 0) { return '' }
    return $Path.Substring(0, $i)
}

# The layers of the last analyzed context (Get-AwCdxLayers), computed once per context.
$script:AwCdxLayerCache = $null

function Get-AwCdxLayers {
    <#
    The Codex config layers of a context, highest precedence first (config-basic): project config
    files > profile > user config > system config. Computed once per context:
    - Chains: for each project config file, the project files that apply in its folder, closest
      first. Codex loads every .codex/config.toml from the project root down to the working
      folder, and the closest wins (config-advanced). A project is trusted or not as a whole, and
      an untrusted project skips all its .codex layers, so a nested file never applies without
      the files above it.
    - Stacks: every combination of one project chain (or none: folders outside the project, or
      an untrusted project) over one user config file (one per Codex home, or none) and the system
      config. Each Codex home gives its own stacks: only one of them is active in a session.
    - ByPath: path -> indexes of the stacks that contain the file.
    Profiles apply only with --profile: Get-AwCdxProfileStacks builds their stacks.
    #>
    param($Ctx)
    # Assigned directly: an if expression would copy the array, and the cache would never match.
    $codexProp = $Ctx.PSObject.Properties['Codex']
    $codexValue = $null
    if ($codexProp) { $codexValue = $codexProp.Value }
    $cache = $script:AwCdxLayerCache
    if ($null -ne $cache -and [object]::ReferenceEquals($cache.Ctx, $Ctx) -and [object]::ReferenceEquals($cache.Codex, $codexValue)) { return $cache }
    $users = @(Get-AwCdxArtifacts $Ctx @('user'))
    $system = @(Get-AwCdxArtifacts $Ctx @('system')) | Select-Object -First 1
    $projects = @(Get-AwCdxArtifacts $Ctx @('project'))
    $folders = @($projects | ForEach-Object { Get-AwCdxProjectFolder $_ })
    $chains = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $projects.Count; $i++) {
        $members = New-Object System.Collections.ArrayList
        for ($j = 0; $j -lt $projects.Count; $j++) {
            if (Test-AwPathInside -Path $folders[$i] -Dir $folders[$j]) { [void]$members.Add([pscustomobject]@{ Length = $folders[$j].Length; Artifact = $projects[$j] }) }
        }
        # An ancestor folder is a prefix of its descendants: the longest folder is the closest.
        $sorted = @($members | Sort-Object -Property Length -Descending | ForEach-Object { $_.Artifact })
        [void]$chains.Add($sorted)
    }
    $lowers = New-Object System.Collections.ArrayList
    if ($users.Count -eq 0) { [void]$lowers.Add(@()) } else { foreach ($u in $users) { [void]$lowers.Add(@($u)) } }
    $stacks = New-Object System.Collections.ArrayList
    foreach ($low in $lowers) {
        $lower = @(@($low) + @($system | Where-Object { $null -ne $_ }))
        [void]$stacks.Add([pscustomobject]@{ Layers = $lower; Project = @() })
        foreach ($chain in $chains) { [void]$stacks.Add([pscustomobject]@{ Layers = @(@($chain) + $lower); Project = $chain }) }
    }
    $byPath = New-AwOrdinalHashtable
    for ($i = 0; $i -lt $stacks.Count; $i++) {
        foreach ($a in @($stacks[$i].Layers)) {
            $p = [string]$a.Path
            if (-not $byPath.ContainsKey($p)) { $byPath[$p] = New-Object System.Collections.Generic.List[int] }
            if (-not $byPath[$p].Contains($i)) { $byPath[$p].Add($i) }
        }
    }
    $script:AwCdxLayerCache = [pscustomobject]@{
        Ctx = $Ctx; Codex = $codexValue; Users = $users; System = $system; Projects = $projects
        Chains = $chains.ToArray(); Stacks = $stacks.ToArray(); ByPath = $byPath
    }
    return $script:AwCdxLayerCache
}

function Get-AwCdxStacks {
    <#
    Layer stacks (arrays, highest precedence first) in which a user, project or system file
    applies (Get-AwCdxLayers): a project file under the nested project files of the folders below
    it and over each user config file and the system config; a user file alone and under each
    project chain; the system config under all of them.
    #>
    param($Ctx, $Artifact)
    $layers = Get-AwCdxLayers $Ctx
    $out = New-Object System.Collections.ArrayList
    $p = [string]$Artifact.Path
    if ($layers.ByPath.ContainsKey($p)) {
        foreach ($i in $layers.ByPath[$p]) { [void]$out.Add($layers.Stacks[$i].Layers) }
    }
    return ,$out.ToArray()
}

function Get-AwCdxProfileStacks {
    <#
    Layer stacks, highest precedence first, in which a profile file applies (codex --profile <name>).
    Precedence (config-basic): project config > profile > user config > system config. The profile
    overlays the config.toml of its own Codex home and the system config: alone in the folders
    without project config, and under each project chain.
    #>
    param($Ctx, $Artifact)
    $layers = Get-AwCdxLayers $Ctx
    $dir = Get-AwCdxDirectory ([string]$Artifact.Path)
    $lower = New-Object System.Collections.ArrayList
    [void]$lower.Add($Artifact)
    foreach ($u in $layers.Users) {
        if ([string]::Equals((Get-AwCdxDirectory ([string]$u.Path)), $dir, [StringComparison]::OrdinalIgnoreCase)) { [void]$lower.Add($u); break }
    }
    if ($null -ne $layers.System) { [void]$lower.Add($layers.System) }
    $stacks = New-Object System.Collections.ArrayList
    [void]$stacks.Add($lower.ToArray())
    foreach ($chain in $layers.Chains) { [void]$stacks.Add(@(@($chain) + $lower.ToArray())) }
    return ,$stacks.ToArray()
}

function Get-AwCdxLayerStacks {
    # The stacks of Get-AwCdxProfileStacks for a profile file, of Get-AwCdxStacks otherwise.
    param($Ctx, $Artifact)
    if ($Artifact.Scope -eq 'profile') { return ,(Get-AwCdxProfileStacks $Ctx $Artifact) }
    return ,(Get-AwCdxStacks $Ctx $Artifact)
}

function Get-AwCdxStackValue {
    # The first file of a stack that sets Path: { Value; Artifact }, or $null.
    param($Stack, [string[]]$Path)
    foreach ($a in @($Stack)) {
        $v = Get-AwCdxValue -Data $a.Data -Path $Path
        if ($null -ne $v) { return [pscustomobject]@{ Value = $v; Artifact = $a } }
    }
    return $null
}

function Test-AwCdxEffective {
    # True when Artifact holds the value of Path that applies in Stack.
    param($Stack, $Artifact, [string[]]$Path)
    $eff = Get-AwCdxStackValue -Stack $Stack -Path $Path
    return ($null -ne $eff -and [object]::ReferenceEquals($eff.Artifact, $Artifact))
}

function Test-AwCdxProfilesSystem {
    <#
    True when a stack uses permission profiles (default_permissions and [permissions]), false when
    it uses the older sandbox settings (sandbox_mode and [sandbox_workspace_write]). The two do not
    compose (docs/permissions): Codex uses the older settings when sandbox_mode appears in any loaded
    config file, and default_permissions otherwise; a managed allowed_permission_profiles table makes
    it use permission profiles in every case. A stack that sets neither keeps the older settings.
    #>
    param($Stack, $Requirements)
    if ($null -ne $Requirements -and (Get-AwCdxValue $Requirements.Data @('allowed_permission_profiles')) -is [System.Collections.IDictionary]) { return $true }
    foreach ($a in @($Stack)) { if ((Get-AwCdxValue $a.Data @('sandbox_mode')) -is [string]) { return $false } }
    foreach ($a in @($Stack)) { if ((Get-AwCdxValue $a.Data @('default_permissions')) -is [string]) { return $true } }
    return $false
}

function Get-AwCdxFullAccess {
    # How a stack removes the sandbox: { Artifact; Key; Value } of the setting that applies when it
    # selects full access (the highest sandbox_mode with the older sandbox settings, the highest
    # default_permissions with permission profiles: Test-AwCdxProfilesSystem); $null otherwise.
    param($Stack, $Requirements)
    if (Test-AwCdxProfilesSystem $Stack $Requirements) {
        $key = 'default_permissions'
        $full = Get-AwCdxDataText 'fullAccessPermissions'
    } else {
        $key = 'sandbox_mode'
        $full = Get-AwCdxDataText 'fullAccessSandboxMode'
    }
    $eff = Get-AwCdxStackValue -Stack $Stack -Path @($key)
    if ($null -ne $eff -and (Test-AwCdxString $eff.Value $full)) { return [pscustomobject]@{ Artifact = $eff.Artifact; Key = $key; Value = $eff.Value } }
    return $null
}

function Test-AwCdxProxyOn {
    <#
    True when the network proxy runs in a stack: features.network_proxy = true, or
    features.network_proxy.enabled = true, in the highest file that sets it (a table without
    enabled does not start it: enabled defaults to off), or a managed
    experimental_network.enabled = true in requirements.toml.
    #>
    param($Stack, $Requirements)
    if ($null -ne $Requirements -and (Test-AwCdxTrue (Get-AwCdxValue $Requirements.Data @('experimental_network', 'enabled')))) { return $true }
    foreach ($a in @($Stack)) {
        $p = Get-AwCdxValue $a.Data @('features', 'network_proxy')
        if ($p -is [bool]) { return $p }
        if ($p -is [System.Collections.IDictionary] -and $p['enabled'] -is [bool]) { return [bool]$p['enabled'] }
    }
    return $false
}

function Get-AwCdxHooksFlag {
    # The hooks feature flag that applies in a stack: { Value; Key; Artifact } of the highest file
    # that sets features.hooks (or its deprecated alias features.codex_hooks), or $null. Hooks are
    # on when no file sets it (hooks, learn.chatgpt.com).
    param($Stack)
    foreach ($l in @($Stack)) {
        foreach ($k in @('hooks', 'codex_hooks')) {
            $flag = Get-AwCdxValue $l.Data @('features', $k)
            if ($flag -is [bool]) { return [pscustomobject]@{ Value = [bool]$flag; Key = ('features.' + $k); Artifact = $l } }
        }
    }
    return $null
}

function Test-AwCdxForbidden {
    # True when requirements.toml restricts List (an array of allowed values) and Value is not in it.
    param($Requirements, [string]$List, [string]$Value)
    if ($null -eq $Requirements) { return $false }
    $allowed = Get-AwCdxValue $Requirements.Data @($List)
    if ($allowed -isnot [System.Array]) { return $false }
    foreach ($x in $allowed) { if (Test-AwCdxString $x $Value) { return $false } }
    return $true
}

function Test-AwCdxProfileForbidden {
    # True when requirements.toml has an allowed_permission_profiles table that does not allow Name.
    param($Requirements, [string]$Name)
    if ($null -eq $Requirements) { return $false }
    $table = Get-AwCdxValue $Requirements.Data @('allowed_permission_profiles')
    if ($table -isnot [System.Collections.IDictionary]) { return $false }
    return -not ($table.Contains($Name) -and (Test-AwCdxTrue $table[$Name]))
}

function Get-AwCdxBroadPath {
    # Why a writable or trusted path is too broad ('the home directory', 'a drive root'...), or $null.
    param([string]$Path, $Ctx)
    if ([string]::IsNullOrEmpty($Path) -or $Path.Length -gt $script:AwCdxMaxPathLength) { return $null }
    $p = $Path.Trim()
    if ($p -eq '') { return $null }
    if (@(Get-AwCdxDataList 'rootPathTokens') -ccontains $p) { return 'the file system root' }
    $n = $p.TrimEnd([char[]]@('\', '/'))
    if ($n -eq '') { return 'the file system root' }
    if ($n -match '^[A-Za-z]:$') { return 'a drive root' }
    if ($n -match '^(\\\\|//)[^\\/]+([\\/][^\\/]+)?$') { return 'a network share root' }
    foreach ($t in @(Get-AwCdxDataList 'homePathTokens')) {
        if ([string]::Equals($n, $t, [StringComparison]::OrdinalIgnoreCase)) { return 'the home directory' }
    }
    if ($n -match '^(?i)([A-Za-z]:[\\/]Users|/home|/Users)$') { return 'the folder of all user profiles' }
    if ($n -match '^(?i)([A-Za-z]:[\\/]Users|/home|/Users)[\\/][^\\/]+$' -or $n -ceq '/root') { return 'the home directory' }
    $userProfile = [string](Get-AwMemberValue $Ctx 'UserProfile')
    if ($userProfile -and [string]::Equals($n.Replace('/', '\'), $userProfile.TrimEnd([char[]]@('\', '/')).Replace('/', '\'), [StringComparison]::OrdinalIgnoreCase)) {
        return 'the home directory'
    }
    return $null
}

function Test-AwCdxLiteralSecret {
    # True for a value stored in a secret key that is a literal secret (not empty, short, a reference or a placeholder).
    param($Value)
    if ($Value -isnot [string]) { return $false }
    $v = $Value.Trim()
    if ($v.Length -lt 8) { return $false }
    if (Test-AwMcpReference $v) { return $false }
    if (Test-AwMcpPlaceholder $v) { return $false }
    return $true
}

function Get-AwCdxMcpContainers {
    # Tables that hold MCP server settings: mcp_servers.<id> and plugins.<plugin>.mcp_servers.<id>,
    # as { Prefix; Server }, in a stable order.
    param($Data)
    $servers = Get-AwCdxValue $Data @('mcp_servers')
    foreach ($id in (Get-AwCdxSortedKeys $servers)) {
        if ($servers[$id] -is [System.Collections.IDictionary]) { [pscustomobject]@{ Prefix = 'mcp_servers.' + (Format-AwCdxKey $id); Server = $servers[$id]; Header = 'mcp_servers.' + $id } }
    }
    $plugins = Get-AwCdxValue $Data @('plugins')
    foreach ($plugin in (Get-AwCdxSortedKeys $plugins)) {
        $inner = Get-AwCdxValue $plugins @($plugin, 'mcp_servers')
        foreach ($id in (Get-AwCdxSortedKeys $inner)) {
            if ($inner[$id] -is [System.Collections.IDictionary]) {
                [pscustomobject]@{ Prefix = ('plugins.{0}.mcp_servers.{1}' -f (Format-AwCdxKey $plugin), (Format-AwCdxKey $id)); Server = $inner[$id]; Header = ('plugins.{0}.mcp_servers.{1}' -f $plugin, $id) }
            }
        }
    }
}

function Get-AwCdxHookHandlers {
    # Hook handlers that run a command or call an MCP tool: { Event; Type; Text }. Shape (hooks.json
    # and inline [hooks] tables): hooks.<Event> = array of { matcher; hooks = array of handlers }.
    param($Hooks)
    if ($Hooks -isnot [System.Collections.IDictionary]) { return }
    $fields = @(Get-AwCdxDataList 'hookCommandFields')
    foreach ($hookEvent in (Get-AwCdxSortedKeys $Hooks)) {
        $groups = $Hooks[$hookEvent]
        if ($groups -isnot [System.Array]) { continue }
        foreach ($group in $groups) {
            if ($group -isnot [System.Collections.IDictionary]) { continue }
            $handlers = @(if ($group['hooks'] -is [System.Array]) { $group['hooks'] } else { $group })
            foreach ($h in $handlers) {
                if ($h -isnot [System.Collections.IDictionary]) { continue }
                $type = if ($h['type'] -is [string]) { $h['type'] } else { 'command' }
                if ($type -ceq 'mcp_tool') {
                    $server = if ($h['server'] -is [string]) { $h['server'] } else { '?' }
                    $tool = if ($h['tool'] -is [string]) { $h['tool'] } else { '?' }
                    [pscustomobject]@{ Event = $hookEvent; Type = 'mcp_tool'; Text = ($server + '/' + $tool) }
                    continue
                }
                if ($type -cne 'command') { continue }
                $text = $null
                foreach ($field in $fields) {
                    if ($h[$field] -is [string] -and $h[$field].Trim() -ne '') { $text = $h[$field]; break }
                }
                if ($text) { [pscustomobject]@{ Event = $hookEvent; Type = 'command'; Text = $text } }
            }
        }
    }
}

function Get-AwCdxAllowRules {
    <#
    prefix_rule() calls of a Starlark rules file whose decision allows the command (decision =
    "allow", or no decision: allow is the default): { Index; Pattern; Explicit }. The file is not
    evaluated: calls are found by name, outside comments, and read up to the next call.
    #>
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return }
    $fn = Get-AwCdxDataText 'ruleFunction'
    if (-not $fn) { return }
    $restrictive = @(Get-AwCdxDataList 'restrictiveDecisions')
    $starts = New-Object System.Collections.Generic.List[int]
    # One pass: the line start and the first '#' of the current line are tracked incrementally,
    # so a long line full of decoys stays linear. Occurrences examined are capped as well.
    $scanned = 0
    $commentAt = -1
    $seen = 0
    $i = $Text.IndexOf($fn, [StringComparison]::Ordinal)
    while ($i -ge 0 -and $starts.Count -lt $script:AwCdxMaxRuleCalls -and $seen -lt 25 * $script:AwCdxMaxRuleCalls) {
        $seen++
        $from = $scanned
        if ($i -gt $scanned) {
            $nl = $Text.LastIndexOf("`n", $i - 1, $i - $scanned, [StringComparison]::Ordinal)
            if ($nl -ge 0) { $commentAt = -1; $from = $nl + 1 }
            if ($commentAt -lt 0 -and $i -gt $from) { $commentAt = $Text.IndexOf([char]'#', $from, $i - $from) }
        }
        $scanned = $i
        $j = $i + $fn.Length
        # Blanks before '(' are matched on slices of 256 characters, never on the whole Text:
        # PowerShell 7.3+ logs every .NET method call made from script with the full text of its
        # string arguments, so one call per occurrence on a 2 MB file took seconds. A run of blanks
        # that fills its slice goes on in the next one, so the end of the run is the same.
        while ($j -lt $Text.Length -and ($Text[$j] -ceq ' ' -or $Text[$j] -ceq "`t")) {
            $slice = [Math]::Min(256, $Text.Length - $j)
            $run = $script:AwCdxRxBlank.Match($Text.Substring($j, $slice)).Length
            $j += $run
            if ($run -lt $slice) { break }
        }
        $boundary = ($i -eq 0 -or -not ([char]::IsLetterOrDigit($Text[$i - 1]) -or $Text[$i - 1] -eq '_'))
        if ($j -lt $Text.Length -and $Text[$j] -eq '(' -and $commentAt -lt 0 -and $boundary) { $starts.Add($i) }
        $i = $Text.IndexOf($fn, $i + $fn.Length, [StringComparison]::Ordinal)
    }
    for ($k = 0; $k -lt $starts.Count; $k++) {
        $from = $starts[$k]
        $to = if ($k + 1 -lt $starts.Count) { $starts[$k + 1] } else { $Text.Length }
        if ($to - $from -gt 4096) { $to = $from + 4096 }
        $segment = $Text.Substring($from, $to - $from)
        $d = [regex]::Match($segment, '(?<![A-Za-z0-9_])decision(?>[ \t\r\n]*)=(?>[ \t\r\n]*)(?:"(?<d>[^"\r\n]{0,40})"|''(?<d>[^''\r\n]{0,40})'')')
        if ($d.Success -and ($restrictive -ccontains $d.Groups['d'].Value -or $d.Groups['d'].Value -cne 'allow')) { continue }
        $pm = [regex]::Match($segment, '(?<![A-Za-z0-9_])pattern(?>[ \t\r\n]*)=(?>[ \t\r\n]*)\[(?<p>[^\]]{0,300})\]')
        $pattern = if ($pm.Success) { ($pm.Groups['p'].Value -replace '\s+', ' ').Trim() } else { '?' }
        [pscustomobject]@{ Index = $from; Pattern = $pattern; Explicit = $d.Success }
    }
}

# ---------------------------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------------------------

Register-AwRule -Id 'AW-CDX-001' -Title 'Codex runs commands without a sandbox' `
    -Severity 'high' -Category 'sandbox-network' -Harness 'codex' `
    -Description 'sandbox_mode = "danger-full-access", or default_permissions = ":danger-full-access", turns the Codex sandbox off: every command the agent runs can read and write wherever the user can and reach the network, and web search then defaults to live results. The documentation reserves it for cases where that broad access is intended. A prompt injection in a file, a web page or a tool result can then run any command on the machine. User, project (the .codex/config.toml of the root and of the folders below it) and system config files and requirements.toml are checked; profiles are checked by AW-CDX-014. The finding is info when requirements.toml does not allow the value (allowed_sandbox_modes or allowed_permission_profiles).' `
    -Fix 'Use sandbox_mode = "workspace-write" (or default_permissions = ":workspace") and grant extra folders or network access explicitly. Keep danger-full-access for a container or VM that is already isolated, and enforce the limit with allowed_sandbox_modes or allowed_permission_profiles in requirements.toml.' `
    -References @('OWASP-ASI05', 'OWASP-ASI02', $script:AwCdxDocs.Security, $script:AwCdxDocs.Permissions, $script:AwCdxDocs.Reference) `
    -Confidence 'high' -Check {
        param($Ctx)
        $req = Get-AwCdxRequirements $Ctx
        $fullMode = Get-AwCdxDataText 'fullAccessSandboxMode'
        $fullPerm = Get-AwCdxDataText 'fullAccessPermissions'
        foreach ($a in @(Get-AwCdxArtifacts $Ctx @('user', 'project', 'system', 'managed'))) {
            $label = Get-AwCdxScopeLabel $a $Ctx
            $mode = Get-AwCdxValue $a.Data @('sandbox_mode')
            if ($a.Scope -ne 'managed' -and (Test-AwCdxString $mode $fullMode)) {
                $ev = 'sandbox_mode = "{0}" ({1})' -f $mode, $label
                $sev = $null
                if (Test-AwCdxForbidden $req 'allowed_sandbox_modes' $mode) { $sev = 'info'; $ev += '; requirements.toml does not allow it (allowed_sandbox_modes)' }
                New-AwCdxFinding 'AW-CDX-001' $a 'sandbox_mode' $ev $sev $null 'sandbox_mode'
            }
            $perm = Get-AwCdxValue $a.Data @('default_permissions')
            if (Test-AwCdxString $perm $fullPerm) {
                $ev = 'default_permissions = "{0}" ({1})' -f $perm, $label
                $sev = $null
                if ($a.Scope -ne 'managed' -and (Test-AwCdxProfileForbidden $req $perm)) { $sev = 'info'; $ev += '; requirements.toml does not allow it (allowed_permission_profiles)' }
                New-AwCdxFinding 'AW-CDX-001' $a 'default_permissions' $ev $sev $null 'default_permissions'
            }
        }
    }

Register-AwRule -Id 'AW-CDX-002' -Title 'Codex never asks for approval' `
    -Severity 'medium' -Category 'approvals' -Harness 'codex' `
    -Description 'approval_policy = "never" disables the approval prompts: Codex never stops to ask before it runs a command, so nobody reviews an action before it happens. The sandbox still applies, which limits the damage. Combined with full access in the layers that apply (sandbox_mode = "danger-full-access", or default_permissions = ":danger-full-access" when no loaded config file sets sandbox_mode, which takes precedence over permission profiles), as the --yolo flag does, there is neither a sandbox nor an approval and the finding is critical. User, project and system config files are checked in the documented precedence: the project .codex/config.toml files from the project root down to the working folder (the closest wins) > user config > system config, each Codex home on its own; profiles are checked by AW-CDX-014. The finding is info when requirements.toml does not allow "never" (allowed_approval_policies).' `
    -Fix 'Use approval_policy = "on-request" (or a granular table that keeps the prompts you need), and never combine "never" with danger-full-access outside an isolated container or VM. Restrict the allowed values with allowed_approval_policies in requirements.toml.' `
    -References @('OWASP-ASI02', $script:AwCdxDocs.Security, $script:AwCdxDocs.Reference) `
    -Confidence 'high' -Check {
        param($Ctx)
        $req = Get-AwCdxRequirements $Ctx
        foreach ($a in @(Get-AwCdxArtifacts $Ctx @('user', 'project', 'system'))) {
            $v = Get-AwCdxValue $a.Data @('approval_policy')
            if (-not (Test-AwCdxString $v 'never')) { continue }
            $ev = 'approval_policy = "never" ({0})' -f (Get-AwCdxScopeLabel $a $Ctx)
            $sev = $null
            $combo = $null
            foreach ($stack in (Get-AwCdxStacks $Ctx $a)) {
                if (-not (Test-AwCdxEffective $stack $a @('approval_policy'))) { continue }
                $full = Get-AwCdxFullAccess $stack $req
                if ($null -eq $full) { continue }
                if ($full.Key -eq 'sandbox_mode' -and (Test-AwCdxForbidden $req 'allowed_sandbox_modes' $full.Value)) { continue }
                if ($full.Key -eq 'default_permissions' -and (Test-AwCdxProfileForbidden $req $full.Value)) { continue }
                $combo = $full
                break
            }
            if ($combo) {
                $sev = 'critical'
                $ev += '; with {0} = "{1}" ({2}): no sandbox and no approval' -f $combo.Key, $combo.Value, (Get-AwCdxScopeLabel $combo.Artifact $Ctx)
            }
            if (Test-AwCdxForbidden $req 'allowed_approval_policies' 'never') { $sev = 'info'; $ev += '; requirements.toml does not allow it (allowed_approval_policies)' }
            New-AwCdxFinding 'AW-CDX-002' $a 'approval_policy' $ev $sev $null 'approval_policy'
        }
    }

Register-AwRule -Id 'AW-CDX-003' -Title 'Codex workspace-write sandbox has network access' `
    -Severity 'medium' -Category 'sandbox-network' -Harness 'codex' `
    -Description 'sandbox_workspace_write.network_access = true allows outbound network access inside the workspace-write sandbox, which keeps it off by default. Every command the agent runs without a prompt can then download code or send workspace content, credentials included, to any host. The rule checks user, project and system config files, in the precedence of AW-CDX-002 (nested project config > project config > user config > system config), and is silent when the sandbox mode that applies is read-only or danger-full-access (AW-CDX-001), and when the layers use permission profiles instead: default_permissions is set and no loaded config file sets sandbox_mode, or requirements.toml has allowed_permission_profiles. The two systems do not compose, so Codex then ignores [sandbox_workspace_write]; the network of a permission profile is checked by AW-CDX-004.' `
    -Fix 'Remove network_access (default false) and approve network access per command, or use a permission profile with the network proxy and an allowlist of domains (permissions.<name>.network.domains).' `
    -References @('OWASP-ASI02', 'OWASP-ASI05', $script:AwCdxDocs.Security, $script:AwCdxDocs.Permissions, $script:AwCdxDocs.Reference) `
    -Confidence 'high' -Check {
        param($Ctx)
        $req = Get-AwCdxRequirements $Ctx
        $path = @('sandbox_workspace_write', 'network_access')
        foreach ($a in @(Get-AwCdxArtifacts $Ctx @('user', 'project', 'system'))) {
            if (-not (Test-AwCdxTrue (Get-AwCdxValue $a.Data $path))) { continue }
            $applies = $false
            foreach ($stack in (Get-AwCdxStacks $Ctx $a)) {
                if (-not (Test-AwCdxEffective $stack $a $path)) { continue }
                if (Test-AwCdxProfilesSystem $stack $req) { continue }
                $mode = Get-AwCdxStackValue $stack @('sandbox_mode')
                if ($null -eq $mode -or (Test-AwCdxString $mode.Value 'workspace-write')) { $applies = $true; break }
            }
            if (-not $applies) { continue }
            New-AwCdxFinding 'AW-CDX-003' $a 'sandbox_workspace_write.network_access' ('sandbox_workspace_write.network_access = true ({0})' -f (Get-AwCdxScopeLabel $a $Ctx)) `
                $null @('[sandbox_workspace_write]', 'sandbox_workspace_write') 'network_access'
        }
    }

Register-AwRule -Id 'AW-CDX-004' -Title 'Codex permission profile allows unrestricted network access' `
    -Severity 'medium' -Category 'sandbox-network' -Harness 'codex' `
    -Description 'Flags permission profiles ([permissions.<name>], a beta feature) whose network is enabled while the network proxy is off, with mode = "full", or with the global "*" = "allow" domain rule, and a network proxy ([features.network_proxy]) that allows "*". network.enabled = true does not start the proxy: without features.network_proxy = true (or features.network_proxy.enabled = true) in the layers where the profile applies, or a managed experimental_network.enabled = true, the documentation says commands have direct, unrestricted network access and the profile domain rules are not enforced. The documentation keeps the global allow rule for cases where public network access is intended; while the network proxy is active, the other rules limit sandboxed commands to the listed domains. The documentation lists the limited and full modes without describing what limited blocks, so confidence is medium.' `
    -Fix 'Turn the network proxy on (features.network_proxy = true), leave mode at "limited" and list the domains the commands need under permissions.<name>.network.domains (deny rules win), instead of "*" = "allow".' `
    -References @('OWASP-ASI02', $script:AwCdxDocs.Permissions, $script:AwCdxDocs.Reference) `
    -Confidence 'medium' -Check {
        param($Ctx)
        $req = Get-AwCdxRequirements $Ctx
        $shown = @{}
        foreach ($a in @(Get-AwCdxArtifacts $Ctx @('user', 'project', 'profile', 'system'))) {
            $label = Get-AwCdxScopeLabel $a $Ctx
            $perms = Get-AwCdxValue $a.Data @('permissions')
            if ($perms -isnot [System.Collections.IDictionary]) { continue }
            # The layers where this file applies with the network proxy off: they do not depend on
            # the permission profile, so they are found once per file.
            $proxyOff = @(foreach ($stack in (Get-AwCdxLayerStacks $Ctx $a)) { if (-not (Test-AwCdxProxyOn $stack $req)) { ,$stack } })
            foreach ($name in (Get-AwCdxSortedKeys $perms)) {
                $net = Get-AwCdxValue $perms @($name, 'network')
                if ($net -isnot [System.Collections.IDictionary] -or -not (Test-AwCdxTrue $net['enabled'])) { continue }
                $prefix = 'permissions.' + (Format-AwCdxKey $name) + '.network'
                $headers = @("[permissions.$name.network]", "permissions.$name.network", "permissions.$name")
                # Network on, proxy off: direct access without domain rules, in some layers where the profile applies.
                # Once the file has its 20 findings of this kind, the layers are not searched again.
                $direct = $false
                if ([int]$shown['proxy|' + [string]$a.Path] -lt $script:AwCdxMaxPerFile) {
                    foreach ($stack in $proxyOff) {
                        if (Test-AwCdxEffective $stack $a @('permissions', $name, 'network', 'enabled')) { $direct = $true; break }
                    }
                }
                if ($direct -and (Test-AwCdxRoom $shown $a 'proxy')) {
                    New-AwCdxFinding 'AW-CDX-004' $a ($prefix + '.enabled') ('{0}.enabled = true and the network proxy is off: commands have direct, unrestricted network access, and the domain rules are not enforced ({1})' -f $prefix, $label) $null $headers 'enabled'
                }
                if ((Test-AwCdxString $net['mode'] 'full') -and (Test-AwCdxRoom $shown $a 'mode')) {
                    New-AwCdxFinding 'AW-CDX-004' $a ($prefix + '.mode') ('{0}.mode = "full" with the network enabled ({1})' -f $prefix, $label) $null $headers 'mode'
                }
                $domains = $net['domains']
                if ($domains -is [System.Collections.IDictionary] -and $domains.Contains('*') -and (Test-AwCdxString $domains['*'] 'allow') -and (Test-AwCdxRoom $shown $a 'domains')) {
                    New-AwCdxFinding 'AW-CDX-004' $a ($prefix + '.domains') ('{0}.domains."*" = "allow": every public host ({1})' -f $prefix, $label) $null $headers '"*"'
                }
            }
            $proxy = Get-AwCdxValue $a.Data @('features', 'network_proxy')
            if ($proxy -is [System.Collections.IDictionary]) {
                $domains = $proxy['domains']
                if ($domains -is [System.Collections.IDictionary] -and $domains.Contains('*') -and (Test-AwCdxString $domains['*'] 'allow')) {
                    New-AwCdxFinding 'AW-CDX-004' $a 'features.network_proxy.domains' ('features.network_proxy.domains."*" = "allow": every public host ({0})' -f $label) `
                        $null @('[features.network_proxy.domains]', '[features.network_proxy]', 'network_proxy') '"*"'
                }
            }
        }
    }

Register-AwRule -Id 'AW-CDX-005' -Title 'Codex can write to a very broad folder' `
    -Severity 'high' -Category 'sandbox-network' -Harness 'codex' `
    -Description 'Flags writable roots and permission profile entries that give sandboxed commands write access to the home directory, a profile folder, a drive root, a network share root or the file system root: sandbox_workspace_write.writable_roots, permissions.<name>.filesystem entries set to "write" (including ":root" and scoped "." entries), and broad permissions.<name>.workspace_roots in a profile that can write its workspace roots. The agent can then change credentials, and shell startup files, scripts and package manager hooks (targets the documentation calls sensitive), outside the project and without a prompt. Only .git, .codex, .agents and .aws folders stay protected inside writable roots.' `
    -Fix 'List only the folders the task needs (a build or cache folder of the project, for example), and keep the home directory and drive roots read-only.' `
    -References @('OWASP-ASI02', 'OWASP-ASI05', $script:AwCdxDocs.Permissions, $script:AwCdxDocs.Security, $script:AwCdxDocs.Reference) `
    -Confidence 'high' -Check {
        param($Ctx)
        $workspaceProfile = Get-AwCdxDataText 'workspaceProfile'
        $rootsToken = Get-AwCdxDataText 'workspaceRootsToken'
        $shown = @{}
        foreach ($a in @(Get-AwCdxArtifacts $Ctx @('user', 'project', 'profile', 'system'))) {
            $label = Get-AwCdxScopeLabel $a $Ctx
            $roots = Get-AwCdxValue $a.Data @('sandbox_workspace_write', 'writable_roots')
            if ($roots -is [System.Array]) {
                foreach ($r in $roots) {
                    if ($r -isnot [string]) { continue }
                    $why = Get-AwCdxBroadPath -Path $r -Ctx $Ctx
                    if ($why -and (Test-AwCdxRoom $shown $a 'roots')) {
                        New-AwCdxFinding 'AW-CDX-005' $a 'sandbox_workspace_write.writable_roots' ("sandbox_workspace_write.writable_roots contains '{0}' ({1}, {2})" -f (Format-AwCommandSnippet $r 120), $why, $label) `
                            $null @('[sandbox_workspace_write]', 'sandbox_workspace_write') 'writable_roots'
                    }
                }
            }
            $perms = Get-AwCdxValue $a.Data @('permissions')
            foreach ($name in (Get-AwCdxSortedKeys $perms)) {
                $permProfile = $perms[$name]
                if ($permProfile -isnot [System.Collections.IDictionary]) { continue }
                $prefix = 'permissions.' + (Format-AwCdxKey $name)
                $fs = $permProfile['filesystem']
                $writesRoots = Test-AwCdxString $permProfile['extends'] $workspaceProfile
                foreach ($entry in (Get-AwCdxSortedKeys $fs)) {
                    $value = $fs[$entry]
                    $writes = (Test-AwCdxString $value 'write') -or ($value -is [System.Collections.IDictionary] -and (Test-AwCdxString $value['.'] 'write'))
                    if (-not $writes) { continue }
                    if ($entry -ceq $rootsToken) { $writesRoots = $true; continue }
                    $why = Get-AwCdxBroadPath -Path $entry -Ctx $Ctx
                    if ($why -and (Test-AwCdxRoom $shown $a 'filesystem')) {
                        New-AwCdxFinding 'AW-CDX-005' $a ($prefix + '.filesystem') ('{0}.filesystem."{1}" = "write" ({2}, {3})' -f $prefix, (Format-AwCommandSnippet $entry 120), $why, $label) `
                            $null @("[permissions.$name.filesystem]", "permissions.$name.filesystem") $entry
                    }
                }
                if (-not $writesRoots) { continue }
                $ws = $permProfile['workspace_roots']
                foreach ($entry in (Get-AwCdxSortedKeys $ws)) {
                    if (-not (Test-AwCdxTrue $ws[$entry])) { continue }
                    $why = Get-AwCdxBroadPath -Path $entry -Ctx $Ctx
                    if ($why -and (Test-AwCdxRoom $shown $a 'workspace_roots')) {
                        New-AwCdxFinding 'AW-CDX-005' $a ($prefix + '.workspace_roots') ('{0}.workspace_roots."{1}" = true in a profile that writes its workspace roots ({2}, {3})' -f $prefix, (Format-AwCommandSnippet $entry 120), $why, $label) `
                            $null @("[permissions.$name.workspace_roots]", "permissions.$name.workspace_roots") $entry
                    }
                }
            }
        }
    }

Register-AwRule -Id 'AW-CDX-006' -Title 'Codex network proxy safety check turned off' `
    -Severity 'medium' -Category 'sandbox-network' -Harness 'codex' `
    -Description 'Flags the dangerously_* network options set to true, under [features.network_proxy] or permissions.<name>.network (the names are in src/Data/codex.json). dangerously_allow_all_unix_sockets bypasses the Unix socket allowlist, a broad local escape hatch (the Docker socket, for example, controls the host). dangerously_allow_non_loopback_proxy lets the sandbox proxy listen beyond localhost, where other machines can reach it. Both default to false: the documentation keeps the first for tightly controlled environments and says to leave the second unset for ordinary local development.' `
    -Fix 'Remove the dangerously_* options. Allow the Unix sockets the commands need one by one under unix_sockets, and keep the proxy on loopback addresses.' `
    -References @('OWASP-ASI05', 'OWASP-ASI02', $script:AwCdxDocs.Permissions, $script:AwCdxDocs.Reference) `
    -Confidence 'high' -Check {
        param($Ctx)
        $options = @(Get-AwCdxDataList 'dangerousNetworkOptions')
        $shown = @{}
        foreach ($a in @(Get-AwCdxArtifacts $Ctx @('user', 'project', 'profile', 'system'))) {
            $label = Get-AwCdxScopeLabel $a $Ctx
            $proxy = Get-AwCdxValue $a.Data @('features', 'network_proxy')
            if ($proxy -is [System.Collections.IDictionary]) {
                foreach ($o in $options) {
                    if (Test-AwCdxTrue $proxy[$o]) {
                        New-AwCdxFinding 'AW-CDX-006' $a ('features.network_proxy.' + $o) ('features.network_proxy.{0} = true ({1})' -f $o, $label) `
                            $null @('[features.network_proxy]', 'network_proxy') $o
                    }
                }
            }
            $perms = Get-AwCdxValue $a.Data @('permissions')
            foreach ($name in (Get-AwCdxSortedKeys $perms)) {
                $net = Get-AwCdxValue $perms @($name, 'network')
                if ($net -isnot [System.Collections.IDictionary]) { continue }
                $prefix = 'permissions.' + (Format-AwCdxKey $name) + '.network'
                foreach ($o in $options) {
                    if ((Test-AwCdxTrue $net[$o]) -and (Test-AwCdxRoom $shown $a $o)) {
                        New-AwCdxFinding 'AW-CDX-006' $a ($prefix + '.' + $o) ('{0}.{1} = true ({2})' -f $prefix, $o, $label) `
                            $null @("[permissions.$name.network]", "permissions.$name.network") $o
                    }
                }
            }
        }
    }

Register-AwRule -Id 'AW-CDX-007' -Title 'Codex passes every environment variable, secrets included, to commands' `
    -Severity 'low' -Category 'secrets' -Harness 'codex' `
    -Description 'shell_environment_policy.inherit = "all" gives every command the agent runs the whole environment of the Codex process. ignore_default_excludes defaults to true, which keeps the variables whose names contain KEY, SECRET or TOKEN, so without exclude filters (filters entries set to "exclude", or the legacy exclude list) or an include allowlist (filters entries set to "include", or include_only), API keys and tokens reach every command and anything a prompt injection makes it print. The rule checks user, project, profile and system config files and is silent when ignore_default_excludes = false or a filter restricts the variables.' `
    -Fix 'Use inherit = "core" (or "none"), set ignore_default_excludes = false, and add [shell_environment_policy.filters] entries that exclude the secrets the commands do not need.' `
    -References @('OWASP-ASI03', $script:AwCdxDocs.Advanced, $script:AwCdxDocs.Reference) `
    -Confidence 'high' -Check {
        param($Ctx)
        foreach ($a in @(Get-AwCdxArtifacts $Ctx @('user', 'project', 'profile', 'system'))) {
            $policy = Get-AwCdxValue $a.Data @('shell_environment_policy')
            if ($policy -isnot [System.Collections.IDictionary] -or -not (Test-AwCdxString $policy['inherit'] 'all')) { continue }
            $ignore = $policy['ignore_default_excludes']
            if ($ignore -is [bool] -and -not $ignore) { continue }
            $restricted = $false
            foreach ($listKey in @('exclude', 'include_only')) {
                $list = $policy[$listKey]
                if ($list -is [System.Array] -and @($list | Where-Object { $_ -is [string] -and $_ -ne '' }).Count -gt 0) { $restricted = $true }
            }
            $filters = $policy['filters']
            foreach ($k in (Get-AwCdxSortedKeys $filters)) {
                if ((Test-AwCdxString $filters[$k] 'exclude') -or (Test-AwCdxString $filters[$k] 'include')) { $restricted = $true }
            }
            if ($restricted) { continue }
            $defaults = if ($ignore -is [bool]) { 'ignore_default_excludes = true' } else { 'ignore_default_excludes not set (default true)' }
            New-AwCdxFinding 'AW-CDX-007' $a 'shell_environment_policy.inherit' ('shell_environment_policy.inherit = "all", no exclude or include filter, {0} ({1})' -f $defaults, (Get-AwCdxScopeLabel $a $Ctx)) `
                $null @('[shell_environment_policy]', 'shell_environment_policy') 'inherit'
        }
    }

Register-AwRule -Id 'AW-CDX-008' -Title 'Codex MCP tools run without approval' `
    -Severity 'high' -Category 'approvals' -Harness 'codex' `
    -Description 'Flags MCP servers whose default_tools_approval_mode is "approve" (every tool of the server, high) and tools whose approval_mode is "approve" (one tool, medium), under mcp_servers.<id> and plugins.<plugin>.mcp_servers.<id>. Tool calls then run without a prompt, so a prompt injection can make the agent write, send or delete data through them. The documentation lists the values auto, prompt, writes and approve and describes only writes (it prompts for tools not marked read-only); auto is the built-in fallback. It also says that a tool call that advertises a destructive annotation always requires approval, unless the tool also advertises a read annotation, without saying whether approve overrides that. That approve skips the prompt is inferred from its name and from the documentation example, so confidence is medium.' `
    -Fix 'Use default_tools_approval_mode = "writes" (or "prompt"), and set approval_mode = "approve" only on read-only tools you trust, never on tools that write, send or delete.' `
    -References @('OWASP-ASI02', $script:AwCdxDocs.Mcp, $script:AwCdxDocs.Reference) `
    -Confidence 'medium' -Check {
        param($Ctx)
        $approve = Get-AwCdxDataText 'autoApproveMode'
        $room = @{}
        foreach ($a in @(Get-AwCdxArtifacts $Ctx @('user', 'project', 'profile', 'system'))) {
            $label = Get-AwCdxScopeLabel $a $Ctx
            $shown = 0
            foreach ($c in @(Get-AwCdxMcpContainers $a.Data)) {
                if ((Test-AwCdxString $c.Server['default_tools_approval_mode'] $approve) -and (Test-AwCdxRoom $room $a 'server')) {
                    New-AwCdxFinding 'AW-CDX-008' $a ($c.Prefix + '.default_tools_approval_mode') ('{0}.default_tools_approval_mode = "{1}": every tool of the server runs without a prompt ({2})' -f $c.Prefix, $approve, $label) `
                        $null @($c.Header) 'default_tools_approval_mode'
                }
                $tools = $c.Server['tools']
                foreach ($t in (Get-AwCdxSortedKeys $tools)) {
                    if ($shown -ge $script:AwCdxMaxPerFile) { break }
                    $tool = $tools[$t]
                    if ($tool -isnot [System.Collections.IDictionary] -or -not (Test-AwCdxString $tool['approval_mode'] $approve)) { continue }
                    $shown++
                    $key = $c.Prefix + '.tools.' + (Format-AwCdxKey $t) + '.approval_mode'
                    New-AwCdxFinding 'AW-CDX-008' $a $key ('{0} = "{1}" ({2})' -f $key, $approve, $label) 'medium' @($c.Header + '.tools.' + $t) 'approval_mode'
                }
            }
        }
    }

Register-AwRule -Id 'AW-CDX-009' -Title 'Secret stored in a Codex config file' `
    -Severity 'high' -Category 'secrets' -Harness 'codex' `
    -Description 'Flags literal values of mcp_servers.<id>.oauth.client_secret (the documentation says it is stored in the configuration and asks to keep the file private and out of version control) and model_providers.<id>.experimental_bearer_token (a direct bearer token, discouraged in favor of env_key). Anyone, or any agent, tool or backup, that reads the file gets the secret. The finding is critical in the project .codex/config.toml, which is usually committed. Values are always masked. Static MCP headers (http_headers) and env values are checked by AW-MCP-002.' `
    -Fix 'Remove the value and rotate the secret. Use env_key for model providers, bearer_token_env_var or env_http_headers for MCP servers, and keep any client secret in the user config file only, out of version control.' `
    -References @('OWASP-ASI03', $script:AwCdxDocs.Mcp, $script:AwCdxDocs.Reference) `
    -Confidence 'high' -Check {
        param($Ctx)
        $shown = @{}
        foreach ($a in @(Get-AwCdxArtifacts $Ctx @('user', 'project', 'profile', 'system', 'managed'))) {
            $label = Get-AwCdxScopeLabel $a $Ctx
            $sev = if ($a.Scope -eq 'project') { 'critical' } else { $null }
            $servers = Get-AwCdxValue $a.Data @('mcp_servers')
            foreach ($id in (Get-AwCdxSortedKeys $servers)) {
                $v = Get-AwCdxValue $servers @($id, 'oauth', 'client_secret')
                if (-not (Test-AwCdxLiteralSecret $v) -or -not (Test-AwCdxRoom $shown $a 'oauth')) { continue }
                $key = 'mcp_servers.' + (Format-AwCdxKey $id) + '.oauth.client_secret'
                New-AwCdxFinding 'AW-CDX-009' $a $key ('{0} = {1} ({2})' -f $key, (Hide-AwSecret -Value $v.Trim()), $label) $sev @("mcp_servers.$id.oauth", "mcp_servers.$id") 'client_secret'
            }
            $providers = Get-AwCdxValue $a.Data @('model_providers')
            foreach ($id in (Get-AwCdxSortedKeys $providers)) {
                $v = Get-AwCdxValue $providers @($id, 'experimental_bearer_token')
                if (-not (Test-AwCdxLiteralSecret $v) -or -not (Test-AwCdxRoom $shown $a 'provider')) { continue }
                $key = 'model_providers.' + (Format-AwCdxKey $id) + '.experimental_bearer_token'
                New-AwCdxFinding 'AW-CDX-009' $a $key ('{0} = {1} ({2})' -f $key, (Hide-AwSecret -Value $v.Trim()), $label) $sev @("model_providers.$id") 'experimental_bearer_token'
            }
        }
    }

Register-AwRule -Id 'AW-CDX-010' -Title 'Codex trusts a folder that is too broad' `
    -Severity 'high' -Category 'approvals' -Harness 'codex' `
    -Description 'projects.<path>.trust_level = "trusted" makes Codex load the project .codex/ layers of that folder: its config, which can change the sandbox, the approvals and the MCP servers, its hooks and its rules. Trusting the home directory, a profile folder, a drive root or the file system root extends that trust to whatever is placed there, and a session started there can work on every repository and credential below it. Whether trust also covers sub-folders is not documented, so confidence is medium. User config and profile files are checked.' `
    -Fix 'Remove the broad entry (or set trust_level = "untrusted") and trust each project folder on its own. Do not start Codex from the home directory or a drive root.' `
    -References @('OWASP-ASI03', 'OWASP-ASI04', $script:AwCdxDocs.Basics, $script:AwCdxDocs.Security, $script:AwCdxDocs.Reference) `
    -Confidence 'medium' -Check {
        param($Ctx)
        $shown = @{}
        foreach ($a in @(Get-AwCdxArtifacts $Ctx @('user', 'profile'))) {
            $projects = Get-AwCdxValue $a.Data @('projects')
            foreach ($p in (Get-AwCdxSortedKeys $projects)) {
                $entry = $projects[$p]
                if ($entry -isnot [System.Collections.IDictionary] -or -not (Test-AwCdxString $entry['trust_level'] 'trusted')) { continue }
                $why = Get-AwCdxBroadPath -Path $p -Ctx $Ctx
                if (-not $why -or -not (Test-AwCdxRoom $shown $a 'project')) { continue }
                $shownPath = Format-AwCommandSnippet $p 120
                New-AwCdxFinding 'AW-CDX-010' $a 'projects.trust_level' ('projects ''{0}'' trust_level = "trusted" ({1}, {2})' -f $shownPath, $why, (Get-AwCdxScopeLabel $a $Ctx)) `
                    $null @(("projects.'" + $p + "'"), ('projects."' + $p + '"'), ('projects.' + $p)) 'trust_level'
            }
        }
    }

Register-AwRule -Id 'AW-CDX-011' -Title 'Codex live web search is enabled' `
    -Severity 'medium' -Category 'sandbox-network' -Harness 'codex' `
    -Description 'web_search = "live" gives the agent unrestricted live retrieval of web pages, instead of the default "cached" mode that answers from an OpenAI-maintained index without external web access. Every page the agent reads can carry a prompt injection, and search queries can carry workspace data out. User, project and system config files are checked; profiles are checked by AW-CDX-014. The finding is info when requirements.toml does not allow "live" (allowed_web_search_modes).' `
    -Fix 'Keep web_search = "cached" (the default), or "indexed", and use live search only in sessions that need it (--search). Restrict it with allowed_web_search_modes in requirements.toml.' `
    -References @('OWASP-ASI01', $script:AwCdxDocs.Basics, $script:AwCdxDocs.Security, $script:AwCdxDocs.Reference) `
    -Confidence 'high' -Check {
        param($Ctx)
        $req = Get-AwCdxRequirements $Ctx
        foreach ($a in @(Get-AwCdxArtifacts $Ctx @('user', 'project', 'system'))) {
            if (-not (Test-AwCdxString (Get-AwCdxValue $a.Data @('web_search')) 'live')) { continue }
            $ev = 'web_search = "live" ({0})' -f (Get-AwCdxScopeLabel $a $Ctx)
            $sev = $null
            if (Test-AwCdxForbidden $req 'allowed_web_search_modes' 'live') { $sev = 'info'; $ev += '; requirements.toml does not allow it (allowed_web_search_modes)' }
            New-AwCdxFinding 'AW-CDX-011' $a 'web_search' $ev $sev $null 'web_search'
        }
    }

Register-AwRule -Id 'AW-CDX-012' -Title 'Project Codex hooks run commands' `
    -Severity 'medium' -Category 'mcp-supply-chain' -Harness 'codex' `
    -Description 'Lists the command and MCP tool hooks of the project .codex/hooks.json and of the [hooks] tables of the project .codex/config.toml files (the root one and those of the folders below it, which load in their folder). They run on agent events, with your rights, in every Codex session of the repository once the project is trusted, and anyone who can change the repository can change them. Codex asks you to review and trust each non-managed hook, and records that trust against the hook hash, so a changed hook needs a new review. The rule is silent when hooks are turned off (features.hooks = false, or the deprecated features.codex_hooks) in every folder and Codex home where the hooks load, in the precedence of AW-CDX-002 (nested project config > project config > user config > system config), or when requirements.toml sets allow_managed_hooks_only = true or features.hooks = false.' `
    -Fix 'Review every hook command and the scripts it calls before you trust it, protect .codex/ with CODEOWNERS and required reviews, and keep personal hooks in ~/.codex/hooks.json. Set allow_managed_hooks_only = true in requirements.toml where repository hooks are not needed.' `
    -References @('OWASP-ASI04', 'OWASP-ASI05', $script:AwCdxDocs.Hooks, $script:AwCdxDocs.Advanced) `
    -Confidence 'high' -Check {
        param($Ctx)
        $req = Get-AwCdxRequirements $Ctx
        if ($req) {
            if (Test-AwCdxTrue (Get-AwCdxValue $req.Data @('allow_managed_hooks_only'))) { return }
            $managed = Get-AwCdxValue $req.Data @('features', 'hooks')
            if ($managed -is [bool] -and -not $managed) { return }
        }
        # Every layer stack (Get-AwCdxLayers) is evaluated on its own: one per Codex home, so a flag in a
        # home that is not active never silences the others, and one per project folder, since a
        # nested .codex/config.toml can turn hooks on or off in its folder.
        $layers = Get-AwCdxLayers $Ctx
        $flags = New-Object object[] $layers.Stacks.Count
        for ($i = 0; $i -lt $layers.Stacks.Count; $i++) { $flags[$i] = Get-AwCdxHooksFlag $layers.Stacks[$i].Layers }
        $root = [string](Get-AwMemberValue $Ctx 'Root')
        $rootConfig = $null
        # Compared as relative paths, so a drive root ('X:\', whose config folder is 'X:') still matches.
        foreach ($p in $layers.Projects) {
            if ((Get-AwRelativePath -Path (Get-AwCdxProjectFolder $p) -Base $root) -eq '.') { $rootConfig = $p; break }
        }
        $all = @(0..($layers.Stacks.Count - 1))
        if ($layers.Stacks.Count -eq 0) { $all = @() }
        $sources = New-Object System.Collections.ArrayList
        # The root .codex/hooks.json loads in every folder of the trusted project: in the stacks of
        # every project chain, and in the stacks without project config file when the root has none.
        # Its own folder is the root: the chain of the root config, or no project config file.
        foreach ($h in @(Get-AwMemberValue $Ctx 'Hooks')) {
            if ($null -eq $h -or $h.Harness -ne 'codex' -or $h.Scope -ne 'project' -or $h.Data -isnot [System.Collections.IDictionary]) { continue }
            $in = @($all | Where-Object { $null -eq $rootConfig -or @($layers.Stacks[$_].Project).Count -gt 0 })
            $own = @($in | Where-Object {
                $chain = @($layers.Stacks[$_].Project)
                if ($null -eq $rootConfig) { $chain.Count -eq 0 } else { $chain.Count -gt 0 -and [object]::ReferenceEquals($chain[0], $rootConfig) }
            })
            [void]$sources.Add([pscustomobject]@{ Artifact = $h; Hooks = $h.Data['hooks']; Json = $true; In = $in; Own = $own })
        }
        # The [hooks] tables of a project config file load in its folder and the folders below it.
        foreach ($p in $layers.Projects) {
            $in = @()
            if ($layers.ByPath.ContainsKey([string]$p.Path)) { $in = @($layers.ByPath[[string]$p.Path]) }
            $own = @($in | Where-Object { [object]::ReferenceEquals(@($layers.Stacks[$_].Project)[0], $p) })
            [void]$sources.Add([pscustomobject]@{ Artifact = $p; Hooks = (Get-AwCdxValue $p.Data @('hooks')); Json = $false; In = $in; Own = $own })
        }
        foreach ($s in $sources) {
            $enabled = @($s.In | Where-Object { $null -eq $flags[$_] -or $flags[$_].Value })
            if ($enabled.Count -eq 0) { continue }
            $handlers = @(Get-AwCdxHookHandlers $s.Hooks)
            if ($handlers.Count -eq 0) { continue }
            # Hooks off in the folder of the file but turned back on below it: name the file that does it.
            $note = ''
            if (@($s.Own | Where-Object { $enabled -contains $_ }).Count -eq 0) {
                $by = $flags[$enabled[0]]
                if ($null -ne $by) { $note = '; hooks are off in its folder but on below it ({0} = true, {1})' -f $by.Key, (Get-AwCdxScopeLabel $by.Artifact $Ctx) }
            }
            $limit = $script:AwCdxMaxPerFile
            for ($i = 0; $i -lt [Math]::Min($handlers.Count, $limit); $i++) {
                $h = $handlers[$i]
                $text = 'hook {0} {1}: {2}' -f (Format-AwCdxKey $h.Event), $h.Type, (Format-AwCommandSnippet $h.Text)
                $text += $note
                if ($i -eq $limit - 1 -and $handlers.Count -gt $limit) { $text += (' (and {0} more)' -f ($handlers.Count - $limit)) }
                $key = 'hooks.' + (Format-AwCdxKey $h.Event)
                if ($s.Json) {
                    New-AwFinding -RuleId 'AW-CDX-012' -Evidence $text -Location @{ Path = $s.Artifact.Path; Line = (Find-AwLineNumber -Text $s.Artifact.Raw -Needle ('"' + $h.Event + '"')); Key = $key }
                } else {
                    New-AwCdxFinding 'AW-CDX-012' $s.Artifact $key $text $null @(('[[hooks.' + $h.Event + ']]'), ('hooks.' + $h.Event)) $null
                }
            }
        }
    }

Register-AwRule -Id 'AW-CDX-013' -Title 'Project Codex rules allow commands outside the sandbox' `
    -Severity 'medium' -Category 'mcp-supply-chain' -Harness 'codex' `
    -Description 'Lists the prefix_rule() entries of the project .codex/rules/*.rules files whose decision is "allow", explicitly or by default (allow is the default decision). A matching command runs outside the sandbox without a prompt, and the rules load as soon as the project is trusted, so anyone who can change the repository can widen what the agent runs unattended. The Starlark files are not evaluated: calls are found by name, outside comments, so computed patterns are not resolved and confidence is medium. Rules are an experimental feature; when several rules match, the most restrictive decision wins.' `
    -Fix 'Review every allow rule of the repository, keep allow rules for narrow, read-only commands, prefer decision = "prompt", and protect .codex/ with CODEOWNERS and required reviews. Keep personal rules in ~/.codex/rules/.' `
    -References @('OWASP-ASI04', 'OWASP-ASI02', $script:AwCdxDocs.Rules, $script:AwCdxDocs.Advanced) `
    -Confidence 'medium' -Check {
        param($Ctx)
        foreach ($r in @(Get-AwMemberValue $Ctx 'CodexRules')) {
            if ($null -eq $r -or $r.Scope -ne 'project' -or [string]::IsNullOrEmpty($r.Raw)) { continue }
            $allows = @(Get-AwCdxAllowRules $r.Raw)
            $limit = $script:AwCdxMaxPerFile
            for ($i = 0; $i -lt [Math]::Min($allows.Count, $limit); $i++) {
                $x = $allows[$i]
                $how = if ($x.Explicit) { 'decision = "allow"' } else { 'no decision (allow by default)' }
                $text = 'prefix_rule pattern [{0}], {1}: matching commands run outside the sandbox without a prompt' -f (Format-AwCommandSnippet $x.Pattern 100), $how
                if ($i -eq $limit - 1 -and $allows.Count -gt $limit) { $text += (' (and {0} more)' -f ($allows.Count - $limit)) }
                New-AwFinding -RuleId 'AW-CDX-013' -Evidence $text -Location @{ Path = $r.Path; Line = (Get-AwCdxLineAt $r.Raw $x.Index); Key = 'prefix_rule' }
            }
        }
    }

Register-AwRule -Id 'AW-CDX-014' -Title 'Codex profile weakens the sandbox or the approvals' `
    -Severity 'medium' -Category 'sandbox-network' -Harness 'codex' `
    -Description 'Checks the profile files (<codex home>/<name>.config.toml, selected with --profile <name>) for settings that weaken the defaults: sandbox_mode = "danger-full-access", default_permissions = ":danger-full-access", approval_policy = "never", sandbox_workspace_write.network_access = true and web_search = "live". One --profile flag then switches a session to that configuration. A profile is evaluated with the layers it applies with, in the documented precedence project config > profile > user config > system config: the config.toml of its Codex home and the system config below it, alone and under the project .codex/config.toml files of each folder (the root one and the nested ones, closest first). A profile setting counts only where it applies (sandbox_mode in any of these files takes precedence over default_permissions, and [sandbox_workspace_write] is ignored with permission profiles). The finding is high when, with the profile, neither the sandbox nor the approvals remain, whichever of these files removes each one (the evidence names the other file); it is not when requirements.toml forbids the value. Legacy [profiles.<name>] tables of the user config.toml are reported as low: Codex 0.134.0 and later no longer read them.' `
    -Fix 'Remove the weakening settings from the profile, or delete the profile, and run sessions that need broad access only inside an isolated container or VM. Delete legacy [profiles.<name>] tables from config.toml.' `
    -References @('OWASP-ASI02', 'OWASP-ASI05', $script:AwCdxDocs.Advanced, $script:AwCdxDocs.Basics, $script:AwCdxDocs.Security, $script:AwCdxDocs.Reference) `
    -Confidence 'high' -Check {
        param($Ctx)
        $req = Get-AwCdxRequirements $Ctx
        $fullMode = Get-AwCdxDataText 'fullAccessSandboxMode'
        $fullPerm = Get-AwCdxDataText 'fullAccessPermissions'
        $weakenings = {
            param($Data)
            $out = New-Object System.Collections.Generic.List[string]
            $full = $false; $never = $false
            if (Test-AwCdxString (Get-AwCdxValue $Data @('sandbox_mode')) $fullMode) { $out.Add(('sandbox_mode = "{0}"' -f $fullMode)); $full = $true }
            if (Test-AwCdxString (Get-AwCdxValue $Data @('default_permissions')) $fullPerm) { $out.Add(('default_permissions = "{0}"' -f $fullPerm)); $full = $true }
            if (Test-AwCdxString (Get-AwCdxValue $Data @('approval_policy')) 'never') { $out.Add('approval_policy = "never"'); $never = $true }
            if (Test-AwCdxTrue (Get-AwCdxValue $Data @('sandbox_workspace_write', 'network_access'))) { $out.Add('sandbox_workspace_write.network_access = true') }
            if (Test-AwCdxString (Get-AwCdxValue $Data @('web_search')) 'live') { $out.Add('web_search = "live"') }
            [pscustomobject]@{ List = $out.ToArray(); Both = ($full -and $never) }
        }
        # Profile files: the weakening values the profile holds where they apply, and whether a
        # session with the profile keeps neither the sandbox nor the approvals.
        $order = @(
            @('sandbox_mode', ('sandbox_mode = "{0}"' -f $fullMode)),
            @('default_permissions', ('default_permissions = "{0}"' -f $fullPerm)),
            @('approval_policy', 'approval_policy = "never"'),
            @('network_access', 'sandbox_workspace_write.network_access = true'),
            @('web_search', 'web_search = "live"'))
        $netPath = @('sandbox_workspace_write', 'network_access')
        foreach ($a in @(Get-AwCdxArtifacts $Ctx @('profile'))) {
            $held = @{}
            $both = $false
            $others = New-Object System.Collections.Generic.List[string]
            foreach ($stack in (Get-AwCdxProfileStacks $Ctx $a)) {
                $full = Get-AwCdxFullAccess $stack $req
                if ($full -and [object]::ReferenceEquals($full.Artifact, $a)) { $held[$full.Key] = $true }
                $never = Get-AwCdxStackValue $stack @('approval_policy')
                if ($never -and -not (Test-AwCdxString $never.Value 'never')) { $never = $null }
                if ($never -and [object]::ReferenceEquals($never.Artifact, $a)) { $held['approval_policy'] = $true }
                if ((Test-AwCdxEffective $stack $a $netPath) -and (Test-AwCdxTrue (Get-AwCdxValue $a.Data $netPath)) -and -not (Test-AwCdxProfilesSystem $stack $req)) {
                    $mode = Get-AwCdxStackValue $stack @('sandbox_mode')
                    if ($null -eq $mode -or (Test-AwCdxString $mode.Value 'workspace-write')) { $held['network_access'] = $true }
                }
                if ((Test-AwCdxEffective $stack $a @('web_search')) -and (Test-AwCdxString (Get-AwCdxValue $a.Data @('web_search')) 'live')) { $held['web_search'] = $true }
                if ($both -or $null -eq $full -or $null -eq $never) { continue }
                $fromProfile = [object]::ReferenceEquals($full.Artifact, $a) -or [object]::ReferenceEquals($never.Artifact, $a)
                if (-not $fromProfile) { continue }
                if ($full.Key -eq 'sandbox_mode' -and (Test-AwCdxForbidden $req 'allowed_sandbox_modes' $full.Value)) { continue }
                if ($full.Key -eq 'default_permissions' -and (Test-AwCdxProfileForbidden $req $full.Value)) { continue }
                if (Test-AwCdxForbidden $req 'allowed_approval_policies' 'never') { continue }
                $both = $true
                if (-not [object]::ReferenceEquals($full.Artifact, $a)) { $others.Add(('{0} = "{1}" ({2})' -f $full.Key, $full.Value, (Get-AwCdxScopeLabel $full.Artifact $Ctx))) }
                if (-not [object]::ReferenceEquals($never.Artifact, $a)) { $others.Add(('approval_policy = "never" ({0})' -f (Get-AwCdxScopeLabel $never.Artifact $Ctx))) }
            }
            $list = @(foreach ($o in $order) { if ($held.ContainsKey($o[0])) { $o[1] } })
            if ($list.Count -eq 0) { continue }
            $name = Get-AwCdxProfileName $a
            $ev = "profile '{0}' (--profile {0}): {1}" -f (Format-AwCommandSnippet $name 64), ($list -join ', ')
            $sev = $null
            if ($both) {
                $sev = 'high'
                if ($others.Count -gt 0) { $ev += '; with ' + ($others -join ' and ') + ': no sandbox and no approval' } else { $ev += '; no sandbox and no approval' }
            }
            $firstKey = ($list[0] -split ' ')[0]
            New-AwCdxFinding 'AW-CDX-014' $a $firstKey $ev $sev $null ($firstKey.Split('.')[-1])
        }
        $shown = @{}
        foreach ($a in @(Get-AwCdxArtifacts $Ctx @('user'))) {
            $profiles = Get-AwCdxValue $a.Data @('profiles')
            foreach ($name in (Get-AwCdxSortedKeys $profiles)) {
                if ($profiles[$name] -isnot [System.Collections.IDictionary]) { continue }
                $w = & $weakenings $profiles[$name]
                if ($w.List.Count -eq 0 -or -not (Test-AwCdxRoom $shown $a 'legacy')) { continue }
                $key = 'profiles.' + (Format-AwCdxKey $name)
                $ev = 'legacy [{0}] table (user config, read by Codex before 0.134.0 only): {1}' -f $key, ($w.List -join ', ')
                New-AwCdxFinding 'AW-CDX-014' $a $key $ev 'low' @("[profiles.$name]", "profiles.$name") $null
            }
        }
    }
