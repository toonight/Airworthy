# Artifact discovery: builds the analysis context from the root and, optionally, the user profile.
# Every file is treated as hostile: size limit, no link escaping the root, parse errors become AW-CORE-001.

$script:AwMaxFileBytes    = 2MB
$script:AwMaxTextFiles    = 500
$script:AwMaxFilesPerGlob = 500
$script:AwMaxTotalBytes   = 32MB   # read budget for one analysis (hostile repositories with many large files)
# Test hook: when set, replaces the machine-wide managed-settings.json candidates.
$script:AwManagedSettingsOverride = $null

function Add-AwDiscoveryError {
    param($State, [string]$Path, [string]$Message, $Line = $null, [string]$Harness = 'generic')
    [void]$State.Errors.Add((New-AwFinding -RuleId 'AW-CORE-001' -Evidence $Message -Harness $Harness `
        -Location @{ Path = $Path; Line = $Line }))
}

function ConvertTo-AwLinkTargetPath {
    <#
    Absolute path of a link target as PowerShell reports it, or $null when it cannot be resolved
    safely. Windows PowerShell strips the \??\ prefix of the stored target, so a link to a network
    share reads 'UNC\server\share' and a volume mount point 'Volume{...}\': those must never be
    taken for paths relative to the link, which would look like they stay inside the root.
    #>
    param([string]$Target, [string]$LinkPath)
    if ([string]::IsNullOrEmpty($Target)) { return $null }
    $t = $Target
    if ($t.StartsWith('\\?\') -or $t.StartsWith('\??\')) { $t = $t.Substring(4) }
    if ($t -match '^(?i)(UNC|GLOBALROOT)[\\/]|^(?i)Volume\{') { return $null }
    if ($t.StartsWith('\\') -or $t.StartsWith('//')) { return $null }
    try {
        if (-not [System.IO.Path]::IsPathRooted($t)) {
            $t = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($LinkPath), $t)
        }
        return [System.IO.Path]::GetFullPath($t)
    } catch {
        return $null
    }
}

function Resolve-AwLinkTarget {
    # Absolute target of a symbolic link or junction, or $null (also for network and volume targets).
    param([System.IO.FileSystemInfo]$Item)
    $target = @($Item.Target) | Where-Object { $_ } | Select-Object -First 1
    if (-not $target) { return $null }
    return (ConvertTo-AwLinkTargetPath -Target ([string]$target) -LinkPath $Item.FullName)
}

function Test-AwSafePath {
    <#
    True when no symbolic link or junction between Root and Path (inclusive) resolves outside Root.
    Other reparse points (cloud placeholders, deduplicated files) are not links and are accepted.
    #>
    param([string]$Path, [string]$Root, [int]$Depth = 0)
    if ($Depth -gt 8) { return $false }
    $rel = Get-AwRelativePath -Path $Path -Base $Root
    if ($null -eq $rel) { return $false }
    if ($rel -eq '.') { return $true }
    $current = $Root.TrimEnd([char[]]@('\', '/'))
    foreach ($part in $rel.Split([char[]]@('\', '/'), [System.StringSplitOptions]::RemoveEmptyEntries)) {
        $current = $current + [System.IO.Path]::DirectorySeparatorChar + $part
        $item = Get-Item -LiteralPath $current -Force -ErrorAction SilentlyContinue
        if ($null -eq $item) { return $true }
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) { continue }
        $linkType = [string]$item.LinkType
        if ($linkType -ne 'SymbolicLink' -and $linkType -ne 'Junction') { continue }
        $target = Resolve-AwLinkTarget -Item $item
        if (-not $target) { return $false }
        if (-not (Test-AwSafePath -Path $target -Root $Root -Depth ($Depth + 1))) { return $false }
    }
    return $true
}

function Read-AwSafeText {
    # Reads a file within the limits. Returns its text, or $null after recording AW-CORE-001.
    param($State, [string]$Path, [string]$Harness = 'generic', [switch]$AllowOutsideRoot)
    try {
        $info = New-Object System.IO.FileInfo -ArgumentList $Path
        if (-not $info.Exists) { return $null }
        if (-not $AllowOutsideRoot -and -not (Test-AwSafePath -Path $info.FullName -Root $State.Root)) {
            Add-AwDiscoveryError $State $Path 'Skipped: a symbolic link or junction leads outside the analyzed root.' $null $Harness
            return $null
        }
        if ($info.Length -gt $script:AwMaxFileBytes) {
            Add-AwDiscoveryError $State $Path ("Skipped: file larger than 2 MB ({0} bytes)." -f $info.Length) $null $Harness
            return $null
        }
        if ($State.BytesRead + $info.Length -gt $script:AwMaxTotalBytes) {
            Add-AwDiscoveryError $State $Path ('Skipped: the read budget of one analysis ({0} bytes) is used up.' -f $script:AwMaxTotalBytes) $null $Harness
            return $null
        }
        $State.BytesRead += $info.Length
        return [System.IO.File]::ReadAllText($info.FullName)
    } catch {
        Add-AwDiscoveryError $State $Path ('Cannot read the file: ' + (Hide-AwSecretsInText $_.Exception.Message)) $null $Harness
        return $null
    }
}

function Get-AwMatchingFiles {
    # Files directly in Dir whose name matches the wildcard, sorted, capped.
    param($State, [string]$Dir, [string]$Like)
    if (-not [System.IO.Directory]::Exists($Dir)) { return @() }
    $files = @(Get-ChildItem -LiteralPath $Dir -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like $Like } | Sort-Object -Property Name | ForEach-Object { $_.FullName })
    if ($files.Count -gt $script:AwMaxFilesPerGlob) {
        Add-AwDiscoveryError $State $Dir ("More than {0} files match '{1}'; only the first {0} were analyzed." -f $script:AwMaxFilesPerGlob, $Like)
        $files = $files[0..($script:AwMaxFilesPerGlob - 1)]
    }
    return $files
}

function New-AwJsonArtifact {
    # Artifact for a JSON/JSONC file, or $null when the file is absent or unreadable.
    param($State, [string]$Path, [string]$Scope, [string]$Harness, [switch]$AllowOutsideRoot)
    if (-not [System.IO.File]::Exists($Path)) { return $null }
    $raw = Read-AwSafeText -State $State -Path $Path -Harness $Harness -AllowOutsideRoot:$AllowOutsideRoot
    if ($null -eq $raw) { return $null }
    $data = $null
    try {
        $parsed = ConvertFrom-AwJsonc -Text $raw -AllowEmpty
        if ($null -eq $parsed) {
            $data = New-AwOrdinalHashtable
        } elseif ($parsed -is [System.Collections.IDictionary]) {
            $data = $parsed
        } else {
            Add-AwDiscoveryError $State $Path 'Invalid configuration: the top-level JSON value is not an object.' 1 $Harness
        }
    } catch {
        $line = $null
        if ($_.Exception.Data.Contains('Line')) { $line = $_.Exception.Data['Line'] }
        Add-AwDiscoveryError $State $Path $_.Exception.Message $line $Harness
    }
    [pscustomobject]@{ Path = (New-Object System.IO.FileInfo -ArgumentList $Path).FullName; Scope = $Scope; Harness = $Harness; Raw = $raw; Data = $data }
}

function Add-AwMcpServers {
    # Normalizes the servers of an MCP artifact into Data.Servers (name -> server hashtable).
    param($State, $Artifact, [string[]]$Keys)
    if ($null -eq $Artifact -or $null -eq $Artifact.Data) { return }
    $servers = New-AwOrdinalHashtable
    foreach ($key in $Keys) {
        $src = $Artifact.Data[$key]
        if ($null -eq $src) { continue }
        if ($src -isnot [System.Collections.IDictionary]) {
            Add-AwDiscoveryError $State $Artifact.Path "Invalid MCP configuration: '$key' is not an object." (Find-AwLineNumber $Artifact.Raw "`"$key`"") $Artifact.Harness
            continue
        }
        foreach ($name in $src.Keys) {
            if ($src[$name] -is [System.Collections.IDictionary]) { $servers[$name] = $src[$name] }
            else { Add-AwDiscoveryError $State $Artifact.Path "Invalid MCP configuration: server '$name' is not an object." (Find-AwLineNumber $Artifact.Raw "`"$name`"") $Artifact.Harness }
        }
    }
    $Artifact.Data['Servers'] = $servers
}

function Add-AwClaudeJsonServers {
    # ~/.claude.json: user servers under 'mcpServers' and per-project servers under 'projects.<path>.mcpServers'.
    param($State, $Artifact)
    if ($null -eq $Artifact -or $null -eq $Artifact.Data) { return }
    Add-AwMcpServers -State $State -Artifact $Artifact -Keys @('mcpServers')
    $projects = $Artifact.Data['projects']
    if ($projects -isnot [System.Collections.IDictionary]) { return }
    $paths = [string[]]@($projects.Keys); [Array]::Sort($paths, [StringComparer]::Ordinal)
    foreach ($p in $paths) {
        $proj = $projects[$p]
        if ($proj -isnot [System.Collections.IDictionary]) { continue }
        $src = $proj['mcpServers']
        if ($src -isnot [System.Collections.IDictionary]) { continue }
        foreach ($name in $src.Keys) {
            if ($src[$name] -is [System.Collections.IDictionary]) { $Artifact.Data['Servers']["$name (project: $p)"] = $src[$name] }
        }
    }
}

function New-AwAgentFile {
    param($State, [string]$Path, [string]$Kind, [string]$Scope, [string]$Harness, [switch]$AllowOutsideRoot)
    $raw = Read-AwSafeText -State $State -Path $Path -Harness $Harness -AllowOutsideRoot:$AllowOutsideRoot
    if ($null -eq $raw) { return $null }
    $parsed = Read-AwFrontmatter -Text $raw
    $fm = $parsed.Frontmatter
    if ($fm.ContainsKey('__errors')) {
        $errs = @($fm['__errors'])
        $more = if ($errs.Count -gt 1) { " (+$($errs.Count - 1) more)" } else { '' }
        Add-AwDiscoveryError $State $Path ("Frontmatter partially parsed: " + $errs[0] + $more) $null $Harness
    }
    [pscustomobject]@{
        Path = (New-Object System.IO.FileInfo -ArgumentList $Path).FullName
        Kind = $Kind; Scope = $Scope; Frontmatter = $fm; Body = $parsed.Body; Raw = $raw
    }
}

function Get-AwVSCodeUserDirs {
    # Candidate VS Code 'User' folders (stable first, then Insiders).
    param([string]$UserProfile, [bool]$IsRealProfile)
    $bases = New-Object System.Collections.Generic.List[string]
    if ($IsRealProfile -and $env:APPDATA) { $bases.Add($env:APPDATA) }
    foreach ($rel in @('AppData\Roaming', '.config', 'Library\Application Support')) {
        $bases.Add([System.IO.Path]::Combine($UserProfile, $rel.Replace('\', [string][System.IO.Path]::DirectorySeparatorChar)))
    }
    $dirs = New-Object System.Collections.Generic.List[string]
    foreach ($product in @('Code', 'Code - Insiders')) {
        foreach ($b in $bases) {
            $dir = [System.IO.Path]::Combine([System.IO.Path]::Combine($b, $product), 'User')
            $known = $false
            foreach ($x in $dirs) { if ([string]::Equals($x, $dir, $script:AwPathComparison)) { $known = $true } }
            if (-not $known) { $dirs.Add($dir) }
        }
    }
    return $dirs.ToArray()
}

function Get-AwManagedSettingsCandidates {
    if ($null -ne $script:AwManagedSettingsOverride) { return @($script:AwManagedSettingsOverride) }
    if ($script:AwIsWindowsOS) {
        $pf = if ($env:ProgramFiles) { $env:ProgramFiles } else { 'C:\Program Files' }
        return @([System.IO.Path]::Combine([System.IO.Path]::Combine($pf, 'ClaudeCode'), 'managed-settings.json'))
    }
    return @('/Library/Application Support/ClaudeCode/managed-settings.json', '/etc/claude-code/managed-settings.json')
}

function New-AwContext {
    <#
    .SYNOPSIS
    Discovers every harness artifact under Path (and the user profile unless -NoUserProfile).
    .DESCRIPTION
    Returns the analysis context described in docs/ARCHITECTURE.md (Discovery). Unreadable or invalid
    files never stop discovery: they become AW-CORE-001 findings in Errors.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [string]$UserSettingsPath,
        [string]$UserProfilePath,
        [switch]$NoUserProfile
    )
    $sep = [string][System.IO.Path]::DirectorySeparatorChar
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "Airworthy: '$Path' is not a directory." }
    $root = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Path).ProviderPath)
    if ($root.Length -gt 3) { $root = $root.TrimEnd([char[]]@('\', '/')) }

    $userProfile = $null
    $isRealProfile = $false
    if (-not $NoUserProfile) {
        if ($UserProfilePath) {
            if (-not (Test-Path -LiteralPath $UserProfilePath -PathType Container)) { throw "Airworthy: user profile '$UserProfilePath' is not a directory." }
            $userProfile = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $UserProfilePath).ProviderPath).TrimEnd([char[]]@('\', '/'))
        } else {
            $userProfile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
            if (-not $userProfile) { $userProfile = $HOME }
            $isRealProfile = $true
        }
    }

    $state = @{ Root = $root; Errors = (New-Object System.Collections.ArrayList); BytesRead = [long]0 }
    $inRoot = { param([string]$Rel) [System.IO.Path]::Combine($root, $Rel.Replace('\', $sep)) }
    $inProfile = { param([string]$Rel) [System.IO.Path]::Combine($userProfile, $Rel.Replace('\', $sep)) }
    $github = & $inRoot '.github'

    # --- VS Code settings ---------------------------------------------------------------
    $userSettings = $null
    $vsUserDirs = @()
    if ($userProfile) { $vsUserDirs = @(Get-AwVSCodeUserDirs -UserProfile $userProfile -IsRealProfile $isRealProfile) }
    if ($UserSettingsPath) {
        $forced = [System.IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($UserSettingsPath))
        if (-not [System.IO.File]::Exists($forced)) { throw "Airworthy: user settings file '$UserSettingsPath' does not exist." }
        $userSettings = New-AwJsonArtifact -State $state -Path $forced -Scope 'user' -Harness 'vscode-copilot' -AllowOutsideRoot
    } else {
        foreach ($dir in $vsUserDirs) {
            $candidate = [System.IO.Path]::Combine($dir, 'settings.json')
            if ([System.IO.File]::Exists($candidate)) {
                $userSettings = New-AwJsonArtifact -State $state -Path $candidate -Scope 'user' -Harness 'vscode-copilot' -AllowOutsideRoot
                break
            }
        }
    }
    $workspaceSettings = New-AwJsonArtifact -State $state -Path (& $inRoot '.vscode\settings.json') -Scope 'workspace' -Harness 'vscode-copilot'
    $workspaceFiles = New-Object System.Collections.ArrayList
    foreach ($f in (Get-AwMatchingFiles $state $root '*.code-workspace')) {
        $a = New-AwJsonArtifact -State $state -Path $f -Scope 'workspace' -Harness 'vscode-copilot'
        if ($a) { [void]$workspaceFiles.Add($a) }
    }

    $layers = New-Object System.Collections.ArrayList
    if ($userSettings -and $userSettings.Data) { [void]$layers.Add(@{ Source = 'user'; Path = $userSettings.Path; Settings = $userSettings.Data }) }
    foreach ($wf in $workspaceFiles) {
        if ($wf.Data -and $wf.Data['settings'] -is [System.Collections.IDictionary]) {
            [void]$layers.Add(@{ Source = 'workspaceFile'; Path = $wf.Path; Settings = $wf.Data['settings'] })
        }
    }
    if ($workspaceSettings -and $workspaceSettings.Data) { [void]$layers.Add(@{ Source = 'workspace'; Path = $workspaceSettings.Path; Settings = $workspaceSettings.Data }) }
    $effective = Get-AwEffectiveSettings -Layers $layers.ToArray()

    # --- MCP --------------------------------------------------------------------------------
    $mcpFiles = New-Object System.Collections.ArrayList
    $seen = @{ Mcp = $false }
    $addMcp = {
        param([string]$File, [string]$Scope, [string]$Harness, [string[]]$Keys, [bool]$Outside, [bool]$ClaudeJson)
        if (-not [System.IO.File]::Exists($File)) { return }
        $seen.Mcp = $true
        $a = New-AwJsonArtifact -State $state -Path $File -Scope $Scope -Harness $Harness -AllowOutsideRoot:$Outside
        if (-not $a) { return }
        if ($ClaudeJson) { Add-AwClaudeJsonServers -State $state -Artifact $a } else { Add-AwMcpServers -State $state -Artifact $a -Keys $Keys }
        [void]$mcpFiles.Add($a)
    }
    & $addMcp (& $inRoot '.vscode\mcp.json') 'workspace' 'vscode-copilot' @('servers') $false $false
    & $addMcp (& $inRoot '.mcp.json') 'project' 'claude-code' @('mcpServers') $false $false
    # Copilot CLI also reads a project .github/mcp.json (cli-config-dir-reference, docs.github.com).
    & $addMcp (& $inRoot '.github\mcp.json') 'project' 'copilot-cli' @('mcpServers') $false $false
    if ($userProfile) {
        foreach ($dir in $vsUserDirs) { & $addMcp ([System.IO.Path]::Combine($dir, 'mcp.json')) 'user' 'vscode-copilot' @('servers') $true $false }
        & $addMcp (& $inProfile '.claude.json') 'user' 'claude-code' @('mcpServers') $true $true
        & $addMcp (& $inProfile '.copilot\mcp-config.json') 'user' 'copilot-cli' @('mcpServers') $true $false
    }

    # --- Agent files --------------------------------------------------------------------
    $agentFiles = New-Object System.Collections.ArrayList
    $addAgents = {
        param([string[]]$Files, [string]$Kind, [string]$Scope, [string]$Harness, [bool]$Outside)
        foreach ($f in $Files) {
            if (-not [System.IO.File]::Exists($f)) { continue }
            $af = New-AwAgentFile -State $state -Path $f -Kind $Kind -Scope $Scope -Harness $Harness -AllowOutsideRoot:$Outside
            if ($af) { [void]$agentFiles.Add($af) }
        }
    }
    & $addAgents (Get-AwMatchingFiles $state (& $inRoot '.github\agents') '*.agent.md') 'agent' 'workspace' 'vscode-copilot' $false
    & $addAgents (Get-AwMatchingFiles $state (& $inRoot '.github\chatmodes') '*.chatmode.md') 'chatmode' 'workspace' 'vscode-copilot' $false
    & $addAgents @(& $inRoot '.github\copilot-instructions.md') 'copilot-instructions' 'workspace' 'vscode-copilot' $false
    & $addAgents (Get-AwMatchingFiles $state (& $inRoot '.github\instructions') '*.instructions.md') 'instructions' 'workspace' 'vscode-copilot' $false
    & $addAgents (Get-AwMatchingFiles $state (& $inRoot '.github\prompts') '*.prompt.md') 'prompt' 'workspace' 'vscode-copilot' $false
    & $addAgents @(& $inRoot 'AGENTS.md') 'agents-md' 'workspace' 'generic' $false
    & $addAgents (Get-AwMatchingFiles $state (& $inRoot '.claude\agents') '*.md') 'claude-agent' 'project' 'claude-code' $false
    & $addAgents @(& $inRoot 'CLAUDE.md') 'claude-md' 'project' 'claude-code' $false
    if ($userProfile) {
        & $addAgents (Get-AwMatchingFiles $state (& $inProfile '.copilot\agents') '*.agent.md') 'agent' 'user' 'copilot-cli' $true
    }

    # --- Claude Code settings -----------------------------------------------------------
    $claudeSettings = New-Object System.Collections.ArrayList
    $addClaude = {
        param([string]$File, [string]$Scope, [bool]$Outside)
        $a = New-AwJsonArtifact -State $state -Path $File -Scope $Scope -Harness 'claude-code' -AllowOutsideRoot:$Outside
        if ($a) { [void]$claudeSettings.Add($a) }
    }
    & $addClaude (& $inRoot '.claude\settings.json') 'project' $false
    & $addClaude (& $inRoot '.claude\settings.local.json') 'local' $false
    if ($userProfile) {
        & $addClaude (& $inProfile '.claude\settings.json') 'user' $true
        if ($isRealProfile -or $null -ne $script:AwManagedSettingsOverride) {
            foreach ($m in (Get-AwManagedSettingsCandidates)) { & $addClaude $m 'managed' $true }
        }
    }

    # --- Hooks --------------------------------------------------------------------------
    $hooks = New-Object System.Collections.ArrayList
    foreach ($f in (Get-AwMatchingFiles $state (Join-Path $github 'hooks') '*.json')) {
        $a = New-AwJsonArtifact -State $state -Path $f -Scope 'project' -Harness 'copilot-cli'
        if ($a) { [void]$hooks.Add($a) }
    }
    if ($userProfile) {
        foreach ($f in (Get-AwMatchingFiles $state (& $inProfile '.copilot\hooks') '*.json')) {
            $a = New-AwJsonArtifact -State $state -Path $f -Scope 'user' -Harness 'copilot-cli' -AllowOutsideRoot
            if ($a) { [void]$hooks.Add($a) }
        }
    }
    foreach ($cs in $claudeSettings) {
        if ($cs.Scope -ne 'project' -and $cs.Scope -ne 'local') { continue }
        $hasHooks = if ($cs.Data) { $cs.Data.ContainsKey('hooks') } else { $cs.Raw -match '"hooks"\s*:' }
        if ($hasHooks) { [void]$hooks.Add($cs) }
    }

    # --- Copilot CLI --------------------------------------------------------------------
    $copilotCli = New-Object System.Collections.ArrayList
    $a = New-AwJsonArtifact -State $state -Path (& $inRoot '.github\copilot\settings.json') -Scope 'project' -Harness 'copilot-cli'
    if ($a) { [void]$copilotCli.Add($a) }
    # Personal overrides, read after the repository settings (cli-config-dir-reference, docs.github.com).
    $a = New-AwJsonArtifact -State $state -Path (& $inRoot '.github\copilot\settings.local.json') -Scope 'local' -Harness 'copilot-cli'
    if ($a) { [void]$copilotCli.Add($a) }
    if ($userProfile) {
        foreach ($name in @('config.json', 'settings.json')) {
            $a = New-AwJsonArtifact -State $state -Path (& $inProfile ".copilot\$name") -Scope 'user' -Harness 'copilot-cli' -AllowOutsideRoot
            if ($a) { [void]$copilotCli.Add($a) }
        }
    }

    # --- Harness detection --------------------------------------------------------------
    $dirExists = { param([string]$P) [System.IO.Directory]::Exists($P) }
    $harnesses = New-Object System.Collections.Generic.List[string]
    $isVSCode = (& $dirExists (& $inRoot '.vscode')) -or (& $dirExists (Join-Path $github 'agents')) -or
        (& $dirExists (Join-Path $github 'chatmodes')) -or (& $dirExists (Join-Path $github 'prompts')) -or
        (& $dirExists (Join-Path $github 'instructions')) -or [System.IO.File]::Exists((Join-Path $github 'copilot-instructions.md')) -or
        ($null -ne $userSettings) -or ($workspaceFiles.Count -gt 0)
    if ($isVSCode) { $harnesses.Add('vscode-copilot') }
    $isClaude = (& $dirExists (& $inRoot '.claude')) -or [System.IO.File]::Exists((& $inRoot 'CLAUDE.md')) -or
        ($userProfile -and (& $dirExists (& $inProfile '.claude')))
    if ($isClaude) { $harnesses.Add('claude-code') }
    $isCli = (& $dirExists (Join-Path $github 'copilot')) -or ($userProfile -and (& $dirExists (& $inProfile '.copilot')))
    if ($isCli) { $harnesses.Add('copilot-cli') }
    if ($seen.Mcp) { $harnesses.Add('mcp') }

    # --- Text files for secret scanning -------------------------------------------------
    $textFiles = New-Object System.Collections.Generic.List[string]
    $addText = {
        param([string]$P)
        if (-not $P) { return }
        foreach ($x in $textFiles) { if ([string]::Equals($x, $P, $script:AwPathComparison)) { return } }
        $textFiles.Add($P)
    }
    foreach ($art in @(@($userSettings, $workspaceSettings) + $workspaceFiles.ToArray() + $mcpFiles.ToArray() +
                       $agentFiles.ToArray() + $hooks.ToArray() + $claudeSettings.ToArray() + $copilotCli.ToArray())) {
        if ($art) { & $addText $art.Path }
    }
    foreach ($envFile in (Get-AwMatchingFiles $state $root '.env*')) {
        $info = New-Object System.IO.FileInfo -ArgumentList $envFile
        if (-not (Test-AwSafePath -Path $info.FullName -Root $root)) {
            Add-AwDiscoveryError $state $envFile 'Skipped: a symbolic link or junction leads outside the analyzed root.'
        } elseif ($info.Length -gt $script:AwMaxFileBytes) {
            Add-AwDiscoveryError $state $envFile ("Skipped: file larger than 2 MB ({0} bytes)." -f $info.Length)
        } elseif ($state.BytesRead + $info.Length -gt $script:AwMaxTotalBytes) {
            # The secret rules read these files later: their size counts in the read budget now.
            Add-AwDiscoveryError $state $envFile ('Skipped: the read budget of one analysis ({0} bytes) is used up.' -f $script:AwMaxTotalBytes)
        } else {
            $state.BytesRead += $info.Length
            & $addText $info.FullName
        }
    }
    $textArray = $textFiles.ToArray()
    [Array]::Sort($textArray, [StringComparer]::OrdinalIgnoreCase)
    if ($textArray.Count -gt $script:AwMaxTextFiles) {
        Add-AwDiscoveryError $state $root ("More than {0} text files to scan; only the first {0} were kept." -f $script:AwMaxTextFiles)
        $textArray = $textArray[0..($script:AwMaxTextFiles - 1)]
    }

    [pscustomobject]@{
        Root           = $root
        IsWindows      = $script:AwIsWindowsOS
        UserProfile    = $userProfile
        Harnesses      = [string[]]$harnesses.ToArray()
        VSCode         = [pscustomobject]@{
            UserSettings      = $userSettings
            WorkspaceSettings = $workspaceSettings
            WorkspaceFiles    = $workspaceFiles.ToArray()
            Effective         = $effective
        }
        McpFiles       = $mcpFiles.ToArray()
        AgentFiles     = $agentFiles.ToArray()
        Hooks          = $hooks.ToArray()
        ClaudeSettings = $claudeSettings.ToArray()
        CopilotCli     = $copilotCli.ToArray()
        TextFiles      = [string[]]$textArray
        Errors         = $state.Errors.ToArray()
    }
}

function Get-AwFileText {
    <#
    .SYNOPSIS
    Returns the text of a discovered file (from the context when known), or $null.
    .DESCRIPTION
    For files in Ctx.TextFiles that are not artifacts (.env*), the file is read with the
    2 MB limit. Never throws.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Ctx, [Parameter(Mandatory)] [string]$Path)
    $vs = $Ctx.VSCode
    foreach ($a in @(@($vs.UserSettings, $vs.WorkspaceSettings) + @($vs.WorkspaceFiles) + @($Ctx.McpFiles) + @($Ctx.AgentFiles) +
                     @($Ctx.Hooks) + @($Ctx.ClaudeSettings) + @($Ctx.CopilotCli))) {
        if ($a -and [string]::Equals($a.Path, $Path, $script:AwPathComparison)) { return $a.Raw }
    }
    try {
        $info = New-Object System.IO.FileInfo -ArgumentList $Path
        if (-not $info.Exists -or $info.Length -gt $script:AwMaxFileBytes) { return $null }
        return [System.IO.File]::ReadAllText($info.FullName)
    } catch {
        return $null
    }
}
