# Copilot CLI rules (AW-CLI-0xx), applied to Ctx.CopilotCli: .github/copilot/settings.json [project],
# .github/copilot/settings.local.json [local], ~/.copilot/config.json (CLI-managed state, including
# trusted folders) and ~/.copilot/settings.json [user].
# Sources (read 2026-10-18): docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference,
# /reference/hooks-reference and /concepts/agents/about-copilot-cli. Only documented keys are checked.

$script:AwCliDocs = @{
    ConfigDir = 'https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference'
    About     = 'https://docs.github.com/en/copilot/concepts/agents/about-copilot-cli'
    Hooks     = 'https://docs.github.com/en/copilot/reference/hooks-reference'
}

# ---------------------------------------------------------------------------------------------
# Helpers (evidence masking: Format-AwCommandSnippet, in Mcp.ps1)
# ---------------------------------------------------------------------------------------------

function Get-AwCliFile {
    # The parsed Copilot CLI artifact with this file name and scope, or $null.
    param($Ctx, [string]$Name, [string]$Scope)
    foreach ($a in @($Ctx.CopilotCli)) {
        if ($null -eq $a -or $a.Data -isnot [System.Collections.IDictionary] -or $a.Scope -ne $Scope) { continue }
        if ([string]::Equals([System.IO.Path]::GetFileName($a.Path), $Name, [StringComparison]::OrdinalIgnoreCase)) { return $a }
    }
    return $null
}

function Get-AwCliValue {
    # Value at a dotted path ('permissions.disableBypassPermissionsMode'), nested or as a literal dotted key.
    param($Data, [string]$Path)
    if ($Data -isnot [System.Collections.IDictionary]) { return $null }
    if ($Data.Contains($Path)) { return ,$Data[$Path] }
    $dot = $Path.IndexOf('.')
    while ($dot -gt 0) {
        $head = $Path.Substring(0, $dot)
        if ($Data.Contains($head)) {
            $found = Get-AwCliValue -Data $Data[$head] -Path $Path.Substring($dot + 1)
            if ($null -ne $found) { return ,$found }
        }
        $dot = $Path.IndexOf('.', $dot + 1)
    }
    return $null
}

function Get-AwCliBroadFolder {
    # Why a trusted folder is too broad ('a drive root', 'the home directory'...), or $null.
    param([string]$Folder, $Ctx)
    $f = $Folder.Trim()
    if ($f -eq '') { return $null }
    $n = $f.TrimEnd([char[]]@('\', '/'))
    if ($n -eq '') { return 'the file system root' }
    if ($n -match '^[A-Za-z]:$') { return 'a drive root' }
    if ($n -match '^(\\\\|//)[^\\/]+([\\/][^\\/]+)?$') { return 'a network share root' }
    if ($n -match '^(?i)(~|\$HOME|\$\{HOME\}|%USERPROFILE%|\$env:(USERPROFILE|HOME))$') { return 'the home directory' }
    if ($n -match '^(?i)([A-Za-z]:[\\/]Users|/home|/Users)$') { return 'the folder of all user profiles' }
    if ($n -match '^(?i)([A-Za-z]:[\\/]Users|/home|/Users)[\\/][^\\/]+$' -or $n -ceq '/root') { return 'the home directory' }
    $userProfile = [string](Get-AwMemberValue $Ctx 'UserProfile')
    if ($userProfile -and [string]::Equals($n.Replace('/', '\'), $userProfile.TrimEnd([char[]]@('\', '/')).Replace('/', '\'), [StringComparison]::OrdinalIgnoreCase)) {
        return 'the home directory'
    }
    return $null
}

function Get-AwCliCommandHooks {
    # Hook entries that run a command or call a URL: { Event; Type; Text }. Accepts the hook file
    # shape ({ version, hooks: { event: [...] } }) and the settings shape ({ event: [...] }).
    param($Hooks)
    if ($Hooks -isnot [System.Collections.IDictionary]) { return }
    if ($Hooks['hooks'] -is [System.Collections.IDictionary]) { $Hooks = $Hooks['hooks'] }
    $events = [string[]]@($Hooks.Keys)
    [Array]::Sort($events, [StringComparer]::Ordinal)
    foreach ($hookEvent in $events) {
        $entries = $Hooks[$hookEvent]
        if ($entries -isnot [System.Array]) { continue }
        foreach ($entry in $entries) {
            if ($entry -isnot [System.Collections.IDictionary]) { continue }
            # Claude-style groups ({ matcher, hooks: [...] }) are read as well.
            $handlers = @(if ($entry['hooks'] -is [System.Array]) { $entry['hooks'] } else { $entry })
            foreach ($h in $handlers) {
                if ($h -isnot [System.Collections.IDictionary]) { continue }
                $type = if ($h['type'] -is [string]) { $h['type'] } else { 'command' }
                if ($type -ceq 'http') {
                    $url = if ($h['url'] -is [string]) { $h['url'] } else { '' }
                    [pscustomobject]@{ Event = $hookEvent; Type = 'http'; Text = $url }
                    continue
                }
                if ($type -cne 'command') { continue }
                $text = $null
                foreach ($field in @('command', 'bash', 'powershell', 'exec')) {
                    if ($h[$field] -is [string] -and $h[$field].Trim() -ne '') { $text = $h[$field]; break }
                }
                if ($text) { [pscustomobject]@{ Event = $hookEvent; Type = 'command'; Text = $text } }
            }
        }
    }
}

function New-AwCliFinding {
    param([string]$RuleId, $Artifact, [string]$Needle, [string]$Key, [string]$Evidence)
    New-AwFinding -RuleId $RuleId -Evidence $Evidence `
        -Location @{ Path = $Artifact.Path; Line = (Find-AwLineNumber -Text $Artifact.Raw -Needle $Needle); Key = $Key }
}

# ---------------------------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------------------------

Register-AwRule -Id 'AW-CLI-001' -Title 'Copilot CLI trusts a folder that is too broad' `
    -Severity 'high' -Category 'approvals' -Harness 'copilot-cli' `
    -Description 'Trusted directories control where Copilot CLI can read, modify and execute files. The documentation advises against launching the CLI from the home directory. A trusted home directory, profile folder, drive root or file system root lets the agent work on every repository, credential and configuration file below it. The trust list lives in ~/.copilot/config.json, which the documentation describes as CLI-managed state that includes trusted folders; the key name (trusted_folders, also accepted as trustedFolders) is not documented, so confidence is medium.' `
    -Fix 'Remove the broad entry from the trusted folders (or reset them in the CLI), and trust each project folder when you first open it. Do not launch Copilot CLI from your home directory.' `
    -References @('OWASP-ASI03', 'OWASP-ASI02', $script:AwCliDocs.About, $script:AwCliDocs.ConfigDir) `
    -Confidence 'medium' -Check {
        param($Ctx)
        foreach ($a in @($Ctx.CopilotCli)) {
            if ($null -eq $a -or $a.Data -isnot [System.Collections.IDictionary]) { continue }
            foreach ($key in @('trusted_folders', 'trustedFolders')) {
                $list = $a.Data[$key]
                if ($list -isnot [System.Array]) { continue }
                foreach ($folder in $list) {
                    if ($folder -isnot [string]) { continue }
                    $why = Get-AwCliBroadFolder -Folder $folder -Ctx $Ctx
                    if ($why) {
                        New-AwCliFinding 'AW-CLI-001' $a ('"' + $key + '"') $key ("{0} contains '{1}' ({2})" -f $key, (Format-AwCommandSnippet $folder 120), $why)
                    }
                }
            }
        }
    }

Register-AwRule -Id 'AW-CLI-002' -Title 'Copilot CLI allows every URL without prompting' `
    -Severity 'medium' -Category 'sandbox-network' -Harness 'copilot-cli' `
    -Description 'allowedUrls in ~/.copilot/settings.json lists URLs or domains the agent may fetch without prompting. An entry that matches every host ("*", "https://*") or a whole top-level domain ("*.com") removes the prompt for any destination, so a prompt injection can send data out or pull instructions from a site it chooses. The documentation shows subdomain wildcards such as *.github.com, but not how a bare "*" is matched, so confidence is medium. allowedUrls is not a repository-overridable key, so only user settings are checked.' `
    -Fix 'List only the hosts you need (for example "docs.github.com" or "*.github.com"), and use deniedUrls, which takes precedence, for hosts that must never be reached.' `
    -References @('OWASP-ASI02', $script:AwCliDocs.ConfigDir) `
    -Confidence 'medium' -Check {
        param($Ctx)
        $a = Get-AwCliFile $Ctx 'settings.json' 'user'
        if ($null -eq $a) { return }
        $list = Get-AwCliValue -Data $a.Data -Path 'allowedUrls'
        if ($list -isnot [System.Array]) { return }
        foreach ($u in $list) {
            if ($u -isnot [string]) { continue }
            if ($u.Trim() -match '^(?i)(?:(?:https?|\*|https?\*)://)?\*(?:\.\*|\.[a-z0-9-]+)?(?::\d+|:\*)?(?:/\*?)?$') {
                New-AwCliFinding 'AW-CLI-002' $a '"allowedUrls"' 'allowedUrls' ("allowedUrls contains '{0}' (any host)" -f (Format-AwCommandSnippet $u 80))
            }
        }
    }

Register-AwRule -Id 'AW-CLI-003' -Title 'Repository settings run Copilot CLI hooks' `
    -Severity 'medium' -Category 'mcp-supply-chain' -Harness 'copilot-cli' `
    -Description 'hooks is a repository-overridable key of .github/copilot/settings.json: the commands it declares (type command, through command, bash, powershell or exec) and the URLs of http hooks run on agent events in every Copilot CLI session in the repository, with your rights. Anyone who can change the repository can change them. The rule is silent when disableAllHooks = true turns hooks off. Hook files in .github/hooks/ are analyzed by the VS Code rules.' `
    -Fix 'Review every hook command and the scripts it calls, protect .github/copilot/ with CODEOWNERS and required reviews, keep personal hooks in ~/.copilot/settings.json, and enforce organization hooks through policy hooks.' `
    -References @('OWASP-ASI04', 'OWASP-ASI05', $script:AwCliDocs.Hooks, $script:AwCliDocs.ConfigDir) `
    -Confidence 'high' -Check {
        param($Ctx)
        $repo = Get-AwCliFile $Ctx 'settings.json' 'project'
        if ($null -eq $repo) { return }
        # Precedence: local overrides (settings.local.json) > repository settings > user settings.
        $off = $null
        $localFile = Get-AwCliFile $Ctx 'settings.local.json' 'local'
        if ($localFile) { $off = Get-AwCliValue -Data $localFile.Data -Path 'disableAllHooks' }
        if ($null -eq $off) { $off = Get-AwCliValue -Data $repo.Data -Path 'disableAllHooks' }
        if ($null -eq $off) {
            $user = Get-AwCliFile $Ctx 'settings.json' 'user'
            if ($user) { $off = Get-AwCliValue -Data $user.Data -Path 'disableAllHooks' }
        }
        if ($off -is [bool] -and $off) { return }
        $hooks = @(Get-AwCliCommandHooks (Get-AwCliValue -Data $repo.Data -Path 'hooks'))
        $limit = 20
        for ($i = 0; $i -lt [Math]::Min($hooks.Count, $limit); $i++) {
            $h = $hooks[$i]
            $text = 'hook {0} {1}: {2}' -f $h.Event, $h.Type, (Format-AwCommandSnippet $h.Text)
            if ($i -eq $limit - 1 -and $hooks.Count -gt $limit) { $text += (' (and {0} more)' -f ($hooks.Count - $limit)) }
            New-AwCliFinding 'AW-CLI-003' $repo ('"' + $h.Event + '"') ('hooks.' + $h.Event) $text
        }
    }

Register-AwRule -Id 'AW-CLI-004' -Title 'Copilot CLI may store tokens in plain text' `
    -Severity 'medium' -Category 'secrets' -Harness 'copilot-cli' `
    -Description 'storeTokenPlaintext = true in ~/.copilot/settings.json allows authentication tokens to be stored in plain text in ~/.copilot/config.json when no system keychain is available. Any process, backup or sync tool that reads the profile then gets a GitHub token.' `
    -Fix 'Remove storeTokenPlaintext (default false) and use a system keychain or credential store, or provide a short-lived token through COPILOT_GITHUB_TOKEN in automation.' `
    -References @('OWASP-ASI03', $script:AwCliDocs.ConfigDir) `
    -Confidence 'high' -Check {
        param($Ctx)
        $a = Get-AwCliFile $Ctx 'settings.json' 'user'
        if ($null -eq $a) { return }
        $v = Get-AwCliValue -Data $a.Data -Path 'storeTokenPlaintext'
        if ($v -is [bool] -and $v) {
            New-AwCliFinding 'AW-CLI-004' $a '"storeTokenPlaintext"' 'storeTokenPlaintext' 'storeTokenPlaintext = true (user settings)'
        }
    }

Register-AwRule -Id 'AW-CLI-005' -Title 'Copilot CLI allow-all mode is not disabled' `
    -Severity 'info' -Category 'approvals' -Harness 'copilot-cli' `
    -Description 'permissions.disableBypassPermissionsMode = "disable" suppresses all allow-all flags (such as --allow-all-tools and the /allow-all and /yolo slash commands), and "allow-auto-only" blocks full allow-all but keeps /allow-all auto. The analyzed user settings set neither, so any session can approve every tool, path and URL at once, which the documentation warns can lead to data loss or other security issues. Managed (MDM) settings, where "disable" always wins, are not read by this analysis and may already enforce it.' `
    -Fix 'Set "permissions": { "disableBypassPermissionsMode": "disable" } in ~/.copilot/settings.json, or enforce it in managed settings, where "disable" always wins.' `
    -References @('OWASP-ASI02', $script:AwCliDocs.ConfigDir, $script:AwCliDocs.About) `
    -Confidence 'high' -Check {
        param($Ctx)
        $a = Get-AwCliFile $Ctx 'settings.json' 'user'
        if ($null -eq $a) { return }
        $v = Get-AwCliValue -Data $a.Data -Path 'permissions.disableBypassPermissionsMode'
        if ($v -is [string] -and ($v -ceq 'disable' -or $v -ceq 'allow-auto-only')) { return }
        New-AwCliFinding 'AW-CLI-005' $a '"permissions"' 'permissions.disableBypassPermissionsMode' 'permissions.disableBypassPermissionsMode is not set in user settings'
    }
