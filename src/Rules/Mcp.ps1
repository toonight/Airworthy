# MCP rules (AW-MCP-0xx), applied to Ctx.McpFiles from every client (VS Code, Claude Code, Copilot CLI).
# Each MCP artifact has Data.Servers (name -> server hashtable). Server entries come from hostile files:
# every field is type-checked and long strings are cut before they are analyzed.
# Sources (read 2026-10-18): code.visualstudio.com/docs/copilot/reference/mcp-configuration,
# code.claude.com/docs/en/mcp, docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference.

$script:AwMcpMaxServers    = 10     # AW-MCP-006 threshold (heuristic)
$script:AwMcpMaxTextLength = 8192   # longer values are cut before tokenizing
$script:AwMcpMaxArgs       = 256
$script:AwMcpMaxDepth      = 3      # wrapper nesting such as cmd /c bash -c "npx ..."

# Shell and interpreter names and flags (AW-MCP-004) live in src/Data/mcp.json, as separate tokens
# (CONTRIBUTING.md, Antivirus hygiene). The file is read on first use.
$script:AwMcpDataPath = [System.IO.Path]::Combine([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'Data'), 'mcp.json')
$script:AwMcpData = $null

function Get-AwMcpData {
    # Parsed src/Data/mcp.json, cached. Throws when the file is missing or invalid (the engine reports AW-CORE-002).
    if ($null -eq $script:AwMcpData) {
        $data = ConvertFrom-AwJsonc -Text ([System.IO.File]::ReadAllText($script:AwMcpDataPath))
        if ($data -isnot [System.Collections.IDictionary]) { throw "Invalid rule data file: $script:AwMcpDataPath" }
        $script:AwMcpData = $data
    }
    return $script:AwMcpData
}

function Get-AwMcpDataList {
    # The string items of a list in the data file (nothing when the key is absent). Call it inside @().
    param($Map, [string]$Key)
    if ($Map -isnot [System.Collections.IDictionary] -or -not $Map.Contains($Key)) { return }
    foreach ($item in @($Map[$Key])) { if ($null -ne $item) { [string]$item } }
}

function Get-AwMcpDataText {
    # A string value of the data file, or ''.
    param($Map, [string]$Key)
    if ($Map -isnot [System.Collections.IDictionary] -or -not $Map.Contains($Key) -or $null -eq $Map[$Key]) { return '' }
    return [string]$Map[$Key]
}

function Test-AwMcpFlagCluster {
    # True for a short option cluster ('-c', '-Ic', '-lc') that ends with, or with -Anywhere contains,
    # one of the given letters (case-sensitive).
    param([string]$Token, [string[]]$Letters, [switch]$Anywhere)
    if ($Token.Length -lt 2 -or $Token[0] -ne [char]'-') { return $false }
    $body = $Token.Substring(1)
    if ($body -cnotmatch '^[A-Za-z]+$') { return $false }
    foreach ($l in $Letters) {
        if ([string]::IsNullOrEmpty($l)) { continue }
        if ($Anywhere) {
            if ($body.IndexOf($l, [StringComparison]::Ordinal) -ge 0) { return $true }
        } elseif ($body.EndsWith($l, [StringComparison]::Ordinal)) {
            return $true
        }
    }
    return $false
}

# Well-known token formats, reported wherever they appear.
$script:AwMcpTokenPattern = '(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|sk-ant-[A-Za-z0-9_\-]{20,}|sk-(?:proj-)?[A-Za-z0-9_\-]{20,}|xox[abprs]-[A-Za-z0-9\-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35}|glpat-[A-Za-z0-9_\-]{20,}|npm_[A-Za-z0-9]{36}|-----BEGIN [A-Z ]*PRIVATE KEY-----)'
# Names of env variables, headers and flags that hold secrets.
$script:AwMcpSecretNamePattern = '(?i)(?:token|secret|passw(?:or)?d|api[_\-.]?key|access[_\-.]?key|private[_\-.]?key|credential|authorization|bearer|(?:^|[_\-.])(?:pat|pwd|pass|auth|key|cookie|session|sig|signature)(?:$|[_\-.]))'
# Values that refer to a secret instead of holding it: ${input:x}, ${env:X}, ${X}, ${X:-d}, $X, %X%, $env:X.
$script:AwMcpReferencePattern = '\$\{[^}]*\}|^\$[A-Za-z_][A-Za-z0-9_]*$|%[A-Za-z_][A-Za-z0-9_]*%|\$env:[A-Za-z_]'
$script:AwMcpPlaceholderPattern = '(?i)^(?:<[^>]*>|\[[^\]]*\]|\{[^}]*\}|your[-_ .].*|.*[-_]here|x{4,}|\*{3,}|\.{3,}|change[-_]?me|replace[-_]?me|placeholder|redacted|todo|tbd|none|null|example|sample)$'

# docker run options that take a value (the next argument is not the image).
$script:AwMcpDockerValueOptions = @(
    '-e', '--env', '--env-file', '-v', '--volume', '--mount', '-p', '--publish', '--name', '--network', '--net',
    '-w', '--workdir', '-u', '--user', '--entrypoint', '-l', '--label', '--label-file', '--add-host', '--cap-add',
    '--cap-drop', '--device', '--dns', '--dns-search', '--dns-option', '-h', '--hostname', '--ipc', '--pid', '--uts',
    '--userns', '--platform', '--pull', '--restart', '--runtime', '--security-opt', '--shm-size', '--tmpfs', '--ulimit',
    '-m', '--memory', '--memory-swap', '--cpus', '--cpu-shares', '-c', '--cpuset-cpus', '--gpus', '--log-driver',
    '--log-opt', '--expose', '--group-add', '--cidfile', '--stop-signal', '--stop-timeout', '--health-cmd',
    '--health-interval', '--health-retries', '--health-timeout', '--volumes-from', '--link', '--mac-address', '--ip',
    '--ip6', '--cgroupns', '--cgroup-parent', '--isolation', '--network-alias', '-a', '--attach', '--storage-opt',
    '--sysctl', '--pids-limit', '--annotation', '--domainname'
)

# ---------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------

function Get-AwMcpText {
    # A scalar JSON value as a string, cut to the analysis limit; $null for objects, arrays and null.
    param($Value)
    if ($null -eq $Value -or $Value -is [System.Collections.IDictionary] -or $Value -is [System.Array]) { return $null }
    $s = [string]$Value
    if ($s.Length -gt $script:AwMcpMaxTextLength) { $s = $s.Substring(0, $script:AwMcpMaxTextLength) }
    return $s
}

function Split-AwMcpCommandLine {
    # Splits a command line on whitespace, honoring single and double quotes.
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return }
    if ($Text.Length -gt $script:AwMcpMaxTextLength) { $Text = $Text.Substring(0, $script:AwMcpMaxTextLength) }
    $tokens = New-Object System.Collections.Generic.List[string]
    $sb = New-Object System.Text.StringBuilder
    $inQuote = $false
    $quoteChar = [char]'"'
    $pending = $false
    foreach ($ch in $Text.ToCharArray()) {
        if ($inQuote) {
            if ($ch -eq $quoteChar) { $inQuote = $false } else { [void]$sb.Append($ch) }
        } elseif ($ch -eq [char]'"' -or $ch -eq [char]"'") {
            $inQuote = $true; $quoteChar = $ch; $pending = $true
        } elseif ([char]::IsWhiteSpace($ch)) {
            if ($pending -or $sb.Length -gt 0) { $tokens.Add($sb.ToString()); [void]$sb.Clear(); $pending = $false }
        } else {
            [void]$sb.Append($ch)
        }
        if ($tokens.Count -ge $script:AwMcpMaxArgs) { break }
    }
    if ($pending -or $sb.Length -gt 0) { $tokens.Add($sb.ToString()) }
    $tokens.ToArray()
}

function Get-AwMcpProgramName {
    # Normalized program name: file name without directory or extension, lower case ('python3.12' -> 'python').
    param([string]$Command)
    $name = $Command.Trim().Trim([char[]]@('"', "'"))
    $i = $name.LastIndexOfAny([char[]]@('\', '/'))
    if ($i -ge 0) { $name = $name.Substring($i + 1) }
    $name = $name.ToLowerInvariant() -replace '\.(exe|cmd|bat|com|ps1|sh)$', ''
    if ($name -match '^(python|pypy)[0-9.]*w?$' -or $name -eq 'py') { return 'python' }
    if ($name -eq 'nodejs') { return 'node' }
    return $name
}

function Get-AwMcpCommandLine {
    # The server's command followed by its args, as one token list.
    # A command that contains spaces and has no args is split like a command line ("npx -y pkg").
    param($Server)
    $command = Get-AwMcpText $Server['command']
    if ($null -eq $command -or $command.Trim() -eq '') { return }
    $command = $command.Trim()
    $argv = New-Object System.Collections.Generic.List[string]
    $raw = $Server['args']
    if ($raw -is [System.Array]) {
        foreach ($a in $raw) {
            $t = Get-AwMcpText $a
            if ($null -ne $t) { $argv.Add($t) }
            if ($argv.Count -ge $script:AwMcpMaxArgs) { break }
        }
    } elseif ($null -ne (Get-AwMcpText $raw)) {
        foreach ($t in @(Split-AwMcpCommandLine (Get-AwMcpText $raw))) { $argv.Add($t) }
    }
    if ($argv.Count -eq 0 -and $command -match '\s' -and $command -notmatch '^([A-Za-z]:[\\/]|/)') {
        return (Split-AwMcpCommandLine $command)
    }
    $command
    $argv.ToArray()
}

function Test-AwMcpReference {
    param([string]$Value)
    return ($Value -match $script:AwMcpReferencePattern)
}

function Test-AwMcpPlaceholder {
    # True for obvious placeholders: <token>, YOUR_KEY, xxxx, ***, or a token format filled with x.
    param([string]$Value)
    $v = $Value.Trim()
    if ($v -match $script:AwMcpPlaceholderPattern) { return $true }
    $body = $v -replace '^(gh[pousr]_|github_pat_|sk-ant-|sk-proj-|sk-|xox[abprs]-|AKIA|AIza|glpat-|npm_)', ''
    return ($body -match '^[xX*.0_\-]+$' -or $body -match '(?i)^(your|example|placeholder)')
}

function Test-AwMcpLiteralSecret {
    # True when a value stored under a secret-looking name is a literal secret (not a reference,
    # placeholder, path, URL, number or boolean).
    param([string]$Value)
    $v = $Value.Trim()
    if ($v.Length -lt 8) { return $false }
    if (Test-AwMcpReference $v) { return $false }
    if (Test-AwMcpPlaceholder $v) { return $false }
    if ($v -match '\s' -or $v -match '^\d+$') { return $false }
    if ($v -match '^(?i)(true|false|yes|no|on|off)$') { return $false }
    if ($v -match '^[A-Za-z][A-Za-z0-9+.\-]*://') { return $false }
    if ($v -match '^(\.{1,2}[\\/]|~[\\/]|[A-Za-z]:[\\/]|/)' -or $v -match '(?i)\.(json|pem|key|crt|cer|p12|pfx|txt|ya?ml|env|toml|ini)$') { return $false }
    return $true
}

# name=value / name: value pairs, and --name value flags, whose name looks like a secret (evidence masking).
$script:AwSecretWords = '(?:token|secret|passw(?:or)?d|pwd|api[_.\-]?key|apikey|access[_.\-]?key|private[_.\-]?key|credential|authorization)'
$script:AwSecretPairPattern = '(?i)(?<k>[A-Za-z0-9_.\-]*' + $script:AwSecretWords + '[A-Za-z0-9_.\-]*)(?<sep>\s*[=:]\s*(?:(?:bearer|basic|token)\s+)?)(?<v>"[^"]*"|''[^'']*''|[^\s"'';&|,)]+)'
$script:AwSecretFlagPattern = '(?i)(?<k>--?[A-Za-z0-9_.\-]*' + $script:AwSecretWords + '[A-Za-z0-9_.\-]*)(?<sep>\s+(?:(?:bearer|basic|token)\s+)?)(?<v>"[^"]*"|''[^'']*''|[^\s\-"''][^\s"'';&|,)]*)'

function Format-AwCommandSnippet {
    # Evidence text for a command line, URL or path, shared by the MCP, Claude Code and Copilot CLI rules:
    # well-known tokens, secret-looking name=value pairs and flags, and URL passwords are masked, then the text is shortened.
    param([string]$Text, [int]$Max = 100)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $t = ($Text -replace '[\r\n\t]+', ' ').Trim()
    if ($t.Length -gt 4 * $Max + 256) { $t = $t.Substring(0, 4 * $Max + 256) }
    $t = [regex]::Replace($t, $script:AwMcpTokenPattern, { param($m) Hide-AwSecret -Value $m.Value })
    $t = [regex]::Replace($t, '(?<=://[^/@:\s]*:)[^/@\s]+(?=@)', '****')
    $mask = {
        param($m)
        $v = $m.Groups['v'].Value
        # Keep references (${X}, $X, %X%) and values that are already masked.
        if ($v -match $script:AwMcpReferencePattern -or $v.Contains($script:AwEllipsis)) { return $m.Value }
        $m.Groups['k'].Value + $m.Groups['sep'].Value + (Hide-AwSecret -Value $v.Trim([char[]]@('"', "'")))
    }
    $t = [regex]::Replace($t, $script:AwSecretPairPattern, $mask)
    $t = [regex]::Replace($t, $script:AwSecretFlagPattern, $mask)
    $t = Hide-AwSecretsInText $t
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + '...' }
    return $t
}

function Get-AwMcpUrlSecret {
    # Masked credential embedded in a URL (user:password@ or a secret query parameter), or $null.
    param([string]$Url)
    $m = [regex]::Match($Url, '^[A-Za-z][A-Za-z0-9+.\-]*://[^/@:\s]*:(?<pw>[^/@\s]+)@')
    if ($m.Success) {
        $pw = $m.Groups['pw'].Value
        if (-not (Test-AwMcpReference $pw) -and -not (Test-AwMcpPlaceholder $pw)) { return 'password in URL = ' + (Hide-AwSecret -Value $pw) }
    }
    $q = [regex]::Match($Url, '(?i)[?&](?<k>access[_\-]?token|api[_\-]?key|apikey|key|token|secret|password|pwd|sig|signature|auth)=(?<v>[^&#\s]+)')
    if ($q.Success -and (Test-AwMcpLiteralSecret $q.Groups['v'].Value)) {
        return ('URL parameter {0} = {1}' -f $q.Groups['k'].Value, (Hide-AwSecret -Value $q.Groups['v'].Value))
    }
    return $null
}

function Get-AwMcpNamedSecret {
    # Masked display of a secret held under Name (env variable, header or flag), or $null.
    param([string]$Name, [string]$Value)
    $v = $Value.Trim()
    $token = [regex]::Match($v, $script:AwMcpTokenPattern)
    if ($token.Success -and -not (Test-AwMcpPlaceholder $token.Value)) { return (Format-AwCommandSnippet $v 120) }
    if ($v -match '^[A-Za-z][A-Za-z0-9+.\-]*://') { return (Get-AwMcpUrlSecret $v) }
    if ($Name -notmatch $script:AwMcpSecretNamePattern) { return $null }
    $scheme = ''
    $m = [regex]::Match($v, '^(?i)(bearer|basic|token|apikey)\s+(?<rest>\S.*)$')
    if ($m.Success) { $scheme = $v.Substring(0, $m.Groups['rest'].Index); $v = $m.Groups['rest'].Value }
    if (Test-AwMcpLiteralSecret $v) { return $scheme + (Hide-AwSecret -Value $v) }
    return $null
}

function Get-AwMcpSecrets {
    # Hardcoded secrets of one server: { Where; Key; Needle; Masked } for env, headers, args, command and url.
    param($Server)
    $found = New-Object System.Collections.ArrayList
    $seen = @{}
    $add = {
        param($Where, $Key, $Needle, $Masked)
        if ($seen.ContainsKey($Where)) { return }
        $seen[$Where] = $true
        [void]$found.Add([pscustomobject]@{ Where = $Where; Key = $Key; Needle = $Needle; Masked = $Masked })
    }
    foreach ($field in @('env', 'headers')) {
        $map = $Server[$field]
        if ($map -isnot [System.Collections.IDictionary]) { continue }
        $names = [string[]]@($map.Keys)
        [Array]::Sort($names, [StringComparer]::Ordinal)
        foreach ($name in $names) {
            $value = Get-AwMcpText $map[$name]
            if ($null -eq $value) { continue }
            $masked = Get-AwMcpNamedSecret -Name $name -Value $value
            if ($masked) { & $add "$field $name" "$field.$name" ('"' + $name + '"') $masked }
        }
    }
    $tokens = @(Get-AwMcpCommandLine $Server)
    for ($i = 0; $i -lt $tokens.Count; $i++) {
        $t = $tokens[$i]
        $flag = [regex]::Match($t, '^--?(?<k>[A-Za-z][A-Za-z0-9_\-.]*)=(?<v>.+)$')
        $header = [regex]::Match($t, '^(?<k>[A-Za-z][A-Za-z0-9_\-]*)\s*:\s*(?<v>\S.*)$')
        $masked = $null
        $where = 'args'
        if ($flag.Success) {
            $masked = Get-AwMcpNamedSecret -Name $flag.Groups['k'].Value -Value $flag.Groups['v'].Value
            $where = 'args --' + $flag.Groups['k'].Value
        } elseif ($header.Success -and $header.Groups['k'].Value -match $script:AwMcpSecretNamePattern) {
            $masked = Get-AwMcpNamedSecret -Name $header.Groups['k'].Value -Value $header.Groups['v'].Value
            $where = 'args header ' + $header.Groups['k'].Value
        } elseif ($t -match '^--?[A-Za-z][A-Za-z0-9_\-.]*$' -and $t.TrimStart('-') -match $script:AwMcpSecretNamePattern -and
                  $i + 1 -lt $tokens.Count -and -not $tokens[$i + 1].StartsWith('-')) {
            $masked = Get-AwMcpNamedSecret -Name $t.TrimStart('-') -Value $tokens[$i + 1]
            if ($masked) { $where = 'args ' + $t; $i++ }
        }
        if (-not $masked) {
            $masked = Get-AwMcpNamedSecret -Name '' -Value $t
            $where = if ($i -eq 0) { 'command' } else { 'args[{0}]' -f ($i - 1) }
        }
        if ($masked) { & $add $where 'args' '"args"' $masked }
    }
    $url = Get-AwMcpText $Server['url']
    if ($url) {
        $masked = Get-AwMcpNamedSecret -Name '' -Value $url
        if ($masked) { & $add 'url' 'url' '"url"' $masked }
    }
    $found.ToArray()
}

function Get-AwMcpShellInfo {
    # For a shell or interpreter invocation: { Flag; Code; Inline (bool); Inner (tokens or $null) }, else $null.
    # Inline is true when code is passed on the command line; Inner is the wrapped command to analyze next.
    param([string[]]$Tokens)
    if ($Tokens.Count -lt 2) { return $null }
    $prog = Get-AwMcpProgramName $Tokens[0]
    $rest = { param([int]$From) if ($From -lt $Tokens.Count) { @($Tokens[$From..($Tokens.Count - 1)]) } else { @() } }
    $info = { param($Flag, $Code, $Inline, $Inner) [pscustomobject]@{ Flag = $Flag; Code = $Code; Inline = $Inline; Inner = $Inner } }
    $innerOf = {
        param([string[]]$Parts)
        if ($Parts.Count -eq 1) { return ,@(Split-AwMcpCommandLine $Parts[0]) }
        return ,$Parts
    }

    $data = Get-AwMcpData

    # cmd /c: a plain "cmd /c npx pkg" is the usual Windows launcher; shell operators make it inline code.
    $cmd = $data['cmd']
    if (@(Get-AwMcpDataList $cmd 'programs') -contains $prog) {
        $inlineFlags = @(Get-AwMcpDataList $cmd 'inlineFlags')
        $operators = (Get-AwMcpDataText $cmd 'operators').ToCharArray()
        for ($i = 1; $i -lt $Tokens.Count; $i++) {
            if ($inlineFlags -contains $Tokens[$i]) {
                $parts = @(& $rest ($i + 1))
                if ($parts.Count -eq 0) { return $null }
                $code = $parts -join ' '
                return (& $info $Tokens[$i] $code ($code.IndexOfAny($operators) -ge 0) (& $innerOf $parts))
            }
        }
        return $null
    }

    # PowerShell hosts accept any unambiguous prefix of a parameter name, with - or /.
    $ps = $data['powershell']
    if (@(Get-AwMcpDataList $ps 'programs') -contains $prog) {
        $commandFlag = Get-AwMcpDataText $ps 'commandFlag'
        $encodedFlag = Get-AwMcpDataText $ps 'encodedFlag'
        $encodedAliases = @(Get-AwMcpDataList $ps 'encodedAliases')
        $fileFlags = @(Get-AwMcpDataList $ps 'fileFlags')
        for ($i = 1; $i -lt $Tokens.Count; $i++) {
            $t = $Tokens[$i]
            if ($t -notmatch '^[-/][A-Za-z]+$') { continue }
            $name = $t.Substring(1).ToLowerInvariant()
            if ($fileFlags -contains $name) { return $null }
            if ($commandFlag -and $commandFlag.StartsWith($name, [StringComparison]::Ordinal)) {
                $parts = @(& $rest ($i + 1))
                if ($parts.Count -eq 0) { return $null }
                return (& $info $t ($parts -join ' ') $true (& $innerOf $parts))
            }
            if ($encodedAliases -contains $name -or ($encodedFlag -and $encodedFlag.StartsWith($name, [StringComparison]::Ordinal))) {
                # The encoded value is never decoded or shown.
                $code = if ($i + 1 -lt $Tokens.Count) { '(encoded value not shown)' } else { '' }
                return (& $info $t $code $true $null)
            }
        }
        return $null
    }

    # POSIX shells: the inline-code letter can sit anywhere in a short option cluster (-c, -lc).
    $posix = $data['posixShells']
    if (@(Get-AwMcpDataList $posix 'programs') -contains $prog) {
        $letters = @(Get-AwMcpDataList $posix 'inlineLetter')
        $valueFlags = @(Get-AwMcpDataList $posix 'valueFlags')
        for ($i = 1; $i -lt $Tokens.Count; $i++) {
            $t = $Tokens[$i]
            if ($t -eq '--' -or -not ($t.StartsWith('-') -or $t.StartsWith('+'))) { return $null }
            if (Test-AwMcpFlagCluster -Token $t -Letters $letters -Anywhere) {
                $code = if ($i + 1 -lt $Tokens.Count) { $Tokens[$i + 1] } else { '' }
                return (& $info $t $code $true @(Split-AwMcpCommandLine $code))
            }
            if ($valueFlags -ccontains $t) { $i++ }
        }
        return $null
    }

    # wsl: the command after the wsl options is analyzed next; wsl itself is not inline code.
    $wsl = $data['wsl']
    if (@(Get-AwMcpDataList $wsl 'programs') -contains $prog) {
        $valueOptions = @(Get-AwMcpDataList $wsl 'valueOptions')
        $passThrough = @(Get-AwMcpDataList $wsl 'passThrough')
        $i = 1
        while ($i -lt $Tokens.Count) {
            $t = $Tokens[$i]
            if ($valueOptions -ccontains $t) { $i += 2; continue }
            if ($passThrough -ccontains $t) { $i++; continue }
            break
        }
        $parts = @(& $rest $i)
        if ($parts.Count -eq 0) { return $null }
        return (& $info $prog ($parts -join ' ') $false $parts)
    }

    # Interpreters: the inline-code flag must come before the script or module name.
    $interpreters = $data['interpreters']
    if ($interpreters -isnot [System.Collections.IDictionary] -or -not $interpreters.Contains($prog)) { return $null }
    $spec = $interpreters[$prog]
    $subcommands = @(Get-AwMcpDataList $spec 'subcommands')
    if ($subcommands.Count -gt 0) {
        if ($subcommands -ccontains $Tokens[1]) { return (& $info $Tokens[1] ((& $rest 2) -join ' ') $true $null) }
        return $null
    }
    $flags = @(Get-AwMcpDataList $spec 'flags')
    $letters = @(Get-AwMcpDataList $spec 'clusterLetters')
    $assignFlags = @(Get-AwMcpDataList $spec 'assignFlags')
    $stop = @(Get-AwMcpDataList $data 'scriptStop')
    for ($i = 1; $i -lt $Tokens.Count; $i++) {
        $t = $Tokens[$i]
        if (-not $t.StartsWith('-') -or $stop -ccontains $t) { return $null }
        $eq = $t.IndexOf('=')
        if ($eq -gt 0 -and $assignFlags -ccontains $t.Substring(0, $eq)) { return (& $info $t $t.Substring($eq + 1) $true $null) }
        if ($flags -ccontains $t -or ($letters.Count -gt 0 -and (Test-AwMcpFlagCluster -Token $t -Letters $letters))) {
            $code = if ($i + 1 -lt $Tokens.Count) { $Tokens[$i + 1] } else { '' }
            return (& $info $t $code $true $null)
        }
    }
    return $null
}

function Get-AwMcpInvocations {
    # The server's command line, then the commands it wraps (cmd /c, sh -c, powershell -Command, wsl).
    param($Server)
    $tokens = @(Get-AwMcpCommandLine $Server)
    $out = New-Object System.Collections.ArrayList
    $depth = 0
    while ($tokens.Count -gt 0 -and $depth -le $script:AwMcpMaxDepth) {
        $shell = Get-AwMcpShellInfo -Tokens $tokens
        [void]$out.Add([pscustomobject]@{ Tokens = [string[]]$tokens; Program = (Get-AwMcpProgramName $tokens[0]); Shell = $shell })
        if ($null -eq $shell -or $null -eq $shell.Inner) { break }
        $tokens = @($shell.Inner | Where-Object { $_ -ne '' })
        $depth++
    }
    $out.ToArray()
}

function Test-AwMcpNpmPinned {
    # $true for an exact version, $false for a missing version, a tag or a range, $null for a local path.
    param([string]$Spec)
    if ($Spec -match '^(\.{0,2}[\\/]|[A-Za-z]:[\\/]|file:|~)' -or $Spec -match '(?i)\.(tgz|tar\.gz)$') { return $null }
    if ($Spec -match '^(?i)(git\+|git:|github:|gitlab:|bitbucket:|https?://)') { return ($Spec -match '#[0-9a-fA-F]{40}$') }
    if (Test-AwMcpReference $Spec) { return $null }
    $m = [regex]::Match($Spec, '^(@[^/@\s]+/)?[^@\s/]+(@(?<v>.*))?$')
    if (-not $m.Success) { return $null }
    if (-not $m.Groups['v'].Success) { return $false }
    return ($m.Groups['v'].Value -match '^v?\d+\.\d+\.\d+(-[0-9A-Za-z.\-]+)?(\+[0-9A-Za-z.\-]+)?$')
}

function Test-AwMcpPythonPinned {
    # $true for pkg==1.2.3 or pkg@1.2.3 (or a git commit), $false otherwise, $null for a local path.
    param([string]$Spec)
    if ($Spec -match '^(\.{0,2}[\\/]|[A-Za-z]:[\\/]|~|\.$)' -or $Spec -match '(?i)\.(whl|tar\.gz|zip)$') { return $null }
    if (Test-AwMcpReference $Spec) { return $null }
    if ($Spec -match '(?i)(git\+|https?://)') { return ($Spec -match '@[0-9a-fA-F]{40}($|#)') }
    if ($Spec -match '^[A-Za-z0-9][A-Za-z0-9._\-]*(\[[^\]]*\])?\s*===?\s*[0-9][0-9A-Za-z.\-+!]*$') { return $true }
    $m = [regex]::Match($Spec, '^[A-Za-z0-9][A-Za-z0-9._\-]*(\[[^\]]*\])?@(?<v>.+)$')
    if ($m.Success) { return ($m.Groups['v'].Value -match '^v?[0-9]') }
    return $false
}

function Get-AwMcpLauncherSpec {
    # Package spec run by a package launcher: { Launcher; Spec; Kind ('npm'|'python') }, or $null.
    param([string[]]$Tokens)
    $prog = Get-AwMcpProgramName $Tokens[0]
    $second = if ($Tokens.Count -gt 1) { $Tokens[1] } else { '' }
    $third = if ($Tokens.Count -gt 2) { $Tokens[2] } else { '' }
    $start = -1; $kind = $null; $launcher = $prog
    if (@('npx', 'bunx', 'pnpx') -contains $prog) { $start = 1; $kind = 'npm' }
    elseif ($prog -eq 'npm' -and ($second -ceq 'exec' -or $second -ceq 'x')) { $start = 2; $kind = 'npm'; $launcher = "npm $second" }
    elseif (($prog -eq 'pnpm' -or $prog -eq 'yarn') -and $second -ceq 'dlx') { $start = 2; $kind = 'npm'; $launcher = "$prog dlx" }
    elseif ($prog -eq 'bun' -and $second -ceq 'x') { $start = 2; $kind = 'npm'; $launcher = 'bun x' }
    elseif ($prog -eq 'uvx') { $start = 1; $kind = 'uv' }
    elseif ($prog -eq 'uv' -and $second -ceq 'tool' -and $third -ceq 'run') { $start = 3; $kind = 'uv'; $launcher = 'uv tool run' }
    elseif ($prog -eq 'pipx' -and $second -ceq 'run') { $start = 2; $kind = 'pipx'; $launcher = 'pipx run' }
    if ($start -lt 0) { return $null }

    $valueOptions = switch ($kind) {
        'npm'  { @('-c', '--call', '--registry', '--cache', '--userconfig', '--prefix', '-w', '--workspace') }
        'uv'   { @('--with', '--with-editable', '--with-requirements', '--python', '-p', '--index', '--index-url',
                   '--extra-index-url', '--default-index', '--find-links', '-f', '--cache-dir', '--config-file',
                   '--directory', '--project', '--env-file', '-c', '--constraints', '--overrides', '--build-constraints') }
        'pipx' { @('--python', '--index-url', '-i', '--pip-args', '--backend') }
    }
    $specOptions = switch ($kind) { 'npm' { @('-p', '--package') } 'uv' { @('--from') } 'pipx' { @('--spec') } }
    $specs = New-Object System.Collections.Generic.List[string]
    $i = $start
    while ($i -lt $Tokens.Count) {
        $t = $Tokens[$i]
        if ($t -eq '--') { if ($specs.Count -eq 0 -and $i + 1 -lt $Tokens.Count) { $specs.Add($Tokens[$i + 1]) }; break }
        $eq = $t.IndexOf('=')
        if ($t.StartsWith('-') -and $eq -gt 0 -and $specOptions -ccontains $t.Substring(0, $eq)) { $specs.Add($t.Substring($eq + 1)); $i++; continue }
        if ($specOptions -ccontains $t) { if ($i + 1 -lt $Tokens.Count) { $specs.Add($Tokens[$i + 1]) }; $i += 2; continue }
        if ($t.StartsWith('-')) { if ($eq -lt 0 -and $valueOptions -ccontains $t) { $i += 2 } else { $i++ }; continue }
        # With an explicit package option, the first positional argument is the command to run.
        if ($specs.Count -eq 0) { $specs.Add($t) }
        break
    }
    if ($specs.Count -eq 0) { return $null }
    [pscustomobject]@{ Launcher = $launcher; Spec = $specs[0]; Kind = $(if ($kind -eq 'npm') { 'npm' } else { 'python' }) }
}

function Get-AwMcpDockerRun {
    # Options and image of 'docker run' or 'podman run': { Image; Options ({ Name; Value }[]) }, or $null.
    param([string[]]$Tokens)
    $prog = Get-AwMcpProgramName $Tokens[0]
    if ($prog -ne 'docker' -and $prog -ne 'podman') { return $null }
    $i = 1
    while ($i -lt $Tokens.Count -and $Tokens[$i].StartsWith('-')) {
        if (@('-H', '--host', '--context', '-c', '--config', '-l', '--log-level', '--tlscacert', '--tlscert', '--tlskey') -ccontains $Tokens[$i]) { $i += 2 } else { $i++ }
    }
    if ($i -lt $Tokens.Count -and $Tokens[$i] -ceq 'container') { $i++ }
    if ($i -ge $Tokens.Count -or $Tokens[$i] -cne 'run') { return $null }
    $i++
    $options = New-Object System.Collections.ArrayList
    $image = $null
    while ($i -lt $Tokens.Count) {
        $t = $Tokens[$i]
        if ($t -eq '--') { if ($i + 1 -lt $Tokens.Count) { $image = $Tokens[$i + 1] }; break }
        if (-not $t.StartsWith('-') -or $t -eq '-') { $image = $t; break }
        $eq = $t.IndexOf('=')
        if ($t.StartsWith('--') -and $eq -gt 0) {
            [void]$options.Add([pscustomobject]@{ Name = $t.Substring(0, $eq); Value = $t.Substring($eq + 1) })
            $i++; continue
        }
        if ($script:AwMcpDockerValueOptions -ccontains $t) {
            $v = if ($i + 1 -lt $Tokens.Count) { $Tokens[$i + 1] } else { $null }
            [void]$options.Add([pscustomobject]@{ Name = $t; Value = $v })
            $i += 2; continue
        }
        [void]$options.Add([pscustomobject]@{ Name = $t; Value = $null })
        $i++
    }
    [pscustomobject]@{ Image = $image; Options = $options.ToArray() }
}

function Test-AwMcpImagePinned {
    # $true for a digest or a tag other than 'latest', $false otherwise, $null for a variable.
    param([string]$Image)
    if ([string]::IsNullOrEmpty($Image) -or (Test-AwMcpReference $Image)) { return $null }
    if ($Image -match '@sha256:[0-9a-fA-F]{64}$') { return $true }
    $last = $Image.Substring($Image.LastIndexOf('/') + 1)
    $colon = $last.LastIndexOf(':')
    if ($colon -lt 0) { return $false }
    $tag = $last.Substring($colon + 1)
    return ($tag -ne '' -and $tag -cne 'latest')
}

function Get-AwMcpBroadHostPath {
    # What a host path exposes when mounted ('the file system root', 'the home directory', 'the Docker socket'), or $null.
    param([string]$Path, $Ctx)
    if ([string]::IsNullOrEmpty($Path)) { return $null }
    $p = $Path.Trim().Trim([char[]]@('"', "'"))
    if ($p -eq '') { return $null }
    if ($p -match '(?i)docker\.sock$|docker_engine$') { return 'the Docker socket' }
    $n = $p.TrimEnd([char[]]@('\', '/'))
    if ($n -eq '' -or $n -match '^[A-Za-z]:$') { return 'the file system root' }
    if ($n -match '^(?i)(~|\$HOME|\$\{HOME\}|\$\{userHome\}|%USERPROFILE%|%HOMEDRIVE%%HOMEPATH%|\$\{env:(USERPROFILE|HOME)\}|\$env:(USERPROFILE|HOME))$') { return 'the home directory' }
    if ($n -match '^(?i)([A-Za-z]:[\\/]Users|/home|/Users)([\\/][^\\/]+)?$' -or $n -ceq '/root') { return 'the home directory' }
    $userProfile = [string](Get-AwMemberValue $Ctx 'UserProfile')
    if ($userProfile -and [string]::Equals($n, $userProfile.TrimEnd([char[]]@('\', '/')), [StringComparison]::OrdinalIgnoreCase)) { return 'the home directory' }
    return $null
}

function Get-AwMcpDockerRisks {
    # Dangerous 'docker run' options: privileged mode, host namespaces, broad capabilities, broad mounts.
    param($Run, $Ctx)
    foreach ($o in $Run.Options) {
        $name = [string]$o.Name
        $value = [string]$o.Value
        if ($name -ceq '--privileged' -and $value -ne 'false') { '--privileged (full access to the host devices)' }
        elseif (($name -ceq '--network' -or $name -ceq '--net') -and $value -eq 'host') { "$name host (shares the host network, including localhost services)" }
        elseif (($name -ceq '--pid' -or $name -ceq '--ipc' -or $name -ceq '--uts' -or $name -ceq '--userns') -and $value -eq 'host') { "$name host (shares a host namespace)" }
        elseif ($name -ceq '--cap-add' -and $value -match '^(?i)(CAP_)?(ALL|SYS_ADMIN)$') { "--cap-add $value" }
        elseif ($name -ceq '-v' -or $name -ceq '--volume') {
            $m = [regex]::Match($value, '^(?<src>\$\{[^}]*\}[^:]*|[A-Za-z]:[\\/][^:]*|[A-Za-z]:|[^:]*)(?::|$)')
            $what = if ($m.Success) { Get-AwMcpBroadHostPath -Path $m.Groups['src'].Value -Ctx $Ctx } else { $null }
            if ($what) { "$name $value (mounts $what)" }
        }
        elseif ($name -ceq '--mount') {
            $src = $null
            foreach ($part in $value.Split(',')) {
                $kv = $part.Split([char[]]@('='), 2)
                if ($kv.Count -eq 2 -and @('source', 'src') -contains $kv[0].Trim()) { $src = $kv[1] }
            }
            $what = Get-AwMcpBroadHostPath -Path $src -Ctx $Ctx
            if ($what) { "--mount $value (mounts $what)" }
        }
    }
}

function Get-AwMcpServers {
    # Every (file, name, server) triple, in a stable order.
    param($Ctx)
    foreach ($file in @($Ctx.McpFiles)) {
        if ($null -eq $file -or $file.Data -isnot [System.Collections.IDictionary]) { continue }
        $servers = $file.Data['Servers']
        if ($servers -isnot [System.Collections.IDictionary]) { continue }
        $names = [string[]]@($servers.Keys)
        [Array]::Sort($names, [StringComparer]::Ordinal)
        foreach ($name in $names) {
            if ($servers[$name] -isnot [System.Collections.IDictionary]) { continue }
            [pscustomobject]@{ File = $file; Name = $name; Server = $servers[$name] }
        }
    }
}

function Get-AwMcpLine {
    # Best-effort line of Needle inside a server entry, or of the server name itself.
    param([string]$Raw, [string]$Server, [string]$Needle)
    if ([string]::IsNullOrEmpty($Raw)) { return $null }
    $start = 0
    $name = $Server
    # 'name (project: path)' entries of ~/.claude.json. String search, not a regex: server names come
    # from hostile files and a backtracking pattern was quadratic on a long name.
    $marker = $Server.LastIndexOf(' (project: ', [StringComparison]::Ordinal)
    if ($marker -ge 0 -and $Server.EndsWith(')', [StringComparison]::Ordinal)) {
        $name = $Server.Substring(0, $marker)
        $projectPath = $Server.Substring($marker + 11, $Server.Length - $marker - 12)
        $p = $Raw.IndexOf('"' + $projectPath + '"', [StringComparison]::Ordinal)
        if ($p -ge 0) { $start = $p }
    }
    $at = $Raw.IndexOf('"' + $name + '"', $start, [StringComparison]::Ordinal)
    if ($at -lt 0) { return $null }
    if ($Needle) {
        $n = $Raw.IndexOf($Needle, $at, [StringComparison]::Ordinal)
        if ($n -ge 0) { $at = $n }
    }
    $line = 1
    $pos = $Raw.IndexOf("`n", 0, $at, [StringComparison]::Ordinal)
    while ($pos -ge 0) {
        $line++
        if ($pos + 1 -ge $at) { break }
        $pos = $Raw.IndexOf("`n", $pos + 1, $at - $pos - 1, [StringComparison]::Ordinal)
    }
    return $line
}

function New-AwMcpFinding {
    param([string]$RuleId, $Entry, [string]$Needle, [string]$Key, [string]$Evidence, [string]$Severity)
    $location = @{ Path = $Entry.File.Path; Line = (Get-AwMcpLine -Raw $Entry.File.Raw -Server $Entry.Name -Needle $Needle); Key = ($Entry.Name + $(if ($Key) { ".$Key" } else { '' })) }
    if ($Severity) { return (New-AwFinding -RuleId $RuleId -Severity $Severity -Evidence $Evidence -Location $location) }
    New-AwFinding -RuleId $RuleId -Evidence $Evidence -Location $location
}

# ---------------------------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------------------------

Register-AwRule -Id 'AW-MCP-001' -Title 'MCP server launched without a pinned version' `
    -Severity 'high' -Category 'mcp-supply-chain' -Harness 'mcp' `
    -Description 'Checks how each stdio MCP server is launched. npx (and npm exec, pnpm/yarn dlx, bunx), uvx, uv tool run and pipx run download the package when the server starts; without an exact version (or with @latest, a tag or a range) a new release, or a hijacked package, runs with the agent''s privileges and no review. The same holds for docker run with an image that has no tag, the latest tag, or no digest. Wrappers such as cmd /c, sh -c and powershell -Command are unwrapped. Local paths are not checked.' `
    -Fix 'Pin an exact version: npx -y @scope/server@1.4.2, uvx package==1.4.2 (or package@1.4.2), pipx run --spec package==1.4.2 package, or docker run image@sha256:<digest>. Review each update before you change the version.' `
    -References @('OWASP-ASI04', 'https://code.visualstudio.com/docs/copilot/reference/mcp-configuration', 'https://code.claude.com/docs/en/mcp') `
    -Confidence 'high' -Check {
        param($Ctx)
        foreach ($entry in @(Get-AwMcpServers $Ctx)) {
            $reported = $false
            foreach ($inv in @(Get-AwMcpInvocations $entry.Server)) {
                $tokens = $inv.Tokens
                $why = $null
                $spec = Get-AwMcpLauncherSpec -Tokens $tokens
                if ($spec) {
                    $pinned = if ($spec.Kind -eq 'npm') { Test-AwMcpNpmPinned $spec.Spec } else { Test-AwMcpPythonPinned $spec.Spec }
                    if ($pinned -eq $false) { $why = "{0} runs '{1}' without a pinned version" -f $spec.Launcher, $spec.Spec }
                } else {
                    $run = Get-AwMcpDockerRun -Tokens $tokens
                    if ($run -and $run.Image -and (Test-AwMcpImagePinned $run.Image) -eq $false) {
                        $why = "{0} run uses image '{1}' without a fixed tag or digest" -f $inv.Program, $run.Image
                    }
                }
                if (-not $why) {
                    $latest = @($tokens | Where-Object { $_ -match '(?i)@latest$' } | Select-Object -First 1)
                    if ($latest.Count -gt 0) { $why = "'{0}' requests the latest release" -f $latest[0] }
                }
                if ($why) {
                    $evidence = "server '{0}': {1} ({2})" -f $entry.Name, (Format-AwCommandSnippet $why 160), (Format-AwCommandSnippet ($tokens -join ' '))
                    New-AwMcpFinding -RuleId 'AW-MCP-001' -Entry $entry -Needle '"args"' -Key 'command' -Evidence $evidence
                    $reported = $true
                }
                if ($reported) { break }
            }
        }
    }

Register-AwRule -Id 'AW-MCP-002' -Title 'Hardcoded secret in an MCP server configuration' `
    -Severity 'critical' -Category 'secrets' -Harness 'mcp' `
    -Description 'Looks for literal secrets in the env, headers, args, command and url of each MCP server: values of variables, headers or flags whose name looks like a secret (TOKEN, SECRET, PASSWORD, API_KEY, Authorization...), well-known token formats (GitHub, OpenAI, Anthropic, Slack, AWS, Google, GitLab, npm, private keys), and credentials embedded in URLs. MCP files are often committed or synced, so the secret leaks to everyone who can read them, and to the agent. References such as ${input:id}, ${env:NAME}, ${NAME} and $NAME are accepted. Values are always masked in the report.' `
    -Fix 'Remove the literal value and rotate the secret. In VS Code use an input variable (an "inputs" entry of type promptString with "password": true, referenced as ${input:id}); in Claude Code and Copilot CLI reference an environment variable (${NAME}) that is set outside the repository.' `
    -References @('OWASP-ASI03', 'https://code.visualstudio.com/docs/copilot/reference/mcp-configuration', 'https://code.claude.com/docs/en/mcp') `
    -Confidence 'high' -Check {
        param($Ctx)
        foreach ($entry in @(Get-AwMcpServers $Ctx)) {
            foreach ($s in @(Get-AwMcpSecrets $entry.Server)) {
                $evidence = "server '{0}': {1} = {2}" -f $entry.Name, $s.Where, $s.Masked
                New-AwMcpFinding -RuleId 'AW-MCP-002' -Entry $entry -Needle $s.Needle -Key $s.Key -Evidence $evidence
            }
        }
    }

Register-AwRule -Id 'AW-MCP-003' -Title 'Remote MCP server reached over cleartext HTTP' `
    -Severity 'high' -Category 'sandbox-network' -Harness 'mcp' `
    -Description 'Flags MCP servers whose url uses http:// or ws:// on a host other than localhost or a loopback address. Tool calls, results, prompts and any Authorization header then travel unencrypted, and anyone on the network path can read or change them, including the tool descriptions the agent trusts.' `
    -Fix 'Use https:// (or wss://) for every remote MCP server, and keep http:// for localhost only.' `
    -References @('OWASP-ASI07', 'https://code.visualstudio.com/docs/copilot/reference/mcp-configuration', 'https://code.claude.com/docs/en/mcp') `
    -Confidence 'high' -Check {
        param($Ctx)
        foreach ($entry in @(Get-AwMcpServers $Ctx)) {
            $url = Get-AwMcpText $entry.Server['url']
            if (-not $url) { continue }
            $m = [regex]::Match($url.Trim(), '^(?i)(?<scheme>http|ws)://(?:[^/?#@]*@)?(?<host>\[[^\]]*\]|[^/?#:]*)(?<rest>[^?#]*)')
            if (-not $m.Success) { continue }
            $hostName = $m.Groups['host'].Value
            if ($hostName -eq '' -or $hostName -match '\$|%') { continue }
            if ($hostName -match '^(?i)(localhost|.*\.localhost|127(\.\d{1,3}){3}|\[::1\]|0\.0\.0\.0)$') { continue }
            # Show scheme, host and path only: the query string and user info may hold secrets.
            $shown = $m.Groups['scheme'].Value.ToLowerInvariant() + '://' + $hostName + $m.Groups['rest'].Value
            $evidence = "server '{0}': url {1} (unencrypted)" -f $entry.Name, (Format-AwCommandSnippet $shown)
            New-AwMcpFinding -RuleId 'AW-MCP-003' -Entry $entry -Needle '"url"' -Key 'url' -Evidence $evidence
        }
    }

Register-AwRule -Id 'AW-MCP-004' -Title 'MCP server runs inline shell or interpreter code' `
    -Severity 'medium' -Category 'mcp-supply-chain' -Harness 'mcp' `
    -Description 'Flags servers launched as a shell or interpreter with code on the command line: powershell/pwsh with a command or an encoded command parameter, cmd /c with shell operators, bash/sh -c, python -c, node -e/-p, perl -e, ruby -e, php -r, deno eval (the program names and flags are listed in src/Data/mcp.json). The configuration file then is a script that runs when the server starts, which is hard to review and a common way to hide a payload. Encoded values are never decoded or shown. A plain "cmd /c npx ..." wrapper, the usual Windows launcher, is not flagged by itself. Confidence is medium: inline code can be benign, the rule only shows that it needs a review.' `
    -Fix 'Launch the server binary or package directly (command + args), or move the code into a reviewed script file in the repository and run that file.' `
    -References @('OWASP-ASI05', 'https://code.visualstudio.com/docs/copilot/reference/mcp-configuration', 'https://code.claude.com/docs/en/mcp') `
    -Confidence 'medium' -Check {
        param($Ctx)
        foreach ($entry in @(Get-AwMcpServers $Ctx)) {
            foreach ($inv in @(Get-AwMcpInvocations $entry.Server)) {
                if ($null -eq $inv.Shell -or -not $inv.Shell.Inline) { continue }
                $evidence = "server '{0}': {1} {2} '{3}'" -f $entry.Name, $inv.Program, $inv.Shell.Flag, (Format-AwCommandSnippet $inv.Shell.Code 80)
                New-AwMcpFinding -RuleId 'AW-MCP-004' -Entry $entry -Needle '"command"' -Key 'command' -Evidence $evidence
                break
            }
        }
    }

Register-AwRule -Id 'AW-MCP-005' -Title 'MCP server container breaks out of its isolation' `
    -Severity 'high' -Category 'sandbox-network' -Harness 'mcp' `
    -Description 'Checks docker run (and podman run) MCP servers for options that remove the container boundary: --privileged, --network/--pid/--ipc host, --cap-add ALL or SYS_ADMIN, and bind mounts of the file system root, the home directory, C:\Users or the Docker socket. With these, a compromised or malicious server reads credentials (~/.ssh, cloud and token stores) or controls the host, while the configuration looks sandboxed.' `
    -Fix 'Drop --privileged and the host namespaces, add only the capabilities the server needs, and mount only the project folder (read-only when possible), for example -v ${workspaceFolder}:/workspace:ro.' `
    -References @('OWASP-ASI05', 'https://code.visualstudio.com/docs/copilot/reference/mcp-configuration') `
    -Confidence 'high' -Check {
        param($Ctx)
        foreach ($entry in @(Get-AwMcpServers $Ctx)) {
            foreach ($inv in @(Get-AwMcpInvocations $entry.Server)) {
                $run = Get-AwMcpDockerRun -Tokens $inv.Tokens
                if ($null -eq $run) { continue }
                foreach ($risk in @(Get-AwMcpDockerRisks -Run $run -Ctx $Ctx)) {
                    $evidence = "server '{0}': {1} run {2}" -f $entry.Name, $inv.Program, (Format-AwCommandSnippet $risk 120)
                    New-AwMcpFinding -RuleId 'AW-MCP-005' -Entry $entry -Needle '"args"' -Key 'args' -Evidence $evidence
                }
            }
        }
    }

Register-AwRule -Id 'AW-MCP-006' -Title 'Large number of MCP servers' `
    -Severity 'info' -Category 'mcp-supply-chain' -Harness 'mcp' `
    -Description 'Counts the MCP servers configured for all clients. Every server adds tools, and tool descriptions, that the agent may call or be steered by, plus code or a remote service to trust and keep up to date. More than 10 servers is a heuristic threshold, not a documented limit (confidence medium); the finding is informational.' `
    -Fix 'Remove the servers you do not use, and enable the others only in the workspaces that need them.' `
    -References @('OWASP-ASI04', 'OWASP-ASI02', 'https://code.visualstudio.com/docs/copilot/reference/mcp-configuration') `
    -Confidence 'medium' -Check {
        param($Ctx)
        $entries = @(Get-AwMcpServers $Ctx)
        if ($entries.Count -le $script:AwMcpMaxServers) { return }
        $perFile = New-Object System.Collections.Generic.List[string]
        foreach ($file in @($Ctx.McpFiles)) {
            $n = @($entries | Where-Object { $_.File.Path -eq $file.Path }).Count
            if ($n -gt 0) { $perFile.Add(('{0}: {1}' -f (Get-AwDisplayPath -Path $file.Path -Ctx $Ctx), $n)) }
        }
        $evidence = '{0} MCP servers configured (threshold {1}): {2}' -f $entries.Count, $script:AwMcpMaxServers, ($perFile -join '; ')
        New-AwFinding -RuleId 'AW-MCP-006' -Evidence $evidence -Location @{ Path = $entries[0].File.Path }
    }
