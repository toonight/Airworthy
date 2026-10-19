# Secret rules (AW-SEC-0xx): known credential formats, private keys, JWTs, generic
# assignments and .env files, in every file of Ctx.TextFiles (capped at 2 MB of text).
# Values are always masked with Hide-AwSecret. Provider formats live in src/Data/secrets.json;
# every pattern starts at a token boundary (lookbehind) and uses bounded or atomic quantifiers,
# so a scan stays linear. Uses the helpers of AgentFiles.ps1, which loads first.

$script:AwSecMaxPerFile    = 25
$script:AwSecMaxPerRule    = 200
$script:AwSecMaxCandidates = 5000   # raw matches examined per file and pattern
$script:AwSecDocMcpServers    = 'https://code.visualstudio.com/docs/copilot/customization/mcp-servers'
$script:AwSecDocGitHubTokens  = 'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github'
$script:AwSecDocClaudeSettings = 'https://code.claude.com/docs/en/settings'

function ConvertTo-AwSecPattern {
    # One provider entry of secrets.json as @{ RuleId; Name; Mask; NeedsDigit; Regex }.
    param([System.Collections.IDictionary]$Entry)
    foreach ($k in @('ruleId', 'name', 'pattern')) {
        if (-not $Entry.Contains($k) -or $Entry[$k] -isnot [string] -or -not $Entry[$k]) { throw "src/Data/secrets.json: provider entry without '$k'." }
    }
    $regex = New-AwAgtRegex -Pattern $Entry['pattern'] -CaseSensitive:($Entry['caseSensitive'] -eq $true)
    if ($regex.GroupNumberFromName('v') -lt 0) { throw "src/Data/secrets.json: pattern of $($Entry['ruleId']) has no 'v' group." }
    [pscustomobject]@{
        RuleId     = $Entry['ruleId']
        Name       = $Entry['name']
        Mask       = ($Entry['mask'] -eq $true)
        NeedsDigit = ($Entry['needsDigit'] -eq $true)
        Regex      = $regex
    }
}

# Provider formats. 'v' is the secret value. NeedsDigit drops word-like matches (sk-learn-...).
$script:AwSecData = Read-AwAgtData 'secrets.json'
$script:AwSecPatterns = @(foreach ($entry in @($script:AwSecData['providers'])) {
    if ($entry -is [System.Collections.IDictionary]) { ConvertTo-AwSecPattern $entry }
})
if ($script:AwSecPatterns.Count -eq 0) { throw 'src/Data/secrets.json: no provider pattern.' }

# Generic assignment: a key containing password/secret/token/api key, then ':' or '=', then a value.
$script:AwSecGenericRegex = New-AwAgtRegex -Pattern ('(?<![A-Za-z0-9_])(?<key>[A-Za-z0-9_.-]{0,40}?(?:password|passwd|secret|token|api[_-]?key)' +
    '[A-Za-z0-9_.-]{0,40}?)["'']?[ \t]{0,4}[:=][ \t]{0,4}(?<q>["'']?)(?<v>[^\s"''`,;<>{}()\[\]]{8,200})')
# Keys that name or describe a secret instead of holding it.
$script:AwSecKeyExclude = New-AwAgtRegex -Pattern ('(?:tokens|tokeniz|secretary|(?:name|names|file|path|dir|url|uri|endpoint|type|types|length|len|count|limit|' +
    'max|min|size|ttl|expiry|expires|expiration|timeout|env|var|ref|id|ids|source|header|prefix|suffix|policy|field|format|mode|enabled|required|location|' +
    'provider|store|manager|helper|command|cmd|regex|pattern|hint|label|description|prompt)$)')
$script:AwSecPlaceholderRegex = New-AwAgtRegex -Pattern ('(?:example|placeholder|change[_-]?me|your[_-]|redacted|dummy|sample|replace[_-]?me|notreal|' +
    'not[_-]a[_-]real|xxxx|\*\*\*\*|\.\.\.\.|todo)')
$script:AwSecLiteralRegex = New-AwAgtRegex -Pattern '^(?:true|false|null|none|nil|undefined|empty|string|required|optional|password|secret|token|[0-9.]+)$'
$script:AwSecRepeatRegex = New-AwAgtRegex -CaseSensitive -Pattern '(.)\1{5}'
$script:AwSecKeyBeforeRegex = New-AwAgtRegex -CaseSensitive -Pattern '(?<k>[A-Za-z_][A-Za-z0-9_.-]{0,63})["'']?[ \t]*[:=][ \t]*["'']?$'
$script:AwSecEnvTemplateRegex = New-AwAgtRegex -Pattern '\.(?:example|sample|template|dist|defaults|schema)$'
$script:AwSecEnvAssignRegex = New-AwAgtRegex -Multiline -Pattern '^[ \t]*(?:export[ \t]+)?[A-Za-z_][A-Za-z0-9_]*[ \t]*='

function Get-AwSecFiles {
    # @{ Path; Text; Harness } for every text file of the context. Cached per context.
    param($Ctx)
    $cache = Get-Variable -Name AwSecFileCache -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if ($null -ne $cache -and [object]::ReferenceEquals($cache.Ctx, $Ctx)) { return ,$cache.Files }
    $files = New-Object System.Collections.ArrayList
    foreach ($p in @($Ctx.TextFiles)) {
        if (-not $p) { continue }
        $text = Get-AwFileText -Ctx $Ctx -Path $p
        if ([string]::IsNullOrEmpty($text)) { continue }
        [void]$files.Add([pscustomobject]@{ Path = $p; Text = (Get-AwAgtScanText $text); Harness = (Get-AwAgtPathHarness $Ctx $p) })
    }
    $script:AwSecFileCache = @{ Ctx = $Ctx; Files = $files.ToArray() }
    return ,$script:AwSecFileCache.Files
}

function Test-AwSecDigitAndLetter {
    param([string]$Value)
    return ($Value -match '[0-9]' -and $Value -match '[A-Za-z]')
}

function Get-AwSecEntropy {
    # Bits per character, over the first 64 characters.
    param([string]$Value)
    if (-not $Value) { return 0.0 }
    if ($Value.Length -gt 64) { $Value = $Value.Substring(0, 64) }
    $freq = @{}
    foreach ($ch in $Value.ToCharArray()) { $k = [int]$ch; if ($freq.ContainsKey($k)) { $freq[$k]++ } else { $freq[$k] = 1 } }
    $h = 0.0
    foreach ($count in $freq.Values) { $p = $count / $Value.Length; $h -= $p * [Math]::Log($p, 2) }
    return $h
}

function Test-AwSecKnownFormat {
    # True when the value matches one of the provider formats (already reported by its own rule).
    param([string]$Value)
    foreach ($p in $script:AwSecPatterns) { if ($p.Mask -and $p.Regex.IsMatch($Value)) { return $true } }
    return $false
}

function Test-AwSecGenericValue {
    # Filters placeholders, references, paths, literals and low-entropy values.
    param([string]$Key, [string]$Value)
    if ($script:AwSecKeyExclude.IsMatch($Key)) { return $false }
    if ($Value.Length -lt 8) { return $false }
    if ('$%&@~/.\'.IndexOf($Value[0]) -ge 0) { return $false }     # $VAR, %VAR%, @ref, paths
    if ($Value -match '^[A-Za-z]:[\\/]' -or $Value -match '^[A-Za-z][A-Za-z0-9+.-]*://') { return $false }
    if ($Value -match '^(?:process\.env|os\.environ|env\.|secrets\.|vault:|op://|arn:aws:)') { return $false }
    if ($script:AwSecLiteralRegex.IsMatch($Value) -or $script:AwSecPlaceholderRegex.IsMatch($Value) -or $script:AwSecRepeatRegex.IsMatch($Value)) { return $false }
    if ((New-Object 'System.Collections.Generic.HashSet[char]' -ArgumentList (,$Value.ToCharArray())).Count -lt 6) { return $false }
    if ((Get-AwSecEntropy $Value) -lt 3.0) { return $false }
    if (Test-AwSecKnownFormat $Value) { return $false }
    return $true
}

function Get-AwSecKeyBefore {
    # Assignment key just before Index on the same line ('GITHUB_TOKEN' in "GITHUB_TOKEN": "ghp_..."), or $null.
    param([string]$Text, [int]$Index)
    $lo = [Math]::Max(0, $Index - 120)
    $before = $Text.Substring($lo, $Index - $lo)
    $nl = $before.LastIndexOf("`n")
    if ($nl -ge 0) { $before = $before.Substring($nl + 1) }
    $m = $script:AwSecKeyBeforeRegex.Match($before)
    if ($m.Success) { return $m.Groups['k'].Value }
    return $null
}

function Find-AwSecMatches {
    <#
    Matches of a provider pattern (or of the generic assignment pattern with -Generic) in a text,
    after filtering: list of @{ Index; Value; Key }. Scans at most 2 MB and examines at most
    AwSecMaxCandidates raw matches, so that a file full of decoys cannot slow the analysis down.
    #>
    param([string]$Text, $Pattern, [switch]$Generic)
    $out = New-Object System.Collections.ArrayList
    $text = Get-AwAgtScanText $Text
    if (-not $text) { return ,$out.ToArray() }
    $regex = if ($Generic) { $script:AwSecGenericRegex } else { $Pattern.Regex }
    $seen = 0
    $m = $regex.Match($text)
    while ($m.Success -and $seen -lt $script:AwSecMaxCandidates) {
        $seen++
        $v = $m.Groups['v']
        if ($Generic) {
            $key = $m.Groups['key'].Value
            if (Test-AwSecGenericValue $key $v.Value) { [void]$out.Add([pscustomobject]@{ Index = $v.Index; Value = $v.Value; Key = $key }) }
        } else {
            $ok = (-not $Pattern.NeedsDigit -or (Test-AwSecDigitAndLetter $v.Value))
            # Documented placeholders (AKIAIOSFODNN7EXAMPLE, ghp_xxxx...) are not secrets.
            if ($ok -and $Pattern.Mask -and ($script:AwSecPlaceholderRegex.IsMatch($v.Value) -or $script:AwSecRepeatRegex.IsMatch($v.Value))) { $ok = $false }
            if ($ok) { [void]$out.Add([pscustomobject]@{ Index = $v.Index; Value = $v.Value; Key = (Get-AwSecKeyBefore $text $v.Index) }) }
        }
        $m = $m.NextMatch()
    }
    return ,$out.ToArray()
}

function Get-AwSecFindings {
    # Findings of one secret rule over every text file, capped per file and per rule.
    param($Ctx, [string]$RuleId)
    $pattern = $script:AwSecPatterns | Where-Object { $_.RuleId -eq $RuleId } | Select-Object -First 1
    $generic = $null -eq $pattern
    $name = if ($generic) { 'Hard-coded value' } else { $pattern.Name }
    $total = 0
    foreach ($file in (Get-AwSecFiles $Ctx)) {
        try {
            $hits = Find-AwSecMatches -Text $file.Text -Pattern $pattern -Generic:$generic
        } catch {
            $inner = $_.Exception
            while ($inner.InnerException) { $inner = $inner.InnerException }
            if ($inner -isnot [System.Text.RegularExpressions.RegexMatchTimeoutException]) { throw }
            New-AwFinding -RuleId $RuleId -Severity 'info' -Harness $file.Harness -Evidence 'Scan of this file stopped: pattern matching took too long.' -Location @{ Path = $file.Path }
            continue
        }
        if ($hits.Count -eq 0) { continue }
        $counter = New-AwAgtLineCounter $file.Text
        $shown = 0
        foreach ($hit in $hits) {
            if ($shown -ge $script:AwSecMaxPerFile -or $total -ge $script:AwSecMaxPerRule) { break }
            $shown++; $total++
            $ev = if ($RuleId -eq 'AW-SEC-007') { "$name ($($hit.Value)); key material not shown" } else { "${name}: $(Hide-AwSecret -Value $hit.Value)" }
            $key = if ($hit.Key) { Protect-AwAgtEvidence $hit.Key 80 } else { $null }
            New-AwFinding -RuleId $RuleId -Harness $file.Harness -Evidence $ev -Location @{ Path = $file.Path; Line = (Get-AwAgtLineAt $counter $hit.Index); Key = $key }
        }
        if ($hits.Count -gt $shown) {
            New-AwFinding -RuleId $RuleId -Severity 'info' -Harness $file.Harness -Location @{ Path = $file.Path } `
                -Evidence ("{0} more '{1}' match(es) in this file are not listed." -f ($hits.Count - $shown), $name)
        }
    }
}

function Register-AwSecRule {
    # Common metadata of the secret rules.
    param([string]$Id, [string]$Title, [string]$Severity, [string]$What, [string]$Description, [string[]]$References,
          [string]$Confidence = 'high', [scriptblock]$Check)
    $fix = ('Revoke the {0} and issue a new one, remove it from the file and from the Git history, and load it at run time instead: ' +
        'an input variable in .vscode/mcp.json (${{input:...}} with "password": true), or an environment variable set outside the repository.') -f $What
    Register-AwRule -Id $Id -Title $Title -Severity $Severity -Category 'secrets' -Harness 'generic' -Description $Description `
        -Fix $fix -References $References -Confidence $Confidence -Check $Check
}

Register-AwSecRule -Id 'AW-SEC-001' -Title 'GitHub token in a configuration file' -Severity 'high' -What 'GitHub token' `
    -Description ("A GitHub token (ghp_, gho_, ghu_, ghs_, ghr_ or github_pat_ prefix) is written in a configuration or instruction file. Anyone " +
        "who can read the repository, and every agent, hook or MCP server that reads the file, can act on GitHub with it.") `
    -References @('OWASP-ASI03', $script:AwSecDocGitHubTokens, $script:AwSecDocMcpServers) `
    -Check { param($Ctx) Get-AwSecFindings -Ctx $Ctx -RuleId 'AW-SEC-001' }

Register-AwSecRule -Id 'AW-SEC-002' -Title 'AWS access key ID in a configuration file' -Severity 'high' -What 'AWS access key' `
    -Description ("An AWS access key ID (AKIA or ASIA followed by 16 characters) is written in a configuration or instruction file. The secret " +
        "access key that goes with it is usually stored next to it.") `
    -References @('OWASP-ASI03', $script:AwSecDocMcpServers) `
    -Check { param($Ctx) Get-AwSecFindings -Ctx $Ctx -RuleId 'AW-SEC-002' }

Register-AwSecRule -Id 'AW-SEC-003' -Title 'Azure Storage account key in a connection string' -Severity 'high' -What 'storage account key' `
    -Description 'An Azure Storage connection string with AccountKey= is written in a configuration or instruction file. The account key gives full access to the storage account.' `
    -References @('OWASP-ASI03', $script:AwSecDocMcpServers) `
    -Check { param($Ctx) Get-AwSecFindings -Ctx $Ctx -RuleId 'AW-SEC-003' }

Register-AwSecRule -Id 'AW-SEC-004' -Title 'OpenAI-style API key in a configuration file' -Severity 'high' -What 'API key' `
    -Description ("A key in the sk- format of OpenAI (sk-, sk-proj-, sk-svcacct-, sk-admin-) is written in a configuration or instruction file. " +
        "Other model providers use the same prefix, so check which service issued it.") `
    -References @('OWASP-ASI03', $script:AwSecDocMcpServers) `
    -Check { param($Ctx) Get-AwSecFindings -Ctx $Ctx -RuleId 'AW-SEC-004' }

Register-AwSecRule -Id 'AW-SEC-005' -Title 'Anthropic API key in a configuration file' -Severity 'high' -What 'Anthropic API key' `
    -Description 'An Anthropic key (sk-ant- prefix) is written in a configuration or instruction file. It allows API calls billed to the account that owns it.' `
    -References @('OWASP-ASI03', $script:AwSecDocClaudeSettings) `
    -Check { param($Ctx) Get-AwSecFindings -Ctx $Ctx -RuleId 'AW-SEC-005' }

Register-AwSecRule -Id 'AW-SEC-006' -Title 'Slack token in a configuration file' -Severity 'high' -What 'Slack token' `
    -Description 'A Slack token (xoxb-, xoxp-, xoxa-, xoxr- or xoxs- prefix) is written in a configuration or instruction file. It can read and post messages as the bot or user that owns it.' `
    -References @('OWASP-ASI03', $script:AwSecDocMcpServers) `
    -Check { param($Ctx) Get-AwSecFindings -Ctx $Ctx -RuleId 'AW-SEC-006' }

Register-AwSecRule -Id 'AW-SEC-007' -Title 'Private key in a configuration file' -Severity 'high' -What 'private key' `
    -Description 'A private key block (-----BEGIN ... PRIVATE KEY-----) is stored in a configuration or instruction file that agents and tools can read.' `
    -References @('OWASP-ASI03') `
    -Check { param($Ctx) Get-AwSecFindings -Ctx $Ctx -RuleId 'AW-SEC-007' }

Register-AwSecRule -Id 'AW-SEC-008' -Title 'JSON Web Token in a configuration file' -Severity 'medium' -What 'token' `
    -Description ("A JSON Web Token (three dot-separated encoded parts, the first two starting with eyJ) is written in a configuration or instruction file. It is a bearer " +
        "token: whoever holds it is authenticated until it expires.") `
    -References @('OWASP-ASI03', $script:AwSecDocMcpServers) `
    -Check { param($Ctx) Get-AwSecFindings -Ctx $Ctx -RuleId 'AW-SEC-008' }

Register-AwSecRule -Id 'AW-SEC-009' -Title 'Hard-coded password, secret or token value' -Severity 'medium' -What 'secret' -Confidence 'medium' `
    -Description ("A key whose name contains password, passwd, secret, token or api key is assigned a literal value. Placeholders, references " +
        "(`${input:...}, `$VAR, %VAR%), paths, URLs, numbers, booleans and low-entropy values (under 3 bits per character or fewer than 6 distinct " +
        "characters) are ignored; the remaining matches may still include false positives.") `
    -References @('OWASP-ASI03', $script:AwSecDocMcpServers) `
    -Check { param($Ctx) Get-AwSecFindings -Ctx $Ctx -RuleId 'AW-SEC-009' }

Register-AwRule -Id 'AW-SEC-010' -Title 'Environment file in the workspace' `
    -Severity 'low' -Category 'secrets' -Harness 'generic' `
    -Description ("A .env file sits at the root of the analyzed folder. Such files usually hold secrets, and agents with file-read or terminal tools " +
        "can read them, then send their content to the model or to a tool. Template files (.env.example, .sample, .template, .dist, .defaults, .schema) are ignored.") `
    -Fix ("Keep secrets out of the workspace (secret store, prompted inputs). If the file must stay, keep it out of Git (.gitignore) and deny agents " +
        "access to it, for example with permissions.deny Read(./.env) and Read(./.env.*) in Claude Code settings.") `
    -References @('OWASP-ASI03', $script:AwSecDocClaudeSettings, $script:AwAgtDocVSCodeSec) `
    -Confidence 'high' -Check {
        param($Ctx)
        foreach ($p in @($Ctx.TextFiles)) {
            if (-not $p) { continue }
            $leaf = [System.IO.Path]::GetFileName($p)
            if (-not $leaf.StartsWith('.env', [StringComparison]::OrdinalIgnoreCase)) { continue }
            if ($script:AwSecEnvTemplateRegex.IsMatch($leaf) -or -not (Test-AwPathInside -Path $p -Dir $Ctx.Root)) { continue }
            $text = Get-AwAgtScanText (Get-AwFileText -Ctx $Ctx -Path $p)
            $count = $script:AwSecEnvAssignRegex.Matches($text).Count
            New-AwFinding -RuleId 'AW-SEC-010' -Evidence ("{0} in the workspace ({1} variable assignment(s))" -f (Protect-AwAgtEvidence $leaf 80), $count) -Location @{ Path = $p }
        }
    }
