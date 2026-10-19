# Rules for agent files (AW-AGT-0xx): custom agents, chat modes, prompt files and instructions.
# Agent files are hostile input. Patterns are linear (bounded quantifiers, token-start
# lookbehinds, match timeout), scans are capped per file, and every snippet shown as
# evidence goes through Protect-AwAgtEvidence (invisible characters made visible, secrets masked).
# Keyword lists live in src/Data/agentfiles.json. This file loads before Secrets.ps1 and also
# holds the text and data helpers both files use.

$script:AwAgtScanMaxChars       = 2MB     # never scan more than the discovery size limit
$script:AwAgtRegexTimeout       = [TimeSpan]::FromSeconds(2)
$script:AwAgtMaxFindingsPerFile = 10
$script:AwAgtMaxMatchesPerFile  = 500     # candidate matches examined per file and pattern
$script:AwAgtMaxComments        = 2000    # HTML comments examined per file
$script:AwAgtMaxDirectiveChars  = 262144  # total comment text per file tested for hidden directives
$script:AwAgtAgentKinds         = @('agent', 'chatmode')
$script:AwAgtDataDir            = Join-Path (Split-Path -Parent $PSScriptRoot) 'Data'

$script:AwAgtDocCustomAgents = 'https://code.visualstudio.com/docs/copilot/customization/custom-agents'
$script:AwAgtDocPromptFiles  = 'https://code.visualstudio.com/docs/copilot/customization/prompt-files'
$script:AwAgtDocGitHubAgents = 'https://docs.github.com/en/copilot/reference/custom-agents-configuration'
$script:AwAgtDocVSCodeSec    = 'https://code.visualstudio.com/docs/copilot/security'
$script:AwAgtDocClaudeMemory = 'https://code.claude.com/docs/en/memory'

# --- Shared data and text helpers ----------------------------------------------------------

function Read-AwAgtData {
    # Rule data from src/Data/<Name> (JSONC). A missing or invalid file stops this rule file with a clear error.
    param([Parameter(Mandatory)] [string]$Name)
    $path = Join-Path $script:AwAgtDataDir $Name
    if (-not [System.IO.File]::Exists($path)) { throw "Rule data file not found: src/Data/$Name" }
    try {
        $data = ConvertFrom-AwJsonc -Text ([System.IO.File]::ReadAllText($path))
    } catch {
        throw "Rule data file src/Data/$Name is invalid: $($_.Exception.Message)"
    }
    if ($data -isnot [System.Collections.IDictionary]) { throw "Rule data file src/Data/$Name must contain a JSON object." }
    return $data
}

function Get-AwAgtDataList {
    # A list of non-empty strings from a data object (empty when the key is absent).
    param($Data, [string]$Key)
    $out = New-Object System.Collections.Generic.List[string]
    if ($Data.Contains($Key)) {
        foreach ($item in @($Data[$Key])) { if ($item -is [string] -and $item) { $out.Add($item) } }
    }
    return ,$out.ToArray()
}

function Join-AwAgtAlternation {
    # Regex alternation of plain tokens (escaped) and regex fragments (kept as they are).
    param([string[]]$Tokens = @(), [string[]]$Fragments = @())
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($t in $Tokens) { if ($t) { $parts.Add([regex]::Escape($t)) } }
    foreach ($f in $Fragments) { if ($f) { $parts.Add($f) } }
    if ($parts.Count -eq 0) { throw 'Join-AwAgtAlternation: no token.' }
    return ($parts.ToArray() -join '|')
}

$script:AwAgtData = Read-AwAgtData 'agentfiles.json'
$script:AwAgtBuiltInAgents = Get-AwAgtDataList $script:AwAgtData 'builtInAgents'

function New-AwAgtRegex {
    # Case-insensitive (unless -CaseSensitive), culture-invariant regex with a match timeout.
    param([Parameter(Mandatory)] [string]$Pattern, [switch]$CaseSensitive, [switch]$Multiline)
    $o = [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    if (-not $CaseSensitive) { $o = $o -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase }
    if ($Multiline) { $o = $o -bor [System.Text.RegularExpressions.RegexOptions]::Multiline }
    New-Object System.Text.RegularExpressions.Regex -ArgumentList @($Pattern, [System.Text.RegularExpressions.RegexOptions]$o, $script:AwAgtRegexTimeout)
}

function Get-AwAgtScanText {
    # Text capped at the 2 MB scan limit ('' for $null).
    param([AllowNull()] [AllowEmptyString()] [string]$Text)
    if ($null -eq $Text) { return '' }
    if ($Text.Length -gt $script:AwAgtScanMaxChars) { return $Text.Substring(0, $script:AwAgtScanMaxChars) }
    return $Text
}

function New-AwAgtLineCounter {
    param([string]$Text)
    @{ Text = $Text; Pos = 0; Line = 1 }
}

function Get-AwAgtLineAt {
    # 1-based line of a character index; linear overall when indexes are visited in increasing order.
    param($Counter, [int]$Index)
    if ($Index -lt $Counter.Pos) { $Counter.Pos = 0; $Counter.Line = 1 }
    if ($Index -gt $Counter.Text.Length) { $Index = $Counter.Text.Length }
    if ($Index -gt $Counter.Pos) {
        $chunk = $Counter.Text.Substring($Counter.Pos, $Index - $Counter.Pos)
        $Counter.Line += $chunk.Length - $chunk.Replace("`n", '').Length
        $Counter.Pos = $Index
    }
    return $Counter.Line
}

function Get-AwAgtLineText {
    # The line that contains Index, capped to 1000 characters around it.
    param([string]$Text, [int]$Index)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    if ($Index -ge $Text.Length) { $Index = $Text.Length - 1 }
    $start = 0
    if ($Index -gt 0) { $start = $Text.LastIndexOf([char]"`n", $Index - 1) + 1 }
    $end = $Text.IndexOf([char]"`n", $Index)
    if ($end -lt 0) { $end = $Text.Length }
    if ($Index - $start -gt 500) { $start = $Index - 500 }
    if ($end - $Index -gt 500) { $end = $Index + 500 }
    return $Text.Substring($start, $end - $start)
}

function Test-AwAgtInvisibleChar {
    # Format and control characters that are invisible or reorder text on screen.
    param([int]$Code)
    return ($Code -eq 0x00AD -or $Code -eq 0x061C -or $Code -eq 0x180E -or
            ($Code -ge 0x200B -and $Code -le 0x200F) -or ($Code -ge 0x202A -and $Code -le 0x202E) -or
            ($Code -ge 0x2060 -and $Code -le 0x2064) -or ($Code -ge 0x2066 -and $Code -le 0x2069) -or
            $Code -eq 0xFEFF -or ($Code -ge 0xFFF9 -and $Code -le 0xFFFB))
}

function Hide-AwAgtSecrets {
    # Masks known secret formats (Secrets.ps1, when loaded) and any long token-like word.
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $evaluator = [System.Text.RegularExpressions.MatchEvaluator] { param($m) Hide-AwSecret -Value $m.Value }
    $patterns = Get-Variable -Name AwSecPatterns -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    foreach ($p in @($patterns)) {
        if ($null -ne $p -and $p.Mask) { $Text = $p.Regex.Replace($Text, $evaluator) }
    }
    $Text = $script:AwAgtTokenRegex.Replace($Text, $evaluator)
    return (Hide-AwSecretsInText $Text)
}

function Protect-AwAgtEvidence {
    <#
    Makes file content safe to show as evidence: control characters become spaces, invisible
    and bidi characters become visible [U+XXXX] markers, secrets are masked, whitespace is
    collapsed and the length is capped.
    #>
    param([AllowNull()] [AllowEmptyString()] [string]$Text, [int]$MaxLength = 160)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    if ($Text.Length -gt 4096) {
        # Extend the cut to the next blank so that a secret is never split before masking.
        $cut = $Text.IndexOfAny([char[]]@(' ', "`t", "`n", "`r"), 4096)
        if ($cut -lt 0 -or $cut -gt 4608) { $cut = 4608 }
        if ($cut -lt $Text.Length) { $Text = $Text.Substring(0, $cut) }
    }
    $sb = New-Object System.Text.StringBuilder
    $i = 0; $n = $Text.Length
    while ($i -lt $n) {
        $c = [int]$Text[$i]
        if ($c -ge 0xD800 -and $c -le 0xDBFF -and $i + 1 -lt $n -and [int]$Text[$i + 1] -ge 0xDC00 -and [int]$Text[$i + 1] -le 0xDFFF) {
            $cp = 0x10000 + (($c - 0xD800) * 0x400) + ([int]$Text[$i + 1] - 0xDC00)
            if ($cp -ge 0xE0000 -and $cp -le 0xE007F) { [void]$sb.AppendFormat('[U+{0:X5}]', $cp) }
            else { [void]$sb.Append($Text, $i, 2) }
            $i += 2
            continue
        }
        if ($c -lt 0x20 -or ($c -ge 0x7F -and $c -le 0x9F)) { [void]$sb.Append(' ') }
        elseif ((Test-AwAgtInvisibleChar $c) -or ($c -ge 0xD800 -and $c -le 0xDFFF)) { [void]$sb.AppendFormat('[U+{0:X4}]', $c) }
        else { [void]$sb.Append($Text[$i]) }
        $i++
    }
    $out = Hide-AwAgtSecrets $sb.ToString()
    $out = [regex]::Replace($out, '\s+', ' ').Trim()
    if ($out.Length -gt $MaxLength) { $out = $out.Substring(0, $MaxLength).TrimEnd() + $script:AwEllipsis }
    return $out
}

function Format-AwAgtList {
    # 'a, b, c (+N more)' for evidence.
    param([string[]]$Items, [int]$Max = 12)
    $all = @($Items)
    $s = (@($all | Select-Object -First $Max) -join ', ')
    if ($all.Count -gt $Max) { $s += " (+$($all.Count - $Max) more)" }
    return $s
}

function Get-AwAgtHarness {
    # Harness a finding on this agent file belongs to.
    param($Ctx, $AgentFile)
    switch ($AgentFile.Kind) {
        'agents-md'    { return 'generic' }
        'claude-agent' { return 'claude-code' }
        'claude-md'    { return 'claude-code' }
        'agent' {
            if ($Ctx.UserProfile -and (Test-AwPathInside -Path $AgentFile.Path -Dir ([System.IO.Path]::Combine($Ctx.UserProfile, '.copilot')))) {
                return 'copilot-cli'
            }
            return 'vscode-copilot'
        }
        default { return 'vscode-copilot' }
    }
}

function Get-AwAgtPathHarness {
    # Harness of a discovered file (agent file or JSON artifact), 'generic' otherwise (.env files).
    param($Ctx, [string]$Path)
    foreach ($af in @($Ctx.AgentFiles)) {
        if ($af -and [string]::Equals($af.Path, $Path, $script:AwPathComparison)) { return (Get-AwAgtHarness $Ctx $af) }
    }
    $vs = $Ctx.VSCode
    foreach ($a in @(@($vs.UserSettings, $vs.WorkspaceSettings) + @($vs.WorkspaceFiles) + @($Ctx.McpFiles) +
                     @($Ctx.Hooks) + @($Ctx.ClaudeSettings) + @($Ctx.CopilotCli) +
                     @(Get-AwMemberValue $Ctx 'Codex') + @(Get-AwMemberValue $Ctx 'CodexRules'))) {
        if ($a -and [string]::Equals($a.Path, $Path, $script:AwPathComparison) -and $script:AwHarnesses -ccontains $a.Harness) { return $a.Harness }
    }
    return 'generic'
}

# --- Agent file helpers --------------------------------------------------------------------

function Get-AwAgtCustomAgents {
    param($Ctx)
    @($Ctx.AgentFiles | Where-Object { $null -ne $_ -and $script:AwAgtAgentKinds -contains $_.Kind })
}

function Get-AwAgtBodyOffset {
    # Index in Raw where the body starts (0 without frontmatter).
    param($AgentFile)
    $raw = [string]$AgentFile.Raw; $body = [string]$AgentFile.Body
    if ($body.Length -le $raw.Length -and $raw.EndsWith($body, [StringComparison]::Ordinal)) { return $raw.Length - $body.Length }
    return 0
}

function Find-AwAgtKeyLine {
    # Line of the first top-level 'Key:' in the frontmatter; -Nested also accepts indented and '- Key:' lines.
    param($AgentFile, [string]$Key, [string]$ValuePattern = '', [switch]$Nested)
    $raw = [string]$AgentFile.Raw
    $end = Get-AwAgtBodyOffset $AgentFile
    if ($end -le 0) { return $null }
    $lead = if ($Nested) { '^[ \t]*(?:-[ \t]+)?' } else { '^' }
    $re = New-AwAgtRegex -Multiline -CaseSensitive -Pattern ($lead + [regex]::Escape($Key) + '[ \t]*:' + $ValuePattern)
    $m = $re.Match($raw, 0, $end)
    if (-not $m.Success) { return $null }
    return (Get-AwAgtLineAt (New-AwAgtLineCounter $raw) $m.Index)
}

function ConvertTo-AwAgtNameList {
    # A frontmatter list (YAML list, flow list kept as text, or comma-separated string) as names.
    param($Value)
    $out = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Value -or $Value -is [System.Collections.IDictionary]) { return ,$out.ToArray() }
    if ($Value -is [string]) {
        $s = $Value.Trim()
        if ($s.StartsWith('[') -and $s.EndsWith(']')) { $s = $s.Substring(1, $s.Length - 2) }
        $items = $s.Split(',')
    } elseif ($Value -is [System.Collections.IEnumerable]) {
        $items = @($Value)
    } else {
        $items = @([string]$Value)
    }
    foreach ($item in $items) {
        if ($null -eq $item -or $item -is [System.Collections.IDictionary] -or ($item -is [System.Collections.IEnumerable] -and $item -isnot [string])) { continue }
        $name = ([string]$item).Trim().Trim([char[]]@("'", '"')).Trim()
        if ($name) { $out.Add($name) }
    }
    return ,$out.ToArray()
}

function Get-AwAgtTools {
    # Tools of an agent or prompt file: $null when the 'tools' key is absent, else string[].
    param($AgentFile)
    $fm = $AgentFile.Frontmatter
    if ($null -eq $fm -or -not $fm.ContainsKey('tools')) { return $null }
    return ,(ConvertTo-AwAgtNameList $fm['tools'])
}

function Get-AwAgtName {
    param($AgentFile)
    $n = $AgentFile.Frontmatter['name']
    if ($n -is [string] -and $n.Trim()) { return $n.Trim() }
    return ([System.IO.Path]::GetFileName($AgentFile.Path) -replace '(?i)\.(agent|chatmode)\.md$', '' -replace '(?i)\.md$', '')
}

function Test-AwAgtToolGranted {
    # True when a tool name is covered by a granted list ('*', exact name, or '<server>/*').
    param([string]$Tool, [string[]]$Granted)
    $t = $Tool.ToLowerInvariant()
    foreach ($g in $Granted) {
        $gl = $g.ToLowerInvariant()
        if ($gl -eq '*' -or $gl -eq $t) { return $true }
        if ($gl.EndsWith('/*') -and $t.StartsWith($gl.Substring(0, $gl.Length - 1))) { return $true }
    }
    return $false
}

# --- Content patterns ----------------------------------------------------------------------

# Apostrophe (ASCII or U+2019) and accented letters are regex escapes: this file stays ASCII.
$script:AwAgtApos = '[''\u2019]'

function New-AwAgtTextRegex {
    param([string]$Pattern)
    New-AwAgtRegex -Pattern $Pattern.Replace('_Q_', $script:AwAgtApos)
}

$script:AwAgtTokenRegex = New-AwAgtRegex -CaseSensitive -Pattern ('(?<![A-Za-z0-9_+/=-])(?=[A-Za-z0-9_+/=-]{0,300}[0-9])' +
    '(?=[A-Za-z0-9_+/=-]{0,300}[A-Za-z])[A-Za-z0-9_+/=-]{20,}')

# Approval-bypass directives. Check = $true: ignored when a negation precedes them in the same clause.
$script:AwAgtBypassPatterns = @(
    @{ Check = $true;  Regex = New-AwAgtTextRegex '\bwithout\s+(?:first\s+|ever\s+)?(?:asking|prompting|confirming|confirmation|approval|permission|consent|(?:any|the|user|human|my|explicit)\s+(?:approval|confirmation|permission|consent|review)|checking\s+with\s+(?:me|the\s+user|anyone)|waiting\s+for\s+(?:approval|confirmation|permission))\b' }
    @{ Check = $false; Regex = New-AwAgtTextRegex '\b(?:do\s+not|don_Q_?t|never|no\s+need\s+to)\s+(?:ever\s+)?(?:ask|prompt|request|seek)\s+(?:(?:me|the\s+user|the\s+human|users?|anyone)\s+)?(?:for\s+)?(?:any\s+)?(?:confirmation|approval|permission|consent|before)\b' }
    @{ Check = $false; Regex = New-AwAgtTextRegex '\b(?:do\s+not|don_Q_?t|never)\s+wait\s+for\s+(?:(?:the\s+)?(?:user|human)(?:_Q_s)?\s+|my\s+|any\s+)?(?:approval|confirmation|permission|consent|review)\b' }
    @{ Check = $false; Regex = New-AwAgtTextRegex '\b(?:do\s+not|don_Q_?t)\s+ask(?=\s*[,.;!\r\n]|\s+(?:questions|just|first)\b)' }
    @{ Check = $true;  Regex = New-AwAgtTextRegex '\bauto[-_ ]?approv(?:e|es|ed|al|ing)\b' }
    @{ Check = $true;  Regex = New-AwAgtTextRegex '\b(?:skip|bypass|ignore|disable|circumvent|override|suppress)\s+(?:(?:all|any|the|every|each|these|those|user|human|tool|terminal|safety)\s+){0,3}(?:(?:approval|confirmation|permission)\s+(?:prompts?|checks?|steps?|dialogs?|requests?)|approvals?|confirmations?|permissions)\b' }
    @{ Check = $true;  Regex = New-AwAgtTextRegex ('(?<![A-Za-z0-9-])(?:' + (Join-AwAgtAlternation (Get-AwAgtDataList $script:AwAgtData 'approvalBypassFlags')) +
        ')(?![A-Za-z0-9-])|\b(?:' + (Join-AwAgtAlternation (Get-AwAgtDataList $script:AwAgtData 'approvalBypassModes')) + ')\b') }
    @{ Check = $true;  Regex = New-AwAgtTextRegex '\b(?:pre-?approved|pre-?authori[sz]ed|(?:approval|permission|consent)\s+(?:is|has\s+been|was)\s+(?:already\s+)?(?:granted|given))\b' }
    @{ Check = $true;  Regex = New-AwAgtTextRegex '\bsans\s+(?:(?:me|te|lui|leur|nous|vous|en)\s+)?(?:demander|consulter|pr[e\xE9]venir)\b' }
    @{ Check = $true;  Regex = New-AwAgtTextRegex '\bsans\s+(?:(?:la|une|aucune|leur|son|sa|ma|mon|votre|ton|ta|l_Q_|d_Q_)\s*)?(?:confirmation|approbation|autorisation|permission|validation|accord|consentement)\b' }
    @{ Check = $true;  Regex = New-AwAgtTextRegex '\bsans\s+attendre\s+(?:(?:la|une|leur|son|votre|l_Q_|d_Q_)\s*)?(?:confirmation|approbation|autorisation|permission|validation|accord|consentement|r[e\xE9]ponse)\b' }
    @{ Check = $false; Regex = New-AwAgtTextRegex '\bne\s+(?:(?:me|te|lui|leur|nous|vous)\s+)?demande[sz]?\s+(?:pas|jamais|plus|aucune?)\s+(?:(?:de|la|une|d_Q_|l_Q_)\s*)?(?:confirmation|approbation|autorisation|permission|validation|accord|consentement|avis|avant)\b' }
    @{ Check = $false; Regex = New-AwAgtTextRegex '\bne\s+(?:jamais|pas|plus)\s+demander\s+(?:(?:de|la|une|d_Q_|l_Q_)\s*)?(?:confirmation|approbation|autorisation|permission|validation|accord|consentement|avis)\b' }
    @{ Check = $false; Regex = New-AwAgtTextRegex '\bn_Q_\s*(?:attends|attendez|attendre)\s+(?:pas|jamais|plus|aucune?)\s+(?:(?:de|la|une|d_Q_|l_Q_)\s*)?(?:confirmation|approbation|autorisation|permission|validation|accord|consentement|r[e\xE9]ponse)\b' }
    @{ Check = $false; Regex = New-AwAgtTextRegex '\bpas\s+(?:besoin|la\s+peine)\s+(?:de\s+|d_Q_\s*)(?:(?:me|lui|leur|nous|vous)\s+)?(?:demander|confirmer|valider|faire\s+valider|attendre)\b' }
    @{ Check = $true;  Regex = New-AwAgtTextRegex '\b(?:approuve[rz]?|valide[rz]?|accepte[rz]?)\s+(?:(?:tout|toutes|tous|les\s+\w+)\s+)?automatiquement\b|\bauto-?approuv\w*|\bauto-?approbation\b|\bapprobation\s+automatique\b' }
    @{ Check = $true;  Regex = New-AwAgtTextRegex '\b(?:ignore[rz]?|saute[rz]?|contourne[rz]?|d[e\xE9]sactive[rz]?|passe[rz]?\s+outre(?:\s+[a\xE0])?)\s+(?:(?:toutes|tous|les|la|le|chaque|aux?|des|l_Q_|d_Q_)\s*){0,3}(?:demandes?\s+(?:de\s+|d_Q_\s*))?(?:approbations?|confirmations?|validations?|autorisations?|permissions?)\b' }
)
$script:AwAgtNegationRegex = New-AwAgtTextRegex ('\b(?:never|not|cannot|can_Q_?t|don_Q_?t|doesn_Q_?t|won_Q_?t|shouldn_Q_?t|mustn_Q_?t|avoid|forbidden|prohibited|' +
    'jamais|pas|ne|interdit|[e\xE9]vite[rz]?)\b|\bn_Q_(?!importe)')

# Hidden directives inside HTML comments.
$script:AwAgtInjectionRegex = New-AwAgtTextRegex ('\b(?:ignore|disregard|forget|override|bypass)\s+(?:(?:all|any|the|your|my|these|those|every)\s+){0,3}' +
    '(?:(?:previous|prior|above|earlier|preceding|former|original|system|other|existing)\s+)?(?:instructions?|rules|prompts?|guidelines|directives|guardrails|constraints|polic(?:y|ies))\b' +
    '|\b(?:system\s+prompt|new\s+instructions|you\s+are\s+now)\b' +
    '|\b(?:ignore[rz]?|oublie[rz]?)\s+(?:(?:toutes|tous|les|tes|vos|ces)\s+){0,3}(?:instructions|r[e\xE8]gles|consignes)\b')
$script:AwAgtAiAddressRegex = New-AwAgtTextRegex '(?<!j_Q_)\b(?:ai|assistants?|agents?|copilot|claude|llms?|chatgpt|gpt|models?|bots?|ia|mod[e\xE8]les?)\b'
$script:AwAgtModalRegex = New-AwAgtTextRegex ('\b(?:must|should|shall|always|never|do\s+not|don_Q_?t|please|ignore|run|execute|delete|send|read|fetch|call|skip|approve|' +
    'doit|dois|devez|doivent|toujours|jamais|ex[e\xE9]cute[rz]?|lance[rz]?|envoie[rz]?|lis|lisez|lire|ignore[rz]?)\b')
$script:AwAgtNetworkCommands = Get-AwAgtDataList $script:AwAgtData 'networkCommands'
$script:AwAgtImperativeVerbs = [string[]]((Get-AwAgtDataList $script:AwAgtData 'imperativeVerbs') + $script:AwAgtNetworkCommands)
$script:AwAgtExfilVerbs = [string[]]((Get-AwAgtDataList $script:AwAgtData 'exfilVerbs') + $script:AwAgtNetworkCommands)
# Line starts allow only blanks before the bullet: \n\s* backtracked quadratically on a run of empty lines.
$script:AwAgtLeadingVerbRegex = New-AwAgtTextRegex ('(?:^|[.!?;:]\s+|\n[ \t]*(?:[-*+][ \t]+)?)(?:please\s+|now\s+|then\s+|first,?\s+)?(?:' +
    (Join-AwAgtAlternation -Tokens $script:AwAgtImperativeVerbs -Fragments (Get-AwAgtDataList $script:AwAgtData 'imperativeVerbsFr')) + ')\b')
$script:AwAgtSensitiveRegex = New-AwAgtTextRegex ('(?:\.env\b|\bsecrets?\b|\btokens?\b|\bpasswords?\b|\bcredentials?\b|\bapi[_ -]?keys?\b|\bid_rsa\b|\.ssh\b|\.aws\b|' +
    '\bprivate\s+keys?\b|\bmots?\s+de\s+passe\b|\bjetons?\b|\bidentifiants\b|\bcl[e\xE9]s?\s+(?:api|priv[e\xE9]es?)\b)')
$script:AwAgtActionRegex = New-AwAgtTextRegex ('\b(?:' +
    (Join-AwAgtAlternation -Tokens $script:AwAgtExfilVerbs -Fragments (Get-AwAgtDataList $script:AwAgtData 'exfilVerbsFr')) + ')\b')
$script:AwAgtBenignCommentRegex = New-AwAgtTextRegex ('\b(?:auto-?generated|generated\s+(?:by|from|with)|do\s+not\s+edit|don_Q_?t\s+edit|re-?generate[sd]?|' +
    'update\s+this\s+(?:file|section|table)|ne\s+pas\s+modifier|g[e\xE9]n[e\xE9]r[e\xE9]\s+(?:automatiquement|par))\b')
$script:AwAgtFenceRegex = New-AwAgtRegex -Multiline -CaseSensitive -Pattern '^[ ]{0,3}(?:```|~~~)'

# Zero-width and bidi characters, and runs of tag characters (U+E0000-U+E007F as UTF-16 pairs).
# Regex escapes in single-quoted strings keep this file ASCII.
$script:AwAgtInvisibleRegex = New-AwAgtRegex -CaseSensitive -Pattern '[\u200B-\u200D\u2060\uFEFF\u202A-\u202E\u2066-\u2069]'
$script:AwAgtTagRunRegex = New-AwAgtRegex -CaseSensitive -Pattern '(?:\uDB40[\uDC00-\uDC7F])+'
$script:AwAgtInvisibleNames = @{
    0x200B = 'zero width space'; 0x200C = 'zero width non-joiner'; 0x200D = 'zero width joiner'; 0x2060 = 'word joiner'
    0xFEFF = 'zero width no-break space'; 0x202A = 'left-to-right embedding'; 0x202B = 'right-to-left embedding'
    0x202C = 'pop directional formatting'; 0x202D = 'left-to-right override'; 0x202E = 'right-to-left override'
    0x2066 = 'left-to-right isolate'; 0x2067 = 'right-to-left isolate'; 0x2068 = 'first strong isolate'; 0x2069 = 'pop directional isolate'
}

$script:AwAgtUrlRegex = New-AwAgtRegex -Pattern '(?<![A-Za-z0-9+.-])(?:https?|wss?|ftp)://(?:\[[0-9A-Fa-f:.]{2,45}\])?[^\s<>"''`)\]}|\\^]{0,2048}'
$script:AwAgtInternalSuffixes = Get-AwAgtDataList $script:AwAgtData 'internalHostSuffixes'

# --- Content scanners ----------------------------------------------------------------------

function Test-AwAgtBenignJoiner {
    # Zero-width (non-)joiners that are part of emoji sequences or of scripts that need them.
    param([string]$Text, [int]$Index)
    $c = [int]$Text[$Index]
    $prev = if ($Index -gt 0) { [int]$Text[$Index - 1] } else { -1 }
    $next = if ($Index + 1 -lt $Text.Length) { [int]$Text[$Index + 1] } else { -1 }
    # Arabic, Indic and Arabic presentation forms use joiners between letters.
    if (($prev -ge 0x0600 -and $prev -le 0x08FF) -or ($prev -ge 0x0900 -and $prev -le 0x0DFF) -or ($prev -ge 0xFB50 -and $prev -le 0xFDFF)) { return $true }
    if ($c -eq 0x200D) {
        $emojiBefore = ($prev -ge 0xDC00 -and $prev -le 0xDFFF) -or $prev -eq 0xFE0F -or ($prev -ge 0x2600 -and $prev -le 0x27BF)
        $emojiAfter = ($next -ge 0xD800 -and $next -le 0xDBFF) -or ($next -ge 0x2600 -and $next -le 0x27BF)
        if ($emojiBefore -and $emojiAfter) { return $true }
    }
    return $false
}

function Find-AwAgtInvisibleChars {
    # Zero-width and bidi characters: @{ Counts = code -> count; FirstIndex; Total; Capped }.
    param([string]$Text)
    $counts = @{}; $first = -1; $total = 0; $seen = 0; $capped = $false
    $m = $script:AwAgtInvisibleRegex.Match($Text)
    while ($m.Success) {
        $seen++
        if ($seen -gt 5000) { $capped = $true; break }
        $i = $m.Index; $c = [int]$Text[$i]
        $skip = ($c -eq 0xFEFF -and $i -eq 0) -or (($c -eq 0x200C -or $c -eq 0x200D) -and (Test-AwAgtBenignJoiner $Text $i))
        if (-not $skip) {
            if ($counts.ContainsKey($c)) { $counts[$c]++ } else { $counts[$c] = 1 }
            if ($first -lt 0) { $first = $i }
            $total++
        }
        $m = $m.NextMatch()
    }
    @{ Counts = $counts; FirstIndex = $first; Total = $total; Capped = $capped }
}

function Find-AwAgtBypassPhrases {
    # Approval-bypass phrases: list of @{ Index; Phrase }, sorted by position.
    param([string]$Text)
    $hits = New-Object System.Collections.ArrayList
    foreach ($p in $script:AwAgtBypassPatterns) {
        $n = 0
        $m = $p.Regex.Match($Text)
        while ($m.Success -and $n -lt $script:AwAgtMaxMatchesPerFile) {
            $n++
            $keep = $true
            if ($p.Check) {
                $lo = [Math]::Max(0, $m.Index - 120)
                $prefix = $Text.Substring($lo, $m.Index - $lo)
                $cut = $prefix.LastIndexOfAny([char[]]@('.', '!', '?', ';', ':', "`n"))
                if ($cut -ge 0) { $prefix = $prefix.Substring($cut + 1) }
                if ($script:AwAgtNegationRegex.IsMatch($prefix)) { $keep = $false }
            }
            if ($keep) { [void]$hits.Add([pscustomobject]@{ Index = $m.Index; Phrase = $m.Value }) }
            $m = $m.NextMatch()
        }
    }
    return ,@($hits | Sort-Object -Property Index)
}

function Test-AwAgtHiddenDirective {
    # True when the text of an HTML comment reads as an instruction.
    param([string]$Text)
    if ($script:AwAgtInjectionRegex.IsMatch($Text)) { return $true }
    if ($script:AwAgtSensitiveRegex.IsMatch($Text) -and $script:AwAgtActionRegex.IsMatch($Text)) { return $true }
    if ($script:AwAgtBenignCommentRegex.IsMatch($Text)) { return $false }
    if ($script:AwAgtLeadingVerbRegex.IsMatch($Text)) { return $true }
    return ($script:AwAgtAiAddressRegex.IsMatch($Text) -and $script:AwAgtModalRegex.IsMatch($Text))
}

function Find-AwAgtHtmlComments {
    # HTML comments (an unclosed one runs to the end): list of @{ Index; Text }, plus Capped.
    param([string]$Text)
    $list = New-Object System.Collections.ArrayList
    $pos = 0; $capped = $false
    while ($pos -lt $Text.Length) {
        $open = $Text.IndexOf('<!--', $pos, [StringComparison]::Ordinal)
        if ($open -lt 0) { break }
        if ($list.Count -ge $script:AwAgtMaxComments) { $capped = $true; break }
        $close = $Text.IndexOf('-->', $open + 4, [StringComparison]::Ordinal)
        $end = if ($close -lt 0) { $Text.Length } else { $close }
        $len = [Math]::Min($end - ($open + 4), 2000)
        [void]$list.Add([pscustomobject]@{ Index = $open; Text = $Text.Substring($open + 4, $len).Trim() })
        if ($close -lt 0) { break }
        $pos = $close + 3
    }
    @{ Comments = $list.ToArray(); Capped = $capped }
}

function Get-AwAgtInternalHost {
    # Why a URL host is private or internal, or $null (public hosts and loopback).
    param([System.Uri]$Uri)
    $hostType = [string]$Uri.HostNameType
    if ($hostType -eq 'IPv4') {
        $b = ([System.Net.IPAddress]::Parse($Uri.Host)).GetAddressBytes()
        if ($b[0] -eq 10) { return 'private IPv4 address (10.0.0.0/8)' }
        if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return 'private IPv4 address (172.16.0.0/12)' }
        if ($b[0] -eq 192 -and $b[1] -eq 168) { return 'private IPv4 address (192.168.0.0/16)' }
        if ($b[0] -eq 169 -and $b[1] -eq 254) {
            if ($b[2] -eq 169 -and $b[3] -eq 254) { return 'cloud instance metadata endpoint' }
            return 'link-local IPv4 address (169.254.0.0/16)'
        }
        if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return 'shared address space (100.64.0.0/10)' }
        return $null
    }
    if ($hostType -eq 'IPv6') {
        $ip = $null
        if (-not [System.Net.IPAddress]::TryParse($Uri.Host.Trim([char[]]@('[', ']')), [ref]$ip)) { return $null }
        if ([System.Net.IPAddress]::IsLoopback($ip)) { return $null }
        if ($ip.IsIPv6LinkLocal) { return 'link-local IPv6 address (fe80::/10)' }
        if ($ip.IsIPv6SiteLocal) { return 'site-local IPv6 address (fec0::/10)' }
        if (($ip.GetAddressBytes()[0] -band 0xFE) -eq 0xFC) { return 'unique local IPv6 address (fc00::/7)' }
        return $null
    }
    if ($hostType -ne 'Dns' -and $hostType -ne 'Basic') { return $null }
    $h = $Uri.Host.ToLowerInvariant().TrimEnd('.')
    if (-not $h -or $h -eq 'localhost' -or $h.EndsWith('.localhost')) { return $null }
    if (-not $h.Contains('.')) { return 'single-label (intranet) hostname' }
    foreach ($s in $script:AwAgtInternalSuffixes) {
        if ($h.EndsWith($s)) { return "internal domain suffix ($s)" }
    }
    return $null
}

function New-AwAgtFinding {
    # Finding on an agent file, with the harness of that file unless the rule is harness-specific.
    param($Ctx, $AgentFile, [string]$RuleId, [string]$Evidence, $Line, [string]$Key, [string]$Severity, [switch]$KeepRuleHarness)
    $params = @{ RuleId = $RuleId; Evidence = $Evidence; Location = @{ Path = $AgentFile.Path; Line = $Line; Key = $Key } }
    if (-not $KeepRuleHarness) { $params['Harness'] = Get-AwAgtHarness $Ctx $AgentFile }
    if ($Severity) { $params['Severity'] = $Severity }
    New-AwFinding @params
}

# --- Frontmatter rules ---------------------------------------------------------------------

Register-AwRule -Id 'AW-AGT-001' -Title "Custom agent enables every tool (tools: '*')" `
    -Severity 'high' -Category 'agent-files' -Harness 'generic' `
    -Description ("A custom agent (.agent.md) or chat mode (.chatmode.md) lists '*' in its tools. GitHub's custom agent reference, which covers GitHub.com, " +
        "Copilot CLI and IDEs, documents tools: ['*'] as enabling all available tools: terminal, file edits, web access and every MCP tool. A prompt-injected " +
        "or misbehaving agent then has the widest possible reach. The VS Code custom agent page itself only documents the '<server>/*' form.") `
    -Fix "Replace '*' with the explicit tools the agent needs, for example tools: ['search', 'usages', 'problems'] for a read-only reviewer. Add terminal or edit tools only to agents that must use them." `
    -References @('OWASP-ASI02', 'OWASP-ASI03', $script:AwAgtDocGitHubAgents, $script:AwAgtDocCustomAgents) `
    -Confidence 'high' -Check {
        param($Ctx)
        foreach ($af in (Get-AwAgtCustomAgents $Ctx)) {
            $tools = Get-AwAgtTools $af
            if ($null -eq $tools -or $tools -notcontains '*') { continue }
            New-AwAgtFinding $Ctx $af 'AW-AGT-001' (Protect-AwAgtEvidence ('tools: ' + (Format-AwAgtList $tools))) (Find-AwAgtKeyLine $af 'tools') 'tools'
        }
    }

Register-AwRule -Id 'AW-AGT-002' -Title "Custom agent enables every tool of an MCP server ('<server>/*')" `
    -Severity 'medium' -Category 'agent-files' -Harness 'generic' `
    -Description ("The tools list uses '<server>/*', which enables every tool of that MCP server, including tools that a server update adds later. " +
        "Write or admin tools of the server become available to the agent without a review.") `
    -Fix "List the individual server tools the agent needs (for example 'github/get_issue' instead of 'github/*')." `
    -References @('OWASP-ASI02', 'OWASP-ASI04', $script:AwAgtDocCustomAgents, $script:AwAgtDocGitHubAgents) `
    -Confidence 'high' -Check {
        param($Ctx)
        foreach ($af in (Get-AwAgtCustomAgents $Ctx)) {
            $tools = Get-AwAgtTools $af
            if ($null -eq $tools -or $tools -contains '*') { continue }
            $wild = @($tools | Where-Object { $_ -match '^[^\s/*]+/\*$' })
            if ($wild.Count -eq 0) { continue }
            New-AwAgtFinding $Ctx $af 'AW-AGT-002' (Protect-AwAgtEvidence ('tools: ' + (Format-AwAgtList $wild) + ' (all tools of these MCP servers)')) (Find-AwAgtKeyLine $af 'tools') 'tools'
        }
    }

Register-AwRule -Id 'AW-AGT-003' -Title 'Custom agent without a tools list (all tools enabled)' `
    -Severity 'medium' -Category 'agent-files' -Harness 'generic' `
    -Description ("A .agent.md file has no tools property. GitHub's custom agent reference states that an unset tools property enables all available tools. " +
        "The VS Code custom agent page does not state this default, so confirm the effective tool list in your VS Code build.") `
    -Fix "Add an explicit tools list with only the tools the agent needs; use tools: [] for an agent that needs no tools." `
    -References @('OWASP-ASI02', 'OWASP-ASI03', $script:AwAgtDocGitHubAgents) `
    -Confidence 'medium' -Check {
        param($Ctx)
        foreach ($af in @($Ctx.AgentFiles | Where-Object { $null -ne $_ -and $_.Kind -eq 'agent' })) {
            if ($null -ne (Get-AwAgtTools $af)) { continue }
            # A 'tools:' line the YAML subset could not parse is not a missing list.
            if ($null -ne (Find-AwAgtKeyLine $af 'tools')) { continue }
            New-AwAgtFinding $Ctx $af 'AW-AGT-003' 'tools not set (defaults to all available tools)' 1 'tools'
        }
    }

Register-AwRule -Id 'AW-AGT-004' -Title "Custom agent can call any agent as a subagent (agents: '*')" `
    -Severity 'medium' -Category 'agent-files' -Harness 'vscode-copilot' `
    -Description ("agents: '*' lets this agent invoke every other custom agent as a subagent, including agents with broader tools. That bypasses the tool " +
        "restrictions of this agent (privilege escalation through subagents). It takes effect when the agent tool is enabled for the agent.") `
    -Fix "Set agents to the explicit list of subagents needed, or agents: [] to prevent subagent use. Set disable-model-invocation: true on powerful agents so that other agents cannot invoke them." `
    -References @('OWASP-ASI03', 'OWASP-ASI07', $script:AwAgtDocCustomAgents) `
    -Confidence 'high' -Check {
        param($Ctx)
        foreach ($af in (Get-AwAgtCustomAgents $Ctx)) {
            if (-not $af.Frontmatter.ContainsKey('agents')) { continue }
            if ((ConvertTo-AwAgtNameList $af.Frontmatter['agents']) -notcontains '*') { continue }
            New-AwAgtFinding $Ctx $af 'AW-AGT-004' "agents: '*' (any custom agent can be invoked as a subagent)" (Find-AwAgtKeyLine $af 'agents') 'agents' -KeepRuleHarness
        }
    }

Register-AwRule -Id 'AW-AGT-005' -Title 'Handoff submits its prompt automatically (send: true)' `
    -Severity 'medium' -Category 'agent-files' -Harness 'vscode-copilot' `
    -Description ("A handoff with send: true submits its prompt to the next agent as soon as the handoff is chosen, without the user reviewing it " +
        "(the documented default is false). A chain of agents can then go from planning to editing or deploying with no human checkpoint.") `
    -Fix "Remove send: true (or set send: false) so that the user reviews and submits each handoff prompt." `
    -References @('OWASP-ASI09', 'OWASP-ASI07', $script:AwAgtDocCustomAgents) `
    -Confidence 'high' -Check {
        param($Ctx)
        foreach ($af in (Get-AwAgtCustomAgents $Ctx)) {
            $handoffs = $af.Frontmatter['handoffs']
            if ($null -eq $handoffs) { continue }
            $items = if ($handoffs -is [System.Collections.IDictionary]) { @($handoffs) } elseif ($handoffs -is [System.Collections.IEnumerable] -and $handoffs -isnot [string]) { @($handoffs) } else { @() }
            $auto = New-Object System.Collections.Generic.List[string]
            foreach ($h in $items) {
                if ($h -isnot [System.Collections.IDictionary]) { continue }
                $send = $h['send']
                if ($send -is [bool] -and $send -or ($send -is [string] -and $send.Trim() -ieq 'true')) {
                    $target = [string]$h['agent']; $label = [string]$h['label']
                    $auto.Add($(if ($label) { "$target ('$label')" } else { $target }))
                }
            }
            if ($auto.Count -eq 0) { continue }
            $line = Find-AwAgtKeyLine $af 'send' '[ \t]*["'']?(?i:true)' -Nested
            New-AwAgtFinding $Ctx $af 'AW-AGT-005' (Protect-AwAgtEvidence ('handoffs with send: true -> ' + (Format-AwAgtList $auto.ToArray()))) $line 'handoffs' -KeepRuleHarness
        }
    }

Register-AwRule -Id 'AW-AGT-006' -Title "Prompt file grants tools beyond its agent's list" `
    -Severity 'medium' -Category 'agent-files' -Harness 'vscode-copilot' `
    -Description ("In a Local harness session, the tools list of a prompt file (.prompt.md) takes precedence over the tools of the custom agent it runs with. " +
        "A prompt file that lists tools its agent does not grant widens that agent's permissions whenever it is used. When the prompt file does not name a " +
        "custom agent of the workspace, the finding is low: it lists tools that none of the workspace's custom agents grant. Tool sets and tool aliases are " +
        "not expanded, so a tool that the agent reaches through a tool set may be reported; confirm the effective tool list in the session.") `
    -Fix "Limit the prompt file's tools to the tools of its agent, or remove the prompt file's tools property so that the agent's list applies. Review prompt files like code (for example with CODEOWNERS)." `
    -References @('OWASP-ASI03', 'OWASP-ASI02', $script:AwAgtDocCustomAgents, $script:AwAgtDocPromptFiles) `
    -Confidence 'medium' -Check {
        param($Ctx)
        $byName = @{}       # agent name (case-insensitive) -> granted tools, or $null for all tools
        $union = New-Object System.Collections.Generic.List[string]
        $unionAll = $false; $explicit = 0
        foreach ($a in (Get-AwAgtCustomAgents $Ctx)) {
            $tools = Get-AwAgtTools $a
            if ($null -eq $tools -or $tools -contains '*') {
                $byName[(Get-AwAgtName $a)] = $null
                $unionAll = $true
            } else {
                $byName[(Get-AwAgtName $a)] = $tools
                $explicit++
                foreach ($t in $tools) { $union.Add($t) }
            }
        }
        foreach ($p in @($Ctx.AgentFiles | Where-Object { $null -ne $_ -and $_.Kind -eq 'prompt' })) {
            $ptools = Get-AwAgtTools $p
            if ($null -eq $ptools -or $ptools.Count -eq 0) { continue }
            $agentName = [string]$p.Frontmatter['agent']
            if (-not $agentName) { $agentName = [string]$p.Frontmatter['mode'] }
            $agentName = $agentName.Trim()
            $line = Find-AwAgtKeyLine $p 'tools'
            if ($agentName -and $byName.ContainsKey($agentName)) {
                $granted = $byName[$agentName]
                if ($null -eq $granted) { continue }
                $extra = @($ptools | Where-Object { -not (Test-AwAgtToolGranted $_ $granted) })
                if ($extra.Count -eq 0) { continue }
                $ev = "prompt tools [$(Format-AwAgtList $extra)] are not granted by agent '$agentName' (agent tools: $(Format-AwAgtList $granted))"
                New-AwAgtFinding $Ctx $p 'AW-AGT-006' (Protect-AwAgtEvidence $ev 240) $line 'tools' -KeepRuleHarness
                continue
            }
            if ($unionAll -or $explicit -eq 0) { continue }
            $extra = @($ptools | Where-Object { -not (Test-AwAgtToolGranted $_ $union.ToArray()) })
            if ($extra.Count -eq 0) { continue }
            $who = if (-not $agentName) { 'the built-in agent, the default when tools are set' }
                   elseif ($script:AwAgtBuiltInAgents -contains $agentName) { "the built-in agent '$agentName'" }
                   else { "agent '$agentName', not found in the workspace" }
            $ev = "prompt tools [$(Format-AwAgtList $extra)] are granted by none of the workspace's custom agents (prompt runs with $who)"
            New-AwAgtFinding $Ctx $p 'AW-AGT-006' (Protect-AwAgtEvidence $ev 240) $line 'tools' -Severity 'low' -KeepRuleHarness
        }
    }

# --- Content rules -------------------------------------------------------------------------

Register-AwRule -Id 'AW-AGT-007' -Title 'Instructions tell the agent not to ask for approval' `
    -Severity 'medium' -Category 'agent-files' -Harness 'generic' `
    -Description ("Instruction or agent text tells the agent to act without asking for approval or confirmation (English or French phrases such as " +
        "'without asking', 'don't ask for confirmation', 'auto-approve', 'skip approval', 'sans demander', 'ne demande pas de confirmation'). " +
        "Instruction files are sent with every request, so such text pushes the model to skip the human checks the harness relies on; it is also a common " +
        "prompt-injection payload. The match is a heuristic: a phrase preceded by a negation in the same clause ('never ... without asking') is ignored, " +
        "but other false positives are possible.") `
    -Fix "Remove the directive. Approvals are enforced by harness settings, not by instructions: keep the approval settings strict and state that the agent must ask before running commands or changing files." `
    -References @('OWASP-ASI01', 'OWASP-ASI09', $script:AwAgtDocVSCodeSec) `
    -Confidence 'medium' -Check {
        param($Ctx)
        foreach ($af in @($Ctx.AgentFiles | Where-Object { $null -ne $_ })) {
            $text = Get-AwAgtScanText $af.Raw
            if (-not $text) { continue }
            $counter = New-AwAgtLineCounter $text
            $lines = @{}
            foreach ($hit in (Find-AwAgtBypassPhrases $text)) {
                if ($lines.Count -ge $script:AwAgtMaxFindingsPerFile) { break }
                $line = Get-AwAgtLineAt $counter $hit.Index
                if ($lines.ContainsKey($line)) { continue }
                $lines[$line] = $true
                $ev = "'" + (Protect-AwAgtEvidence $hit.Phrase 60) + "' in: " + (Protect-AwAgtEvidence (Get-AwAgtLineText $text $hit.Index) 160)
                New-AwAgtFinding $Ctx $af 'AW-AGT-007' $ev $line $null
            }
        }
    }

Register-AwRule -Id 'AW-AGT-008' -Title 'Hidden instruction in an HTML comment' `
    -Severity 'high' -Category 'agent-files' -Harness 'generic' `
    -Description ("An HTML comment in an agent or instruction file contains an instruction (for example 'ignore previous instructions', 'run ...', " +
        "a request to read or send secrets, or a directive addressed to an AI agent). Comments are invisible in rendered Markdown, so reviewers miss them, " +
        "while the raw text can reach the model: a classic prompt-injection vector. Claude Code documents that block-level HTML comments in CLAUDE.md are " +
        "stripped before the file enters the context, so those findings are low; VS Code does not document whether comments in instruction files are removed. " +
        "The detection is a heuristic.") `
    -Fix "Delete the comment, or turn a legitimate note into visible text. Check who added it (git log / git blame) and treat it as a possible prompt-injection attempt." `
    -References @('OWASP-ASI01', 'OWASP-ASI06', $script:AwAgtDocVSCodeSec, $script:AwAgtDocClaudeMemory) `
    -Confidence 'medium' -Check {
        param($Ctx)
        foreach ($af in @($Ctx.AgentFiles | Where-Object { $null -ne $_ })) {
            $text = Get-AwAgtScanText $af.Raw
            if ($text.IndexOf('<!--', [StringComparison]::Ordinal) -lt 0) { continue }
            $scan = Find-AwAgtHtmlComments $text
            $fences = $null
            if ($af.Kind -eq 'claude-md') { $fences = @($script:AwAgtFenceRegex.Matches($text) | Select-Object -First 10000 | ForEach-Object { $_.Index }) }
            $counter = New-AwAgtLineCounter $text
            $count = 0
            # Bound the total comment text whose directive status is tested: 2000 comments of 2000
            # characters each would otherwise be a lot of regex work on a crafted file.
            $budget = $script:AwAgtMaxDirectiveChars
            foreach ($c in $scan.Comments) {
                if ($count -ge $script:AwAgtMaxFindingsPerFile -or $budget -le 0) { break }
                $budget -= ($c.Text.Length + 1)
                if (-not $c.Text -or -not (Test-AwAgtHiddenDirective $c.Text)) { continue }
                $count++
                $severity = $null; $note = ''
                if ($af.Kind -eq 'claude-md') {
                    $lineStart = $text.LastIndexOf([char]"`n", [Math]::Max(0, $c.Index - 1)) + 1
                    $blockLevel = $text.Substring($lineStart, $c.Index - $lineStart).Trim().Length -eq 0
                    $inFence = (@($fences | Where-Object { $_ -lt $c.Index }).Count % 2) -eq 1
                    if ($blockLevel -and -not $inFence) {
                        $severity = 'low'
                        $note = ' (block-level comment: Claude Code strips it from CLAUDE.md before adding it to the context, but tools that read the file still see it)'
                    }
                }
                $ev = 'HTML comment: ' + (Protect-AwAgtEvidence $c.Text 140) + $note
                New-AwAgtFinding $Ctx $af 'AW-AGT-008' $ev (Get-AwAgtLineAt $counter $c.Index) $null -Severity $severity
            }
            if ($scan.Capped) {
                New-AwAgtFinding $Ctx $af 'AW-AGT-008' "More than $($script:AwAgtMaxComments) HTML comments: the rest of the file was not checked." $null $null -Severity 'info'
            }
        }
    }

Register-AwRule -Id 'AW-AGT-009' -Title 'Invisible or bidirectional control characters in an agent file' `
    -Severity 'high' -Category 'agent-files' -Harness 'generic' `
    -Description ("The file contains zero-width characters (U+200B-U+200D, U+2060, U+FEFF inside the text) or Unicode bidirectional controls " +
        "(U+202A-U+202E, U+2066-U+2069). They are invisible or reorder text on screen, so a reviewer reads something different from what the model " +
        "receives (hidden prompt injection, 'Trojan Source'). Zero-width joiners inside emoji sequences or scripts that need them, and a leading byte " +
        "order mark, are ignored.") `
    -Fix "Remove the characters (for example in an editor that shows invisible characters, or by searching for the code points) and review the surrounding text." `
    -References @('OWASP-ASI01', 'OWASP-ASI06', $script:AwAgtDocVSCodeSec) `
    -Confidence 'high' -Check {
        param($Ctx)
        foreach ($af in @($Ctx.AgentFiles | Where-Object { $null -ne $_ })) {
            $text = Get-AwAgtScanText $af.Raw
            $r = Find-AwAgtInvisibleChars $text
            if ($r.Total -eq 0) { continue }
            $codes = [int[]]@($r.Counts.Keys); [Array]::Sort($codes)
            $parts = foreach ($code in $codes) { '{0} x U+{1:X4} ({2})' -f $r.Counts[$code], $code, $script:AwAgtInvisibleNames[$code] }
            $more = if ($r.Capped) { ' (scan stopped after 5000 characters)' } else { '' }
            $ev = ($parts -join ', ') + $more + '; first in: ' + (Protect-AwAgtEvidence (Get-AwAgtLineText $text $r.FirstIndex) 120)
            New-AwAgtFinding $Ctx $af 'AW-AGT-009' $ev (Get-AwAgtLineAt (New-AwAgtLineCounter $text) $r.FirstIndex) $null
        }
    }

Register-AwRule -Id 'AW-AGT-010' -Title 'Unicode tag characters hide text in an agent file' `
    -Severity 'high' -Category 'agent-files' -Harness 'generic' `
    -Description ("The file contains Unicode tag characters (U+E0000-U+E007F). They render as nothing but encode ASCII text that models can read, " +
        "a known way to hide instructions ('ASCII smuggling'). The evidence shows the decoded text.") `
    -Fix "Remove the tag characters, review the decoded text, and find out how they entered the file." `
    -References @('OWASP-ASI01', 'OWASP-ASI06', $script:AwAgtDocVSCodeSec) `
    -Confidence 'high' -Check {
        param($Ctx)
        foreach ($af in @($Ctx.AgentFiles | Where-Object { $null -ne $_ })) {
            $text = Get-AwAgtScanText $af.Raw
            $m = $script:AwAgtTagRunRegex.Match($text)
            if (-not $m.Success) { continue }
            $first = $m.Index; $total = 0; $runs = 0
            $decoded = New-Object System.Text.StringBuilder
            while ($m.Success -and $runs -lt 1000) {
                $runs++
                $total += $m.Length / 2
                if ($decoded.Length -lt 400) {
                    for ($k = 0; $k + 1 -lt $m.Length -and $decoded.Length -lt 400; $k += 2) {
                        $ascii = [int]$m.Value[$k + 1] - 0xDC00
                        if ($ascii -ge 0x20 -and $ascii -le 0x7E) { [void]$decoded.Append([char]$ascii) }
                    }
                    [void]$decoded.Append(' ')
                }
                $m = $m.NextMatch()
            }
            $ev = "$total tag characters; decoded text: '" + (Protect-AwAgtEvidence $decoded.ToString() 140) + "'"
            New-AwAgtFinding $Ctx $af 'AW-AGT-010' $ev (Get-AwAgtLineAt (New-AwAgtLineCounter $text) $first) $null
        }
    }

Register-AwRule -Id 'AW-AGT-011' -Title 'Instructions point to private or internal URLs' `
    -Severity 'low' -Category 'agent-files' -Harness 'generic' `
    -Description ("Agent or instruction files contain URLs to private IP addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, link-local, the " +
        "169.254.169.254 metadata endpoint, IPv6 unique local) or internal hostnames (single-label names, .local, .internal, .corp, .lan...). They reveal " +
        "internal infrastructure to anyone who can read the files and steer the agent's web and terminal tools toward internal services. Loopback " +
        "addresses (localhost, 127.0.0.0/8) are ignored.") `
    -Fix "Remove internal URLs from shared instruction files or replace them with placeholders; let agents reach internal services only through approved, authenticated tools." `
    -References @('OWASP-ASI02', $script:AwAgtDocVSCodeSec) `
    -Confidence 'high' -Check {
        param($Ctx)
        foreach ($af in @($Ctx.AgentFiles | Where-Object { $null -ne $_ })) {
            $text = Get-AwAgtScanText $af.Raw
            if ($text.IndexOf('://', [StringComparison]::Ordinal) -lt 0) { continue }
            $counter = New-AwAgtLineCounter $text
            $seen = @{}; $n = 0
            $m = $script:AwAgtUrlRegex.Match($text)
            while ($m.Success -and $n -lt $script:AwAgtMaxMatchesPerFile -and $seen.Count -lt $script:AwAgtMaxFindingsPerFile) {
                $n++
                $u = $null
                $candidate = $m.Value.TrimEnd([char[]]@('.', ',', ';', ':', '!', '?', "'", '*', '_'))
                if ([System.Uri]::TryCreate($candidate, [System.UriKind]::Absolute, [ref]$u)) {
                    $reason = $null
                    try { $reason = Get-AwAgtInternalHost $u } catch { $reason = $null }
                    if ($reason -and -not $seen.ContainsKey($u.Authority)) {
                        $seen[$u.Authority] = $true
                        $shown = $u.Scheme + '://' + $u.Authority + $(if ($u.PathAndQuery.Length -gt 1) { '/' + $script:AwEllipsis } else { '' })
                        New-AwAgtFinding $Ctx $af 'AW-AGT-011' ((Protect-AwAgtEvidence $shown 120) + " ($reason)") (Get-AwAgtLineAt $counter $m.Index) $null
                    }
                }
                $m = $m.NextMatch()
            }
        }
    }

Register-AwRule -Id 'AW-AGT-012' -Title 'Custom agent model not pinned' `
    -Severity 'info' -Category 'agent-files' -Harness 'generic' `
    -Description ("The custom agent does not set model (or sets 'auto'), so it runs with whichever model is selected in the model picker. Its behavior " +
        "then depends on each user's choice and changes over time, which makes reviews and tests of the agent hard to reproduce.") `
    -Fix "Set model to the reviewed model, for example model: 'GPT-5 (copilot)', or to a prioritized list of reviewed models." `
    -References @('OWASP-ASI04', $script:AwAgtDocCustomAgents, $script:AwAgtDocGitHubAgents) `
    -Confidence 'high' -Check {
        param($Ctx)
        foreach ($af in (Get-AwAgtCustomAgents $Ctx)) {
            $models = ConvertTo-AwAgtNameList $af.Frontmatter['model']
            $pinned = @($models | Where-Object { $_ -and $_ -ine 'auto' })
            if ($pinned.Count -gt 0) { continue }
            $ev = if ($models.Count -gt 0) { "model: $(Protect-AwAgtEvidence (Format-AwAgtList $models) 60) (automatic selection)" } else { 'model not set (uses the model picker selection)' }
            New-AwAgtFinding $Ctx $af 'AW-AGT-012' $ev (Find-AwAgtKeyLine $af 'model') 'model'
        }
    }

Register-AwRule -Id 'AW-AGT-013' -Title 'Agent frontmatter hooks run only in the Local harness' `
    -Severity 'info' -Category 'agent-files' -Harness 'vscode-copilot' `
    -Description ("The agent defines hooks in its frontmatter (preview). VS Code runs them only in the Local harness while this agent is active, and " +
        "only with chat.useHooks enabled in a trusted workspace; the Copilot harness does not run them. Do not count them as a security control for " +
        "Copilot harness sessions, and review their commands: they run on the machine.") `
    -Fix "Keep security hooks in hook files that the target harness loads (managed or workspace hooks), and review frontmatter hook commands like scripts." `
    -References @('OWASP-ASI05', $script:AwAgtDocCustomAgents) `
    -Confidence 'high' -Check {
        param($Ctx)
        foreach ($af in (Get-AwAgtCustomAgents $Ctx)) {
            $hooks = $af.Frontmatter['hooks']
            if ($null -eq $hooks) { continue }
            $events = @()
            if ($hooks -is [System.Collections.IDictionary]) { $events = [string[]]@($hooks.Keys); [Array]::Sort($events, [StringComparer]::Ordinal) }
            elseif ($hooks -is [System.Collections.IEnumerable] -and $hooks -isnot [string]) { if (@($hooks).Count -eq 0) { continue } }
            elseif (-not [string]$hooks) { continue }
            $ev = if ($events.Count -gt 0) { 'hooks: ' + (Protect-AwAgtEvidence (Format-AwAgtList $events) 120) } else { 'hooks defined in the frontmatter' }
            New-AwAgtFinding $Ctx $af 'AW-AGT-013' $ev (Find-AwAgtKeyLine $af 'hooks') 'hooks' -KeepRuleHarness
        }
    }
