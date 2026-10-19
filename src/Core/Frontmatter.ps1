# Frontmatter parser for agent files: a small, indentation-based YAML subset.
# Supported: key: value, quoted strings, booleans, null, numbers, flow lists/maps,
# block lists, nested maps, lists of maps, block scalars (| and >). Anything else is
# skipped and reported in the '__errors' key. It never throws.

$script:AwYamlMaxDepth = 16
$script:AwYamlMaxLines = 2000   # real frontmatter is short; these two limits bound the cost of hostile files
$script:AwYamlMaxChars = 65536
# The plain key part is atomic: a lazy key followed by [ \t]* backtracked quadratically on a long
# line of blanks. The key keeps its trailing blanks, which ConvertFrom-AwYamlKey trims.
$script:AwYamlKeyRegex = New-Object System.Text.RegularExpressions.Regex -ArgumentList @(
    ('^(?<k>"(?:[^"\\]|\\.)*"|''(?:[^'']|'''')*''|[^\s#''"\[\]{},&*!|>%@`-](?>[^:#]*)|-[^\s:#](?>[^:#]*))' +
     '[ \t]*:(?:[ \t]+(?<v>.*))?$'),
    [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
)

function Add-AwYamlError {
    param($State, [int]$LineNo, [string]$Message)
    $State.Errors.Add("line ${LineNo}: $Message")
}

function Skip-AwYamlBlank {
    param($State)
    while ($State.Pos -lt $State.Lines.Count -and $State.Lines[$State.Pos].Skip) { $State.Pos++ }
}

function Skip-AwYamlChildren {
    # Skips the lines indented deeper than $Indent (children of a line we could not parse).
    param($State, [int]$Indent)
    while ($State.Pos -lt $State.Lines.Count) {
        $l = $State.Lines[$State.Pos]
        if (-not $l.Skip -and $l.Indent -le $Indent) { break }
        $State.Pos++
    }
}

function Test-AwYamlListItem {
    param([string]$Content)
    return ($Content -eq '-' -or $Content.StartsWith('- ') -or $Content.StartsWith("-`t"))
}

function Find-AwYamlFlowEnd {
    # Index of the bracket closing the flow collection that starts at 0, or -1.
    # With -Scan (an empty hashtable on the first call), a later call on the same text with more
    # appended resumes where the previous one stopped, so a value continued over many lines is
    # scanned once instead of once per line.
    param([string]$Text, [hashtable]$Scan)
    $depth = 0; $i = 0; $quote = [char]0; $n = $Text.Length
    if ($null -ne $Scan -and $Scan.ContainsKey('Pos')) { $depth = $Scan.Depth; $i = $Scan.Pos; $quote = $Scan.Quote }
    while ($i -lt $n) {
        $ch = $Text[$i]
        if ($quote -eq [char]'"') {
            if ($ch -eq [char]'\') {
                if ($i + 1 -ge $n) { break }
                $i += 2; continue
            }
            if ($ch -eq [char]'"') { $quote = [char]0 }
        } elseif ($quote -eq [char]"'") {
            if ($ch -eq [char]"'") {
                if ($i + 1 -ge $n) { break }
                if ($Text[$i + 1] -eq [char]"'") { $i += 2; continue }
                $quote = [char]0
            }
        } elseif ($ch -eq [char]'"' -or $ch -eq [char]"'") {
            $quote = $ch
        } elseif ($ch -eq [char]'[' -or $ch -eq [char]'{') {
            $depth++
        } elseif ($ch -eq [char]']' -or $ch -eq [char]'}') {
            $depth--
            if ($depth -eq 0) { return $i }
        }
        $i++
    }
    if ($null -ne $Scan) { $Scan['Pos'] = $i; $Scan['Depth'] = $depth; $Scan['Quote'] = $quote }
    return -1
}

function Split-AwYamlFlow {
    # Splits the inside of a flow collection on top-level commas (quotes and nesting respected).
    param([string]$Inner)
    $parts = New-Object System.Collections.Generic.List[string]
    $depth = 0; $i = 0; $n = $Inner.Length; $startAt = 0
    while ($i -lt $n) {
        $ch = $Inner[$i]
        if ($ch -eq [char]'"') {
            $i++
            while ($i -lt $n -and $Inner[$i] -ne [char]'"') { if ($Inner[$i] -eq [char]'\') { $i++ }; $i++ }
        } elseif ($ch -eq [char]"'") {
            $i++
            while ($i -lt $n) {
                if ($Inner[$i] -eq [char]"'") { if ($i + 1 -lt $n -and $Inner[$i + 1] -eq [char]"'") { $i++ } else { break } }
                $i++
            }
        } elseif ($ch -eq [char]'[' -or $ch -eq [char]'{') { $depth++ }
        elseif ($ch -eq [char]']' -or $ch -eq [char]'}') { $depth-- }
        elseif ($ch -eq [char]',' -and $depth -eq 0) {
            $parts.Add($Inner.Substring($startAt, $i - $startAt)); $startAt = $i + 1
        }
        $i++
    }
    $parts.Add($Inner.Substring($startAt))
    return ,$parts
}

function Get-AwYamlQuotedEnd {
    # Index of the closing quote of a quoted scalar starting at 0, or -1.
    param([string]$Text)
    $q = $Text[0]; $i = 1; $n = $Text.Length
    while ($i -lt $n) {
        if ($q -eq [char]'"' -and $Text[$i] -eq [char]'\') { $i += 2; continue }
        if ($Text[$i] -eq $q) {
            if ($q -eq [char]"'" -and $i + 1 -lt $n -and $Text[$i + 1] -eq [char]"'") { $i += 2; continue }
            return $i
        }
        $i++
    }
    return -1
}

function ConvertFrom-AwYamlDoubleQuoted {
    param([string]$Inner)
    $sb = New-Object System.Text.StringBuilder
    $i = 0; $n = $Inner.Length
    while ($i -lt $n) {
        $ch = $Inner[$i]
        if ($ch -ne [char]'\' -or $i + 1 -ge $n) { [void]$sb.Append($ch); $i++; continue }
        $e = [string]$Inner[$i + 1]; $i += 2
        switch -CaseSensitive ($e) {
            'n' { [void]$sb.Append("`n") }
            't' { [void]$sb.Append("`t") }
            'r' { [void]$sb.Append("`r") }
            '0' { [void]$sb.Append("`0") }
            'u' {
                $hex = if ($i + 4 -le $n) { $Inner.Substring($i, 4) } else { '' }
                if ($hex -match '^[0-9A-Fa-f]{4}$') { [void]$sb.Append([char][Convert]::ToInt32($hex, 16)); $i += 4 }
                else { [void]$sb.Append('\u') }
            }
            'x' {
                $hex = if ($i + 2 -le $n) { $Inner.Substring($i, 2) } else { '' }
                if ($hex -match '^[0-9A-Fa-f]{2}$') { [void]$sb.Append([char][Convert]::ToInt32($hex, 16)); $i += 2 }
                else { [void]$sb.Append('\x') }
            }
            default { [void]$sb.Append($e) }   # \" \\ \/ and unknown escapes
        }
    }
    return $sb.ToString()
}

function Remove-AwYamlComment {
    # Strips a trailing ' # comment' from a plain scalar.
    param([string]$Text)
    $m = [regex]::Match($Text, '(^|[ \t])#')
    if ($m.Success) { return $Text.Substring(0, $m.Index).TrimEnd() }
    return $Text.TrimEnd()
}

function ConvertFrom-AwYamlScalar {
    # Converts an inline value (scalar or flow collection). Throws a message when unsupported.
    param([string]$Text, [int]$Depth = 0)
    $t = $Text.Trim()
    if ($t.Length -eq 0) { return $null }
    if ($Depth -gt $script:AwYamlMaxDepth) { throw 'flow collection nested too deeply' }
    $first = $t[0]

    if ($first -eq [char]'"' -or $first -eq [char]"'") {
        $end = Get-AwYamlQuotedEnd -Text $t
        if ($end -lt 0) { throw 'unterminated quoted string' }
        $after = $t.Substring($end + 1).Trim()
        if ($after.Length -gt 0 -and -not $after.StartsWith('#')) { throw 'unexpected text after a quoted string' }
        $inner = $t.Substring(1, $end - 1)
        if ($first -eq [char]"'") { return $inner.Replace("''", "'") }
        return ConvertFrom-AwYamlDoubleQuoted -Inner $inner
    }

    if ($first -eq [char]'[' -or $first -eq [char]'{') {
        $end = Find-AwYamlFlowEnd -Text $t
        if ($end -lt 0) { throw 'unterminated flow collection' }
        $after = $t.Substring($end + 1).Trim()
        if ($after.Length -gt 0 -and -not $after.StartsWith('#')) { throw 'unexpected text after a flow collection' }
        $parts = Split-AwYamlFlow -Inner $t.Substring(1, $end - 1)
        # A trailing comma leaves one empty last part.
        if ($parts.Count -gt 0 -and $parts[$parts.Count - 1].Trim().Length -eq 0) { $parts.RemoveAt($parts.Count - 1) }
        if ($first -eq [char]'[') {
            $list = New-Object System.Collections.ArrayList
            foreach ($p in $parts) {
                if ($p.Trim().Length -eq 0) { throw 'empty item in a flow list' }
                [void]$list.Add((ConvertFrom-AwYamlScalar -Text $p -Depth ($Depth + 1)))
            }
            return ,$list.ToArray()
        }
        $map = New-AwOrdinalHashtable
        foreach ($p in $parts) {
            $km = $script:AwYamlKeyRegex.Match($p.Trim())
            if (-not $km.Success) { throw 'cannot parse an entry of a flow map' }
            $key = ConvertFrom-AwYamlKey -Text $km.Groups['k'].Value
            $map[$key] = ConvertFrom-AwYamlScalar -Text $km.Groups['v'].Value -Depth ($Depth + 1)
        }
        return ,$map
    }

    if ('&*!%@`|>'.IndexOf($first) -ge 0) { throw "unsupported YAML syntax '$first' (anchors, aliases, tags, directives)" }

    $plain = Remove-AwYamlComment -Text $t
    if ($plain.Length -eq 0) { return $null }
    if ($plain -cmatch '^(true|True|TRUE)$') { return $true }
    if ($plain -cmatch '^(false|False|FALSE)$') { return $false }
    if ($plain -cmatch '^(null|Null|NULL|~)$') { return $null }
    if ($plain -match '^[-+]?[0-9]+$') {
        try { return ConvertFrom-AwJsonNumber -Token $plain.TrimStart('+') } catch { return $plain }
    }
    if ($plain -match '^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$') {
        $d = 0.0
        if ([double]::TryParse($plain, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $d }
    }
    return $plain
}

function ConvertFrom-AwYamlKey {
    param([string]$Text)
    $k = $Text.Trim()
    if ($k.Length -ge 2 -and $k[0] -eq [char]'"') { return ConvertFrom-AwYamlDoubleQuoted -Inner $k.Substring(1, $k.Length - 2) }
    if ($k.Length -ge 2 -and $k[0] -eq [char]"'") { return $k.Substring(1, $k.Length - 2).Replace("''", "'") }
    return $k
}

function Read-AwYamlInlineValue {
    # Parses the value that follows 'key:' or '- ' on the current line (already consumed),
    # pulling continuation lines for multi-line flow collections and plain scalars.
    param($State, [string]$Rest, [int]$Indent, [int]$LineNo)
    $text = $Rest.Trim()
    $first = $text[0]
    $scan = @{}
    if (($first -eq [char]'[' -or $first -eq [char]'{') -and (Find-AwYamlFlowEnd -Text $text -Scan $scan) -lt 0) {
        while ($State.Pos -lt $State.Lines.Count -and (Find-AwYamlFlowEnd -Text $text -Scan $scan) -lt 0) {
            $l = $State.Lines[$State.Pos]
            if (-not $l.Skip) { $text = $text + ' ' + $l.Content }
            $State.Pos++
        }
    } elseif ($first -ne [char]'"' -and $first -ne [char]"'" -and $first -ne [char]'[' -and $first -ne [char]'{') {
        # Plain multi-line scalar: deeper lines continue it. Each line loses its comment once the
        # next one is appended (comment lines never get here: they are skipped).
        $parts = New-Object System.Collections.Generic.List[string]
        $parts.Add($text)
        while ($State.Pos -lt $State.Lines.Count) {
            $l = $State.Lines[$State.Pos]
            if ($l.Skip) { $State.Pos++; continue }
            if ($l.Indent -le $Indent) { break }
            $parts[$parts.Count - 1] = Remove-AwYamlComment -Text $parts[$parts.Count - 1]
            $parts.Add($l.Content)
            $State.Pos++
        }
        $text = $parts.ToArray() -join ' '
    }
    try {
        return ,(ConvertFrom-AwYamlScalar -Text $text)
    } catch {
        Add-AwYamlError $State $LineNo ("$($_.Exception.Message); value kept as text")
        Skip-AwYamlChildren $State $Indent
        return $text
    }
}

function Read-AwYamlBlockScalar {
    # Literal (|) or folded (>) block scalar, with clip / strip (-) / keep (+) chomping.
    param($State, [int]$ParentIndent, [string]$Header)
    $folded = $Header.StartsWith('>')
    $chomp = if ($Header.Contains('-')) { 'strip' } elseif ($Header.Contains('+')) { 'keep' } else { 'clip' }
    $collected = New-Object System.Collections.Generic.List[string]
    $blockIndent = -1
    while ($State.Pos -lt $State.Lines.Count) {
        $l = $State.Lines[$State.Pos]
        if ($l.Empty) { $collected.Add(''); $State.Pos++; continue }
        if ($l.Indent -le $ParentIndent) { break }
        if ($blockIndent -lt 0) { $blockIndent = $l.Indent }
        $cut = [Math]::Min($blockIndent, $l.Indent)
        $collected.Add($l.Raw.Substring($cut))
        $State.Pos++
    }
    $trailing = 0
    for ($k = $collected.Count - 1; $k -ge 0 -and $collected[$k].Length -eq 0; $k--) { $trailing++ }
    $lines = @(); if ($collected.Count - $trailing -gt 0) { $lines = $collected.GetRange(0, $collected.Count - $trailing).ToArray() }
    if ($folded) {
        $sb = New-Object System.Text.StringBuilder
        # Folding: a line break between two text lines becomes a space; each empty line becomes a newline.
        for ($k = 0; $k -lt $lines.Count; $k++) {
            if ($k -gt 0 -and $lines[$k].Length -eq 0) { [void]$sb.Append("`n"); continue }
            if ($k -gt 0 -and $lines[$k - 1].Length -gt 0) { [void]$sb.Append(' ') }
            [void]$sb.Append($lines[$k])
        }
        $body = $sb.ToString()
    } else {
        $body = $lines -join "`n"
    }
    if ($lines.Count -eq 0) { return '' }
    switch ($chomp) {
        'strip' { return $body }
        'keep'  { return $body + ("`n" * ($trailing + 1)) }
        default { return $body + "`n" }
    }
}

function Read-AwYamlNode {
    param($State, [int]$Indent)
    $State.Depth++
    try {
        $line = $State.Lines[$State.Pos]
        if ($State.Depth -gt $script:AwYamlMaxDepth) {
            Add-AwYamlError $State $line.LineNo 'nesting too deep; block skipped'
            Skip-AwYamlChildren $State ($Indent - 1)
            return $null
        }
        if (Test-AwYamlListItem $line.Content) { return ,(Read-AwYamlList $State $Indent) }
        return ,(Read-AwYamlMap $State $Indent)
    } finally {
        $State.Depth--
    }
}

function Read-AwYamlValueAfterKey {
    # Value of 'key:' or '- ' when nothing follows on the same line.
    param($State, [int]$Indent)
    Skip-AwYamlBlank $State
    if ($State.Pos -ge $State.Lines.Count) { return $null }
    $next = $State.Lines[$State.Pos]
    if ($next.Indent -gt $Indent) { return ,(Read-AwYamlNode $State $next.Indent) }
    return $null
}

function Read-AwYamlMap {
    param($State, [int]$Indent)
    $map = New-AwOrdinalHashtable
    while ($true) {
        Skip-AwYamlBlank $State
        if ($State.Pos -ge $State.Lines.Count) { break }
        $line = $State.Lines[$State.Pos]
        if ($line.Indent -lt $Indent) { break }
        if ($line.Indent -gt $Indent -or (Test-AwYamlListItem $line.Content)) {
            Add-AwYamlError $State $line.LineNo 'unexpected indentation or list item; line skipped'
            $State.Pos++
            Skip-AwYamlChildren $State $line.Indent
            continue
        }
        $km = $script:AwYamlKeyRegex.Match($line.Content)
        if (-not $km.Success) {
            Add-AwYamlError $State $line.LineNo 'not a "key: value" line; skipped'
            $State.Pos++
            Skip-AwYamlChildren $State $Indent
            continue
        }
        $key = ConvertFrom-AwYamlKey -Text $km.Groups['k'].Value
        $rest = $km.Groups['v'].Value
        $State.Pos++
        if ($rest.Trim().Length -eq 0 -or $rest.Trim().StartsWith('#')) {
            Skip-AwYamlBlank $State
            $next = $null
            if ($State.Pos -lt $State.Lines.Count) { $next = $State.Lines[$State.Pos] }
            if ($null -ne $next -and $next.Indent -eq $Indent -and (Test-AwYamlListItem $next.Content)) {
                $value = Read-AwYamlList $State $Indent      # "key:" followed by "- item" at the same indent
            } else {
                $value = Read-AwYamlValueAfterKey $State $Indent
            }
        } elseif ($rest.Trim() -match '^[|>][+-]?[1-9]?[+-]?\s*(#.*)?$') {
            $value = Read-AwYamlBlockScalar $State $Indent $rest.Trim()
        } else {
            $value = Read-AwYamlInlineValue $State $rest $Indent $line.LineNo
        }
        $map[$key] = $value
    }
    return ,$map
}

function Read-AwYamlList {
    param($State, [int]$Indent)
    $list = New-Object System.Collections.ArrayList
    while ($true) {
        Skip-AwYamlBlank $State
        if ($State.Pos -ge $State.Lines.Count) { break }
        $line = $State.Lines[$State.Pos]
        if ($line.Indent -ne $Indent -or -not (Test-AwYamlListItem $line.Content)) { break }
        $afterDash = $line.Content.Substring(1)
        $rest = $afterDash.TrimStart()
        $itemIndent = $Indent + 1 + ($afterDash.Length - $rest.Length)
        if ($rest.Length -eq 0 -or $rest.StartsWith('#')) {
            $State.Pos++
            $item = Read-AwYamlValueAfterKey $State $Indent
        } elseif ($script:AwYamlKeyRegex.IsMatch($rest)) {
            # "- key: value" starts a map whose keys are aligned on the first key.
            $State.Lines[$State.Pos] = @{ LineNo = $line.LineNo; Indent = $itemIndent; Content = $rest; Raw = $line.Raw; Skip = $false; Empty = $false }
            $item = Read-AwYamlMap $State $itemIndent
        } elseif (Test-AwYamlListItem $rest) {
            Add-AwYamlError $State $line.LineNo 'nested inline list items are not supported; item skipped'
            $State.Pos++
            Skip-AwYamlChildren $State $Indent
            continue
        } else {
            $State.Pos++
            $item = Read-AwYamlInlineValue $State $rest $Indent $line.LineNo
        }
        [void]$list.Add($item)
    }
    return ,$list.ToArray()
}

function Read-AwFrontmatter {
    <#
    .SYNOPSIS
    Splits a Markdown file into its YAML frontmatter (hashtable) and its body.
    .DESCRIPTION
    Returns @{ Frontmatter = <hashtable>; Body = <string> }. Without a leading '---'
    block, Frontmatter is empty and Body is the whole text. Unsupported YAML is ignored
    and described in Frontmatter['__errors'] (string[]). Never throws.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowEmptyString()] [AllowNull()] [string]$Text)
    if ($null -eq $Text) { $Text = '' }
    $fm = New-AwOrdinalHashtable
    $errors = New-Object System.Collections.Generic.List[string]
    $result = @{ Frontmatter = $fm; Body = $Text }

    $t = $Text
    if ($t.Length -gt 0 -and $t[0] -eq $script:AwBom) { $t = $t.Substring(1) }
    $open = [regex]::Match($t, '\A---[ \t]*\r?\n')
    if (-not $open.Success) {
        if ($t -match '\A---[ \t]*\z') { $errors.Add('frontmatter is not closed by a --- line') ; $fm['__errors'] = $errors.ToArray() }
        return $result
    }
    $close = [regex]::new('(?m)^(?:---|\.\.\.)[ \t]*\r?$').Match($t, $open.Length)
    if (-not $close.Success) {
        $errors.Add('frontmatter is not closed by a --- line; treated as body')
        $fm['__errors'] = $errors.ToArray()
        return $result
    }
    $yaml = $t.Substring($open.Length, $close.Index - $open.Length)
    $bodyStart = $close.Index + $close.Length
    if ($bodyStart -lt $t.Length -and $t[$bodyStart] -eq [char]"`n") { $bodyStart++ }
    $result.Body = $t.Substring($bodyStart)

    try {
        $records = New-Object System.Collections.ArrayList
        if ($yaml.Length -gt $script:AwYamlMaxChars) {
            $errors.Add("frontmatter larger than $($script:AwYamlMaxChars) characters; the rest was ignored")
            $cut = $yaml.LastIndexOf("`n", $script:AwYamlMaxChars - 1)
            $yaml = if ($cut -gt 0) { $yaml.Substring(0, $cut) } else { '' }
        }
        $rawLines = $yaml -split "`n"
        if ($yaml.Length -eq 0) { $rawLines = @() }
        if ($rawLines.Count -gt $script:AwYamlMaxLines) {
            $errors.Add("frontmatter longer than $($script:AwYamlMaxLines) lines; the rest was ignored")
            $rawLines = $rawLines[0..($script:AwYamlMaxLines - 1)]
        }
        for ($k = 0; $k -lt $rawLines.Count; $k++) {
            $raw = $rawLines[$k].TrimEnd("`r")
            $lineNo = $k + 2
            $lead = [regex]::Match($raw, '^[ \t]*').Value
            if ($lead.Contains("`t") -and $raw.Trim().Length -gt 0) { $errors.Add("line ${lineNo}: tab used for indentation (counted as one space)") }
            $content = $raw.Substring($lead.Length).TrimEnd()
            $empty = $content.Length -eq 0
            [void]$records.Add(@{
                LineNo = $lineNo; Indent = $lead.Length; Content = $content; Raw = $raw
                Empty = $empty; Skip = ($empty -or $content.StartsWith('#'))
            })
        }
        $state = @{ Lines = $records; Pos = 0; Errors = $errors; Depth = 0 }
        Skip-AwYamlBlank $state
        if ($state.Pos -lt $records.Count) {
            $first = $records[$state.Pos]
            if (Test-AwYamlListItem $first.Content) {
                $errors.Add("line $($first.LineNo): the frontmatter is a list, not a map; ignored")
            } else {
                $parsed = Read-AwYamlMap $state $first.Indent
                foreach ($key in $parsed.Keys) { $fm[$key] = $parsed[$key] }
                Skip-AwYamlBlank $state
                if ($state.Pos -lt $records.Count) {
                    $errors.Add("line $($records[$state.Pos].LineNo): content after the top-level map was ignored")
                }
            }
        }
    } catch {
        $errors.Add("frontmatter parser error: $($_.Exception.Message)")
    }
    if ($errors.Count -gt 0) { $fm['__errors'] = $errors.ToArray() }
    return $result
}
