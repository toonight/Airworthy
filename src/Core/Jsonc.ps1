# JSONC parser: a regex-driven tokenizer feeding an iterative (non-recursive) parser.
# Objects become case-sensitive hashtables (JSON keys are case-sensitive), arrays become object[].

$script:AwJsoncMaxDepth = 64

# One token per match, preceded by its trivia (whitespace and comments, atomic: no backtracking).
# \G keeps matches contiguous; group 'e' catches anything invalid.
#   t = trivia, s = string, n = number, p = punctuation, w = word, e = error
$script:AwJsoncTokenRegex = New-Object System.Text.RegularExpressions.Regex -ArgumentList @(
    ('\G(?<t>(?>(?:[ \t\r\n]+|//[^\r\n]*|/\*[\s\S]*?\*/)*))' +
     '(?:(?<s>"(?:[^"\\\x00-\x08\x0A-\x1F]|\\[^\r\n])*")' +
     '|(?<n>-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)' +
     '|(?<p>[{}\[\]:,])' +
     '|(?<w>[A-Za-z_$][A-Za-z0-9_$]*)' +
     '|(?<e>/\*|"|[\s\S]))'),
    [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
)
$script:AwJsoncGroupT = $script:AwJsoncTokenRegex.GroupNumberFromName('t')
$script:AwJsoncGroupE = $script:AwJsoncTokenRegex.GroupNumberFromName('e')

# The valid prefix of a string body: plain characters, simple escapes and \u with 4 hex digits
# (atomic: no backtracking). It stops at the backslash of the first invalid escape.
$script:AwJsoncEscapeRegex = New-Object System.Text.RegularExpressions.Regex -ArgumentList @(
    '\G(?>(?:[^\\]+|\\["\\/bfnrt]|\\u[0-9A-Fa-f]{4})*)',
    [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
)

function New-AwOrdinalHashtable {
    # Case-sensitive hashtable, used for every parsed JSON object and YAML map.
    New-Object System.Collections.Hashtable -ArgumentList @([System.StringComparer]::Ordinal)
}

function New-AwJsoncError {
    # Builds a FormatException whose Data holds the 1-based Line and Column.
    param([string]$Text, [int]$Index, [string]$Message)
    if ($Index -gt $Text.Length) { $Index = $Text.Length }
    $line = 1; $lineStart = 0
    for ($p = $Text.IndexOf([char]"`n"); $p -ge 0 -and $p -lt $Index; $p = $Text.IndexOf([char]"`n", $p + 1)) {
        $line++; $lineStart = $p + 1
    }
    $column = $Index - $lineStart + 1
    $ex = New-Object System.FormatException -ArgumentList "Invalid JSON at line $line, column ${column}: $Message"
    $ex.Data['Line'] = $line
    $ex.Data['Column'] = $column
    return $ex
}

function Format-AwJsoncSnippet {
    # Short, secret-safe rendering of an offending token for error messages.
    param([string]$Value)
    if ($Value.Length -eq 1 -and [int][char]$Value -lt 32) { return ('U+{0:X4}' -f [int][char]$Value) }
    if ($Value.Length -ge 12) { return "'" + (Hide-AwSecret -Value $Value) + "'" }
    return "'$Value'"
}

function ConvertFrom-AwJsonString {
    # Unescapes a JSON string token (quotes included). Throws a message on a bad escape.
    # The body is checked in one pass, then escaped backslashes become NUL (the tokenizer lets no
    # raw NUL into a string, and the check rejects a backslash followed by NUL), so the other
    # escapes are replaced in bulk; only \u escapes are decoded one by one. PowerShell 7.3+ logs
    # every .NET method call made from script with the full text of its string arguments, so the
    # loop passes only the gaps between escapes, never the whole body.
    param([string]$Token)
    $inner = $Token.Substring(1, $Token.Length - 2)
    if ($inner.IndexOf([char]'\') -lt 0) { return $inner }
    $valid = $script:AwJsoncEscapeRegex.Match($inner).Length
    if ($valid -lt $inner.Length) {
        $esc = [string]$inner[$valid + 1]
        if ($esc -ceq 'u') { throw 'Invalid \u escape (expected 4 hexadecimal digits)' }
        throw ("Invalid escape sequence '\" + $esc + "'")
    }
    $t = $inner.Replace('\\', "`0").Replace('\"', '"').Replace('\/', '/').Replace('\b', "`b").Replace('\f', "`f").Replace('\n', "`n").Replace('\r', "`r").Replace('\t', "`t")
    $i = $t.IndexOf([char]'\')
    if ($i -lt 0) { return $t.Replace("`0", '\') }
    $sb = New-Object System.Text.StringBuilder -ArgumentList $t.Length
    $from = 0
    while ($i -ge 0) {
        if ($i -gt $from) { [void]$sb.Append($t.Substring($from, $i - $from).Replace("`0", '\')) }
        [void]$sb.Append([char][Convert]::ToInt32($t.Substring($i + 2, 4), 16))
        $from = $i + 6
        $i = $t.IndexOf([char]'\', $from)
    }
    if ($from -lt $t.Length) { [void]$sb.Append($t.Substring($from).Replace("`0", '\')) }
    return $sb.ToString()
}

function ConvertFrom-AwJsonNumber {
    param([string]$Token)
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    if ($Token.IndexOfAny([char[]]'.eE') -lt 0) {
        $i32 = 0
        if ([int]::TryParse($Token, [System.Globalization.NumberStyles]::AllowLeadingSign, $inv, [ref]$i32)) { return $i32 }
        $i64 = [long]0
        if ([long]::TryParse($Token, [System.Globalization.NumberStyles]::AllowLeadingSign, $inv, [ref]$i64)) { return $i64 }
    }
    $d = 0.0
    if ([double]::TryParse($Token, [System.Globalization.NumberStyles]::Float, $inv, [ref]$d) -and
        -not [double]::IsInfinity($d)) { return $d }
    throw 'Number out of range'
}

function ConvertFrom-AwJsonc {
    <#
    .SYNOPSIS
    Parses JSON with comments (JSONC) into nested hashtables and arrays.
    .DESCRIPTION
    Supports // and /* */ comments outside strings and trailing commas. Duplicate keys:
    the last one wins. Keys are case-sensitive. Maximum nesting depth: 64. Throws a
    System.FormatException (Data['Line'], Data['Column']) on invalid input.
    With -AllowEmpty, a document with no value (only whitespace or comments) returns $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [AllowNull()] [string]$Text,
        [switch]$AllowEmpty
    )
    if ($null -eq $Text) { $Text = '' }
    $start = 0
    if ($Text.Length -gt 0 -and $Text[0] -eq $script:AwBom) { $start = 1 }

    # States: 0 value, 1 value or ']', 2 key or '}', 3 ':', 4 ',' or close, 5 end of document.
    $expect = 0
    $stack = New-Object System.Collections.ArrayList
    $root = $null
    $hasRoot = $false

    $ordinal = [System.StringComparer]::Ordinal
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $numberMarks = [char[]]'.eE'
    $ge = $script:AwJsoncGroupE
    $gt = $script:AwJsoncGroupT
    # A match fails only at the end of the input (trailing trivia), which ends the loop.
    $m = $script:AwJsoncTokenRegex.Match($Text, $start)
    while ($m.Success) {
        $g = $m.Groups
        if ($g[$ge].Success) {
            $bad = $g[$ge].Value; $at = $g[$ge].Index
            if ($bad -eq '/*') { throw (New-AwJsoncError $Text $at 'Unterminated block comment') }
            if ($bad -eq '"')  { throw (New-AwJsoncError $Text $at 'Unterminated string, or unescaped control character in a string') }
            throw (New-AwJsoncError $Text $at ('Unexpected character ' + (Format-AwJsoncSnippet $bad)))
        }
        $at = $m.Index + $g[$gt].Length
        $c = $Text[$at]
        if ('{}[]:,'.IndexOf($c) -ge 0) {
            $kind = [string]$c; $tok = $kind
        } else {
            $tok = $Text.Substring($at, $m.Index + $m.Length - $at)
            if ($c -eq [char]'"') { $kind = 's' }
            elseif ($c -eq [char]'-' -or ($c -ge [char]'0' -and $c -le [char]'9')) { $kind = 'n' }
            else { $kind = 'w' }
        }

        $hasValue = $false
        $value = $null

        if ($expect -eq 2) {
            if ($kind -eq 's') {
                if ($tok.IndexOf([char]'\') -lt 0) { $stack[$stack.Count - 1].Key = $tok.Substring(1, $tok.Length - 2) }
                else {
                    try { $stack[$stack.Count - 1].Key = ConvertFrom-AwJsonString $tok }
                    catch { throw (New-AwJsoncError $Text $at $_.Exception.Message) }
                }
                $expect = 3
            } elseif ($kind -eq '}') {
                $frame = $stack[$stack.Count - 1]; $stack.RemoveAt($stack.Count - 1)
                $value = $frame.Map; $hasValue = $true
            } else {
                throw (New-AwJsoncError $Text $at ("Expected a property name in double quotes or '}', found " + (Format-AwJsoncSnippet $tok)))
            }
        }
        elseif ($expect -eq 3) {
            if ($kind -ne ':') { throw (New-AwJsoncError $Text $at ("Expected ':', found " + (Format-AwJsoncSnippet $tok))) }
            $expect = 0
        }
        elseif ($expect -eq 4) {
            $frame = $stack[$stack.Count - 1]
            if ($kind -eq ',') {
                if ($frame.IsObject) { $expect = 2 } else { $expect = 1 }
            } elseif (($kind -eq '}' -and $frame.IsObject) -or ($kind -eq ']' -and -not $frame.IsObject)) {
                $stack.RemoveAt($stack.Count - 1)
                if ($frame.IsObject) { $value = $frame.Map } else { $value = $frame.List.ToArray() }
                $hasValue = $true
            } else {
                $close = if ($frame.IsObject) { "'}'" } else { "']'" }
                throw (New-AwJsoncError $Text $at ("Expected ',' or $close, found " + (Format-AwJsoncSnippet $tok)))
            }
        }
        elseif ($expect -eq 5) {
            throw (New-AwJsoncError $Text $at ('Unexpected content after the end of the JSON value: ' + (Format-AwJsoncSnippet $tok)))
        }
        else {
            # Expecting a value (state 0) or a value or ']' (state 1).
            if ($kind -eq ']' -and $expect -eq 1) {
                $frame = $stack[$stack.Count - 1]; $stack.RemoveAt($stack.Count - 1)
                $value = $frame.List.ToArray(); $hasValue = $true
            } elseif ($kind -eq '{' -or $kind -eq '[') {
                if ($stack.Count -ge $script:AwJsoncMaxDepth) {
                    throw (New-AwJsoncError $Text $at "Maximum nesting depth of $($script:AwJsoncMaxDepth) exceeded")
                }
                if ($kind -eq '{') {
                    [void]$stack.Add(@{ IsObject = $true; Map = [System.Collections.Hashtable]::new($ordinal); Key = $null })
                    $expect = 2
                } else {
                    [void]$stack.Add(@{ IsObject = $false; List = [System.Collections.ArrayList]::new() })
                    $expect = 1
                }
            } elseif ($kind -eq 's') {
                if ($tok.IndexOf([char]'\') -lt 0) { $value = $tok.Substring(1, $tok.Length - 2) }
                else {
                    try { $value = ConvertFrom-AwJsonString $tok } catch { throw (New-AwJsoncError $Text $at $_.Exception.Message) }
                }
                $hasValue = $true
            } elseif ($kind -eq 'n') {
                # Fast path for plain integers; the function handles long, double and range errors.
                if ($tok.Length -lt 10 -and $tok.IndexOfAny($numberMarks) -lt 0) { $value = [int]::Parse($tok, $inv) }
                else {
                    try { $value = ConvertFrom-AwJsonNumber $tok } catch { throw (New-AwJsoncError $Text $at $_.Exception.Message) }
                }
                $hasValue = $true
            } elseif ($kind -eq 'w') {
                if ($tok -ceq 'true') { $value = $true }
                elseif ($tok -ceq 'false') { $value = $false }
                elseif ($tok -ceq 'null') { $value = $null }
                else { throw (New-AwJsoncError $Text $at ('Unexpected identifier ' + (Format-AwJsoncSnippet $tok))) }
                $hasValue = $true
            } else {
                throw (New-AwJsoncError $Text $at ('Expected a value, found ' + (Format-AwJsoncSnippet $tok)))
            }
        }

        if ($hasValue) {
            if ($stack.Count -eq 0) {
                $root = $value; $hasRoot = $true; $expect = 5
            } else {
                $top = $stack[$stack.Count - 1]
                if ($top.IsObject) { $top.Map[$top.Key] = $value } else { [void]$top.List.Add($value) }
                $expect = 4
            }
        }
        $m = $m.NextMatch()
    }

    if (-not $hasRoot) {
        if ($stack.Count -eq 0 -and $AllowEmpty) { return $null }
        if ($stack.Count -eq 0) { throw (New-AwJsoncError $Text $Text.Length 'The document contains no JSON value') }
        throw (New-AwJsoncError $Text $Text.Length "Unexpected end of input: $($stack.Count) unclosed '{' or '['")
    }
    return ,$root
}
