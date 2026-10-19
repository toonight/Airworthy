# TOML 1.0 parser (https://toml.io/en/v1.0.0), used for Codex CLI configuration files.
#
# A linear scanner reads the text once, left to right. Its only regexes are runs of character
# classes, anchored with \G or matched against one bounded token, with every repetition inside an
# atomic group, so no input can make them backtrack (no ReDoS). Arrays and inline tables are
# parsed with an explicit stack, so deep nesting cannot overflow the call stack.
#
# Tables become case-sensitive hashtables; arrays and arrays of tables become object[].
# Integers are [long], floats [double], booleans [bool]. Offset date-times, local date-times,
# local dates and local times are returned as [string], with their original text.
# Newlines inside multi-line strings are returned as LF.
#
# Bounds for hostile input: 2 MB of text, 64 nested tables and arrays below the root table, and a
# budget of parse steps. A step is a key part, a value, an array element, a header, a Unicode
# escape or a helper call; a PowerShell function call is far slower than the scanning itself, so
# the budget bounds the parse time whatever the document holds.

$script:AwTomlMaxDepth  = 64
$script:AwTomlMaxLength = 2097152
$script:AwTomlMaxSteps  = 20000

# Control characters are \x00-\x08, \x0A-\x1F and \x7F on one line; multi-line strings also
# allow LF (\x0A) and CR (\x0D), and every string and comment allows tab (\x09).
$script:AwTomlRxWs         = [regex]'\G[ \t]*'
$script:AwTomlRxTrivia     = [regex]'\G(?>(?:[ \t]|\r?\n|#[^\x00-\x08\x0A-\x1F\x7F]*)*)'
$script:AwTomlRxLineEnd    = [regex]'\G(?>[ \t]*)(?>(?:#[^\x00-\x08\x0A-\x1F\x7F]*)?)'
$script:AwTomlRxBareKey    = [regex]'\G[A-Za-z0-9_-]+'
$script:AwTomlRxToken      = [regex]'\G[0-9A-Za-z_+.:-]+'
$script:AwTomlRxBasic      = [regex]'\G(?>(?:[^"\\\x00-\x08\x0A-\x1F\x7F]+|\\[^\x00-\x08\x0A-\x1F\x7F])*)'
$script:AwTomlRxMlBasic    = [regex]'\G(?>(?:[^"\\\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+|\\[^\x00-\x08\x0B\x0C\x0E-\x1F\x7F]|"(?!""))*)'
$script:AwTomlRxLiteral    = [regex]'\G[^''\x00-\x08\x0A-\x1F\x7F]*'
$script:AwTomlRxMlLiteral  = [regex]'\G(?>(?:[^''\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+|''(?!''''))*)'
$script:AwTomlRxBareCr     = [regex]'\r(?!\n)'
# Escape checks run on a raw string body and stop at the first invalid escape.
$script:AwTomlRxEscapes    = [regex]'\G(?>(?:[^\\]+|\\[\\btnfr"]|\\u[0-9A-Fa-f]{4}|\\U[0-9A-Fa-f]{8})*)'
$script:AwTomlRxMlEscapes  = [regex]'\G(?>(?:[^\\]+|\\[\\btnfr"]|\\u[0-9A-Fa-f]{4}|\\U[0-9A-Fa-f]{8}|\\(?>[ \t]*)\r?\n)*)'
$script:AwTomlRxLineEndBackslash = [regex]'\\(?>[ \t]*)\n(?>[ \t\n]*)'
# Value tokens, matched as a whole.
$script:AwTomlRxSmallInt   = [regex]'^[+-]?(?:0|[1-9][0-9]{0,17})\z'
$script:AwTomlRxDec        = [regex]'^[+-]?(?:0|[1-9](?>(?:_?[0-9])*))\z'
$script:AwTomlRxHex        = [regex]'^0x[0-9A-Fa-f](?>(?:_?[0-9A-Fa-f])*)\z'
$script:AwTomlRxOct        = [regex]'^0o[0-7](?>(?:_?[0-7])*)\z'
$script:AwTomlRxBin        = [regex]'^0b[01](?>(?:_?[01])*)\z'
$script:AwTomlRxFloat      = [regex]'^[+-]?(?:0|[1-9](?>(?:_?[0-9])*))(?:\.[0-9](?>(?:_?[0-9])*))?(?:[eE][+-]?[0-9](?>(?:_?[0-9])*))?\z'
$script:AwTomlRxDateStart  = [regex]'^[0-9]{4}-'
$script:AwTomlRxDateTime   = [regex]'^([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt ]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.(?>[0-9]+))?(?:[Zz]|[+-]([0-9]{2}):([0-9]{2}))?\z'
$script:AwTomlRxDate       = [regex]'^([0-9]{4})-([0-9]{2})-([0-9]{2})\z'
$script:AwTomlRxTime       = [regex]'^([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.(?>[0-9]+))?\z'

# PowerShell 7.3+ logs every .NET method call made from script with the full text of its string
# arguments, so a regex call on the whole 2 MB document costs about 2 ms there. The scanner
# therefore runs its regexes on a window: a copy of AwTomlWindow characters of the document, cut
# again when the position leaves it. A match that ends within AwTomlWindowMargin characters of
# the window end might go on past it, so Find-AwTomlMatch matches it again on larger windows. A
# match that ends before the margin is the match on the whole document, because each windowed
# regex reads at most this many characters past the end of its match:
#   0  Ws, BareKey, Token, Literal, LineEnd
#   1  Trivia, Basic
#   2  MlBasic, MlLiteral
# The margin must stay above the largest of these: a new windowed regex goes in this table first.
$script:AwTomlWindow       = 1024
$script:AwTomlWindowMargin = 16

function New-AwTomlError {
    # FormatException whose Data holds the 1-based Line and Column of Index.
    param([string]$Text, [int]$Index, [string]$Message)
    if ($Index -lt 0) { $Index = 0 }
    if ($Index -gt $Text.Length) { $Index = $Text.Length }
    $before = $Text.Substring(0, $Index)
    $line = 1 + $before.Length - $before.Replace("`n", '').Length
    $column = $Index - $before.LastIndexOf([char]"`n")
    $ex = New-Object System.FormatException -ArgumentList "Invalid TOML at line $line, column ${column}: $Message"
    $ex.Data['Line'] = $line
    $ex.Data['Column'] = $column
    return $ex
}

function New-AwTomlBudgetError {
    param($s, [int]$Index)
    return (New-AwTomlError $s.T $Index "The document is too complex: more than $($script:AwTomlMaxSteps) parse steps (keys, values, strings and escapes)")
}

function Move-AwTomlWindow {
    # Cuts a window at From; returns it, its start and its limit, and keeps them in $s.
    param($s, [int]$From)
    $n = $s.T.Length
    $size = $script:AwTomlWindow
    $limit = $From + $size - $script:AwTomlWindowMargin
    if ($size -ge $n - $From) { $size = $n - $From; $limit = $n }
    $W = $s.T.Substring($From, $size)
    $s.W = $W; $s.Wb = $From; $s.Wl = $limit
    return @($W, $From, $limit)
}

function Find-AwTomlMatch {
    # The match of Rx at At, when a windowed match ended inside the margin: retried on a window cut
    # at At, then on windows sixteen times larger, until it ends before the margin of one (or the
    # window reaches the end). Returns the match, then the new window, its start and its limit.
    # With the default window, a 2 MB token is also matched on 1K, 16K and 256K characters before
    # the rest of the document: about 1.15 times the work of one match on the whole document.
    # The window is cut here as Move-AwTomlWindow cuts it, since on Windows PowerShell 5.1 a
    # function call costs more than the cut.
    param($s, $Rx, [int]$At)
    $T = $s.T; $n = $T.Length
    $size = $script:AwTomlWindow
    $limit = $At + $size - $script:AwTomlWindowMargin
    if ($size -ge $n - $At) { $size = $n - $At; $limit = $n }
    $W = $T.Substring($At, $size)
    $m = $Rx.Match($W, 0)
    if ($At + $m.Length -le $limit) {
        $s.W = $W; $s.Wb = $At; $s.Wl = $limit
        return @($m, $W, $At, $limit)
    }
    do {
        $size *= 16
        $limit = $At + $size - $script:AwTomlWindowMargin
        if ($size -ge $n - $At) { $size = $n - $At; $limit = $n }
        $G = $T.Substring($At, $size)
        $m = $Rx.Match($G, 0)
    } while ($At + $m.Length -gt $limit)
    # A match that fits the first larger window keeps it: a fast path that gives up hands the same
    # token to the next reader, which then matches it again without a new cut.
    if ($size -le 16 * $script:AwTomlWindow) {
        $s.W = $G; $s.Wb = $At; $s.Wl = $limit
        return @($m, $G, $At, $limit)
    }
    # The next match starts where this long one ends (or at At again after a failed fast path).
    $from = $At + $m.Length
    $size = $script:AwTomlWindow
    $limit = $from + $size - $script:AwTomlWindowMargin
    if ($size -ge $n - $from) { $size = $n - $from; $limit = $n }
    $W = $T.Substring($from, $size)
    $s.W = $W; $s.Wb = $from; $s.Wl = $limit
    return @($m, $W, $from, $limit)
}

function Format-AwTomlFound {
    # Describes what the parser found at Index, for error messages; long words are masked.
    param($s, [int]$Index)
    if ($Index -ge $s.End) { return 'the end of the document' }
    $T = $s.T
    $c = $T[$Index]
    $code = [int]$c
    if ($c -eq "`n") { return 'the end of the line' }
    if ($c -eq "`r") {
        if ($T[$Index + 1] -eq "`n") { return 'the end of the line' }
        return 'a carriage return without a line feed'
    }
    if ($code -lt 32 -or $code -eq 127) { return ('the control character U+{0:X4}' -f $code) }
    if ($c -eq '#') { return 'a comment' }
    $m = $script:AwTomlRxToken.Match($T, $Index)
    if ($m.Length -gt 1) { return (Format-AwJsoncSnippet $m.Value) }
    return "'$c'"
}

function Format-AwTomlKey {
    # Dotted key for messages: bare parts as they are, other parts quoted, at most 80 characters.
    param($Parts, [int]$Count = -1)
    if ($Count -lt 0 -or $Count -gt $Parts.Count) { $Count = $Parts.Count }
    $out = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $Count; $i++) {
        $k = [string]$Parts[$i]
        if ($k.Length -gt 80) { $k = $k.Substring(0, 80) }
        if ($k.Length -gt 0 -and $script:AwTomlRxBareKey.Match($k).Length -eq $k.Length) { $out.Add($k) }
        else { $out.Add('"' + $k + '"') }
    }
    $text = $out -join '.'
    if ($text.Length -gt 80) { $text = $text.Substring(0, 79) + $script:AwEllipsis }
    return $text
}

function Get-AwTomlEscapeError {
    # Message for the invalid escape that starts at Index in a raw string body.
    param([string]$Raw, [int]$Index)
    if ($Index + 1 -ge $Raw.Length) { return 'Invalid escape sequence at the end of the string' }
    $n = $Raw[$Index + 1]
    if ($n -ceq 'u') { return 'Invalid Unicode escape: \u must be followed by 4 hexadecimal digits' }
    if ($n -ceq 'U') { return 'Invalid Unicode escape: \U must be followed by 8 hexadecimal digits' }
    $code = [int]$n
    if ($code -le 32 -or $code -eq 127) { return ('Invalid escape sequence: a backslash followed by U+{0:X4}' -f $code) }
    return "Invalid escape sequence '\$n'"
}

function ConvertFrom-AwTomlEscapes {
    # Decodes a basic string body whose escapes were already checked. Escaped backslashes become
    # NUL first (a raw NUL cannot occur in a basic string), so the other escapes are replaced in
    # bulk; only \u and \U escapes are decoded one by one.
    param($s, [string]$Text, [bool]$Multiline, [int]$At)
    $maxSteps = $script:AwTomlMaxSteps
    $s.Steps++
    if ($s.Steps -gt $maxSteps) { throw (New-AwTomlBudgetError $s $At) }
    $t = $Text.Replace('\\', "`0")
    if ($Multiline -and $t.IndexOf([char]"`n") -ge 0) { $t = $script:AwTomlRxLineEndBackslash.Replace($t, '') }
    $t = $t.Replace('\"', '"').Replace('\b', "`b").Replace('\t', "`t").Replace('\n', "`n").Replace('\f', "`f").Replace('\r', "`r")
    $i = $t.IndexOf([char]'\')
    if ($i -lt 0) { return $t.Replace("`0", '\') }
    $sb = [System.Text.StringBuilder]::new($t.Length)
    $from = 0
    while ($i -ge 0) {
        if ($i -gt $from) { [void]$sb.Append($t.Substring($from, $i - $from).Replace("`0", '\')) }
        $kind = $t[$i + 1]
        $n = 4
        if ($kind -ceq 'U') { $n = 8 }
        $hex = $t.Substring($i + 2, $n)
        $cp = [System.Convert]::ToInt32($hex, 16)
        if ($cp -lt 0 -or $cp -gt 0x10FFFF -or ($cp -ge 0xD800 -and $cp -le 0xDFFF)) {
            throw (New-AwTomlError $s.T $At ('Invalid Unicode escape \' + $kind + $hex + ': not a Unicode scalar value'))
        }
        [void]$sb.Append([char]::ConvertFromUtf32($cp))
        $s.Steps++
        if ($s.Steps -gt $maxSteps) { throw (New-AwTomlBudgetError $s $At) }
        $from = $i + 2 + $n
        $i = $t.IndexOf([char]'\', $from)
    }
    if ($from -lt $t.Length) { [void]$sb.Append($t.Substring($from).Replace("`0", '\')) }
    return $sb.ToString()
}

function Read-AwTomlString {
    # Reads the string that starts at $s.P (any of the four kinds) and moves $s.P past it.
    param($s, [bool]$AllowMultiline)
    $T = $s.T
    $p = $s.P
    $W = $s.W; $wb = $s.Wb; $wl = $s.Wl
    $s.Steps++
    if ($s.Steps -gt $script:AwTomlMaxSteps) { throw (New-AwTomlBudgetError $s $p) }
    $q = $T[$p]
    if ($T[$p + 1] -eq $q -and $T[$p + 2] -eq $q) {
        if (-not $AllowMultiline) { throw (New-AwTomlError $T $p 'A multi-line string cannot be used as a key') }
        return (Read-AwTomlMultilineString $s)
    }
    $basic = ($q -eq '"')
    $start = $p + 1
    if ($basic) { $rx = $script:AwTomlRxBasic } else { $rx = $script:AwTomlRxLiteral }
    if ($basic -and $s.BasicAt -eq $start) { $m = $s.BasicMatch }
    else {
        if ($start -lt $wb -or $start -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $start }
        $m = $rx.Match($W, $start - $wb)
        if ($start + $m.Length -gt $wl) { $m, $W, $wb, $wl = Find-AwTomlMatch $s $rx $start }
    }
    $end = $start + $m.Length
    if ($T[$end] -ne $q) {
        $c = $T[$end]
        if ($c -eq '\') { $end++; $c = $T[$end] }
        if ($c -eq "`n" -or $c -eq "`r" -or $end -ge $s.End) {
            throw (New-AwTomlError $T $p 'Unterminated string (a single-line string must end on the line where it starts)')
        }
        throw (New-AwTomlError $T $end ('Invalid character in a string: ' + (Format-AwTomlFound $s $end) + ' (control characters must be escaped)'))
    }
    $s.P = $end + 1
    $raw = $m.Value
    if (-not $basic -or $raw.IndexOf([char]'\') -lt 0) { return $raw }
    $v = $script:AwTomlRxEscapes.Match($raw)
    if ($v.Length -lt $raw.Length) { throw (New-AwTomlError $T ($start + $v.Length) (Get-AwTomlEscapeError $raw $v.Length)) }
    return (ConvertFrom-AwTomlEscapes $s $raw $false $p)
}

function Read-AwTomlMultilineString {
    # Reads a """basic""" or '''literal''' multi-line string at $s.P and moves $s.P past it.
    param($s)
    $T = $s.T
    $p = $s.P
    $W = $s.W; $wb = $s.Wb; $wl = $s.Wl
    $s.Steps++
    if ($s.Steps -gt $script:AwTomlMaxSteps) { throw (New-AwTomlBudgetError $s $p) }
    $q = $T[$p]
    $basic = ($q -eq '"')
    $start = $p + 3
    if ($basic) { $rx = $script:AwTomlRxMlBasic } else { $rx = $script:AwTomlRxMlLiteral }
    if ($start -lt $wb -or $start -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $start }
    $m = $rx.Match($W, $start - $wb)
    if ($start + $m.Length -gt $wl) { $m, $W, $wb, $wl = Find-AwTomlMatch $s $rx $start }
    $end = $start + $m.Length
    if (-not ($T[$end] -eq $q -and $T[$end + 1] -eq $q -and $T[$end + 2] -eq $q)) {
        if ($end -ge $s.End) { throw (New-AwTomlError $T $p 'Unterminated multi-line string') }
        if ($T[$end] -eq '\') { $end++ }
        throw (New-AwTomlError $T $end ('Invalid character in a multi-line string: ' + (Format-AwTomlFound $s $end) + ' (control characters must be escaped)'))
    }
    # One or two quotes right before the closing delimiter belong to the string.
    $extra = 0
    if ($T[$end + 3] -eq $q) { $extra = 1; if ($T[$end + 4] -eq $q) { $extra = 2 } }
    $raw = $T.Substring($start, $end - $start + $extra)
    $s.P = $end + 3 + $extra
    if ($raw.IndexOf([char]"`r") -ge 0) {
        $cr = $script:AwTomlRxBareCr.Match($raw)
        if ($cr.Success) { throw (New-AwTomlError $T ($start + $cr.Index) 'Carriage return without a line feed in a multi-line string') }
    }
    $escaped = $false
    if ($basic -and $raw.IndexOf([char]'\') -ge 0) {
        $v = $script:AwTomlRxMlEscapes.Match($raw)
        if ($v.Length -lt $raw.Length) { throw (New-AwTomlError $T ($start + $v.Length) (Get-AwTomlEscapeError $raw $v.Length)) }
        $escaped = $true
    }
    # A newline right after the opening delimiter is trimmed; CRLF becomes LF.
    if ($raw.Length -gt 0 -and $raw[0] -eq "`n") { $raw = $raw.Substring(1) }
    elseif ($raw.Length -gt 1 -and $raw[0] -eq "`r" -and $raw[1] -eq "`n") { $raw = $raw.Substring(2) }
    if ($raw.IndexOf([char]"`r") -ge 0) { $raw = $raw.Replace("`r`n", "`n") }
    if (-not $escaped) { return $raw }
    return (ConvertFrom-AwTomlEscapes $s $raw $true $p)
}

function ConvertFrom-AwTomlToken {
    # Converts a bare value token (boolean, number, date or time) that starts at At.
    param($s, [string]$Tok, [int]$At)
    $s.Steps++
    if ($s.Steps -gt $script:AwTomlMaxSteps) { throw (New-AwTomlBudgetError $s $At) }
    if ($Tok -ceq 'true') { return $true }
    if ($Tok -ceq 'false') { return $false }
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $outOfRange = 'Integer out of range (TOML integers are signed 64-bit): '

    # Dates and times are checked, then kept as text.
    if ($Tok.IndexOf([char]':') -ge 0 -or $script:AwTomlRxDateStart.IsMatch($Tok)) {
        $date = 0; $time = 0; $offset = 0
        $m = $script:AwTomlRxDateTime.Match($Tok)
        if ($m.Success) { $date = 1; $time = 4; $offset = 7 }
        else {
            $m = $script:AwTomlRxDate.Match($Tok)
            if ($m.Success) { $date = 1 }
            else {
                $m = $script:AwTomlRxTime.Match($Tok)
                if ($m.Success) { $time = 1 }
            }
        }
        $ok = $m.Success
        $g = $m.Groups
        if ($ok -and $date -gt 0) {
            $year = [int]$g[$date].Value; $month = [int]$g[$date + 1].Value; $day = [int]$g[$date + 2].Value
            $days = 31
            if ($month -eq 2) {
                $days = 28
                if (($year % 4 -eq 0 -and $year % 100 -ne 0) -or $year % 400 -eq 0) { $days = 29 }
            } elseif ($month -eq 4 -or $month -eq 6 -or $month -eq 9 -or $month -eq 11) {
                $days = 30
            }
            $ok = $month -ge 1 -and $month -le 12 -and $day -ge 1 -and $day -le $days
        }
        if ($ok -and $time -gt 0) {
            # Second 60 is a leap second (RFC 3339).
            $ok = [int]$g[$time].Value -le 23 -and [int]$g[$time + 1].Value -le 59 -and [int]$g[$time + 2].Value -le 60
        }
        if ($ok -and $offset -gt 0 -and $g[$offset].Success) {
            $ok = [int]$g[$offset].Value -le 23 -and [int]$g[$offset + 1].Value -le 59
        }
        if ($ok) { return $Tok }
        throw (New-AwTomlError $s.T $At ('Invalid date or time ' + (Format-AwJsoncSnippet $Tok)))
    }

    if ($script:AwTomlRxDec.IsMatch($Tok)) {
        $digits = $Tok.Replace('_', '')
        $v = [long]0
        if ($digits.Length -le 20 -and [long]::TryParse($digits, [System.Globalization.NumberStyles]::AllowLeadingSign, $inv, [ref]$v)) { return $v }
        throw (New-AwTomlError $s.T $At ($outOfRange + (Format-AwJsoncSnippet $Tok)))
    }
    if ($Tok.Length -gt 2 -and $Tok[0] -eq '0') {
        $prefix = $Tok[1]
        $base = 0
        $maxDigits = 0
        if ($prefix -ceq 'x' -and $script:AwTomlRxHex.IsMatch($Tok)) { $base = 16; $maxDigits = 16 }
        elseif ($prefix -ceq 'o' -and $script:AwTomlRxOct.IsMatch($Tok)) { $base = 8; $maxDigits = 22 }
        elseif ($prefix -ceq 'b' -and $script:AwTomlRxBin.IsMatch($Tok)) { $base = 2; $maxDigits = 64 }
        if ($base -gt 0) {
            $digits = $Tok.Substring(2).Replace('_', '').TrimStart([char]'0')
            if ($digits.Length -eq 0) { return [long]0 }
            # A value of 2^63 or more overflows, or wraps to a negative number.
            $v = [long]-1
            if ($digits.Length -le $maxDigits) {
                try { $v = [System.Convert]::ToInt64($digits, $base) } catch { $v = [long]-1 }
            }
            if ($v -ge 0) { return $v }
            throw (New-AwTomlError $s.T $At ($outOfRange + (Format-AwJsoncSnippet $Tok)))
        }
    }
    if ($script:AwTomlRxFloat.IsMatch($Tok)) {
        # .NET Framework fails on overflow and .NET Core returns infinity: both are refused.
        # .NET Framework also drops the sign of -0.0, which is restored here.
        $d = 0.0
        if ([double]::TryParse($Tok.Replace('_', ''), [System.Globalization.NumberStyles]::Float, $inv, [ref]$d) -and
            -not [double]::IsInfinity($d)) {
            if ($d -eq 0 -and $Tok[0] -eq '-') { $d = 0.0 * -1.0 }
            return $d
        }
        throw (New-AwTomlError $s.T $At ('Float out of range: ' + (Format-AwJsoncSnippet $Tok)))
    }
    if ($Tok -ceq 'inf' -or $Tok -ceq '+inf') { return [double]::PositiveInfinity }
    if ($Tok -ceq '-inf') { return [double]::NegativeInfinity }
    if ($Tok -ceq 'nan' -or $Tok -ceq '+nan' -or $Tok -ceq '-nan') { return [double]::NaN }
    throw (New-AwTomlError $s.T $At ('Invalid value ' + (Format-AwJsoncSnippet $Tok) +
        ' (strings must be quoted; booleans, inf and nan are lowercase)'))
}

function Read-AwTomlKey {
    # Reads a bare, quoted or dotted key at $s.P into $s.KeyParts; $s.P ends after trailing spaces.
    param($s)
    $T = $s.T
    $p = $s.P
    $W = $s.W; $wb = $s.Wb; $wl = $s.Wl
    $start = $p
    $parts = [System.Collections.Generic.List[string]]::new()
    $limit = $script:AwTomlMaxDepth + 1
    while ($true) {
        $c = $T[$p]
        if ($c -eq '"' -or $c -eq "'") {
            $s.P = $p
            $parts.Add((Read-AwTomlString $s $false))
            $p = $s.P
            $W = $s.W; $wb = $s.Wb; $wl = $s.Wl
        } elseif ($p -eq $s.KeyAt) {
            # The caller already read this bare part and its spaces; the spaces match below is empty.
            $parts.Add($s.KeyHead)
            $p = $s.KeyNext
        } else {
            if ($p -lt $wb -or $p -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $p }
            $m = $script:AwTomlRxBareKey.Match($W, $p - $wb)
            if ($p + $m.Length -gt $wl) { $m, $W, $wb, $wl = Find-AwTomlMatch $s $script:AwTomlRxBareKey $p }
            if ($m.Length -eq 0) { throw (New-AwTomlError $T $p ('Expected a key, found ' + (Format-AwTomlFound $s $p))) }
            $parts.Add($m.Value)
            $p += $m.Length
        }
        if ($parts.Count -gt $limit) { throw (New-AwTomlError $T $start "Maximum nesting depth of $($script:AwTomlMaxDepth) exceeded by a dotted key") }
        if ($p -lt $wb -or $p -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $p }
        $mw = $script:AwTomlRxWs.Match($W, $p - $wb)
        if ($p + $mw.Length -gt $wl) { $mw, $W, $wb, $wl = Find-AwTomlMatch $s $script:AwTomlRxWs $p }
        $p += $mw.Length
        if ($T[$p] -ne '.') { break }
        $p++
        if ($p -lt $wb -or $p -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $p }
        $mw = $script:AwTomlRxWs.Match($W, $p - $wb)
        if ($p + $mw.Length -gt $wl) { $mw, $W, $wb, $wl = Find-AwTomlMatch $s $script:AwTomlRxWs $p }
        $p += $mw.Length
    }
    $s.Steps += 1 + $parts.Count
    if ($s.Steps -gt $script:AwTomlMaxSteps) { throw (New-AwTomlBudgetError $s $start) }
    $s.P = $p
    $s.KeyParts = $parts
}

function Resolve-AwTomlDotted {
    # Walks the parts of a dotted key (all but the last) from Table, creating the missing tables,
    # and returns the table that receives the value; $s.Depth is set to its depth. Dotted keys
    # only extend tables that dotted keys of the same section (table or inline table) created, or
    # tables that a header created implicitly.
    param($s, $Table, [int]$Depth, [int]$Section, $Parts, [int]$At)
    $s.Steps++
    if ($s.Steps -gt $script:AwTomlMaxSteps) { throw (New-AwTomlBudgetError $s $At) }
    $kinds = $s.Kinds
    $mine = 'd' + $Section
    $kind = $null
    for ($i = 0; $i -lt $Parts.Count - 1; $i++) {
        $k = $Parts[$i]
        $Depth++
        if ($Depth -gt $script:AwTomlMaxDepth) { throw (New-AwTomlError $s.T $At "Maximum nesting depth of $($script:AwTomlMaxDepth) exceeded") }
        if ($Table.ContainsKey($k)) {
            $v = $Table[$k]
            if ($v -is [System.Collections.Hashtable]) {
                [void]$kinds.TryGetValue($v, [ref]$kind)
                if ($kind -ceq 'implicit') { $kinds[$v] = $mine }
                elseif ($kind -cne $mine) {
                    $name = Format-AwTomlKey $Parts ($i + 1)
                    if ($kind -ceq 'frozen') { throw (New-AwTomlError $s.T $At "Cannot add keys to '$name': an inline table cannot be extended") }
                    throw (New-AwTomlError $s.T $At "Cannot add keys to '$name' with dotted keys: the table is already defined")
                }
                $Table = $v
            } elseif ($v -is [System.Collections.ArrayList]) {
                throw (New-AwTomlError $s.T $At ("Cannot add keys to '" + (Format-AwTomlKey $Parts ($i + 1)) + "' with dotted keys: it is an array of tables"))
            } else {
                throw (New-AwTomlError $s.T $At ("Cannot use '" + (Format-AwTomlKey $Parts ($i + 1)) + "' as a table: the key already holds a value"))
            }
        } else {
            $new = [System.Collections.Hashtable]::new([System.StringComparer]::Ordinal)
            $Table[$k] = $new
            $kinds[$new] = $mine
            $Table = $new
        }
    }
    $s.Depth = $Depth
    return $Table
}

function Resolve-AwTomlHeader {
    # Applies a [table] or [[array.of.tables]] header and returns the table it opens;
    # $s.Depth is set to its depth.
    param($s, $Parts, [bool]$IsArray, [int]$At)
    $s.Steps++
    if ($s.Steps -gt $script:AwTomlMaxSteps) { throw (New-AwTomlBudgetError $s $At) }
    $kinds = $s.Kinds
    $max = $script:AwTomlMaxDepth
    $Table = $s.Root
    $depth = 0
    $kind = $null
    $last = $Parts.Count - 1
    for ($i = 0; $i -lt $last; $i++) {
        $k = $Parts[$i]
        if ($Table.ContainsKey($k)) {
            $v = $Table[$k]
            if ($v -is [System.Collections.Hashtable]) {
                [void]$kinds.TryGetValue($v, [ref]$kind)
                if ($kind -ceq 'frozen') {
                    throw (New-AwTomlError $s.T $At ("Cannot extend '" + (Format-AwTomlKey $Parts ($i + 1)) + "': an inline table cannot be extended"))
                }
                $Table = $v
                $depth++
            } elseif ($v -is [System.Collections.ArrayList]) {
                # A header below an array of tables extends its last element.
                $Table = $v[$v.Count - 1]
                $depth += 2
            } else {
                throw (New-AwTomlError $s.T $At ("Cannot use '" + (Format-AwTomlKey $Parts ($i + 1)) + "' as a table: the key already holds a value"))
            }
        } else {
            $new = [System.Collections.Hashtable]::new([System.StringComparer]::Ordinal)
            $Table[$k] = $new
            $kinds[$new] = 'implicit'
            $Table = $new
            $depth++
        }
        if ($depth -gt $max) { throw (New-AwTomlError $s.T $At "Maximum nesting depth of $max exceeded") }
    }
    $k = $Parts[$last]
    if ($IsArray) {
        if ($Table.ContainsKey($k)) {
            $list = $Table[$k]
            if ($list -isnot [System.Collections.ArrayList]) {
                $name = Format-AwTomlKey $Parts
                if ($list -is [System.Collections.Hashtable]) { throw (New-AwTomlError $s.T $At "Cannot define [[$name]]: '$name' is already a table") }
                if ($list -is [array]) { throw (New-AwTomlError $s.T $At "Cannot define [[$name]]: '$name' is a static array, which cannot be extended") }
                throw (New-AwTomlError $s.T $At "Cannot define [[$name]]: the key already holds a value")
            }
        } else {
            $list = [System.Collections.ArrayList]::new()
            $Table[$k] = $list
            [void]$s.Arrays.Add(@($Table, $k))
        }
        $depth += 2
        if ($depth -gt $max) { throw (New-AwTomlError $s.T $At "Maximum nesting depth of $max exceeded") }
        $new = [System.Collections.Hashtable]::new([System.StringComparer]::Ordinal)
        [void]$list.Add($new)
        $kinds[$new] = 'defined'
        $s.Depth = $depth
        return $new
    }
    if ($Table.ContainsKey($k)) {
        $v = $Table[$k]
        $kind = $null
        if ($v -is [System.Collections.Hashtable]) { [void]$kinds.TryGetValue($v, [ref]$kind) }
        if ($kind -ceq 'implicit') {
            $kinds[$v] = 'defined'
            $Table = $v
        } else {
            $name = Format-AwTomlKey $Parts
            if ($kind -ceq 'defined') { throw (New-AwTomlError $s.T $At "Table [$name] is defined more than once") }
            if ($kind -ceq 'frozen') { throw (New-AwTomlError $s.T $At "Table [$name] is already defined as an inline table") }
            if ($null -ne $kind) { throw (New-AwTomlError $s.T $At "Table [$name] is already defined with dotted keys") }
            if ($v -is [System.Collections.ArrayList]) { throw (New-AwTomlError $s.T $At "Table [$name] is already defined as an array of tables") }
            throw (New-AwTomlError $s.T $At "Cannot define table [$name]: the key already holds a value")
        }
    } else {
        $new = [System.Collections.Hashtable]::new([System.StringComparer]::Ordinal)
        $Table[$k] = $new
        $kinds[$new] = 'defined'
        $Table = $new
    }
    $depth++
    if ($depth -gt $max) { throw (New-AwTomlError $s.T $At "Maximum nesting depth of $max exceeded") }
    $s.Depth = $depth
    return $Table
}

function Read-AwTomlInlineKey {
    # Reads 'key =' inside an inline table and records in the frame where its value goes.
    param($s, $Frame)
    $T = $s.T
    $at = $s.P
    $W = $s.W; $wb = $s.Wb; $wl = $s.Wl
    $maxSteps = $script:AwTomlMaxSteps
    $s.Steps++
    if ($s.Steps -gt $maxSteps) { throw (New-AwTomlBudgetError $s $at) }
    $c = $T[$at]
    if ($c -eq '}') { throw (New-AwTomlError $T $at 'A trailing comma is not allowed in an inline table') }
    if ($c -eq "`n" -or $c -eq "`r" -or $c -eq '#') { throw (New-AwTomlError $T $at ('An inline table must stay on one line, found ' + (Format-AwTomlFound $s $at))) }
    # A single bare key is read without the general key reader.
    $parts = $null
    if ($at -lt $wb -or $at -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $at }
    $m = $script:AwTomlRxBareKey.Match($W, $at - $wb)
    if ($at + $m.Length -gt $wl) { $m, $W, $wb, $wl = Find-AwTomlMatch $s $script:AwTomlRxBareKey $at }
    if ($m.Length -gt 0) {
        $p = $at + $m.Length
        if ($p -lt $wb -or $p -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $p }
        $mw = $script:AwTomlRxWs.Match($W, $p - $wb)
        if ($p + $mw.Length -gt $wl) { $mw, $W, $wb, $wl = Find-AwTomlMatch $s $script:AwTomlRxWs $p }
        $p += $mw.Length
        if ($T[$p] -eq '=') {
            $parts = [string[]]@($m.Value)
            $s.Steps++
            if ($s.Steps -gt $maxSteps) { throw (New-AwTomlBudgetError $s $at) }
        } else { $s.KeyAt = $at; $s.KeyHead = $m.Value; $s.KeyNext = $p }
    }
    if ($null -eq $parts) {
        Read-AwTomlKey $s
        $parts = $s.KeyParts
        $p = $s.P
        $W = $s.W; $wb = $s.Wb; $wl = $s.Wl
        if ($T[$p] -ne '=') { throw (New-AwTomlError $T $p ("Expected '=' after the key '" + (Format-AwTomlKey $parts) + "', found " + (Format-AwTomlFound $s $p))) }
    }
    $p++
    if ($p -lt $wb -or $p -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $p }
    $mw = $script:AwTomlRxWs.Match($W, $p - $wb)
    if ($p + $mw.Length -gt $wl) { $mw, $W, $wb, $wl = Find-AwTomlMatch $s $script:AwTomlRxWs $p }
    $s.P = $p + $mw.Length
    $target = $Frame.Map
    $s.Depth = $Frame.Depth
    if ($parts.Count -gt 1) { $target = Resolve-AwTomlDotted $s $Frame.Map $Frame.Depth $Frame.Section $parts $at }
    $stem = $parts[$parts.Count - 1]
    if ($target.ContainsKey($stem)) { throw (New-AwTomlError $T $at ("Duplicate key '" + (Format-AwTomlKey $parts) + "' in an inline table")) }
    $Frame.Target = $target
    $Frame.Stem = $stem
    $Frame.TargetDepth = $s.Depth
}

function Read-AwTomlValue {
    # Reads the value at $s.P and moves $s.P past it. Arrays and inline tables nest on an
    # explicit stack. Depth is the depth of the table that receives the value.
    param($s, [int]$Depth)
    $T = $s.T
    $max = $script:AwTomlMaxDepth
    $maxSteps = $script:AwTomlMaxSteps
    $rxTrivia = $script:AwTomlRxTrivia
    $rxWs = $script:AwTomlRxWs
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $stack = $null
    $p = $s.P
    $W = $s.W; $wb = $s.Wb; $wl = $s.Wl
    $s.Steps++
    if ($s.Steps -gt $maxSteps) { throw (New-AwTomlBudgetError $s $p) }
    while ($true) {
        # A value starts at $p.
        $c = $T[$p]
        $complete = $true
        if ($c -eq '[' -or $c -eq '{') {
            if ($null -eq $stack) { $stack = [System.Collections.ArrayList]::new() }
            if ($stack.Count -eq 0) { $d = $Depth + 1 }
            else {
                $top = $stack[$stack.Count - 1]
                if ($top.IsArray) { $d = $top.Depth + 1 } else { $d = $top.TargetDepth + 1 }
            }
            if ($d -gt $max) { throw (New-AwTomlError $T $p "Maximum nesting depth of $max exceeded") }
            $p++
            if ($c -eq '[') {
                [void]$stack.Add(@{ IsArray = $true; Depth = $d; List = [System.Collections.ArrayList]::new() })
                if ($p -lt $wb -or $p -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $p }
                $mw = $rxTrivia.Match($W, $p - $wb)
                if ($p + $mw.Length -gt $wl) { $mw, $W, $wb, $wl = Find-AwTomlMatch $s $rxTrivia $p }
                $p += $mw.Length
                if ($T[$p] -eq ']') {
                    $p++
                    $stack.RemoveAt($stack.Count - 1)
                    $value = @()
                } else {
                    $complete = $false
                }
            } else {
                # Each inline table is a section of its own for dotted keys.
                $s.Section++
                $map = [System.Collections.Hashtable]::new([System.StringComparer]::Ordinal)
                $frame = @{ IsArray = $false; Depth = $d; Map = $map; Section = $s.Section; Target = $null; Stem = $null; TargetDepth = $d }
                [void]$stack.Add($frame)
                if ($p -lt $wb -or $p -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $p }
                $mw = $rxWs.Match($W, $p - $wb)
                if ($p + $mw.Length -gt $wl) { $mw, $W, $wb, $wl = Find-AwTomlMatch $s $rxWs $p }
                $p += $mw.Length
                if ($T[$p] -eq '}') {
                    $p++
                    $stack.RemoveAt($stack.Count - 1)
                    $s.Kinds[$map] = 'frozen'
                    $value = $map
                } else {
                    $s.P = $p
                    Read-AwTomlInlineKey $s $frame
                    $p = $s.P
                    $W = $s.W; $wb = $s.Wb; $wl = $s.Wl
                    $complete = $false
                }
            }
        } else {
            $value = $null
            $done = $false
            if ($c -eq '"') {
                # Fast path: a basic string without escapes. Otherwise Read-AwTomlString takes its match.
                if (-not ($T[$p + 1] -eq '"' -and $T[$p + 2] -eq '"')) {
                    $sp = $p + 1
                    if ($s.BasicAt -eq $sp) { $m = $s.BasicMatch }
                    else {
                        if ($sp -lt $wb -or $sp -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $sp }
                        $m = $script:AwTomlRxBasic.Match($W, $sp - $wb)
                        if ($sp + $m.Length -gt $wl) { $m, $W, $wb, $wl = Find-AwTomlMatch $s $script:AwTomlRxBasic $sp }
                    }
                    $e = $p + 1 + $m.Length
                    if ($T[$e] -eq '"' -and $m.Value.IndexOf([char]'\') -lt 0) { $value = $m.Value; $p = $e + 1; $done = $true }
                    else { $s.BasicAt = $sp; $s.BasicMatch = $m }
                }
            } elseif ($c -eq "'") {
                # Fast path: a literal string.
                if (-not ($T[$p + 1] -eq "'" -and $T[$p + 2] -eq "'")) {
                    $sp = $p + 1
                    if ($sp -lt $wb -or $sp -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $sp }
                    $m = $script:AwTomlRxLiteral.Match($W, $sp - $wb)
                    if ($sp + $m.Length -gt $wl) { $m, $W, $wb, $wl = Find-AwTomlMatch $s $script:AwTomlRxLiteral $sp }
                    $e = $p + 1 + $m.Length
                    if ($T[$e] -eq "'") { $value = $m.Value; $p = $e + 1; $done = $true }
                }
            } else {
                if ($p -lt $wb -or $p -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $p }
                $m = $script:AwTomlRxToken.Match($W, $p - $wb)
                if ($p + $m.Length -gt $wl) { $m, $W, $wb, $wl = Find-AwTomlMatch $s $script:AwTomlRxToken $p }
                if ($m.Length -eq 0) { throw (New-AwTomlError $T $p ('Expected a value, found ' + (Format-AwTomlFound $s $p))) }
                $tok = $m.Value
                $at = $p
                $p += $m.Length
                # A date and a time separated by a space form one date-time.
                if ($tok.Length -eq 10 -and $tok[4] -eq '-' -and $T[$p] -eq ' ' -and [int]$T[$p + 1] -ge 48 -and [int]$T[$p + 1] -le 57) {
                    $sp = $p + 1
                    if ($sp -lt $wb -or $sp -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $sp }
                    $m = $script:AwTomlRxToken.Match($W, $sp - $wb)
                    if ($sp + $m.Length -gt $wl) { $m, $W, $wb, $wl = Find-AwTomlMatch $s $script:AwTomlRxToken $sp }
                    $tok = $tok + ' ' + $m.Value
                    $p += 1 + $m.Length
                }
                if ($tok -ceq 'true') { $value = $true }
                elseif ($tok -ceq 'false') { $value = $false }
                elseif ($script:AwTomlRxSmallInt.IsMatch($tok)) { $value = [long]::Parse($tok, $inv) }
                else { $value = ConvertFrom-AwTomlToken $s $tok $at }
                $done = $true
            }
            if (-not $done) {
                $s.P = $p
                $value = Read-AwTomlString $s $true
                $p = $s.P
                $W = $s.W; $wb = $s.Wb; $wl = $s.Wl
            }
        }

        if (-not $complete) { continue }
        # Hand the value to its container, closing every container that ends here.
        while ($true) {
            if ($null -eq $stack -or $stack.Count -eq 0) {
                $s.P = $p
                return ,$value
            }
            $top = $stack[$stack.Count - 1]
            $s.Steps++
            if ($s.Steps -gt $maxSteps) { throw (New-AwTomlBudgetError $s $p) }
            if ($top.IsArray) {
                [void]$top.List.Add($value)
                if ($p -lt $wb -or $p -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $p }
                $mw = $rxTrivia.Match($W, $p - $wb)
                if ($p + $mw.Length -gt $wl) { $mw, $W, $wb, $wl = Find-AwTomlMatch $s $rxTrivia $p }
                $p += $mw.Length
                $c = $T[$p]
                if ($c -eq ',') {
                    $p++
                    if ($p -lt $wb -or $p -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $p }
                    $mw = $rxTrivia.Match($W, $p - $wb)
                    if ($p + $mw.Length -gt $wl) { $mw, $W, $wb, $wl = Find-AwTomlMatch $s $rxTrivia $p }
                    $p += $mw.Length
                    if ($T[$p] -ne ']') { break }
                    $c = ']'
                }
                if ($c -eq ']') {
                    $p++
                    $stack.RemoveAt($stack.Count - 1)
                    $value = $top.List.ToArray()
                    continue
                }
                throw (New-AwTomlError $T $p ("Expected ',' or ']' after an array element, found " + (Format-AwTomlFound $s $p)))
            }
            $top.Target[$top.Stem] = $value
            if ($p -lt $wb -or $p -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $p }
            $mw = $rxWs.Match($W, $p - $wb)
            if ($p + $mw.Length -gt $wl) { $mw, $W, $wb, $wl = Find-AwTomlMatch $s $rxWs $p }
            $p += $mw.Length
            $c = $T[$p]
            if ($c -eq ',') {
                $p++
                if ($p -lt $wb -or $p -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $p }
                $mw = $rxWs.Match($W, $p - $wb)
                if ($p + $mw.Length -gt $wl) { $mw, $W, $wb, $wl = Find-AwTomlMatch $s $rxWs $p }
                $s.P = $p + $mw.Length
                Read-AwTomlInlineKey $s $top
                $p = $s.P
                $W = $s.W; $wb = $s.Wb; $wl = $s.Wl
                break
            }
            if ($c -eq '}') {
                $p++
                $stack.RemoveAt($stack.Count - 1)
                $s.Kinds[$top.Map] = 'frozen'
                $value = $top.Map
                continue
            }
            if ($c -eq "`n" -or $c -eq "`r" -or $c -eq '#') {
                throw (New-AwTomlError $T $p ("Expected ',' or '}': an inline table must stay on one line, found " + (Format-AwTomlFound $s $p)))
            }
            throw (New-AwTomlError $T $p ("Expected ',' or '}' in an inline table, found " + (Format-AwTomlFound $s $p)))
        }
    }
}

function ConvertFrom-AwToml {
    <#
    .SYNOPSIS
    Parses a TOML 1.0 document into nested hashtables and arrays.
    .DESCRIPTION
    Supports comments; bare, quoted and dotted keys; [table] and [[array.of.tables]] headers;
    inline tables; multi-line arrays with comments and trailing commas; the four string kinds
    and their escapes; integers (decimal, hexadecimal, octal and binary, with underscores);
    floats (exponents, inf, nan); booleans; offset and local date-times, dates and times.

    Tables are case-sensitive hashtables; arrays and arrays of tables are object[]; integers are
    [long], floats [double] and booleans [bool]. Dates and times are returned as [string], with
    their original text. Newlines inside multi-line strings are returned as LF.

    Invalid TOML throws a System.FormatException with Data['Line'] and Data['Column'], for
    example on a duplicate key, a table defined twice, an invalid escape or an unterminated
    string. Limits for hostile input: 2 MB of text, 64 nested tables and arrays below the root
    table, and 20000 parse steps (about one per key part, value, header, string and escape).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowEmptyString()] [AllowNull()] [string]$Text)
    if ($null -eq $Text) { $Text = '' }
    if ($Text.Length -gt $script:AwTomlMaxLength) {
        $ex = New-Object System.FormatException -ArgumentList ('Invalid TOML: the document is larger than the 2 MB limit ({0} characters)' -f $Text.Length)
        $ex.Data['Line'] = $null
        $ex.Data['Column'] = $null
        throw $ex
    }
    $start = 0
    if ($Text.Length -gt 0 -and $Text[0] -eq $script:AwBom) { $start = 1 }
    if ($Text.Length -gt 0 -and $Text[$Text.Length - 1] -eq "`r") {
        throw (New-AwTomlError $Text ($Text.Length - 1) 'Carriage return without a line feed')
    }
    # A final line feed lets the last statement end like the others.
    $T = $Text + "`n"
    $root = [System.Collections.Hashtable]::new([System.StringComparer]::Ordinal)
    # How each table was created: 'implicit' (by a header path), 'defined' (by its header),
    # 'frozen' (inline table) or 'd<section>' (by dotted keys in that section).
    $kinds = [System.Collections.Generic.Dictionary[object,string]]::new()
    $kinds[$root] = 'defined'
    # A fast path that stops leaves what it read for the reader that takes over, so a long string or
    # run of spaces past a window edge is matched once: the basic string body at BasicAt, or the bare
    # first key part at KeyAt with the position after its spaces. The text never changes during a
    # parse, so what was read at a position stays true.
    $s = @{
        T = $T; End = $Text.Length; P = $start; Root = $root; Kinds = $kinds
        Arrays = [System.Collections.ArrayList]::new(); Section = 0; Depth = 0; Steps = 0; KeyParts = $null
        W = ''; Wb = 0; Wl = -1
        BasicAt = -1; BasicMatch = $null; KeyAt = -1; KeyHead = ''; KeyNext = 0
    }
    $rxTrivia = $script:AwTomlRxTrivia
    $rxWs = $script:AwTomlRxWs
    $rxBare = $script:AwTomlRxBareKey
    $rxLineEnd = $script:AwTomlRxLineEnd
    $rxBasic = $script:AwTomlRxBasic
    $rxLiteral = $script:AwTomlRxLiteral
    $rxToken = $script:AwTomlRxToken
    $rxSmallInt = $script:AwTomlRxSmallInt
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $maxSteps = $script:AwTomlMaxSteps
    $current = $root
    $currentDepth = 0
    $currentSection = 0
    $currentParts = $null
    $n = $T.Length
    $p = $start
    $W = $s.W; $wb = $s.Wb; $wl = $s.Wl
    while ($true) {
        if ($p -lt $wb -or $p -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $p }
        $mw = $rxTrivia.Match($W, $p - $wb)
        if ($p + $mw.Length -gt $wl) { $mw, $W, $wb, $wl = Find-AwTomlMatch $s $rxTrivia $p }
        $p += $mw.Length
        if ($p -ge $n) { break }
        $at = $p
        $code = [int]$T[$p]
        if ($code -lt 32 -or $code -eq 127) {
            throw (New-AwTomlError $T $p ('Invalid character: ' + (Format-AwTomlFound $s $p) + ' (control characters are not allowed in comments or outside strings)'))
        }
        $s.Steps++
        if ($s.Steps -gt $maxSteps) { throw (New-AwTomlBudgetError $s $at) }

        if ($T[$p] -eq '[') {
            # [table] or [[array of tables]]; a single bare key skips the general key reader.
            $isArray = ($T[$p + 1] -eq '[')
            if ($isArray) { $p += 2 } else { $p++ }
            if ($p -lt $wb -or $p -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $p }
            $mw = $rxWs.Match($W, $p - $wb)
            if ($p + $mw.Length -gt $wl) { $mw, $W, $wb, $wl = Find-AwTomlMatch $s $rxWs $p }
            $p += $mw.Length
            $parts = $null
            if ($p -lt $wb -or $p -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $p }
            $m = $rxBare.Match($W, $p - $wb)
            if ($p + $m.Length -gt $wl) { $m, $W, $wb, $wl = Find-AwTomlMatch $s $rxBare $p }
            if ($m.Length -gt 0) {
                $q = $p + $m.Length
                if ($q -lt $wb -or $q -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $q }
                $mw = $rxWs.Match($W, $q - $wb)
                if ($q + $mw.Length -gt $wl) { $mw, $W, $wb, $wl = Find-AwTomlMatch $s $rxWs $q }
                $q += $mw.Length
                if ($T[$q] -eq ']') { $parts = [string[]]@($m.Value); $p = $q }
                else { $s.KeyAt = $p; $s.KeyHead = $m.Value; $s.KeyNext = $q }
            }
            if ($null -eq $parts) {
                $s.P = $p
                Read-AwTomlKey $s
                $parts = $s.KeyParts
                $p = $s.P
                $W = $s.W; $wb = $s.Wb; $wl = $s.Wl
            }
            if ($isArray) {
                if ($T[$p] -ne ']' -or $T[$p + 1] -ne ']') {
                    throw (New-AwTomlError $T $p ("Expected ']]' to close the array of tables header, found " + (Format-AwTomlFound $s $p)))
                }
                $p += 2
            } elseif ($T[$p] -ne ']') {
                throw (New-AwTomlError $T $p ("Expected ']' to close the table header, found " + (Format-AwTomlFound $s $p)))
            } else {
                $p++
            }
            $current = Resolve-AwTomlHeader $s $parts $isArray $at
            $currentDepth = $s.Depth
            $s.Section++
            $currentSection = $s.Section
            $currentParts = $parts
        } else {
            # key = value; a single bare key skips the general key reader.
            $parts = $null
            $key = $null
            if ($p -lt $wb -or $p -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $p }
            $m = $rxBare.Match($W, $p - $wb)
            if ($p + $m.Length -gt $wl) { $m, $W, $wb, $wl = Find-AwTomlMatch $s $rxBare $p }
            if ($m.Length -gt 0) {
                $q = $p + $m.Length
                if ($q -lt $wb -or $q -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $q }
                $mw = $rxWs.Match($W, $q - $wb)
                if ($q + $mw.Length -gt $wl) { $mw, $W, $wb, $wl = Find-AwTomlMatch $s $rxWs $q }
                $q += $mw.Length
                if ($T[$q] -eq '=') { $key = $m.Value; $p = $q }
                else { $s.KeyAt = $p; $s.KeyHead = $m.Value; $s.KeyNext = $q }
            }
            if ($null -eq $key) {
                $s.P = $p
                Read-AwTomlKey $s
                $parts = $s.KeyParts
                $p = $s.P
                $W = $s.W; $wb = $s.Wb; $wl = $s.Wl
                if ($T[$p] -ne '=') {
                    throw (New-AwTomlError $T $p ("Expected '=' after the key '" + (Format-AwTomlKey $parts) + "', found " + (Format-AwTomlFound $s $p)))
                }
                $key = $parts[$parts.Count - 1]
            }
            $p++
            if ($p -lt $wb -or $p -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $p }
            $mw = $rxWs.Match($W, $p - $wb)
            if ($p + $mw.Length -gt $wl) { $mw, $W, $wb, $wl = Find-AwTomlMatch $s $rxWs $p }
            $p += $mw.Length
            $target = $current
            $targetDepth = $currentDepth
            if ($null -ne $parts -and $parts.Count -gt 1) {
                $target = Resolve-AwTomlDotted $s $current $currentDepth $currentSection $parts $at
                $targetDepth = $s.Depth
            }
            if ($target.ContainsKey($key)) {
                if ($null -eq $parts) { $parts = [string[]]@($key) }
                $where = ''
                if ($null -ne $currentParts) { $where = ' in table [' + (Format-AwTomlKey $currentParts) + ']' }
                throw (New-AwTomlError $T $at ("Duplicate key '" + (Format-AwTomlKey $parts) + "'" + $where))
            }
            # Common scalars are read here, since a function call costs more than their parsing;
            # Read-AwTomlValue reads everything else.
            $done = $false
            $c = $T[$p]
            if ($c -eq '"') {
                if (-not ($T[$p + 1] -eq '"' -and $T[$p + 2] -eq '"')) {
                    $sp = $p + 1
                    if ($sp -lt $wb -or $sp -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $sp }
                    $m = $rxBasic.Match($W, $sp - $wb)
                    if ($sp + $m.Length -gt $wl) { $m, $W, $wb, $wl = Find-AwTomlMatch $s $rxBasic $sp }
                    $e = $p + 1 + $m.Length
                    if ($T[$e] -eq '"' -and $m.Value.IndexOf([char]'\') -lt 0) { $value = $m.Value; $p = $e + 1; $done = $true }
                    else { $s.BasicAt = $sp; $s.BasicMatch = $m }
                }
            } elseif ($c -eq "'") {
                if (-not ($T[$p + 1] -eq "'" -and $T[$p + 2] -eq "'")) {
                    $sp = $p + 1
                    if ($sp -lt $wb -or $sp -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $sp }
                    $m = $rxLiteral.Match($W, $sp - $wb)
                    if ($sp + $m.Length -gt $wl) { $m, $W, $wb, $wl = Find-AwTomlMatch $s $rxLiteral $sp }
                    $e = $p + 1 + $m.Length
                    if ($T[$e] -eq "'") { $value = $m.Value; $p = $e + 1; $done = $true }
                }
            } elseif ($c -ne '[' -and $c -ne '{') {
                if ($p -lt $wb -or $p -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $p }
                $m = $rxToken.Match($W, $p - $wb)
                if ($p + $m.Length -gt $wl) { $m, $W, $wb, $wl = Find-AwTomlMatch $s $rxToken $p }
                # A 10-character token followed by a space may be the date of a date-time.
                if ($m.Length -gt 0 -and -not ($m.Length -eq 10 -and $T[$p + 10] -eq ' ')) {
                    $tok = $m.Value
                    if ($tok -ceq 'true') { $value = $true }
                    elseif ($tok -ceq 'false') { $value = $false }
                    elseif ($rxSmallInt.IsMatch($tok)) { $value = [long]::Parse($tok, $inv) }
                    else { $value = ConvertFrom-AwTomlToken $s $tok $p }
                    $p += $m.Length
                    $done = $true
                }
            }
            if (-not $done) {
                $s.P = $p
                $value = Read-AwTomlValue $s $targetDepth
                $p = $s.P
                $W = $s.W; $wb = $s.Wb; $wl = $s.Wl
            }
            $target[$key] = $value
        }
        # The statement must end the line; a comment may follow it.
        if ($p -lt $wb -or $p -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $p }
        $mw = $rxLineEnd.Match($W, $p - $wb)
        if ($p + $mw.Length -gt $wl) { $mw, $W, $wb, $wl = Find-AwTomlMatch $s $rxLineEnd $p }
        $p += $mw.Length
        $c = $T[$p]
        if ($c -eq "`n") { $p++ }
        elseif ($c -eq "`r" -and $T[$p + 1] -eq "`n") { $p += 2 }
        else { throw (New-AwTomlError $T $p ('Expected the end of the line, found ' + (Format-AwTomlFound $s $p))) }
    }
    # Arrays of tables stay growable until the end of the document.
    foreach ($entry in $s.Arrays) { $entry[0][$entry[1]] = $entry[0][$entry[1]].ToArray() }
    return $root
}
