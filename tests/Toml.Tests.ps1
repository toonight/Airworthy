# Tests for the TOML parser (src/Core/Toml.ps1).
$aw = Get-Module Airworthy
$fixtures = Join-Path $PSScriptRoot 'fixtures\toml'
# Control and non-ASCII characters come from a JSON fixture with backslash-u escapes (CONTRIBUTING.md, Antivirus hygiene).
$vectors = & $aw { param($p) ConvertFrom-AwJsonc -Text ([System.IO.File]::ReadAllText($p)) } (Join-Path $fixtures 'strings.json')
$ctl = $vectors['controls']
$mb2 = 2097152

function ConvertFrom-TestToml {
    param([AllowEmptyString()] [AllowNull()] [string]$Text)
    & $aw { param($t) ConvertFrom-AwToml -Text $t } $Text
}

function Read-TestToml([string]$Name) { ConvertFrom-TestToml ([System.IO.File]::ReadAllText((Join-Path $fixtures $Name))) }

function Read-TestJson([string]$Name) {
    & $aw { param($p) ConvertFrom-AwJsonc -Text ([System.IO.File]::ReadAllText($p)) } (Join-Path $fixtures $Name)
}

function Get-TestTomlError {
    # Returns the FormatException raised for invalid input.
    param([AllowEmptyString()] [string]$Text)
    $ex = Assert-Throws { ConvertFrom-TestToml $Text }
    while ($ex -isnot [System.FormatException] -and $null -ne $ex.InnerException) { $ex = $ex.InnerException }
    Assert-True ($ex -is [System.FormatException]) "expected a FormatException, got $($ex.GetType().FullName)"
    return $ex
}

function Measure-TestToml {
    # Parses Text; returns the elapsed seconds, the value and the error message ('' when it parsed).
    param([string]$Text)
    $message = ''
    $value = $null
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try { $value = ConvertFrom-TestToml $Text } catch { $message = $_.Exception.Message }
    $sw.Stop()
    Write-Host ('AW-TIME-TEMP {0:N3}' -f $sw.Elapsed.TotalSeconds)
    return [pscustomobject]@{ Seconds = $sw.Elapsed.TotalSeconds; Value = $value; Message = $message }
}

function Measure-TestHostileToml {
    # Measure-TestToml on a text within the size limit; asserts that the parse took under 2 seconds.
    param([string]$Text)
    Assert-True ($Text.Length -le $mb2) 'the input stays within the size limit'
    $r = Measure-TestToml $Text
    Assert-True ($r.Seconds -lt 2) ("took {0:N2} s" -f $r.Seconds)
    return $r
}

function Join-TestLines([string[]]$Lines) { return ($Lines -join "`n") }

function New-TestTomlKeys {
    # Count lines 'k<i> = <Value>', joined by Newline (no newline after the last one).
    param([int]$Count, [string]$Value, [string]$Newline = "`n")
    $lines = foreach ($i in 0..($Count - 1)) { 'k' + $i + ' = ' + $Value }
    return ($lines -join $Newline)
}

function Set-TestTomlWindow {
    # Sets the window size and margin of the parser; returns the previous pair.
    param([int]$Size, [int]$Margin)
    return (& $aw {
        param($size, $margin)
        $old = @($script:AwTomlWindow, $script:AwTomlWindowMargin)
        $script:AwTomlWindow = $size
        $script:AwTomlWindowMargin = $margin
        return ,$old
    } $Size $Margin)
}

function Format-TestTomlValue {
    # Exact text of a parsed value: types, ordinal key order, string lengths and double bits.
    param($Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [hashtable]) {
        $keys = [string[]]@($Value.Keys)
        [System.Array]::Sort($keys, [System.StringComparer]::Ordinal)
        $parts = foreach ($k in $keys) { [string]$k.Length + ':' + $k + '=' + (Format-TestTomlValue $Value[$k]) }
        return '{' + ($parts -join ',') + '}'
    }
    if ($Value -is [object[]]) {
        $parts = foreach ($v in $Value) { Format-TestTomlValue $v }
        return '[' + ($parts -join ',') + ']'
    }
    if ($Value -is [double]) { return 'double:' + [System.BitConverter]::DoubleToInt64Bits($Value) }
    if ($Value -is [string]) { return 'string:' + $Value.Length + ':' + $Value }
    return $Value.GetType().Name + ':' + $Value
}

function Get-TestTomlOutcome {
    # The exact result of parsing Text: the value, or the exception type, line, column and message.
    param([string]$Text)
    try { $r = ConvertFrom-TestToml $Text } catch {
        $ex = $_.Exception
        while ($ex -isnot [System.FormatException] -and $null -ne $ex.InnerException) { $ex = $ex.InnerException }
        return ('error ' + $ex.GetType().Name + ' ' + $ex.Data['Line'] + ':' + $ex.Data['Column'] + ' ' + $ex.Message)
    }
    return (Format-TestTomlValue $r)
}

function Get-TestTomlOutcomes {
    # Outcome of each text with the given window size and margin; the previous ones are restored.
    param($Texts, [int]$Size, [int]$Margin)
    $old = Set-TestTomlWindow $Size $Margin
    try {
        $out = New-Object System.Collections.Generic.List[string]
        foreach ($t in $Texts) { $out.Add((Get-TestTomlOutcome $t)) }
        return ,$out.ToArray()
    } finally {
        $null = Set-TestTomlWindow $old[0] $old[1]
    }
}

function Compare-TestTomlOutcomes {
    # Asserts that two outcome lists are equal; the message names the first differences.
    param($Texts, $Expected, $Actual, [string]$What)
    $diff = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $Expected.Count; $i++) {
        if (-not [string]::Equals($Expected[$i], $Actual[$i], [System.StringComparison]::Ordinal)) {
            $diff.Add("text $i <$($Texts[$i])>: expected <$($Expected[$i])>, got <$($Actual[$i])>")
        }
    }
    Assert-Equal 0 $diff.Count ($What + ': ' + (@($diff | Select-Object -First 3) -join ' | '))
}

function New-TestTomlFuzz {
    # Seeded TOML-like documents: statements, headers, comments and junk, built from fragments
    # whose tokens end near the edges of small windows. Many are invalid somewhere.
    param([int]$Seed, [int]$Count)
    $rng = New-Object System.Random -ArgumentList $Seed
    $keys = @('a', 'b', 'k_1', 'key-2', '"q k"', "'lit'", 'a.b', 'a . b', '"a"."b"', 'x. y .z', '1234', '3.14',
        '"\u0041"', '""', 'a+b', 'a:b', '"a\tb"')
    $values = @('1', '-0', '+17', '0x1F', '0o7', '0b1', '1_000', '1e5', '3.14', '-inf', 'nan', 'true', 'false',
        '1979-05-27', '1979-05-27 07:32:00', '1979-05-27T07:32:00Z', '07:32:00', '1979-05-27  07:32:00', '1979-05-27 x',
        '"x"', '"a\"b\\c"', '"\u0041\n"', '"\x"', "'C:\x'", '"""m"""', '"""a""b"""""', "'''l'''", "'''x''''",
        ('"""\' + "`n" + '  y"""'), ("'''" + "`r`n" + "z'''"), '[]', '[1, 2]', ('[ 1, # c' + "`n" + ' 2, ]'), '{}',
        '{ a = 1, b.c = "x" }', '[ { a = 1 }, [ "z" ] ]', '{ a = 1 # c }', '[[1],[2,],]')
    $junk = @('=', '"', '"""', "'", "'''", '\', "`r", "`n", "`r`n", '#', '[', ']', '[[', ']]', '{', '}', ',', '.', ' ',
        "`t", 'x', '\u12', '1979-05-27', $ctl['nul'], $ctl['bell'], $ctl['esc'], $ctl['del'], $ctl['lineSeparator'])
    $all = @($keys + $values + $junk)
    $docs = New-Object System.Collections.Generic.List[string]
    for ($d = 0; $d -lt $Count; $d++) {
        $sb = New-Object System.Text.StringBuilder
        $lines = $rng.Next(1, 7)
        for ($l = 0; $l -lt $lines; $l++) {
            $kind = $rng.Next(10)
            if ($kind -lt 5) {
                $key = $keys[$rng.Next($keys.Count)]
                if ($rng.Next(4) -eq 0) { $key = 'k' * $rng.Next(1, 40) }
                $value = $values[$rng.Next($values.Count)]
                if ($rng.Next(4) -eq 0) { $value = '"' + ('x' * $rng.Next(0, 40)) + '"' }
                [void]$sb.Append($key + (' ' * $rng.Next(0, 3)) + '=' + (' ' * $rng.Next(0, 20)) + $value)
                if ($rng.Next(3) -eq 0) { [void]$sb.Append(' # ' + ('c' * $rng.Next(0, 30))) }
            } elseif ($kind -eq 5) {
                $key = $keys[$rng.Next($keys.Count)]
                if ($rng.Next(2) -eq 0) { [void]$sb.Append('[' + $key + ']') } else { [void]$sb.Append('[[' + $key + ']]') }
            } elseif ($kind -eq 6) {
                [void]$sb.Append((' ' * $rng.Next(0, 20)) + '#' + ('c' * $rng.Next(0, 40)))
            } else {
                $n = $rng.Next(1, 7)
                for ($j = 0; $j -lt $n; $j++) { [void]$sb.Append($all[$rng.Next($all.Count)]) }
            }
            # Sometimes a stray fragment lands anywhere in the document.
            if ($rng.Next(8) -eq 0) { [void]$sb.Insert($rng.Next(0, $sb.Length + 1), $junk[$rng.Next($junk.Count)]) }
            if ($rng.Next(4) -eq 0) { [void]$sb.Append("`r`n") } else { [void]$sb.Append("`n") }
        }
        $docs.Add($sb.ToString())
    }
    return ,$docs.ToArray()
}

function Test-TestTomlDocumentRef {
    # True when an AST node is the TOML document ($T, $Text or $s.T) used as a value, rather than as
    # the target of a member access or of an index.
    param($Node)
    $isDoc = $false
    if ($Node -is [System.Management.Automation.Language.VariableExpressionAst]) {
        $name = $Node.VariablePath.UserPath
        $isDoc = ($name -ceq 'T' -or $name -ceq 'Text')
    } elseif ($Node -is [System.Management.Automation.Language.MemberExpressionAst] -and
        $Node -isnot [System.Management.Automation.Language.InvokeMemberExpressionAst]) {
        $isDoc = ($Node.Expression -is [System.Management.Automation.Language.VariableExpressionAst] -and
            $Node.Expression.VariablePath.UserPath -ceq 's' -and $Node.Member.Extent.Text -ceq 'T')
    }
    if (-not $isDoc) { return $false }
    $parent = $Node.Parent
    if ($parent -is [System.Management.Automation.Language.MemberExpressionAst] -and [object]::ReferenceEquals($parent.Expression, $Node)) { return $false }
    if ($parent -is [System.Management.Automation.Language.IndexExpressionAst] -and [object]::ReferenceEquals($parent.Target, $Node)) { return $false }
    return $true
}

$tomlPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'src\Core\Toml.ps1'

Describe 'ConvertFrom-AwToml: the toml.io example' {
    It 'parses it into the same structure as its JSON equivalent' {
        Assert-Equal (Read-TestJson 'example.json') (Read-TestToml 'example.toml')
    }
    It 'returns hashtables, object[] and typed scalars' {
        $r = Read-TestToml 'example.toml'
        Assert-True ($r -is [hashtable])
        Assert-True ($r['owner'] -is [hashtable])
        Assert-Equal '1979-05-27T07:32:00-08:00' $r['owner']['dob']
        Assert-True ($r['owner']['dob'] -is [string]) 'dates keep their text'
        Assert-True ($r['database']['enabled'] -is [bool])
        Assert-True ($r['database']['ports'] -is [object[]])
        Assert-True ($r['database']['ports'][0] -is [long])
        Assert-True ($r['database']['data'][1][0] -is [double])
        Assert-True ($r['database']['temp_targets'] -is [hashtable])
        Assert-True ($r['database']['temp_targets']['case'] -is [double]) '72.0 is a float'
        Assert-Equal 2 $r['servers'].Count
        Assert-Equal 'backend' $r.servers.beta.role
    }
}

Describe 'ConvertFrom-AwToml: keys' {
    It 'parses bare, quoted, empty and dotted keys like the specification' {
        Assert-Equal (Read-TestJson 'keys.json') (Read-TestToml 'keys.toml')
    }
    It 'keeps all-digit keys and dotted numbers as strings' {
        $r = Read-TestToml 'keys.toml'
        Assert-True $r.ContainsKey('1234')
        Assert-Equal 'pi' $r['3']['14159']
    }
    It 'keeps keys case-sensitive' {
        $r = ConvertFrom-TestToml "a = 1`nA = 2"
        Assert-Equal 2 $r.Count
        Assert-Equal 1 $r['a']
        Assert-Equal 2 $r['A']
        Assert-False ((ConvertFrom-TestToml 'k = 1').ContainsKey('K'))
    }
    It 'accepts escapes in quoted keys and literal keys with backslashes' {
        $r = ConvertFrom-TestToml (Join-TestLines @('"a\tb" = 1', "'C:\x' = 2", '"\u0041" = 3'))
        Assert-Equal 1 $r["a`tb"]
        Assert-Equal 2 $r['C:\x']
        Assert-Equal 3 $r['A']
    }
}

Describe 'ConvertFrom-AwToml: strings' {
    It 'decodes the four string kinds and every escape' {
        Assert-Equal $vectors['expected'] (Read-TestToml 'strings.toml')
    }
    It 'decodes \U escapes above U+FFFF into surrogate pairs' {
        $r = ConvertFrom-TestToml 'e = "\U0001F600"'
        Assert-Equal @(0xD83D, 0xDE00) @($r['e'].ToCharArray() | ForEach-Object { [int]$_ })
    }
    It 'decodes \u0000 and lowercase hexadecimal digits' {
        $r = ConvertFrom-TestToml 'e = "a\u0000b\u00e9"'
        Assert-Equal @(0x61, 0, 0x62, 0xE9) @($r['e'].ToCharArray() | ForEach-Object { [int]$_ })
    }
    It 'keeps raw UTF-8 text in keys and strings' {
        Assert-Equal $vectors['unicode'] (Read-TestToml 'unicode.toml')
    }
    It 'returns LF for CRLF line endings in multi-line strings and trims the first newline' {
        $r = ConvertFrom-TestToml ("a = `"`"`"`r`none`r`ntwo`"`"`"`r`nb = '''`r`nx`r`n'''`r`n")
        Assert-Equal "one`ntwo" $r['a']
        Assert-Equal "x`n" $r['b']
    }
    It 'removes a line-ending backslash with the spaces before the newline (CRLF too)' {
        $r = ConvertFrom-TestToml ("a = `"`"`"one \  `t`r`n   `r`n  two`"`"`"")
        Assert-Equal 'one two' $r['a']
    }
    It 'keeps comment markers and a # inside strings' {
        $r = ConvertFrom-TestToml "a = `"x # y`" # comment`nb = 'z # w'"
        Assert-Equal 'x # y' $r['a']
        Assert-Equal 'z # w' $r['b']
    }
    It 'accepts non-ASCII characters such as U+2028 in strings and comments' {
        $ls = $ctl['lineSeparator']
        $r = ConvertFrom-TestToml ("a = `"x" + $ls + "y`" # z" + $ls)
        Assert-Equal ('x' + $ls + 'y') $r['a']
    }
}

Describe 'ConvertFrom-AwToml: integers, floats and booleans' {
    It 'parses decimal integers as [long]' {
        $r = ConvertFrom-TestToml (Join-TestLines @('int1 = +99', 'int2 = 42', 'int3 = 0', 'int4 = -17', 'int5 = 1_000',
            'int6 = 5_349_221', 'int7 = 53_49_221', 'int8 = 1_2_3_4_5', 'zp = +0', 'zm = -0'))
        $expected = @{ int1 = 99; int2 = 42; int3 = 0; int4 = -17; int5 = 1000; int6 = 5349221; int7 = 5349221; int8 = 12345; zp = 0; zm = 0 }
        Assert-Equal $expected $r
        foreach ($k in $r.Keys) { Assert-True ($r[$k] -is [long]) "$k is $($r[$k].GetType().Name)" }
    }
    It 'parses hexadecimal, octal and binary integers' {
        $r = ConvertFrom-TestToml (Join-TestLines @('hex1 = 0xDEADBEEF', 'hex2 = 0xdeadbeef', 'hex3 = 0xdead_beef', 'hex4 = 0x00ff',
            'oct1 = 0o01234567', 'oct2 = 0o755', 'bin1 = 0b11010110', 'zero = 0x0'))
        Assert-Equal 3735928559 $r['hex1']
        Assert-Equal 3735928559 $r['hex2']
        Assert-Equal 3735928559 $r['hex3']
        Assert-Equal 255 $r['hex4']
        Assert-Equal 342391 $r['oct1']
        Assert-Equal 493 $r['oct2']
        Assert-Equal 214 $r['bin1']
        Assert-Equal 0 $r['zero']
        foreach ($k in $r.Keys) { Assert-True ($r[$k] -is [long]) "$k is $($r[$k].GetType().Name)" }
    }
    It 'accepts the whole signed 64-bit range in every base' {
        $r = ConvertFrom-TestToml (Join-TestLines @('max = 9223372036854775807', 'min = -9223372036854775808',
            'hex = 0x7FFFFFFFFFFFFFFF', 'oct = 0o777777777777777777777', ('bin = 0b' + ('1' * 63))))
        Assert-Equal ([long]::MaxValue) $r['max']
        Assert-Equal ([long]::MinValue) $r['min']
        Assert-Equal ([long]::MaxValue) $r['hex']
        Assert-Equal ([long]::MaxValue) $r['oct']
        Assert-Equal ([long]::MaxValue) $r['bin']
    }
    It 'parses floats as [double]' {
        $r = ConvertFrom-TestToml (Join-TestLines @('flt1 = +1.0', 'flt2 = 3.1415', 'flt3 = -0.01', 'flt4 = 5e+22', 'flt5 = 1e06',
            'flt6 = -2E-2', 'flt7 = 6.626e-34', 'flt8 = 224_617.445_991_228', 'flt9 = 1e1_0', 'flt10 = 0.1'))
        foreach ($k in $r.Keys) { Assert-True ($r[$k] -is [double]) "$k is $($r[$k].GetType().Name)" }
        Assert-True ($r['flt1'] -eq 1.0)
        Assert-True ($r['flt2'] -eq 3.1415)
        Assert-True ($r['flt3'] -eq -0.01)
        Assert-True ($r['flt4'] -eq 5e22)
        Assert-True ($r['flt5'] -eq 1e6)
        Assert-True ($r['flt6'] -eq -0.02)
        Assert-True ($r['flt7'] -eq 6.626e-34)
        Assert-True ($r['flt8'] -eq 224617.445991228)
        Assert-True ($r['flt9'] -eq 1e10)
        Assert-True ($r['flt10'] -eq 0.1)
    }
    It 'parses signed zeros, infinities and NaN' {
        $r = ConvertFrom-TestToml (Join-TestLines @('nz = -0.0', 'pz = +0.0', 'sf1 = inf', 'sf2 = +inf', 'sf3 = -inf', 'sf4 = nan', 'sf5 = +nan', 'sf6 = -nan'))
        Assert-True ((1 / $r['nz']) -eq [double]::NegativeInfinity) '-0.0 keeps its sign'
        Assert-True ((1 / $r['pz']) -eq [double]::PositiveInfinity)
        Assert-True ([double]::IsPositiveInfinity($r['sf1']))
        Assert-True ([double]::IsPositiveInfinity($r['sf2']))
        Assert-True ([double]::IsNegativeInfinity($r['sf3']))
        foreach ($k in 'sf4', 'sf5', 'sf6') { Assert-True ($r[$k] -is [double] -and [double]::IsNaN($r[$k])) $k }
    }
    It 'parses booleans as [bool]' {
        $r = ConvertFrom-TestToml "t = true`nf = false"
        Assert-True ($r['t'] -is [bool] -and $r['t'])
        Assert-True ($r['f'] -is [bool] -and -not $r['f'])
    }
}

Describe 'ConvertFrom-AwToml: dates and times' {
    $dates = @(
        @('odt1', '1979-05-27T07:32:00Z'), @('odt2', '1979-05-27T00:32:00-07:00'), @('odt3', '1979-05-27T00:32:00.999999-07:00'),
        @('odt4', '1979-05-27 07:32:00Z'), @('ldt1', '1979-05-27T07:32:00'), @('ldt2', '1979-05-27T00:32:00.999999'),
        @('ld1', '1979-05-27'), @('lt1', '07:32:00'), @('lt2', '00:32:00.999999'), @('lower', '1979-05-27t07:32:00z'),
        @('spaced', '1979-05-27 07:32:00'), @('leap', '2024-02-29'), @('leap400', '2000-02-29'),
        @('leapsecond', '1990-12-31T23:59:60Z'), @('yearzero', '0000-01-01'), @('nanos', '07:32:00.123456789123')
    )
    It 'keeps offset and local date-times, dates and times as their original text' {
        $r = ConvertFrom-TestToml (Join-TestLines @($dates | ForEach-Object { $_[0] + ' = ' + $_[1] }))
        Assert-Equal $dates.Count $r.Count
        foreach ($d in $dates) {
            Assert-Equal $d[1] $r[$d[0]] $d[0]
            Assert-True ($r[$d[0]] -is [string]) "$($d[0]) is a string, never a [datetime]"
        }
    }
    It 'reads dates and date-times in arrays, inline tables and before comments' {
        $r = ConvertFrom-TestToml (Join-TestLines @('a = [1979-05-27, 1979-05-27 07:32:00Z, 07:32:00]', 'b = { d = 1979-05-27 07:32:00 }',
            'c = 1979-05-27 # a date, then a comment', 'e = 1979-05-27 07:32:00 # a date-time'))
        Assert-Equal @('1979-05-27', '1979-05-27 07:32:00Z', '07:32:00') $r['a']
        Assert-Equal '1979-05-27 07:32:00' $r['b']['d']
        Assert-Equal '1979-05-27' $r['c']
        Assert-Equal '1979-05-27 07:32:00' $r['e']
    }
}

Describe 'ConvertFrom-AwToml: arrays' {
    It 'parses the arrays of the specification' {
        $r = ConvertFrom-TestToml (Join-TestLines @(
            'integers = [ 1, 2, 3 ]',
            'colors = [ "red", "yellow", "green" ]',
            'nested_arrays_of_ints = [ [ 1, 2 ], [3, 4, 5] ]',
            'nested_mixed_array = [ [ 1, 2 ], ["a", "b", "c"] ]',
            'string_array = [ "all", ''strings'', """are the same""", ''''''type'''''' ]',
            'numbers = [ 0.1, 0.2, 0.5, 1, 2, 5 ]',
            'contributors = [',
            '  "Example Contributor <contributor@example.invalid>",',
            '  { name = "Second Contributor", email = "second@example.invalid", url = "https://example.invalid/second" }',
            ']'))
        Assert-Equal @(1, 2, 3) $r['integers']
        Assert-Equal @('red', 'yellow', 'green') $r['colors']
        Assert-Equal @(3, 4, 5) $r['nested_arrays_of_ints'][1]
        Assert-Equal @('a', 'b', 'c') $r['nested_mixed_array'][1]
        Assert-Equal @('all', 'strings', 'are the same', 'type') $r['string_array']
        Assert-True ($r['numbers'][0] -is [double] -and $r['numbers'][3] -is [long]) 'mixed types are allowed'
        Assert-Equal 'Second Contributor' $r['contributors'][1]['name']
        Assert-True ($r['contributors'][1] -is [hashtable])
    }
    It 'accepts newlines, comments and a trailing comma anywhere between elements' {
        $r = ConvertFrom-TestToml (Join-TestLines @(
            'integers2 = [', '  1, 2, 3', ']',
            'integers3 = [', '  1,', '  2, # this is ok', ']',
            'commented = [ # after the bracket', '  # a full line', '  1 # after a value', '  , # before a comma', '  2', '  # before the bracket', ']',
            'nested = [[1,', '2,],[],]'))
        Assert-Equal @(1, 2, 3) $r['integers2']
        Assert-Equal @(1, 2) $r['integers3']
        Assert-Equal @(1, 2) $r['commented']
        Assert-Equal 2 $r['nested'].Count
        Assert-Equal @(1, 2) $r['nested'][0]
    }
    It 'keeps empty and one-element arrays as object[]' {
        $r = ConvertFrom-TestToml "single = [ 42 ]`nempty = [ ]`nnested = [ [], [[]] ]`nlast = [`n]"
        Assert-True ($r['single'] -is [object[]]); Assert-Equal 1 $r['single'].Count; Assert-Equal 42 $r['single'][0]
        Assert-True ($r['empty'] -is [object[]]); Assert-Equal 0 $r['empty'].Count
        Assert-True ($r['nested'][1][0] -is [object[]]); Assert-Equal 0 $r['nested'][1][0].Count
        Assert-Equal 0 $r['last'].Count
    }
    It 'parses CRLF line endings inside arrays' {
        $r = ConvertFrom-TestToml "a = [`r`n  1, # one`r`n  2,`r`n]`r`n"
        Assert-Equal @(1, 2) $r['a']
    }
}

Describe 'ConvertFrom-AwToml: tables, inline tables and arrays of tables' {
    It 'parses them like the specification' {
        Assert-Equal (Read-TestJson 'tables.json') (Read-TestToml 'tables.toml')
    }
    It 'returns arrays of tables as object[] of hashtables, in document order' {
        $r = Read-TestToml 'tables.toml'
        Assert-True ($r['products'] -is [object[]])
        Assert-Equal 3 $r['products'].Count
        Assert-True ($r['products'][1] -is [hashtable]); Assert-Equal 0 $r['products'][1].Count
        Assert-True ($r['fruits'][0]['varieties'] -is [object[]])
        Assert-Equal 'granny smith' $r['fruits'][0]['varieties'][1]['name']
        Assert-Equal 'plantain' $r['fruits'][1]['varieties'][0]['name']
    }
    It 'builds tables from dotted keys inside inline tables' {
        $r = ConvertFrom-TestToml 'a = { b.c = 1, b.d = 2, e = { f = [ { g = 1 } ] } }'
        Assert-Equal @{ c = 1; d = 2 } $r['a']['b']
        Assert-Equal 1 $r['a']['e']['f'][0]['g']
    }
    It 'lets dotted keys extend a table that a header created implicitly' {
        $r = ConvertFrom-TestToml "[a.b.c]`nz = 9`n[a]`nb.d = 1"
        Assert-Equal 9 $r['a']['b']['c']['z']
        Assert-Equal 1 $r['a']['b']['d']
    }
    It 'adds a table to the last element of an array of tables' {
        $r = ConvertFrom-TestToml "[[a]]`nx = 1`n[[a]]`nx = 2`n[a.b]`ny = 3"
        Assert-False $r['a'][0].ContainsKey('b')
        Assert-Equal 3 $r['a'][1]['b']['y']
    }
}

Describe 'ConvertFrom-AwToml: documents, comments and line endings' {
    It 'returns an empty table for an empty document or comments only' {
        $e = ConvertFrom-TestToml ''
        Assert-True ($e -is [hashtable]); Assert-Equal 0 $e.Count
        Assert-Equal 0 (ConvertFrom-TestToml $null).Count
        Assert-Equal 0 (ConvertFrom-TestToml "# only`n`n  # comments`t`n").Count
    }
    It 'skips a leading BOM' {
        $r = ConvertFrom-TestToml ((& $aw { [string]$script:AwBom }) + 'a = 1')
        Assert-Equal 1 $r['a']
    }
    It 'parses CRLF documents, indentation and a missing final newline' {
        $r = ConvertFrom-TestToml "  a = 1 # c`r`n`t[t]`r`n`tb = `"x`"`r`n[u]`r`nc = true"
        Assert-Equal 1 $r['a']
        Assert-Equal 'x' $r['t']['b']
        Assert-Equal $true $r['u']['c']
    }
    It 'accepts tabs in comments' {
        Assert-Equal 1 (ConvertFrom-TestToml "#`tcomment`ta = 2`na = 1")['a']
    }
}

# Invalid documents; the bounded-window tests below parse them again at small window sizes.
$invalidCases = @(
    @{ Name = 'duplicate key';                      Text = "a = 1`na = 2";                                   Pattern = "Duplicate key 'a'" }
    @{ Name = 'same bare and quoted key (spec)';    Text = "spelling = `"a`"`n`"spelling`" = `"b`"";         Pattern = "Duplicate key 'spelling'" }
    @{ Name = 'duplicate key in a table';           Text = "[t]`na = 1`na = 2";                              Pattern = "Duplicate key 'a' in table \[t\]" }
    @{ Name = 'duplicate dotted key';               Text = "a.b = 1`na.b = 2";                               Pattern = "Duplicate key 'a\.b'" }
    @{ Name = 'duplicate key in an inline table';   Text = 'a = { b = 1, b = 2 }';                           Pattern = "Duplicate key 'b' in an inline table" }
    @{ Name = 'table defined twice';                Text = "[fruit]`napple = 1`n[fruit]`norange = 2";        Pattern = 'Table \[fruit\] is defined more than once' }
    @{ Name = 'table after dotted keys (spec)';     Text = "[fruit]`napple.color = `"red`"`n[fruit.apple]";  Pattern = 'Table \[fruit\.apple\] is already defined with dotted keys' }
    @{ Name = 'super-table after dotted keys';      Text = "a.b = 1`n[a]";                                   Pattern = 'Table \[a\] is already defined with dotted keys' }
    @{ Name = 'dotted keys into a header table';    Text = "[a.b.c]`nz = 9`n[a]`nb.c.t = 1";                 Pattern = "Cannot add keys to 'b\.c' with dotted keys" }
    @{ Name = 'table over a value';                 Text = "a = 1`n[a]";                                     Pattern = 'Cannot define table \[a\]: the key already holds a value' }
    @{ Name = 'header through a value';             Text = "a = 1`n[a.b]";                                   Pattern = "Cannot use 'a' as a table" }
    @{ Name = 'dotted key through a value (spec)';  Text = "fruit.apple = 1`nfruit.apple.smooth = true";     Pattern = "Cannot use 'fruit\.apple' as a table" }
    @{ Name = 'dotted key into an inline table (spec)'; Text = "[product]`ntype = { name = `"Nail`" }`ntype.edible = false"; Pattern = 'an inline table cannot be extended' }
    @{ Name = 'header into an inline table';        Text = "a = {}`n[a.b]";                                  Pattern = "Cannot extend 'a': an inline table" }
    @{ Name = 'header over an inline table';        Text = "a = { b = 1 }`n[a]";                             Pattern = 'already defined as an inline table' }
    @{ Name = 'inline table over dotted keys (spec)'; Text = "[product]`ntype.name = `"Nail`"`ntype = { edible = false }"; Pattern = "Duplicate key 'type'" }
    @{ Name = 'dotted key into a nested inline table'; Text = 'a = { b = { c = 1 }, b.d = 2 }';             Pattern = 'an inline table cannot be extended' }
    @{ Name = 'array of tables over a static array (spec)'; Text = "fruits = []`n[[fruits]]";                Pattern = 'static array' }
    @{ Name = 'array of tables over a table';       Text = "[a]`n[[a]]";                                     Pattern = "'a' is already a table" }
    @{ Name = 'table over an array of tables';      Text = "[[a]]`n[a]";                                     Pattern = 'already defined as an array of tables' }
    @{ Name = 'sub-table before its array (spec)';  Text = "[fruit.physical]`ncolor = `"red`"`n[[fruit]]";   Pattern = "'fruit' is already a table" }
    @{ Name = 'dotted keys into an array of tables'; Text = "[[a.b]]`n[a]`nb.c = 1";                         Pattern = 'it is an array of tables' }
    @{ Name = 'trailing comma in an inline table';  Text = 'a = { b = 1, }';                                 Pattern = 'trailing comma' }
    @{ Name = 'newline inside an inline table';     Text = "a = { b = 1,`nc = 2 }";                          Pattern = 'stay on one line' }
    @{ Name = 'newline after an opening brace';     Text = "a = {`n}";                                       Pattern = 'stay on one line' }
    @{ Name = 'newline before a closing brace';     Text = "a = { b = 1`n}";                                 Pattern = 'stay on one line' }
    @{ Name = 'comment inside an inline table';     Text = 'a = { b = 1 # c }';                              Pattern = 'stay on one line' }
    @{ Name = 'missing comma in an inline table';   Text = 'a = { b = 1 c = 2 }';                            Pattern = "Expected ',' or '\}' in an inline table" }
    @{ Name = 'unclosed inline table';              Text = 'a = { b = 1';                                    Pattern = 'end of the document' }
    @{ Name = 'missing comma in an array';          Text = 'a = [1 2]';                                      Pattern = "Expected ',' or '\]' after an array element" }
    @{ Name = 'leading comma in an array';          Text = 'a = [,1]';                                       Pattern = 'Expected a value' }
    @{ Name = 'double comma in an array';           Text = 'a = [1,,2]';                                     Pattern = 'Expected a value' }
    @{ Name = 'unclosed array';                     Text = 'a = [1, 2';                                      Pattern = 'end of the document' }
    @{ Name = 'unterminated basic string';          Text = 'a = "abc';                                       Pattern = 'Unterminated string' }
    @{ Name = 'basic string cut by a newline';      Text = "a = `"abc`nb = 1";                               Pattern = 'Unterminated string' }
    @{ Name = 'unterminated literal string';        Text = "a = 'abc";                                       Pattern = 'Unterminated string' }
    @{ Name = 'unterminated multi-line string';     Text = "a = `"`"`"abc`nb = 1";                           Pattern = 'Unterminated multi-line string' }
    @{ Name = 'unterminated multi-line literal';    Text = "a = '''abc`nb = 1";                              Pattern = 'Unterminated multi-line string' }
    @{ Name = 'backslash before the end of the input'; Text = 'a = """abc\';                                 Pattern = 'Unterminated multi-line string' }
    @{ Name = 'six closing quotes';                 Text = 'a = """x""""""';                                 Pattern = 'Expected the end of the line' }
    @{ Name = 'invalid escape';                     Text = 'a = "\x41"';                                     Pattern = "Invalid escape sequence '\\x'" }
    @{ Name = 'escaped space';                      Text = 'a = "a\ b"';                                     Pattern = 'backslash followed by U\+0020' }
    @{ Name = 'escaped space in a multi-line string'; Text = 'a = """a\ b"""';                               Pattern = 'backslash followed by U\+0020' }
    @{ Name = 'escape in a quoted key';             Text = '"a\qb" = 1';                                     Pattern = "Invalid escape sequence '\\q'" }
    @{ Name = 'short \u escape';                    Text = 'a = "\u12"';                                     Pattern = 'must be followed by 4 hexadecimal digits' }
    @{ Name = 'short \U escape';                    Text = 'a = "\U0001F60"';                                Pattern = 'must be followed by 8 hexadecimal digits' }
    @{ Name = 'surrogate \u escape';                Text = 'a = "\uD800"';                                   Pattern = 'not a Unicode scalar value' }
    @{ Name = '\U escape above U+10FFFF';           Text = 'a = "\U00110000"';                               Pattern = 'not a Unicode scalar value' }
    @{ Name = '\U escape with the sign bit';        Text = 'a = "\UFFFFFFFF"';                               Pattern = 'not a Unicode scalar value' }
    @{ Name = 'multi-line string as a key';         Text = '"""a""" = 1';                                    Pattern = 'cannot be used as a key' }
    @{ Name = 'multi-line literal as a key';        Text = "'''a''' = 1";                                    Pattern = 'cannot be used as a key' }
    @{ Name = 'missing value';                      Text = 'a = ';                                           Pattern = 'Expected a value, found the end of the document' }
    @{ Name = 'missing value before a comment (spec)'; Text = 'key = # INVALID';                             Pattern = 'Expected a value, found a comment' }
    @{ Name = 'value on the next line (spec)';      Text = "key =`n`"value`"";                               Pattern = 'Expected a value, found the end of the line' }
    @{ Name = 'missing equals sign';                Text = 'a 1';                                            Pattern = "Expected '=' after the key 'a'" }
    @{ Name = 'key without a value';                Text = "a`nb = 1";                                       Pattern = "Expected '=' after the key 'a', found the end of the line" }
    @{ Name = 'two pairs on one line (spec)';       Text = 'first = "Ada" last = "Example"';                 Pattern = 'Expected the end of the line' }
    @{ Name = 'text after a header';                Text = '[a] b = 1';                                      Pattern = 'Expected the end of the line' }
    @{ Name = 'empty bare key (spec)';              Text = '= "no key name"';                                Pattern = 'Expected a key' }
    @{ Name = 'empty dotted part';                  Text = 'a..b = 1';                                       Pattern = 'Expected a key' }
    @{ Name = 'leading dot';                        Text = '.a = 1';                                         Pattern = 'Expected a key' }
    @{ Name = 'trailing dot';                       Text = 'a. = 1';                                         Pattern = 'Expected a key' }
    @{ Name = 'empty header';                       Text = '[]';                                             Pattern = 'Expected a key' }
    @{ Name = 'unclosed header';                    Text = '[a';                                             Pattern = "Expected '\]' to close the table header" }
    @{ Name = 'unclosed array of tables header';    Text = '[[a]';                                           Pattern = "Expected '\]\]'" }
    @{ Name = 'space between closing brackets';     Text = '[[a] ]';                                         Pattern = "Expected '\]\]'" }
    @{ Name = 'space between opening brackets';     Text = '[ [a] ]';                                        Pattern = 'Expected a key' }
    @{ Name = 'non-ASCII bare key';                 Text = ($ctl['eAcute'] + ' = 1');                        Pattern = 'Expected a key' }
    @{ Name = 'capitalized boolean';                Text = 'a = True';                                       Pattern = 'Invalid value' }
    @{ Name = 'unquoted string';                    Text = 'a = abc';                                        Pattern = 'Invalid value' }
    @{ Name = 'leading zero';                       Text = 'a = 01';                                         Pattern = 'Invalid value' }
    @{ Name = 'double underscore';                  Text = 'a = 1__2';                                       Pattern = 'Invalid value' }
    @{ Name = 'leading underscore';                 Text = 'a = _1';                                         Pattern = 'Invalid value' }
    @{ Name = 'trailing underscore';                Text = 'a = 1_';                                         Pattern = 'Invalid value' }
    @{ Name = 'signed hexadecimal';                 Text = 'a = +0x1';                                       Pattern = 'Invalid value' }
    @{ Name = 'uppercase prefix';                   Text = 'a = 0X1F';                                       Pattern = 'Invalid value' }
    @{ Name = 'underscore after a prefix';          Text = 'a = 0x_1';                                       Pattern = 'Invalid value' }
    @{ Name = 'octal digit 8';                      Text = 'a = 0o8';                                        Pattern = 'Invalid value' }
    @{ Name = 'binary digit 2';                     Text = 'a = 0b2';                                        Pattern = 'Invalid value' }
    @{ Name = 'float without an integer part (spec)'; Text = 'a = .7';                                       Pattern = 'Invalid value' }
    @{ Name = 'float without a fraction (spec)';    Text = 'a = 7.';                                         Pattern = 'Invalid value' }
    @{ Name = 'float with an empty fraction (spec)'; Text = 'a = 3.e+20';                                    Pattern = 'Invalid value' }
    @{ Name = 'float with an empty exponent';       Text = 'a = 1e';                                         Pattern = 'Invalid value' }
    @{ Name = 'float with a leading zero';          Text = 'a = 03.14';                                      Pattern = 'Invalid value' }
    @{ Name = 'capitalized infinity';               Text = 'a = Inf';                                        Pattern = 'Invalid value' }
    @{ Name = 'capitalized NaN';                    Text = 'a = NaN';                                        Pattern = 'Invalid value' }
    @{ Name = 'integer above the 64-bit range';     Text = 'a = 9223372036854775808';                        Pattern = 'Integer out of range' }
    @{ Name = 'integer below the 64-bit range';     Text = 'a = -9223372036854775809';                       Pattern = 'Integer out of range' }
    @{ Name = 'hexadecimal above the range';        Text = 'a = 0x8000000000000000';                         Pattern = 'Integer out of range' }
    @{ Name = 'octal above the range';              Text = 'a = 0o1000000000000000000000';                   Pattern = 'Integer out of range' }
    @{ Name = 'binary above the range';             Text = ('a = 0b1' + ('0' * 63));                         Pattern = 'Integer out of range' }
    @{ Name = 'float out of range';                 Text = 'a = 1e400';                                      Pattern = 'Float out of range' }
    @{ Name = 'month 13';                           Text = 'a = 1979-13-01';                                 Pattern = 'Invalid date or time' }
    @{ Name = 'February 30';                        Text = 'a = 1979-02-30';                                 Pattern = 'Invalid date or time' }
    @{ Name = 'February 29 of a common year';       Text = 'a = 2023-02-29';                                 Pattern = 'Invalid date or time' }
    @{ Name = 'February 29 of 1900';                Text = 'a = 1900-02-29';                                 Pattern = 'Invalid date or time' }
    @{ Name = 'day 31 of April';                    Text = 'a = 1979-04-31';                                 Pattern = 'Invalid date or time' }
    @{ Name = 'hour 24';                            Text = 'a = 1979-05-27T24:00:00';                        Pattern = 'Invalid date or time' }
    @{ Name = 'minute 60';                          Text = 'a = 07:60:00';                                   Pattern = 'Invalid date or time' }
    @{ Name = 'second 61';                          Text = 'a = 07:32:61';                                   Pattern = 'Invalid date or time' }
    @{ Name = 'time without seconds';               Text = 'a = 07:32';                                      Pattern = 'Invalid date or time' }
    @{ Name = 'offset hour 24';                     Text = 'a = 1979-05-27T07:32:00+24:00';                  Pattern = 'Invalid date or time' }
    @{ Name = 'one-digit month';                    Text = 'a = 1979-5-27';                                  Pattern = 'Invalid date or time' }
    @{ Name = 'offset on a local time';             Text = 'a = 07:32:00Z';                                  Pattern = 'Invalid date or time' }
    @{ Name = 'empty fraction of a second';         Text = 'a = 07:32:00.';                                  Pattern = 'Invalid date or time' }
    @{ Name = 'date followed by a number';          Text = 'a = 1979-05-27 123';                             Pattern = 'Invalid date or time' }
    @{ Name = 'bare carriage return';               Text = "a = 1`rb = 2";                                   Pattern = 'carriage return without a line feed' }
    @{ Name = 'carriage return at the end';         Text = "a = 1`r";                                        Pattern = 'Carriage return without a line feed' }
    @{ Name = 'carriage return in a multi-line string'; Text = "a = `"`"`"x`ry`"`"`"";                       Pattern = 'Carriage return without a line feed in a multi-line string' }
    @{ Name = 'carriage return in a comment';       Text = "# x`ry`na = 1";                                  Pattern = 'carriage return' }
    @{ Name = 'control character in a basic string'; Text = ('a = "x' + $ctl['bell'] + 'y"');                Pattern = 'control character U\+0007' }
    @{ Name = 'DEL in a basic string';              Text = ('a = "x' + $ctl['del'] + 'y"');                  Pattern = 'control character U\+007F' }
    @{ Name = 'NUL in a literal string';            Text = ("a = 'x" + $ctl['nul'] + "y'");                  Pattern = 'control character U\+0000' }
    @{ Name = 'ESC in a multi-line string';         Text = ('a = """x' + $ctl['esc'] + 'y"""');              Pattern = 'control character U\+001B' }
    @{ Name = 'DEL in a multi-line literal';        Text = ("a = '''x" + $ctl['del'] + "y'''");              Pattern = 'control character U\+007F' }
    @{ Name = 'control character after a backslash'; Text = ('a = "x\' + $ctl['bell'] + '"');                Pattern = 'control character U\+0007' }
    @{ Name = 'control character in a comment';     Text = ('# x' + $ctl['bell'] + 'y');                     Pattern = 'control character U\+0007' }
    @{ Name = 'DEL in a comment after a value';     Text = ('a = 1 # x' + $ctl['del']);                      Pattern = 'control character U\+007F' }
)

Describe 'ConvertFrom-AwToml: invalid documents' {
    foreach ($c in $invalidCases) {
        It "rejects: $($c.Name)" {
            $ex = Get-TestTomlError $c.Text
            Assert-Match $ex.Message $c.Pattern
            Assert-Match $ex.Message '^Invalid TOML at line \d+, column \d+: '
            Assert-True ($ex.Data['Line'] -is [int] -and $ex.Data['Line'] -ge 1) 'Data[Line]'
        }
    }

    It 'reports the line and column of the error' {
        $ex = Get-TestTomlError "a = 1`nb = 2`n`nc = = 3"
        Assert-Equal 4 $ex.Data['Line']
        Assert-Equal 5 $ex.Data['Column']
        Assert-Match $ex.Message 'line 4, column 5'
    }
    It 'counts lines the same way with CRLF line endings' {
        $ex = Get-TestTomlError "a = 1`r`nb = = 2"
        Assert-Equal 2 $ex.Data['Line']
        Assert-Equal 5 $ex.Data['Column']
    }
    It 'reports the line of a duplicate key and of a table defined twice' {
        Assert-Equal 3 (Get-TestTomlError "a = 1`n`na = 2").Data['Line']
        $ex = Get-TestTomlError "[a]`nx = 1`n[a]"
        Assert-Equal 3 $ex.Data['Line']
        Assert-Equal 1 $ex.Data['Column']
    }
    It 'reports where an unterminated string starts' {
        $ex = Get-TestTomlError "a = 1`nb = `"`"`"x`ny`nz"
        Assert-Equal 2 $ex.Data['Line']
        Assert-Equal 5 $ex.Data['Column']
    }
    It 'reports the exact place of an invalid escape, also inside a multi-line string' {
        $ex = Get-TestTomlError "a = 1`nb = `"ok \q`""
        Assert-Equal 2 $ex.Data['Line']
        Assert-Equal 9 $ex.Data['Column']
        $ex = Get-TestTomlError "a = `"`"`"`nok`nbad \q`n`"`"`""
        Assert-Equal 3 $ex.Data['Line']
        Assert-Equal 5 $ex.Data['Column']
    }
    It 'never echoes a long unquoted token in full (secret-safe messages)' {
        $ex = Get-TestTomlError 'token = ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234'
        Assert-NotMatch $ex.Message 'FAKEFAKEFAKEFAKE'
        Assert-Match $ex.Message 'ghp_'
    }
}

# Texts around the edges of tokens: date-time joins, spaced and invalid keys, comments where a
# value or the end of the line is expected, extra closing quotes, a BOM, and the strings and keys
# that a fast path hands over to the next reader. The bounded-window tests below parse them again
# at small window sizes.
$tokenCases = @(
    @{ Name = 'a tab between a date and a time';      Text = "a = 1979-05-27`t07:32:00";   Line = 1; Column = 16; Pattern = "Expected the end of the line, found '07:32:00'" }
    @{ Name = 'two spaces between a date and a time'; Text = 'a = 1979-05-27  07:32:00';   Line = 1; Column = 17; Pattern = "Expected the end of the line, found '07:32:00'" }
    @{ Name = 'a word after a date and a space';      Text = 'a = 1979-05-27 x';           Line = 1; Column = 16; Pattern = "Expected the end of the line, found 'x'" }
    @{ Name = 'spaces around a dot';                  Text = 'a . b = 1';                  Value = @{ a = @{ b = 1 } } }
    @{ Name = 'a space before a dot';                 Text = 'a .b = 1';                   Value = @{ a = @{ b = 1 } } }
    @{ Name = 'a space after a dot';                  Text = 'a. b = 1';                   Value = @{ a = @{ b = 1 } } }
    @{ Name = 'quoted parts around a spaced dot';     Text = "`"a`" . 'b' = 1";            Value = @{ a = @{ b = 1 } } }
    @{ Name = 'a spaced dotted header';               Text = '[ a . "b" ]';                Value = @{ a = @{ b = @{} } } }
    @{ Name = 'a plus sign in a key';                 Text = 'a+b = 1';                    Line = 1; Column = 2;  Pattern = "Expected '=' after the key 'a', found '\+b'" }
    @{ Name = 'a colon in a key';                     Text = 'a:b = 1';                    Line = 1; Column = 2;  Pattern = "Expected '=' after the key 'a', found ':b'" }
    @{ Name = 'a plus sign in a header';              Text = '[a+b]';                      Line = 1; Column = 3;  Pattern = "Expected '\]' to close the table header, found '\+b'" }
    @{ Name = 'a plus sign in an inline table key';   Text = 't = { a+b = 1 }';            Line = 1; Column = 8;  Pattern = "Expected '=' after the key 'a', found '\+b'" }
    @{ Name = 'a comment instead of a value';         Text = 'a =   # c';                  Line = 1; Column = 7;  Pattern = 'Expected a value, found a comment' }
    @{ Name = 'a comment inside an inline table';     Text = 'a = { b = 1   # c }';        Line = 1; Column = 15; Pattern = "Expected ',' or '\}': an inline table must stay on one line, found a comment" }
    @{ Name = 'a carriage return after a comment';    Text = "a = 1 # c`rx";               Line = 1; Column = 10; Pattern = 'Expected the end of the line, found a carriage return without a line feed' }
    @{ Name = 'a word after a string';                Text = 'a = "x" b';                  Line = 1; Column = 9;  Pattern = "Expected the end of the line, found 'b'" }
    @{ Name = 'four closing quotes';                  Text = 'a = """x""""';               Value = @{ a = 'x"' } }
    @{ Name = 'five closing quotes';                  Text = 'a = """x"""""';              Value = @{ a = 'x""' } }
    @{ Name = 'four closing apostrophes';             Text = "a = '''x''''";               Value = @{ a = "x'" } }
    @{ Name = 'five closing apostrophes';             Text = "a = '''x'''''";              Value = @{ a = "x''" } }
    @{ Name = 'a BOM before the first key';           Text = ((& $aw { [string]$script:AwBom }) + 'a = 1'); Value = @{ a = 1 } }
    @{ Name = 'an escaped string value';              Text = 'a = "x\ty"';                 Value = @{ a = "x`ty" } }
    @{ Name = 'an escaped string in an array';        Text = 'a = [ "x\ty", "z" ]';        Value = @{ a = @("x`ty", 'z') } }
    @{ Name = 'an escaped string in an inline table'; Text = 'a = { b = "x\ty" }';         Value = @{ a = @{ b = "x`ty" } } }
    @{ Name = 'an invalid escape in a value';         Text = 'a = "x\qy"';                 Line = 1; Column = 7;  Pattern = "Invalid escape sequence '\\q'" }
    @{ Name = 'a control character in a value';       Text = ('a = "x' + $ctl['bell'] + 'y"'); Line = 1; Column = 7; Pattern = 'Invalid character in a string: the control character U\+0007' }
    @{ Name = 'an unterminated escaped string';       Text = 'a = "x\ty';                  Line = 1; Column = 5;  Pattern = 'Unterminated string' }
    @{ Name = 'spaces before a dot in a key';         Text = 'a   .b = 1';                 Value = @{ a = @{ b = 1 } } }
    @{ Name = 'spaces before a dot in a header';      Text = '[a   .b]';                   Value = @{ a = @{ b = @{} } } }
    @{ Name = 'spaces before a dot in an inline key'; Text = 't = { a   .b = 1 }';         Value = @{ t = @{ a = @{ b = 1 } } } }
    @{ Name = 'spaces before a quoted part';          Text = 'a   ."b" = 1';               Value = @{ a = @{ b = 1 } } }
    @{ Name = 'spaces before a plus sign in a key';   Text = 'a   +b = 1';                 Line = 1; Column = 5;  Pattern = "Expected '=' after the key 'a', found '\+b'" }
)

Describe 'ConvertFrom-AwToml: results around the edges of tokens' {
    foreach ($c in $tokenCases) {
        It "reads $($c.Name) exactly" {
            if ($c.ContainsKey('Value')) {
                Assert-Equal $c.Value (ConvertFrom-TestToml $c.Text)
            } else {
                $ex = Get-TestTomlError $c.Text
                Assert-Equal $c.Line $ex.Data['Line'] 'line'
                Assert-Equal $c.Column $ex.Data['Column'] 'column'
                Assert-Match $ex.Message $c.Pattern
            }
        }
    }
}

Describe 'ConvertFrom-AwToml: depth and size limits' {
    It 'accepts 64 nested arrays and rejects 65' {
        $r = ConvertFrom-TestToml ('a = ' + ('[' * 64) + (']' * 64))
        Assert-True ($r['a'] -is [object[]])
        Assert-Match (Get-TestTomlError ('a = ' + ('[' * 65) + (']' * 65))).Message 'Maximum nesting depth of 64'
    }
    It 'accepts 64 nested inline tables and rejects 65' {
        $ok = 'a = ' + ('{ b = ' * 63) + '{}' + (' }' * 63)
        Assert-True ((ConvertFrom-TestToml $ok)['a'] -is [hashtable])
        $deep = 'a = ' + ('{ b = ' * 64) + '{}' + (' }' * 64)
        Assert-Match (Get-TestTomlError $deep).Message 'Maximum nesting depth of 64'
    }
    It 'counts header tables, dotted keys and values together' {
        $path = @(1..60 | ForEach-Object { "t$_" }) -join '.'
        $r = ConvertFrom-TestToml ("[$path]`na = [[[[1]]]]")
        Assert-True ($r.ContainsKey('t1'))
        Assert-Match (Get-TestTomlError ("[$path]`na = [[[[[1]]]]]")).Message 'Maximum nesting depth of 64'
        $t = ConvertFrom-TestToml ("[$path]`nb.c.d.e.f = 1`na = { b = { c = { d = {} } } }")
        foreach ($k in @(@(1..60 | ForEach-Object { "t$_" }) + @('b', 'c', 'd', 'e'))) { $t = $t[$k] }
        Assert-Equal 1 $t['f'] 'four dotted tables below 60 header tables'
        Assert-Match (Get-TestTomlError ("[$path]`nb.c.d.e.f.g = 1")).Message 'Maximum nesting depth of 64'
        Assert-Match (Get-TestTomlError ("[$path]`na = { b = { c = { d = { e = {} } } } }")).Message 'Maximum nesting depth of 64'
    }
    It 'accepts a 64-level header and rejects 65 levels' {
        $ok = '[' + (@(1..64 | ForEach-Object { "t$_" }) -join '.') + ']'
        Assert-True ((ConvertFrom-TestToml $ok).ContainsKey('t1'))
        $deep = '[' + (@(1..65 | ForEach-Object { "t$_" }) -join '.') + ']'
        Assert-Match (Get-TestTomlError $deep).Message 'Maximum nesting depth of 64'
    }
    It 'counts an array of tables as two levels' {
        $ok = '[[' + (@(1..63 | ForEach-Object { "t$_" }) -join '.') + ']]'
        Assert-True ((ConvertFrom-TestToml $ok).ContainsKey('t1'))
        $deep = '[[' + (@(1..64 | ForEach-Object { "t$_" }) -join '.') + ']]'
        Assert-Match (Get-TestTomlError $deep).Message 'Maximum nesting depth of 64'
    }
    It 'accepts a 65-part dotted key (64 tables) and rejects 66 parts' {
        $ok = (@(1..65 | ForEach-Object { "k$_" }) -join '.') + ' = 1'
        Assert-True ((ConvertFrom-TestToml $ok).ContainsKey('k1'))
        $deep = (@(1..66 | ForEach-Object { "k$_" }) -join '.') + ' = 1'
        Assert-Match (Get-TestTomlError $deep).Message 'Maximum nesting depth of 64'
    }
    It 'rejects a document larger than 2 MB before parsing it' {
        $ex = Get-TestTomlError ('a = "' + ('x' * $mb2) + '"')
        Assert-Match $ex.Message 'larger than the 2 MB limit'
        Assert-Equal $null $ex.Data['Line']
    }
    It 'parses a document of a few thousand keys and values' {
        $sb = New-Object System.Text.StringBuilder
        for ($i = 0; $i -lt 2000; $i++) { [void]$sb.Append("[t$i]`nname = `"item-$i`"`nvalue = $i`n") }
        $r = ConvertFrom-TestToml $sb.ToString()
        Assert-Equal 2000 $r.Count
        Assert-Equal 'item-1999' $r['t1999']['name']
    }
}

Describe 'ConvertFrom-AwToml: hostile input finishes in under 2 seconds' {
    $line = $mb2 - 64
    $hostile = @(
        @{ Name = '2 MB basic string';             Text = ('a = "' + ('x' * $line) + '"');                  Pattern = '' }
        @{ Name = '2 MB literal string';           Text = ("a = '" + ('x' * $line) + "'");                  Pattern = '' }
        @{ Name = '2 MB multi-line literal';       Text = ("a = '''" + ('x' * $line) + "'''");              Pattern = '' }
        @{ Name = '2 MB of escaped backslashes';   Text = ('a = "' + ('\\' * ($line / 2)) + '"');           Pattern = '' }
        @{ Name = '2 MB of line-ending backslashes'; Text = ('a = """' + (('\' + "`n") * ($line / 2)) + '"""'); Pattern = '' }
        @{ Name = '2 MB of quote pairs';           Text = ('a = """' + ('""x' * [int][Math]::Floor($line / 3)) + '"""'); Pattern = '' }
        @{ Name = '2 MB comment';                  Text = ('# ' + ('x' * $line));                           Pattern = '' }
        @{ Name = '2 MB bare key';                 Text = (('k' * $line) + ' = 1');                         Pattern = '' }
        @{ Name = '2 MB of whitespace';            Text = ((' ' * $line) + 'a = 1');                        Pattern = '' }
        @{ Name = '2 MB of newlines';              Text = (("`n" * $line) + 'a = 1');                       Pattern = '' }
        @{ Name = '2 MB of comment lines';         Text = (("#`n" * ($line / 2)) + 'a = 1');                Pattern = '' }
        @{ Name = '2 MB float';                    Text = ('a = 0.' + ('1' * $line));                       Pattern = '' }
        @{ Name = '2 MB integer';                  Text = ('a = ' + ('1' * $line));                         Pattern = 'Integer out of range' }
        @{ Name = '2 MB invalid token';            Text = ('a = ' + ('z' * $line));                         Pattern = 'Invalid value' }
        @{ Name = '2 MB date-like token';          Text = ('a = 1979-05-27T07:32:00.' + ('1' * $line));     Pattern = '' }
        @{ Name = 'unterminated basic string';     Text = ('a = "' + ('x' * $line));                        Pattern = 'Unterminated string' }
        @{ Name = 'unterminated literal string';   Text = ("a = '" + ('x' * $line));                        Pattern = 'Unterminated string' }
        @{ Name = 'unterminated multi-line string'; Text = ('a = """' + ("x`n" * ($line / 2)));             Pattern = 'Unterminated multi-line string' }
        @{ Name = 'unterminated multi-line literal'; Text = ("a = '''" + ("x`n" * ($line / 2)));            Pattern = 'Unterminated multi-line string' }
        @{ Name = 'unterminated string of escapes'; Text = ('a = "' + ('\"' * ($line / 2)));                Pattern = 'Unterminated string' }
        @{ Name = '10k nested arrays';             Text = ('a = ' + ('[' * 10000) + (']' * 10000));         Pattern = 'Maximum nesting depth' }
        @{ Name = '10k nested inline tables';      Text = ('a = ' + ('{b=' * 10000) + '1' + ('}' * 10000)); Pattern = 'Maximum nesting depth' }
        @{ Name = '10k-part dotted key';           Text = (('a.' * 10000) + 'a = 1');                       Pattern = 'Maximum nesting depth' }
        @{ Name = '10k-part header';               Text = ('[' + ('a.' * 10000) + 'a]');                    Pattern = 'Maximum nesting depth' }
        @{ Name = '1M array elements';             Text = ('a = [' + ('1,' * 1000000) + ']');               Pattern = 'too complex' }
        @{ Name = '1M empty arrays';               Text = ('a = [' + ('[],' * 600000) + ']');               Pattern = 'too complex' }
        @{ Name = '150k tables with a key each';   Text = ("[[a]]`nx = 1`n" * 150000);                      Pattern = 'too complex' }
        @{ Name = '300k headers';                  Text = (('[[a]]' + "`n") * 300000);                      Pattern = 'too complex' }
        @{ Name = '2 MB of \u escapes';            Text = ('a = "' + ('\u0041' * ($line / 6)) + '"');       Pattern = 'too complex' }
    )
    foreach ($h in $hostile) {
        It "$($h.Name)" {
            Assert-True ($h.Text.Length -le $mb2) 'the input stays within the size limit'
            $r = Measure-TestToml $h.Text
            Assert-True ($r.Seconds -lt 2) ("took {0:N2} s" -f $r.Seconds)
            if ($h.Pattern) { Assert-Match $r.Message $h.Pattern }
            else { Assert-True ($r.Message -eq '' -or $r.Message -match '^Invalid TOML') "unexpected failure: $($r.Message)" }
        }
    }
    It 'returns the 2 MB values in full' {
        $r = ConvertFrom-TestToml ('a = "' + ('x' * $line) + '"')
        Assert-Equal $line $r['a'].Length
        $r = ConvertFrom-TestToml ('a = "' + ('\\' * ($line / 2)) + '"')
        Assert-Equal ($line / 2) $r['a'].Length
        Assert-Equal 0 $r['a'].Replace('\', '').Length
    }
}

Describe 'ConvertFrom-AwToml: hostile input across window edges finishes in under 2 seconds' {
    It '19,000 keys with 90-character strings (valid, almost the whole step budget)' {
        $r = Measure-TestHostileToml (New-TestTomlKeys 19000 ('"' + ('x' * 90) + '"'))
        Assert-Equal '' $r.Message
        Assert-Equal 19000 $r.Value.Count
        Assert-Equal ('x' * 90) $r.Value['k18999']
    }
    It '20,001 keys with 90-character strings (too complex at the last key)' {
        $r = Measure-TestHostileToml (New-TestTomlKeys 20001 ('"' + ('x' * 90) + '"'))
        Assert-Match $r.Message '^Invalid TOML at line 20001, column 1: The document is too complex'
    }
    It '1,900 bare keys of 1,000 to 1,100 characters (each one crosses a window edge)' {
        $lines = foreach ($i in 0..1899) { ('k' * (1000 + $i % 101)) + $i + ' = ' + $i }
        $r = Measure-TestHostileToml ($lines -join "`n")
        Assert-Equal '' $r.Message
        Assert-Equal 1900 $r.Value.Count
        Assert-Equal 1899 $r.Value[('k' * 1081) + '1899']
    }
    It 'short keys after a 1.9 MB comment' {
        $r = Measure-TestHostileToml ('#' + ('x' * 1900000) + "`n" + (New-TestTomlKeys 10000 '1'))
        Assert-Equal '' $r.Message
        Assert-Equal 10000 $r.Value.Count
    }
    It '19,990 keys, then a 1.8 MB comment after the last value' {
        $r = Measure-TestHostileToml ((New-TestTomlKeys 19990 '1') + ' # ' + ('x' * 1800000))
        Assert-Equal '' $r.Message
        Assert-Equal 19990 $r.Value.Count
    }
    It '200k array lines with a comment each' {
        $r = Measure-TestHostileToml ('a = [' + "`n" + (('  1, # c' + "`n") * 200000) + ']')
        Assert-Match $r.Message 'too complex'
    }
    It 'an inline table of 60k keys' {
        $parts = foreach ($i in 0..59999) { 'k' + $i + ' = 1' }
        $r = Measure-TestHostileToml ('a = { ' + ($parts -join ', ') + ' }')
        Assert-Match $r.Message 'too complex'
    }
    It '100k keys with a comment each' {
        $r = Measure-TestHostileToml (New-TestTomlKeys 100000 '1 # c')
        Assert-Match $r.Message '^Invalid TOML at line 20001, column 1: The document is too complex'
    }
    It 'a CRLF document of 20k keys (valid, the whole step budget)' {
        $r = Measure-TestHostileToml (New-TestTomlKeys 20000 '1' "`r`n")
        Assert-Equal '' $r.Message
        Assert-Equal 20000 $r.Value.Count
    }
    It 'a key, 2 MB of spaces, then a dotted part' {
        $r = Measure-TestHostileToml ('a' + (' ' * ($mb2 - 64)) + '.b = 1')
        Assert-Equal '' $r.Message
        Assert-Equal 1 $r.Value['a']['b']
    }
    It '1,900 dotted keys with 1,050 spaces before each dot (the key reader takes the run the main loop matched)' {
        $lines = foreach ($i in 0..1899) { 'a' + (' ' * 1050) + '.b' + $i + ' = 1' }
        $r = Measure-TestHostileToml ($lines -join "`n")
        Assert-Equal '' $r.Message
        Assert-Equal 1900 $r.Value['a'].Count
    }
    It '1,000 dotted keys with 1,050 spaces before each dot and escaped 1,010-character strings' {
        $lines = foreach ($i in 0..999) { 'a' + (' ' * 1050) + '.b' + $i + ' = "' + ('x' * 1010) + '\n"' }
        $r = Measure-TestHostileToml ($lines -join "`n")
        Assert-Equal '' $r.Message
        Assert-Equal 1000 $r.Value['a'].Count
        Assert-Equal (('x' * 1010) + "`n") $r.Value['a']['b999']
    }
    It '2,040 keys with escaped 1,010-character strings (each string is matched once past a window edge, then handed over)' {
        $r = Measure-TestHostileToml (New-TestTomlKeys 2040 ('"' + ('x' * 1010) + '\n"'))
        Assert-Equal '' $r.Message
        Assert-Equal 2040 $r.Value.Count
        Assert-Equal (('x' * 1010) + "`n") $r.Value['k2039']
    }
    It '2,040 keys with escaped 1,010-character strings, the escape first' {
        $r = Measure-TestHostileToml (New-TestTomlKeys 2040 ('"\n' + ('x' * 1010) + '"'))
        Assert-Equal '' $r.Message
        Assert-Equal 2040 $r.Value.Count
        Assert-Equal ("`n" + ('x' * 1010)) $r.Value['k2039']
    }
    It '2,020 inline tables with an escaped 1,010-character string each' {
        $r = Measure-TestHostileToml (New-TestTomlKeys 2020 ('{ b = "' + ('x' * 1010) + '\n" }'))
        Assert-Equal '' $r.Message
        Assert-Equal 2020 $r.Value.Count
        Assert-Equal (('x' * 1010) + "`n") $r.Value['k2019']['b']
    }
    It 'an array of 2,040 escaped 1,010-character strings' {
        $r = Measure-TestHostileToml ('a = [' + "`n" + (('"' + ('x' * 1010) + '\n",' + "`n") * 2040) + ']')
        Assert-Equal '' $r.Message
        Assert-Equal 2040 $r.Value['a'].Count
        Assert-Equal (('x' * 1010) + "`n") $r.Value['a'][2039]
    }
    It 'still counts the steps of the readers that take a handed-over string (100 keys parse with 400 steps, 101 do not)' {
        # One step per statement, then one each in Read-AwTomlValue, Read-AwTomlString and the escapes.
        $value = '"' + ('x' * 1010) + '\n"'
        $old = & $aw { $old = $script:AwTomlMaxSteps; $script:AwTomlMaxSteps = 400; $old }
        try {
            $r = Measure-TestHostileToml (New-TestTomlKeys 100 $value)
            $over = Measure-TestHostileToml (New-TestTomlKeys 101 $value)
        } finally {
            & $aw { param($v) $script:AwTomlMaxSteps = $v } $old
        }
        Assert-Equal '' $r.Message
        Assert-Equal (('x' * 1010) + "`n") $r.Value['k99']
        Assert-Match $over.Message '^Invalid TOML at line 101, column 1: The document is too complex: more than 400 parse steps'
    }
    It 'a key, then an unterminated 2 MB string' {
        $r = Measure-TestHostileToml ('k "' + ('x' * ($mb2 - 64)))
        Assert-Match $r.Message "^Invalid TOML at line 1, column 3: Expected '=' after the key 'k', found '`"'"
    }
}

Describe 'ConvertFrom-AwToml: round-trip types' {
    It 'parses a configuration file like its JSON equivalent, value for value' {
        Assert-Equal (Read-TestJson 'config.json') (Read-TestToml 'config.toml')
    }
    It 'returns [long], [double], [bool], [string], hashtables and object[]' {
        $r = Read-TestToml 'config.toml'
        Assert-True ($r -is [hashtable])
        Assert-True ($r['max_turns'] -is [long])
        Assert-True ($r['temperature'] -is [double])
        Assert-True ($r['hide_reasoning'] -is [bool])
        Assert-True ($r['model'] -is [string])
        Assert-True ($r['updated'] -is [string])
        Assert-True ($r['mcp_servers'] -is [hashtable])
        Assert-True ($r['mcp_servers']['docs']['args'] -is [object[]])
        Assert-True ($r['mcp_servers']['docs']['env'] -is [hashtable])
        Assert-Equal 'C:\Example\cache' $r['sandbox_workspace_write']['writable_roots'][0]
        Assert-Equal 'trusted' $r['projects']['C:\Example\repo']['trust_level']
    }
    It 'never returns PSCustomObject, ArrayList or [datetime] values' {
        $seen = New-Object System.Collections.ArrayList
        $todo = New-Object System.Collections.Stack
        foreach ($name in 'config.toml', 'tables.toml', 'example.toml', 'strings.toml') { $todo.Push((Read-TestToml $name)) }
        while ($todo.Count -gt 0) {
            $v = $todo.Pop()
            [void]$seen.Add($v.GetType().FullName)
            if ($v -is [hashtable]) { foreach ($k in $v.Keys) { $todo.Push($v[$k]) } }
            elseif ($v -is [object[]]) { foreach ($x in $v) { $todo.Push($x) } }
        }
        foreach ($t in $seen) {
            Assert-Contains @('System.Collections.Hashtable', 'System.Object[]', 'System.String', 'System.Int64', 'System.Double', 'System.Boolean') $t
        }
    }
    It 'survives a round trip through JSON text and the JSONC parser' {
        foreach ($name in 'config.toml', 'tables.toml', 'example.toml', 'keys.toml', 'strings.toml', 'unicode.toml') {
            $r = Read-TestToml $name
            $json = ConvertTo-Json -InputObject $r -Depth 64 -Compress
            $back = & $aw { param($t) ConvertFrom-AwJsonc -Text $t } $json
            Assert-Equal $r $back $name
        }
    }
    It 'keeps tables case-sensitive (ordinal keys)' {
        $r = ConvertFrom-TestToml "[T]`nk = 1`n[t]`nK = 2"
        Assert-Equal 2 $r.Count
        Assert-Equal 1 $r['T']['k']
        Assert-Equal 2 $r['t']['K']
        Assert-False $r['t'].ContainsKey('k')
    }
}

Describe 'ConvertFrom-AwToml: bounded window (results do not depend on the window size)' {
    $defaults = & $aw { @($script:AwTomlWindow, $script:AwTomlWindowMargin) }
    $texts = New-Object System.Collections.Generic.List[string]
    foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'fixtures') -Recurse -File -Filter '*.toml' | Sort-Object -Property FullName)) {
        $texts.Add([System.IO.File]::ReadAllText($file.FullName))
    }
    foreach ($c in $invalidCases) { $texts.Add($c.Text) }
    foreach ($c in $tokenCases) { $texts.Add($c.Text) }
    # The texts of the line and column tests above.
    foreach ($t in @("a = 1`nb = 2`n`nc = = 3", "a = 1`r`nb = = 2", "a = 1`n`na = 2", "[a]`nx = 1`n[a]", "a = 1`nb = `"`"`"x`ny`nz",
        "a = 1`nb = `"ok \q`"", "a = `"`"`"`nok`nbad \q`n`"`"`"", 'token = ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234')) { $texts.Add($t) }
    $texts = $texts.ToArray()
    # A 4 MB window holds every document whole, as the parser did before windows.
    $whole = Get-TestTomlOutcomes $texts 4194304 16
    foreach ($pair in @(@(4, 3), @(5, 3), @(7, 3), @(17, 16), @(64, 16), $defaults)) {
        It "gives the same values, messages, lines and columns with a window of $($pair[0]) and a margin of $($pair[1]) (fixtures, invalid and edge cases)" {
            $outcomes = Get-TestTomlOutcomes $texts $pair[0] $pair[1]
            Compare-TestTomlOutcomes $texts $whole $outcomes ('window ' + $pair[0] + ', margin ' + $pair[1])
        }
    }
    $docs = New-TestTomlFuzz 20261019 300
    $wholeDocs = Get-TestTomlOutcomes $docs 4194304 16
    foreach ($pair in @(@(5, 3), @(17, 16))) {
        It "gives the same results on 300 seeded random documents with a window of $($pair[0]) and a margin of $($pair[1])" {
            $outcomes = Get-TestTomlOutcomes $docs $pair[0] $pair[1]
            Compare-TestTomlOutcomes $docs $wholeDocs $outcomes ('seeded documents, window ' + $pair[0] + ', margin ' + $pair[1])
        }
    }
    It 'matches each windowed regex at every position as on the whole text, moving forward and back' {
        $tricky = @(
            ('k = "a\"b\\c\' + $ctl['bell'] + 'd" ""x""" e"""""f' + "`n" + '"\' + "`r`n" + 'g\'),
            ('  # c' + "`r`n" + '#' + $ctl['del'] + "`n`t`r" + 'x' + "`r`n`r`n" + '# z' + "`r" + ' ' + $ctl['nul'] + ' #' + $ctl['lineSeparator'] + "`t"),
            ('key_1-2.a+b:c 1979-05-27 07:32:00Z 0x1F_a inf' + "'lit'" + $ctl['esc'] + "x'''y''''z'" + "`r`n" + "'''"),
            ("''x''''" + "`r`n" + "'" + $ctl['bell'] + "''' " + '"""" "" """\' + "`n" + '""\""""')
        )
        $names = @('AwTomlRxWs', 'AwTomlRxTrivia', 'AwTomlRxLineEnd', 'AwTomlRxBareKey', 'AwTomlRxToken',
            'AwTomlRxBasic', 'AwTomlRxMlBasic', 'AwTomlRxLiteral', 'AwTomlRxMlLiteral')
        foreach ($pair in @(@(4, 3), @(17, 16))) {
            $old = Set-TestTomlWindow $pair[0] $pair[1]
            try {
                # The same three lines as every windowed match in the parser, then the match on the whole text.
                $bad = & $aw {
                    param($Texts, $Names)
                    $out = New-Object System.Collections.Generic.List[string]
                    foreach ($name in $Names) {
                        $rx = Get-Variable -Name $name -Scope Script -ValueOnly
                        foreach ($T in $Texts) {
                            $s = @{ T = $T; W = ''; Wb = 0; Wl = -1 }
                            $W = ''; $wb = 0; $wl = -1
                            foreach ($p in @(@(0..$T.Length) + @($T.Length..0))) {
                                if ($p -lt $wb -or $p -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s $p }
                                $m = $rx.Match($W, $p - $wb)
                                if ($p + $m.Length -gt $wl) { $m, $W, $wb, $wl = Find-AwTomlMatch $s $rx $p }
                                $whole = $rx.Match($T, $p)
                                if ($m.Success -ne $whole.Success -or $m.Length -ne $whole.Length -or
                                    -not [string]::Equals($m.Value, $whole.Value, [System.StringComparison]::Ordinal)) {
                                    $out.Add($name + ' at ' + $p + ' of <' + $T + '>: <' + $m.Value + '> instead of <' + $whole.Value + '>')
                                }
                            }
                        }
                    }
                    return ,$out.ToArray()
                } $tricky $names
            } finally {
                $null = Set-TestTomlWindow $old[0] $old[1]
            }
            Assert-Equal 0 @($bad).Count ('window ' + $pair[0] + ': ' + (@($bad | Select-Object -First 3) -join ' | '))
        }
    }
    It 'returns the match and the new window from Find-AwTomlMatch, and keeps the window in the state' {
        $old = Set-TestTomlWindow 4 3
        try {
            $r = & $aw {
                param($T)
                $s = @{ T = $T; W = ''; Wb = 0; Wl = -1 }
                $moved = @(Move-AwTomlWindow $s 0)
                $found = @(Find-AwTomlMatch $s $script:AwTomlRxWs 1)
                return ,@($moved.Count, $found.Count, $found[0].Length, $found[1], $found[2], $found[3], $s.W, $s.Wb, $s.Wl)
            } ('x' + (' ' * 50) + 'y')
        } finally {
            $null = Set-TestTomlWindow $old[0] $old[1]
        }
        # The 50 spaces fit the first larger window (64 characters), which is kept at the run.
        $kept = (' ' * 50) + 'y'
        Assert-Equal @(3, 4, 50, $kept, 1, 52, $kept, 1, 52) $r
    }
    It 'moves the window past a match longer than the first larger window' {
        $old = Set-TestTomlWindow 4 3
        try {
            $r = & $aw {
                param($T)
                $s = @{ T = $T; W = ''; Wb = 0; Wl = -1 }
                $found = @(Find-AwTomlMatch $s $script:AwTomlRxWs 1)
                return ,@($found.Count, $found[0].Length, $found[1], $found[2], $found[3], $s.W, $s.Wb, $s.Wl)
            } ('x' + (' ' * 100) + 'y')
        } finally {
            $null = Set-TestTomlWindow $old[0] $old[1]
        }
        # 100 spaces need more than 64 characters; the next window starts after them.
        Assert-Equal @(4, 100, 'y', 101, 102, 'y', 101, 102) $r
    }
}

Describe 'ConvertFrom-AwToml: source hygiene' {
    It 'keeps the parser and these tests ASCII-only (Windows PowerShell 5.1 reads BOM-less files as ANSI)' {
        $root = Split-Path -Parent $PSScriptRoot
        foreach ($file in @((Join-Path $root 'src\Core\Toml.ps1'), (Join-Path $PSScriptRoot 'Toml.Tests.ps1'))) {
            $bytes = [System.IO.File]::ReadAllBytes($file)
            Assert-Equal 0 @($bytes | Where-Object { $_ -gt 127 }).Count $file
        }
    }
    It 'passes the document to one method call only, the Match of Format-AwTomlFound (AST)' {
        # PowerShell 7.3+ logs every .NET method call made from script with the full text of its
        # string arguments, so only an error path may give the whole document to a method.
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($tomlPath, [ref]$tokens, [ref]$errors)
        Assert-Equal 0 @($errors).Count 'Toml.ps1 parses'
        $found = New-Object System.Collections.Generic.List[string]
        foreach ($call in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)) {
            $passes = $false
            foreach ($arg in @($call.Arguments)) {
                if ($null -ne $arg -and @($arg.FindAll({ param($n) Test-TestTomlDocumentRef $n }, $true)).Count -gt 0) { $passes = $true }
            }
            if (-not $passes) { continue }
            $fn = $call.Parent
            while ($null -ne $fn -and $fn -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $fn = $fn.Parent }
            $where = '(script)'
            if ($null -ne $fn) { $where = $fn.Name }
            $found.Add($where + ': ' + $call.Member.Extent.Text + ' at line ' + $call.Extent.StartLineNumber)
        }
        Assert-Equal 1 $found.Count ($found -join '; ')
        Assert-Match $found[0] '^Format-AwTomlFound: Match at line \d+$'
    }
    It 'runs every windowed match through the three-line template' {
        # Before: move the window when the position is outside it. After: match again on larger
        # windows when the match ends inside the margin.
        $lines = [System.IO.File]::ReadAllLines($tomlPath)
        $site = [regex]'^\s*\$(\w+) = \$([\w:]+)\.Match\(\$W, \$(\w+) - \$wb\)$'
        $count = 0
        $inFind = 0
        $bad = New-Object System.Collections.Generic.List[string]
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            if ($line.IndexOf('.Match($W', [System.StringComparison]::Ordinal) -lt 0) { continue }
            $m = $site.Match($line)
            if (-not $m.Success) {
                if ($line.Trim() -ceq '$m = $Rx.Match($W, 0)') { $inFind++ } else { $bad.Add('line ' + ($i + 1) + ' is not a template: ' + $line.Trim()) }
                continue
            }
            $v = '$' + $m.Groups[1].Value
            $rx = '$' + $m.Groups[2].Value
            $p = '$' + $m.Groups[3].Value
            $before = 'if (' + $p + ' -lt $wb -or ' + $p + ' -gt $wl) { $W, $wb, $wl = Move-AwTomlWindow $s ' + $p + ' }'
            $after = 'if (' + $p + ' + ' + $v + '.Length -gt $wl) { ' + $v + ', $W, $wb, $wl = Find-AwTomlMatch $s ' + $rx + ' ' + $p + ' }'
            if ($i -eq 0 -or $lines[$i - 1].Trim() -cne $before) { $bad.Add('line ' + $i + ' should be: ' + $before) }
            if ($i + 1 -ge $lines.Count -or $lines[$i + 1].Trim() -cne $after) { $bad.Add('line ' + ($i + 2) + ' should be: ' + $after) }
            $count++
        }
        Assert-Equal 0 $bad.Count ($bad -join '; ')
        Assert-Equal 29 $count 'windowed match sites'
        Assert-Equal 1 $inFind 'the first match of Find-AwTomlMatch'
    }
    It 'keeps the windowed regexes as they are, and the margin above their read-ahead' {
        $expected = @{
            AwTomlRxWs        = '\G[ \t]*'
            AwTomlRxTrivia    = '\G(?>(?:[ \t]|\r?\n|#[^\x00-\x08\x0A-\x1F\x7F]*)*)'
            AwTomlRxLineEnd   = '\G(?>[ \t]*)(?>(?:#[^\x00-\x08\x0A-\x1F\x7F]*)?)'
            AwTomlRxBareKey   = '\G[A-Za-z0-9_-]+'
            AwTomlRxToken     = '\G[0-9A-Za-z_+.:-]+'
            AwTomlRxBasic     = '\G(?>(?:[^"\\\x00-\x08\x0A-\x1F\x7F]+|\\[^\x00-\x08\x0A-\x1F\x7F])*)'
            AwTomlRxMlBasic   = '\G(?>(?:[^"\\\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+|\\[^\x00-\x08\x0B\x0C\x0E-\x1F\x7F]|"(?!""))*)'
            AwTomlRxLiteral   = '\G[^''\x00-\x08\x0A-\x1F\x7F]*'
            AwTomlRxMlLiteral = '\G(?>(?:[^''\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+|''(?!''''))*)'
        }
        foreach ($name in $expected.Keys) {
            $actual = & $aw { param($n) [string](Get-Variable -Name $n -Scope Script -ValueOnly) } $name
            Assert-Equal $expected[$name] $actual ($name + ' changed: re-check the read-ahead table')
        }
        $window = & $aw { @($script:AwTomlWindow, $script:AwTomlWindowMargin) }
        Assert-True ($window[1] -ge 3) ('AwTomlWindowMargin is ' + $window[1] + ': re-check the read-ahead table')
        Assert-True ($window[0] -gt $window[1]) 'the window is larger than its margin'
    }
}
