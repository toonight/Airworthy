# Tests for the JSONC parser (src/Core/Jsonc.ps1).
$aw = Get-Module Airworthy
# Non-ASCII test strings come from a JSON fixture with backslash-u escapes (CONTRIBUTING.md, Antivirus hygiene).
$escapesFile = Join-Path $PSScriptRoot 'fixtures\jsonc\escapes.json'

function ConvertFrom-TestJsonc {
    param([string]$Text, [switch]$AllowEmpty)
    & $aw { param($t, $e) ConvertFrom-AwJsonc -Text $t -AllowEmpty:$e } $Text ([bool]$AllowEmpty)
}

function Get-TestJsoncError {
    # Returns the FormatException raised for invalid input.
    param([string]$Text)
    $ex = Assert-Throws { ConvertFrom-TestJsonc $Text }
    while ($ex -isnot [System.FormatException] -and $null -ne $ex.InnerException) { $ex = $ex.InnerException }
    Assert-True ($ex -is [System.FormatException]) "expected a FormatException, got $($ex.GetType().FullName)"
    return $ex
}

Describe 'ConvertFrom-AwJsonc: values' {
    It 'parses scalars with the right .NET types' {
        $r = ConvertFrom-TestJsonc '{"s":"x","i":42,"neg":-7,"l":9223372036854775807,"d":1.5,"e":1e3,"E":2.5E-2,"t":true,"f":false,"n":null,"z":-0}'
        Assert-Equal 'x' $r['s']
        Assert-True ($r['i'] -is [int]); Assert-Equal 42 $r['i']
        Assert-Equal (-7) $r['neg']
        Assert-True ($r['l'] -is [long]); Assert-Equal ([long]::MaxValue) $r['l']
        Assert-True ($r['d'] -is [double]); Assert-Equal 1.5 $r['d']
        Assert-Equal 1000 $r['e']
        Assert-Equal 0.025 $r['E']
        Assert-True ($r['t'] -is [bool] -and $r['t'])
        Assert-True ($r['f'] -is [bool] -and -not $r['f'])
        Assert-True ($r.ContainsKey('n') -and $null -eq $r['n'])
        Assert-Equal 0 $r['z']
    }
    It 'returns hashtables, never PSCustomObject' {
        $r = ConvertFrom-TestJsonc '{"a":{"b":{"c":[{"d":1}]}}}'
        Assert-True ($r -is [hashtable])
        Assert-True ($r['a'] -is [hashtable])
        Assert-True ($r['a']['b']['c'] -is [object[]])
        Assert-True ($r['a']['b']['c'][0] -is [hashtable])
        Assert-Equal 1 $r.a.b.c[0].d
    }
    It 'keeps keys case-sensitive' {
        $r = ConvertFrom-TestJsonc '{"chat.tools.global.autoApprove":true,"Chat.Tools.Global.AutoApprove":false}'
        Assert-Equal 2 $r.Count
        Assert-Equal $true $r['chat.tools.global.autoApprove']
        Assert-Equal $false $r['Chat.Tools.Global.AutoApprove']
    }
    It 'returns arrays as object[] and keeps empty containers' {
        $r = ConvertFrom-TestJsonc '{"a":[],"o":{},"n":[[1,2],[3]]}'
        Assert-True ($r['a'] -is [object[]]); Assert-Equal 0 $r['a'].Count
        Assert-True ($r['o'] -is [hashtable]); Assert-Equal 0 $r['o'].Count
        Assert-Equal 2 $r['n'].Count
        Assert-Equal @(1, 2) $r['n'][0]
    }
    It 'returns a top-level array or scalar unchanged' {
        $a = ConvertFrom-TestJsonc '[1,"two",null]'
        Assert-True ($a -is [object[]]); Assert-Equal 3 $a.Count; Assert-Equal 'two' $a[1]
        $e = ConvertFrom-TestJsonc '[]'
        Assert-True ($e -is [object[]]); Assert-Equal 0 $e.Count
        Assert-Equal 'x' (ConvertFrom-TestJsonc '"x"')
        Assert-Equal 3 (ConvertFrom-TestJsonc ' 3 ')
    }
    It 'lets the last duplicate key win' {
        $r = ConvertFrom-TestJsonc '{"a":1,"b":2,"a":3}'
        Assert-Equal 3 $r['a']
        Assert-Equal 2 $r.Count
    }
    It 'skips a leading BOM' {
        $r = ConvertFrom-TestJsonc ((& $aw { [string]$script:AwBom }) + '{"a":1}')
        Assert-Equal 1 $r['a']
    }
    It 'parses multi-line documents with CRLF line endings' {
        $r = ConvertFrom-TestJsonc "{`r`n  `"a`": 1,`r`n  `"b`": [true]`r`n}`r`n"
        Assert-Equal 1 $r['a']
        Assert-Equal @($true) $r['b']
    }
}

Describe 'ConvertFrom-AwJsonc: comments and trailing commas' {
    It 'ignores line and block comments outside strings' {
        $text = "// header`n/* block`n comment */ {`n  `"a`": 1, // trailing`n  /* inline */ `"b`" /* x */ : /* y */ 2`n} // end"
        $r = ConvertFrom-TestJsonc $text
        Assert-Equal 1 $r['a']; Assert-Equal 2 $r['b']
    }
    It 'accepts a line comment at the very end without a newline' {
        Assert-Equal 1 (ConvertFrom-TestJsonc '{"a":1}//x')['a']
    }
    It 'keeps comment markers that are inside strings' {
        $r = ConvertFrom-TestJsonc '{"url":"https://example.invalid/a//b","c":"/* not a comment */","d":"// nor this"}'
        Assert-Equal 'https://example.invalid/a//b' $r['url']
        Assert-Equal '/* not a comment */' $r['c']
        Assert-Equal '// nor this' $r['d']
    }
    It 'does not let quotes inside a comment open a string' {
        $r = ConvertFrom-TestJsonc "/* it's `"quoted`" */ {`"a`": 1} // `"also`""
        Assert-Equal 1 $r['a']
    }
    It 'accepts trailing commas in objects and arrays, nested' {
        $r = ConvertFrom-TestJsonc '{"a":[1,2,],"b":{"c":true,},"d":[{"e":1,},],}'
        Assert-Equal @(1, 2) $r['a']
        Assert-Equal $true $r['b']['c']
        Assert-Equal 1 $r['d'][0]['e']
        Assert-Equal 1 $r['d'].Count
    }
    It 'accepts a trailing comma followed by a comment' {
        $r = ConvertFrom-TestJsonc "{`"a`": 1, // last`n}"
        Assert-Equal 1 $r['a']
    }
}

Describe 'ConvertFrom-AwJsonc: strings, escapes and unicode' {
    It 'decodes every JSON escape' {
        $r = ConvertFrom-TestJsonc '{"s":"q\" b\\ s\/ \b\f\n\r\t end"}'
        $expected = 'q" b\ s/ ' + "`b`f`n`r`t" + ' end'
        Assert-Equal $expected $r['s']
    }
    It 'decodes \u escapes, including surrogate pairs (checked by code point)' {
        $raw = [System.IO.File]::ReadAllText($escapesFile)
        Assert-False ($raw -match '[^\x00-\x7F]') 'the fixture must stay ASCII'
        $r = (ConvertFrom-TestJsonc $raw)['escapes']
        Assert-Equal 4 $r['e'].Length
        Assert-True ($r['e'].StartsWith('caf'))
        Assert-Equal 0xE9 ([int]$r['e'][3])
        Assert-Equal @(0xD83D, 0xDE00) @($r['emoji'].ToCharArray() | ForEach-Object { [int]$_ })
        Assert-True ([char]::IsSurrogatePair($r['emoji'], 0))
        Assert-Equal @(0x61, 0, 0x62) @($r['nul'].ToCharArray() | ForEach-Object { [int]$_ })
    }
    It 'keeps raw non-ASCII characters' {
        $raw = (ConvertFrom-TestJsonc ([System.IO.File]::ReadAllText($escapesFile)))['raw']
        $text = '{"' + $raw['key'] + '":"' + $raw['value'] + '"}'
        Assert-False $text.Contains('\') 'the document must hold the characters themselves'
        $r = ConvertFrom-TestJsonc $text
        Assert-Equal 1 $r.Count
        Assert-Equal $raw['value'] $r[$raw['key']]
        Assert-Equal @(0x6B, 0xE9) @($raw['key'].ToCharArray() | ForEach-Object { [int]$_ })
    }
    It 'handles an escaped quote followed by comment-like text' {
        $r = ConvertFrom-TestJsonc '{"a":"x\"//y","b":"\\"}'
        Assert-Equal 'x"//y' $r['a']
        Assert-Equal '\' $r['b']
    }
    It 'decodes escapes in keys' {
        $r = (ConvertFrom-TestJsonc ([System.IO.File]::ReadAllText($escapesFile)))['keyEscape']
        Assert-Equal 1 $r['ab']
        Assert-Equal 1 $r.Count
    }
    It 'tolerates a raw tab inside a string' {
        $r = ConvertFrom-TestJsonc "{`"a`":`"x`ty`"}"
        Assert-Equal "x`ty" $r['a']
    }
}

Describe 'ConvertFrom-AwJsonc: invalid input' {
    $cases = @(
        @{ Name = 'unterminated string';       Text = '{"a":"abc}';       Pattern = 'Unterminated string' }
        @{ Name = 'raw newline in a string';    Text = "{`"a`":`"x`ny`"}";   Pattern = 'Unterminated string' }
        @{ Name = 'raw control character';      Text = "{`"a`":`"x`a`"}";   Pattern = 'Unterminated string' }
        @{ Name = 'unterminated block comment'; Text = '{"a":1} /* open';  Pattern = 'Unterminated block comment' }
        @{ Name = 'missing colon';              Text = '{"a" 1}';          Pattern = "Expected ':'" }
        @{ Name = 'missing comma';              Text = '{"a":1 "b":2}';    Pattern = "Expected ','" }
        @{ Name = 'leading comma in array';     Text = '[,1]';             Pattern = 'Expected a value' }
        @{ Name = 'double comma';               Text = '[1,,2]';           Pattern = 'Expected a value' }
        @{ Name = 'comma only object';          Text = '{,}';              Pattern = 'property name' }
        @{ Name = 'single quotes';              Text = "{'a':1}";          Pattern = 'Unexpected character' }
        @{ Name = 'unquoted key';               Text = '{a:1}';            Pattern = 'property name' }
        @{ Name = 'NaN literal';                Text = '{"a":NaN}';        Pattern = 'Unexpected identifier' }
        @{ Name = 'capitalized literal';        Text = '{"a":True}';       Pattern = 'Unexpected identifier' }
        @{ Name = 'leading zero';               Text = '{"a":01}';         Pattern = "Expected ','" }
        @{ Name = 'leading plus';               Text = '[+1]';             Pattern = 'Unexpected character' }
        @{ Name = 'trailing garbage';           Text = '{} x';             Pattern = 'after the end' }
        @{ Name = 'two documents';              Text = '{} {}';            Pattern = 'after the end' }
        @{ Name = 'unclosed object';            Text = '{"a":1';           Pattern = 'end of input' }
        @{ Name = 'unclosed array';             Text = '[1,[2]';           Pattern = 'end of input' }
        @{ Name = 'unmatched closer';           Text = ']';                Pattern = 'Expected a value' }
        @{ Name = 'wrong closer';               Text = '[1}';              Pattern = "Expected ',' or '\]'" }
        @{ Name = 'invalid escape';             Text = '{"a":"\x41"}';     Pattern = 'Invalid escape' }
        @{ Name = 'short unicode escape';       Text = '{"a":"\u12"}';     Pattern = 'Invalid \\u escape' }
        @{ Name = 'number out of range';        Text = '[1e400]';          Pattern = 'out of range' }
        @{ Name = 'empty document';             Text = '';                 Pattern = 'no JSON value' }
        @{ Name = 'comments only';              Text = "// nothing`n/* here */"; Pattern = 'no JSON value' }
    )
    foreach ($c in $cases) {
        It "rejects: $($c.Name)" {
            $ex = Get-TestJsoncError $c.Text
            Assert-Match $ex.Message $c.Pattern
            Assert-Match $ex.Message '^Invalid JSON at line \d+, column \d+: '
        }
    }

    It 'reports the line and column of the error' {
        $ex = Get-TestJsoncError "{`n  `"a`": 1,`n  `"b`" 2`n}"
        Assert-Equal 3 $ex.Data['Line']
        Assert-Equal 7 $ex.Data['Column']
        Assert-Match $ex.Message 'line 3, column 7'
    }
    It 'never echoes a long unquoted token in full (secret-safe messages)' {
        $ex = Get-TestJsoncError '{"token": ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234}'
        Assert-NotMatch $ex.Message 'FAKEFAKEFAKEFAKE'
        Assert-Match $ex.Message 'ghp_'
    }
    It 'returns $null for an empty document with -AllowEmpty' {
        Assert-Equal $null (ConvertFrom-TestJsonc '' -AllowEmpty)
        Assert-Equal $null (ConvertFrom-TestJsonc "  // only a comment`n" -AllowEmpty)
    }
    It 'still rejects an unclosed document with -AllowEmpty' {
        Assert-Throws { ConvertFrom-TestJsonc '{' -AllowEmpty } -ExpectedMessage 'end of input'
    }
}

Describe 'ConvertFrom-AwJsonc: depth limit and size' {
    It 'accepts 64 nested levels' {
        $text = ('[' * 64) + (']' * 64)
        $r = ConvertFrom-TestJsonc $text
        Assert-True ($r -is [object[]])
    }
    It 'rejects 65 nested levels' {
        $ex = Get-TestJsoncError (('[' * 65) + (']' * 65))
        Assert-Match $ex.Message 'Maximum nesting depth of 64'
    }
    It 'rejects hostile deep nesting without a stack overflow' {
        $ex = Get-TestJsoncError (('{"a":' * 5000) + '1' + ('}' * 5000))
        Assert-Match $ex.Message 'Maximum nesting depth'
    }
    It 'parses a few thousand entries quickly' {
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append('{"items":[')
        for ($i = 0; $i -lt 3000; $i++) { [void]$sb.Append('{"id":' + $i + ',"name":"item-' + $i + '","on":true},') }
        [void]$sb.Append(']}')
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $r = ConvertFrom-TestJsonc $sb.ToString()
        $sw.Stop()
        Assert-Equal 3000 $r['items'].Count
        Assert-Equal 'item-2999' $r['items'][2999]['name']
        Assert-True ($sw.Elapsed.TotalSeconds -lt 20) "took $($sw.Elapsed.TotalSeconds) s"
    }
}
