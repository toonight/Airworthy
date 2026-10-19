# Tests for src/Rules/Secrets.ps1 (AW-SEC-0xx). Every analysis uses -NoUserProfile; every secret is FAKE.
# Token-shaped inputs come from fixtures/secrets/strings.json (CONTRIBUTING.md, Antivirus hygiene).
$aw = Get-Module Airworthy
$fixtures = Join-Path $PSScriptRoot 'fixtures'
$leaky = Join-Path $fixtures 'secrets\leaky'
$clean = Join-Path $fixtures 'secrets\clean'
$insecure = Join-Path $fixtures 'insecure'
$hardened = Join-Path $fixtures 'hardened'
$mixed = Join-Path $fixtures 'mixed'
$edge = Join-Path $fixtures 'core\edge'
$tmp = Join-Path $fixtures ('secrets\_tmp-' + [guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($tmp)
$utf8 = New-Object System.Text.UTF8Encoding($false)
$scans = @{}

$fx = & $aw { param($p) ConvertFrom-AwJsonc -Text ([System.IO.File]::ReadAllText($p)) } (Join-Path $fixtures 'secrets\strings.json')
$fakeSecrets = @($fx['fakeSecrets'])
$ellipsis = & $aw { $script:AwEllipsis }

function New-TestFile([string]$Path, [string]$Text) {
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { [void][System.IO.Directory]::CreateDirectory($dir) }
    [System.IO.File]::WriteAllText($Path, $Text, $utf8)
}
function Get-Scan([string]$Path) {
    if (-not $scans.ContainsKey($Path)) { $scans[$Path] = Invoke-Airworthy -Path $Path -NoUserProfile -PassThru -Quiet }
    return $scans[$Path]
}
function Get-Rule([string]$Path, [string]$RuleId, [string]$Leaf) {
    # Findings of one rule, sorted by file then line. The comma keeps 0- and 1-item results as arrays.
    $f = @((Get-Scan $Path).Findings | Where-Object { $_.RuleId -eq $RuleId -and (-not $Leaf -or (Split-Path -Leaf $_.Location.Path) -eq $Leaf) } |
        Sort-Object -Property @{ Expression = { [string]$_.Location.Path } }, @{ Expression = { [int]$_.Location.Line } })
    return ,$f
}
function Get-Lines($Findings) { return ,@($Findings | ForEach-Object { $_.Location.Line }) }
function Get-SecretCount([string]$RuleId, [string]$Text) {
    # Number of accepted matches of one secret rule in a text (internal scanner).
    $n = & $aw {
        param($id, $t)
        $p = $script:AwSecPatterns | Where-Object { $_.RuleId -eq $id } | Select-Object -First 1
        (Find-AwSecMatches -Text $t -Pattern $p -Generic:($null -eq $p)).Count
    } $RuleId $Text
    return [int]$n
}

try {

Describe 'Secrets: rule registry and data' {
    It 'registers AW-SEC-001 to AW-SEC-010 as generic secrets rules' {
        $rules = @(& $aw { Get-AwRules } | Where-Object { $_.Id -like 'AW-SEC-*' })
        Assert-Equal @(1..10 | ForEach-Object { 'AW-SEC-{0:D3}' -f $_ }) @($rules | ForEach-Object { $_.Id })
        foreach ($r in $rules) {
            Assert-Equal 'secrets' $r.Category $r.Id
            Assert-Equal 'generic' $r.Harness $r.Id
            Assert-Contains $r.References 'OWASP-ASI03' $r.Id
            Assert-True ($r.Description.Length -gt 60 -and $r.Fix.Length -gt 40) $r.Id
        }
        Assert-Equal 'medium' @($rules | Where-Object { $_.Id -eq 'AW-SEC-009' })[0].Confidence
        Assert-Equal 'low' @($rules | Where-Object { $_.Id -eq 'AW-SEC-010' })[0].Severity
        Assert-Equal 'medium' @($rules | Where-Object { $_.Id -eq 'AW-SEC-008' })[0].Severity
    }
    It 'loads one provider pattern per format rule from src/Data/secrets.json' {
        $ids = @(& $aw { $script:AwSecPatterns | ForEach-Object { $_.RuleId } })
        Assert-Equal @(1..8 | ForEach-Object { 'AW-SEC-{0:D3}' -f $_ }) $ids
        $masked = @(& $aw { $script:AwSecPatterns | Where-Object { -not $_.Mask } | ForEach-Object { $_.RuleId } })
        Assert-Equal @('AW-SEC-007') $masked
        Assert-True (& $aw { [bool]($script:AwSecPatterns | Where-Object { $_.RuleId -eq 'AW-SEC-003' }).Regex.Options.HasFlag([System.Text.RegularExpressions.RegexOptions]::IgnoreCase) })
        Assert-True (& $aw { ($script:AwSecPatterns | Where-Object { $_.RuleId -eq 'AW-SEC-001' }).Regex.MatchTimeout.TotalSeconds -gt 0 })
    }
    It 'keeps the rule file ASCII-only' {
        $bytes = [System.IO.File]::ReadAllBytes((Join-Path (Split-Path -Parent $PSScriptRoot) 'src\Rules\Secrets.ps1'))
        Assert-Equal 0 @($bytes | Where-Object { $_ -gt 127 }).Count
    }
}

Describe 'Secrets: masking' {
    It 'never shows a full fake secret anywhere in the findings' {
        Assert-True ($fakeSecrets.Count -ge 16)
        foreach ($p in @($leaky, $insecure, $clean)) {
            $r = Get-Scan $p
            $all = ($r.Findings | ConvertTo-Json -Depth 8) + ($r.Errors | ConvertTo-Json -Depth 8)
            foreach ($f in $r.Findings) { $all += [string]$f.Evidence + [string]$f.Title + [string]$f.Location.Key }
            foreach ($s in $fakeSecrets) { Assert-NotMatch $all ([regex]::Escape($s)) "$p leaks $($s.Substring(0, 8))..." }
        }
    }
    It 'finds every fake secret of the leaky fixture' {
        # A secret that is not reported would make the masking test above pass for the wrong reason.
        $f = @((Get-Scan $leaky).Findings | Where-Object { $_.RuleId -like 'AW-SEC-*' -and $_.RuleId -ne 'AW-SEC-010' })
        Assert-Equal 15 $f.Count (($f | ForEach-Object { $_.RuleId + ' ' + $_.Evidence }) -join '; ')
    }
    It 'never shows a full fake secret in the JSON output' {
        if (-not (& $aw { [bool](Get-Command ConvertTo-AwJson -ErrorAction SilentlyContinue) })) { return }
        $json = (@(Invoke-Airworthy -Path $leaky -NoUserProfile -Format Json -Quiet) -join "`n")
        Assert-True ($json.Length -gt 100)
        foreach ($s in $fakeSecrets) { Assert-NotMatch $json ([regex]::Escape($s)) $s.Substring(0, 8) }
    }
    It 'shows the first 4 and last 2 characters and the length' {
        $f = Get-Rule $leaky 'AW-SEC-001' 'mcp.json'
        Assert-Equal ('GitHub token: ghp_' + $ellipsis + 'ab (40 chars)') $f[0].Evidence
        Assert-Equal 'GITHUB_TOKEN' $f[0].Location.Key
    }
}

Describe 'AW-SEC-001 GitHub tokens' {
    It 'finds classic and fine-grained tokens, in JSON and in Markdown' {
        Assert-Equal @(9, 10) (Get-Lines (Get-Rule $leaky 'AW-SEC-001' 'mcp.json'))
        $md = Get-Rule $leaky 'AW-SEC-001' 'copilot-instructions.md'
        Assert-Equal @(7) (Get-Lines $md)
        Assert-Equal 'vscode-copilot' $md[0].Harness
        Assert-Equal 'high' $md[0].Severity
        Assert-Equal @(9) (Get-Lines (Get-Rule $insecure 'AW-SEC-001'))
    }
    It 'finds every documented prefix and the stateless installation token format' {
        foreach ($prefix in @($fx['github']['prefixes'])) { Assert-Equal 1 (Get-SecretCount 'AW-SEC-001' ('x ' + $prefix + $fx['github']['body'] + ' y')) $prefix }
        $stateless = $fx['github']['stateless']
        Assert-Equal 1 (Get-SecretCount 'AW-SEC-001' "token $stateless")
        Assert-Equal 0 (Get-SecretCount 'AW-SEC-008' "token $stateless")
    }
    It 'ignores placeholders and short or prefixed look-alikes' {
        Assert-Equal 0 (Get-Rule $clean 'AW-SEC-001').Count
        Assert-Equal 0 (Get-SecretCount 'AW-SEC-001' $fx['github']['lookAlikes'])
    }
}

Describe 'AW-SEC-002 AWS access key IDs' {
    It 'finds AKIA and ASIA keys' {
        $f = Get-Rule $leaky 'AW-SEC-002'
        Assert-Equal @(14) (Get-Lines $f)
        Assert-Equal 'AWS_ACCESS_KEY_ID' $f[0].Location.Key
        Assert-Equal 1 (Get-SecretCount 'AW-SEC-002' $fx['aws']['positive'])
    }
    It 'ignores documentation placeholders, lowercase and longer words' {
        Assert-Equal 0 (Get-Rule $clean 'AW-SEC-002').Count
        Assert-Equal 0 (Get-SecretCount 'AW-SEC-002' $fx['aws']['negative'])
    }
}

Describe 'AW-SEC-003 Azure Storage account keys' {
    It 'finds AccountKey= in a connection string' {
        $f = Get-Rule $leaky 'AW-SEC-003'
        Assert-Equal @(15) (Get-Lines $f)
        Assert-Equal 'AccountKey' $f[0].Location.Key
        Assert-Equal ('Azure Storage account key: FAKE' + $ellipsis + 'ab (84 chars)') $f[0].Evidence
    }
    It 'ignores placeholders' {
        Assert-Equal 0 (Get-Rule $clean 'AW-SEC-003').Count
        Assert-Equal 0 (Get-SecretCount 'AW-SEC-003' $fx['azure']['negative'])
    }
}

Describe 'AW-SEC-004 OpenAI-style keys' {
    It 'finds project and legacy keys but not Anthropic keys' {
        Assert-Equal @(11) (Get-Lines (Get-Rule $leaky 'AW-SEC-004' 'mcp.json'))
        $env = Get-Rule $leaky 'AW-SEC-004' '.env'
        Assert-Equal @(3) (Get-Lines $env)
        Assert-Equal 'generic' $env[0].Harness
    }
    It 'ignores hyphenated words without digits' {
        Assert-Equal 0 (Get-Rule $clean 'AW-SEC-004').Count
        Assert-Equal 0 (Get-SecretCount 'AW-SEC-004' $fx['openai']['negative'])
    }
}

Describe 'AW-SEC-005 Anthropic keys' {
    It 'finds keys in MCP and Claude Code settings' {
        Assert-Equal @(12) (Get-Lines (Get-Rule $leaky 'AW-SEC-005' 'mcp.json'))
        $cc = Get-Rule $leaky 'AW-SEC-005' 'settings.json'
        Assert-Equal @(3) (Get-Lines $cc)
        Assert-Equal 'claude-code' $cc[0].Harness
    }
    It 'ignores keys without digits' {
        Assert-Equal 0 (Get-SecretCount 'AW-SEC-005' $fx['anthropic']['negative'])
        Assert-Equal 0 (Get-Rule $clean 'AW-SEC-005').Count
    }
}

Describe 'AW-SEC-006 Slack tokens' {
    It 'finds bot tokens' {
        Assert-Equal @(13) (Get-Lines (Get-Rule $leaky 'AW-SEC-006'))
        Assert-Equal 1 (Get-SecretCount 'AW-SEC-006' $fx['slack']['positive'])
    }
    It 'ignores placeholders without digits' {
        Assert-Equal 0 (Get-Rule $clean 'AW-SEC-006').Count
    }
}

Describe 'AW-SEC-007 private key blocks' {
    It 'reports the header without the key material' {
        $f = Get-Rule $leaky 'AW-SEC-007'
        Assert-Equal @(3) (Get-Lines $f)
        Assert-Equal 'Private key block (-----BEGIN RSA PRIVATE KEY-----); key material not shown' $f[0].Evidence
    }
    It 'knows the common headers and ignores public keys' {
        foreach ($h in @($fx['privateKey']['headers'])) {
            Assert-Equal 1 (Get-SecretCount 'AW-SEC-007' "x`n$h`nFAKE`n") $h
        }
        Assert-Equal 0 (Get-SecretCount 'AW-SEC-007' ("x`n" + $fx['privateKey']['publicHeader'] + "`nFAKE`n"))
        Assert-Equal 0 (Get-Rule $clean 'AW-SEC-007').Count
    }
}

Describe 'AW-SEC-008 JSON Web Tokens' {
    It 'finds a JWT, also at the end of a sentence' {
        $f = Get-Rule $leaky 'AW-SEC-008'
        Assert-Equal @(2) (Get-Lines $f)
        Assert-Equal 'medium' $f[0].Severity
        Assert-Equal 'SESSION_JWT' $f[0].Location.Key
        Assert-Equal 1 (Get-SecretCount 'AW-SEC-008' $fx['jwt']['endOfSentence'])
    }
    It 'ignores a lone JWT header' {
        Assert-Equal 0 (Get-Rule $clean 'AW-SEC-008').Count
        Assert-Equal 0 (Get-SecretCount 'AW-SEC-008' $fx['jwt']['headerOnly'])
    }
}

Describe 'AW-SEC-009 generic hard-coded values' {
    It 'finds password, secret and token assignments in JSON and .env files' {
        Assert-Equal @(4, 5) (Get-Lines (Get-Rule $leaky 'AW-SEC-009' '.env'))
        $j = Get-Rule $leaky 'AW-SEC-009' 'mcp.json'
        Assert-Equal @(16) (Get-Lines $j)
        Assert-Equal 'DB_PASSWORD' $j[0].Location.Key
        Assert-Equal 'medium' $j[0].Confidence
        Assert-Equal @('APP_SECRET', 'API_TOKEN') @((Get-Rule $leaky 'AW-SEC-009' '.env') | ForEach-Object { $_.Location.Key })
    }
    It 'does not repeat values already reported by a provider rule' {
        Assert-Equal 0 @((Get-Rule $leaky 'AW-SEC-009') | Where-Object { $_.Location.Line -ge 9 -and $_.Location.Line -le 13 -and $_.Location.Path -like '*mcp.json' }).Count
    }
    It 'ignores placeholders, references, paths, names and low-entropy values' {
        foreach ($p in @($clean, $hardened, $mixed, $edge)) { Assert-Equal 0 (Get-Rule $p 'AW-SEC-009').Count $p }
        foreach ($n in @($fx['generic']['negatives'])) { Assert-Equal 0 (Get-SecretCount 'AW-SEC-009' $n) $n }
    }
    It 'accepts high-entropy literals with various key styles' {
        foreach ($t in @($fx['generic']['positives'])) { Assert-Equal 1 (Get-SecretCount 'AW-SEC-009' $t) $t }
    }
    It 'computes the entropy filter in bits per character' {
        $e = & $aw { @((Get-AwSecEntropy 'aaaaaaaa'), (Get-AwSecEntropy 'abcdefgh'), (Get-AwSecEntropy '')) }
        Assert-Equal 0 ([int]$e[0]); Assert-Equal 3 ([int][Math]::Round($e[1])); Assert-Equal 0 ([int]$e[2])
    }
}

Describe 'AW-SEC-010 .env files' {
    It 'reports .env files at the root, not templates' {
        $f = Get-Rule $leaky 'AW-SEC-010'
        Assert-Equal @('.env', '.env.local') @($f | ForEach-Object { Split-Path -Leaf $_.Location.Path } | Sort-Object)
        Assert-Equal 'low' $f[0].Severity
        Assert-Match (@($f | Where-Object { $_.Location.Path -like '*\.env' })[0].Evidence) '\(4 variable assignment\(s\)\)'
    }
    It 'ignores folders without .env files and template files' {
        foreach ($p in @($clean, $edge, $insecure, $hardened)) { Assert-Equal 0 (Get-Rule $p 'AW-SEC-010').Count $p }
    }
}

Describe 'Secrets: caps, limits and hostile input' {
    It 'lists 25 matches per file and summarizes the rest' {
        $dir = Join-Path $tmp 'cap'
        $lines = foreach ($i in 1..40) { $fx['github']['capLine'] -f $i }
        New-TestFile (Join-Path $dir '.env') (($lines -join "`n") + "`n")
        $f = Get-Rule $dir 'AW-SEC-001'
        Assert-Equal 26 $f.Count
        $info = @($f | Where-Object { $_.Severity -eq 'info' })
        Assert-Equal 1 $info.Count
        Assert-Match $info[0].Evidence "^15 more 'GitHub token' match"
        Assert-Equal 25 @($f | Where-Object { $_.Severity -eq 'high' }).Count
    }
    It 'lists at most 200 matches per rule' {
        $dir = Join-Path $tmp 'many'
        foreach ($n in @('', '.a', '.b', '.c', '.d', '.e', '.f', '.g', '.h')) {
            $tag = ($n + 'zz').Substring(0, 2).Replace('.', 'q')
            $lines = foreach ($i in 1..25) { $fx['github']['manyLine'] -f $i, $tag }
            New-TestFile (Join-Path $dir ".env$n") (($lines -join "`n") + "`n")
        }
        $f = Get-Rule $dir 'AW-SEC-001'
        Assert-Equal 200 @($f | Where-Object { $_.Severity -eq 'high' }).Count
        Assert-True (@($f | Where-Object { $_.Severity -eq 'info' }).Count -ge 1)
    }
    It 'scans at most 2 MB of a text' {
        $token = $fx['github']['token']
        $pad = 'a ' * 1100000
        Assert-Equal 1 (Get-SecretCount 'AW-SEC-001' ($token + ' ' + $pad))
        Assert-Equal 0 (Get-SecretCount 'AW-SEC-001' ($pad + ' ' + $token))
    }
    It 'stays fast on text built to cause backtracking' {
        $h = $fx['hostile']
        $dir = Join-Path $tmp 'hostile'
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append($h['jwt'] * 60000); [void]$sb.Append("`n")
        [void]$sb.Append($h['jwt'] + ('a' * 5000) + '.' + $h['jwt'] + ('b' * 9000)); [void]$sb.Append("`n")
        [void]$sb.Append($h['openai'] + ('a' * 150000)); [void]$sb.Append("`n")
        [void]$sb.Append($h['assignment'] * 40000); [void]$sb.Append("`n")
        [void]$sb.Append($h['github'] + ('A' * 200000)); [void]$sb.Append("`n")
        [void]$sb.Append($h['azure'] + ('B' * 150000)); [void]$sb.Append("`n")
        [void]$sb.Append($h['pem'] + (' A' * 50000)); [void]$sb.Append("`n")
        [void]$sb.Append($h['slack'] + ('-' * 100000)); [void]$sb.Append("`n")
        [void]$sb.Append($h['lastLine']); [void]$sb.Append("`n")
        New-TestFile (Join-Path $dir '.env') $sb.ToString()
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $r = Get-Scan $dir
        $sw.Stop()
        Assert-True ($sw.Elapsed.TotalSeconds -lt 60) ("took {0:N1} s" -f $sw.Elapsed.TotalSeconds)
        Assert-Equal 0 @($r.Findings | Where-Object { $_.RuleId -eq 'AW-CORE-002' -and [string]$_.Location.Key -like 'AW-SEC-*' }).Count
        Assert-Equal 1 @($r.Findings | Where-Object { $_.RuleId -eq 'AW-SEC-001' }).Count
    }
    It 'never fails a rule on the shared fixtures' {
        foreach ($p in @($leaky, $clean, $insecure, $hardened, $mixed, $edge)) {
            $fail = @((Get-Scan $p).Findings | Where-Object { $_.RuleId -eq 'AW-CORE-002' -and [string]$_.Location.Key -like 'AW-SEC-*' })
            Assert-Equal 0 $fail.Count ("$p " + (($fail | ForEach-Object { $_.Evidence }) -join '; '))
        }
        Assert-Equal 0 @((Get-Scan $hardened).Findings | Where-Object { $_.RuleId -like 'AW-SEC-*' }).Count
        Assert-Equal 0 @((Get-Scan $mixed).Findings | Where-Object { $_.RuleId -like 'AW-SEC-*' }).Count
    }
}

} finally {
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}
