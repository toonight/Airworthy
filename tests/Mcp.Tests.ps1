# Tests for src/Rules/Mcp.ps1 (AW-MCP-001 to AW-MCP-006). Every secret below is FAKE.
$aw = Get-Module Airworthy
$fixtures = Join-Path $PSScriptRoot 'fixtures'
$area = Join-Path $fixtures 'mcp'
$tmp = Join-Path $area ('_tmp-' + [guid]::NewGuid().ToString('N'))
$utf8 = New-Object System.Text.UTF8Encoding($false)
$fakeGh = 'ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE12'

function New-McpCase {
    # A temporary folder holding the given files (relative path -> text).
    param([hashtable]$Files)
    $root = Join-Path $tmp ([guid]::NewGuid().ToString('N').Substring(0, 12))
    [void][System.IO.Directory]::CreateDirectory($root)
    foreach ($rel in $Files.Keys) {
        $p = Join-Path $root $rel
        [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $p))
        [System.IO.File]::WriteAllText($p, $Files[$rel], $utf8)
    }
    return $root
}

function Invoke-Rule {
    # Runs one rule's Check on the context of Root (no user profile unless one is given).
    param([string]$RuleId, [string]$Root, [string]$UserProfilePath)
    & $aw {
        param($id, $r, $u)
        if (-not $script:AwRules.ContainsKey($id)) { throw "Rule $id is not registered" }
        $ctx = if ($u) { New-AwContext -Path $r -UserProfilePath $u } else { New-AwContext -Path $r -NoUserProfile }
        @(& $script:AwRules[$id].Check $ctx)
    } $RuleId $Root $UserProfilePath
}

function Get-ServerFindings {
    # Findings of a rule for one VS Code server entry (JSON text of the server object).
    param([string]$RuleId, [string]$Server)
    $root = New-McpCase @{ '.vscode\mcp.json' = ('{ "servers": { "s": ' + $Server + ' } }') }
    @(Invoke-Rule $RuleId $root)
}

function Get-FixtureServerNames {
    # Server names of a fixture folder's .vscode/mcp.json, read with the module's own JSONC parser.
    param([string]$Dir)
    & $aw {
        param($p)
        $d = ConvertFrom-AwJsonc -Text ([System.IO.File]::ReadAllText($p))
        [string[]]@($d['servers'].Keys)
    } ([System.IO.Path]::Combine([System.IO.Path]::Combine($Dir, '.vscode'), 'mcp.json'))
}

function Assert-Flags([string]$RuleId, [string]$Server, [string]$Message) {
    $f = @(Get-ServerFindings $RuleId $Server)
    Assert-Equal 1 $f.Count ("expected one $RuleId finding: $Message")
    return $f[0]
}

function Assert-Silent([string]$RuleId, [string]$Server, [string]$Message) {
    $f = @(Get-ServerFindings $RuleId $Server)
    Assert-Equal 0 $f.Count ("expected no $RuleId finding: $Message")
}

try {
    Describe 'MCP rules: registration' {
        It 'registers AW-MCP-001 to AW-MCP-006 with complete metadata' {
            $rules = @(& $aw { Get-AwRules } | Where-Object { $_.Id -like 'AW-MCP-*' })
            Assert-Equal @('AW-MCP-001', 'AW-MCP-002', 'AW-MCP-003', 'AW-MCP-004', 'AW-MCP-005', 'AW-MCP-006') @($rules | ForEach-Object { $_.Id })
            foreach ($r in $rules) {
                Assert-Equal 'mcp' $r.Harness $r.Id
                Assert-True ($r.Description.Length -gt 80) $r.Id
                Assert-True ($r.Fix.Length -gt 20) $r.Id
                Assert-True (@($r.References | Where-Object { $_ -like 'OWASP-ASI*' }).Count -ge 1) $r.Id
                Assert-True (@($r.References | Where-Object { $_ -like 'https://*' }).Count -ge 1) $r.Id
            }
            Assert-Equal 'critical' @($rules | Where-Object { $_.Id -eq 'AW-MCP-002' })[0].Severity
            Assert-Equal 'secrets' @($rules | Where-Object { $_.Id -eq 'AW-MCP-002' })[0].Category
            Assert-Equal 'medium' @($rules | Where-Object { $_.Id -eq 'AW-MCP-004' })[0].Confidence
            Assert-Equal 'info' @($rules | Where-Object { $_.Id -eq 'AW-MCP-006' })[0].Severity
        }
    }

    Describe 'AW-MCP-001 unpinned launchers' {
        It 'flags npx without a version, with its location' {
            $f = Assert-Flags 'AW-MCP-001' '{ "command": "npx", "args": ["-y", "@example/server"] }' 'npx -y'
            Assert-Match $f.Evidence "server 's': npx runs '@example/server' without a pinned version"
            Assert-Equal 's.command' $f.Location.Key
            Assert-Equal 1 $f.Location.Line
            Assert-Match $f.Location.Path 'mcp\.json$'
        }
        It 'flags @latest, tags and ranges' {
            Assert-Flags 'AW-MCP-001' '{ "command": "npx", "args": ["-y", "@example/server@latest"] }' '@latest' | Out-Null
            Assert-Flags 'AW-MCP-001' '{ "command": "npx", "args": ["example-server@next"] }' 'tag' | Out-Null
            Assert-Flags 'AW-MCP-001' '{ "command": "npx", "args": ["example-server@^1.2.0"] }' 'range' | Out-Null
            Assert-Flags 'AW-MCP-001' '{ "command": "npx", "args": ["--package=example-server", "example"] }' '--package=' | Out-Null
            Assert-Flags 'AW-MCP-001' '{ "command": "npx", "args": ["-p", "example-server", "example"] }' '-p' | Out-Null
        }
        It 'flags the other package launchers' {
            foreach ($s in @(
                '{ "command": "npm", "args": ["exec", "example-server"] }',
                '{ "command": "pnpm", "args": ["dlx", "example-server"] }',
                '{ "command": "yarn", "args": ["dlx", "example-server"] }',
                '{ "command": "bunx", "args": ["example-server"] }',
                '{ "command": "uvx", "args": ["example-server"] }',
                '{ "command": "uvx", "args": ["example-server@latest"] }',
                '{ "command": "uvx", "args": ["--from", "example-server>=1.0", "example"] }',
                '{ "command": "uv", "args": ["tool", "run", "example-server"] }',
                '{ "command": "pipx", "args": ["run", "example-server"] }'
            )) { Assert-Flags 'AW-MCP-001' $s $s | Out-Null }
        }
        It 'flags docker images without a fixed tag or digest' {
            Assert-Flags 'AW-MCP-001' '{ "command": "docker", "args": ["run", "-i", "--rm", "-e", "TOKEN", "ghcr.io/example/server"] }' 'no tag' | Out-Null
            $f = Assert-Flags 'AW-MCP-001' '{ "command": "podman", "args": ["run", "-i", "example/server:latest"] }' 'latest'
            Assert-Match $f.Evidence "podman run uses image 'example/server:latest'"
        }
        It 'unwraps cmd /c, command strings and full paths' {
            Assert-Flags 'AW-MCP-001' '{ "command": "cmd", "args": ["/c", "npx", "-y", "@example/server"] }' 'cmd /c' | Out-Null
            Assert-Flags 'AW-MCP-001' '{ "command": "npx -y @example/server" }' 'command string' | Out-Null
            Assert-Flags 'AW-MCP-001' '{ "command": "C:\\Program Files\\nodejs\\npx.cmd", "args": ["-y", "@example/server"] }' 'full path' | Out-Null
            Assert-Flags 'AW-MCP-001' '{ "command": "bash", "args": ["-c", "npx -y @example/server"] }' 'bash -c' | Out-Null
        }
        It 'reports one finding per server' {
            Assert-Flags 'AW-MCP-001' '{ "command": "cmd", "args": ["/c", "npx", "-y", "@example/server@latest"] }' 'wrapper and inner' | Out-Null
        }
        It 'accepts exact versions, digests and local commands' {
            foreach ($s in @(
                '{ "command": "npx", "args": ["-y", "@example/server@1.4.2"] }',
                '{ "command": "npx", "args": ["--yes", "example-server@2.0.0-beta.1"] }',
                '{ "command": "npx", "args": ["-p", "example-server@1.0.0", "example"] }',
                '{ "command": "npx", "args": ["./tools/local-server"] }',
                '{ "command": "uvx", "args": ["example-server==1.2.3"] }',
                '{ "command": "uvx", "args": ["example-server@1.2.3"] }',
                '{ "command": "uvx", "args": ["--from", "example-server==1.0.0", "example"] }',
                '{ "command": "pipx", "args": ["run", "--spec", "example-server==1.0", "example"] }',
                '{ "command": "docker", "args": ["run", "-i", "--rm", "example/server:1.2.3"] }',
                '{ "command": "docker", "args": ["run", "-i", "example/server@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"] }',
                '{ "command": "docker", "args": ["ps"] }',
                '{ "command": "node", "args": ["server.js"] }',
                '{ "command": "cmd", "args": ["/c", "npx", "-y", "@example/server@3.0.1"] }',
                '{ "type": "http", "url": "https://mcp.example.invalid/mcp" }'
            )) { Assert-Silent 'AW-MCP-001' $s $s }
        }
    }

    Describe 'AW-MCP-002 hardcoded secrets' {
        It 'flags a token in env and masks it' {
            $f = Assert-Flags 'AW-MCP-002' ('{ "command": "node", "args": ["s.js"], "env": { "GITHUB_TOKEN": "' + $fakeGh + '" } }') 'env token'
            Assert-Match $f.Evidence "server 's': env GITHUB_TOKEN = ghp_"
            Assert-NotMatch $f.Evidence 'FAKEFAKEFAKEFAKEFAKE'
            Assert-Equal 's.env.GITHUB_TOKEN' $f.Location.Key
            Assert-Equal 'critical' $f.Severity
        }
        It 'flags literal values under secret-looking names' {
            $f = Assert-Flags 'AW-MCP-002' '{ "command": "node", "env": { "EXAMPLE_API_KEY": "FAKE-example-key-123456" } }' 'API key'
            Assert-NotMatch $f.Evidence 'FAKE-example-key-123456'
            Assert-Flags 'AW-MCP-002' '{ "command": "node", "env": { "DB_PASSWORD": "FAKEpassw0rd!" } }' 'password' | Out-Null
            Assert-Flags 'AW-MCP-002' '{ "command": "node", "env": { "CONFIG": "sk-ant-FAKEFAKEFAKEFAKEFAKE0123" } }' 'token format, neutral name' | Out-Null
        }
        It 'flags secrets in headers, args and URLs' {
            $f = Assert-Flags 'AW-MCP-002' '{ "type": "http", "url": "https://x.example.invalid/mcp", "headers": { "Authorization": "Bearer FAKEtoken0123456789abcdef" } }' 'header'
            Assert-Match $f.Evidence 'headers Authorization = Bearer FAKE'
            Assert-NotMatch $f.Evidence 'FAKEtoken0123456789abcdef'
            Assert-Flags 'AW-MCP-002' '{ "command": "example-server", "args": ["--api-key=FAKE0123456789abcdef"] }' '--flag=value' | Out-Null
            Assert-Flags 'AW-MCP-002' '{ "command": "example-server", "args": ["--token", "FAKE0123456789abcdef"] }' '--flag value' | Out-Null
            Assert-Flags 'AW-MCP-002' '{ "command": "npx", "args": ["mcp-remote@1.0.0", "https://x.example.invalid", "--header", "Authorization: Bearer FAKE0123456789abcdef"] }' 'header arg' | Out-Null
            Assert-Flags 'AW-MCP-002' '{ "type": "http", "url": "https://x.example.invalid/mcp?api_key=FAKE0123456789abcdef" }' 'query' | Out-Null
            $u = Assert-Flags 'AW-MCP-002' '{ "command": "example-server", "args": ["postgres://admin:FAKEsecret99@db.example.invalid/app"] }' 'user info'
            Assert-NotMatch $u.Evidence 'FAKEsecret99'
        }
        It 'reports each secret once' {
            $f = @(Get-ServerFindings 'AW-MCP-002' ('{ "command": "node", "env": { "A_TOKEN": "' + $fakeGh + '", "B_SECRET": "FAKE-second-secret-0001" } }'))
            Assert-Equal 2 $f.Count
        }
        It 'accepts references, placeholders and non-secret values' {
            foreach ($s in @(
                '{ "command": "node", "env": { "API_KEY": "${input:api-key}" } }',
                '{ "command": "node", "env": { "API_KEY": "${env:EXAMPLE_KEY}" } }',
                '{ "command": "node", "env": { "API_KEY": "${EXAMPLE_KEY}", "TOKEN": "${EXAMPLE_TOKEN:-}" } }',
                '{ "command": "node", "env": { "API_KEY": "$EXAMPLE_KEY", "SECRET": "%EXAMPLE_SECRET%" } }',
                '{ "command": "node", "env": { "API_KEY": "<your-api-key>", "TOKEN": "YOUR_TOKEN_HERE", "SECRET": "xxxxxxxxxxxx" } }',
                '{ "command": "node", "env": { "OPENAI_API_KEY": "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxx" } }',
                '{ "command": "node", "env": { "GOOGLE_APPLICATION_CREDENTIALS": "/secrets/creds.json", "TOKEN_ENDPOINT": "https://login.example.invalid/token" } }',
                '{ "command": "node", "env": { "SESSION_TIMEOUT": "86400000", "AUTH_ENABLED": "true", "PASS": "short" } }',
                '{ "command": "node", "env": { "NODE_ENV": "production", "LOG_LEVEL": "debugverbose" } }',
                '{ "type": "http", "url": "https://x.example.invalid/mcp", "headers": { "Authorization": "Bearer ${input:token}" } }',
                '{ "command": "example-server", "args": ["--token", "${input:token}", "--config", "settings.json"] }',
                '{ "command": "example-server", "args": ["--key-file", "./keys/server.pem"] }'
            )) { Assert-Silent 'AW-MCP-002' $s $s }
        }
    }

    Describe 'AW-MCP-003 cleartext remote servers' {
        It 'flags http:// and ws:// on a remote host, without the query string' {
            $f = Assert-Flags 'AW-MCP-003' '{ "type": "http", "url": "http://mcp.example.invalid/mcp?key=FAKE0123456789" }' 'http'
            Assert-Equal "server 's': url http://mcp.example.invalid/mcp (unencrypted)" $f.Evidence
            Assert-Equal 's.url' $f.Location.Key
            Assert-Flags 'AW-MCP-003' '{ "type": "ws", "url": "ws://10.0.0.5:9000/mcp" }' 'ws' | Out-Null
            Assert-Flags 'AW-MCP-003' '{ "type": "sse", "url": "HTTP://user@mcp.example.invalid:8080/sse" }' 'upper case, user info' | Out-Null
        }
        It 'accepts https, loopback hosts, variables and stdio servers' {
            foreach ($s in @(
                '{ "type": "http", "url": "https://mcp.example.invalid/mcp" }',
                '{ "type": "http", "url": "http://localhost:8099/mcp" }',
                '{ "type": "http", "url": "http://127.0.0.1:3000/mcp" }',
                '{ "type": "http", "url": "http://[::1]:3000/mcp" }',
                '{ "type": "http", "url": "http://tools.localhost/mcp" }',
                '{ "type": "http", "url": "http://${input:host}/mcp" }',
                '{ "command": "node", "args": ["server.js"] }'
            )) { Assert-Silent 'AW-MCP-003' $s $s }
        }
    }

    Describe 'AW-MCP-004 inline shell or interpreter code' {
        # The shell and interpreter cases live in JSON fixtures (CONTRIBUTING.md, Antivirus hygiene): names and flags only,
        # with the placeholder PAYLOAD instead of code.
        It 'flags every server of the mcp/inline-flagged fixture once' {
            $dir = Join-Path $area 'inline-flagged'
            $names = @(Get-FixtureServerNames $dir)
            Assert-True ($names.Count -ge 15) 'fixture size'
            $f = @(Invoke-Rule 'AW-MCP-004' $dir)
            $keys = @($f | ForEach-Object { $_.Location.Key } | Sort-Object)
            Assert-Equal @($names | ForEach-Object { $_ + '.command' } | Sort-Object) $keys
            foreach ($x in $f) { Assert-Equal 'medium' $x.Severity $x.Location.Key }
        }
        It 'never shows an encoded value and keeps the evidence readable' {
            $f = @(Invoke-Rule 'AW-MCP-004' (Join-Path $area 'inline-flagged'))
            $byKey = @{}; foreach ($x in $f) { $byKey[$x.Location.Key] = $x.Evidence }
            foreach ($k in @('ps-encoded.command', 'pwsh-e.command', 'pwsh-ec.command')) {
                Assert-Match $byKey[$k] 'encoded value not shown' $k
                Assert-NotMatch $byKey[$k] 'PAYLOAD' $k
            }
            Assert-Equal "server 'cmd-pipe': cmd /c 'PAYLOAD | more'" $byKey['cmd-pipe.command']
            Assert-Equal "server 'wsl-bash': bash -c './server'" $byKey['wsl-bash.command']
            Assert-Equal "server 'node-eval': node --eval=PAYLOAD 'PAYLOAD'" $byKey['node-eval.command']
            Assert-Match $byKey['python-cluster.command'] "python -Ic 'PAYLOAD'"
        }
        It 'shows the masked code in the evidence' {
            $f = Assert-Flags 'AW-MCP-004' ('{ "command": "bash", "args": ["-c", "TOKEN=' + $fakeGh + ' ./server"] }') 'masked'
            Assert-Match $f.Evidence "server 's': bash -c 'TOKEN=ghp_"
            Assert-NotMatch $f.Evidence 'FAKEFAKEFAKEFAKEFAKE'
        }
        It 'accepts plain launchers, scripts and modules (mcp/inline-silent fixture)' {
            $dir = Join-Path $area 'inline-silent'
            Assert-True (@(Get-FixtureServerNames $dir).Count -ge 10) 'fixture size'
            Assert-Equal 0 @(Invoke-Rule 'AW-MCP-004' $dir).Count
        }
        It 'reads the shell and interpreter tokens from src/Data/mcp.json' {
            $d = & $aw { Get-AwMcpData }
            Assert-True ($d -is [System.Collections.IDictionary])
            foreach ($k in @('cmd', 'powershell', 'posixShells', 'wsl', 'interpreters')) { Assert-True ($d.Contains($k)) $k }
            Assert-Contains @(& $aw { Get-AwMcpDataList (Get-AwMcpData)['powershell'] 'programs' }) 'pwsh'
        }
        It 'reports a missing data file as a rule failure, not a crash' {
            & $aw { param($dir) $script:AwMcpSavedDataPath = $script:AwMcpDataPath; $script:AwMcpDataPath = [System.IO.Path]::Combine($dir, 'no-such-data.json'); $script:AwMcpData = $null } $area
            try {
                $r = Invoke-Airworthy -Path (Join-Path $area 'inline-flagged') -NoUserProfile -PassThru -Quiet
                Assert-True (@($r.Findings | Where-Object { $_.RuleId -eq 'AW-CORE-002' -and $_.Location.Key -eq 'AW-MCP-004' }).Count -eq 1)
                Assert-Equal 0 @($r.Findings | Where-Object { $_.RuleId -eq 'AW-MCP-004' }).Count
            } finally {
                & $aw { $script:AwMcpDataPath = $script:AwMcpSavedDataPath; $script:AwMcpData = $null }
            }
            Assert-True (@(Invoke-Rule 'AW-MCP-004' (Join-Path $area 'inline-flagged')).Count -gt 0) 'restored'
        }
    }

    Describe 'AW-MCP-005 docker options that break isolation' {
        It 'flags privileged mode, host namespaces and broad capabilities' {
            $f = Assert-Flags 'AW-MCP-005' '{ "command": "docker", "args": ["run", "-i", "--privileged", "example/server:1.0.0"] }' 'privileged'
            Assert-Match $f.Evidence '--privileged'
            Assert-Flags 'AW-MCP-005' '{ "command": "docker", "args": ["run", "-i", "--network", "host", "example/server:1.0.0"] }' 'network host' | Out-Null
            Assert-Flags 'AW-MCP-005' '{ "command": "docker", "args": ["run", "--net=host", "example/server:1.0.0"] }' 'net=host' | Out-Null
            Assert-Flags 'AW-MCP-005' '{ "command": "docker", "args": ["run", "--pid=host", "example/server:1.0.0"] }' 'pid host' | Out-Null
            Assert-Flags 'AW-MCP-005' '{ "command": "docker", "args": ["run", "--cap-add", "SYS_ADMIN", "example/server:1.0.0"] }' 'cap-add' | Out-Null
        }
        It 'flags mounts of the root, the home directory and the Docker socket' {
            foreach ($s in @(
                '{ "command": "docker", "args": ["run", "-v", "/:/host", "example/server:1.0.0"] }',
                '{ "command": "docker", "args": ["run", "-v", "C:\\:/host", "example/server:1.0.0"] }',
                '{ "command": "docker", "args": ["run", "--volume", "${userHome}:/home/app", "example/server:1.0.0"] }',
                '{ "command": "docker", "args": ["run", "-v", "${env:USERPROFILE}:/home/app", "example/server:1.0.0"] }',
                '{ "command": "docker", "args": ["run", "-v", "~:/root", "example/server:1.0.0"] }',
                '{ "command": "docker", "args": ["run", "-v", "C:\\Users\\example:/data", "example/server:1.0.0"] }',
                '{ "command": "docker", "args": ["run", "-v", "/var/run/docker.sock:/var/run/docker.sock", "example/server:1.0.0"] }',
                '{ "command": "docker", "args": ["run", "--mount", "type=bind,source=/,target=/host", "example/server:1.0.0"] }',
                '{ "command": "cmd", "args": ["/c", "docker", "run", "-v", "/home/dev:/data", "example/server:1.0.0"] }'
            )) { Assert-Flags 'AW-MCP-005' $s $s | Out-Null }
        }
        It 'flags a mount of the analyzed user profile' {
            $profileDir = New-McpCase @{ 'placeholder.txt' = 'synthetic' }
            $json = '{ "servers": { "s": { "command": "docker", "args": ["run", "-v", "' + $profileDir.Replace('\', '\\') + ':/data", "example/server:1.0.0"] } } }'
            $root = New-McpCase @{ '.vscode\mcp.json' = $json }
            Assert-Equal 1 @(Invoke-Rule 'AW-MCP-005' $root $profileDir).Count
        }
        It 'reports each risky option' {
            Assert-Equal 2 @(Get-ServerFindings 'AW-MCP-005' '{ "command": "docker", "args": ["run", "--privileged", "-v", "/:/host", "example/server:1.0.0"] }').Count
        }
        It 'accepts scoped mounts and safe options' {
            foreach ($s in @(
                '{ "command": "docker", "args": ["run", "-i", "--rm", "-v", "${workspaceFolder}:/workspace:ro", "example/server:1.0.0"] }',
                '{ "command": "docker", "args": ["run", "--network", "none", "--privileged=false", "example/server:1.0.0"] }',
                '{ "command": "docker", "args": ["run", "-v", "/home/dev/project:/data", "-v", "cache:/cache", "example/server:1.0.0"] }',
                '{ "command": "docker", "args": ["run", "example/server:1.0.0", "--privileged"] }',
                '{ "command": "docker", "args": ["exec", "--privileged", "box", "server"] }',
                '{ "command": "node", "args": ["--privileged"] }'
            )) { Assert-Silent 'AW-MCP-005' $s $s }
        }
    }

    Describe 'AW-MCP-006 server count' {
        It 'reports more than 10 servers across files' {
            $f = @(Invoke-Rule 'AW-MCP-006' (Join-Path $area 'repo'))
            Assert-Equal 1 $f.Count
            Assert-Match $f[0].Evidence '^12 MCP servers configured \(threshold 10\): \.vscode\\mcp\.json: 6; \.mcp\.json: 6$'
            Assert-Equal 'info' $f[0].Severity
        }
        It 'is silent at 10 servers or fewer' {
            $servers = (1..10 | ForEach-Object { '"s{0}": {{ "command": "node", "args": ["s{0}.js"] }}' -f $_ }) -join ', '
            $root = New-McpCase @{ '.mcp.json' = ('{ "mcpServers": { ' + $servers + ' } }') }
            Assert-Equal 0 @(Invoke-Rule 'AW-MCP-006' $root).Count
            Assert-Equal 0 @(Invoke-Rule 'AW-MCP-006' (Join-Path $area 'clean')).Count
        }
    }

    Describe 'MCP rules: fixtures and clients' {
        It 'finds every issue of the mcp/repo fixture' {
            $r = Invoke-Airworthy -Path (Join-Path $area 'repo') -NoUserProfile -PassThru -Quiet
            $mine = @($r.Findings | Where-Object { $_.RuleId -like 'AW-MCP-*' })
            Assert-Equal @('AW-MCP-002', 'AW-MCP-001', 'AW-MCP-003', 'AW-MCP-005', 'AW-MCP-005', 'AW-MCP-004', 'AW-MCP-006') @($mine | ForEach-Object { $_.RuleId })
            $keys = @($mine | ForEach-Object { $_.Location.Key })
            foreach ($k in @('unpinned.command', 'secret-env.env.EXAMPLE_API_KEY', 'cleartext.url', 'inline.command', 'container.args')) { Assert-Contains $keys $k }
            Assert-NotContains $keys 'safe.command'
            Assert-NotMatch (($mine | ForEach-Object { $_.Evidence }) -join "`n") 'FAKE-example-api-key-0001'
        }
        It 'is silent on the mcp/clean fixture' {
            $r = Invoke-Airworthy -Path (Join-Path $area 'clean') -NoUserProfile -PassThru -Quiet
            Assert-Equal 0 @($r.Findings | Where-Object { $_.RuleId -like 'AW-MCP-*' }).Count
        }
        It 'analyzes the Copilot CLI and ~/.claude.json servers of the user profile' {
            $root = New-McpCase @{ 'README.md' = 'synthetic' }
            $profileDir = Join-Path $area 'profile'
            $unpinned = @(Invoke-Rule 'AW-MCP-001' $root $profileDir)
            Assert-Equal @('cli-tool.command') @($unpinned | ForEach-Object { $_.Location.Key })
            $secrets = @(Invoke-Rule 'AW-MCP-002' $root $profileDir)
            Assert-Equal 2 $secrets.Count
            $keys = @($secrets | ForEach-Object { $_.Location.Key })
            Assert-Contains $keys 'user-search.url'
            Assert-Contains $keys 'alpha-db (project: D:/work/alpha).env.DB_PASSWORD'
            $alpha = @($secrets | Where-Object { $_.Location.Key -like 'alpha-db*' })[0]
            Assert-Equal 8 $alpha.Location.Line
            Assert-NotMatch (($secrets | ForEach-Object { $_.Evidence }) -join "`n") 'FAKE-db-password-42|FAKEFAKE0123456789key'
        }
        It 'reports the shared insecure fixture and stays silent on hardened' {
            $r = Invoke-Airworthy -Path (Join-Path $fixtures 'insecure') -NoUserProfile -PassThru -Quiet
            $ids = @($r.Findings | ForEach-Object { $_.RuleId })
            foreach ($id in @('AW-MCP-001', 'AW-MCP-002', 'AW-MCP-003')) { Assert-Contains $ids $id }
            Assert-Equal 4 @($r.Findings | Where-Object { $_.RuleId -eq 'AW-MCP-001' }).Count
            Assert-Equal 1 @($r.Findings | Where-Object { $_.RuleId -eq 'AW-MCP-001' -and $_.Location.Path -like '*\.codex\config.toml' }).Count
            Assert-NotMatch (($r.Findings | ForEach-Object { $_.Evidence }) -join "`n") 'FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234'
            $h = Invoke-Airworthy -Path (Join-Path $fixtures 'hardened') -NoUserProfile -PassThru -Quiet
            Assert-Equal 0 @($h.Findings | Where-Object { $_.RuleId -like 'AW-MCP-*' }).Count
            $m = Invoke-Airworthy -Path (Join-Path $fixtures 'mixed') -NoUserProfile -PassThru -Quiet
            Assert-Equal @('unpinned-search.command') @($m.Findings | Where-Object { $_.RuleId -like 'AW-MCP-*' } | ForEach-Object { $_.Location.Key })
        }
    }

    Describe 'MCP rules: evidence masking' {
        It 'masks secret flags, pairs, URL passwords and tokens in command lines' {
            $mask = { param($t) & $aw { param($x) Format-AwCommandSnippet -Text $x -Max 400 } $t }
            $out = & $mask ('npx -y pkg --api-key=FAKE-abc-123 --token FAKE-def-456 TOKEN=FAKEshort -H "Authorization: Bearer FAKE-ghi" ' +
                            'postgres://admin:FAKEpw@db.example.invalid ' + $fakeGh + ' --port 3000 KEY=${input:k}')
            foreach ($secret in @('FAKE-abc-123', 'FAKE-def-456', 'FAKEshort', 'FAKE-ghi', 'FAKEpw', 'FAKEFAKEFAKEFAKE')) { Assert-NotMatch $out ([regex]::Escape($secret)) }
            Assert-Match $out '--api-key=FAKE\S+ \(12 chars\) --token FAKE\S+ \(12 chars\) TOKEN=\*\*\*\* '
            Assert-Match $out 'Bearer \*\*\*\*"'
            Assert-Match $out '--port 3000'
            Assert-Match $out ([regex]::Escape('KEY=${input:k}'))
            Assert-Equal 'npx -y @example/auth-server --port 3000' (& $mask 'npx -y @example/auth-server --port 3000')
        }
        It 'never shows a short secret flag of an unpinned server' {
            $f = Assert-Flags 'AW-MCP-001' '{ "command": "npx", "args": ["-y", "@example/server", "--api-key=FAKE-abc-123", "--password", "FAKEpw12"] }' 'masked'
            Assert-NotMatch $f.Evidence 'FAKE-abc-123|FAKEpw12'
            $g = Assert-Flags 'AW-MCP-004' '{ "command": "bash", "args": ["-c", "DB_PASSWORD=FAKEpw12 ./server --secret FAKE-s3"] }' 'masked inline code'
            Assert-NotMatch $g.Evidence 'FAKEpw12|FAKE-s3'
        }
    }

    Describe 'MCP rules: hostile input' {
        It 'ignores malformed server fields without failing' {
            $json = '{ "servers": { "a": { "command": 42, "args": { "x": 1 }, "env": ["A"], "headers": "x", "url": ["http://x"] },' +
                    ' "b": { "command": ["npx"], "args": "-y @example/server" }, "c": { "command": "", "args": [null, true, 1.5, {"k": "v"}] },' +
                    ' "d": { "command": "npx", "args": "-y @example/from-string" } } }'
            $root = New-McpCase @{ '.vscode\mcp.json' = $json }
            $all = @()
            foreach ($id in @('AW-MCP-001', 'AW-MCP-002', 'AW-MCP-003', 'AW-MCP-004', 'AW-MCP-005', 'AW-MCP-006')) { $all += @(Invoke-Rule $id $root) }
            Assert-Equal @('d.command') @($all | ForEach-Object { $_.Location.Key })
        }
        It 'stays fast on a huge command line' {
            $long = 'x' * 200000
            $root = New-McpCase @{ '.vscode\mcp.json' = ('{ "servers": { "big": { "command": "bash", "args": ["-c", "' + $long + '"], "env": { "TOKEN": "' + $long + '" } } } }') }
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $f = @(Invoke-Rule 'AW-MCP-004' $root)
            $s = @(Invoke-Rule 'AW-MCP-002' $root)
            $sw.Stop()
            Assert-Equal 1 $f.Count
            Assert-True ($f[0].Evidence.Length -lt 200)
            Assert-True ($sw.Elapsed.TotalSeconds -lt 10) ('took {0:N1}s' -f $sw.Elapsed.TotalSeconds)
            Assert-Equal 0 $s.Count
        }
        It 'runs through the engine without a rule failure' {
            $r = Invoke-Airworthy -Path (Join-Path $area 'repo') -UserProfilePath (Join-Path $area 'profile') -PassThru -Quiet
            Assert-Equal 0 @($r.Findings | Where-Object { $_.RuleId -eq 'AW-CORE-002' -and $_.Location.Key -like 'AW-MCP-*' }).Count
        }
    }
} finally {
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force }
}
