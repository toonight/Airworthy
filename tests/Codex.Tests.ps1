# Tests for Codex CLI support: discovery (src/Core/Discovery.ps1, nested project layers and the system
# config included), the mapping of Codex MCP servers into Ctx.McpFiles, and the rules of
# src/Rules/Codex.ps1 (AW-CDX-001 to AW-CDX-014) with their layer stacks.
# Every secret below is FAKE; the ones of the fixtures are listed in fixtures\codex\strings.json.
$aw = Get-Module Airworthy
$fixtures = Join-Path $PSScriptRoot 'fixtures'
$area = Join-Path $fixtures 'codex'
$tmp = Join-Path $area ('_tmp-' + [guid]::NewGuid().ToString('N'))
$utf8 = New-Object System.Text.UTF8Encoding($false)
$profileInsecure = Join-Path $area 'profile-insecure'
$profileHardened = Join-Path $area 'profile-hardened'
$projectInsecure = Join-Path $area 'project-insecure'
$projectHardened = Join-Path $area 'project-hardened'
$projectInvalid = Join-Path $area 'project-invalid'
$managedFile = Join-Path $area 'managed\requirements.toml'
$strings = & $aw { param($p) ConvertFrom-AwJsonc -Text ([System.IO.File]::ReadAllText($p)) } (Join-Path $area 'strings.json')
$FakeSecrets = @($strings['fakeSecrets'])

function Toml {
    # TOML text from lines.
    param([Parameter(ValueFromRemainingArguments = $true)] [string[]]$Lines)
    return (($Lines -join "`n") + "`n")
}

function New-CdxTree {
    # A temporary folder holding the given files (relative path -> text).
    param([hashtable]$Files)
    $root = Join-Path $tmp ([guid]::NewGuid().ToString('N').Substring(0, 12))
    [void][System.IO.Directory]::CreateDirectory($root)
    if ($Files) {
        foreach ($rel in $Files.Keys) {
            $p = Join-Path $root $rel
            [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $p))
            [System.IO.File]::WriteAllText($p, $Files[$rel], $utf8)
        }
    }
    return $root
}

function New-CdxCase {
    # A project folder, and a user profile folder when user files, requirements or a system config are given.
    param([string]$User, [string]$Project, [hashtable]$UserFiles, [hashtable]$ProjectFiles, [string]$Requirements, [string]$System)
    $pf = @{ 'README.md' = 'synthetic' }
    if ($Project) { $pf['.codex\config.toml'] = $Project }
    if ($ProjectFiles) { foreach ($k in $ProjectFiles.Keys) { $pf[$k] = $ProjectFiles[$k] } }
    $userDir = $null
    if ($User -or $UserFiles -or $Requirements -or $System) {
        $uf = @{ 'placeholder.txt' = 'synthetic' }
        if ($User) { $uf['.codex\config.toml'] = $User }
        if ($UserFiles) { foreach ($k in $UserFiles.Keys) { $uf[$k] = $UserFiles[$k] } }
        $userDir = New-CdxTree $uf
    }
    $req = $null
    if ($Requirements) { $req = Join-Path (New-CdxTree @{ 'requirements.toml' = $Requirements }) 'requirements.toml' }
    $sys = $null
    if ($System) { $sys = Join-Path (New-CdxTree @{ 'config.toml' = $System }) 'config.toml' }
    [pscustomobject]@{ Root = (New-CdxTree $pf); User = $userDir; Requirements = $req; System = $sys }
}

function Get-CdxContext {
    # The analysis context of a case; requirements.toml and the system config.toml are read through the test hooks.
    param($Case)
    $sys = $null
    if ($Case.PSObject.Properties['System']) { $sys = $Case.System }
    & $aw {
        param($r, $u, $q, $s)
        $script:AwCodexRequirementsOverride = if ($q) { @($q) } else { $null }
        $script:AwCodexSystemConfigOverride = if ($s) { @($s) } else { $null }
        try {
            if ($u) { New-AwContext -Path $r -UserProfilePath $u } else { New-AwContext -Path $r -NoUserProfile }
        } finally {
            $script:AwCodexRequirementsOverride = $null
            $script:AwCodexSystemConfigOverride = $null
        }
    } $Case.Root $Case.User $Case.Requirements $sys
}

function Invoke-CdxCheck {
    # Runs one rule's Check on a context.
    param([string]$RuleId, $Ctx)
    & $aw {
        param($id, $c)
        if (-not $script:AwRules.ContainsKey($id)) { throw "Rule $id is not registered" }
        @(& $script:AwRules[$id].Check $c)
    } $RuleId $Ctx
}

function Invoke-CdxRule {
    # Runs one rule on a case built from TOML texts.
    param([string]$RuleId, [string]$User, [string]$Project, [hashtable]$UserFiles, [hashtable]$ProjectFiles, [string]$Requirements, [string]$System)
    $case = New-CdxCase -User $User -Project $Project -UserFiles $UserFiles -ProjectFiles $ProjectFiles -Requirements $Requirements -System $System
    Invoke-CdxCheck $RuleId (Get-CdxContext $case)
}

function Invoke-CdxFixture {
    # Runs one rule on fixture folders.
    param([string]$RuleId, [string]$Root, [string]$User, [string]$Requirements)
    Invoke-CdxCheck $RuleId (Get-CdxContext ([pscustomobject]@{ Root = $Root; User = $User; Requirements = $Requirements }))
}

function New-CdxJunction {
    # A junction at Path to Target; $false when the file system does not allow it.
    param([string]$Path, [string]$Target)
    try {
        [void](New-Item -ItemType Junction -Path $Path -Target $Target -ErrorAction Stop)
        return $true
    } catch {
        return $false
    }
}

function Join-CdxHomes {
    # A copy of Ctx whose user config files are those of the given contexts, in order: what
    # discovery returns for two Codex homes (CODEX_HOME first, then ~/.codex).
    param($Ctx, [object[]]$HomeContexts)
    $users = @(foreach ($c in $HomeContexts) { @($c.Codex | Where-Object { $_.Scope -eq 'user' }) })
    $copy = $Ctx.PSObject.Copy()
    $copy.Codex = @($users + @($Ctx.Codex | Where-Object { $_.Scope -ne 'user' }))
    return $copy
}

function Get-Evidence($Findings) { return ,[string[]]@($Findings | ForEach-Object { $_.Evidence }) }
function Has([string]$Text, [string]$Needle) { $Text.IndexOf($Needle, [StringComparison]::Ordinal) -ge 0 }

try {
    Describe 'Codex rules: registration' {
        It 'registers AW-CDX-001 to AW-CDX-014 with complete metadata' {
            $rules = @(& $aw { Get-AwRules } | Where-Object { $_.Id -like 'AW-CDX-*' })
            Assert-Equal @(1..14 | ForEach-Object { 'AW-CDX-{0:D3}' -f $_ }) @($rules | ForEach-Object { $_.Id })
            foreach ($r in $rules) {
                Assert-Equal 'codex' $r.Harness $r.Id
                Assert-True ($r.Description.Length -gt 80) $r.Id
                Assert-True ($r.Fix.Length -gt 20) $r.Id
                Assert-True (@($r.References | Where-Object { $_ -like 'OWASP-ASI*' }).Count -ge 1) $r.Id
                Assert-True (@($r.References | Where-Object { $_ -like 'https://learn.chatgpt.com/docs/*' }).Count -ge 1) $r.Id
            }
            Assert-Equal @('high', 'medium', 'medium', 'medium', 'high', 'medium', 'low', 'high', 'high', 'high', 'medium', 'medium', 'medium', 'medium') @($rules | ForEach-Object { $_.Severity })
            Assert-Equal @('high', 'high', 'high', 'medium', 'high', 'high', 'high', 'medium', 'high', 'medium', 'high', 'high', 'medium', 'high') @($rules | ForEach-Object { $_.Confidence })
        }
        It 'loads its data file' {
            $d = & $aw { $script:AwCdxData }
            Assert-Equal 'danger-full-access' $d['fullAccessSandboxMode']
            Assert-Equal @('dangerously_allow_all_unix_sockets', 'dangerously_allow_non_loopback_proxy') @($d['dangerousNetworkOptions'])
        }
    }

    Describe 'AW-CDX-001 sandbox turned off' {
        It 'flags full access in user and project config' {
            $f = @(Invoke-CdxRule 'AW-CDX-001' -User (Toml '# user' 'sandbox_mode = "danger-full-access"'))
            Assert-Equal 1 $f.Count
            Assert-Equal 'sandbox_mode = "danger-full-access" (user config)' $f[0].Evidence
            Assert-Equal 'high' $f[0].Severity
            Assert-Equal 2 $f[0].Location.Line
            Assert-Equal 'sandbox_mode' $f[0].Location.Key
            Assert-Match $f[0].Location.Path '\\\.codex\\config\.toml$'
            $f = @(Invoke-CdxRule 'AW-CDX-001' -Project (Toml 'default_permissions = ":danger-full-access"'))
            Assert-Equal @('default_permissions = ":danger-full-access" (project config)') (Get-Evidence $f)
        }
        It 'reports a managed default, and is info when requirements.toml forbids the value' {
            $f = @(Invoke-CdxRule 'AW-CDX-001' -Requirements (Toml 'default_permissions = ":danger-full-access"'))
            Assert-Equal @('default_permissions = ":danger-full-access" (requirements.toml)') (Get-Evidence $f)
            Assert-Equal 'high' $f[0].Severity
            $f = @(Invoke-CdxRule 'AW-CDX-001' -User (Toml 'sandbox_mode = "danger-full-access"') -Requirements (Toml 'allowed_sandbox_modes = ["read-only", "workspace-write"]'))
            Assert-Equal 1 $f.Count
            Assert-Equal 'info' $f[0].Severity
            Assert-Equal 'sandbox_mode = "danger-full-access" (user config); requirements.toml does not allow it (allowed_sandbox_modes)' $f[0].Evidence
            $f = @(Invoke-CdxRule 'AW-CDX-001' -Project (Toml 'default_permissions = ":danger-full-access"') -Requirements (Toml '[allowed_permission_profiles]' '":workspace" = true' '":danger-full-access" = false'))
            Assert-Equal 'info' $f[0].Severity
            $f = @(Invoke-CdxRule 'AW-CDX-001' -User (Toml 'sandbox_mode = "danger-full-access"') -Requirements (Toml 'allowed_sandbox_modes = ["danger-full-access"]'))
            Assert-Equal 'high' $f[0].Severity
        }
        It 'is silent on other modes, spellings, types, tables and profiles' {
            foreach ($t in @('sandbox_mode = "workspace-write"', 'sandbox_mode = "read-only"', 'Sandbox_Mode = "danger-full-access"',
                             'sandbox_mode = "Danger-Full-Access"', 'sandbox_mode = ["danger-full-access"]', 'default_permissions = ":workspace"',
                             'default_permissions = "danger-full-access"', '"sandbox_mode " = "danger-full-access"')) {
                Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-001' -User (Toml $t)).Count $t
            }
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-001' -User (Toml '[other]' 'sandbox_mode = "danger-full-access"')).Count
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-001' -UserFiles @{ '.codex\yolo.config.toml' = (Toml 'sandbox_mode = "danger-full-access"') }).Count
        }
    }

    Describe 'AW-CDX-002 approvals turned off' {
        It 'reports approval_policy = "never" as medium' {
            $f = @(Invoke-CdxRule 'AW-CDX-002' -User (Toml 'approval_policy = "never"'))
            Assert-Equal 1 $f.Count
            Assert-Equal 'medium' $f[0].Severity
            Assert-Equal 'approval_policy = "never" (user config)' $f[0].Evidence
            Assert-Equal 1 $f[0].Location.Line
        }
        It 'is critical with full access in the same layers' {
            $f = @(Invoke-CdxRule 'AW-CDX-002' -User (Toml 'approval_policy = "never"' 'sandbox_mode = "danger-full-access"'))
            Assert-Equal 'critical' $f[0].Severity
            Assert-Equal 'approval_policy = "never" (user config); with sandbox_mode = "danger-full-access" (user config): no sandbox and no approval' $f[0].Evidence
            $f = @(Invoke-CdxRule 'AW-CDX-002' -User (Toml 'approval_policy = "never"') -Project (Toml 'default_permissions = ":danger-full-access"'))
            Assert-Equal 'critical' $f[0].Severity
            Assert-Match $f[0].Evidence 'with default_permissions = ":danger-full-access" \(project config\)'
        }
        It 'follows the precedence of project config over user config' {
            # In the project folder the project approval applies; elsewhere the user sandbox is not full access.
            $f = @(Invoke-CdxRule 'AW-CDX-002' -User (Toml 'approval_policy = "never"') -Project (Toml 'approval_policy = "on-request"' 'sandbox_mode = "danger-full-access"'))
            Assert-Equal 1 $f.Count
            Assert-Equal 'medium' $f[0].Severity
            # The project sandbox mode overrides the user full access.
            $f = @(Invoke-CdxRule 'AW-CDX-002' -User (Toml 'sandbox_mode = "danger-full-access"') -Project (Toml 'approval_policy = "never"' 'sandbox_mode = "workspace-write"'))
            Assert-Equal @('approval_policy = "never" (project config)') (Get-Evidence $f)
            Assert-Equal 'medium' $f[0].Severity
        }
        It 'uses sandbox_mode from any layer over default_permissions, as Codex does' {
            # A higher default_permissions does not replace a sandbox_mode set in a lower layer.
            $f = @(Invoke-CdxRule 'AW-CDX-002' -User (Toml 'sandbox_mode = "danger-full-access"') -Project (Toml 'approval_policy = "never"' 'default_permissions = ":workspace"'))
            Assert-Equal 'critical' $f[0].Severity
            Assert-Equal 'approval_policy = "never" (project config); with sandbox_mode = "danger-full-access" (user config): no sandbox and no approval' $f[0].Evidence
            # And a full-access permission profile does not apply when a layer sets sandbox_mode.
            $f = @(Invoke-CdxRule 'AW-CDX-002' -User (Toml 'sandbox_mode = "workspace-write"') -Project (Toml 'approval_policy = "never"' 'default_permissions = ":danger-full-access"'))
            Assert-Equal 'medium' $f[0].Severity
            # A managed allowed_permission_profiles table makes Codex use permission profiles.
            $f = @(Invoke-CdxRule 'AW-CDX-002' -User (Toml 'approval_policy = "never"' 'sandbox_mode = "danger-full-access"') -Requirements (Toml '[allowed_permission_profiles]' '":workspace" = true'))
            Assert-Equal 'medium' $f[0].Severity
        }
        It 'follows requirements.toml' {
            $f = @(Invoke-CdxRule 'AW-CDX-002' -User (Toml 'approval_policy = "never"' 'sandbox_mode = "danger-full-access"') -Requirements (Toml 'allowed_approval_policies = ["on-request"]'))
            Assert-Equal 'info' $f[0].Severity
            Assert-Match $f[0].Evidence 'requirements\.toml does not allow it \(allowed_approval_policies\)$'
            $f = @(Invoke-CdxRule 'AW-CDX-002' -User (Toml 'approval_policy = "never"' 'sandbox_mode = "danger-full-access"') -Requirements (Toml 'allowed_sandbox_modes = ["workspace-write"]'))
            Assert-Equal 'medium' $f[0].Severity
        }
        It 'is silent on other policies' {
            foreach ($t in @('approval_policy = "on-request"', 'approval_policy = "Never"', 'approval_policy = ["never"]',
                             'approval_policy = { granular = { sandbox_approval = false, rules = false } }')) {
                Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-002' -User (Toml $t)).Count $t
            }
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-002' -User (Toml '[profiles.x]' 'approval_policy = "never"')).Count
        }
    }

    Describe 'AW-CDX-003 network access in the workspace-write sandbox' {
        It 'flags network_access = true' {
            $f = @(Invoke-CdxRule 'AW-CDX-003' -User (Toml 'sandbox_mode = "workspace-write"' '' '[sandbox_workspace_write]' 'network_access = true'))
            Assert-Equal 1 $f.Count
            Assert-Equal 'sandbox_workspace_write.network_access = true (user config)' $f[0].Evidence
            Assert-Equal 4 $f[0].Location.Line
            Assert-Equal 'sandbox_workspace_write.network_access' $f[0].Location.Key
            $f = @(Invoke-CdxRule 'AW-CDX-003' -Project (Toml '# project' 'sandbox_workspace_write.network_access = true'))
            Assert-Equal @('sandbox_workspace_write.network_access = true (project config)') (Get-Evidence $f)
            Assert-Equal 2 $f[0].Location.Line
        }
        It 'follows the sandbox mode and the precedence of the layers' {
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-003' -User (Toml 'sandbox_mode = "read-only"' '[sandbox_workspace_write]' 'network_access = true')).Count
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-003' -User (Toml 'sandbox_mode = "danger-full-access"' '[sandbox_workspace_write]' 'network_access = true')).Count
            # The project value wins in its folder, but the user value still applies elsewhere.
            $f = @(Invoke-CdxRule 'AW-CDX-003' -User (Toml '[sandbox_workspace_write]' 'network_access = true') -Project (Toml '[sandbox_workspace_write]' 'network_access = false'))
            Assert-Equal @('sandbox_workspace_write.network_access = true (user config)') (Get-Evidence $f)
            # A read-only user sandbox does not stop it when the project selects workspace-write.
            $f = @(Invoke-CdxRule 'AW-CDX-003' -User (Toml 'sandbox_mode = "read-only"' '[sandbox_workspace_write]' 'network_access = true') -Project (Toml 'sandbox_mode = "workspace-write"'))
            Assert-Equal 1 $f.Count
        }
        It 'is silent when the layers use permission profiles, which ignore [sandbox_workspace_write]' {
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-003' -User (Toml 'default_permissions = ":workspace"' '[sandbox_workspace_write]' 'network_access = true')).Count
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-003' -Project (Toml 'default_permissions = "project-edit"' '[sandbox_workspace_write]' 'network_access = true') -User (Toml 'default_permissions = ":read-only"')).Count
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-003' -User (Toml 'sandbox_mode = "workspace-write"' '[sandbox_workspace_write]' 'network_access = true') -Requirements (Toml '[allowed_permission_profiles]' '":workspace" = true')).Count
        }
        It 'still reports it when sandbox_mode in any layer brings back the older settings' {
            # default_permissions in the user config, sandbox_mode in the project config: Codex uses sandbox_mode.
            $f = @(Invoke-CdxRule 'AW-CDX-003' -User (Toml 'default_permissions = ":workspace"' '[sandbox_workspace_write]' 'network_access = true') -Project (Toml 'sandbox_mode = "workspace-write"'))
            Assert-Equal @('sandbox_workspace_write.network_access = true (user config)') (Get-Evidence $f)
            $f = @(Invoke-CdxRule 'AW-CDX-003' -User (Toml 'sandbox_mode = "workspace-write"') -Project (Toml 'default_permissions = ":workspace"' '[sandbox_workspace_write]' 'network_access = true'))
            Assert-Equal @('sandbox_workspace_write.network_access = true (project config)') (Get-Evidence $f)
        }
        It 'is silent otherwise' {
            foreach ($t in @((Toml '[sandbox_workspace_write]' 'network_access = false'), (Toml '[sandbox_workspace_write]' 'network_access = "true"'),
                             (Toml '[sandbox_workspace_write]' 'Network_Access = true'), (Toml 'network_access = true'))) {
                Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-003' -User $t).Count $t
            }
        }
    }

    Describe 'AW-CDX-004 unrestricted network in a permission profile' {
        It 'flags full mode and global allow rules' {
            $t = Toml '[permissions.open.network]' 'enabled = true' 'mode = "full"' '' '[permissions.open.network.domains]' '"*" = "allow"' '"api.example.invalid" = "allow"' '' '[features.network_proxy]' 'enabled = true' '[features.network_proxy.domains]' '"*" = "allow"'
            $f = @(Invoke-CdxRule 'AW-CDX-004' -User $t)
            Assert-Equal @('permissions.open.network.mode = "full" with the network enabled (user config)',
                           'permissions.open.network.domains."*" = "allow": every public host (user config)',
                           'features.network_proxy.domains."*" = "allow": every public host (user config)') (Get-Evidence $f)
            Assert-Equal @(3, 6, 12) @($f | ForEach-Object { $_.Location.Line })
            Assert-Equal 'medium' $f[0].Severity
            $f = @(Invoke-CdxRule 'AW-CDX-004' -UserFiles @{ '.codex\net.config.toml' = (Toml '[features]' 'network_proxy = true' '[permissions."my profile".network]' 'enabled = true' 'mode = "full"') })
            Assert-Equal @('permissions."my profile".network.mode = "full" with the network enabled (profile ''net'')') (Get-Evidence $f)
        }
        It 'flags a network enabled while the network proxy is off' {
            # Network on, proxy off: direct, unrestricted access; the domain rules are not enforced.
            $t = Toml '[permissions.dev.network]' 'enabled = true' '' '[permissions.dev.network.domains]' '"api.example.invalid" = "allow"'
            $f = @(Invoke-CdxRule 'AW-CDX-004' -User $t)
            Assert-Equal @('permissions.dev.network.enabled = true and the network proxy is off: commands have direct, unrestricted network access, and the domain rules are not enforced (user config)') (Get-Evidence $f)
            Assert-Equal 2 $f[0].Location.Line
            Assert-Equal 'permissions.dev.network.enabled' $f[0].Location.Key
            Assert-Equal 'medium' $f[0].Severity
            # A proxy table without enabled = true, a disabled proxy, and a profile file on its own.
            foreach ($proxy in @((Toml '[features.network_proxy.domains]' '"api.example.invalid" = "allow"'), (Toml '[features]' 'network_proxy = false'),
                                 (Toml '[features.network_proxy]' 'enabled = false'))) {
                Assert-Equal 1 @(Invoke-CdxRule 'AW-CDX-004' -User ($t + $proxy)).Count $proxy
            }
            $f = @(Invoke-CdxRule 'AW-CDX-004' -UserFiles @{ '.codex\net.config.toml' = $t })
            Assert-Match $f[0].Evidence 'network proxy is off.*\(profile ''net''\)$'
            # The user profile still applies alone in folders without the project config that turns the proxy on.
            $f = @(Invoke-CdxRule 'AW-CDX-004' -User $t -Project (Toml '[features]' 'network_proxy = true'))
            Assert-Equal 1 $f.Count
            # Network modes "full" and "limited" do not start the proxy either.
            Assert-Equal 2 @(Invoke-CdxRule 'AW-CDX-004' -User (Toml '[permissions.p.network]' 'enabled = true' 'mode = "full"')).Count
        }
        It 'is silent on limited mode, a disabled network and specific domains' {
            foreach ($t in @((Toml '[permissions.p.network]' 'enabled = false' 'mode = "full"'),
                             (Toml '[permissions.p.network]' 'mode = "full"'),
                             (Toml '[permissions.p.network]' 'enabled = "true"' 'mode = "full"'),
                             (Toml '[features]' 'network_proxy = true' '[permissions.p.network]' 'enabled = true' 'mode = "limited"' '[permissions.p.network.domains]' '"api.example.invalid" = "allow"' '"*" = "deny"'),
                             (Toml '[features]' 'network_proxy = true'),
                             (Toml '[features.network_proxy.domains]' '"*.example.invalid" = "allow"'))) {
                Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-004' -User $t).Count $t
            }
        }
        It 'is silent on a network enabled behind the proxy, in any layer that applies' {
            $t = Toml '[permissions.dev.network]' 'enabled = true' '[permissions.dev.network.domains]' '"api.example.invalid" = "allow"'
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-004' -User ($t + (Toml '[features.network_proxy]' 'enabled = true'))).Count
            # Project profile, proxy turned on in the user config below it.
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-004' -Project $t -User (Toml '[features]' 'network_proxy = true')).Count
            # Profile file over the user config of its Codex home.
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-004' -User (Toml '[features]' 'network_proxy = true') -UserFiles @{ '.codex\net.config.toml' = $t }).Count
            # Managed networking started by requirements.toml.
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-004' -User $t -Requirements (Toml '[experimental_network]' 'enabled = true')).Count
            Assert-Equal 1 @(Invoke-CdxRule 'AW-CDX-004' -User $t -Requirements (Toml '[experimental_network.domains]' '"api.example.invalid" = "allow"')).Count
        }
    }

    Describe 'AW-CDX-005 writes to broad folders' {
        It 'flags broad writable roots' {
            $roots = @('~', '~/', 'C:\\', 'D:', '/', '/home/dev', '/Users/dev', 'C:\\Users\\FAKEUSER', 'C:\\Users', '/root', '$HOME', '%USERPROFILE%', '\\\\fileserver\\share')
            $list = (@($roots | ForEach-Object { '"' + $_ + '"' }) + @('"/tmp/cache"', '"~/code/app"')) -join ', '
            $f = @(Invoke-CdxRule 'AW-CDX-005' -User (Toml '[sandbox_workspace_write]' ('writable_roots = [' + $list + ']')))
            Assert-Equal $roots.Count $f.Count
            Assert-Equal "sandbox_workspace_write.writable_roots contains '~' (the home directory, user config)" $f[0].Evidence
            Assert-Equal "sandbox_workspace_write.writable_roots contains 'C:\' (a drive root, user config)" $f[2].Evidence
            Assert-Equal "sandbox_workspace_write.writable_roots contains '/' (the file system root, user config)" $f[4].Evidence
            Assert-Equal "sandbox_workspace_write.writable_roots contains 'C:\Users' (the folder of all user profiles, user config)" $f[8].Evidence
            Assert-Equal "sandbox_workspace_write.writable_roots contains '\\fileserver\share' (a network share root, user config)" $f[12].Evidence
            Assert-Equal 'high' $f[0].Severity
            Assert-Equal 2 $f[0].Location.Line
        }
        It 'flags the analyzed user profile itself' {
            $case = New-CdxCase -UserFiles @{ 'placeholder.txt' = 'synthetic' }
            $toml = Toml '[sandbox_workspace_write]' ('writable_roots = ["' + $case.User.Replace('\', '\\') + '"]')
            [void][System.IO.Directory]::CreateDirectory((Join-Path $case.User '.codex'))
            [System.IO.File]::WriteAllText((Join-Path $case.User '.codex\config.toml'), $toml, $utf8)
            $f = @(Invoke-CdxCheck 'AW-CDX-005' (Get-CdxContext $case))
            Assert-Equal 1 $f.Count
            Assert-Match $f[0].Evidence '\(the home directory, user config\)$'
        }
        It 'flags write access to broad paths in permission profiles' {
            $t = Toml '[permissions.wide]' 'extends = ":workspace"' '' '[permissions.wide.filesystem]' '":root" = "write"' '"/etc" = "write"' '":minimal" = "read"' '' `
                      '[permissions.wide.filesystem."~"]' '"." = "write"' '".ssh" = "deny"' '' '[permissions.wide.workspace_roots]' '"~" = true' '"~/code/app" = true'
            $f = @(Invoke-CdxRule 'AW-CDX-005' -User $t)
            Assert-Equal @('permissions.wide.filesystem.":root" = "write" (the file system root, user config)',
                           'permissions.wide.filesystem."~" = "write" (the home directory, user config)',
                           'permissions.wide.workspace_roots."~" = true in a profile that writes its workspace roots (the home directory, user config)') (Get-Evidence $f)
            Assert-Equal 5 $f[0].Location.Line
            # Write access to :workspace_roots makes broad workspace roots writable as well.
            $f = @(Invoke-CdxRule 'AW-CDX-005' -Project (Toml '[permissions.p.filesystem]' '":workspace_roots" = "write"' '[permissions.p.workspace_roots]' '"D:\\" = true'))
            Assert-Equal 1 $f.Count
            Assert-Match $f[0].Evidence '\(a drive root, project config\)$'
        }
        It 'is silent on narrow paths and read-only profiles' {
            foreach ($t in @((Toml '[sandbox_workspace_write]' 'writable_roots = ["/tmp/cache", "~/code/app", "C:\\work\\repo", "/home/dev/project", ".", ""]'),
                             (Toml '[sandbox_workspace_write]' 'writable_roots = "~"'),
                             (Toml '[sandbox_workspace_write]' 'writable_roots = [1, ["~"], { p = "~" }]'),
                             (Toml '[permissions.audit.filesystem]' '":root" = "read"' '"~" = "deny"'),
                             (Toml '[permissions.ro]' 'extends = ":read-only"' '[permissions.ro.workspace_roots]' '"~" = true'),
                             (Toml '[permissions.ro.filesystem."~"]' '".cache" = "write"'),
                             (Toml '[permissions.ro.filesystem]' '":root" = "Write"'))) {
                Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-005' -User $t).Count $t
            }
        }
    }

    Describe 'AW-CDX-006 dangerously_* network options' {
        It 'flags the options under the network proxy and permission profiles' {
            $t = Toml '[features.network_proxy]' 'enabled = true' 'dangerously_allow_all_unix_sockets = true' 'dangerously_allow_non_loopback_proxy = true' '' '[permissions.p.network]' 'dangerously_allow_all_unix_sockets = true'
            $f = @(Invoke-CdxRule 'AW-CDX-006' -User $t)
            Assert-Equal @('features.network_proxy.dangerously_allow_all_unix_sockets = true (user config)',
                           'features.network_proxy.dangerously_allow_non_loopback_proxy = true (user config)',
                           'permissions.p.network.dangerously_allow_all_unix_sockets = true (user config)') (Get-Evidence $f)
            Assert-Equal @(3, 4, 7) @($f | ForEach-Object { $_.Location.Line })
            $f = @(Invoke-CdxRule 'AW-CDX-006' -UserFiles @{ '.codex\dev.config.toml' = (Toml '[features.network_proxy]' 'dangerously_allow_non_loopback_proxy = true') })
            Assert-Equal @('features.network_proxy.dangerously_allow_non_loopback_proxy = true (profile ''dev'')') (Get-Evidence $f)
        }
        It 'is silent otherwise' {
            foreach ($t in @((Toml '[features.network_proxy]' 'dangerously_allow_all_unix_sockets = false'),
                             (Toml '[features]' 'network_proxy = true'),
                             (Toml '[other]' 'dangerously_allow_all_unix_sockets = true'),
                             (Toml '[features.network_proxy]' 'dangerously_allow_all_unix_sockets = "true"'),
                             (Toml '[permissions.p.network]' 'allow_local_binding = true'))) {
                Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-006' -User $t).Count $t
            }
        }
    }

    Describe 'AW-CDX-007 whole environment passed to commands' {
        It 'flags inherit = "all" without filters' {
            $f = @(Invoke-CdxRule 'AW-CDX-007' -User (Toml '[shell_environment_policy]' 'inherit = "all"' '' '[shell_environment_policy.set]' 'CI = "1"'))
            Assert-Equal 1 $f.Count
            Assert-Equal 'low' $f[0].Severity
            Assert-Equal 'shell_environment_policy.inherit = "all", no exclude or include filter, ignore_default_excludes not set (default true) (user config)' $f[0].Evidence
            Assert-Equal 2 $f[0].Location.Line
            $f = @(Invoke-CdxRule 'AW-CDX-007' -Project (Toml 'shell_environment_policy = { inherit = "all", ignore_default_excludes = true }'))
            Assert-Equal @('shell_environment_policy.inherit = "all", no exclude or include filter, ignore_default_excludes = true (project config)') (Get-Evidence $f)
        }
        It 'is silent with a narrower inheritance, the default excludes or a filter' {
            foreach ($t in @((Toml '[shell_environment_policy]' 'inherit = "core"'),
                             (Toml '[shell_environment_policy]' 'inherit = "All"'),
                             (Toml '[shell_environment_policy]' 'inherit = "all"' 'ignore_default_excludes = false'),
                             (Toml '[shell_environment_policy]' 'inherit = "all"' 'exclude = ["AWS_*", "*TOKEN*"]'),
                             (Toml '[shell_environment_policy]' 'inherit = "all"' 'include_only = ["PATH", "HOME"]'),
                             (Toml '[shell_environment_policy]' 'inherit = "all"' '[shell_environment_policy.filters]' '"AWS_*" = "exclude"'),
                             (Toml '[shell_environment_policy]' 'inherit = "all"' '[shell_environment_policy.filters]' '"PATH" = "include"'))) {
                Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-007' -User $t).Count $t
            }
            $f = @(Invoke-CdxRule 'AW-CDX-007' -User (Toml '[shell_environment_policy]' 'inherit = "all"' 'exclude = []'))
            Assert-Equal 1 $f.Count
        }
    }

    Describe 'AW-CDX-008 MCP tools approved without a prompt' {
        It 'flags approve on a server, a tool and a plugin server' {
            $t = Toml '[mcp_servers.github]' 'command = "npx"' 'default_tools_approval_mode = "approve"' '' '[mcp_servers.github.tools.create_issue]' 'approval_mode = "approve"' '' `
                      '[mcp_servers.github.tools.list_issues]' 'approval_mode = "writes"' '' '[plugins.fake-plugin.mcp_servers.helper]' 'default_tools_approval_mode = "approve"'
            $f = @(Invoke-CdxRule 'AW-CDX-008' -User $t)
            Assert-Equal @('mcp_servers.github.default_tools_approval_mode = "approve": every tool of the server runs without a prompt (user config)',
                           'mcp_servers.github.tools.create_issue.approval_mode = "approve" (user config)',
                           'plugins.fake-plugin.mcp_servers.helper.default_tools_approval_mode = "approve": every tool of the server runs without a prompt (user config)') (Get-Evidence $f)
            Assert-Equal @('high', 'medium', 'high') @($f | ForEach-Object { $_.Severity })
            Assert-Equal @(3, 6, 12) @($f | ForEach-Object { $_.Location.Line })
            Assert-Equal 'mcp_servers.github.tools.create_issue.approval_mode' $f[1].Location.Key
        }
        It 'is silent on the other modes' {
            foreach ($mode in @('auto', 'prompt', 'writes', 'Approve')) {
                $t = Toml '[mcp_servers.s]' ('default_tools_approval_mode = "' + $mode + '"') '[mcp_servers.s.tools.t]' ('approval_mode = "' + $mode + '"')
                Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-008' -User $t).Count $mode
            }
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-008' -User (Toml '[mcp_servers.s]' 'approval_mode = "approve"' 'tools = "approve"')).Count
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-008' -User (Toml '[other.s]' 'default_tools_approval_mode = "approve"')).Count
        }
    }

    Describe 'AW-CDX-009 secrets stored in Codex config' {
        It 'flags and masks an OAuth client secret and a provider bearer token' {
            $t = Toml '[mcp_servers.docs]' 'url = "https://mcp.example.invalid/mcp"' '' '[mcp_servers.docs.oauth]' 'client_id = "fake-client"' 'client_secret = "FAKE-oauth-secret-FAKE-0001"' '' `
                      '[model_providers.fake]' 'experimental_bearer_token = "FAKE-provider-bearer-FAKE-0002"'
            $f = @(Invoke-CdxRule 'AW-CDX-009' -User $t)
            Assert-Equal 2 $f.Count
            Assert-Match $f[0].Evidence '^mcp_servers\.docs\.oauth\.client_secret = FAKE.01 \(27 chars\) \(user config\)$'
            Assert-Match $f[1].Evidence '^model_providers\.fake\.experimental_bearer_token = FAKE.02 \(30 chars\) \(user config\)$'
            Assert-Equal @('high', 'high') @($f | ForEach-Object { $_.Severity })
            Assert-Equal @(6, 9) @($f | ForEach-Object { $_.Location.Line })
            foreach ($x in $f) { Assert-False (Has $x.Evidence 'FAKE-oauth-secret-FAKE-0001') ; Assert-False (Has $x.Evidence 'FAKE-provider-bearer-FAKE-0002') }
        }
        It 'is critical in the project config' {
            $f = @(Invoke-CdxRule 'AW-CDX-009' -Project (Toml 'mcp_servers.remote.oauth.client_secret = "FAKE-project-secret-FAKE-0005"'))
            Assert-Equal 1 $f.Count
            Assert-Equal 'critical' $f[0].Severity
            Assert-Match $f[0].Evidence '\(project config\)$'
        }
        It 'ignores references, placeholders, short values and other keys' {
            foreach ($v in @('"${OAUTH_SECRET}"', '"<client-secret>"', '"short"', '12345678901234', '"your-secret-here"', '""')) {
                Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-009' -User (Toml '[mcp_servers.s.oauth]' ('client_secret = ' + $v))).Count $v
            }
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-009' -User (Toml '[model_providers.p]' 'env_key = "FAKE_PROVIDER_API_KEY"')).Count
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-009' -User (Toml '[other.s.oauth]' 'client_secret = "FAKE-elsewhere-FAKE-0009"')).Count
        }
    }

    Describe 'AW-CDX-010 broad trusted folders' {
        It 'flags trusted home directories, profile folders and roots' {
            $t = Toml '[projects."C:\\Users\\FAKEUSER"]' 'trust_level = "trusted"' '[projects."/"]' 'trust_level = "trusted"' '[projects."D:\\"]' 'trust_level = "trusted"' `
                      '[projects."~"]' 'trust_level = "trusted"' '[projects."/home"]' 'trust_level = "trusted"' '[projects."/home/dev/project"]' 'trust_level = "trusted"' `
                      '[projects."D:\\work\\repo"]' 'trust_level = "trusted"'
            $f = @(Invoke-CdxRule 'AW-CDX-010' -User $t)
            Assert-Equal @('projects ''/'' trust_level = "trusted" (the file system root, user config)',
                           'projects ''/home'' trust_level = "trusted" (the folder of all user profiles, user config)',
                           'projects ''C:\Users\FAKEUSER'' trust_level = "trusted" (the home directory, user config)',
                           'projects ''D:\'' trust_level = "trusted" (a drive root, user config)',
                           'projects ''~'' trust_level = "trusted" (the home directory, user config)') (Get-Evidence $f)
            Assert-Equal 'high' $f[0].Severity
            Assert-Equal 4 $f[0].Location.Line
        }
        It 'is silent on project folders, untrusted entries and project config' {
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-010' -User (Toml '[projects."/home/dev"]' 'trust_level = "untrusted"' '[projects."D:\\work\\repo"]' 'trust_level = "trusted"')).Count
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-010' -User (Toml '[projects."/"]' 'trust_level = "Trusted"' '[projects."D:\\"]' 'trust_level = true')).Count
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-010' -User (Toml 'projects = ["/"]')).Count
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-010' -Project (Toml '[projects."/"]' 'trust_level = "trusted"')).Count
        }
    }

    Describe 'AW-CDX-011 live web search' {
        It 'flags web_search = "live" in user and project config' {
            $f = @(Invoke-CdxRule 'AW-CDX-011' -User (Toml 'model = "gpt-fake"' 'web_search = "live"') -Project (Toml 'web_search = "live"'))
            Assert-Equal @('web_search = "live" (user config)', 'web_search = "live" (project config)') (Get-Evidence $f)
            Assert-Equal @(2, 1) @($f | ForEach-Object { $_.Location.Line })
            Assert-Equal 'medium' $f[0].Severity
        }
        It 'follows allowed_web_search_modes' {
            Assert-Equal 'info' @(Invoke-CdxRule 'AW-CDX-011' -User (Toml 'web_search = "live"') -Requirements (Toml 'allowed_web_search_modes = []'))[0].Severity
            Assert-Equal 'info' @(Invoke-CdxRule 'AW-CDX-011' -User (Toml 'web_search = "live"') -Requirements (Toml 'allowed_web_search_modes = ["cached"]'))[0].Severity
            Assert-Equal 'medium' @(Invoke-CdxRule 'AW-CDX-011' -User (Toml 'web_search = "live"') -Requirements (Toml 'allowed_web_search_modes = ["cached", "live"]'))[0].Severity
        }
        It 'is silent on the other modes and on profiles' {
            foreach ($t in @('web_search = "cached"', 'web_search = "indexed"', 'web_search = "disabled"', 'web_search = "Live"', 'web_search = true')) {
                Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-011' -User (Toml $t)).Count $t
            }
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-011' -UserFiles @{ '.codex\web.config.toml' = (Toml 'web_search = "live"') }).Count
        }
    }

    Describe 'AW-CDX-012 project hooks' {
        It 'lists the command and MCP tool hooks of hooks.json and of the project config' {
            $f = @(Invoke-CdxFixture 'AW-CDX-012' $projectInsecure)
            Assert-Equal @('hook PostToolUse mcp_tool: linter/lint_changes', 'hook SessionStart command: ./scripts/session-start.sh',
                           'hook PreToolUse command: ./scripts/check-tool.sh') (Get-Evidence $f)
            Assert-Equal @(10, 3, 20) @($f | ForEach-Object { $_.Location.Line })
            Assert-Equal @('hooks.PostToolUse', 'hooks.SessionStart', 'hooks.PreToolUse') @($f | ForEach-Object { $_.Location.Key })
            Assert-Match $f[0].Location.Path '\\\.codex\\hooks\.json$'
            Assert-Match $f[2].Location.Path '\\\.codex\\config\.toml$'
            Assert-Equal 'medium' $f[0].Severity
        }
        It 'honors the hooks feature flag and requirements.toml' {
            $hooks = '{ "hooks": { "Stop": [ { "hooks": [ { "type": "command", "command": "./stop.sh" } ] } ] } }'
            Assert-Equal 1 @(Invoke-CdxRule 'AW-CDX-012' -ProjectFiles @{ '.codex\hooks.json' = $hooks }).Count
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-012' -ProjectFiles @{ '.codex\hooks.json' = $hooks } -Project (Toml '[features]' 'hooks = false')).Count
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-012' -ProjectFiles @{ '.codex\hooks.json' = $hooks } -User (Toml '[features]' 'codex_hooks = false')).Count
            Assert-Equal 1 @(Invoke-CdxRule 'AW-CDX-012' -ProjectFiles @{ '.codex\hooks.json' = $hooks } -User (Toml '[features]' 'hooks = false') -Project (Toml '[features]' 'hooks = true')).Count
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-012' -ProjectFiles @{ '.codex\hooks.json' = $hooks } -Requirements (Toml 'allow_managed_hooks_only = true')).Count
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-012' -ProjectFiles @{ '.codex\hooks.json' = $hooks } -Requirements (Toml '[features]' 'hooks = false')).Count
            Assert-Equal 1 @(Invoke-CdxRule 'AW-CDX-012' -ProjectFiles @{ '.codex\hooks.json' = $hooks } -Requirements (Toml 'allow_managed_hooks_only = false')).Count
        }
        It 'masks secrets and ignores user hooks and handlers without a command' {
            $f = @(Invoke-CdxRule 'AW-CDX-012' -Project (Toml '[[hooks.SessionStart]]' '[[hooks.SessionStart.hooks]]' 'type = "command"' 'command = "TOKEN=FAKE-hook-t1 ./start.sh --password FAKE-hook-p2"'))
            Assert-Equal 1 $f.Count
            Assert-NotMatch $f[0].Evidence 'FAKE-hook-t1|FAKE-hook-p2'
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-012' -UserFiles @{ '.codex\hooks.json' = '{ "hooks": { "Stop": [ { "hooks": [ { "type": "command", "command": "./stop.sh" } ] } ] } }' }).Count
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-012' -User (Toml '[[hooks.Stop]]' '[[hooks.Stop.hooks]]' 'command = "./stop.sh"')).Count
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-012' -Project (Toml '[[hooks.Stop]]' '[[hooks.Stop.hooks]]' 'type = "prompt"' 'prompt = "Check it"' '[[hooks.Stop.hooks]]' 'type = "command"' 'command = " "')).Count
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-012' -Project (Toml 'hooks = "./x.sh"')).Count
        }
    }

    Describe 'AW-CDX-013 project rules that allow commands' {
        It 'lists allow rules, explicit or by default' {
            $f = @(Invoke-CdxFixture 'AW-CDX-013' $projectInsecure)
            Assert-Equal @('prefix_rule pattern ["git", "push"], decision = "allow": matching commands run outside the sandbox without a prompt',
                           'prefix_rule pattern ["npm", "publish"], no decision (allow by default): matching commands run outside the sandbox without a prompt') (Get-Evidence $f)
            Assert-Equal @(3, 11) @($f | ForEach-Object { $_.Location.Line })
            Assert-Match $f[0].Location.Path '\\\.codex\\rules\\default\.rules$'
            Assert-Equal 'medium' $f[0].Severity
        }
        It 'ignores restrictive rules, comments, other functions and user rules' {
            $rules = @('prefix_rule(pattern = ["rm"], decision = "forbidden")', '# prefix_rule(pattern = ["curl"])', 'my_prefix_rule(pattern = ["ls"])',
                       'prefix_rule(pattern = ["git"], decision = ''prompt'')') -join "`n"
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-013' -ProjectFiles @{ '.codex\rules\default.rules' = $rules }).Count
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-013' -UserFiles @{ '.codex\rules\default.rules' = 'prefix_rule(pattern = ["git"])' }).Count
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-013' -ProjectFiles @{ '.codex\rules\notes.txt' = 'prefix_rule(pattern = ["git"])' }).Count
        }
        It 'caps the findings and stays fast on a 2 MB rules file' {
            $many = (@(1..300 | ForEach-Object { 'prefix_rule(pattern = ["tool' + $_ + '"], decision = "allow")' }) -join "`n")
            $f = @(Invoke-CdxRule 'AW-CDX-013' -ProjectFiles @{ '.codex\rules\many.rules' = $many })
            Assert-Equal 20 $f.Count
            Assert-Match $f[19].Evidence '\(and 180 more\)$'
            $case = New-CdxCase -ProjectFiles @{ '.codex\rules\decoys.rules' = ('prefix_rule ' * 170000) + "`n" + ('#prefix_rule(' * 1000) }
            $ctx = Get-CdxContext $case
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $f = @(Invoke-CdxCheck 'AW-CDX-013' $ctx)
            $ms = $sw.ElapsedMilliseconds
            Assert-Equal 0 $f.Count
            Assert-True ($ms -lt 2000) "rules scan took $ms ms"
        }
        It 'finds a call after any run of blanks before the parenthesis' {
            # The blanks are skipped 256 characters at a time: runs that end on each side of a
            # slice end, spaces and tabs mixed. The pattern is read within 4096 characters only.
            $problems = New-Object System.Collections.Generic.List[string]
            foreach ($n in @(0, 1, 255, 256, 257, 511, 512, 513, 600, 100000)) {
                $text = "x = 1`nprefix_rule" + (" `t" * $n).Substring(0, $n) + '(pattern = ["git"])' + "`n"
                $expected = if (11 + $n + 19 -le 4096) { '"git"' } else { '?' }
                $r = @(& $aw { param($t) @(Get-AwCdxAllowRules $t) } $text)
                $got = @($r | ForEach-Object { '{0}:{1}:{2}' -f $_.Index, $_.Pattern, $_.Explicit }) -join ', '
                if ($got -cne ('6:' + $expected + ':False')) { $problems.Add("$n blanks gave '$got'") }
            }
            # Blanks up to the end of the file, or before another character, are no call.
            $others = [ordered]@{
                'blanks to the end'     = 'prefix_rule' + (' ' * 256)
                'blanks, then a letter' = 'prefix_rule' + (' ' * 256) + 'x(pattern = ["git"])'
                'blanks, then a line'   = 'prefix_rule' + (' ' * 512) + "`n(pattern = [`"git`"])"
            }
            foreach ($name in $others.Keys) {
                $r = @(& $aw { param($t) @(Get-AwCdxAllowRules $t) } $others[$name])
                if ($r.Count -ne 0) { $problems.Add("$name gave $($r.Count) calls") }
            }
            Assert-Equal @() $problems.ToArray() 'cases that differ'
            $blank = "x = 1`nprefix_rule" + (' ' * 600) + '(pattern = ["git"])' + "`n"
            $f = @(Invoke-CdxRule 'AW-CDX-013' -ProjectFiles @{ '.codex\rules\default.rules' = $blank })
            Assert-Equal @('prefix_rule pattern ["git"], no decision (allow by default): matching commands run outside the sandbox without a prompt') (Get-Evidence $f)
            Assert-Equal 2 $f[0].Location.Line
        }
        It 'stays fast on a 2 MB rules file whose decoys are each followed by 300 blanks' {
            $text = 'prefix_rule' + (' ' * 300) + '(pattern = ["git"])' + "`n" + (('prefix_rule' + (' ' * 300)) * 6600)
            Assert-True ($text.Length -lt 2MB) 'the file stays within the size limit'
            $ctx = Get-CdxContext (New-CdxCase -ProjectFiles @{ '.codex\rules\blanks.rules' = $text })
            Assert-Equal @($text.Length) @($ctx.CodexRules | ForEach-Object { $_.Raw.Length })
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $f = @(Invoke-CdxCheck 'AW-CDX-013' $ctx)
            $ms = $sw.ElapsedMilliseconds
            Assert-Equal @('prefix_rule pattern ["git"], no decision (allow by default): matching commands run outside the sandbox without a prompt') (Get-Evidence $f)
            Assert-Equal 1 $f[0].Location.Line
            Assert-True ($ms -lt 2000) "rules scan took $ms ms"
        }
    }

    Describe 'AW-CDX-014 profiles that weaken the defaults' {
        It 'flags profile files, high when they remove the sandbox and the approvals' {
            $f = @(Invoke-CdxRule 'AW-CDX-014' -UserFiles @{
                '.codex\yolo.config.toml' = (Toml 'sandbox_mode = "danger-full-access"' 'approval_policy = "never"')
                '.codex\research.config.toml' = (Toml 'web_search = "live"' '[sandbox_workspace_write]' 'network_access = true')
                '.codex\review.config.toml' = (Toml 'approval_policy = "on-request"')
            })
            Assert-Equal @('profile ''research'' (--profile research): sandbox_workspace_write.network_access = true, web_search = "live"',
                           'profile ''yolo'' (--profile yolo): sandbox_mode = "danger-full-access", approval_policy = "never"; no sandbox and no approval') (Get-Evidence $f)
            Assert-Equal @('medium', 'high') @($f | ForEach-Object { $_.Severity })
            Assert-Equal @(3, 1) @($f | ForEach-Object { $_.Location.Line })
            Assert-Equal @('sandbox_workspace_write.network_access', 'sandbox_mode') @($f | ForEach-Object { $_.Location.Key })
        }
        It 'combines a profile with the user config of its Codex home and the project config' {
            # The profile turns the approvals off; the user config below it turns the sandbox off.
            $f = @(Invoke-CdxRule 'AW-CDX-014' -User (Toml 'sandbox_mode = "danger-full-access"') -UserFiles @{ '.codex\fast.config.toml' = (Toml 'approval_policy = "never"') })
            Assert-Equal @('profile ''fast'' (--profile fast): approval_policy = "never"; with sandbox_mode = "danger-full-access" (user config): no sandbox and no approval') (Get-Evidence $f)
            Assert-Equal 'high' $f[0].Severity
            Assert-Equal 'approval_policy' $f[0].Location.Key
            Assert-Equal 1 $f[0].Location.Line
            Assert-Match $f[0].Location.Path '\\\.codex\\fast\.config\.toml$'
            # The other way round, with a permission profile.
            $f = @(Invoke-CdxRule 'AW-CDX-014' -User (Toml 'approval_policy = "never"') -UserFiles @{ '.codex\open.config.toml' = (Toml 'default_permissions = ":danger-full-access"') })
            Assert-Equal @('profile ''open'' (--profile open): default_permissions = ":danger-full-access"; with approval_policy = "never" (user config): no sandbox and no approval') (Get-Evidence $f)
            Assert-Equal 'high' $f[0].Severity
            # A project config above the profile.
            $f = @(Invoke-CdxRule 'AW-CDX-014' -Project (Toml 'sandbox_mode = "danger-full-access"') -UserFiles @{ '.codex\fast.config.toml' = (Toml 'approval_policy = "never"') })
            Assert-Equal 'high' $f[0].Severity
            Assert-Equal 'profile ''fast'' (--profile fast): approval_policy = "never"; with sandbox_mode = "danger-full-access" (project config): no sandbox and no approval' $f[0].Evidence
        }
        It 'counts profile settings only where they apply' {
            # The profile keeps the sandbox on over the user full access: medium.
            $f = @(Invoke-CdxRule 'AW-CDX-014' -User (Toml 'sandbox_mode = "danger-full-access"') -UserFiles @{ '.codex\fast.config.toml' = (Toml 'approval_policy = "never"' 'sandbox_mode = "workspace-write"') })
            Assert-Equal @('profile ''fast'' (--profile fast): approval_policy = "never"') (Get-Evidence $f)
            Assert-Equal 'medium' $f[0].Severity
            # requirements.toml forbids the full access of the user config.
            $f = @(Invoke-CdxRule 'AW-CDX-014' -User (Toml 'sandbox_mode = "danger-full-access"') -UserFiles @{ '.codex\fast.config.toml' = (Toml 'approval_policy = "never"') } -Requirements (Toml 'allowed_sandbox_modes = ["workspace-write"]'))
            Assert-Equal @('medium') @($f | ForEach-Object { $_.Severity })
            # sandbox_mode in the user config takes precedence over the default_permissions of the profile.
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-014' -User (Toml 'sandbox_mode = "workspace-write"' 'approval_policy = "never"') -UserFiles @{ '.codex\open.config.toml' = (Toml 'default_permissions = ":danger-full-access"') }).Count
            # Permission profiles ignore the [sandbox_workspace_write] table of the profile.
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-014' -User (Toml 'default_permissions = ":workspace"') -UserFiles @{ '.codex\net.config.toml' = (Toml '[sandbox_workspace_write]' 'network_access = true') }).Count
            # A user config that weakens everything on its own is AW-CDX-002's business, not the profile's.
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-014' -User (Toml 'sandbox_mode = "danger-full-access"' 'approval_policy = "never"') -UserFiles @{ '.codex\calm.config.toml' = (Toml 'model = "gpt-fake"') }).Count
        }
        It 'reports legacy [profiles] tables of the user config as low' {
            $f = @(Invoke-CdxRule 'AW-CDX-014' -User (Toml 'model = "gpt-fake"' '[profiles.legacy]' 'approval_policy = "never"' '[profiles.safe]' 'approval_policy = "on-request"'))
            Assert-Equal @('legacy [profiles.legacy] table (user config, read by Codex before 0.134.0 only): approval_policy = "never"') (Get-Evidence $f)
            Assert-Equal 'low' $f[0].Severity
            Assert-Equal 2 $f[0].Location.Line
        }
        It 'ignores other file names and project profiles' {
            $f = @(Invoke-CdxRule 'AW-CDX-014' -UserFiles @{
                '.codex\bad name.config.toml' = (Toml 'sandbox_mode = "danger-full-access"')
                '.codex\notes.toml' = (Toml 'sandbox_mode = "danger-full-access"')
                '.codex\x.config.toml.bak' = (Toml 'sandbox_mode = "danger-full-access"')
                '.codex\calm.config.toml' = (Toml 'approval_policy = "Never"')
            })
            Assert-Equal 0 $f.Count
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-014' -Project (Toml '[profiles.p]' 'sandbox_mode = "danger-full-access"')).Count
        }
    }

    Describe 'Codex discovery' {
        It 'reads the user, project and profile files with their scope' {
            $ctx = Get-CdxContext ([pscustomobject]@{ Root = $projectInsecure; User = $profileInsecure; Requirements = $null })
            Assert-Equal @('user', 'project', 'profile', 'profile') @($ctx.Codex | ForEach-Object { $_.Scope })
            Assert-Equal @('config.toml', 'config.toml', 'review.config.toml', 'yolo.config.toml') @($ctx.Codex | ForEach-Object { Split-Path -Leaf $_.Path })
            Assert-Equal (Join-Path $profileInsecure '.codex\config.toml') $ctx.Codex[0].Path
            Assert-Equal (Join-Path $projectInsecure '.codex\config.toml') $ctx.Codex[1].Path
            foreach ($a in $ctx.Codex) {
                Assert-Equal @('Path', 'Scope', 'Harness', 'Raw', 'Data') @($a.PSObject.Properties.Name)
                Assert-Equal 'codex' $a.Harness
                Assert-True ($a.Data -is [System.Collections.IDictionary]) $a.Path
            }
            Assert-Equal 'danger-full-access' $ctx.Codex[0].Data['sandbox_mode']
            Assert-Equal 'trusted' $ctx.Codex[0].Data['projects']['C:\Users\FAKEUSER']['trust_level']
            Assert-Contains $ctx.Harnesses 'codex'
            Assert-Contains $ctx.Harnesses 'mcp'
            $rules = @($ctx.CodexRules)
            Assert-Equal 1 $rules.Count
            Assert-Equal @('Path', 'Scope', 'Harness', 'Raw', 'Data') @($rules[0].PSObject.Properties.Name)
            Assert-Equal 'project' $rules[0].Scope
            Assert-Equal $null $rules[0].Data
            Assert-Match $rules[0].Raw 'prefix_rule'
            $hooks = @($ctx.Hooks | Where-Object { $_.Harness -eq 'codex' })
            Assert-Equal 1 $hooks.Count
            Assert-Equal (Join-Path $projectInsecure '.codex\hooks.json') $hooks[0].Path
            Assert-Equal 'project' $hooks[0].Scope
            foreach ($p in @(@($ctx.Codex | ForEach-Object { $_.Path }) + @($rules[0].Path, $hooks[0].Path))) { Assert-Contains $ctx.TextFiles $p }
            Assert-Equal 0 @($ctx.Errors).Count
        }
        It 'reads only the project files without a user profile' {
            $ctx = Get-CdxContext ([pscustomobject]@{ Root = $projectInsecure; User = $null; Requirements = $managedFile })
            Assert-Equal @('project') @($ctx.Codex | ForEach-Object { $_.Scope })
            Assert-Equal $null $ctx.UserProfile
            Assert-Contains $ctx.Harnesses 'codex'
        }
        It 'detects Codex from a .codex folder, in the project or the profile' {
            $ctx = Get-CdxContext (New-CdxCase -ProjectFiles @{ '.codex\placeholder.txt' = 'synthetic' })
            Assert-Contains $ctx.Harnesses 'codex'
            Assert-Equal 0 @($ctx.Codex).Count
            Assert-True ($ctx.Codex -is [array])
            Assert-True ($ctx.CodexRules -is [array])
            $ctx = Get-CdxContext (New-CdxCase -UserFiles @{ '.codex\placeholder.txt' = 'synthetic' })
            Assert-Contains $ctx.Harnesses 'codex'
            $ctx = Get-CdxContext (New-CdxCase -UserFiles @{ 'placeholder.txt' = 'synthetic' })
            Assert-NotContains $ctx.Harnesses 'codex'
            Assert-Equal 0 @($ctx.Codex).Count
        }
        It 'reads requirements.toml as a managed file with the user profile only' {
            $ctx = Get-CdxContext ([pscustomobject]@{ Root = $projectHardened; User = $profileHardened; Requirements = $managedFile })
            Assert-Equal @('user', 'project', 'managed') @($ctx.Codex | ForEach-Object { $_.Scope })
            Assert-Equal $managedFile $ctx.Codex[2].Path
            Assert-Equal $true $ctx.Codex[2].Data['allow_managed_hooks_only']
            # Requirements are not MCP files, even when they list allowed servers.
            Assert-Equal @('user', 'project') @($ctx.McpFiles | Where-Object { $_.Harness -eq 'codex' } | ForEach-Object { $_.Scope })
        }
        It 'accepts profile names of letters, digits, hyphens and underscores only' {
            $ctx = Get-CdxContext (New-CdxCase -UserFiles @{
                '.codex\ok_1-A.config.toml' = (Toml 'model = "a"')
                '.codex\bad name.config.toml' = (Toml 'model = "b"')
                '.codex\managed_config.toml' = (Toml 'model = "c"')
                '.codex\notes.toml' = (Toml 'model = "d"')
            })
            Assert-Equal @('ok_1-A.config.toml') @($ctx.Codex | ForEach-Object { Split-Path -Leaf $_.Path })
            Assert-Equal 'profile' $ctx.Codex[0].Scope
        }
        It 'honors CODEX_HOME only for the real profile' {
            $other = New-CdxTree @{ 'config.toml' = (Toml 'sandbox_mode = "danger-full-access"') }
            $saved = $env:CODEX_HOME
            try {
                $env:CODEX_HOME = $other
                $ctx = Get-CdxContext (New-CdxCase -User (Toml 'model = "gpt-fake"'))
                Assert-Equal 1 @($ctx.Codex).Count
                Assert-False ($ctx.Codex[0].Path.StartsWith($other, [StringComparison]::OrdinalIgnoreCase))
                $fakeProfile = 'C:\FAKE\profile'
                Assert-Equal @('C:\FAKE\profile\.codex') @(& $aw { param($u) Get-AwCodexHomes -UserProfile $u -IsRealProfile $false } $fakeProfile)
                Assert-Equal @($other, 'C:\FAKE\profile\.codex') @(& $aw { param($u) Get-AwCodexHomes -UserProfile $u -IsRealProfile $true } $fakeProfile)
                $env:CODEX_HOME = 'relative\codex'
                Assert-Equal @('C:\FAKE\profile\.codex') @(& $aw { param($u) Get-AwCodexHomes -UserProfile $u -IsRealProfile $true } $fakeProfile)
                $env:CODEX_HOME = Join-Path $other 'missing'
                Assert-Equal @('C:\FAKE\profile\.codex') @(& $aw { param($u) Get-AwCodexHomes -UserProfile $u -IsRealProfile $true } $fakeProfile)
                Assert-Equal 0 @(& $aw { Get-AwCodexHomes -UserProfile $null -IsRealProfile $true }).Count
            } finally {
                $env:CODEX_HOME = $saved
            }
        }
        It 'skips a project rules folder whose link leaves the root' {
            $outside = New-CdxTree @{ 'default.rules' = 'prefix_rule(pattern = ["git"])' }
            $case = New-CdxCase -ProjectFiles @{ '.codex\placeholder.txt' = 'synthetic' }
            $link = Join-Path $case.Root '.codex\rules'
            $made = $false
            try {
                [void](New-Item -ItemType Junction -Path $link -Target $outside -ErrorAction Stop)
                $made = $true
            } catch {
                $made = $false
            }
            if ($made) {
                try {
                    $ctx = Get-CdxContext $case
                    Assert-Equal 0 @($ctx.CodexRules).Count
                    Assert-True (@($ctx.Errors | Where-Object { $_.Evidence -match 'symbolic link or junction' }).Count -ge 1)
                } finally {
                    [System.IO.Directory]::Delete($link)
                }
            }
        }
    }

    Describe 'Codex MCP servers' {
        It 'maps mcp_servers tables onto the shape of the MCP rules' {
            $ctx = Get-CdxContext ([pscustomobject]@{ Root = $projectInsecure; User = $profileInsecure; Requirements = $null })
            $mcp = @($ctx.McpFiles | Where-Object { $_.Harness -eq 'codex' })
            Assert-Equal @('user', 'project') @($mcp | ForEach-Object { $_.Scope })
            Assert-Equal @('Path', 'Scope', 'Harness', 'Raw', 'Data') @($mcp[0].PSObject.Properties.Name)
            Assert-Equal @('Servers') @($mcp[0].Data.Keys)
            $u = $mcp[0].Data['Servers']
            Assert-Equal @('docs', 'github') @($u.Keys | Sort-Object)
            Assert-Equal 'npx' $u['github']['command']
            Assert-Equal @('-y', '@modelcontextprotocol/server-github') @($u['github']['args'])
            Assert-Equal $FakeSecrets[5] $u['github']['env']['GITHUB_PERSONAL_ACCESS_TOKEN']
            Assert-Equal 'approve' $u['github']['default_tools_approval_mode']
            Assert-Equal 'http://mcp.example.invalid/mcp' $u['docs']['url']
            Assert-True ($u['docs']['headers'] -is [System.Collections.IDictionary])
            Assert-Equal @('Authorization') @($u['docs']['headers'].Keys)
            Assert-Equal @('local-tools', 'remote') @($mcp[1].Data['Servers'].Keys | Sort-Object)
        }
        It 'takes headers from http_headers only' {
            $ctx = Get-CdxContext (New-CdxCase -User (Toml '[mcp_servers.a]' 'url = "https://a.example.invalid"' 'headers = { Authorization = "Bearer FAKE-ignored-FAKE-0007" }' '' `
                '[mcp_servers.b]' 'url = "https://b.example.invalid"' 'http_headers = { "X-Token" = "FAKE-real-FAKE-0008" }'))
            $s = @($ctx.McpFiles)[0].Data['Servers']
            Assert-False $s['a'].Contains('headers')
            Assert-Equal 'FAKE-real-FAKE-0008' $s['b']['headers']['X-Token']
        }
        It 'runs the AW-MCP rules on Codex servers' {
            $r = Invoke-Airworthy -Path $projectInsecure -UserProfilePath $profileInsecure -PassThru -Quiet
            $mcp = @($r.Findings | Where-Object { $_.RuleId -like 'AW-MCP-*' })
            Assert-Equal @('AW-MCP-001', 'AW-MCP-001', 'AW-MCP-002', 'AW-MCP-002', 'AW-MCP-002', 'AW-MCP-003', 'AW-MCP-004') @($mcp | ForEach-Object { $_.RuleId } | Sort-Object)
            $http = @($mcp | Where-Object { $_.RuleId -eq 'AW-MCP-003' })[0]
            Assert-Equal 'docs.url' $http.Location.Key
            Assert-Equal 48 $http.Location.Line
            $pin = @($mcp | Where-Object { $_.RuleId -eq 'AW-MCP-001' -and $_.Location.Key -eq 'github.command' })[0]
            Assert-Equal 40 $pin.Location.Line
            Assert-Contains $r.Harnesses 'codex'
        }
        It 'runs the container rule on a docker server' {
            $digest = 'a' * 64
            $ctx = Get-CdxContext (New-CdxCase -User (Toml '[mcp_servers.box]' 'command = "docker"' ('args = ["run", "--privileged", "-i", "fake/image@sha256:' + $digest + '"]')))
            $f = @(Invoke-CdxCheck 'AW-MCP-005' $ctx)
            Assert-Equal 1 $f.Count
            Assert-Equal 'box.args' $f[0].Location.Key
            Assert-Equal 1 $f[0].Location.Line
            Assert-Equal 0 @(Invoke-CdxCheck 'AW-MCP-001' $ctx).Count
        }
        It 'keeps the line of a server whose name prefixes another' {
            $ctx = Get-CdxContext (New-CdxCase -User (Toml '[mcp_servers.github]' 'url = "http://gh.example.invalid/mcp"' '' '[mcp_servers.git]' 'url = "http://git.example.invalid/mcp"'))
            $f = @(Invoke-CdxCheck 'AW-MCP-003' $ctx)
            Assert-Equal @('git.url', 'github.url') @($f | ForEach-Object { $_.Location.Key })
            Assert-Equal @(4, 1) @($f | ForEach-Object { $_.Location.Line })
        }
        It 'reports invalid mcp_servers values as AW-CORE-001' {
            $ctx = Get-CdxContext (New-CdxCase -User (Toml 'mcp_servers = "not a table"'))
            Assert-Equal @("Invalid MCP configuration: 'mcp_servers' is not a table.") @($ctx.Errors | ForEach-Object { $_.Evidence })
            Assert-Equal 'codex' $ctx.Errors[0].Harness
            Assert-Equal 0 @($ctx.McpFiles)[0].Data['Servers'].Count
            $ctx = Get-CdxContext (New-CdxCase -User (Toml 'mcp_servers = { a = 1, b = { command = "npx" }, c = [1, 2] }'))
            Assert-Equal @("Invalid MCP configuration: server 'a' is not a table.", "Invalid MCP configuration: server 'c' is not a table.") @($ctx.Errors | ForEach-Object { $_.Evidence })
            Assert-Equal @('b') @(@($ctx.McpFiles)[0].Data['Servers'].Keys)
            Assert-Contains $ctx.Harnesses 'mcp'
        }
        It 'adds no MCP file for a config without mcp_servers' {
            $ctx = Get-CdxContext (New-CdxCase -User (Toml 'model = "gpt-fake"'))
            Assert-Equal 0 @($ctx.McpFiles).Count
            Assert-NotContains $ctx.Harnesses 'mcp'
        }
    }

    Describe 'Codex nested project layers and system config: discovery' {
        It 'reads the .codex/config.toml of the folders below the root, breadth first, within the depth limit' {
            $case = New-CdxCase -Project (Toml 'model = "root"') -ProjectFiles @{
                'packages\app\.codex\config.toml'            = (Toml 'model = "app"')
                'packages\.codex\config.toml'                = (Toml 'model = "packages"')
                'Zeta\.codex\config.toml'                    = (Toml 'model = "zeta"')
                'a\b\c\d\e\f\.codex\config.toml'             = (Toml 'model = "depth6"')
                'a\b\c\d\e\f\g\.codex\config.toml'           = (Toml 'model = "depth7"')
                'node_modules\pkg\.codex\config.toml'        = (Toml 'model = "node_modules"')
                'Build\.codex\config.toml'                   = (Toml 'model = "build"')
                'vendor\lib\.codex\config.toml'              = (Toml 'model = "vendor"')
                '.git\.codex\config.toml'                    = (Toml 'model = "git"')
                '.venv\x\.codex\config.toml'                 = (Toml 'model = "venv"')
                'packages\app\.codex\inner\.codex\config.toml' = (Toml 'model = "inside-codex"')
                'packages\app\notes\config.toml'             = (Toml 'model = "not-a-layer"')
            }
            $ctx = Get-CdxContext $case
            Assert-Equal @('root', 'zeta', 'packages', 'app', 'depth6') @($ctx.Codex | ForEach-Object { $_.Data['model'] })
            Assert-Equal @('project', 'project', 'project', 'project', 'project') @($ctx.Codex | ForEach-Object { $_.Scope })
            Assert-Equal (Join-Path $case.Root 'packages\app\.codex\config.toml') $ctx.Codex[3].Path
            foreach ($a in $ctx.Codex) {
                Assert-Equal @('Path', 'Scope', 'Harness', 'Raw', 'Data') @($a.PSObject.Properties.Name)
                Assert-Contains $ctx.TextFiles $a.Path
            }
            Assert-Equal 0 @($ctx.Errors).Count
            Assert-Contains $ctx.Harnesses 'codex'
        }
        It 'detects Codex from a nested config file alone, and maps its MCP servers' {
            $case = New-CdxCase -ProjectFiles @{ 'svc\api\.codex\config.toml' = (Toml '[mcp_servers.nested]' 'url = "http://nested.example.invalid/mcp"') }
            $ctx = Get-CdxContext $case
            Assert-Contains $ctx.Harnesses 'codex'
            Assert-Contains $ctx.Harnesses 'mcp'
            $mcp = @($ctx.McpFiles | Where-Object { $_.Harness -eq 'codex' })
            Assert-Equal 1 $mcp.Count
            Assert-Equal 'project' $mcp[0].Scope
            Assert-Equal (Join-Path $case.Root 'svc\api\.codex\config.toml') $mcp[0].Path
            Assert-Equal @('nested') @($mcp[0].Data['Servers'].Keys)
            $r = Invoke-Airworthy -Path $case.Root -NoUserProfile -PassThru -Quiet
            $http = @($r.Findings | Where-Object { $_.RuleId -eq 'AW-MCP-003' })
            Assert-Equal 1 $http.Count
            Assert-Match $http[0].Location.Path '\\svc\\api\\\.codex\\config\.toml$'
            Assert-Equal 1 $http[0].Location.Line
        }
        It 'caps the nested files and the folders searched, with AW-CORE-001' {
            $files = @{}
            for ($i = 0; $i -le 50; $i++) { $files[('d{0:D2}\.codex\config.toml' -f $i)] = (Toml ('model = "m{0}"' -f $i)) }
            $ctx = Get-CdxContext (New-CdxCase -ProjectFiles $files)
            Assert-Equal 50 @($ctx.Codex).Count
            Assert-Equal 'm49' $ctx.Codex[49].Data['model']
            Assert-Equal @('More than 50 nested .codex/config.toml files; only the first 50 were analyzed.') @($ctx.Errors | ForEach-Object { $_.Evidence })
            Assert-Equal 'codex' $ctx.Errors[0].Harness
            # Folder budget: the folders already queued are still checked, no further one is queued.
            $case = New-CdxCase -ProjectFiles @{
                'a\.codex\config.toml' = (Toml 'model = "a"'); 'b\.codex\config.toml' = (Toml 'model = "b"')
                'c\.codex\config.toml' = (Toml 'model = "c"'); 'd\.codex\config.toml' = (Toml 'model = "d"')
                'a\deep\.codex\config.toml' = (Toml 'model = "a-deep"')
            }
            $saved = & $aw { $script:AwCodexMaxNestedDirs }
            try {
                & $aw { $script:AwCodexMaxNestedDirs = 3 }
                $ctx = Get-CdxContext $case
            } finally {
                & $aw { param($v) $script:AwCodexMaxNestedDirs = $v } $saved
            }
            Assert-Equal @('a', 'b', 'c') @($ctx.Codex | ForEach-Object { $_.Data['model'] })
            Assert-Equal @('Stopped looking for nested .codex/config.toml files after 3 folders.') @($ctx.Errors | ForEach-Object { $_.Evidence })
        }
        It 'applies the size limit and the TOML errors to nested files' {
            $ctx = Get-CdxContext (New-CdxCase -ProjectFiles @{
                'big\.codex\config.toml' = ('a = "' + ('x' * (2MB)) + '"')
                'bad\.codex\config.toml' = (Toml 'ok = 1' 'broken = ')
            })
            $e = @($ctx.Errors | ForEach-Object { $_.Evidence })
            Assert-Equal 2 $e.Count
            Assert-Match $e[0] '^Invalid TOML at line 2'
            Assert-Match $e[1] 'larger than 2 MB'
            Assert-Equal @('project') @($ctx.Codex | ForEach-Object { $_.Scope })
            Assert-Equal $null $ctx.Codex[0].Data
        }
        It 'enters no link or junction, and skips a nested .codex link that leaves the root' {
            $outside = New-CdxTree @{ '.codex\config.toml' = (Toml 'sandbox_mode = "danger-full-access"'); 'inner\.codex\config.toml' = (Toml 'model = "outside"') }
            $case = New-CdxCase -ProjectFiles @{ 'pkg\README.md' = 'synthetic'; 'inside\.codex\config.toml' = (Toml 'model = "inside"') }
            $links = @((Join-Path $case.Root 'linked'), (Join-Path $case.Root 'loop'), (Join-Path $case.Root 'pkg\.codex'))
            $made = (New-CdxJunction $links[0] $outside) -and (New-CdxJunction $links[1] $case.Root) -and (New-CdxJunction $links[2] (Join-Path $outside '.codex'))
            try {
                if ($made) {
                    $ctx = Get-CdxContext $case
                    Assert-Equal @('inside') @($ctx.Codex | ForEach-Object { $_.Data['model'] })
                    $e = @($ctx.Errors)
                    Assert-Equal 1 $e.Count
                    Assert-Match $e[0].Evidence 'symbolic link or junction leads outside the analyzed root'
                    Assert-Match $e[0].Location.Path '\\pkg\\\.codex\\config\.toml$'
                }
            } finally {
                foreach ($l in $links) { if ([System.IO.Directory]::Exists($l)) { [System.IO.Directory]::Delete($l) } }
            }
        }
        It 'reads the system config.toml through the test hook only, as the lowest layer' {
            $case = New-CdxCase -User (Toml 'model = "user"') -Project (Toml 'model = "project"') -System (Toml 'model = "system"' '[mcp_servers.sys]' 'command = "fake-server"')
            $ctx = Get-CdxContext $case
            Assert-Equal @('user', 'project', 'system') @($ctx.Codex | ForEach-Object { $_.Scope })
            Assert-Equal $case.System $ctx.Codex[2].Path
            Assert-Equal @('system') @($ctx.McpFiles | Where-Object { $_.Harness -eq 'codex' } | ForEach-Object { $_.Scope })
            Assert-Contains $ctx.TextFiles $case.System
            # Never without a user profile, and never without the hook in tests.
            $ctx = Get-CdxContext ([pscustomobject]@{ Root = $case.Root; User = $null; Requirements = $null; System = $case.System })
            Assert-Equal @('project') @($ctx.Codex | ForEach-Object { $_.Scope })
            $ctx = Get-CdxContext ([pscustomobject]@{ Root = $case.Root; User = $case.User; Requirements = $null })
            Assert-Equal @('user', 'project') @($ctx.Codex | ForEach-Object { $_.Scope })
            # Unix only: no Windows location is documented.
            $candidates = @(& $aw { Get-AwCodexSystemConfigCandidates })
            if (& $aw { $script:AwIsWindowsOS }) { Assert-Equal 0 $candidates.Count } else { Assert-Equal @('/etc/codex/config.toml') $candidates }
        }
    }

    Describe 'Codex nested project layers and system config: rules' {
        It 'points to the nested or system file that sets the value' {
            $f = @(Invoke-CdxRule 'AW-CDX-001' -ProjectFiles @{ 'packages\app\.codex\config.toml' = (Toml '# nested' 'sandbox_mode = "danger-full-access"') } -System (Toml 'default_permissions = ":danger-full-access"'))
            Assert-Equal @('sandbox_mode = "danger-full-access" (project config in ''packages/app'')', 'default_permissions = ":danger-full-access" (system config)') (Get-Evidence $f)
            Assert-Match $f[0].Location.Path '\\packages\\app\\\.codex\\config\.toml$'
            Assert-Equal 2 $f[0].Location.Line
            Assert-Match $f[1].Location.Path '\\config\.toml$'
            $f = @(Invoke-CdxRule 'AW-CDX-011' -Project (Toml 'web_search = "live"') -ProjectFiles @{ 'docs\.codex\config.toml' = (Toml 'web_search = "live"') })
            Assert-Equal @('web_search = "live" (project config)', 'web_search = "live" (project config in ''docs'')') (Get-Evidence $f)
            Assert-Equal 'critical' @(Invoke-CdxRule 'AW-CDX-009' -ProjectFiles @{ 'svc\.codex\config.toml' = (Toml 'mcp_servers.r.oauth.client_secret = "FAKE-nested-secret-FAKE-0010"') })[0].Severity
        }
        It 'AW-CDX-002 stacks each folder: nested > intermediate > root project > user > system' {
            # The root approval and the nested full access apply together in the nested folder.
            $f = @(Invoke-CdxRule 'AW-CDX-002' -Project (Toml 'approval_policy = "never"') -ProjectFiles @{ 'packages\app\.codex\config.toml' = (Toml 'sandbox_mode = "danger-full-access"') })
            Assert-Equal @('approval_policy = "never" (project config); with sandbox_mode = "danger-full-access" (project config in ''packages/app''): no sandbox and no approval') (Get-Evidence $f)
            Assert-Equal 'critical' $f[0].Severity
            Assert-Match $f[0].Location.Path '\\[0-9a-f]{12}\\\.codex\\config\.toml$'
            # An intermediate layer over the root, under the nested one.
            $f = @(Invoke-CdxRule 'AW-CDX-002' -Project (Toml 'approval_policy = "on-request"') -ProjectFiles @{
                'packages\.codex\config.toml' = (Toml 'approval_policy = "never"')
                'packages\app\.codex\config.toml' = (Toml 'sandbox_mode = "danger-full-access"') })
            Assert-Equal @('approval_policy = "never" (project config in ''packages''); with sandbox_mode = "danger-full-access" (project config in ''packages/app''): no sandbox and no approval') (Get-Evidence $f)
            Assert-Match $f[0].Location.Path '\\packages\\\.codex\\config\.toml$'
        }
        It 'AW-CDX-002 does not combine layers that never apply together' {
            # The nested folder overrides the root approval; the root folder keeps its sandbox.
            $f = @(Invoke-CdxRule 'AW-CDX-002' -Project (Toml 'approval_policy = "never"') -ProjectFiles @{ 'app\.codex\config.toml' = (Toml 'approval_policy = "on-request"' 'sandbox_mode = "danger-full-access"') })
            Assert-Equal @('medium') @($f | ForEach-Object { $_.Severity })
            # Sibling folders never stack.
            $f = @(Invoke-CdxRule 'AW-CDX-002' -ProjectFiles @{ 'a\.codex\config.toml' = (Toml 'approval_policy = "never"'); 'b\.codex\config.toml' = (Toml 'sandbox_mode = "danger-full-access"') })
            Assert-Equal @('medium') @($f | ForEach-Object { $_.Severity })
            # A trusted project loads all its layers, an untrusted one none: the nested full access
            # never applies without the root approval above the user one.
            $f = @(Invoke-CdxRule 'AW-CDX-002' -User (Toml 'approval_policy = "never"') -Project (Toml 'approval_policy = "on-request"') -ProjectFiles @{ 'app\.codex\config.toml' = (Toml 'sandbox_mode = "danger-full-access"') })
            Assert-Equal @('approval_policy = "never" (user config)') (Get-Evidence $f)
            Assert-Equal 'medium' $f[0].Severity
        }
        It 'AW-CDX-002 puts the system config below the user config' {
            $f = @(Invoke-CdxRule 'AW-CDX-002' -User (Toml 'approval_policy = "never"') -System (Toml 'sandbox_mode = "danger-full-access"'))
            Assert-Equal @('approval_policy = "never" (user config); with sandbox_mode = "danger-full-access" (system config): no sandbox and no approval') (Get-Evidence $f)
            Assert-Equal 'critical' $f[0].Severity
            $f = @(Invoke-CdxRule 'AW-CDX-002' -User (Toml 'approval_policy = "never"' 'sandbox_mode = "workspace-write"') -System (Toml 'sandbox_mode = "danger-full-access"'))
            Assert-Equal 'medium' $f[0].Severity
            $f = @(Invoke-CdxRule 'AW-CDX-002' -User (Toml 'model = "gpt-fake"') -System (Toml 'approval_policy = "never"' 'sandbox_mode = "danger-full-access"'))
            Assert-Equal @('approval_policy = "never" (system config); with sandbox_mode = "danger-full-access" (system config): no sandbox and no approval') (Get-Evidence $f)
            # A user approval overrides the system one.
            $f = @(Invoke-CdxRule 'AW-CDX-002' -User (Toml 'approval_policy = "on-request"') -System (Toml 'approval_policy = "never"' 'sandbox_mode = "danger-full-access"'))
            Assert-Equal @('approval_policy = "never" (system config)') (Get-Evidence $f)
            Assert-Equal 'medium' $f[0].Severity
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-002' -User (Toml 'approval_policy = "never"') -System (Toml 'sandbox_mode = "danger-full-access"') -Requirements (Toml 'allowed_approval_policies = ["on-request"]') | Where-Object { $_.Severity -ne 'info' }).Count
        }
        It 'AW-CDX-003 follows the sandbox mode of the folder chain and of the system config' {
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-003' -Project (Toml 'sandbox_mode = "read-only"') -ProjectFiles @{ 'pkg\.codex\config.toml' = (Toml '[sandbox_workspace_write]' 'network_access = true') }).Count
            $f = @(Invoke-CdxRule 'AW-CDX-003' -Project (Toml 'sandbox_mode = "workspace-write"') -ProjectFiles @{ 'pkg\.codex\config.toml' = (Toml '[sandbox_workspace_write]' 'network_access = true') })
            Assert-Equal @('sandbox_workspace_write.network_access = true (project config in ''pkg'')') (Get-Evidence $f)
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-003' -User (Toml '[sandbox_workspace_write]' 'network_access = true') -System (Toml 'sandbox_mode = "read-only"')).Count
            Assert-Equal 1 @(Invoke-CdxRule 'AW-CDX-003' -User (Toml '[sandbox_workspace_write]' 'network_access = true') -System (Toml 'sandbox_mode = "workspace-write"')).Count
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-003' -User (Toml '[sandbox_workspace_write]' 'network_access = true') -System (Toml 'default_permissions = ":workspace"')).Count
        }
        It 'AW-CDX-004 sees a network proxy turned off in a nested folder, or on in the system config' {
            $t = Toml '[features]' 'network_proxy = true' '[permissions.dev.network]' 'enabled = true'
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-004' -Project $t).Count
            $f = @(Invoke-CdxRule 'AW-CDX-004' -Project $t -ProjectFiles @{ 'tools\.codex\config.toml' = (Toml '[features]' 'network_proxy = false') })
            Assert-Equal 1 $f.Count
            Assert-Match $f[0].Evidence 'network proxy is off.*\(project config\)$'
            $perm = Toml '[permissions.dev.network]' 'enabled = true'
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-004' -User $perm -System (Toml '[features]' 'network_proxy = true')).Count
            Assert-Equal 1 @(Invoke-CdxRule 'AW-CDX-004' -User $perm -System (Toml '[features]' 'network_proxy = false')).Count
        }
        It 'AW-CDX-012 lists the hooks of nested config files and follows the hooks flag per folder' {
            $nested = Toml '[[hooks.Stop]]' '[[hooks.Stop.hooks]]' 'type = "command"' 'command = "./nested-stop.sh"'
            $f = @(Invoke-CdxRule 'AW-CDX-012' -ProjectFiles @{ 'pkg\.codex\config.toml' = $nested })
            Assert-Equal @('hook Stop command: ./nested-stop.sh') (Get-Evidence $f)
            Assert-Match $f[0].Location.Path '\\pkg\\\.codex\\config\.toml$'
            Assert-Equal 1 $f[0].Location.Line
            # The root flag applies in the nested folder too.
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-012' -Project (Toml '[features]' 'hooks = false') -ProjectFiles @{ 'pkg\.codex\config.toml' = $nested }).Count
            $json = '{ "hooks": { "Stop": [ { "hooks": [ { "type": "command", "command": "./stop.sh" } ] } ] } }'
            # A nested flag turns hooks off in its folder only: the root hooks still run at the root.
            $f = @(Invoke-CdxRule 'AW-CDX-012' -ProjectFiles @{ '.codex\hooks.json' = $json; 'pkg\.codex\config.toml' = (Toml '[features]' 'hooks = false') })
            Assert-Equal @('hook Stop command: ./stop.sh') (Get-Evidence $f)
            # Hooks off at the root but turned on below it: the evidence names the nested file.
            $f = @(Invoke-CdxRule 'AW-CDX-012' -Project (Toml '[features]' 'hooks = false') -ProjectFiles @{ '.codex\hooks.json' = $json; 'pkg\.codex\config.toml' = (Toml '[features]' 'hooks = true') })
            Assert-Equal @('hook Stop command: ./stop.sh; hooks are off in its folder but on below it (features.hooks = true, project config in ''pkg'')') (Get-Evidence $f)
            Assert-Match $f[0].Location.Path '\\\.codex\\hooks\.json$'
        }
        It 'AW-CDX-012 finds the root config when the analyzed folder is a drive root' {
            $json = '{ "hooks": { "Stop": [ { "hooks": [ { "type": "command", "command": "./stop.sh" } ] } ] } }'
            # The same files seen from a drive root (Root 'X:\', files under 'X:\.codex\').
            $atDrive = {
                param($Ctx)
                $move = { param($a) $c = $a.PSObject.Copy(); $c.Path = 'X:\.codex\' + (Split-Path -Leaf $a.Path); $c }
                $copy = $Ctx.PSObject.Copy()
                $copy.Root = 'X:\'
                $copy.Codex = @($Ctx.Codex | ForEach-Object { & $move $_ })
                $copy.Hooks = @($Ctx.Hooks | ForEach-Object { & $move $_ })
                return $copy
            }
            $off = Get-CdxContext (New-CdxCase -Project (Toml '[features]' 'hooks = false') -ProjectFiles @{ '.codex\hooks.json' = $json })
            Assert-Equal 0 @(Invoke-CdxCheck 'AW-CDX-012' $off).Count
            Assert-Equal 0 @(Invoke-CdxCheck 'AW-CDX-012' (& $atDrive $off)).Count
            $on = Get-CdxContext (New-CdxCase -Project (Toml 'model = "gpt-fake"') -ProjectFiles @{ '.codex\hooks.json' = $json })
            Assert-Equal @('hook Stop command: ./stop.sh') (Get-Evidence @(Invoke-CdxCheck 'AW-CDX-012' (& $atDrive $on)))
        }
        It 'AW-CDX-012 puts the system hooks flag below the user one' {
            $json = '{ "hooks": { "Stop": [ { "hooks": [ { "type": "command", "command": "./stop.sh" } ] } ] } }'
            Assert-Equal 0 @(Invoke-CdxRule 'AW-CDX-012' -ProjectFiles @{ '.codex\hooks.json' = $json } -System (Toml '[features]' 'hooks = false')).Count
            Assert-Equal 1 @(Invoke-CdxRule 'AW-CDX-012' -ProjectFiles @{ '.codex\hooks.json' = $json } -User (Toml '[features]' 'hooks = true') -System (Toml '[features]' 'hooks = false')).Count
            Assert-Equal 1 @(Invoke-CdxRule 'AW-CDX-012' -ProjectFiles @{ '.codex\hooks.json' = $json } -System (Toml '[features]' 'codex_hooks = true')).Count
        }
        It 'AW-CDX-012 evaluates each Codex home on its own (regression: CODEX_HOME and ~/.codex)' {
            $json = '{ "hooks": { "Stop": [ { "hooks": [ { "type": "command", "command": "./stop.sh" } ] } ] } }'
            $project = Get-CdxContext (New-CdxCase -User (Toml 'model = "gpt-fake"') -ProjectFiles @{ '.codex\hooks.json' = $json })
            $silent = Get-CdxContext (New-CdxCase -User (Toml '[features]' 'hooks = false'))
            $silentToo = Get-CdxContext (New-CdxCase -User (Toml '[features]' 'codex_hooks = false'))
            # hooks = false in the home that is not active must not silence the active one, in either order.
            $two = Join-CdxHomes $project @($project, $silent)
            Assert-Equal 2 @($two.Codex | Where-Object { $_.Scope -eq 'user' }).Count
            Assert-Equal @('hook Stop command: ./stop.sh') (Get-Evidence @(Invoke-CdxCheck 'AW-CDX-012' $two))
            Assert-Equal 1 @(Invoke-CdxCheck 'AW-CDX-012' (Join-CdxHomes $project @($silent, $project))).Count
            # Silent when both homes turn hooks off.
            Assert-Equal 0 @(Invoke-CdxCheck 'AW-CDX-012' (Join-CdxHomes $project @($silent, $silentToo))).Count
            # The project config still wins over both homes.
            $on = Get-CdxContext (New-CdxCase -Project (Toml '[features]' 'hooks = true') -ProjectFiles @{ '.codex\hooks.json' = $json })
            Assert-Equal 1 @(Invoke-CdxCheck 'AW-CDX-012' (Join-CdxHomes $on @($silent, $silentToo))).Count
            # The other rules already stack each home on its own.
            $full = Get-CdxContext (New-CdxCase -User (Toml 'sandbox_mode = "danger-full-access"'))
            $never = Get-CdxContext (New-CdxCase -User (Toml 'approval_policy = "never"'))
            Assert-Equal @('medium') @(Invoke-CdxCheck 'AW-CDX-002' (Join-CdxHomes $never @($never, $full)) | ForEach-Object { $_.Severity })
        }
        It 'AW-CDX-014 stacks a profile with the nested chain and the system config' {
            $f = @(Invoke-CdxRule 'AW-CDX-014' -UserFiles @{ '.codex\fast.config.toml' = (Toml 'approval_policy = "never"') } -System (Toml 'sandbox_mode = "danger-full-access"'))
            Assert-Equal @('profile ''fast'' (--profile fast): approval_policy = "never"; with sandbox_mode = "danger-full-access" (system config): no sandbox and no approval') (Get-Evidence $f)
            Assert-Equal 'high' $f[0].Severity
            $f = @(Invoke-CdxRule 'AW-CDX-014' -UserFiles @{ '.codex\fast.config.toml' = (Toml 'approval_policy = "never"') } -ProjectFiles @{ 'pkg\.codex\config.toml' = (Toml 'sandbox_mode = "danger-full-access"') })
            Assert-Equal @('profile ''fast'' (--profile fast): approval_policy = "never"; with sandbox_mode = "danger-full-access" (project config in ''pkg''): no sandbox and no approval') (Get-Evidence $f)
            # The profile is above the system config: its sandbox mode wins.
            $f = @(Invoke-CdxRule 'AW-CDX-014' -UserFiles @{ '.codex\fast.config.toml' = (Toml 'approval_policy = "never"' 'sandbox_mode = "workspace-write"') } -System (Toml 'sandbox_mode = "danger-full-access"'))
            Assert-Equal 'medium' $f[0].Severity
        }
        It 'keeps the layer stacks cheap with 50 nested folders and hostile permission tables' {
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.Append("[features]`nnetwork_proxy = true`n")
            for ($i = 1; $i -le 2000; $i++) { [void]$sb.Append("[permissions.p$i.network]`nenabled = true`n") }
            $files = @{}
            for ($i = 0; $i -lt 50; $i++) { $files[('n{0:D2}\.codex\config.toml' -f $i)] = (Toml 'approval_policy = "never"' '[features]' 'network_proxy = false' 'hooks = true') }
            $files['.codex\hooks.json'] = '{ "hooks": { "Stop": [ { "hooks": [ { "type": "command", "command": "./stop.sh" } ] } ] } }'
            $ctx = Get-CdxContext (New-CdxCase -User (Toml 'sandbox_mode = "danger-full-access"') -Project $sb.ToString() -ProjectFiles $files)
            Assert-Equal 52 @($ctx.Codex).Count
            # The layers are computed once per context.
            $same = & $aw { param($c) [object]::ReferenceEquals((Get-AwCdxLayers $c), (Get-AwCdxLayers $c)) } $ctx
            Assert-True $same
            foreach ($id in @('AW-CDX-002', 'AW-CDX-003', 'AW-CDX-004', 'AW-CDX-012', 'AW-CDX-014')) {
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $f = @(Invoke-CdxCheck $id $ctx)
                $ms = $sw.ElapsedMilliseconds
                Assert-True ($ms -lt 3000) "$id took $ms ms"
                if ($id -eq 'AW-CDX-004') { Assert-Equal 20 $f.Count }
                if ($id -eq 'AW-CDX-002') { Assert-Equal 50 @($f | Where-Object { $_.Severity -eq 'critical' }).Count }
            }
        }
    }

    Describe 'Codex discovery: hostile TOML' {
        It 'turns an invalid file into AW-CORE-001 and keeps the analysis going' {
            $ctx = Get-CdxContext ([pscustomobject]@{ Root = $projectInvalid; User = $profileHardened; Requirements = $null })
            $e = @($ctx.Errors)
            Assert-Equal 1 $e.Count
            Assert-Equal 'AW-CORE-001' $e[0].RuleId
            Assert-Equal 'codex' $e[0].Harness
            Assert-Equal 3 $e[0].Location.Line
            Assert-Match $e[0].Evidence '^Invalid TOML at line 3'
            Assert-Match $e[0].Location.Path '\\\.codex\\config\.toml$'
            Assert-Equal @('user', 'project') @($ctx.Codex | ForEach-Object { $_.Scope })
            Assert-True ($ctx.Codex[0].Data -is [System.Collections.IDictionary])
            Assert-Equal $null $ctx.Codex[1].Data
            Assert-Match $ctx.Codex[1].Raw 'approval_policy'
            $r = Invoke-Airworthy -Path $projectInvalid -UserProfilePath $profileHardened -PassThru -Quiet
            Assert-Equal 1 @($r.Findings | Where-Object { $_.RuleId -eq 'AW-CORE-001' }).Count
            Assert-Equal 0 @($r.Findings | Where-Object { $_.RuleId -eq 'AW-CORE-002' }).Count
        }
        It 'skips files larger than 2 MB' {
            $ctx = Get-CdxContext (New-CdxCase -Project ('a = "' + ('x' * (2MB)) + '"'))
            Assert-Equal 1 @($ctx.Errors).Count
            Assert-Match $ctx.Errors[0].Evidence 'larger than 2 MB'
            Assert-Equal 0 @($ctx.Codex).Count
        }
        It 'rejects deep nesting, unterminated strings and oversized documents in under 2 seconds' {
            $cases = [ordered]@{
                'deep arrays'          = 'a = ' + ('[' * 20000) + (']' * 20000)
                'deep inline tables'   = 'a = ' + ('{ b = ' * 5000) + '1' + (' }' * 5000)
                'deep tables'          = '[' + ((@(1..5000) | ForEach-Object { 't' }) -join '.') + ']'
                'unterminated string'  = 'a = "' + ('x' * 1900000)
                'unterminated literal' = "a = '" + ('y' * 1900000)
                'many keys'            = ((@(1..60000) | ForEach-Object { 'k' + $_ + ' = 1' }) -join "`n")
            }
            # Every case runs: the slow or failing ones are listed together at the end.
            $problems = New-Object System.Collections.Generic.List[string]
            foreach ($name in $cases.Keys) {
                try {
                    $case = New-CdxCase -Project $cases[$name]
                    $sw = [System.Diagnostics.Stopwatch]::StartNew()
                    $ctx = Get-CdxContext $case
                    $ms = $sw.ElapsedMilliseconds
                    $count = @($ctx.Errors | Where-Object { $_.RuleId -eq 'AW-CORE-001' -and $_.Harness -eq 'codex' }).Count
                    if ($count -ne 1) { $problems.Add("$name gave $count AW-CORE-001 findings") }
                    if ($null -ne $ctx.Codex[0].Data) { $problems.Add("$name was parsed") }
                    if ($ms -ge 2000) { $problems.Add("$name took $ms ms") }
                } catch {
                    $problems.Add("$name failed: " + $_.Exception.Message)
                }
            }
            Assert-Equal @() $problems.ToArray() 'slow or failing cases'
        }
        It 'reports 2 MB lines, huge arrays, escape floods, unterminated strings and stray CRs as AW-CORE-001 in under 2 seconds' {
            $n = 2MB - 64
            $mixed = New-Object System.Text.StringBuilder
            for ($i = 0; $i -lt 4000; $i++) { if ($i % 2) { [void]$mixed.Append("k$i = 1`r`n") } else { [void]$mixed.Append("k$i = 1`n") } }
            $cases = [ordered]@{
                '2 MB line, unterminated multi-line string'  = 'a = """' + ('x' * ($n - 7))
                '2 MB line, unterminated multi-line literal' = "a = '''" + ('x' * ($n - 7))
                '2 MB line, invalid escape at the end'       = 'a = "' + ('x' * ($n - 8)) + '\q"'
                '2 MB line of backslashes'                   = 'a = "' + ('\' * ($n - 7)) + '"'
                'array of 500k strings'                      = 'a = [' + ('"x",' * 500000) + ']'
                'multi-line array of 200k commented lines'   = "a = [`n" + ("  1, # c`n" * 200000) + ']'
                'inline table of 60k keys'                   = 'a = {' + ((@(1..60000) | ForEach-Object { "k$_=1" }) -join ',') + '}'
                '180k unicode escapes'                       = 'a = "' + ('\U00000041' * 180000) + '"'
                'surrogate escape after valid escapes'       = 'a = "' + ('\U0001F600' * 1000) + '\uD800"'
                'unterminated line-ending backslashes'       = 'a = """' + (('\' + "`n") * 900000)
                'unterminated quote pairs'                   = 'a = """' + ('""x' * 650000)
                'unterminated multi-line literal of lines'   = "a = '''" + ("x`n" * 1000000)
                'mixed CRLF and LF, then a bare CR'          = $mixed.ToString() + "z = 1`rbad = 2`n"
                'bare CR in a CRLF multi-line string'        = "a = '''" + ("line`r`n" * 150000) + "x`ry'''"
                'bare CR in a comment'                       = "a = 1`r`n# note`r more`r`n"
                'bare CR at the end of a CRLF document'      = "a = 1`r`n" + ("# c`r`n" * 100000) + "`r"
            }
            # Every case runs: the slow or failing ones are listed together at the end.
            $problems = New-Object System.Collections.Generic.List[string]
            foreach ($name in $cases.Keys) {
                try {
                    if ($cases[$name].Length -gt $n + 64) { $problems.Add("$name is larger than the size limit"); continue }
                    $case = New-CdxCase -Project $cases[$name]
                    $sw = [System.Diagnostics.Stopwatch]::StartNew()
                    $ctx = Get-CdxContext $case
                    $ms = $sw.ElapsedMilliseconds
                    $seen = $name + ': ' + (@($ctx.Errors | ForEach-Object { $_.Evidence }) -join '; ')
                    $count = @($ctx.Errors | Where-Object { $_.RuleId -eq 'AW-CORE-001' -and $_.Harness -eq 'codex' }).Count
                    if ($count -ne 1) { $problems.Add("$count AW-CORE-001 findings for $seen") }
                    elseif ($ctx.Errors[0].Evidence -notmatch '^Invalid TOML at line [0-9]+') { $problems.Add("unexpected evidence for $seen") }
                    if ($null -ne $ctx.Codex[0].Data) { $problems.Add("$name was parsed") }
                    if ($ms -ge 2000) { $problems.Add("$name took $ms ms") }
                } catch {
                    $problems.Add("$name failed: " + $_.Exception.Message)
                }
            }
            Assert-Equal @() $problems.ToArray() 'slow or failing cases'
        }
        It 'keeps line lookups linear and lists at most 20 findings per file and kind on hostile entries' {
            # Keys padded with spaces trim to '~' after a long run of spaces: a key search for each
            # of them used to cost the length of the run times the length of the key.
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.Append("[permissions.p.filesystem]`n#" + (' ' * 1000000) + "`n")
            for ($i = 1; $i -le 300; $i++) { [void]$sb.Append('"' + (' ' * $i) + '~" = "write"' + "`n") }
            $ctx = Get-CdxContext (New-CdxCase -Project $sb.ToString())
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $f = @(Invoke-CdxCheck 'AW-CDX-005' $ctx)
            $ms = $sw.ElapsedMilliseconds
            Assert-Equal 20 $f.Count
            Assert-True ($ms -lt 2000) "AW-CDX-005 took $ms ms"
            Assert-Equal 1 $f[0].Location.Line 'the header line, since padded keys are not searched'
            # Thirty servers and thirty writable roots: twenty findings of each kind.
            $t = New-Object System.Text.StringBuilder
            [void]$t.Append('[sandbox_workspace_write]' + "`n" + 'writable_roots = [' + ((@(1..30) | ForEach-Object { '"~' + ('/' * $_) + '"' }) -join ', ') + "]`n")
            for ($i = 1; $i -le 30; $i++) { [void]$t.Append("[mcp_servers.s$i]`ncommand = `"fake-server`"`ndefault_tools_approval_mode = `"approve`"`n") }
            $case = New-CdxCase -User $t.ToString()
            $ctx = Get-CdxContext $case
            Assert-Equal 20 @(Invoke-CdxCheck 'AW-CDX-005' $ctx).Count
            Assert-Equal 20 @(Invoke-CdxCheck 'AW-CDX-008' $ctx).Count
            $r = Invoke-Airworthy -Path $case.Root -UserProfilePath $case.User -PassThru -Quiet
            Assert-Equal 'high' @($r.Findings | Where-Object { $_.RuleId -eq 'AW-CDX-008' })[0].Severity
            # A million blank lines before the servers: lines stay exact and cheap to count.
            $blank = ("`n" * 1000000) + (Toml '[mcp_servers.s1]' 'default_tools_approval_mode = "approve"' '[mcp_servers.s2]' 'default_tools_approval_mode = "approve"')
            $ctx = Get-CdxContext (New-CdxCase -Project $blank)
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $f = @(Invoke-CdxCheck 'AW-CDX-008' $ctx)
            $ms = $sw.ElapsedMilliseconds
            Assert-Equal @(1000002, 1000004) @($f | ForEach-Object { $_.Location.Line })
            Assert-True ($ms -lt 2000) "AW-CDX-008 took $ms ms"
        }
        It 'accepts a long comment-only document' {
            $ctx = Get-CdxContext (New-CdxCase -Project ('# ' + ('#' * 1900000)))
            Assert-Equal 0 @($ctx.Errors).Count
            Assert-Equal 0 $ctx.Codex[0].Data.Count
        }
        It 'never fails a rule on values of the wrong type' {
            $odd = Toml 'sandbox_mode = ["danger-full-access"]' 'approval_policy = 1' 'web_search = { live = true }' 'default_permissions = []' `
                        'sandbox_workspace_write = "x"' 'shell_environment_policy = { inherit = 1, filters = [] }' 'permissions = 3' 'projects = ["/"]' `
                        'model_providers = "p"' 'hooks = [1]' 'profiles = { a = 1, b = { sandbox_mode = 2 } }' 'plugins = { p = { mcp_servers = 1 } }' `
                        'features = { network_proxy = [1], hooks = "no" }' 'mcp_servers = { s = { command = 1, args = "x", env = [1], http_headers = 2, tools = 3, oauth = 4 } }'
            $case = New-CdxCase -User $odd -Project $odd -UserFiles @{ '.codex\odd.config.toml' = $odd } -ProjectFiles @{ '.codex\hooks.json' = '{ "hooks": { "Stop": 1, "X": [1, { "hooks": 2 }] } }'; '.codex\rules\odd.rules' = 'x = prefix_rule' }
            $r = Invoke-Airworthy -Path $case.Root -UserProfilePath $case.User -PassThru -Quiet
            Assert-Equal 0 @($r.Findings | Where-Object { $_.RuleId -eq 'AW-CORE-002' }).Count
            Assert-Equal 0 @($r.Findings | Where-Object { $_.RuleId -like 'AW-CDX-*' }).Count
        }
    }

    Describe 'Codex fixtures through the engine' {
        It 'reports every AW-CDX rule on the insecure fixtures' {
            $r = Invoke-Airworthy -Path $projectInsecure -UserProfilePath $profileInsecure -PassThru -Quiet
            $ids = @($r.Findings | Where-Object { $_.RuleId -like 'AW-CDX-*' } | ForEach-Object { $_.RuleId } | Sort-Object)
            Assert-Equal @('AW-CDX-001', 'AW-CDX-002', 'AW-CDX-003', 'AW-CDX-004', 'AW-CDX-005', 'AW-CDX-005', 'AW-CDX-006', 'AW-CDX-007',
                           'AW-CDX-008', 'AW-CDX-008', 'AW-CDX-009', 'AW-CDX-009', 'AW-CDX-009', 'AW-CDX-010', 'AW-CDX-011', 'AW-CDX-011',
                           'AW-CDX-012', 'AW-CDX-012', 'AW-CDX-012', 'AW-CDX-013', 'AW-CDX-013', 'AW-CDX-014', 'AW-CDX-014') $ids
            Assert-Equal 'critical' @($r.Findings | Where-Object { $_.RuleId -eq 'AW-CDX-002' })[0].Severity
            Assert-Equal 0 @($r.Findings | Where-Object { $_.RuleId -eq 'AW-CORE-002' }).Count
            Assert-Equal 'F' $r.Score.Grade
            Assert-True ($r.Score.Categories['sandbox-network'].Applicable)
        }
        It 'reports no AW-CDX or AW-MCP finding on the hardened fixtures' {
            $r = Invoke-Airworthy -Path $projectHardened -UserProfilePath $profileHardened -PassThru -Quiet
            Assert-Equal @() @($r.Findings | Where-Object { $_.RuleId -like 'AW-CDX-*' -or $_.RuleId -like 'AW-MCP-*' } | ForEach-Object { $_.RuleId + ': ' + $_.Evidence })
            Assert-Contains $r.Harnesses 'codex'
            Assert-Equal 0 @($r.Findings | Where-Object { $_.RuleId -like 'AW-CORE-*' }).Count
        }
        It 'lowers the managed-blocked findings with requirements.toml' {
            $ctx = Get-CdxContext ([pscustomobject]@{ Root = $projectInsecure; User = $profileInsecure; Requirements = $managedFile })
            Assert-Equal @('info') @(Invoke-CdxCheck 'AW-CDX-001' $ctx | ForEach-Object { $_.Severity })
            Assert-Equal @('info') @(Invoke-CdxCheck 'AW-CDX-002' $ctx | ForEach-Object { $_.Severity })
            Assert-Equal @('info', 'info') @(Invoke-CdxCheck 'AW-CDX-011' $ctx | ForEach-Object { $_.Severity })
            Assert-Equal 0 @(Invoke-CdxCheck 'AW-CDX-012' $ctx).Count
        }
        It 'never writes a FAKE secret in full, in any format' {
            Assert-Equal 6 $FakeSecrets.Count
            foreach ($fmt in @('Json', 'Sarif', 'Markdown', 'Html')) {
                $text = (@(Invoke-Airworthy -Path $projectInsecure -UserProfilePath $profileInsecure -Format $fmt -Quiet -WarningAction SilentlyContinue) | Out-String)
                Assert-True ($text.Length -gt 500) "$fmt output"
                foreach ($s in $FakeSecrets) { Assert-False (Has $text $s) "full secret in $fmt" }
            }
        }
        It 'masks the user name with -Redact' {
            $r = Invoke-Airworthy -Path $projectInsecure -UserProfilePath $profileInsecure -Redact -PassThru -Quiet
            $f = @($r.Findings | Where-Object { $_.RuleId -eq 'AW-CDX-001' })[0]
            Assert-Equal '~\.codex\config.toml' $f.Location.Path
        }
        It 'reports the project .codex/config.toml of the shared fixtures' {
            $expected = @{
                insecure = @('AW-CDX-001', 'AW-CDX-002', 'AW-CDX-007', 'AW-CDX-008', 'AW-CDX-009', 'AW-CDX-011', 'AW-CDX-012')
                mixed    = @('AW-CDX-003', 'AW-CDX-008')
                hardened = @()
            }
            foreach ($name in @('insecure', 'hardened', 'mixed')) {
                $r = Invoke-Airworthy -Path (Join-Path $fixtures $name) -NoUserProfile -PassThru -Quiet
                Assert-Contains $r.Harnesses 'codex' $name
                $cdx = @($r.Findings | Where-Object { $_.RuleId -like 'AW-CDX-*' })
                Assert-Equal $expected[$name] @($cdx | ForEach-Object { $_.RuleId } | Sort-Object) $name
                foreach ($f in $cdx) { Assert-Match $f.Location.Path '\\\.codex\\config\.toml$' $f.RuleId }
            }
            $i = Invoke-Airworthy -Path (Join-Path $fixtures 'insecure') -NoUserProfile -PassThru -Quiet
            Assert-Equal 'critical' @($i.Findings | Where-Object { $_.RuleId -eq 'AW-CDX-002' })[0].Severity
            Assert-Equal 'critical' @($i.Findings | Where-Object { $_.RuleId -eq 'AW-CDX-009' })[0].Severity
            $m = Invoke-Airworthy -Path (Join-Path $fixtures 'mixed') -NoUserProfile -PassThru -Quiet
            Assert-Equal 'medium' @($m.Findings | Where-Object { $_.RuleId -eq 'AW-CDX-008' })[0].Severity
        }
    }
} finally {
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force }
}
