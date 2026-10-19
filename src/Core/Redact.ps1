# Secret masking and path display helpers.

$script:AwIsWindowsOS = ([System.IO.Path]::DirectorySeparatorChar -eq [char]'\')
$script:AwPathComparison = if ($script:AwIsWindowsOS) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }

function Hide-AwSecret {
    <#
    .SYNOPSIS
    Masks a secret: first 4 and last 2 characters plus the length when it has 12 or more characters, '****' otherwise.
    #>
    [CmdletBinding()]
    param([AllowNull()] [AllowEmptyString()] [string]$Value)
    if ([string]::IsNullOrEmpty($Value) -or $Value.Length -lt 12) { return '****' }
    return ($Value.Substring(0, 4) + $script:AwEllipsis + $Value.Substring($Value.Length - 2) + ' (' + $Value.Length + ' chars)')
}

function Hide-AwSecretsInText {
    # Masks long token-like words (letters and digits, 20+ chars) in free text such as error messages.
    param([AllowNull()] [AllowEmptyString()] [string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $pattern = '(?<![A-Za-z0-9_])(?=[A-Za-z0-9_]*[0-9])(?=[A-Za-z0-9_]*[A-Za-z])[A-Za-z0-9_]{20,}(?![A-Za-z0-9_])'
    return [regex]::Replace($Text, $pattern, { param($m) Hide-AwSecret -Value $m.Value })
}

function Get-AwMemberValue {
    # Reads a key or property from a hashtable or object without tripping StrictMode.
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Test-AwPathInside {
    # True when Path is Dir itself or lies under it (no resolution of links).
    param([string]$Path, [string]$Dir)
    if ([string]::IsNullOrEmpty($Path) -or [string]::IsNullOrEmpty($Dir)) { return $false }
    $d = $Dir.TrimEnd([char[]]@('\', '/'))
    if ($Path.Length -lt $d.Length) { return $false }
    if (-not $Path.StartsWith($d, $script:AwPathComparison)) { return $false }
    if ($Path.Length -eq $d.Length) { return $true }
    $next = $Path[$d.Length]
    return ($next -eq [char]'\' -or $next -eq [char]'/' -or $d.Length -eq 0)
}

function Get-AwRelativePath {
    # Path relative to Base, '.' for Base itself, or $null when Path is outside Base.
    param([string]$Path, [string]$Base)
    if (-not (Test-AwPathInside -Path $Path -Dir $Base)) { return $null }
    $d = $Base.TrimEnd([char[]]@('\', '/'))
    if ($Path.Length -eq $d.Length) { return '.' }
    return $Path.Substring($d.Length + 1)
}

function Hide-AwUserInPath {
    # Replaces the user profile prefix with '~' and masks path segments equal to the user name.
    param([string]$Path, [string]$UserProfile)
    if ([string]::IsNullOrEmpty($Path)) { return $Path }
    $out = $Path
    if ($UserProfile) {
        $rel = Get-AwRelativePath -Path $Path -Base $UserProfile
        if ($null -ne $rel) {
            $sep = [System.IO.Path]::DirectorySeparatorChar
            $out = if ($rel -eq '.') { '~' } else { '~' + $sep + $rel }
        }
    }
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($n in @($env:USERNAME, $env:USER)) { if ($n -and $n.Length -ge 2) { $names.Add($n) } }
    if ($UserProfile) {
        $leaf = Split-Path -Path $UserProfile.TrimEnd([char[]]@('\', '/')) -Leaf
        if ($leaf -and $leaf.Length -ge 2) { $names.Add($leaf) }
    }
    foreach ($n in $names) {
        $pattern = '(?<=^|[\\/])' + [regex]::Escape($n) + '(?=$|[\\/])'
        $out = [regex]::Replace($out, $pattern, '%USERNAME%', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    return $out
}

function Hide-AwUserInText {
    # Free-text variant of Hide-AwUserInPath: the profile path becomes '~', the user name is masked.
    param([AllowNull()] [AllowEmptyString()] [string]$Text, [string]$UserProfile)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $out = $Text
    if ($UserProfile) {
        $p = [regex]::Escape($UserProfile.TrimEnd([char[]]@('\', '/')))
        $out = [regex]::Replace($out, $p + '(?=$|[\\/\s''"])', '~', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($n in @($env:USERNAME, $env:USER)) { if ($n -and $n.Length -ge 2) { $names.Add($n) } }
    if ($UserProfile) {
        $leaf = Split-Path -Path $UserProfile.TrimEnd([char[]]@('\', '/')) -Leaf
        if ($leaf -and $leaf.Length -ge 2) { $names.Add($leaf) }
    }
    foreach ($n in $names) {
        $out = [regex]::Replace($out, '(?<![A-Za-z0-9_])' + [regex]::Escape($n) + '(?![A-Za-z0-9_])', '%USERNAME%',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    return $out
}

function Get-AwDisplayPath {
    <#
    .SYNOPSIS
    Returns a path for display: relative to Ctx.Root when inside it, otherwise unchanged.
    .DESCRIPTION
    With -Redact, a path outside the root has the user profile replaced by '~' and any
    path segment equal to the user name masked. Ctx is the context from New-AwContext
    (or any object with Root and, optionally, UserProfile properties).
    #>
    [CmdletBinding()]
    param([AllowNull()] [AllowEmptyString()] [string]$Path, $Ctx, [switch]$Redact)
    if ([string]::IsNullOrEmpty($Path)) { return $Path }
    $root = [string](Get-AwMemberValue $Ctx 'Root')
    $userProfile = [string](Get-AwMemberValue $Ctx 'UserProfile')
    $full = $Path
    try { if ([System.IO.Path]::IsPathRooted($Path)) { $full = [System.IO.Path]::GetFullPath($Path) } } catch { $full = $Path }
    if ($root -and [System.IO.Path]::IsPathRooted($root)) {
        $rel = Get-AwRelativePath -Path $full -Base $root
        if ($null -ne $rel) { return $rel }
    }
    if ($Redact) { return Hide-AwUserInPath -Path $full -UserProfile $userProfile }
    return $full
}

function Get-AwPathLabel {
    # Leaf name of a path, with the user name masked ('D:\src\my-repo' -> 'my-repo'), or '.' when
    # the path has no leaf name (a drive root). -Redact shows the analyzed root this way.
    param([AllowNull()] [AllowEmptyString()] [string]$Path, [string]$UserProfile)
    if ([string]::IsNullOrEmpty($Path)) { return $Path }
    $leaf = ''
    try { $leaf = [System.IO.Path]::GetFileName($Path.TrimEnd([char[]]@('\', '/'))) } catch { $leaf = '' }
    if ([string]::IsNullOrEmpty($leaf)) { return '.' }
    return (Hide-AwUserInPath -Path $leaf -UserProfile $UserProfile)
}

function Hide-AwRootInText {
    # Replaces the absolute analyzed root in free text, written with either separator, by Label:
    # 'cannot read D:\src\my-repo\.mcp.json' -> 'cannot read my-repo\.mcp.json'.
    param([AllowNull()] [AllowEmptyString()] [string]$Text, [string]$Root, [string]$Label)
    if ([string]::IsNullOrEmpty($Text) -or [string]::IsNullOrEmpty($Root)) { return $Text }
    $trimmed = $Root.TrimEnd([char[]]@('\', '/'))
    if ($trimmed.Length -lt 2) { return $Text }
    $segments = @(foreach ($s in ($trimmed -split '[\\/]')) { [regex]::Escape($s) })
    $pattern = '(?<![A-Za-z0-9_])' + ($segments -join '[\\/]') + '(?![A-Za-z0-9_-])'
    $options = [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    if ($script:AwIsWindowsOS) { $options = [System.Text.RegularExpressions.RegexOptions]'CultureInvariant, IgnoreCase' }
    return [regex]::Replace($Text, $pattern, ([string]$Label).Replace('$', '$$'), $options)
}

function Hide-AwPrivateText {
    # -Redact for free text: the analyzed root becomes RootLabel, then the user profile becomes '~'
    # and the user name is masked.
    param([AllowNull()] [AllowEmptyString()] [string]$Text, $Ctx, [string]$RootLabel)
    $t = Hide-AwRootInText -Text $Text -Root ([string](Get-AwMemberValue $Ctx 'Root')) -Label $RootLabel
    return (Hide-AwUserInText -Text $t -UserProfile ([string](Get-AwMemberValue $Ctx 'UserProfile')))
}

function Hide-AwOptionPath {
    # -Redact for a path option (OutFile, UserProfilePath, UserSettingsPath): the analyzed root
    # becomes RootLabel, the profile '~', the user name is masked, and a path that is still
    # absolute keeps only its leaf name.
    param([AllowNull()] [AllowEmptyString()] [string]$Path, $Ctx, [string]$RootLabel)
    if ([string]::IsNullOrEmpty($Path)) { return $Path }
    $userProfile = [string](Get-AwMemberValue $Ctx 'UserProfile')
    $p = Hide-AwRootInText -Text $Path -Root ([string](Get-AwMemberValue $Ctx 'Root')) -Label $RootLabel
    $p = Hide-AwUserInPath -Path $p -UserProfile $userProfile
    $rooted = $true
    try { $rooted = [System.IO.Path]::IsPathRooted($p) } catch { $rooted = $true }
    if ($rooted) { $p = Get-AwPathLabel -Path $p -UserProfile $userProfile }
    return $p
}
