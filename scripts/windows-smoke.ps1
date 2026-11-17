# Windows smoke run of the CLI (CI job `windows`): a workspace and a local source with spaces and non-ASCII
# characters in their paths, CRLF rule files, update without an engine, search, show redirected to a file, export.
# Usage: pwsh scripts/windows-smoke.ps1 [-Exe suriharvest]   (run from the repository root, after `uv sync`)
param([string]$Exe = "suriharvest")
$ErrorActionPreference = "Stop"

function Run {
    & uv run --no-sync $Exe @args
    if ($LASTEXITCODE -ne 0) { throw "suriharvest $($args -join ' ') exited with $LASTEXITCODE" }
}

$base = Join-Path ([IO.Path]::GetTempPath()) ("suriharvest smoke " + [guid]::NewGuid().ToString("N").Substring(0, 8))
$ws = Join-Path $base "ws suri"
$src = Join-Path $base ([string]::new([char[]](0x72, 0xE8, 0x67, 0x6C, 0x65, 0x73)))  # "règles"
$utf8 = New-Object System.Text.UTF8Encoding($false)
$han = [string]::new([char[]](0x6F22, 0x5B57))
try {
    New-Item -ItemType Directory -Force -Path (Join-Path $src "sub dir") | Out-Null
    $rules = "alert http any any -> any any (msg:""smoke $han one""; content:""a1""; sid:1000010; rev:1;)`r`n" +
             "alert http any any -> any any (msg:""smoke two""; content:""a2""; sid:1000011; rev:1;)`r`n"
    [IO.File]::WriteAllText((Join-Path $src "sub dir\local.rules"), $rules, $utf8)

    Run --version
    Run init $ws
    $yaml = "sources:`n- name: mine`n  type: local`n  url: '" + $src.Replace("'", "''") + "'`n  licence: MIT`n  redistribute: 'yes'`n"
    [IO.File]::WriteAllText((Join-Path $ws "sources.yaml"), $yaml, $utf8)
    $env:SURIHARVEST_HOME = $ws
    Run update --no-validate
    Run search smoke
    Run update --no-validate  # second run: incremental, same lock file

    # Redirected output: the ANSI code page has no CJK characters; the CLI must write UTF-8 instead of failing.
    $out = Join-Path $base "show.txt"
    cmd /c "uv run --no-sync $Exe show 1000010 > ""$out"" 2>&1"
    if ($LASTEXITCODE -ne 0) { Get-Content $out; throw "show redirected to a file exited with $LASTEXITCODE" }
    $text = [IO.File]::ReadAllText($out, $utf8)
    if (-not $text.Contains($han)) { throw "show output lacks the non-ASCII message: $text" }

    $exp = Join-Path $base "export dir"
    Run export $exp
    $bytes = [IO.File]::ReadAllBytes((Join-Path $exp "suricata.rules"))
    if ([Array]::IndexOf($bytes, [byte]13) -ge 0) { throw "export suricata.rules contains CR: files must be written with LF" }
    Write-Host "windows smoke: ok"
} finally {
    Remove-Item Env:SURIHARVEST_HOME -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $base -ErrorAction SilentlyContinue
}
