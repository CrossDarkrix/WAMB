# WAMB bootstrap build script.
#
#   powershell -ExecutionPolicy Bypass -File build.ps1 [-WithClamAV] [-WithABA]
#
# What it does:
#   1. Installs Git and Go with winget when they are missing.
#   2. Uses the repository this script lives in (or clones WAMB first
#      when the script is run on its own).
#   3. Builds wamb.exe.
# With -WithClamAV it also downloads the official ClamAV portable build,
# extracts it next to the repo, fetches the signature databases, and
# writes a ready-to-use config if none exists yet.
# With -WithABA it also builds a-better-antivirus (the stealer tripwire
# WAMB is designed to coexist with) from source and installs it, then
# registers clamscan.exe in ABA's ignore list: a scanner reads every
# file by design, which otherwise looks like a stealer sweep to ABA.
# The ABA install step asks for administrator rights (UAC) when needed.
param(
    [switch]$WithClamAV,
    [switch]$WithABA,
    [string]$Repo = 'https://github.com/CrossDarkrix/WAMB.git'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Refresh-Path {
    $extra = @('C:\Program Files\Git\cmd', 'C:\Program Files\Go\bin')
    foreach ($p in $extra) {
        if ((Test-Path $p) -and ($env:Path -notlike "*$p*")) { $env:Path += ";$p" }
    }
}

function Ensure-Tool([string]$cmd, [string]$wingetId, [string]$name) {
    Refresh-Path
    if (Get-Command $cmd -ErrorAction SilentlyContinue) { return }
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw "$name is not installed and winget was not found. Install the 'App Installer' from the Microsoft Store (it provides winget), or install $name manually."
    }
    Write-Host "Installing $name with winget..."
    winget install --id $wingetId -e --accept-source-agreements --accept-package-agreements
    Refresh-Path
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        throw "$name was installed but '$cmd' is still not on PATH. Open a new terminal and run this script again."
    }
}

Write-Host '== Toolchain =='
Ensure-Tool 'git' 'Git.Git' 'Git'
Ensure-Tool 'go' 'GoLang.Go' 'Go'
git --version
go version

Write-Host '== Source =='
$root = $PSScriptRoot
if (-not (Test-Path (Join-Path $root 'go.mod'))) {
    $dest = Join-Path (Get-Location) 'WAMB'
    if (Test-Path (Join-Path $dest 'go.mod')) {
        git -C $dest pull --ff-only
    } else {
        git clone $Repo $dest
    }
    $root = $dest
}
Write-Host "Repository: $root"

Write-Host '== Build =='
Push-Location $root
$env:CGO_ENABLED = '0'
go build -o wamb.exe .
if ($LASTEXITCODE -ne 0) { throw 'go build failed.' }
Pop-Location
Write-Host "Built: $root\wamb.exe"

if ($WithClamAV) {
    Write-Host '== ClamAV =='
    $clamDir = Join-Path $root 'clamav'
    $zip = Join-Path $root 'clamav-1.5.5.win.x64.zip'
    $zipUrl = 'https://www.clamav.net/downloads/production/clamav-1.5.5.win.x64.zip'
    $zipSize = 225800047
    if (-not (Test-Path (Join-Path $clamDir 'clamscan.exe'))) {
        if (-not (Test-Path $zip)) {
            Write-Host 'Downloading ClamAV (about 215 MB)...'
            curl.exe -L -o $zip $zipUrl
        }
        if ((Get-Item $zip).Length -ne $zipSize) { throw 'ClamAV zip size mismatch - the download may be corrupted.' }
        $tmp = Join-Path $root 'clamav-extract'
        if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force }
        Expand-Archive -Path $zip -DestinationPath $tmp -Force
        Move-Item (Join-Path $tmp 'clamav-1.5.5.win.x64') $clamDir
        Remove-Item $tmp -Recurse -Force
    }
    @"
DatabaseMirror database.clamav.net
DatabaseDirectory $clamDir\database
Checks 1
"@ | Set-Content (Join-Path $clamDir 'freshclam.conf') -Encoding ASCII
    & (Join-Path $clamDir 'freshclam.exe') --config-file=(Join-Path $clamDir 'freshclam.conf')

    $cfgDir = Join-Path $env:LOCALAPPDATA 'WAMB'
    $cfgPath = Join-Path $cfgDir 'config.json'
    if (-not (Test-Path $cfgPath)) {
        New-Item -ItemType Directory -Force $cfgDir | Out-Null
        $cfg = [ordered]@{
            clamscan_path    = Join-Path $clamDir 'clamscan.exe'
            freshclam_path   = Join-Path $clamDir 'freshclam.exe'
            freshclam_conf   = Join-Path $clamDir 'freshclam.conf'
            database_dir     = Join-Path $clamDir 'database'
            base_dir         = $cfgDir
            quarantine_dir   = Join-Path $cfgDir 'quarantine'
            mirror_dir       = ''
            targets          = @((Join-Path $env:USERPROFILE 'Downloads'), (Join-Path $env:USERPROFILE 'Desktop'))
            exclude_files    = @()
            exclude_dirs     = @()
            exclude_regex    = @()
            level            = 2
            notify_on_detect = $true
            discord_webhook  = ''
            watch_debounce_sec = 3
            watch_quarantine = $false
            schedule_scan    = '03:00'
            schedule_update  = '02:00'
        }
        $json = $cfg | ConvertTo-Json -Depth 5
        [System.IO.File]::WriteAllText($cfgPath, $json, (New-Object System.Text.UTF8Encoding $false))
        Write-Host "Config written: $cfgPath"
    }
}

if ($WithABA) {
    Write-Host '== ABA (a-better-antivirus) =='
    $abaRepo = 'https://github.com/vulnix0x4/a-better-antivirus'
    $abaDir = Join-Path (Split-Path $root -Parent) 'a-better-antivirus'
    if (Test-Path (Join-Path $abaDir '.git')) {
        git -C $abaDir pull --ff-only
    } elseif (Test-Path $abaDir) {
        Write-Host "Using existing source in $abaDir"
    } else {
        git clone $abaRepo $abaDir
    }
    Push-Location $abaDir
    $env:CGO_ENABLED = '0'
    go build -o dist\aba.exe ./cmd/aba
    if ($LASTEXITCODE -ne 0) { throw 'ABA build failed.' }
    Pop-Location
    $abaExe = Join-Path $abaDir 'dist\aba.exe'
    Write-Host "Built: $abaExe"

    # Where is the clamscan ABA should ignore?
    $clamExe = $null
    if (Test-Path (Join-Path $root 'clamav\clamscan.exe')) { $clamExe = Join-Path $root 'clamav\clamscan.exe' }
    elseif (Test-Path 'C:\Program Files\ClamAV\clamscan.exe') { $clamExe = 'C:\Program Files\ClamAV\clamscan.exe' }

    $needIgnore = $false
    if ($clamExe) {
        $rules = & $abaExe ignore list
        $needIgnore = ($rules -notmatch [regex]::Escape($clamExe))
    }
    $svc = Get-Service 'File Access Monitor' -ErrorAction SilentlyContinue

    $steps = @()
    if (-not $svc) { $steps += "& '$abaExe' install --yes --preset balanced" }
    if ($needIgnore) { $steps += "& '$abaExe' ignore add '$clamExe' --note 'WAMB (ClamAV) scanner'" }
    if ($steps.Count -eq 0) {
        Write-Host 'ABA is installed and clamscan is already ignored - nothing to do.'
        & $abaExe doctor
    } else {
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if ($isAdmin) {
            foreach ($s in $steps) { Invoke-Expression $s }
            & $abaExe doctor
        } else {
            Write-Host 'ABA setup needs administrator rights - opening an elevated window...'
            $cmds = ($steps -join '; ') + "; & '$abaExe' doctor; pause"
            Start-Process powershell -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $cmds -Verb RunAs -Wait
        }
    }
}

Write-Host ''
Write-Host 'Done. Try: .\wamb.exe scan --help'
