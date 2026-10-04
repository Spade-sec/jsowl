# JsOwl build script (PowerShell).
# Usage:
#   .\build\build.ps1                          # vet + test + build (current platform)
#   .\build\build.ps1 -SkipTest                # skip vet and tests
#   .\build\build.ps1 -Version v1.2.3          # stamp a release version
#   .\build\build.ps1 -AllPlatforms            # cross-compile windows/linux/darwin
param(
    [string]$Version = "",
    [switch]$SkipTest,
    [switch]$AllPlatforms
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if (-not $Version) {
    if (git rev-parse --is-inside-work-tree 2>$null) {
        $ErrorActionPreference = "Continue"
        $describe = (git describe --tags --abbrev=0 2>$null | Out-String).Trim()
        $ErrorActionPreference = "Stop"
        if ($LASTEXITCODE -eq 0 -and $describe) {
            $Version = "$describe"
        } else {
            $Version = "dev-" + (git rev-parse --short HEAD)
        }
    } else {
        $Version = "dev"
    }
}

$ldflags = "-X main.version=$Version -s -w"
$rsrcModule = "github.com/akavel/rsrc@v0.10.2"
New-Item -ItemType Directory -Force -Path "bin" | Out-Null

Write-Host "== JsOwl build: version $Version ==" -ForegroundColor Cyan

if (-not $SkipTest) {
    Write-Host "-> go vet ./..." -ForegroundColor DarkGray
    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw "go vet failed" }

    Write-Host "-> go test ./..." -ForegroundColor DarkGray
    go test ./...
    if ($LASTEXITCODE -ne 0) { throw "go test failed" }
}

# Windows executables carry img/jsowl.ico as a Win32 resource. rsrc turns
# the .ico into an arch-tagged .syso next to each main package, which the
# go tool links in automatically; the .syso files are build artifacts and
# are removed after the target is built. Regenerate the .ico from the PNG
# artwork with: python build/convert_icon.py
function Invoke-IconResource([string]$goarch) {
    if (-not (Test-Path "img/jsowl.ico")) {
        throw "icon not found: img/jsowl.ico (run: python build/convert_icon.py)"
    }
    foreach ($dir in @("cmd/jsowl", "cmd/jsowl-mcp")) {
        $out = Join-Path $dir "rsrc_windows_$goarch.syso"
        Write-Host "-> icon resource $out" -ForegroundColor DarkGray
        go run $rsrcModule -arch $goarch -ico "img/jsowl.ico" -o $out
        if ($LASTEXITCODE -ne 0) { throw "icon resource generation failed: $out" }
    }
}

function Remove-IconResource([string]$goarch) {
    foreach ($dir in @("cmd/jsowl", "cmd/jsowl-mcp")) {
        $file = Join-Path $dir "rsrc_windows_$goarch.syso"
        if (Test-Path $file) { Remove-Item $file }
    }
}

function Build-Target($goos, $goarch, $outName) {
    Write-Host "-> build $outName ($goos/$goarch)" -ForegroundColor DarkGray
    $mcpName = if ($outName -match '\.exe$') { $outName -replace '\.exe$', '-mcp.exe' } else { "$outName-mcp" }
    $env:GOOS = $goos
    $env:GOARCH = $goarch
    $withIcon = ($goos -eq "windows")
    try {
        if ($withIcon) { Invoke-IconResource $goarch }
        go build -trimpath -ldflags $ldflags -o (Join-Path "bin" $outName) ./cmd/jsowl
        if ($LASTEXITCODE -ne 0) { throw "build jsowl for $goos/$goarch failed" }
        go build -trimpath -ldflags $ldflags -o (Join-Path "bin" $mcpName) ./cmd/jsowl-mcp
        if ($LASTEXITCODE -ne 0) { throw "build jsowl-mcp for $goos/$goarch failed" }
    } finally {
        if ($withIcon) { Remove-IconResource $goarch }
    }
}

if ($AllPlatforms) {
    Build-Target "windows" "amd64" "jsowl-windows-amd64.exe"
    Build-Target "windows" "arm64" "jsowl-windows-arm64.exe"
    Build-Target "linux" "amd64" "jsowl-linux-amd64"
    Build-Target "linux" "arm64" "jsowl-linux-arm64"
    Build-Target "darwin" "amd64" "jsowl-darwin-amd64"
    Build-Target "darwin" "arm64" "jsowl-darwin-arm64"
} elseif ($IsWindows -or $env:OS -eq "Windows_NT") {
    $arch = switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { "amd64" }
        "ARM64" { "arm64" }
        "x86" { "386" }
        default { "amd64" }
    }
    Build-Target "windows" $arch "jsowl.exe"
} else {
    if ($IsMacOS) {
        Build-Target "darwin" "arm64" "jsowl"
    } else {
        Build-Target "linux" "amd64" "jsowl"
    }
}

Remove-Item Env:GOOS, Env:GOARCH -ErrorAction SilentlyContinue

Write-Host "== done: bin/ ==" -ForegroundColor Green
Get-ChildItem "bin" | Format-Table Name, Length -AutoSize
