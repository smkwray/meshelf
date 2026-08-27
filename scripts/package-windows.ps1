[CmdletBinding()]
param(
    [string]$OutputDirectory = "",
    [switch]$Install,
    [switch]$Launch
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repo "release\windows"
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)

$cargo = (& rustup which --toolchain 1.92.0 cargo).Trim()
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $cargo -PathType Leaf)) {
    throw "Rust 1.92.0 is unavailable; run scripts\bootstrap.bat first"
}
$toolchainBin = Split-Path -Parent $cargo
$env:Path = "$toolchainBin;$env:Path"
$logicalCores = [Environment]::ProcessorCount
$env:CARGO_BUILD_JOBS = [Math]::Max(1, [Math]::Floor($logicalCores / 2)).ToString()
Write-Output "Rust build jobs: $env:CARGO_BUILD_JOBS of $logicalCores logical cores"

& $cargo build --locked --release -p meshelf-desktop -p meshelfctl
if ($LASTEXITCODE -ne 0) {
    throw "Windows release build failed"
}

$versionMatch = Select-String -Path (Join-Path $repo "Cargo.toml") -Pattern '^version = "([^"]+)"' | Select-Object -First 1
if (-not $versionMatch) {
    throw "workspace version is missing from Cargo.toml"
}
$version = $versionMatch.Matches[0].Groups[1].Value
$packageName = "meshelf-$version-windows-x64"
$stage = Join-Path $OutputDirectory $packageName
$zip = Join-Path $OutputDirectory "$packageName.zip"

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
if (Test-Path -LiteralPath $stage) {
    Remove-Item -LiteralPath $stage -Recurse -Force
}
if (Test-Path -LiteralPath $zip) {
    Remove-Item -LiteralPath $zip -Force
}
New-Item -ItemType Directory -Path $stage | Out-Null

$desktop = Join-Path $repo "target\release\meshelf-desktop.exe"
$ctl = Join-Path $repo "target\release\meshelfctl.exe"
Copy-Item -LiteralPath $desktop, $ctl -Destination $stage
Copy-Item -LiteralPath (Join-Path $repo "README.md"), (Join-Path $repo "LICENSE.md"), (Join-Path $repo "THIRD_PARTY_NOTICES.md"), (Join-Path $repo "UNSIGNED_CANDIDATE_BUILD.txt") -Destination $stage
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "install-windows.ps1"), (Join-Path $PSScriptRoot "uninstall-windows.ps1") -Destination $stage

Add-Type -AssemblyName System.Drawing
$icon = [System.Drawing.Icon]::ExtractAssociatedIcon((Join-Path $stage "meshelf-desktop.exe"))
if ($null -eq $icon) {
    throw "meshelf-desktop.exe has no extractable Windows icon"
}
$icon.Dispose()

$hashLines = @(
    Get-FileHash -Algorithm SHA256 (Join-Path $stage "meshelf-desktop.exe"), (Join-Path $stage "meshelfctl.exe") |
        ForEach-Object { "$($_.Hash.ToLowerInvariant())  $([System.IO.Path]::GetFileName($_.Path))" }
)
Set-Content -LiteralPath (Join-Path $stage "SHA256SUMS.txt") -Encoding ascii -Value $hashLines
Compress-Archive -LiteralPath $stage -DestinationPath $zip -CompressionLevel Optimal
$zipHash = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
Set-Content -LiteralPath "$zip.sha256" -Encoding ascii -Value "$zipHash  $([System.IO.Path]::GetFileName($zip))"

if ($Install) {
    $installArgs = @{ SourceDirectory = $stage }
    if ($Launch) {
        $installArgs.Launch = $true
    }
    & (Join-Path $stage "install-windows.ps1") @installArgs
}

Write-Output $zip
Write-Output "SHA256=$zipHash"
