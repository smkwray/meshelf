[CmdletBinding()]
param(
    [string]$SourceDirectory = $PSScriptRoot,
    [string]$InstallDirectory = (Join-Path $env:LOCALAPPDATA "Programs\meshelf"),
    [switch]$Launch
)

$ErrorActionPreference = "Stop"
$SourceDirectory = [System.IO.Path]::GetFullPath($SourceDirectory)
$InstallDirectory = [System.IO.Path]::GetFullPath($InstallDirectory)
$required = @("meshelf-desktop.exe", "meshelfctl.exe")
foreach ($name in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $SourceDirectory $name) -PathType Leaf)) {
        throw "package is missing $name"
    }
}

New-Item -ItemType Directory -Force -Path $InstallDirectory | Out-Null
foreach ($name in @(
    "meshelf-desktop.exe",
    "meshelfctl.exe",
    "README.md",
    "LICENSE.md",
    "THIRD_PARTY_NOTICES.md",
    "UNSIGNED_CANDIDATE_BUILD.txt",
    "SHA256SUMS.txt",
    "install-windows.ps1",
    "uninstall-windows.ps1"
)) {
    $source = Join-Path $SourceDirectory $name
    if (Test-Path -LiteralPath $source -PathType Leaf) {
        Copy-Item -LiteralPath $source -Destination $InstallDirectory -Force
    }
}

$desktopExe = Join-Path $InstallDirectory "meshelf-desktop.exe"
$shell = New-Object -ComObject WScript.Shell
function Set-MeshelfShortcut([string]$Path) {
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $shortcut = $shell.CreateShortcut($Path)
    $shortcut.TargetPath = $desktopExe
    $shortcut.WorkingDirectory = $InstallDirectory
    $shortcut.IconLocation = "$desktopExe,0"
    $shortcut.Description = "meshelf clipboard shelf"
    $shortcut.Save()
}

$desktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "meshelf.lnk"
$startMenuShortcut = Join-Path ([Environment]::GetFolderPath("Programs")) "meshelf\meshelf.lnk"
Set-MeshelfShortcut $desktopShortcut
Set-MeshelfShortcut $startMenuShortcut

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$pathEntries = @($userPath -split ';' | Where-Object { $_ })
if (-not ($pathEntries | Where-Object { [string]::Equals($_.TrimEnd('\'), $InstallDirectory.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase) })) {
    $updatedPath = (@($pathEntries) + $InstallDirectory) -join ';'
    [Environment]::SetEnvironmentVariable("Path", $updatedPath, "User")
}

if ($Launch) {
    Start-Process -FilePath $desktopExe
}

Write-Output "Installed meshelf for the current user at $InstallDirectory"
Write-Output "Desktop shortcut: $desktopShortcut"
Write-Output "Start Menu shortcut: $startMenuShortcut"
Write-Output "Open a new terminal before invoking meshelfctl by name."
