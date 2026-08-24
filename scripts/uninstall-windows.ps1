[CmdletBinding()]
param(
    [string]$InstallDirectory = (Join-Path $env:LOCALAPPDATA "Programs\meshelf"),
    [switch]$RemoveLocalData
)

$ErrorActionPreference = "Stop"
$InstallDirectory = [System.IO.Path]::GetFullPath($InstallDirectory)
$desktopExe = Join-Path $InstallDirectory "meshelf-desktop.exe"

Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $desktopExe } | ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force
}

foreach ($shortcut in @(
    (Join-Path ([Environment]::GetFolderPath("Desktop")) "meshelf.lnk"),
    (Join-Path ([Environment]::GetFolderPath("Programs")) "meshelf\meshelf.lnk"),
    (Join-Path ([Environment]::GetFolderPath("Startup")) "meshelf.lnk")
)) {
    if (Test-Path -LiteralPath $shortcut) {
        Remove-Item -LiteralPath $shortcut -Force
    }
}

$startMenuDirectory = Join-Path ([Environment]::GetFolderPath("Programs")) "meshelf"
if ((Test-Path -LiteralPath $startMenuDirectory) -and -not (Get-ChildItem -LiteralPath $startMenuDirectory -Force)) {
    Remove-Item -LiteralPath $startMenuDirectory -Force
}

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$updatedEntries = @($userPath -split ';' | Where-Object {
    $_ -and -not [string]::Equals($_.TrimEnd('\'), $InstallDirectory.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)
})
[Environment]::SetEnvironmentVariable("Path", ($updatedEntries -join ';'), "User")

Set-Location $env:TEMP
if (Test-Path -LiteralPath $InstallDirectory) {
    Remove-Item -LiteralPath $InstallDirectory -Recurse -Force
}
if ($RemoveLocalData) {
    $dataDirectory = Join-Path $env:APPDATA "meshelf"
    if (Test-Path -LiteralPath $dataDirectory) {
        Remove-Item -LiteralPath $dataDirectory -Recurse -Force
    }
}

Write-Output "Removed the per-user meshelf installation and shortcuts."
if (-not $RemoveLocalData) {
    Write-Output "Local meshelf identity, trust state, and receive history were preserved."
}
