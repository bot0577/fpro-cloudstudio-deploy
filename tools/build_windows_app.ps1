$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

$pyinstaller = Get-Command pyinstaller -ErrorAction SilentlyContinue
if ($pyinstaller) {
    $buildCommand = $pyinstaller.Source
    $buildPrefix = @()
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $buildCommand = (Get-Command python).Source
    $buildPrefix = @('-m', 'PyInstaller')
} else {
    throw 'PyInstaller was not found. Install Python 3 and pyinstaller first.'
}

& $buildCommand @buildPrefix --noconfirm --clean --onefile --windowed `
    --name FProCloudStudio `
    --hidden-import fpro_ssh_receiver `
    --hidden-import fpro_crypto `
    --hidden-import websocket `
    --collect-submodules cryptography `
    tools\fpro_delivery_gui.py

if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed with exit code $LASTEXITCODE."
}

Write-Host "Generated: $repo\dist\FProCloudStudio.exe"
