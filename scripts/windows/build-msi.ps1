<#
.SYNOPSIS
    Build the Rustinel Windows installer.

.DESCRIPTION
    Produces a signed .msi from an already-built rustinel.exe. Runs the same
    way locally and in CI, so a failure in the release pipeline can be
    reproduced on a laptop without pushing a tag.

    The order matters and is not arbitrary: the binary is signed *before* it
    goes into the MSI, and the MSI is signed after it is built. Signing the MSI
    alone would leave an unsigned executable on disk after installation, which
    is what a user sees when they run the agent, and what SmartScreen judges.

.PARAMETER Binary
    Path to rustinel.exe. Defaults to the release build.

.PARAMETER Version
    Product version, x.y.z. Defaults to the version in Cargo.toml.

.PARAMETER OutputDirectory
    Where to write the .msi.

.PARAMETER Sign
    Sign the binary and the installer. Off by default so a local build needs no
    credentials.

.PARAMETER RequireSigning
    Fail if signing is requested but no credentials are configured. Used by the
    release workflow, where an unsigned installer must never reach a user.

.EXAMPLE
    cargo build --release
    .\scripts\windows\build-msi.ps1

.EXAMPLE
    .\scripts\windows\build-msi.ps1 -Sign -RequireSigning -Version 1.5.1
#>
[CmdletBinding()]
param(
    [string]$Binary = 'target/release/rustinel.exe',
    [string]$Version,
    [string]$OutputDirectory = 'dist',
    [switch]$Sign,
    [switch]$RequireSigning
)

$ErrorActionPreference = 'Stop'

# Two levels up from scripts/windows. Written as nested Split-Path rather than
# a three-argument Join-Path, which only exists in PowerShell 7: this script has
# to run under the Windows PowerShell 5.1 that ships with the OS.
$repoRoot = (Resolve-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent)).Path
Push-Location $repoRoot
try {
    if (-not (Test-Path $Binary)) {
        throw "Binary not found at $Binary. Run: cargo build --release"
    }

    if (-not $Version) {
        # The MSI version has to match what shipped, and Cargo.toml is the one
        # place that knows.
        $manifest = Get-Content 'Cargo.toml' -Raw
        if ($manifest -notmatch '(?m)^version\s*=\s*"([^"]+)"') {
            throw 'Could not read the version from Cargo.toml'
        }
        $Version = $Matches[1]
    }

    # Windows Installer compares versions as three numeric fields and ignores
    # anything after them, so 1.5.1-rc1 and 1.5.1 would be indistinguishable to
    # the upgrade logic. Strip the pre-release suffix and say so, rather than
    # shipping two builds Windows cannot tell apart.
    $msiVersion = $Version
    if ($Version -match '^(\d+\.\d+\.\d+)') {
        $msiVersion = $Matches[1]
        if ($msiVersion -ne $Version) {
            Write-Host "MSI ProductVersion is $msiVersion; Windows Installer ignores the '-$($Version.Substring($msiVersion.Length + 1))' suffix"
        }
    }
    else {
        throw "Version '$Version' is not in x.y.z form"
    }

    Write-Host "Building Rustinel $Version installer"

    if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
        throw @'
The WiX toolset is not installed.

  dotnet tool install --global wix
  wix extension add --global WixToolset.UI.wixext
  wix extension add --global WixToolset.Util.wixext
'@
    }

    # Sign the binary first: this is the file the user runs, and the one whose
    # signature the operating system checks on every launch.
    if ($Sign) {
        & (Join-Path $PSScriptRoot 'sign.ps1') `
            -Path $Binary `
            -Description 'Rustinel endpoint detection and response agent' `
            -Required:$RequireSigning
    }

    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
    $msiPath = Join-Path $OutputDirectory "rustinel-$Version-x86_64.msi"

    $license = Join-Path $repoRoot 'packaging/windows/License.rtf'
    $icon = Join-Path $repoRoot 'packaging/windows/rustinel.ico'
    $source = Join-Path $repoRoot 'packaging/windows/rustinel.wxs'
    $config = Join-Path $repoRoot 'config.toml'

    foreach ($required in @($license, $icon, $source, $config)) {
        if (-not (Test-Path $required)) {
            throw "Packaging input missing: $required"
        }
    }

    Write-Host "Compiling $source"
    & wix build `
        -arch x64 `
        -ext WixToolset.UI.wixext `
        -ext WixToolset.Util.wixext `
        -d "ProductVersion=$msiVersion" `
        -d "BinaryFile=$((Resolve-Path $Binary).Path)" `
        -d "ConfigFile=$config" `
        -d "LicenseFile=$license" `
        -d "IconFile=$icon" `
        -o $msiPath `
        $source

    if ($LASTEXITCODE -ne 0) {
        throw "wix build failed with exit code $LASTEXITCODE"
    }

    # Sign the installer too. An unsigned MSI wrapping a signed binary still
    # produces an "unknown publisher" prompt at the moment the user decides
    # whether to trust it.
    if ($Sign) {
        & (Join-Path $PSScriptRoot 'sign.ps1') `
            -Path $msiPath `
            -Description 'Rustinel installer' `
            -Required:$RequireSigning
    }

    $sizeMB = [math]::Round((Get-Item $msiPath).Length / 1MB, 2)
    Write-Host "Built $msiPath ($sizeMB MB)"

    # Emit the path for the workflow step that uploads it.
    if ($env:GITHUB_OUTPUT) {
        "msi=$msiPath" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
    }

    return $msiPath
}
finally {
    Pop-Location
}
