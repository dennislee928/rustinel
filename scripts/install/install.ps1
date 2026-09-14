param(
    [string]$Repo = "Karib0u/rustinel",
    [string]$Version = "latest",
    [string]$InstallDir = (Join-Path (Get-Location) "rustinel"),
    [switch]$Run,
    [switch]$Force,
    # Install the signed MSI and register the Windows service, instead of
    # unpacking the portable archive for evaluation. Off by default: the
    # streamed one-liner is an evaluation path, and an installer that
    # registers a SYSTEM service should be asked for rather than assumed.
    [switch]$Msi,
    # Where the MSI puts the agent. Ignored by the portable path, which uses
    # -InstallDir.
    [string]$MsiInstallDir
)

$ErrorActionPreference = "Stop"

function Show-InstallScope {
    Write-Host "This script only installs published Rustinel release binaries."
    Write-Host "It does not install Rust, Cargo, or build Rustinel from source."
    Write-Host "Source build guide: https://docs.rustinel.io/getting-started/#compile-from-source"
}

function Test-TruthyEnv {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }

    $normalized = $Value.Trim().ToLowerInvariant()
    return @("1", "true", "yes", "on") -contains $normalized
}

function Test-SetupSupported {
    param([string]$Path)

    # Probe the installed binary. Only releases that ship the managed-deployment
    # workflow answer `setup --help` successfully; older/stable builds do not, so
    # we avoid advertising a command they cannot run.
    $exe = Join-Path $Path "rustinel.exe"
    if (-not (Test-Path $exe)) {
        return $false
    }
    try {
        & $exe setup --help *> $null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Show-PromotionCommand {
    param([string]$Path)

    if (-not (Test-SetupSupported -Path $Path)) {
        return
    }
    Write-Host "Permanent deployment command:"
    Write-Host "  Set-Location `"$Path`"; .\rustinel.exe setup --yes"
}

function Show-PortableEvaluation {
    param(
        [string]$Path,
        [string]$ReleaseVersion
    )

    $demoRulesPath = Join-Path $Path "rules\sigma"
    $demoRulesStatus = "not found"
    $demoRule = Get-ChildItem -Path $demoRulesPath -Filter "*whoami*.yml" -File -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($demoRule) {
        $demoRulesStatus = "present"
    }

    Write-Host ""
    Write-Host "Rustinel $ReleaseVersion installed to:"
    Write-Host "  $Path"
    Write-Host ""
    Write-Host "Portable evaluation mode:"
    Write-Host "  Package: $Path"
    Write-Host "  Config: $(Join-Path $Path 'config.toml')"
    Write-Host "  Demo rules: $demoRulesPath ($demoRulesStatus)"
    Write-Host "  Alerts: $(Join-Path $Path 'logs\alerts.json.*')"
    Write-Host "  Active response: disabled in bundled config"
    Write-Host ""
    Write-Host "Start monitoring from an elevated PowerShell:"
    Write-Host "  Set-Location `"$Path`""
    Write-Host "  .\rustinel.exe run"
    Write-Host ""
    Write-Host "Demo trigger from another PowerShell:"
    Write-Host "  whoami"
    Write-Host ""
    Write-Host "Show the alert:"
    Write-Host "  Get-Content `"$Path\logs\alerts.json.*`""
    Write-Host ""
    Show-PromotionCommand -Path $Path
    Write-Host ""
    Write-Host "For a permanent install, the signed MSI registers the service and owns"
    Write-Host "upgrades and uninstall. From an elevated PowerShell:"
    Write-Host "  `$env:RUSTINEL_MSI='1'; irm https://rustinel.io/install.ps1 | iex"
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-InstallerSignature {
    param(
        [string]$Path,
        [string]$SourceRepo
    )

    $signature = Get-AuthenticodeSignature -FilePath $Path

    if ($signature.Status -eq "Valid") {
        Write-Host "Publisher: $($signature.SignerCertificate.Subject)"
        if (-not $signature.TimeStamperCertificate) {
            Write-Warning "The signature is not timestamped; it stops validating when the certificate expires."
        }
        return
    }

    # HashMismatch means the file was altered after it was signed. That is the
    # one status that is never explainable by a missing certificate, so it is
    # refused no matter where the release came from.
    if ($signature.Status -eq "HashMismatch") {
        throw "Refusing to install: the MSI does not match its own signature. It was altered after signing."
    }

    # A release from the official repository is always signed. Anything else
    # there means the artifact is not what it claims to be, and this installer
    # is about to hand it SYSTEM.
    if ($SourceRepo -eq "Karib0u/rustinel") {
        throw "Refusing to install: the MSI signature is $($signature.Status). Official releases are signed. Report this at https://github.com/$SourceRepo/security"
    }

    # A fork has no access to the signing credentials, so it cannot establish a
    # publisher. The checksum check above still proves the download matches the
    # release it came from; what is missing is any evidence about who produced
    # that release.
    Write-Warning "No valid publisher signature on the MSI from $SourceRepo (status: $($signature.Status))."
    Write-Warning "Only continue if you trust that repository."
}

function Install-Msi {
    param(
        [string]$MsiPath,
        [string]$TargetDir
    )

    if (-not (Test-Administrator)) {
        throw "The MSI registers a Windows service and must be installed from an elevated PowerShell. Re-run this as Administrator, or omit -Msi for the portable evaluation package."
    }

    $log = Join-Path ([System.IO.Path]::GetTempPath()) "rustinel-msi-$([System.Guid]::NewGuid()).log"
    $arguments = @("/i", "`"$MsiPath`"", "/qn", "/norestart", "/l*v", "`"$log`"")
    if ($TargetDir) {
        $arguments += "INSTALLFOLDER=`"$TargetDir`""
    }

    Write-Host "Running msiexec (log: $log)"
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru

    # 3010 is ERROR_SUCCESS_REBOOT_REQUIRED. The install succeeded; something
    # held a file open. Treating it as a failure would send the operator
    # chasing a problem they do not have.
    if ($process.ExitCode -eq 3010) {
        Write-Warning "Installed. A reboot is required to finish replacing a file in use."
    }
    elseif ($process.ExitCode -ne 0) {
        throw "msiexec failed with exit code $($process.ExitCode). Verbose log: $log"
    }

    Write-Host ""
    Write-Host "Rustinel installed. The service is registered as 'Rustinel' and starts at boot."
    Write-Host "  Status:  Get-Service Rustinel"
    Write-Host "  Config:  $env:ProgramData\Rustinel\config.toml"
    Write-Host "  Alerts:  $env:ProgramData\Rustinel\logs"
    Write-Host ""
    Write-Host "The installer deliberately ships no detection rules. Install them with:"
    Write-Host "  & `"$env:ProgramFiles\Rustinel\rustinel.exe`" rules install essential"
    Write-Host ""
    # Not "msiexec /x $MsiPath": this script downloaded the MSI to a temporary
    # directory it deletes on the way out. Windows keeps its own cached copy,
    # which is what the ProductCode below reaches.
    Write-Host "Uninstall from Apps & Features, or by ProductCode:"
    Write-Host "  `$key = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' |"
    Write-Host "      Where-Object DisplayName -eq 'Rustinel'"
    Write-Host "  msiexec /x `$key.PSChildName /qn"
}

$InvokedFromStream = [string]::IsNullOrEmpty($PSCommandPath)

if (-not $PSBoundParameters.ContainsKey("Repo") -and -not [string]::IsNullOrWhiteSpace($env:RUSTINEL_REPO)) {
    $Repo = $env:RUSTINEL_REPO
}

if (-not $PSBoundParameters.ContainsKey("Version") -and -not [string]::IsNullOrWhiteSpace($env:RUSTINEL_VERSION)) {
    $Version = $env:RUSTINEL_VERSION
}

if (-not $PSBoundParameters.ContainsKey("InstallDir") -and -not [string]::IsNullOrWhiteSpace($env:RUSTINEL_INSTALL_DIR)) {
    $InstallDir = $env:RUSTINEL_INSTALL_DIR
}

if (-not $PSBoundParameters.ContainsKey("Run") -and (Test-TruthyEnv $env:RUSTINEL_RUN)) {
    $Run = $true
}

if (-not $PSBoundParameters.ContainsKey("Force") -and (Test-TruthyEnv $env:RUSTINEL_FORCE)) {
    $Force = $true
}

if (-not $PSBoundParameters.ContainsKey("Msi") -and (Test-TruthyEnv $env:RUSTINEL_MSI)) {
    $Msi = $true
}

if (-not $PSBoundParameters.ContainsKey("MsiInstallDir") -and -not [string]::IsNullOrWhiteSpace($env:RUSTINEL_MSI_INSTALL_DIR)) {
    $MsiInstallDir = $env:RUSTINEL_MSI_INSTALL_DIR
}

# The MSI installs a service that runs on its own; there is nothing to launch
# in the foreground and nothing to evaluate in a temporary directory. Running
# the evaluation path afterwards would start a second, portable agent
# competing with the service for the same ETW sessions.
$RunEvaluation = (-not $Msi) -and ([bool]$Run -or $InvokedFromStream)

if (-not [Environment]::Is64BitOperatingSystem) {
    throw "Only 64-bit Windows is supported by the published release archive."
}

# Checked before the download rather than after it. The MSI refuses to install
# unelevated anyway, and finding that out is cheaper before pulling tens of
# megabytes than after.
if ($Msi -and -not (Test-Administrator)) {
    throw "The MSI registers a Windows service and must be installed from an elevated PowerShell. Re-run this as Administrator, or drop -Msi/RUSTINEL_MSI for the portable evaluation package."
}

if ($Version -eq "latest") {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
    $Version = $release.tag_name.TrimStart("v")
} else {
    $Version = $Version.TrimStart("v")
}

if ($Msi) {
    $asset = "rustinel-$Version-x86_64.msi"
} else {
    $asset = "rustinel-$Version-x86_64-pc-windows-msvc.zip"
}
$checksums = "rustinel-$Version-checksums-sha256.txt"
$baseUrl = "https://github.com/$Repo/releases/download/v$Version"
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) "rustinel-install-$([System.Guid]::NewGuid())"

New-Item -ItemType Directory -Path $tmp | Out-Null

try {
    $assetPath = Join-Path $tmp $asset
    $checksumsPath = Join-Path $tmp $checksums

    # GitHub redirects release assets to a presigned CDN URL signed for GET, so a
    # HEAD probe is rejected and Invoke-WebRequest throws a false "not found".
    # Let the actual GET download be the existence check instead.
    Write-Host "Downloading $asset"
    try {
        Invoke-WebRequest -Uri "$baseUrl/$asset" -OutFile $assetPath
    } catch {
        Show-InstallScope
        throw "No published release asset found for this host: $asset. Release page: https://github.com/$Repo/releases/tag/v$Version"
    }
    Invoke-WebRequest -Uri "$baseUrl/$checksums" -OutFile $checksumsPath

    $expected = Get-Content $checksumsPath |
        Where-Object { $_ -match [regex]::Escape($asset) } |
        ForEach-Object { ($_ -split "\s+")[0].ToLowerInvariant() } |
        Select-Object -First 1

    if (-not $expected) {
        throw "Checksum file did not contain $asset"
    }

    $actual = (Get-FileHash -Algorithm SHA256 $assetPath).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "Checksum mismatch for $asset. Expected $expected, got $actual."
    }

    if ($Msi) {
        # The checksum above proves the download matches the release; the
        # signature proves the release came from whoever owns the certificate.
        # Both matter, and neither substitutes for the other: a checksum file
        # fetched from the same place as the artifact is only as trustworthy
        # as that place.
        Assert-InstallerSignature -Path $assetPath -SourceRepo $Repo
        Install-Msi -MsiPath $assetPath -TargetDir $MsiInstallDir
        return
    }

    $extractDir = Join-Path $tmp "extract"
    Expand-Archive -Path $assetPath -DestinationPath $extractDir
    $packageDir = Join-Path $extractDir "rustinel-$Version-x86_64-pc-windows-msvc"

    if (-not (Test-Path $packageDir)) {
        throw "Archive did not contain expected directory: rustinel-$Version-x86_64-pc-windows-msvc"
    }

    if (Test-Path $InstallDir) {
        if ($Force) {
            Remove-Item -Recurse -Force $InstallDir
        } else {
            throw "Install directory already exists: $InstallDir. Pass -Force or choose another -InstallDir."
        }
    }

    New-Item -ItemType Directory -Path $InstallDir | Out-Null
    Copy-Item -Path (Join-Path $packageDir "*") -Destination $InstallDir -Recurse -Force

    Show-PortableEvaluation -Path $InstallDir -ReleaseVersion $Version

    if ($RunEvaluation) {
        Set-Location $InstallDir
        Write-Host ""
        Write-Host "Starting portable evaluation. Trigger detection with: whoami"
        Write-Host "Alerts are written to: $(Join-Path $InstallDir 'logs\alerts.json.*')"
        Write-Host ""
        & .\rustinel.exe run
        $runStatus = $LASTEXITCODE
        if ($null -eq $runStatus) {
            $runStatus = 0
        }
        Write-Host ""
        Show-PromotionCommand -Path $InstallDir
        if ($runStatus -ne 0 -and -not $InvokedFromStream) {
            exit $runStatus
        }
    }
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
