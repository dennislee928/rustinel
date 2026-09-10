<#
.SYNOPSIS
    Authenticode-sign Windows artifacts.

.DESCRIPTION
    Signs a file with one of two credential sources, chosen by which is
    configured rather than by a switch:

      DigiCert KeyLocker  the production path. The private key never leaves
                          DigiCert's HSM; signtool reaches it through the
                          DigiCert Signing Manager KSP. This is what an EV or
                          OV certificate issued after June 2023 requires,
                          because the CA/Browser Forum baseline requirements
                          stopped allowing exportable code-signing keys.

      PFX file            for a self-signed certificate during development, or
                          an older non-HSM certificate. Not suitable for a
                          public release: a PFX is an exportable private key.

    With neither configured the script does nothing and says so. That is
    deliberate: a fork, a pull request build, and a local `cargo build` all have
    no signing credentials, and failing there would mean nobody outside the
    project could build an installer at all. Release builds pass -Required so
    the same script becomes a hard failure when it matters.

.PARAMETER Path
    File to sign. Accepts .exe, .dll, .msi, .cat, .sys.

.PARAMETER Description
    Shown in the User Account Control prompt the signed file produces.

.PARAMETER Required
    Fail rather than skip when no credentials are configured.

.NOTES
    Timestamping is not optional. An untimestamped signature stops validating
    the moment the certificate expires, which turns a released installer into a
    warning dialog on a date nobody chose.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$Description = 'Rustinel endpoint detection and response agent',

    [switch]$Required
)

$ErrorActionPreference = 'Stop'

# RFC 3161 timestamp authority. DigiCert's, because the certificate is theirs;
# any RFC 3161 server would do.
$TimestampUrl = 'http://timestamp.digicert.com'

function Find-SignTool {
    <#
        signtool.exe ships in the Windows SDK, which installs it under a
        versioned directory. The newest x64 build is the right one; hard-coding
        a version would break on every SDK update.
    #>
    $candidates = @()

    $kitRoot = 'C:\Program Files (x86)\Windows Kits\10\bin'
    if (Test-Path $kitRoot) {
        $candidates += Get-ChildItem -Path $kitRoot -Recurse -Filter 'signtool.exe' -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\' } |
            Sort-Object -Property FullName -Descending
    }

    $onPath = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($onPath) {
        $candidates += Get-Item $onPath.Source
    }

    if ($candidates.Count -eq 0) {
        throw 'signtool.exe not found. Install the Windows SDK signing tools.'
    }

    return $candidates[0].FullName
}

function Test-KeyLockerConfigured {
    # All five are needed; a partial configuration is a misconfiguration rather
    # than a reason to fall back silently to something less safe.
    return $env:SM_API_KEY -and
           $env:SM_CLIENT_CERT_FILE -and
           $env:SM_CLIENT_CERT_PASSWORD -and
           $env:SM_HOST -and
           $env:SM_CODE_SIGNING_CERT_SHA1_HASH
}

function Test-PfxConfigured {
    return $env:WINDOWS_PFX_FILE -and (Test-Path $env:WINDOWS_PFX_FILE)
}

function Invoke-SignTool {
    param([string[]]$Arguments)

    $signtool = Find-SignTool
    Write-Host "signtool: $signtool"

    & $signtool @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "signtool failed with exit code $LASTEXITCODE"
    }
}

if (-not (Test-Path $Path)) {
    throw "Cannot sign $Path : file not found"
}

$resolved = (Resolve-Path $Path).Path

if (Test-KeyLockerConfigured) {
    Write-Host "Signing $resolved with DigiCert KeyLocker"

    # The KSP reads its configuration from the environment the DigiCert client
    # tools set up; smctl registers it once per runner.
    Invoke-SignTool @(
        'sign',
        '/sha1', $env:SM_CODE_SIGNING_CERT_SHA1_HASH,
        '/tr', $TimestampUrl,
        '/td', 'SHA256',
        '/fd', 'SHA256',
        '/d', $Description,
        '/csp', 'DigiCert Signing Manager KSP',
        '/kc', $env:SM_KEYPAIR_ALIAS,
        '/v',
        $resolved
    )
}
elseif (Test-PfxConfigured) {
    Write-Host "Signing $resolved with a PFX certificate"
    Write-Warning 'A PFX holds an exportable private key. Do not use this for a public release.'

    $arguments = @(
        'sign',
        '/f', $env:WINDOWS_PFX_FILE,
        '/tr', $TimestampUrl,
        '/td', 'SHA256',
        '/fd', 'SHA256',
        '/d', $Description,
        '/v'
    )
    if ($env:WINDOWS_PFX_PASSWORD) {
        $arguments += @('/p', $env:WINDOWS_PFX_PASSWORD)
    }
    $arguments += $resolved

    Invoke-SignTool $arguments
}
elseif ($Required) {
    throw @'
No signing credentials are configured, and -Required was given.

Set either the DigiCert KeyLocker variables:
  SM_HOST, SM_API_KEY, SM_CLIENT_CERT_FILE, SM_CLIENT_CERT_PASSWORD,
  SM_CODE_SIGNING_CERT_SHA1_HASH, SM_KEYPAIR_ALIAS

or, for development only:
  WINDOWS_PFX_FILE, WINDOWS_PFX_PASSWORD
'@
}
else {
    Write-Warning "No signing credentials configured; leaving $resolved unsigned."
    Write-Warning 'Windows will show a SmartScreen warning for this file.'
    return
}

# Verify what was actually produced rather than trusting the exit code. The
# /pa flag checks against the Authenticode policy an end user's machine will
# use, which is stricter than the default driver policy.
Write-Host "Verifying signature on $resolved"
$signtool = Find-SignTool
& $signtool verify /pa /v $resolved
if ($LASTEXITCODE -ne 0) {
    throw "Signature verification failed for $resolved"
}

Write-Host "Signed and verified: $resolved"
