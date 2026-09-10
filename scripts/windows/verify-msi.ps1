<#
.SYNOPSIS
    Check that a built MSI says what it is supposed to say.

.DESCRIPTION
    `wix build` exiting zero means the authoring compiled, not that the
    installer will do the right thing. The properties that matter here are ones
    a typo silently breaks and only a real installation would reveal:

      the service name and arguments      a mismatch with src/platform/windows.rs
                                          gives a service that starts and then
                                          cannot find its configuration

      the configuration component bits     without NeverOverwrite and Permanent,
                                          an upgrade silently discards every
                                          rule, allowlist, and response policy
                                          the operator wrote

      the upgrade code                     a changed one gives every machine two
                                          Rustinels and one working agent

      the launch conditions                without them the MSI installs on
                                          32-bit Windows or without elevation
                                          and fails halfway through

    Reads the MSI database directly rather than installing, so it runs on any
    machine and in CI.

.PARAMETER Path
    The .msi to inspect.

.PARAMETER ExpectSigned
    Also require a valid Authenticode signature.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [switch]$ExpectSigned
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Path)) {
    throw "MSI not found: $Path"
}
$resolved = (Resolve-Path $Path).Path
Write-Host "Verifying $resolved"

$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.GetType().InvokeMember(
    'OpenDatabase', 'InvokeMethod', $null, $installer, @($resolved, 0))

function Get-Rows {
    param([string]$Sql)

    $view = $database.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $database, @($Sql))
    $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null

    $rows = @()
    while ($true) {
        $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
        if ($null -eq $record) { break }

        $fields = $record.GetType().InvokeMember('FieldCount', 'GetProperty', $null, $record, $null)
        $values = @()
        for ($i = 1; $i -le $fields; $i++) {
            $values += [string]$record.GetType().InvokeMember(
                'StringData', 'GetProperty', $null, $record, @($i))
        }
        $rows += , $values
    }

    # Comma-wrapped: `return $rows` unrolls a one-element array, which would
    # hand the caller the row's fields instead of a list containing one row,
    # and every index would silently address a character of a string.
    return , $rows
}

$failures = @()

function Assert {
    param([bool]$Condition, [string]$Message)

    if ($Condition) {
        Write-Host "  ok    $Message"
    }
    else {
        Write-Host "  FAIL  $Message"
        $script:failures += $Message
    }
}

# --- Identity ---------------------------------------------------------------
# Assigned before iterating: a function returning a wrapped array is
# enumerated once by the pipeline, so `foreach (... in Get-Rows ...)` would
# see one item holding every row.
$propertyRows = Get-Rows 'SELECT `Property`, `Value` FROM `Property`'
$properties = @{}
foreach ($row in $propertyRows) {
    $properties[$row[0]] = $row[1]
}

Assert ($properties['ProductName'] -eq 'Rustinel') "ProductName is Rustinel"
Assert ($properties['ProductVersion'] -match '^\d+\.\d+\.\d+$') `
    "ProductVersion is x.y.z ($($properties['ProductVersion']))"
# The one value that must never change across releases.
Assert ($properties['UpgradeCode'] -eq '{7B0E4C2A-9D31-4F58-A6E7-2C15D8B34F90}') `
    "UpgradeCode is unchanged"

# --- Service ----------------------------------------------------------------
$services = Get-Rows 'SELECT `Name`, `DisplayName`, `StartType`, `Arguments` FROM `ServiceInstall`'
Assert ($services.Count -eq 1) "exactly one service is installed"

if ($services.Count -ge 1) {
    $service = $services[0]
    Assert ($service[0] -eq 'Rustinel') "service name matches src/platform/windows.rs"
    Assert ($service[1] -eq 'Rustinel ETW Sentinel') "service display name matches"
    # 2 is SERVICE_AUTO_START: an EDR that does not start at boot is not an EDR.
    Assert ($service[2] -eq '2') "service starts automatically"
    Assert ($service[3] -like 'run --config *--no-console') `
        "service arguments match the binary's own contract"
}

# Start on install, stop on install and uninstall, delete on uninstall.
$control = Get-Rows 'SELECT `Name`, `Event` FROM `ServiceControl`'
Assert ($control.Count -ge 1) "the service is controlled on install and uninstall"
if ($control.Count -ge 1) {
    $event = [int]$control[0][1]
    Assert (($event -band 1) -ne 0) "service is started on install"
    Assert (($event -band 2) -ne 0) "service is stopped before an upgrade replaces the binary"
    Assert (($event -band 32) -ne 0) "service is stopped on uninstall"
    Assert (($event -band 128) -ne 0) "service is deleted on uninstall"
}

# --- Configuration is never destroyed ---------------------------------------
$componentRows = Get-Rows 'SELECT `Component`, `Attributes` FROM `Component`'
$components = @{}
foreach ($row in $componentRows) {
    $components[$row[0]] = [int]$row[1]
}

Assert ($components.ContainsKey('ConfigFile')) "the configuration component exists"
if ($components.ContainsKey('ConfigFile')) {
    $attributes = $components['ConfigFile']
    # msidbComponentAttributesNeverOverwrite = 16, Permanent = 128.
    Assert (($attributes -band 16) -ne 0) `
        "config.toml is NeverOverwrite, so an upgrade cannot discard it"
    Assert (($attributes -band 128) -ne 0) `
        "config.toml is Permanent, so an uninstall cannot discard it"
}

# --- Refusals ---------------------------------------------------------------
$conditionRows = Get-Rows 'SELECT `Condition` FROM `LaunchCondition`'
$conditions = @($conditionRows | ForEach-Object { $_[0] })
Assert ($conditions -contains 'VersionNT64') "refuses to install on 32-bit Windows"
Assert ($conditions -contains 'Privileged') "refuses to install without elevation"
Assert ($conditions -contains 'NOT WIX_DOWNGRADE_DETECTED') "refuses to downgrade"

# --- Payload ----------------------------------------------------------------
$fileRows = Get-Rows 'SELECT `FileName` FROM `File`'
$files = @($fileRows | ForEach-Object { $_[0] })
Assert (($files | Where-Object { $_ -like '*rustinel.exe' }).Count -eq 1) "the agent binary is included"
Assert (($files | Where-Object { $_ -like '*config.toml' }).Count -eq 1) "a default configuration is included"

# --- Signature --------------------------------------------------------------
if ($ExpectSigned) {
    $signature = Get-AuthenticodeSignature -FilePath $resolved
    Assert ($signature.Status -eq 'Valid') "Authenticode signature is valid ($($signature.Status))"
    Assert ($null -ne $signature.TimeStamperCertificate) `
        "signature is timestamped, so it outlives the certificate"
    if ($signature.SignerCertificate) {
        Write-Host "  signer: $($signature.SignerCertificate.Subject)"
    }
}

if ($failures.Count -gt 0) {
    Write-Host ''
    throw "$($failures.Count) installer check(s) failed:`n  - $($failures -join "`n  - ")"
}

Write-Host ''
Write-Host "All installer checks passed for $resolved"
