# Windows Installer

Rustinel ships for Windows two ways. The `.msi` is the one to use: it registers
the service, lays down configuration under `ProgramData`, and takes all of it
away again on uninstall. The `.zip` is a portable build for people who want the
binary and nothing else.

## Installing

```powershell
msiexec /i rustinel-1.5.1-x86_64.msi
```

Silently, for deployment:

```powershell
msiexec /i rustinel-1.5.1-x86_64.msi /qn /l*v install.log
```

The installer must run elevated. It refuses otherwise rather than failing
halfway through registering a service, and it refuses on 32-bit Windows.

### What lands where

| Path | Contents |
| --- | --- |
| `C:\Program Files\Rustinel\rustinel.exe` | The agent |
| `C:\ProgramData\Rustinel\config.toml` | Configuration |
| `C:\ProgramData\Rustinel\rules\` | Rule packs |
| `C:\ProgramData\Rustinel\logs\` | Alerts and operational logs |
| `C:\ProgramData\Rustinel\quarantine\` | Quarantined files, restricted to SYSTEM and Administrators |
| `C:\ProgramData\Rustinel\state\` | Response state |

The service is `Rustinel`, displayed as `Rustinel ETW Sentinel`, running as
LocalSystem and started automatically. It runs
`rustinel.exe run --config "C:\ProgramData\Rustinel\config.toml" --no-console`,
which is the same contract `rustinel service install` uses for portable
installs.

### After installing

The installer deliberately does not fetch rules. A network call during an MSI
transaction is a common cause of failed installs and is difficult to roll back,
so it is left as a separate step you can see fail:

```powershell
rustinel rules install essential
rustinel doctor
```

`doctor` is worth running before you consider the install finished. It reports
the audit policy the Security-channel collectors need, the platform protections
the agent depends on, and whether the response actions you enabled can actually
run.

## Upgrading

Install the new MSI over the old one. Windows recognises it as a major upgrade,
stops the service, replaces the binary, and starts it again.

**Your configuration is not touched.** `config.toml` is marked never-overwrite
and permanent, so an upgrade cannot discard the rules, allowlists, and response
policy you wrote, and an uninstall cannot either. The consequence is that new
configuration keys added by a release do not appear in your file: they take
their defaults, and the release notes say what changed.

Downgrades are refused. Uninstall first if you mean it.

## Uninstalling

```powershell
msiexec /x rustinel-1.5.1-x86_64.msi /qn
```

Removed: the binary, the service, and the empty data directories.

Left behind: `config.toml`, your rules, your logs, and anything in quarantine.
An uninstall is not consent to destroy an incident record. Delete
`C:\ProgramData\Rustinel` by hand if you want it gone, and restore anything you
still need from quarantine first:

```powershell
rustinel response quarantine
rustinel response restore <id> --to C:\triage\
```

## Building the installer

Needs the .NET SDK and the WiX toolset:

```powershell
dotnet tool install --global wix --version 5.0.2
wix extension add --global WixToolset.UI.wixext/5.0.2
wix extension add --global WixToolset.Util.wixext/5.0.2
```

Then:

```powershell
cargo build --release
.\scripts\windows\build-msi.ps1
.\scripts\windows\verify-msi.ps1 -Path (Get-Item dist\*.msi).FullName
```

`verify-msi.ps1` reads the built package and checks the things a typo silently
breaks: that the service name and arguments match the binary's own contract,
that the configuration component really is never-overwrite, that the upgrade
code has not changed, and that the launch conditions are present. It runs in CI
on every change, because packaging exercised only at release time is packaging
that breaks at release time.

## Signing

An unsigned installer works. It also shows an unknown-publisher prompt, and
SmartScreen will warn about it until enough people have installed it anyway,
which is not a reputation an EDR agent should be asking for.

`scripts/windows/sign.ps1` handles two credential sources and picks whichever is
configured.

### DigiCert KeyLocker

The production path. A code-signing certificate issued after June 2023 has to
keep its private key in hardware, so there is no file to copy onto a build
machine: `signtool` reaches the key through DigiCert's Key Storage Provider and
the key never leaves their HSM.

Set these as repository secrets:

| Secret | What it is |
| --- | --- |
| `SM_HOST` | DigiCert ONE host, e.g. `https://clientauth.one.digicert.com` |
| `SM_API_KEY` | Software Trust Manager API key |
| `SM_CLIENT_CERT_FILE_B64` | Base64 of the client authentication `.p12` |
| `SM_CLIENT_CERT_PASSWORD` | Password for that `.p12` |
| `SM_CODE_SIGNING_CERT_SHA1_HASH` | SHA-1 thumbprint of the signing certificate |
| `SM_KEYPAIR_ALIAS` | Keypair alias in Software Trust Manager |

To produce the base64 for the client certificate:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("Certificate_pkcs12.p12")) | Set-Clipboard
```

The release workflow skips signing entirely when `SM_API_KEY` is absent, so a
fork can still build. What it will not do is publish an unsigned installer while
claiming it is signed: the verification step only asserts a signature when
credentials were present.

### A PFX file

For development against a self-signed certificate, or an older non-HSM
certificate:

```powershell
$env:WINDOWS_PFX_FILE = "C:\path\to\cert.pfx"
$env:WINDOWS_PFX_PASSWORD = "..."
.\scripts\windows\build-msi.ps1 -Sign
```

A PFX holds an exportable private key. It is fine on your own machine and wrong
for a public release, and the script says so every time it uses one.

### Both the binary and the installer are signed

In that order. Signing only the MSI would leave an unsigned `rustinel.exe` on
disk after installation, and that is the file Windows checks on every launch.

Every signature is timestamped against an RFC 3161 authority. An untimestamped
signature stops validating the day the certificate expires, which turns a
released installer into a warning dialog on a date nobody chose.

## Verifying a release

```powershell
Get-AuthenticodeSignature .\rustinel-1.5.1-x86_64.msi | Format-List Status, SignerCertificate
```

Checksums and build provenance for every release asset are published alongside
them. The provenance attestation is generated by GitHub and can be checked with:

```powershell
gh attestation verify rustinel-1.5.1-x86_64.msi --repo Karib0u/rustinel
```

## What is not signed

The kernel driver in `driver/`. It is source, and loading a driver needs a
signature chaining to a Microsoft cross-signing certificate, obtained through
attestation signing or WHQL submission with an EV certificate. That is a
separate certificate from the one signing the agent, and a separate process.
See [`driver/README.md`](https://github.com/Karib0u/rustinel/blob/main/driver/README.md).
