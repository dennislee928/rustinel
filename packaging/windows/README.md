# Windows packaging

WiX authoring for the Rustinel MSI. Operator-facing documentation is in
[`docs/windows-installer.md`](../../docs/windows-installer.md); this is the note
for whoever has to change these files.

| File | What it is |
| --- | --- |
| `rustinel.wxs` | The installer definition |
| `License.rtf` | Apache-2.0, shown in the licence pane. Generated from `LICENSE` |
| `rustinel.ico` | Tray and Add/Remove Programs icon, drawn from the social-card shield |

Built by `scripts/windows/build-msi.ps1` and checked by
`scripts/windows/verify-msi.ps1`, which runs in CI on every change.

## Three things that must not change

**`UpgradeCode`.** `{7B0E4C2A-9D31-4F58-A6E7-2C15D8B34F90}`. Windows uses it to
recognise that a new MSI upgrades an existing install rather than sitting beside
it. Change it and every machine that upgrades ends up with two Rustinels, two
service registrations, and one working agent. `verify-msi.ps1` asserts it.

**The service name and arguments.** `rustinel.wxs` mirrors
`src/platform/windows.rs`. The two must agree, because `rustinel service
install` registers the same service for portable installs and a divergence gives
a service that starts and then cannot find its configuration. `verify-msi.ps1`
asserts both.

**The configuration component's attributes.** `NeverOverwrite` and `Permanent`
on the `ConfigFile` component are what stop an upgrade discarding the operator's
rules, allowlists, and response policy, and what stop an uninstall taking them.
This is the single worst thing an agent upgrade can do, so it is asserted too.

## Adding a file to the installer

Add a `Component` to the right `ComponentGroup`. Each needs a stable `Guid` when
it has no file keypath, and `Bitness="always64"` so it lands in the 64-bit view
of the registry and the filesystem.

Anything the *service* writes to belongs under `DATAFOLDER`, not
`INSTALLFOLDER`. A service writing into its own program directory violates the
Windows convention and gives a compromised agent a path to modifying its own
binary directory.

## Regenerating the licence and icon

Both are checked in because the build should not need Python. Regenerate them
only when `LICENSE` or the brand assets change; the scripts that produced them
are one-off and live in the commit that added them.

## What the installer deliberately does not do

**Fetch rules.** A network call inside an MSI transaction is a common cause of
failed installs and is hard to roll back. `rustinel rules install essential` is
a separate step the operator can watch fail.

**Offer repair.** `ARPNOREPAIR` is set. The agent has no UI, and a repair on a
running service is a confusing half-reinstall rather than a fix.

**Install the kernel driver.** It is unsigned source; see
[`driver/README.md`](../../driver/README.md).
