# Rustinel kernel driver

The part of response that can say no.

Everything the Rustinel agent does runs in user mode, which means it acts
*after* the operation it responds to. A credential dumper's handle to `lsass`
is already open by the time the sensor reports it; the agent kills the process a
few milliseconds later, and whatever was read in those milliseconds is read.

Windows offers exactly four supported ways to refuse an operation while it is
happening. All four are kernel-mode callbacks, which is why this directory
exists.

| Callback | What it refuses | Where |
| --- | --- | --- |
| `ObRegisterCallbacks` | Handle opens and duplicates against a protected process | `src/callbacks.c` |
| `CmRegisterCallbackEx` | Registry writes under a protected key | `src/callbacks.c` |
| `FltRegisterFilter` | Writes, renames, and deletes against a protected path | `src/minifilter.c` |
| `PsSetCreateProcessNotifyRoutineEx` | A process, before its first instruction | `src/process.c` |
| `FwpsCalloutRegister` | Packets, after inspecting payload | Not implemented, and not planned |

The last row is deliberate. WFP *filters* block by address, port, and
application, they are installed from user mode, and the kernel already enforces
them; the agent does that today in `src/response/executor/wfp.rs`. A callout is
only needed to inspect payload bytes, which Rustinel does not do.

`src/process.c` also carries `ZwTerminateProcess`, reachable over
`IOCTL_RUSTINEL_PROTECT_PROCESS`. It exists because a kernel-mode kill reaches
targets a user-mode one cannot: a protected-process-light process refuses the
agent a handle with the rights to terminate it, however privileged the agent is.
Critical processes are refused there rather than attempted, because terminating
one bugchecks the machine and the kernel is the last place to catch that.

Thread creation is watched and never denied. Windows offers no supported way to
refuse a thread; the notification exists so remote-thread injection is reported
from a channel that cannot be lost to a full trace buffer.

## What is deliberately absent

**ELAM.** An Early Launch Anti-Malware driver classifies boot-start drivers
before they load, and is the only way to see a rootkit that installs itself
earlier than an ordinary driver. It is not here because an ELAM driver must be
signed with a Microsoft-issued Early Launch certificate, which is issued only to
members of the Microsoft Virus Initiative. That is a membership problem, not a
code problem, and writing an ELAM driver that cannot be signed would be writing
something that cannot run.

**ETW Threat Intelligence.** `Microsoft-Windows-Threat-Intelligence` is the only
source of cross-process memory-write and APC-injection events. Subscribing needs
the agent to run as a Protected Process Light, which needs an ELAM driver, which
needs the certificate above. The same wall.

**Hardware telemetry.** Intel Threat Detection Technology is exposed through
Microsoft Defender and a partner SDK, not a public interface. Intel Processor
Trace reaches user mode only through `ipt.sys`, which is a debugging transport
rather than a security one. Neither is reachable for an open-source agent, and
the honest position is to say so rather than to claim a proxy heuristic is the
same thing.

## This driver does not ship

It is source, not a product. A driver loads on 64-bit Windows only with a
signature chaining to a Microsoft cross-signing certificate, obtained through
attestation signing or WHQL submission with an EV code-signing certificate.
`ObRegisterCallbacks` additionally refuses to register for any image not linked
with `/INTEGRITYCHECK` and signed.

Neither is a coding problem. Until an organisation with those certificates
builds and signs it, the agent runs without a driver, `KernelDriverExecutor`
reports every action unsupported, and the user-mode executors do the work after
the fact. That is the normal case and nothing about it is broken.

## Design

The driver holds no detection logic. It holds a flat, fixed-size policy table
pushed down by the agent over one IOCTL, and enforces that table in the
pre-operation callbacks. Everything that decides *what* belongs in the table
lives in user mode.

That split is the point. Kernel code that can be wrong in an interesting way is
kernel code that can bugcheck the machine, so the interesting part stays where
being wrong is survivable.

Four rules the callbacks obey, in `src/callbacks.c`:

1. **Never block.** A pre-operation callback runs on the thread performing the
   operation. Calling up to the agent would stall that thread and deadlock
   outright whenever the agent is itself the caller.
2. **Never allocate on the decision path.** Allocation can fail and a failure
   there has nowhere to go, which is why the policy table is fixed-size.
3. **Fail open.** If the policy cannot be read, the operation is allowed. A
   driver that denies when confused takes the machine down, which is worse than
   a missed block.
4. **Never police the agent or the kernel.** A policy steerable into denying the
   agent its own handles disarms response; one that touches System bugchecks.

## Interface

`include/rustinel_ioctl.h` is the contract, mirrored by
`src/response/executor/driver.rs`. The two must agree exactly: a struct that
disagrees across the boundary is kernel memory corruption, not a parse error.
`RUSTINEL_POLICY_VERSION` exists so a mismatched pair fails loudly instead.

## Building

Needs the Windows Driver Kit, or the EWDK for a build without an installed
Visual Studio.

```
:: One-time, on the development machine only. Reboots.
bcdedit /set testsigning on

:: Build (EWDK: run LaunchBuildEnv.cmd first)
msbuild rustinel.vcxproj /p:Configuration=Release /p:Platform=x64
```

The image must be linked with `/INTEGRITYCHECK` or `ObRegisterCallbacks`
returns `STATUS_ACCESS_DENIED` at load and nowhere else. That single missing
flag is the most common reason a development build appears to load and then does
nothing.

## Signing, and what each option gets you

| Option | Loads on | Good for |
| --- | --- | --- |
| Self-signed, test-signing on | Only machines with test-signing enabled | Development |
| Attestation signing | Windows 10 1607 and later | Production, no WHQL testing |
| WHQL | Everything, including older builds | Production, distribution |

Attestation signing requires a hardware-backed EV code-signing certificate and a
Microsoft Partner Center account. There is no path that avoids the certificate.

## Installing, for development

```
sc create RustinelDrv type= kernel binPath= C:\path\to\rustinel.sys
sc start RustinelDrv
```

Verify what registered, rather than assuming: a driver that loaded but
registered nothing is the failure mode this hides.

```
rustinel doctor
```

## Altitude

`RUSTINEL_ALTITUDE` in the header is a placeholder in the anti-virus range.
Altitudes are allocated by Microsoft and must be unique; two filters sharing one
is a load failure at best and a silent ordering bug at worst. Request one before
distributing anything built from this source.
