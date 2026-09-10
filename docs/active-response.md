# Active Response

Rustinel includes an optional response engine that acts on the process behind an
alert. It is disabled by default, and when it is enabled it starts in dry run:
it selects and records actions without performing any of them. Turn prevention
on only after reading what the dry run recorded.

Active response runs on **Windows, Linux, and macOS**. It is least exercised on
macOS, where the operating system also refuses to act on SIP-protected and some
system processes even as root. A failure there is logged and audited; the alert
itself is unaffected.

## What user mode can and cannot do

Rustinel runs entirely in user mode (Ring 3). Every action it takes happens
*after* the operation that triggered it has already completed: the sensor sees
an ETW or eBPF event only once the kernel is done with it. That is enough to
kill a credential dumper a few milliseconds into its run, and not enough to stop
the handle being opened in the first place.

Denying an operation outright requires a kernel driver, which Rustinel does not
ship. Windows exposes four supported ways to deny, three of them kernel-only:

| To deny | Kernel API | What Rustinel does instead |
| --- | --- | --- |
| A handle to another process | `ObRegisterCallbacks` pre-operation | Terminates or suspends the requester afterwards |
| A registry write | `CmRegisterCallbackEx` pre-operation | Deletes the value afterwards |
| A file write | Minifilter `FltRegisterFilter` pre-operation | Quarantines the file afterwards |
| A packet | WFP callout `FwpsCalloutRegister` | Installs a WFP filter, which the kernel *does* enforce |

The last row is different in kind from the others. A WFP filter blocks by
address, port, and application; it is installed from user mode and evaluated in
the kernel on every later connection, so nothing about it is after the fact. A
callout is only needed to inspect payload bytes, which Rustinel does not do.

For the other three the difference is a race rather than a capability. A Run key
write deleted a few milliseconds after it lands did exist for those
milliseconds, and survives if the machine reboots inside that window.

Loading a driver on 64-bit Windows needs a signature chaining to a Microsoft
cross-signing certificate, which is an organisational prerequisite rather than a
coding one. The driver source is in `driver/`, and `KernelDriverExecutor` probes
for it at startup: with a driver loaded it takes precedence over the user-mode
executors, and without one it reports every action unsupported and they do the
work. Every action's audit record carries the *enforcement* that actually
applied, so which of the two happened is never a guess.

## Modes

1. **Disabled** (`enabled = false`): no response work is queued.
2. **Dry run** (`prevention_enabled = false`): actions are selected, logged, and
   audited. Nothing is performed. This is the default when response is on.
3. **Prevention** (`prevention_enabled = true`): actions are performed.

A policy rule can set `dry_run = true` to hold one rule back while the rest of
the policy is live. It can only tighten: no rule can switch prevention on.

## Actions

| Action | What it does | Platforms | Enforcement | Enabled by default |
| --- | --- | --- | --- | --- |
| `terminate_process` | Kills the process | Windows, Linux, macOS | post-hoc | Yes |
| `suspend_process` | Freezes every thread, leaving the process for triage | Windows, Linux, macOS | post-hoc | No |
| `isolate_host` | Cuts the host off the network except an allowlist | Windows | **inline** | No |
| `block_process_network` | Denies one image network access | Windows | **inline** | No |
| `quarantine_file` | Moves a file out of reach, reversibly | Windows, Linux, macOS | post-hoc | No |
| `revert_registry` | Deletes a persistence value or key | Windows | post-hoc | No |
| `disable_service` | Stops a service and marks it disabled | Windows | post-hoc | No |
| `disable_scheduled_task` | Disables a scheduled task | Windows | post-hoc | No |

The two network actions are the only ones marked inline, and the distinction is
real rather than cosmetic. A WFP filter is installed from user mode but
evaluated by the kernel on every later connection, so the packet never leaves.
Everything else happens after the operation it responds to.

An action that cannot run on this platform, or whose subject the alert does not
name, is reported as unsupported rather than silently ignored, so a policy
naming one is visible in the audit stream instead of quietly doing nothing.

### What each action needs from the alert

Most actions act on something other than the process, and only an alert that
named that subject can drive them.

| Action | Subject | Comes from |
| --- | --- | --- |
| `terminate_process`, `suspend_process`, `block_process_network` | The process | Any alert carrying a process |
| `quarantine_file` | A file | A file event's target, a service image, or the process image on a YARA hit |
| `revert_registry` | A key, and a value where the event named one | A registry event |
| `disable_service` | A service name | A service creation event (7045) |
| `disable_scheduled_task` | A task path | A task registration event |
| `isolate_host` | Nothing; it acts on the host | Any alert |

An action whose subject is absent is suppressed with `missing_target`, not
applied to a substitute.

### Reverting the registry

A persistence value that did not exist before the attack is deleted, because for
that one deletion *is* the original state.

A value that did exist is restored instead. Winlogon's `Userinit` and a service's
`ImagePath` are modified by an attacker rather than created, and deleting one
breaks the logon path or the service rather than repairing it.

Knowing which is which needs the previous value, and a registry event never
carries one: it says what was written, never what was there before. So the agent
reads the auto-start keys at startup and keeps that snapshot for the life of the
process. The limit is worth stating plainly: a restore returns the value to its
state when the agent started, not to its state immediately before the attack.
For the auto-start keys those are nearly always the same, because legitimate
writes to them are rare.

### Quarantine

A file is moved into `response.quarantine_directory` under its SHA-256, stored
with its bytes obfuscated, and accompanied by a metadata document naming where
it came from. Restoring reproduces the original exactly.

On Windows the directory is restricted to SYSTEM, Administrators, and the
account the agent runs as. It holds live malware: an inherited ACL that lets
interactive users read it turns the quarantine into a distribution point, and
one that lets them write it turns a restore into an arbitrary file write.

The obfuscation is a single-byte XOR. It is not encryption and is not claimed to
be: it exists so the quarantine directory does not read as a malware collection
to the next scanner that walks it, and so a stored file cannot be run by
double-clicking it.

Nothing under the agent's own install and data directories is ever quarantined.
A response engine that can be steered into quarantining its own binary is one an
attacker can disarm through a detection.

### Isolation

Isolation refuses to run unless `[response.actions.isolate_host]` names at least
one exception. Cutting off a machine reachable only over the network it just
lost is an outage the agent cannot undo remotely, so the empty case is treated
as an operator who has not decided rather than one who wants everything blocked.

Exceptions are networks, not addresses. `allow_cidrs = ["10.0.0.0/8"]` keeps the
whole range reachable, and a bare address is treated as a host route. An entry
that is not an address or a network is refused before anything is installed
rather than silently dropped, because an exception the operator believes is in
force and is not is how a machine gets stranded. `rustinel doctor` reports the
same thing ahead of time.

Loopback is permitted unconditionally and is not configurable. A host that
cannot reach itself loses local inter-process communication over TCP, which
breaks software that has nothing to do with the incident.

Filters are installed under Rustinel's own WFP provider and sublayer, with
permit filters weighted above the block so exceptions win. `rustinel response
unisolate` enumerates by provider rather than trusting a stored list, so
isolation can be lifted after a reboot, a crash, or a lost state file.

With `persistent = true`, the default, filters survive a reboot. That fails
closed: a host stays isolated even if the agent never starts again, which is the
safe direction for containment and the dangerous one for reachability.

On Windows, `terminate_process` is `OpenProcess` plus `TerminateProcess`, and
`suspend_process` is `NtSuspendProcess`. `DebugActiveProcess` would also freeze a
process but kills it when the debugger detaches, which defeats the purpose of
preserving it. On Linux and macOS the two actions are `SIGKILL` and `SIGSTOP`.

A suspended process stays suspended. Nothing resumes it automatically; resume it
from the platform's own tools once triage is done.

When a rule selects several actions, they run in a fixed order rather than the
order written: freeze first, then containment, then termination last, so the
process is still alive for the steps that need it.

## Policy rules

Which alerts get which actions is decided by `[[response.rules]]` in
configuration, not by the detection rules themselves. Rule packs are installed
from a catalog and replaced wholesale by `rustinel rules install`, so a rule
author who could name an action would be deciding what runs on someone else's
machine. Rules select; the operator decides.

Rules are evaluated in order and the first match wins. Every field that is set
must match; an unset field matches everything.

```toml
[[response.rules]]
name = "credential-access"
tags = ["attack.t1003*"]          # Sigma rule tags; * wildcards allowed
categories = ["process_access"]   # Sigma logsource category of the event
rule_ids = []                     # exact rule.id values (sigma::<uuid>)
rule_names = []                   # rule titles; * wildcards allowed
engines = ["sigma", "yara"]       # sigma, yara, ioc
min_severity = "high"
actions = ["suspend_process", "terminate_process"]
dry_run = false
```

Leave the list out entirely to keep the behaviour Rustinel had before policy
rules existed: terminate at or above `response.min_severity`. That fallback is
what `min_severity` means now; it is ignored once any rule is defined.

An action runs only when a rule selects it **and** it is enabled under
`[response.actions]` **and** the executor can perform it. An action that fails
any of those is reported as `no enabled action` rather than silently dropped.

## Severity Handling

- Sigma uses the rule `level`
- YARA is always treated as `critical`
- IOC uses `ioc.default_severity`

`response.min_severity` and any rule's `min_severity` are applied after those
mappings.

## Allowlists and protected processes

Rustinel will not act on processes that match either of these:

- `allowlist_images`: image basenames or full paths
- `allowlist_paths`: trusted path prefixes

By default, `response.allowlist_paths` inherits `allowlist.paths`, whose
per-platform defaults are listed once in
[Configuration -> Default Trusted Paths](configuration.md#default-trusted-paths).

Separately, a compiled-in list of processes is never acted on, because their
death takes the machine or the session with them. On Windows that is `smss.exe`,
`csrss.exe`, `wininit.exe`, `winlogon.exe`, `services.exe`, `lsass.exe`, and the
kernel pseudo-processes; on Linux `systemd`, `init`, the systemd daemons,
`dbus-daemon`, and `sshd`; on macOS `launchd`, `kernel_task`, `WindowServer`,
`loginwindow`, and `securityd`. Add to that list with
`response.protected_images`; nothing removes an entry from it.

## Safety Checks

The engine declines to act when:

- The PID is missing
- The PID is in the protected low system range (0-4)
- The target is the Rustinel process itself
- The process image path is unknown, so it cannot be checked against the allowlist
- The image or path is allowlisted, or on the protected list
- The process is marked critical, so terminating it would bugcheck Windows
- The process runs as a protected process (PPL), which would refuse the handle anyway
- The action has hit `max_actions_per_minute` for its kind
- The same action ran against the same target within `cooldown_secs`
- The process identity no longer matches the alert, meaning the PID was recycled

The identity check runs immediately before acting, not when the alert arrives,
and compares image and start time. It is what stops a recycled PID being killed
in place of the process that actually alerted.

The two rate controls exist for a rule that matches far more often than its
author expected. `max_actions_per_minute` bounds the damage per minute per
action kind; `cooldown_secs` stops the same action being retried against the
same target in a loop. A dry run consults both but consumes neither.

## Audit records

Every attempted action is written to the alert stream as an ECS document with
`event.dataset: rustinel.response`, including the ones that did nothing. A trail
that showed only successes could not answer why something was *not* stopped.

```json
{
  "event.kind": "event",
  "event.category": ["intrusion_detection"],
  "event.action": "rustinel.response.terminate_process",
  "event.outcome": "success",
  "event.dataset": "rustinel.response",
  "edr.response.action": "terminate_process",
  "edr.response.mode": "prevention",
  "edr.response.decision": "performed",
  "edr.response.executor": "ring3",
  "edr.response.enforcement": "post_hoc",
  "edr.response.policy_rule": "credential-access",
  "edr.response.target": "4242:/tmp/evil",
  "rule.name": "Suspicious LSASS Access",
  "process.pid": 4242
}
```

`edr.response.decision` is one of `performed`, `dry_run`, `suppressed`, or
`failed`. `edr.response.reason` carries the suppression reason or the operating
system error. Set `audit_to_alerts = false` to keep these out of the alert file;
the operational log still records them.

## Logging

Response actions are also logged in the operational log:

```text
response: Active response would perform action pid=4242 image="/tmp/evil" action=terminate_process dry_run=true
response: Active response performed action pid=4242 image="/tmp/evil" action=terminate_process executor=ring3 enforcement=post_hoc
response: Active response suppressed action pid=4242 image="/tmp/evil" action=terminate_process reason=cooldown
response: Active response skipped: allowlisted pid=4321 image="/usr/bin/bash"
```

## Example Configuration

### Windows

```toml
[allowlist]
paths = [
  "C:\\Windows\\",
  "C:\\Program Files\\",
  "C:\\Program Files (x86)\\",
]

[response]
enabled = true
prevention_enabled = false
allowlist_images = []

[response.actions.suspend_process]
enabled = true

[[response.rules]]
name = "credential-access"
tags = ["attack.t1003*"]
min_severity = "high"
actions = ["suspend_process"]

[[response.rules]]
name = "critical-catch-all"
min_severity = "critical"
actions = ["terminate_process"]
```

### Linux

```toml
[allowlist]
paths = [
  "/usr/bin/",
  "/usr/sbin/",
]

[response]
enabled = true
prevention_enabled = false
min_severity = "critical"
allowlist_images = []
```

## Safe Test Flow

### Cross-Platform YARA Demo

1. Enable dry-run mode:

```toml
[response]
enabled = true
prevention_enabled = false
```

2. Start Rustinel.
3. Build and run the sample binary:

```bash
rustc ./examples/yara_demo.rs -o ./examples/yara_demo
./examples/yara_demo
```

On Windows:

```powershell
rustc .\examples\yara_demo.rs -o .\examples\yara_demo.exe
.\examples\yara_demo.exe
```

4. Confirm the operational log shows a dry-run decision, and that the alert file
   contains a matching `rustinel.response` record with
   `edr.response.decision: dry_run`.
5. After validation, switch `prevention_enabled = true` and repeat. The change is
   picked up by hot reload; no restart is needed.

### Sigma Demo

The bundled `whoami` rules verify Sigma detection and the response safety path.
The system `whoami` executable is inside the default trusted path allowlist, so
the expected response log is `Active response skipped: allowlisted`.

Windows:

```powershell
whoami
```

Linux:

```bash
whoami
```

Use the YARA demo above, or another long-running executable outside the trusted
path allowlist, when validating dry-run or termination behavior.

## Platform posture

Some of what protects a machine is not something the agent can do. An attacker
in kernel mode is past Rustinel entirely: they can patch the structures its
telemetry comes from, or read `lsass` memory it is watching. What stops that is
the platform's own virtualization-based protection.

`rustinel doctor` reports on five of them, as warnings rather than failures,
because a machine without them is not misconfigured for Rustinel; it is a
machine where a kernel-mode attacker wins.

| Check | Why it matters to response |
| --- | --- |
| `posture_vbs` | Without VBS the kernel has no isolated world to protect itself with |
| `posture_hvci` | Memory integrity is what stops an unsigned or vulnerable driver reaching kernel mode |
| `posture_credential_guard` | Makes an `lsass` read worthless even when the detection misses |
| `posture_lsa_protection` | Makes `lsass` a protected process, so the handle open is refused by the kernel |
| `posture_dma_protection` | A peripheral reading physical memory over DMA is invisible to any software agent |

It also checks that the actions you have enabled can actually run, because an
action that cannot is invisible until the moment it is needed:

| Check | What it catches |
| --- | --- |
| `response_isolation_exceptions` | Isolation enabled with no exceptions, or with one that does not parse |
| `response_filtering_engine` | The filtering engine unreachable, usually missing elevation or a stopped Base Filtering Engine service |
| `response_quarantine_directory` | A quarantine directory that cannot be written |
| `response_containment_active` | This host is already contained by a previous isolation |

The doctor reads these; it never changes them. Turning on Credential Guard or
memory integrity has reboot and driver-compatibility consequences that belong to
whoever owns the machine.

## Replay never responds

`rustinel replay` reconstructs detections from a recording and never constructs a
response engine, whatever the configuration says. Replaying a recording of an
incident cannot kill anything on the machine doing the replaying.
