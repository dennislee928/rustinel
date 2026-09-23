/*
 * Rustinel kernel driver: the interface between the user-mode agent and the
 * kernel callbacks.
 *
 * This header is the contract. It is included by the driver and mirrored by
 * `src/response/executor/driver.rs`, and the two must agree exactly: a struct
 * that disagrees across the boundary is a kernel memory-corruption bug, not a
 * deserialization error.
 *
 * # Why this exists
 *
 * Everything the user-mode agent does happens after the operation it responds
 * to. Windows offers exactly four supported ways to deny an operation while it
 * is happening, and all four are kernel-mode callbacks:
 *
 *   ObRegisterCallbacks    strip or deny rights on a handle open or duplicate
 *   CmRegisterCallbackEx   fail a registry operation before it is committed
 *   FltRegisterFilter      complete an IRP with STATUS_ACCESS_DENIED
 *   FwpsCalloutRegister    drop a packet after inspecting its payload
 *
 * The first three are implemented here. The fourth is not: WFP *filters*,
 * which block by address, port, and application, are reachable from user mode
 * and the agent already installs them; a callout is only needed to inspect
 * payload bytes, which Rustinel does not do.
 *
 * # The policy model
 *
 * The driver holds no detection logic. It holds a small, flat policy pushed
 * down by the agent: which processes are protected, which registry keys are
 * protected, and which images are blocked. Decisions are made against that
 * table in the pre-operation callback, on the calling thread, with no round
 * trip to user mode.
 *
 * That is deliberate. A pre-operation callback runs in the context of the
 * thread performing the operation, and blocking it on a user-mode agent would
 * stall the very process being evaluated, deadlock if the agent is itself the
 * caller, and hang the machine if the agent has died. The kernel decides; the
 * agent only supplies the table.
 */

#pragma once

#include <initguid.h>

/* Device the agent opens: \\.\Rustinel */
#define RUSTINEL_DEVICE_NAME    L"\\Device\\Rustinel"
#define RUSTINEL_SYMLINK_NAME   L"\\DosDevices\\Rustinel"
#define RUSTINEL_USER_PATH      L"\\\\.\\Rustinel"

/*
 * Altitude for the object callbacks and the minifilter.
 *
 * Altitudes are assigned by Microsoft and must be unique; the value below is
 * in the FSFilter Anti-Virus range (320000-329999) and MUST be replaced with
 * an allocated one before this driver is distributed. Two filters sharing an
 * altitude is a load failure at best and an ordering bug at worst.
 */
#define RUSTINEL_ALTITUDE       L"321410"

#define RUSTINEL_TYPE           40000

#define IOCTL_RUSTINEL_SET_POLICY \
    CTL_CODE(RUSTINEL_TYPE, 0x800, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_RUSTINEL_CLEAR_POLICY \
    CTL_CODE(RUSTINEL_TYPE, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_RUSTINEL_QUERY_STATE \
    CTL_CODE(RUSTINEL_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_RUSTINEL_PROTECT_PROCESS \
    CTL_CODE(RUSTINEL_TYPE, 0x803, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/*
 * Bumped whenever any structure below changes shape.
 *
 * The driver refuses a policy whose version it does not recognise rather than
 * interpreting unknown bytes, so an agent and a driver from different builds
 * fail loudly instead of corrupting kernel memory.
 */
#define RUSTINEL_POLICY_VERSION 1

#define RUSTINEL_MAX_PROTECTED_PROCESSES 64
#define RUSTINEL_MAX_PROTECTED_KEYS      64
#define RUSTINEL_MAX_BLOCKED_IMAGES      256
#define RUSTINEL_MAX_PATH_CCH            260

/* What to do when a rule matches. */
typedef enum _RUSTINEL_DISPOSITION {
    /* Report only: the operation proceeds untouched. */
    RustinelDispositionAudit = 0,
    /*
     * Remove the dangerous rights from the handle and let the open succeed.
     *
     * Preferred over an outright denial for process handles: a caller that is
     * refused entirely knows it was blocked, whereas one handed a handle
     * without VM_READ often fails in a way indistinguishable from an ordinary
     * permissions problem.
     */
    RustinelDispositionStrip = 1,
    /* Fail the operation with STATUS_ACCESS_DENIED. */
    RustinelDispositionDeny = 2,
} RUSTINEL_DISPOSITION;

/*
 * A process whose handles are policed.
 *
 * Identified by both PID and start key: a PID alone is reused, and a policy
 * entry that outlives its process would police an unrelated one.
 */
typedef struct _RUSTINEL_PROTECTED_PROCESS {
    ULONG   ProcessId;
    ULONG64 StartKey;
    /* Rights to remove or refuse, e.g. PROCESS_VM_READ | PROCESS_VM_WRITE. */
    ACCESS_MASK DeniedAccess;
    ULONG   Disposition;
} RUSTINEL_PROTECTED_PROCESS, *PRUSTINEL_PROTECTED_PROCESS;

/*
 * A registry subtree that may not be written.
 *
 * Matched as a case-insensitive prefix against the kernel's own name for the
 * key, which is always the `\REGISTRY\MACHINE\...` form.
 */
typedef struct _RUSTINEL_PROTECTED_KEY {
    WCHAR   Prefix[RUSTINEL_MAX_PATH_CCH];
    ULONG   PrefixCch;
    ULONG   Disposition;
} RUSTINEL_PROTECTED_KEY, *PRUSTINEL_PROTECTED_KEY;

/* An image that may not be created, opened for write, or executed. */
typedef struct _RUSTINEL_BLOCKED_IMAGE {
    WCHAR   Path[RUSTINEL_MAX_PATH_CCH];
    ULONG   PathCch;
    ULONG   Disposition;
} RUSTINEL_BLOCKED_IMAGE, *PRUSTINEL_BLOCKED_IMAGE;

/*
 * The whole policy, replaced atomically.
 *
 * Sent as one buffer rather than incrementally so the driver never evaluates a
 * half-applied policy: the callbacks read the current table under a lock that
 * is only taken for the pointer swap.
 */
typedef struct _RUSTINEL_POLICY {
    ULONG   Version;
    ULONG   ProcessCount;
    ULONG   KeyCount;
    ULONG   ImageCount;
    /* PID of the agent, which is never policed and never blocked. */
    ULONG   AgentProcessId;
    RUSTINEL_PROTECTED_PROCESS Processes[RUSTINEL_MAX_PROTECTED_PROCESSES];
    RUSTINEL_PROTECTED_KEY     Keys[RUSTINEL_MAX_PROTECTED_KEYS];
    RUSTINEL_BLOCKED_IMAGE     Images[RUSTINEL_MAX_BLOCKED_IMAGES];
} RUSTINEL_POLICY, *PRUSTINEL_POLICY;

/* What the driver reports back about itself. */
typedef struct _RUSTINEL_STATE {
    ULONG   Version;
    /* Which callbacks actually registered. */
    BOOLEAN ObjectCallbacksActive;
    BOOLEAN RegistryCallbackActive;
    BOOLEAN MinifilterActive;
    /* Counters since load, for the agent's telemetry. */
    ULONG64 HandlesStripped;
    ULONG64 HandlesDenied;
    ULONG64 RegistryWritesDenied;
    ULONG64 FileOperationsDenied;
} RUSTINEL_STATE, *PRUSTINEL_STATE;
