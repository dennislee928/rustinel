/*
 * Rustinel kernel driver: the three pre-operation callbacks.
 *
 * These are the operations Windows lets a driver refuse while they are
 * happening, which is the whole reason the driver exists. Everything the
 * user-mode agent does is after the fact; everything here is instead of.
 *
 * # Rules every callback in this file obeys
 *
 * 1. **Never block.** A pre-operation callback runs on the thread performing
 *    the operation. Waiting on anything here stalls that thread, and waiting on
 *    the user-mode agent would deadlock the moment the agent is the caller.
 *    Decisions are made against the in-memory policy table and nothing else.
 *
 * 2. **Never allocate on the decision path.** Allocation can fail, and a
 *    failure here has nowhere to go. The policy table is fixed-size and
 *    pre-allocated for exactly this reason.
 *
 * 3. **Fail open, not closed.** If the policy cannot be read, the operation is
 *    allowed. A driver that denies operations when confused takes the machine
 *    down, which is a worse outcome than a missed block.
 *
 * 4. **Never police the agent or the kernel.** A policy that can be steered
 *    into denying the agent its own handles is a self-inflicted outage, and one
 *    that touches System or the memory manager is a bugcheck.
 */

#include <ntifs.h>
#include <wdm.h>
#include "../include/rustinel_ioctl.h"

extern RUSTINEL_POLICY* g_Policy;
extern EX_SPIN_LOCK     g_PolicyLock;
extern RUSTINEL_STATE   g_State;

/* Handle registration returned by ObRegisterCallbacks, for teardown. */
PVOID g_ObHandle = NULL;
/* Cookie returned by CmRegisterCallbackEx, for teardown. */
LARGE_INTEGER g_CmCookie = { 0 };

/*
 * Take a read reference to the policy.
 *
 * The table is swapped wholesale under the lock, so a reader holds the shared
 * lock only long enough to copy the pointer. Callbacks run at PASSIVE_LEVEL
 * for registry and APC_LEVEL or below for objects, so a spin lock at DISPATCH
 * is safe and short.
 */
static RUSTINEL_POLICY* AcquirePolicy(KIRQL* OldIrql)
{
    RUSTINEL_POLICY* policy;

    *OldIrql = ExAcquireSpinLockShared(&g_PolicyLock);
    policy = g_Policy;
    return policy;
}

static VOID ReleasePolicy(KIRQL OldIrql)
{
    ExReleaseSpinLockShared(&g_PolicyLock, OldIrql);
}

/*
 * Whether this process is one the policy protects.
 *
 * Matched on PID *and* start key. A PID on its own is recycled, and a stale
 * entry matching a reused PID would police an innocent process.
 */
static const RUSTINEL_PROTECTED_PROCESS* FindProtectedProcess(
    _In_ const RUSTINEL_POLICY* Policy,
    _In_ PEPROCESS Process)
{
    ULONG64 startKey = PsGetProcessStartKey(Process);
    ULONG pid = (ULONG)(ULONG_PTR)PsGetProcessId(Process);

    for (ULONG i = 0; i < Policy->ProcessCount; i++) {
        const RUSTINEL_PROTECTED_PROCESS* entry = &Policy->Processes[i];
        if (entry->ProcessId == pid && entry->StartKey == startKey) {
            return entry;
        }
    }

    return NULL;
}

/*
 * Object manager pre-operation: police handles to protected processes.
 *
 * This is what stops credential dumping while it is happening. A process
 * asking for a handle to `lsass.exe` with PROCESS_VM_READ is the operation
 * that matters, and here it can be refused or, better, granted a handle that
 * simply does not carry the right.
 *
 * Stripping is preferred over denying: a caller refused outright learns it was
 * blocked and can adapt, whereas one handed a handle whose later
 * ReadProcessMemory fails sees something that looks like an ordinary
 * permissions problem.
 */
static OB_PREOP_CALLBACK_STATUS PreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION Info)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    /* A handle the kernel takes for itself is never ours to police. */
    if (Info->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    if (Info->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS target = (PEPROCESS)Info->Object;
    PEPROCESS caller = PsGetCurrentProcess();

    /* A process opening itself is routine and is never interfered with. */
    if (target == caller) {
        return OB_PREOP_SUCCESS;
    }

    KIRQL irql;
    RUSTINEL_POLICY* policy = AcquirePolicy(&irql);
    if (policy == NULL) {
        ReleasePolicy(irql);
        return OB_PREOP_SUCCESS;
    }

    ULONG callerPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    /*
     * The agent is exempt. It has to be able to open the processes it is
     * about to terminate, and a policy that can be steered into blocking it
     * would disarm the response engine entirely.
     */
    if (callerPid == policy->AgentProcessId) {
        ReleasePolicy(irql);
        return OB_PREOP_SUCCESS;
    }

    const RUSTINEL_PROTECTED_PROCESS* entry = FindProtectedProcess(policy, target);
    if (entry == NULL) {
        ReleasePolicy(irql);
        return OB_PREOP_SUCCESS;
    }

    ACCESS_MASK denied = entry->DeniedAccess;
    ULONG disposition = entry->Disposition;
    ReleasePolicy(irql);

    if (disposition == RustinelDispositionAudit) {
        return OB_PREOP_SUCCESS;
    }

    /*
     * Create and duplicate carry the requested rights in different fields;
     * both have to be handled or a duplicate becomes a way around the create.
     */
    ACCESS_MASK* requested =
        (Info->Operation == OB_OPERATION_HANDLE_CREATE)
            ? &Info->Parameters->CreateHandleInformation.DesiredAccess
            : &Info->Parameters->DuplicateHandleInformation.DesiredAccess;

    if ((*requested & denied) == 0) {
        return OB_PREOP_SUCCESS;
    }

    if (disposition == RustinelDispositionDeny) {
        /*
         * There is no way to fail the open from here; removing every right
         * yields a handle that can do nothing, which is the closest the
         * object manager allows.
         */
        *requested = 0;
        InterlockedIncrement64((LONG64*)&g_State.HandlesDenied);
    } else {
        *requested &= ~denied;
        InterlockedIncrement64((LONG64*)&g_State.HandlesStripped);
    }

    return OB_PREOP_SUCCESS;
}

/*
 * Configuration manager callback: refuse writes to protected keys.
 *
 * This is the one that stops persistence rather than reporting it. A Run key
 * write refused here never existed; the same write caught by the user-mode
 * agent existed for as long as it took the event to arrive, and survives if
 * the machine reboots inside that window.
 *
 * Only value writes and deletions are policed. Reads are left alone: they are
 * enormously more frequent and blocking one breaks software without stopping
 * an attack.
 */
static NTSTATUS RegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);

    if (Argument2 == NULL) {
        return STATUS_SUCCESS;
    }

    REG_NOTIFY_CLASS operation = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    PVOID object = NULL;
    switch (operation) {
    case RegNtPreSetValueKey:
        object = ((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->Object;
        break;
    case RegNtPreDeleteValueKey:
        object = ((PREG_DELETE_VALUE_KEY_INFORMATION)Argument2)->Object;
        break;
    case RegNtPreCreateKeyEx:
    case RegNtPreDeleteKey:
        object = ((PREG_DELETE_KEY_INFORMATION)Argument2)->Object;
        break;
    default:
        return STATUS_SUCCESS;
    }

    if (object == NULL) {
        return STATUS_SUCCESS;
    }

    KIRQL irql;
    RUSTINEL_POLICY* policy = AcquirePolicy(&irql);
    if (policy == NULL || policy->KeyCount == 0) {
        ReleasePolicy(irql);
        return STATUS_SUCCESS;
    }

    if ((ULONG)(ULONG_PTR)PsGetCurrentProcessId() == policy->AgentProcessId) {
        ReleasePolicy(irql);
        return STATUS_SUCCESS;
    }
    ReleasePolicy(irql);

    /*
     * The key's name has to be asked for, and asking allocates, which cannot
     * happen above PASSIVE_LEVEL. Registry callbacks are documented to run at
     * PASSIVE_LEVEL, but the check is cheap and the alternative is a bugcheck.
     */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_SUCCESS;
    }

    PCUNICODE_STRING name = NULL;
    NTSTATUS status = CmCallbackGetKeyObjectIDEx(&g_CmCookie, object, NULL, &name, 0);
    if (!NT_SUCCESS(status) || name == NULL) {
        return STATUS_SUCCESS;
    }

    NTSTATUS result = STATUS_SUCCESS;

    policy = AcquirePolicy(&irql);
    if (policy != NULL) {
        for (ULONG i = 0; i < policy->KeyCount; i++) {
            const RUSTINEL_PROTECTED_KEY* key = &policy->Keys[i];
            if (key->Disposition == RustinelDispositionAudit) {
                continue;
            }
            if (name->Length / sizeof(WCHAR) < key->PrefixCch) {
                continue;
            }

            UNICODE_STRING prefix;
            prefix.Buffer = (PWCH)key->Prefix;
            prefix.Length = (USHORT)(key->PrefixCch * sizeof(WCHAR));
            prefix.MaximumLength = prefix.Length;

            UNICODE_STRING candidate;
            candidate.Buffer = name->Buffer;
            candidate.Length = prefix.Length;
            candidate.MaximumLength = prefix.Length;

            if (RtlEqualUnicodeString(&prefix, &candidate, TRUE)) {
                result = STATUS_ACCESS_DENIED;
                InterlockedIncrement64((LONG64*)&g_State.RegistryWritesDenied);
                break;
            }
        }
    }
    ReleasePolicy(irql);

    CmCallbackReleaseKeyObjectIDEx(name);
    return result;
}

/*
 * Register both callbacks.
 *
 * `ObRegisterCallbacks` requires the driver image to carry the
 * `/INTEGRITYCHECK` link flag and to be signed; a driver missing either gets
 * STATUS_ACCESS_DENIED here and nowhere else, which is the single most common
 * reason this function fails on a development machine.
 */
NTSTATUS RustinelRegisterCallbacks(_In_ PDRIVER_OBJECT DriverObject)
{
    OB_OPERATION_REGISTRATION operations[1];
    OB_CALLBACK_REGISTRATION registration;
    UNICODE_STRING altitude;

    RtlZeroMemory(operations, sizeof(operations));
    operations[0].ObjectType = PsProcessType;
    operations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[0].PreOperation = PreOperationCallback;
    operations[0].PostOperation = NULL;

    RtlInitUnicodeString(&altitude, RUSTINEL_ALTITUDE);

    RtlZeroMemory(&registration, sizeof(registration));
    registration.Version = OB_FLT_REGISTRATION_VERSION;
    registration.OperationRegistrationCount = 1;
    registration.Altitude = altitude;
    registration.RegistrationContext = NULL;
    registration.OperationRegistration = operations;

    NTSTATUS status = ObRegisterCallbacks(&registration, &g_ObHandle);
    if (NT_SUCCESS(status)) {
        g_State.ObjectCallbacksActive = TRUE;
    } else {
        g_ObHandle = NULL;
    }

    NTSTATUS cmStatus = CmRegisterCallbackEx(
        RegistryCallback,
        &altitude,
        DriverObject,
        NULL,
        &g_CmCookie,
        NULL);
    if (NT_SUCCESS(cmStatus)) {
        g_State.RegistryCallbackActive = TRUE;
    }

    /*
     * A driver that registered neither callback is doing nothing and should
     * not stay loaded pretending otherwise.
     */
    if (!g_State.ObjectCallbacksActive && !g_State.RegistryCallbackActive) {
        return NT_SUCCESS(status) ? cmStatus : status;
    }

    return STATUS_SUCCESS;
}

/* Unregister everything registered above. Safe to call twice. */
VOID RustinelUnregisterCallbacks(VOID)
{
    if (g_ObHandle != NULL) {
        ObUnRegisterCallbacks(g_ObHandle);
        g_ObHandle = NULL;
        g_State.ObjectCallbacksActive = FALSE;
    }

    if (g_State.RegistryCallbackActive) {
        CmUnRegisterCallback(g_CmCookie);
        g_State.RegistryCallbackActive = FALSE;
    }
}
