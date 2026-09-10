/*
 * Rustinel kernel driver: process and thread lifecycle, and kernel-side kill.
 *
 * Two things live here that user mode cannot do.
 *
 * The first is denying a process its own creation. `PsSetCreateProcessNotifyRoutineEx`
 * is the only supported way to stop a process before its first instruction
 * runs: setting `CreationStatus` to a failure in the create notification makes
 * `CreateProcess` fail in the parent. The user-mode agent, seeing the same
 * event through ETW, is already too late; the child is running by the time the
 * event arrives, and killing it is a race the child sometimes wins.
 *
 * The second is `ZwTerminateProcess` from kernel mode, which succeeds against
 * targets `TerminateProcess` cannot touch: a protected-process-light target
 * refuses a user-mode handle outright.
 *
 * Thread creation is watched but never denied. There is no supported way to
 * refuse a thread, and the notification is a reporting channel: a thread whose
 * creating process differs from its owning process is the shape of injection,
 * and reporting it from here is more reliable than the ETW equivalent because
 * it cannot be lost to a full trace buffer.
 */

#include <ntifs.h>
#include <wdm.h>
#include "../include/rustinel_ioctl.h"

extern RUSTINEL_POLICY* g_Policy;
extern EX_SPIN_LOCK     g_PolicyLock;
extern RUSTINEL_STATE   g_State;

static BOOLEAN g_ProcessCallbackRegistered = FALSE;
static BOOLEAN g_ThreadCallbackRegistered = FALSE;

/*
 * Whether an image is on the blocked list.
 *
 * Compared case-insensitively against the tail of the path, so a policy naming
 * `\dropper.exe` matches wherever it was written. The kernel gives the path in
 * its own `\Device\HarddiskVolume3\...` form, which is why matching on a
 * suffix rather than on the whole string is the only thing that works without
 * a volume-name translation the agent would have to keep in sync.
 */
static BOOLEAN IsImageBlocked(
    _In_ const RUSTINEL_POLICY* Policy,
    _In_opt_ PCUNICODE_STRING ImageName,
    _Out_ PULONG Disposition)
{
    *Disposition = RustinelDispositionAudit;

    if (ImageName == NULL || ImageName->Buffer == NULL) {
        return FALSE;
    }

    for (ULONG i = 0; i < Policy->ImageCount; i++) {
        const RUSTINEL_BLOCKED_IMAGE* image = &Policy->Images[i];
        if (image->PathCch == 0 || image->PathCch > ImageName->Length / sizeof(WCHAR)) {
            continue;
        }

        UNICODE_STRING candidate;
        candidate.Buffer = ImageName->Buffer +
            (ImageName->Length / sizeof(WCHAR)) - image->PathCch;
        candidate.Length = (USHORT)(image->PathCch * sizeof(WCHAR));
        candidate.MaximumLength = candidate.Length;

        UNICODE_STRING blocked;
        blocked.Buffer = (PWCH)image->Path;
        blocked.Length = candidate.Length;
        blocked.MaximumLength = candidate.Length;

        if (RtlEqualUnicodeString(&blocked, &candidate, TRUE)) {
            *Disposition = image->Disposition;
            return TRUE;
        }
    }

    return FALSE;
}

/*
 * Process create and exit.
 *
 * The create half runs before the first instruction of the new process, in the
 * context of the creating thread, which is what makes refusing it possible at
 * all.
 */
static VOID CreateProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);

    /* Exit notification: nothing to decide. */
    if (CreateInfo == NULL) {
        return;
    }

    KIRQL irql = ExAcquireSpinLockShared(&g_PolicyLock);
    RUSTINEL_POLICY* policy = g_Policy;

    if (policy == NULL || policy->ImageCount == 0) {
        ExReleaseSpinLockShared(&g_PolicyLock, irql);
        return;
    }

    /*
     * The agent's own children are never blocked. It has to be able to run
     * whatever it runs, and a policy steerable into blocking them would be a
     * way to disable response through a detection.
     */
    if ((ULONG)(ULONG_PTR)PsGetCurrentProcessId() == policy->AgentProcessId) {
        ExReleaseSpinLockShared(&g_PolicyLock, irql);
        return;
    }

    ULONG disposition = RustinelDispositionAudit;
    BOOLEAN blocked = IsImageBlocked(policy, CreateInfo->ImageFileName, &disposition);
    ExReleaseSpinLockShared(&g_PolicyLock, irql);

    if (blocked && disposition == RustinelDispositionDeny) {
        /*
         * This is the whole point of the callback. The process never runs; the
         * parent's CreateProcess returns this status.
         */
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
    }
}

/*
 * Thread creation, reported rather than denied.
 *
 * A thread whose creator is not its owner is the shape of remote-thread
 * injection. Windows offers no way to refuse it, so this only counts; the
 * response to it is the agent terminating the creator, which the object
 * callback has usually already declawed by refusing the handle it needed.
 */
static VOID CreateThreadNotify(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ThreadId);

    if (!Create) {
        return;
    }

    /*
     * The owning process differing from the creating one is what makes this
     * interesting. Same-process thread creation is the overwhelming majority
     * and is ignored without touching the policy at all.
     */
    if (ProcessId == PsGetCurrentProcessId()) {
        return;
    }

    InterlockedIncrement64((LONG64*)&g_State.HandlesStripped);
}

/*
 * Terminate a process from kernel mode.
 *
 * Reaches targets `TerminateProcess` cannot: a protected-process-light process
 * refuses a user-mode handle with the rights needed to kill it, and returns
 * access-denied to the agent no matter how privileged it is.
 *
 * Critical processes are refused here rather than attempted, because
 * terminating one bugchecks the machine. That check belongs in the kernel: it
 * is the last place before the point of no return.
 */
NTSTATUS RustinelTerminateProcess(_In_ ULONG ProcessId, _In_ ULONG64 StartKey)
{
    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* The PID may have been reused since the agent decided. */
    if (PsGetProcessStartKey(process) != StartKey) {
        ObDereferenceObject(process);
        return STATUS_NOT_FOUND;
    }

    if (PsIsProcessCritical(process)) {
        ObDereferenceObject(process);
        return STATUS_ACCESS_DENIED;
    }

    HANDLE handle = NULL;
    status = ObOpenObjectByPointer(
        process,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_TERMINATE,
        *PsProcessType,
        KernelMode,
        &handle);

    if (NT_SUCCESS(status)) {
        status = ZwTerminateProcess(handle, STATUS_VIRUS_INFECTED);
        ZwClose(handle);
    }

    ObDereferenceObject(process);
    return status;
}

/* Register the lifecycle callbacks. */
NTSTATUS RustinelRegisterProcessCallbacks(VOID)
{
    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotify, FALSE);
    if (NT_SUCCESS(status)) {
        g_ProcessCallbackRegistered = TRUE;
    } else if (status == STATUS_ACCESS_DENIED) {
        /*
         * Same cause as the object callbacks: the image was not linked with
         * /INTEGRITYCHECK, or is not signed.
         */
        return status;
    }

    NTSTATUS threadStatus = PsSetCreateThreadNotifyRoutine(CreateThreadNotify);
    if (NT_SUCCESS(threadStatus)) {
        g_ThreadCallbackRegistered = TRUE;
    }

    return g_ProcessCallbackRegistered ? STATUS_SUCCESS : status;
}

/* Unregister them. Safe to call twice. */
VOID RustinelUnregisterProcessCallbacks(VOID)
{
    if (g_ProcessCallbackRegistered) {
        PsSetCreateProcessNotifyRoutineEx(CreateProcessNotify, TRUE);
        g_ProcessCallbackRegistered = FALSE;
    }

    if (g_ThreadCallbackRegistered) {
        PsRemoveCreateThreadNotifyRoutine(CreateThreadNotify);
        g_ThreadCallbackRegistered = FALSE;
    }
}
