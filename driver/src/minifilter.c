/*
 * Rustinel kernel driver: filesystem minifilter.
 *
 * The user-mode agent sees a file write through ETW after the bytes are on
 * disk. Against ransomware that is the difference between a report and a
 * defence: by the time the event arrives the file is encrypted, and the agent's
 * best move is to kill the encryptor and hope the rest of the directory
 * survives.
 *
 * A minifilter sees the write as an IRP, before it reaches the filesystem, and
 * can complete it with STATUS_ACCESS_DENIED. The write never happens.
 *
 * # What this filter denies
 *
 * Only what the policy names. There is no heuristic here and no rate counting:
 * the agent decides which process is encrypting and which paths must be
 * protected, and pushes that down. Ransomware heuristics belong where being
 * wrong costs a false positive rather than a bugcheck.
 *
 * # What it deliberately does not do
 *
 * It does not scan content. A minifilter that reads file data on the write path
 * doubles the cost of every write on the machine, and the same decision can be
 * made from the path and the writing process.
 */

#include <fltKernel.h>
#include "../include/rustinel_ioctl.h"

extern RUSTINEL_POLICY* g_Policy;
extern EX_SPIN_LOCK     g_PolicyLock;
extern RUSTINEL_STATE   g_State;

PFLT_FILTER g_FilterHandle = NULL;

/*
 * Whether a path is one the policy protects from writes.
 *
 * Matched as a case-insensitive suffix, for the same reason as the image list:
 * the filter sees `\Device\HarddiskVolume3\Users\...` and the agent knows
 * `C:\Users\...`, and translating between them in the kernel would need a
 * volume map the agent would have to keep current.
 */
static BOOLEAN IsProtectedPath(
    _In_ const RUSTINEL_POLICY* Policy,
    _In_ PCUNICODE_STRING Path,
    _Out_ PULONG Disposition)
{
    *Disposition = RustinelDispositionAudit;

    if (Path == NULL || Path->Buffer == NULL) {
        return FALSE;
    }

    for (ULONG i = 0; i < Policy->ImageCount; i++) {
        const RUSTINEL_BLOCKED_IMAGE* entry = &Policy->Images[i];
        if (entry->PathCch == 0 || entry->PathCch > Path->Length / sizeof(WCHAR)) {
            continue;
        }

        UNICODE_STRING candidate;
        candidate.Buffer = Path->Buffer + (Path->Length / sizeof(WCHAR)) - entry->PathCch;
        candidate.Length = (USHORT)(entry->PathCch * sizeof(WCHAR));
        candidate.MaximumLength = candidate.Length;

        UNICODE_STRING protected;
        protected.Buffer = (PWCH)entry->Path;
        protected.Length = candidate.Length;
        protected.MaximumLength = candidate.Length;

        if (RtlEqualUnicodeString(&protected, &candidate, TRUE)) {
            *Disposition = entry->Disposition;
            return TRUE;
        }
    }

    return FALSE;
}

/*
 * Pre-operation for write, create-for-write, and set-information.
 *
 * Set-information is here because it covers rename and delete, which is how
 * ransomware finishes: the original is renamed or removed after the encrypted
 * copy is written. A filter that only denies writes still loses the file.
 */
static FLT_PREOP_CALLBACK_STATUS PreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    /* Paged-pool work and name queries need PASSIVE_LEVEL. */
    if (!FLT_IS_IRP_OPERATION(Data) || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    KIRQL irql = ExAcquireSpinLockShared(&g_PolicyLock);
    RUSTINEL_POLICY* policy = g_Policy;
    BOOLEAN nothingToDo = (policy == NULL || policy->ImageCount == 0);
    ULONG agentPid = nothingToDo ? 0 : policy->AgentProcessId;
    ExReleaseSpinLockShared(&g_PolicyLock, irql);

    if (nothingToDo) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* The agent writes quarantine files; it is never denied. */
    if ((ULONG)(ULONG_PTR)PsGetCurrentProcessId() == agentPid) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status)) {
        /* Fail open: a name we cannot read is not grounds for denying I/O. */
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FltParseFileNameInformation(nameInfo);

    ULONG disposition = RustinelDispositionAudit;
    BOOLEAN protectedPath = FALSE;

    irql = ExAcquireSpinLockShared(&g_PolicyLock);
    if (g_Policy != NULL) {
        protectedPath = IsProtectedPath(g_Policy, &nameInfo->Name, &disposition);
    }
    ExReleaseSpinLockShared(&g_PolicyLock, irql);

    FltReleaseFileNameInformation(nameInfo);

    if (!protectedPath || disposition != RustinelDispositionDeny) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /*
     * Completing the IRP here is the denial. The filesystem never sees it and
     * the caller gets access-denied from its own write.
     */
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    InterlockedIncrement64((LONG64*)&g_State.FileOperationsDenied);
    return FLT_PREOP_COMPLETE;
}

static NTSTATUS FilterUnloadCallback(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    if (g_FilterHandle != NULL) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        g_State.MinifilterActive = FALSE;
    }

    return STATUS_SUCCESS;
}

/* The operations this filter attaches to. */
static const FLT_OPERATION_REGISTRATION g_Callbacks[] = {
    { IRP_MJ_CREATE,          0, PreOperation, NULL },
    { IRP_MJ_WRITE,           0, PreOperation, NULL },
    { IRP_MJ_SET_INFORMATION, 0, PreOperation, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    g_Callbacks,
    FilterUnloadCallback,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

/*
 * Register and start filtering.
 *
 * The altitude comes from the INF rather than from here; a minifilter without
 * one in its service key fails to register, which is the usual reason a
 * hand-installed filter driver loads and then does nothing.
 */
NTSTATUS RustinelRegisterMinifilter(_In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status = FltRegisterFilter(DriverObject, &g_FilterRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        return status;
    }

    g_State.MinifilterActive = TRUE;
    return STATUS_SUCCESS;
}

VOID RustinelUnregisterMinifilter(VOID)
{
    if (g_FilterHandle != NULL) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        g_State.MinifilterActive = FALSE;
    }
}
