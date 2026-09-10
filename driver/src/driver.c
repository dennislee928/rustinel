/*
 * Rustinel kernel driver: entry point, device, and policy plumbing.
 *
 * The driver is deliberately small and stupid. It holds no rules, no
 * correlation, and no notion of what is malicious; it holds a table of
 * processes, keys, and images, and it enforces that table in the three
 * pre-operation callbacks. Everything that decides *what* goes in the table
 * lives in the user-mode agent, where it can be reloaded, tested, and got
 * wrong without bugchecking the machine.
 *
 * That split is the whole design. Kernel code that can be wrong in an
 * interesting way is kernel code that can take the machine down, so the
 * interesting part stays in user mode.
 */

#include <ntifs.h>
#include <wdm.h>
#include "../include/rustinel_ioctl.h"

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD RustinelUnload;

__drv_dispatchType(IRP_MJ_CREATE) DRIVER_DISPATCH RustinelCreateClose;
__drv_dispatchType(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH RustinelDeviceControl;

NTSTATUS RustinelRegisterCallbacks(_In_ PDRIVER_OBJECT DriverObject);
VOID RustinelUnregisterCallbacks(VOID);
NTSTATUS RustinelRegisterProcessCallbacks(VOID);
VOID RustinelUnregisterProcessCallbacks(VOID);
NTSTATUS RustinelRegisterMinifilter(_In_ PDRIVER_OBJECT DriverObject);
VOID RustinelUnregisterMinifilter(VOID);
NTSTATUS RustinelTerminateProcess(_In_ ULONG ProcessId, _In_ ULONG64 StartKey);

/* The live policy. Swapped wholesale; never edited in place. */
RUSTINEL_POLICY* g_Policy = NULL;
EX_SPIN_LOCK     g_PolicyLock = 0;
RUSTINEL_STATE   g_State = { 0 };

static PDEVICE_OBJECT g_DeviceObject = NULL;

#define RUSTINEL_POOL_TAG 'ntsR'

/*
 * Replace the policy.
 *
 * The new table is built completely before the swap, so a callback firing
 * during the update sees either the whole old policy or the whole new one and
 * never a half-written mixture. The old table is freed after the swap, once no
 * reader can still be holding it: the exclusive lock guarantees that, because
 * readers take it shared for the pointer copy alone.
 */
static NTSTATUS ApplyPolicy(_In_ const RUSTINEL_POLICY* Incoming)
{
    if (Incoming->Version != RUSTINEL_POLICY_VERSION) {
        return STATUS_REVISION_MISMATCH;
    }
    if (Incoming->ProcessCount > RUSTINEL_MAX_PROTECTED_PROCESSES ||
        Incoming->KeyCount > RUSTINEL_MAX_PROTECTED_KEYS ||
        Incoming->ImageCount > RUSTINEL_MAX_BLOCKED_IMAGES) {
        return STATUS_INVALID_PARAMETER;
    }

    RUSTINEL_POLICY* fresh = (RUSTINEL_POLICY*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(RUSTINEL_POLICY), RUSTINEL_POOL_TAG);
    if (fresh == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(fresh, Incoming, sizeof(RUSTINEL_POLICY));

    /*
     * Every string is terminated here rather than trusting the sender. A
     * non-terminated string from user mode is how a prefix comparison walks
     * off the end of the buffer.
     */
    for (ULONG i = 0; i < fresh->KeyCount; i++) {
        if (fresh->Keys[i].PrefixCch >= RUSTINEL_MAX_PATH_CCH) {
            fresh->Keys[i].PrefixCch = RUSTINEL_MAX_PATH_CCH - 1;
        }
        fresh->Keys[i].Prefix[fresh->Keys[i].PrefixCch] = L'\0';
    }
    for (ULONG i = 0; i < fresh->ImageCount; i++) {
        if (fresh->Images[i].PathCch >= RUSTINEL_MAX_PATH_CCH) {
            fresh->Images[i].PathCch = RUSTINEL_MAX_PATH_CCH - 1;
        }
        fresh->Images[i].Path[fresh->Images[i].PathCch] = L'\0';
    }

    KIRQL irql = ExAcquireSpinLockExclusive(&g_PolicyLock);
    RUSTINEL_POLICY* old = g_Policy;
    g_Policy = fresh;
    ExReleaseSpinLockExclusive(&g_PolicyLock, irql);

    if (old != NULL) {
        ExFreePoolWithTag(old, RUSTINEL_POOL_TAG);
    }

    return STATUS_SUCCESS;
}

static VOID ClearPolicy(VOID)
{
    KIRQL irql = ExAcquireSpinLockExclusive(&g_PolicyLock);
    RUSTINEL_POLICY* old = g_Policy;
    g_Policy = NULL;
    ExReleaseSpinLockExclusive(&g_PolicyLock, irql);

    if (old != NULL) {
        ExFreePoolWithTag(old, RUSTINEL_POOL_TAG);
    }
}

NTSTATUS RustinelCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS RustinelDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (code) {
    case IOCTL_RUSTINEL_SET_POLICY:
        /*
         * METHOD_BUFFERED, so the buffer is already a kernel copy and cannot
         * change under us. The length still has to be checked: a short buffer
         * accepted here reads uninitialised pool.
         */
        if (inputLength < sizeof(RUSTINEL_POLICY)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = ApplyPolicy((const RUSTINEL_POLICY*)Irp->AssociatedIrp.SystemBuffer);
        break;

    case IOCTL_RUSTINEL_PROTECT_PROCESS: {
        /*
         * Terminate from kernel mode. Reaches protected-process targets that
         * refuse the agent a user-mode handle, and refuses critical processes
         * rather than bugchecking the machine.
         */
        if (inputLength < sizeof(RUSTINEL_PROTECTED_PROCESS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        const RUSTINEL_PROTECTED_PROCESS* target =
            (const RUSTINEL_PROTECTED_PROCESS*)Irp->AssociatedIrp.SystemBuffer;
        status = RustinelTerminateProcess(target->ProcessId, target->StartKey);
        break;
    }

    case IOCTL_RUSTINEL_CLEAR_POLICY:
        ClearPolicy();
        status = STATUS_SUCCESS;
        break;

    case IOCTL_RUSTINEL_QUERY_STATE:
        if (outputLength < sizeof(RUSTINEL_STATE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        g_State.Version = RUSTINEL_POLICY_VERSION;
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &g_State, sizeof(RUSTINEL_STATE));
        information = sizeof(RUSTINEL_STATE);
        status = STATUS_SUCCESS;
        break;

    default:
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID RustinelUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    /*
     * Callbacks first. A policy freed while a callback is still registered is
     * a use-after-free on the next handle open, and unregistering waits for
     * in-flight callbacks to finish.
     */
    RustinelUnregisterMinifilter();
    RustinelUnregisterProcessCallbacks();
    RustinelUnregisterCallbacks();
    ClearPolicy();

    if (g_DeviceObject != NULL) {
        UNICODE_STRING symlink;
        RtlInitUnicodeString(&symlink, RUSTINEL_SYMLINK_NAME);
        IoDeleteSymbolicLink(&symlink);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING deviceName;
    UNICODE_STRING symlinkName;
    NTSTATUS status;

    RtlInitUnicodeString(&deviceName, RUSTINEL_DEVICE_NAME);
    RtlInitUnicodeString(&symlinkName, RUSTINEL_SYMLINK_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = RustinelCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = RustinelCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = RustinelDeviceControl;
    DriverObject->DriverUnload = RustinelUnload;

    status = RustinelRegisterCallbacks(DriverObject);
    if (NT_SUCCESS(status)) {
        /*
         * Neither of these is fatal on its own. A driver with the object
         * callbacks but no minifilter still denies handles, and saying which
         * registered is what `IOCTL_RUSTINEL_QUERY_STATE` is for.
         */
        RustinelRegisterProcessCallbacks();
        RustinelRegisterMinifilter(DriverObject);
    }
    if (!NT_SUCCESS(status)) {
        /*
         * Almost always STATUS_ACCESS_DENIED from ObRegisterCallbacks on a
         * driver that was not linked with /INTEGRITYCHECK or not signed. The
         * device is torn down rather than left loaded doing nothing.
         */
        RustinelUnload(DriverObject);
        return status;
    }

    return STATUS_SUCCESS;
}
