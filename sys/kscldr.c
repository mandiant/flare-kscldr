#include <ntddk.h>
#include <wdmsec.h>
#include <Initguid.h>

#pragma intrinsic(__debugbreak)

#include "kscldr.h"
#include "config.h"

#define PDEBUG(_s, ...)                             DbgPrint(LBL # _s, \
                                                        __VA_ARGS__)

#define DEVICE_NAME                                 L"\\Device\\kscldr"
#define LBL                                         "[kscldr] "
#define TAG                                         'lcsk'

#define BUF_DEFAULT_VALUE                           "\xc3"
#define BUF_DEFAULT_LENGTH                          1
#define SCLDR_DEFAULT_MAX_LENGTH                    0x100000

// {114587DA-AC71-4408-BF5C-B7136CF9BE28} for IoCreateDeviceSecure
DEFINE_GUID(KSCLDR_CLASS_GUID, 
0x114587da, 0xac71, 0x4408, 0xbf, 0x5c, 0xb7, 0x13, 0x6c, 0xf9, 0xbe, 0x28);

/**
 * Device extension structure.
 *
 * mutex - Note that specifying Exclusive access to the device object only
 *      guarantees that one handle can be opened, but the documentation for
 *      IoCreateDeviceSecure and for Specifying Exclusive Access to Device
 *      Objects do not expressly indicate that the I/O Manager serializes IRPs
 *      to this device. It follows that multiple threads in a given process
 *      could conceivably affinitize across CPUs and issue simultaneous I/O
 *      requests using the same handle (e.g. calling WriteFile repeatedly with
 *      a non-NULL lpOverlapped argument).
 * do_break - Enable/disable breakpoint before calling shellcode (depending on
 *      the disposition of the compile-time setting CFG_EN_ENFORCE_BREAKPOINT).
 * max_len - Sanity check to prevent unintentionally consuming nonpaged pool
 *      with large files that are not actually shellcode. Can be overridden via
 *      IOCTL_kscldr_setmaxlength if the user really means to load such a large
 *      file into nonpaged pool.
 * len - Current shellcode buffer length.
 * buf - Shellcode buffer.
 */
struct ScldrDevExt {
    FAST_MUTEX mutex;
    BOOLEAN do_break;
    ULONG max_len;
    ULONG len;
    PUCHAR buf;
};

typedef void (*fptr_sc_t)(void);

DRIVER_UNLOAD Unload;
DRIVER_DISPATCH scldrCreateClose;
DRIVER_DISPATCH scldrWrite;
DRIVER_DISPATCH scldrDeviceControl;

NTSTATUS scldrDevExtInit(struct ScldrDevExt *dev_ext);
NTSTATUS scldrDevExtDestroy(struct ScldrDevExt *dev_ext);
NTSTATUS scldrDevExtSetBuf(
    struct ScldrDevExt *dev_ext,
    const char *buf,
    ULONG len
   );
NTSTATUS scldrDevExtSetBufUnsafe(
    struct ScldrDevExt *dev_ext,
    const char *buf,
    ULONG len
   );

UNICODE_STRING g_dev_name;
UNICODE_STRING g_link_name;

/**
 * Register IRP dispatch routines, create device object and configure for
 * buffered I/O, initialize device extension, and create symlink.
 *
 * IRQL constrained by e.g. IoCreateDeviceSecure, but DriverEntry will always
 * be called at PASSIVE_LEVEL.
 *
 * @return
 *      STATUS_SUCCESS if successful;
 *      STATUS_UNSUCCESSFUL if unexpected error;
 *      Other if a callee returns failure.
 */
NTSTATUS
DriverEntry (
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
    )
{
    PDEVICE_OBJECT dev_obj = NULL;
    NTSTATUS nts = STATUS_UNSUCCESSFUL;
    struct ScldrDevExt *dev_ext = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);

    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    PDEBUG("Loading\n");

    DriverObject->DriverUnload = Unload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = scldrCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = scldrCreateClose;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = scldrWrite;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = scldrDeviceControl;

    RtlInitUnicodeString(&g_dev_name, DEVICE_NAME);
    RtlInitUnicodeString(&g_link_name, KSCLDR_LINK_NAME_W);

    nts = IoCreateDeviceSecure(
        DriverObject,
        sizeof(struct ScldrDevExt),
        &g_dev_name,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        TRUE,
        &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
        (struct _GUID *)&KSCLDR_CLASS_GUID,
        &dev_obj
       );
    if (!NT_SUCCESS(nts))
    {
        goto exit_DriverEntry;
    }

    dev_obj->Flags |= DO_BUFFERED_IO;
    dev_ext = (struct ScldrDevExt *)dev_obj->DeviceExtension;
    if (NULL == dev_ext)
    {
        goto exit_DriverEntry;
    }

    scldrDevExtInit(dev_ext);
    if (!NT_SUCCESS(nts))
    {
        goto exit_DriverEntry;
    }

    nts = scldrDevExtSetBuf(dev_ext, BUF_DEFAULT_VALUE, BUF_DEFAULT_LENGTH);
    if (!NT_SUCCESS(nts))
    {
        goto exit_DriverEntry;
    }

    nts = IoCreateSymbolicLink(&g_link_name, &g_dev_name);
    if (!NT_SUCCESS(nts))
    {
        goto exit_DriverEntry;
    }

exit_DriverEntry:
    if (!NT_SUCCESS(nts))
    {
        PDEBUG("Loading failed\n");
        if (dev_obj)
        {
            IoDeleteDevice(dev_obj);
        }
    }
    else
    {
        PDEBUG("Successfully loaded\n");
    }

    return nts;
}

/**
 * Destroy device extension, symlink, and device object for driver unload.
 *
 * IRQL is constrained by e.g. IoDeleteSymbolicLink, but DriverUnload will
 * always be called at PASSIVE_LEVEL.
 */
VOID
Unload(
    __in PDRIVER_OBJECT DriverObject
   )
{
    PDEVICE_OBJECT dev_obj = NULL;
    struct ScldrDevExt *dev_ext = NULL;
    NTSTATUS nts = STATUS_UNSUCCESSFUL;

    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    dev_obj = DriverObject->DeviceObject;
    dev_ext = (struct ScldrDevExt *)dev_obj->DeviceExtension;
    if (dev_ext)
    {
        nts = scldrDevExtDestroy(dev_ext);
        if (!NT_SUCCESS(nts))
        {
            PDEBUG("scldrDevExtDestroy returned %d", nts);
        }
    }
    IoDeleteSymbolicLink(&g_link_name);
    IoDeleteDevice(dev_obj);

    PDEBUG("Unloaded\n");
}

/**
 * IRQL is constrained by IoCompleteRequest, but dispatch routines will always
 * be called at PASSIVE_LEVEL.
 *
 * @return STATUS_SUCCESS.
 */
NTSTATUS
scldrCreateClose(
    __inout PDEVICE_OBJECT DeviceObject,
    __inout PIRP Irp
)
{
    NTSTATUS nts = STATUS_SUCCESS;
    PIO_STACK_LOCATION io_stack = NULL;
    PCHAR op_create = "Create";
    PCHAR op_close = "Close";
    PCHAR which = "Unanticipated";

    UNREFERENCED_PARAMETER(DeviceObject);

    ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);

    io_stack = IoGetCurrentIrpStackLocation(Irp);

    switch (io_stack->MajorFunction) {
        case IRP_MJ_CREATE:
            which = op_create;
            break;
        case IRP_MJ_CLOSE:
            which = op_close;
            break;
        default:
            break;
    }

    PDEBUG(
        "scldrCreateClose: %s operation %d\n",
        which,
        io_stack->MajorFunction
       );

    Irp->IoStatus.Status = nts;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return nts;
}

/**
 * Write shellcode to buffer.
 *
 * IRQL is constrained by the FAST_MUTEX, but dispatch routines will always be
 * called at PASSIVE_LEVEL.
 *
 * @return
 *      STATUS_SUCCESS if successful;
 *      STATUS_INVALID_DEVICE_STATE if device extension is null;
 *      STATUS_BUFFER_OVERFLOW if user buffer exceeds maximum shellcode length;
 *      STATUS_UNSUCCESSFUL if unexpected error;
 *      Other if a callee returns failure.
 */
NTSTATUS
scldrWrite(
    __inout PDEVICE_OBJECT DeviceObject,
    __inout PIRP Irp
)
{
    NTSTATUS nts = STATUS_UNSUCCESSFUL;
    ULONG len = 0;
    PVOID src = NULL;
    PIO_STACK_LOCATION io_stack = NULL;
    struct ScldrDevExt *dev_ext = NULL;
    BOOLEAN took_mutex = FALSE;

    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    io_stack = IoGetCurrentIrpStackLocation(Irp);

    len = io_stack->Parameters.Write.Length;

    PDEBUG("scldrWrite(%d)\n", len);

    // Assume failure
    Irp->IoStatus.Information = 0;

    dev_ext = (struct ScldrDevExt *)DeviceObject->DeviceExtension;
    if (NULL == dev_ext)
    {
        len = 0;
        nts = STATUS_INVALID_DEVICE_STATE;
        goto exit_scldrWrite;
    }

    ExAcquireFastMutex(&dev_ext->mutex);
    took_mutex = TRUE;

    if (len > dev_ext->max_len)
    {
        nts = STATUS_BUFFER_OVERFLOW;
        len = 0;
    }
    else
    {
        if (!len)
        {
            if (dev_ext->buf)
            {
                ExFreePoolWithTag(dev_ext->buf, TAG);
                dev_ext->buf = NULL;
                dev_ext->len = 0;
            }
        }
        else
        {
            src = Irp->AssociatedIrp.SystemBuffer;
            nts = scldrDevExtSetBufUnsafe(dev_ext, (PUCHAR)src, len);
        }
    }

exit_scldrWrite:
    if (took_mutex)
    {
        ExReleaseFastMutex(&dev_ext->mutex);
    }

    Irp->IoStatus.Information = len;
    Irp->IoStatus.Status = nts;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return nts;
}

/**
 * Service the following IOCTLs:
 *      IOCTL_kscldr_setbreakpointdisposition: set/clear pre-call breakpoint;
 *      IOCTL_kscldr_setmaxlength: set shellcode buffer maximum length;
 *      IOCTL_kscldr_callsc: call shellcode at APC_LEVEL with optional offset.
 *
 * IRQL is constrained by the FAST_MUTEX, but dispatch routines will always be
 * called at PASSIVE_LEVEL.
 *
 * @return
 *      STATUS_SUCCESS if successful;
 *      STATUS_INVALID_DEVICE_STATE if device extension is null;
 *      STATUS_INVALID_BUFFER_SIZE if a user parameter is the wrong size;
 *      STATUS_BUFFER_OVERFLOW if invalid shellcode offset specified or no
 *          shellcode present;
 *      STATUS_UNSUCCESSFUL if unexpected error;
 *      Other if a callee returns failure.
 */
NTSTATUS
scldrDeviceControl(
    __inout PDEVICE_OBJECT DeviceObject,
    __inout PIRP Irp
)
{
    NTSTATUS nts = STATUS_UNSUCCESSFUL;
    ULONG input_len = 0;
    PVOID src = NULL;
    PIO_STACK_LOCATION io_stack = NULL;
    struct ScldrDevExt *dev_ext = NULL;
    ULONG sc_offset = 0;
    ULONG ioctl = 0;
    fptr_sc_t fptr_sc = NULL;
    BOOLEAN took_mutex = FALSE;

    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    io_stack = IoGetCurrentIrpStackLocation(Irp);

    src = Irp->AssociatedIrp.SystemBuffer;
    input_len = io_stack->Parameters.DeviceIoControl.InputBufferLength;

    ioctl = io_stack->Parameters.DeviceIoControl.IoControlCode;
    PDEBUG("DeviceIoControl(%d)...\n", ioctl);

    Irp->IoStatus.Information = 0;

    dev_ext = (struct ScldrDevExt *)DeviceObject->DeviceExtension;
    if (NULL == dev_ext)
    {
        nts = STATUS_INVALID_DEVICE_STATE;
        goto exit_scldrDeviceControl;
    }

    ExAcquireFastMutex(&dev_ext->mutex);
    took_mutex = TRUE;

    switch (ioctl) {

        case IOCTL_kscldr_setbreakpointdisposition:
        {
            if (input_len != sizeof(ULONG))
            {
                nts = STATUS_INVALID_BUFFER_SIZE;
            }
            else
            {
#if CFG_EN_ENFORCE_BREAKPOINT
                if (*(BOOLEAN *)src)
                {
                    PDEBUG("DeviceIoControl("
                        "IOCTL_kscldr_setbreakpointdisposition):"
                        "Breakpoint cannot be disabled in this release\n");
                }
#else
                dev_ext->do_break = *(BOOLEAN *)src;
#endif // CFG_EN_ENFORCE_BREAKPOINT
                nts = STATUS_SUCCESS;
            }
            break;

        }

        case IOCTL_kscldr_setmaxlength:
        {
            if (input_len != sizeof(ULONG))
            {
                nts = STATUS_INVALID_BUFFER_SIZE;
            }
            else
            {
                // Only affects future writes
                dev_ext->max_len = *(ULONG *)src;
                nts = STATUS_SUCCESS;
            }
            break;
        }

        case IOCTL_kscldr_callsc:
        {
            if (NULL == dev_ext->buf)
            {
                nts = STATUS_BUFFER_OVERFLOW;
            }
            else if ((input_len != 0) && (input_len != sizeof(ULONG)))
            {
                nts = STATUS_INVALID_BUFFER_SIZE;
            }
            else
            {
                if (sizeof(ULONG) == input_len)
                {
                    sc_offset = *(ULONG *)src;
                }

                if (sc_offset >= dev_ext->len)
                {
                    nts = STATUS_BUFFER_OVERFLOW;
                }
                else
                {
                    fptr_sc = (fptr_sc_t)(dev_ext->buf + sc_offset);

                    PDEBUG("DeviceIoControl(IOCTL_kscldr_callsc): Pre\n");

#if CFG_EN_ENFORCE_BREAKPOINT
                    // Break unconditionally in pre-built releases
                    __debugbreak();
#else
                    if (dev_ext->do_break)
                    {
                        __debugbreak();
                    }
#endif // CFG_EN_ENFORCE_BREAKPOINT

                    fptr_sc();
                    PDEBUG("DeviceIoControl(IOCTL_kscldr_callsc): Post\n");

                    nts = STATUS_SUCCESS;
                }
            }
            break;
        }
    }

exit_scldrDeviceControl:
    if (took_mutex)
    {
        ExReleaseFastMutex(&dev_ext->mutex);
    }

    Irp->IoStatus.Status = nts;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return nts;
}

/**
 * Initialize an ScldrDevExt.
 *
 * IRQL constrained by ExInitializeFastMutex.
 *
 * @param dev_ext an ScldrDevExt to initialize.
 *
 * @return
 *      STATUS_SUCCESS if successful;
 *      STATUS_INVALID_PARAMETER if null pointer.
 */
NTSTATUS
scldrDevExtInit(struct ScldrDevExt *dev_ext)
{
    NTSTATUS nts = STATUS_UNSUCCESSFUL;

    ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);

    if (NULL == dev_ext) {
        nts = STATUS_INVALID_PARAMETER;
        goto exit_scldrDevExtInit;
    }

    ExInitializeFastMutex(&dev_ext->mutex);
    dev_ext->do_break = TRUE;
    dev_ext->max_len = SCLDR_DEFAULT_MAX_LENGTH;
    dev_ext->len = 0;
    dev_ext->buf = NULL;

    nts = STATUS_SUCCESS;

exit_scldrDevExtInit:
    return nts;
}

/**
 * Deallocate buffers associated with an ScldrDevExt.
 *
 * IRQL is constrained by the FAST_MUTEX.
 *
 * @param dev_ext the ScldrDevExt to destroy.
 *
 * @return
 *      STATUS_SUCCESS if successful;
 *      STATUS_INVALID_PARAMETER if null pointer.
 */
NTSTATUS
scldrDevExtDestroy(struct ScldrDevExt *dev_ext)
{
    NTSTATUS nts = STATUS_UNSUCCESSFUL;
    BOOLEAN took_mutex = FALSE;

    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    if (NULL == dev_ext)
    {
        nts = STATUS_INVALID_PARAMETER;
        goto exit_scldrDevExtDestroy;
    }

    ExAcquireFastMutex(&dev_ext->mutex);
    took_mutex = TRUE;

    if (dev_ext->buf)
    {
        ExFreePoolWithTag(dev_ext->buf, TAG);
        dev_ext->buf = NULL;
        dev_ext->len = 0;
    }

    nts = STATUS_SUCCESS;

exit_scldrDevExtDestroy:
    if (took_mutex)
    {
        ExReleaseFastMutex(&dev_ext->mutex);
    }

    return nts;
}

/**
 * Set the buffer of an ScldrDevExt.
 *
 * IRQL is constrained by the FAST_MUTEX.
 *
 * @param dev_ext an instance of ScldrDevExt
 * @param buf the buffer to assign to dev_ext.buf
 * @param len the length of @buf
 *
 * @return
 *      STATUS_SUCCESS when successful;
 *      STATUS_INVALID_PARAMETER if NULL pointer or invalid length;
 *      Other (e.g. STATUS_NO_MEMORY) if a callee returns failure.
 */
NTSTATUS
scldrDevExtSetBuf(struct ScldrDevExt *dev_ext, const char *buf, ULONG len)
{
    NTSTATUS nts = STATUS_UNSUCCESSFUL;
    BOOLEAN took_mutex = FALSE;

    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    if ((NULL == dev_ext) || (NULL == buf))
    {
        nts = STATUS_INVALID_PARAMETER;
        goto exit_scldrDevExtSetBuf;
    }

    ExAcquireFastMutex(&dev_ext->mutex);
    took_mutex = TRUE;

    nts = scldrDevExtSetBufUnsafe(dev_ext, buf, len);

exit_scldrDevExtSetBuf:
    if (took_mutex)
    {
        ExReleaseFastMutex(&dev_ext->mutex);
    }

    return nts;
}

/**
 * Set the buffer of an ScldrDevExt without taking any mutexes (assumes the
 * caller has taken care of synchronization).
 *
 * IRQL is constrained by ExAllocatePoolWithTag which, when called with
 * NonPagedPool, can be called through DISPATCH_LEVEL.
 *
 * @param dev_ext an instance of ScldrDevExt
 * @param buf the buffer to assign to dev_ext.buf
 * @param len the length of @buf
 *
 * @return
 *      STATUS_SUCCESS when successful;
 *      STATUS_INVALID_PARAMETER if NULL pointer or invalid length;
 *      STATUS_NO_MEMORY if ExAllocatePoolWithTag failed.
 */
NTSTATUS
scldrDevExtSetBufUnsafe(
    struct ScldrDevExt *dev_ext,
    const char *buf,
    ULONG len
   )
{
    NTSTATUS nts = STATUS_SUCCESS;

    ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);

    if ((NULL == dev_ext) || (NULL == buf) || (!len) ||
        (len > dev_ext->max_len))
    {
        nts = STATUS_INVALID_PARAMETER;
        goto exit_scldrDevExtSetBufUnsafe;
    }

    // Dispose of any memory already allocated
    if (dev_ext->buf)
    {
        ExFreePoolWithTag(dev_ext->buf, TAG);
        dev_ext->buf = NULL;
        dev_ext->len = 0;
    }

    // Allocate, check, copy
    dev_ext->buf = ExAllocatePoolWithTag(NonPagedPool, len, TAG);
    if (!dev_ext->buf)
    {
        nts = STATUS_NO_MEMORY;
    }
    else
    {
        dev_ext->len = len;
        RtlSecureZeroMemory(dev_ext->buf, dev_ext->len);
        RtlCopyMemory(dev_ext->buf, buf, dev_ext->len);
    }

exit_scldrDevExtSetBufUnsafe:
    return nts;
}
