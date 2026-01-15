/*
 * AEGIS FUSION - Kernel Monitor Driver (Windows)
 *
 * Driver de modo kernel para interceptar operaciones del sistema
 * Compatible con Windows 10/11 (WDM/KMDF)
 */

#include <fltKernel.h>
#include <ntstrsafe.h>

extern HANDLE PsGetProcessInheritedFromUniqueProcessId(PEPROCESS Process);

#include "..\\inc\\aegis_common.h"
#include "..\\inc\\ioctl_codes.h"

// Set to 1 to isolate load issues (DriverEntry returns immediately).
#define AEGIS_SAFE_START 0

// ============================================================================
// DEFINICIONES Y ESTRUCTURAS
// ============================================================================

// Tipos de eventos y estructuras definidas en aegis_common.h

// Ring buffer para eventos
#define RING_BUFFER_SIZE 4096
typedef struct _AEGIS_RING_BUFFER {
    AEGIS_EVENT Events[RING_BUFFER_SIZE];
    volatile LONG WriteIndex;
    volatile LONG ReadIndex;
    KSPIN_LOCK SpinLock;
} AEGIS_RING_BUFFER, *PAEGIS_RING_BUFFER;

// Contexto global del driver
typedef struct _AEGIS_CONTEXT {
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING DeviceName;
    UNICODE_STRING SymlinkName;
    PAEGIS_RING_BUFFER RingBuffer;
    BOOLEAN Monitoring;
    PFLT_FILTER FilterHandle;

    // Callback handles
    PVOID ProcessNotifyHandle;
    PVOID ThreadNotifyHandle;
    PVOID ImageNotifyHandle;
    LARGE_INTEGER RegistryCallbackCookie;
} AEGIS_CONTEXT, *PAEGIS_CONTEXT;

static AEGIS_CONTEXT g_AegisContext = {0};

static VOID AegisSetProcessName(ULONG processId, WCHAR *buffer, size_t bufferCount) {
    UNICODE_STRING pidString;
    WCHAR pidBuffer[16] = {0};

    if (!buffer || bufferCount == 0) {
        return;
    }

    RtlInitEmptyUnicodeString(&pidString, pidBuffer, sizeof(pidBuffer));
    if (NT_SUCCESS(RtlIntegerToUnicodeString(processId, 10, &pidString))) {
        RtlStringCchCopyW(buffer, bufferCount, L"Process_");
        RtlStringCchCatW(buffer, bufferCount, pidString.Buffer);
    } else {
        RtlStringCchCopyW(buffer, bufferCount, L"Process");
    }
}

static VOID AegisCopyUnicodeString(PCUNICODE_STRING source, WCHAR *buffer, size_t bufferCount) {
    if (!buffer || bufferCount == 0) {
        return;
    }

    buffer[0] = L'\0';
    if (!source || !source->Buffer || source->Length == 0) {
        return;
    }

    USHORT maxBytes = (USHORT)((bufferCount - 1) * sizeof(WCHAR));
    USHORT copyLen = min(source->Length, maxBytes);
    if (copyLen == 0) {
        return;
    }

    RtlCopyMemory(buffer, source->Buffer, copyLen);
    buffer[copyLen / sizeof(WCHAR)] = L'\0';
}

static VOID AegisSetProcessNameFromPath(PCUNICODE_STRING imagePath, WCHAR *buffer, size_t bufferCount) {
    if (!buffer || bufferCount == 0) {
        return;
    }

    buffer[0] = L'\0';
    if (!imagePath || !imagePath->Buffer || imagePath->Length == 0) {
        return;
    }

    USHORT length = (USHORT)(imagePath->Length / sizeof(WCHAR));
    const WCHAR *start = imagePath->Buffer;
    const WCHAR *end = start + length;
    const WCHAR *name = start;

    for (const WCHAR *p = start; p < end; ++p) {
        if (*p == L'\\' || *p == L'/') {
            name = p + 1;
        }
    }

    size_t nameLen = (size_t)(end - name);
    if (nameLen >= bufferCount) {
        nameLen = bufferCount - 1;
    }

    if (nameLen == 0) {
        return;
    }

    RtlCopyMemory(buffer, name, nameLen * sizeof(WCHAR));
    buffer[nameLen] = L'\0';
}

static VOID AegisCopyCommandLine(
    PCUNICODE_STRING commandLine,
    UCHAR *dest,
    ULONG destSize,
    ULONG *outLength
) {
    if (outLength) {
        *outLength = 0;
    }

    if (!dest || destSize == 0 || !commandLine || !commandLine->Buffer || commandLine->Length == 0) {
        return;
    }

    ULONG copyLen = min((ULONG)commandLine->Length, destSize);
    copyLen &= ~1u;
    if (copyLen == 0) {
        return;
    }

    RtlCopyMemory(dest, commandLine->Buffer, copyLen);
    if (outLength) {
        *outLength = copyLen;
    }
}

static ULONG AegisGetParentProcessId(PEPROCESS Process, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    if (CreateInfo && CreateInfo->ParentProcessId) {
        return HandleToULong(CreateInfo->ParentProcessId);
    }

    if (Process) {
        return HandleToULong(PsGetProcessInheritedFromUniqueProcessId(Process));
    }

    return 0;
}

// ============================================================================
// FUNCIONES DE RING BUFFER
// ============================================================================

NTSTATUS RingBufferInit(PAEGIS_RING_BUFFER* RingBuffer) {
    *RingBuffer = (PAEGIS_RING_BUFFER)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(AEGIS_RING_BUFFER),
        AEGIS_POOL_TAG
    );

    if (*RingBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(*RingBuffer, sizeof(AEGIS_RING_BUFFER));
    KeInitializeSpinLock(&(*RingBuffer)->SpinLock);

    KdPrint(("[AEGIS] Ring buffer initialized (size: %d events)\n", RING_BUFFER_SIZE));
    return STATUS_SUCCESS;
}

VOID RingBufferWrite(PAEGIS_RING_BUFFER RingBuffer, PAEGIS_EVENT Event) {
    KIRQL oldIrql;
    LONG writeIdx;

    if (!RingBuffer || !Event) {
        return;
    }

    KeAcquireSpinLock(&RingBuffer->SpinLock, &oldIrql);

    writeIdx = RingBuffer->WriteIndex;
    RtlCopyMemory(&RingBuffer->Events[writeIdx], Event, sizeof(AEGIS_EVENT));

    // Avanzar write index (circular)
    RingBuffer->WriteIndex = (writeIdx + 1) % RING_BUFFER_SIZE;

    // Si alcanzamos el read index, perdimos eventos (overflow)
    if (RingBuffer->WriteIndex == RingBuffer->ReadIndex) {
        RingBuffer->ReadIndex = (RingBuffer->ReadIndex + 1) % RING_BUFFER_SIZE;
        KdPrint(("[AEGIS] WARNING: Ring buffer overflow, event dropped\n"));
    }

    KeReleaseSpinLock(&RingBuffer->SpinLock, oldIrql);
}

BOOLEAN RingBufferRead(PAEGIS_RING_BUFFER RingBuffer, PAEGIS_EVENT Event) {
    KIRQL oldIrql;
    LONG readIdx;
    BOOLEAN hasData = FALSE;

    if (!RingBuffer || !Event) {
        return FALSE;
    }

    KeAcquireSpinLock(&RingBuffer->SpinLock, &oldIrql);

    if (RingBuffer->ReadIndex != RingBuffer->WriteIndex) {
        readIdx = RingBuffer->ReadIndex;
        RtlCopyMemory(Event, &RingBuffer->Events[readIdx], sizeof(AEGIS_EVENT));
        RingBuffer->ReadIndex = (readIdx + 1) % RING_BUFFER_SIZE;
        hasData = TRUE;
    }

    KeReleaseSpinLock(&RingBuffer->SpinLock, oldIrql);
    return hasData;
}

// ============================================================================
// CALLBACKS DE MONITOREO
// ============================================================================

/*
 * Callback para creacion/terminacion de procesos
 */
VOID ProcessNotifyCallbackEx(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    AEGIS_EVENT event = {0};

    if (!g_AegisContext.Monitoring) {
        return;
    }

    // Llenar evento
    event.EventType = CreateInfo ? AegisEventProcessCreate : AegisEventProcessTerminate;
    KeQuerySystemTime(&event.Timestamp);
    event.ProcessId = HandleToULong(ProcessId);
    event.ThreadId = HandleToULong(PsGetCurrentThreadId());
    event.ParentProcessId = AegisGetParentProcessId(Process, CreateInfo);

    if (CreateInfo && CreateInfo->ImageFileName) {
        AegisCopyUnicodeString(
            CreateInfo->ImageFileName,
            event.Path,
            RTL_NUMBER_OF(event.Path)
        );
        AegisSetProcessNameFromPath(
            CreateInfo->ImageFileName,
            event.ProcessName,
            RTL_NUMBER_OF(event.ProcessName)
        );
        if (event.ProcessName[0] == L'\0') {
            AegisSetProcessName(event.ProcessId, event.ProcessName, RTL_NUMBER_OF(event.ProcessName));
        }
    } else {
        AegisSetProcessName(event.ProcessId, event.ProcessName, RTL_NUMBER_OF(event.ProcessName));
    }

    if (CreateInfo && CreateInfo->CommandLine) {
        AegisCopyCommandLine(
            CreateInfo->CommandLine,
            event.Data,
            sizeof(event.Data),
            &event.DataLength
        );
    }

    // Escribir al ring buffer
    RingBufferWrite(g_AegisContext.RingBuffer, &event);

    KdPrint(("[AEGIS] Process %s: PID=%lu\n",
             CreateInfo ? "created" : "terminated",
             event.ProcessId));
}

/*
 * Callback para creacion de threads
 */
VOID ThreadNotifyCallback(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create
) {
    AEGIS_EVENT event = {0};

    UNREFERENCED_PARAMETER(Create);

    if (!g_AegisContext.Monitoring) {
        return;
    }

    event.EventType = AegisEventThreadCreate;
    KeQuerySystemTime(&event.Timestamp);
    event.ProcessId = HandleToULong(ProcessId);
    event.ThreadId = HandleToULong(ThreadId);

    RingBufferWrite(g_AegisContext.RingBuffer, &event);
}

/*
 * Callback para carga de imagenes (DLLs/EXEs)
 */
VOID ImageLoadCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
) {
    AEGIS_EVENT event = {0};

    UNREFERENCED_PARAMETER(ImageInfo);

    if (!g_AegisContext.Monitoring) {
        return;
    }

    event.EventType = AegisEventImageLoad;
    KeQuerySystemTime(&event.Timestamp);
    event.ProcessId = HandleToULong(ProcessId);

    // Copiar path de la imagen
    if (FullImageName && FullImageName->Buffer) {
        USHORT copyLen = min(FullImageName->Length, sizeof(event.Path) - sizeof(WCHAR));
        RtlCopyMemory(event.Path, FullImageName->Buffer, copyLen);
        event.Path[copyLen / sizeof(WCHAR)] = L'\0';
    }

    RingBufferWrite(g_AegisContext.RingBuffer, &event);

    KdPrint(("[AEGIS] Image loaded: %wZ (PID=%lu)\n",
             FullImageName, event.ProcessId));
}

/*
 * Callback para operaciones de registro
 */
NTSTATUS RegistryCallback(
    PVOID CallbackContext,
    PVOID Argument1,
    PVOID Argument2
) {
    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    AEGIS_EVENT event = {0};

    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Argument2);

    if (!g_AegisContext.Monitoring) {
        return STATUS_SUCCESS;
    }

    // Solo interceptar SetValue y DeleteValue
    if (notifyClass == RegNtPostSetValueKey) {
        event.EventType = AegisEventRegistrySet;
    } else if (notifyClass == RegNtPostDeleteValueKey) {
        event.EventType = AegisEventRegistryDelete;
    } else {
        return STATUS_SUCCESS;
    }

    KeQuerySystemTime(&event.Timestamp);
    event.ProcessId = HandleToULong(PsGetCurrentProcessId());

    RingBufferWrite(g_AegisContext.RingBuffer, &event);

    return STATUS_SUCCESS;
}

// ============================================================================
// MINIFILTER PARA FILE SYSTEM
// ============================================================================

static VOID AegisQueueFileEvent(AEGIS_EVENT_TYPE eventType, ULONG processId, PUNICODE_STRING path) {
    AEGIS_EVENT event = {0};

    event.EventType = eventType;
    KeQuerySystemTime(&event.Timestamp);
    event.ProcessId = processId;
    event.ThreadId = HandleToULong(PsGetCurrentThreadId());
    AegisSetProcessName(event.ProcessId, event.ProcessName, RTL_NUMBER_OF(event.ProcessName));

    if (path && path->Buffer) {
        USHORT copyLen = min(path->Length, sizeof(event.Path) - sizeof(WCHAR));
        RtlCopyMemory(event.Path, path->Buffer, copyLen);
        event.Path[copyLen / sizeof(WCHAR)] = L'\0';
    }

    RingBufferWrite(g_AegisContext.RingBuffer, &event);
}

FLT_PREOP_CALLBACK_STATUS
AegisPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!g_AegisContext.Monitoring) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );

    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(nameInfo);
        if (NT_SUCCESS(status)) {
            AegisQueueFileEvent(
                AegisEventFileCreate,
                (ULONG)FltGetRequestorProcessId(Data),
                &nameInfo->Name
            );
        }
        FltReleaseFileNameInformation(nameInfo);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
AegisPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!g_AegisContext.Monitoring) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );

    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(nameInfo);
        if (NT_SUCCESS(status)) {
            AegisQueueFileEvent(
                AegisEventFileWrite,
                (ULONG)FltGetRequestorProcessId(Data),
                &nameInfo->Name
            );
        }
        FltReleaseFileNameInformation(nameInfo);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
AegisPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!g_AegisContext.Monitoring) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FILE_INFORMATION_CLASS infoClass =
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    if (infoClass == FileDispositionInformation || infoClass == FileDispositionInformationEx) {
        PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
        NTSTATUS status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo
        );

        if (NT_SUCCESS(status)) {
            status = FltParseFileNameInformation(nameInfo);
            if (NT_SUCCESS(status)) {
                AegisQueueFileEvent(
                    AegisEventFileDelete,
                    (ULONG)FltGetRequestorProcessId(Data),
                    &nameInfo->Name
                );
            }
            FltReleaseFileNameInformation(nameInfo);
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

const FLT_OPERATION_REGISTRATION AegisCallbacks[] = {
    { IRP_MJ_CREATE, 0, AegisPreCreate, NULL },
    { IRP_MJ_WRITE, 0, AegisPreWrite, NULL },
    { IRP_MJ_SET_INFORMATION, 0, AegisPreSetInformation, NULL },
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION AegisFilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    AegisCallbacks,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

static VOID AegisStartMinifilter(PDRIVER_OBJECT DriverObject) {
    NTSTATUS status = FltRegisterFilter(
        DriverObject,
        &AegisFilterRegistration,
        &g_AegisContext.FilterHandle
    );

    if (!NT_SUCCESS(status)) {
        g_AegisContext.FilterHandle = NULL;
        KdPrint(("[AEGIS] Minifilter registration failed: 0x%08X\n", status));
        return;
    }

    status = FltStartFiltering(g_AegisContext.FilterHandle);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[AEGIS] Minifilter start failed: 0x%08X\n", status));
        FltUnregisterFilter(g_AegisContext.FilterHandle);
        g_AegisContext.FilterHandle = NULL;
        return;
    }

    KdPrint(("[AEGIS] Minifilter started\n"));
}

// ============================================================================
// DISPOSITIVO Y COMUNICACION CON USERLAND
// ============================================================================

NTSTATUS AegisCreateDevice(PDRIVER_OBJECT DriverObject) {
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;

    // Inicializar nombres
    RtlInitUnicodeString(&g_AegisContext.DeviceName, AEGIS_DEVICE_NAME);
    RtlInitUnicodeString(&g_AegisContext.SymlinkName, AEGIS_SYMLINK_NAME);

    // Crear dispositivo
    status = IoCreateDevice(
        DriverObject,
        0,
        &g_AegisContext.DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("[AEGIS] Failed to create device: 0x%08X\n", status));
        return status;
    }

    g_AegisContext.DeviceObject = deviceObject;

    // Crear symlink
    status = IoCreateSymbolicLink(&g_AegisContext.SymlinkName, &g_AegisContext.DeviceName);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[AEGIS] Failed to create symlink: 0x%08X\n", status));
        IoDeleteDevice(deviceObject);
        return status;
    }

    KdPrint(("[AEGIS] Device created successfully\n"));
    return STATUS_SUCCESS;
}

// ============================================================================
// IRP HANDLERS
// ============================================================================

NTSTATUS AegisCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS AegisDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesReturned = 0;

    ULONG controlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (controlCode) {
        case IOCTL_AEGIS_GET_EVENT:
        {
            if (outputBufferLength >= sizeof(AEGIS_EVENT)) {
                if (RingBufferRead(g_AegisContext.RingBuffer, (PAEGIS_EVENT)outputBuffer)) {
                    bytesReturned = sizeof(AEGIS_EVENT);
                } else {
                    status = STATUS_NO_MORE_ENTRIES;
                }
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        }
        case IOCTL_AEGIS_START:
            g_AegisContext.Monitoring = TRUE;
            KdPrint(("[AEGIS] Monitoring STARTED\n"));
            break;
        case IOCTL_AEGIS_STOP:
            g_AegisContext.Monitoring = FALSE;
            KdPrint(("[AEGIS] Monitoring STOPPED\n"));
            break;
        case IOCTL_AEGIS_GET_STATS:
            if (outputBufferLength >= sizeof(ULONG)) {
                *(PULONG)outputBuffer = g_AegisContext.RingBuffer
                    ? (ULONG)((g_AegisContext.RingBuffer->WriteIndex -
                               g_AegisContext.RingBuffer->ReadIndex +
                               RING_BUFFER_SIZE) %
                              RING_BUFFER_SIZE)
                    : 0;
                bytesReturned = sizeof(ULONG);
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

// ============================================================================
// DRIVER ENTRY Y UNLOAD
// ============================================================================

VOID AegisUnload(PDRIVER_OBJECT DriverObject) {
    KdPrint(("[AEGIS] Driver unloading...\n"));

    UNREFERENCED_PARAMETER(DriverObject);

    // Desregistrar callbacks
    if (g_AegisContext.ProcessNotifyHandle) {
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);
    }

    if (g_AegisContext.ThreadNotifyHandle) {
        PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
    }

    if (g_AegisContext.ImageNotifyHandle) {
        PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
    }

    if (g_AegisContext.RegistryCallbackCookie.QuadPart != 0) {
        CmUnRegisterCallback(g_AegisContext.RegistryCallbackCookie);
    }

    if (g_AegisContext.FilterHandle) {
        FltUnregisterFilter(g_AegisContext.FilterHandle);
        g_AegisContext.FilterHandle = NULL;
    }

    // Eliminar symlink y dispositivo
    if (g_AegisContext.SymlinkName.Buffer) {
        IoDeleteSymbolicLink(&g_AegisContext.SymlinkName);
    }

    if (g_AegisContext.DeviceObject) {
        IoDeleteDevice(g_AegisContext.DeviceObject);
    }

    // Liberar ring buffer
    if (g_AegisContext.RingBuffer) {
        ExFreePoolWithTag(g_AegisContext.RingBuffer, AEGIS_POOL_TAG);
    }

    KdPrint(("[AEGIS] Driver unloaded successfully\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"385200");

    UNREFERENCED_PARAMETER(RegistryPath);

    KdPrint(("========================================\n"));
    KdPrint(("   AEGIS FUSION KERNEL MONITOR v1.0\n"));
    KdPrint(("   Loading driver...\n"));
    KdPrint(("========================================\n"));

    // Inicializar contexto
    RtlZeroMemory(&g_AegisContext, sizeof(AEGIS_CONTEXT));

#if AEGIS_SAFE_START
    DriverObject->DriverUnload = AegisUnload;
    KdPrint(("[AEGIS] SAFE_START enabled (DriverEntry returns early)\n"));
    return STATUS_SUCCESS;
#endif

    // Inicializar ring buffer
    status = RingBufferInit(&g_AegisContext.RingBuffer);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[AEGIS] Failed to initialize ring buffer\n"));
        return status;
    }

    // Crear dispositivo
    status = AegisCreateDevice(DriverObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Configurar IRP handlers
    DriverObject->MajorFunction[IRP_MJ_CREATE] = AegisCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = AegisCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AegisDeviceControl;
    DriverObject->DriverUnload = AegisUnload;

    // Registrar callbacks
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, FALSE);
    if (NT_SUCCESS(status)) {
        KdPrint(("[AEGIS] Process notify callback registered\n"));
        g_AegisContext.ProcessNotifyHandle = (PVOID)1;
    }

    status = PsSetCreateThreadNotifyRoutine(ThreadNotifyCallback);
    if (NT_SUCCESS(status)) {
        KdPrint(("[AEGIS] Thread notify callback registered\n"));
        g_AegisContext.ThreadNotifyHandle = (PVOID)1;
    }

    status = PsSetLoadImageNotifyRoutine(ImageLoadCallback);
    if (NT_SUCCESS(status)) {
        KdPrint(("[AEGIS] Image load callback registered\n"));
        g_AegisContext.ImageNotifyHandle = (PVOID)1;
    }

    // Registrar callback de registro
    status = CmRegisterCallbackEx(
        RegistryCallback,
        &altitude,
        DriverObject,
        NULL,
        &g_AegisContext.RegistryCallbackCookie,
        NULL
    );
    if (NT_SUCCESS(status)) {
        KdPrint(("[AEGIS] Registry callback registered\n"));
    }

    // Iniciar monitoreo de file system (minifilter)
    AegisStartMinifilter(DriverObject);

    // Activar monitoreo
    g_AegisContext.Monitoring = TRUE;

    KdPrint(("========================================\n"));
    KdPrint(("   AEGIS FUSION: ACTIVE AND PROTECTING\n"));
    KdPrint(("========================================\n"));

    return STATUS_SUCCESS;
}

// ============================================================================
// NOTAS DE COMPILACION
// ============================================================================

/*
Para compilar este driver:

1. Instalar Windows Driver Kit (WDK)
2. Usar Visual Studio con WDK integration
3. Configurar proyecto como "Kernel Mode Driver"
4. Build configuration:
   - Target OS: Windows 10/11
   - Platform: x64
   - Configuration: Release/Debug

5. Firmar el driver con certificado de test:
   makecert -r -pe -ss PrivateCertStore -n "CN=AegisTest" AegisTest.cer
   signtool sign /s PrivateCertStore /n AegisTest /t http://timestamp.digicert.com AegisFusion.sys

6. Instalar driver:
   sc create AegisFusion type= kernel binPath= C:\path\to\AegisFusion.sys
   sc start AegisFusion

IMPORTANTE:
- Este codigo es educacional y requiere adaptaciones para produccion
- Requiere certificado EV para distribucion publica
- Debe pasar Windows Hardware Lab Kit (HLK) tests
- Considerar HVCI (Hypervisor-protected Code Integrity) compatibility
*/
