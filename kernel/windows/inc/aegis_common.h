#pragma once

#include <wdm.h>

#define AEGIS_DEVICE_NAME L"\\Device\\AegisFusion"
#define AEGIS_SYMLINK_NAME L"\\DosDevices\\AegisFusion"
#define AEGIS_POOL_TAG 'siGA'

typedef enum _AEGIS_EVENT_TYPE {
    AegisEventFileCreate = 1,
    AegisEventFileWrite = 2,
    AegisEventFileDelete = 3,
    AegisEventProcessCreate = 10,
    AegisEventProcessTerminate = 11,
    AegisEventThreadCreate = 12,
    AegisEventImageLoad = 13,
    AegisEventRegistrySet = 20,
    AegisEventRegistryDelete = 21
} AEGIS_EVENT_TYPE;

typedef struct _AEGIS_EVENT {
    LARGE_INTEGER Timestamp;
    ULONG EventType;
    ULONG ProcessId;
    ULONG ParentProcessId;
    ULONG ThreadId;
    WCHAR ProcessName[64];
    WCHAR Path[260];
    ULONG DataLength;
    UCHAR Data[256];
} AEGIS_EVENT, *PAEGIS_EVENT;
