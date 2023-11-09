import angr


ALL_TYPES_STRING = '''
typedef void* PVOID;
typedef unsigned short wchar_t;

// Hack coz we don't wanna have to import every type involved
typedef PVOID PKKERNEL_ROUTINE;
typedef PVOID PKRUNDOWN_ROUTINE;
typedef PVOID PKNORMAL_ROUTINE;
typedef PVOID PETHREAD;
typedef PVOID PKEVENT;
typedef PVOID PIO_APC_ROUTINE; 
typedef PVOID PDRIVER_CANCEL;
typedef PVOID PSECURITY_DESCRIPTOR;
typedef PVOID PIO_COMPLETION_ROUTINE;
typedef PVOID PCM_RESOURCE_LIST;
typedef PVOID PSID;
typedef PVOID PIO_TIMER;
typedef PVOID PVPB;
typedef PVOID PINTERFACE;
typedef PVOID PDEVICE_CAPABILITIES;
typedef PVOID PIO_RESOURCE_REQUIREMENTS_LIST;
typedef PVOID PMDL;
typedef int DEVICE_TYPE;
typedef int LCID;

typedef PVOID PFAST_IO_DISPATCH;
typedef PVOID PIO_SECURITY_CONTEXT;
typedef PVOID PFILE_OBJECT;
/*
typedef PVOID PDRIVER_INITIALIZE;
typedef PVOID PDRIVER_STARTIO;
typedef PVOID PDRIVER_UNLOAD;
typedef PVOID PDRIVER_DISPATCH;
*/
#define IRP_MJ_MAXIMUM_FUNCTION 27
#define IN
#define OUT
#define NTAPI
#define _ANONYMOUS_UNION
#define _ANONYMOUS_STRUCT
#define NTSTATUS LONG
#define DUMMYUNIONNAME u
#define DUMMYSTRUCTNAME s



#define CONST const 

typedef void VOID;
typedef void* PVOID;
typedef PVOID HANDLE;

typedef int8_t BYTE;
typedef int16_t WORD;
typedef int32_t DWORD;
typedef int64_t QWORD;


typedef BYTE BOOLEAN;
typedef BOOLEAN *PBOOLEAN;

typedef char CHAR, *PCHAR;
typedef char CCHAR, *PCCHAR; 
typedef unsigned char UCHAR, *PUCHAR;
typedef short CSHORT, *PCSHORT;
typedef unsigned short USHORT, *PUSHORT;
typedef int LONG, *PLONG;
typedef unsigned int ULONG, *PULONG, *ULONG_PTR;
typedef long long LONGLONG, *PLONGLONG;
typedef unsigned long long ULONGLONG, *PULONGLONG;

typedef wchar_t WCHAR;
typedef WCHAR *NWPSTR, *LPWSTR, *PWSTR;

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _CLIENT_ID {
  HANDLE UniqueProcess;
  HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _LARGE_INTEGER {
  LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;
typedef struct _GUID {
  unsigned int Data1;
  unsigned short Data2;
  unsigned short Data3;
  unsigned char Data4[8];
} GUID;
typedef struct _LIST_ENTRY {
  struct _LIST_ENTRY* Flink;
  struct _LIST_ENTRY* Blink;
} LIST_ENTRY, *PLIST_ENTRY;


typedef UCHAR KIRQL, *PKIRQL;
typedef DWORD SECURITY_INFORMATION, *PSECURITY_INFORMATION;
typedef int FS_INFORMATION_CLASS, *PFS_INFORMATION_CLASS;

typedef int FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;
typedef int DEVICE_RELATION_TYPE, *PDEVICE_RELATION_TYPE;
typedef int BUS_QUERY_ID_TYPE, *PBUS_QUERY_ID_TYPE;
typedef int DEVICE_TEXT_TYPE, *PDEVICE_TEXT_TYPE;
typedef int DEVICE_USAGE_NOTIFICATION_TYPE;

typedef struct _FILE_BASIC_INFORMATION {
  LARGE_INTEGER CreationTime;
  LARGE_INTEGER LastAccessTime;
  LARGE_INTEGER LastWriteTime;
  LARGE_INTEGER ChangeTime;
  ULONG         FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _OSVERSIONINFOW {
  ULONG dwOSVersionInfoSize;
  ULONG dwMajorVersion;
  ULONG dwMinorVersion;
  ULONG dwBuildNumber;
  ULONG dwPlatformId;
  WCHAR szCSDVersion[128];
} OSVERSIONINFOW, *POSVERSIONINFOW, *LPOSVERSIONINFOW, RTL_OSVERSIONINFOW, *PRTL_OSVERSIONINFOW;

typedef struct _KDEVICE_QUEUE_ENTRY {
  LIST_ENTRY DeviceListEntry;
  ULONG SortKey;
  BOOLEAN Inserted;
} KDEVICE_QUEUE_ENTRY, *PKDEVICE_QUEUE_ENTRY;

typedef struct _POWER_SEQUENCE {
  ULONG SequenceD1;
  ULONG SequenceD2;
  ULONG SequenceD3;
} POWER_SEQUENCE, *PPOWER_SEQUENCE;
typedef int SYSTEM_POWER_STATE, *PSYSTEM_POWER_STATE;

typedef int POWER_INFORMATION_LEVEL;

typedef int POWER_ACTION, *PPOWER_ACTION;

typedef int DEVICE_POWER_STATE, *PDEVICE_POWER_STATE;

typedef int MONITOR_DISPLAY_STATE, *PMONITOR_DISPLAY_STATE;

typedef union _POWER_STATE {
  SYSTEM_POWER_STATE SystemState;
  DEVICE_POWER_STATE DeviceState;
} POWER_STATE, *PPOWER_STATE;

typedef int POWER_STATE_TYPE, *PPOWER_STATE_TYPE;
typedef CCHAR KPROCESSOR_MODE;


struct _IRP;
struct _DEVICE_OBJECT;
struct _DRIVER_OBJECT;
struct _IO_STACK_LOCATION;

// #########################   TODO: ONLY HALF THE STRUCT HERE COZ WE DON'T CARE!!!!!!!
typedef struct _DEVICE_OBJECT {
  CSHORT                   Type;
  USHORT                   Size;
  LONG                     ReferenceCount;
  struct _DRIVER_OBJECT    *DriverObject;
  struct _DEVICE_OBJECT    *NextDevice;
  struct _DEVICE_OBJECT    *AttachedDevice;
  struct _IRP              *CurrentIrp;
  PIO_TIMER                Timer;
  ULONG                    Flags;
  ULONG                    Characteristics;
  PVPB                     Vpb;
  PVOID                    DeviceExtension;
  DEVICE_TYPE              DeviceType;
  CCHAR                    StackSize;
} DEVICE_OBJECT, *PDEVICE_OBJECT;

typedef NTSTATUS
(NTAPI DRIVER_ADD_DEVICE)(
  IN struct _DRIVER_OBJECT *DriverObject,
  IN struct _DEVICE_OBJECT *PhysicalDeviceObject);
typedef DRIVER_ADD_DEVICE *PDRIVER_ADD_DEVICE;

typedef struct _DRIVER_EXTENSION {
  struct _DRIVER_OBJECT *DriverObject;
  PDRIVER_ADD_DEVICE AddDevice;
  ULONG Count;
  UNICODE_STRING ServiceKeyName;
} DRIVER_EXTENSION, *PDRIVER_EXTENSION;

#define DRVO_UNLOAD_INVOKED               0x00000001
#define DRVO_LEGACY_DRIVER                0x00000002
#define DRVO_BUILTIN_DRIVER               0x00000004

typedef NTSTATUS
(NTAPI DRIVER_INITIALIZE)(
  IN struct _DRIVER_OBJECT *DriverObject,
  IN PUNICODE_STRING RegistryPath);
typedef DRIVER_INITIALIZE *PDRIVER_INITIALIZE;

typedef VOID
(NTAPI DRIVER_STARTIO)(
  IN struct _DEVICE_OBJECT *DeviceObject,
  IN struct _IRP *Irp);
typedef DRIVER_STARTIO *PDRIVER_STARTIO;

typedef VOID
(NTAPI DRIVER_UNLOAD)(
  IN struct _DRIVER_OBJECT *DriverObject);
typedef DRIVER_UNLOAD *PDRIVER_UNLOAD;

typedef NTSTATUS
(NTAPI DRIVER_DISPATCH)(
  IN struct _DEVICE_OBJECT *DeviceObject,
  IN struct _IRP *Irp);
typedef DRIVER_DISPATCH *PDRIVER_DISPATCH;

typedef struct _DRIVER_OBJECT {
  CSHORT             Type;
  CSHORT             Size;
  PDEVICE_OBJECT     DeviceObject;
  ULONG              Flags;
  PVOID              DriverStart;
  ULONG              DriverSize;
  PVOID              DriverSection;
  PDRIVER_EXTENSION  DriverExtension;
  UNICODE_STRING     DriverName;
  PUNICODE_STRING    HardwareDatabase;
  PFAST_IO_DISPATCH  FastIoDispatch;
  PDRIVER_INITIALIZE DriverInit;
  PDRIVER_STARTIO    DriverStartIo;
  PDRIVER_UNLOAD     DriverUnload;
  PDRIVER_DISPATCH   MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
} DRIVER_OBJECT, *PDRIVER_OBJECT;

typedef union {
    ULONG val;
    void* ________NOOOOO________;
} POINTER_ALIGNED_ULONG;

#define POINTER_ALIGNED(type, name) union { \
    void* ________NOOOOO________; \
    type val; \
} name;

typedef struct _IO_STACK_LOCATION {
  UCHAR MajorFunction;
  UCHAR MinorFunction;
  UCHAR Flags;
  UCHAR Control;
  union {
    struct {
      POINTER_ALIGNED_ULONG OutputBufferLength;
      POINTER_ALIGNED_ULONG InputBufferLength;
      POINTER_ALIGNED_ULONG IoControlCode;
      PVOID Type3InputBuffer;
    } DeviceIoControl;
    struct {
      PVOID Argument1;
      PVOID Argument2;
      PVOID Argument3;
      PVOID Argument4;
    } Others;
  } Parameters;
  PDEVICE_OBJECT DeviceObject;
  PFILE_OBJECT FileObject;
  PIO_COMPLETION_ROUTINE CompletionRoutine;
  PVOID Context;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;

typedef struct _IO_STATUS_BLOCK {
  _ANONYMOUS_UNION union {
    NTSTATUS Status;
    PVOID Pointer;
  } DUMMYUNIONNAME;
  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _KAPC {
  UCHAR Type;
  UCHAR SpareByte0;
  UCHAR Size;
  UCHAR SpareByte1;
  ULONG SpareLong0;
  struct _KTHREAD *Thread;
  LIST_ENTRY ApcListEntry;
  PKKERNEL_ROUTINE KernelRoutine;
  PKRUNDOWN_ROUTINE RundownRoutine;
  PKNORMAL_ROUTINE NormalRoutine;
  PVOID NormalContext;
  PVOID SystemArgument1;
  PVOID SystemArgument2;
  CCHAR ApcStateIndex;
  KPROCESSOR_MODE ApcMode;
  BOOLEAN Inserted;
} KAPC, *PKAPC;

typedef struct _IRP {
  CSHORT Type;
  USHORT Size;
  struct _MDL *MdlAddress;
  ULONG Flags;
  union {
    struct _IRP *MasterIrp;
    volatile LONG IrpCount;
    PVOID SystemBuffer;
  } AssociatedIrp;
  LIST_ENTRY ThreadListEntry;
  IO_STATUS_BLOCK IoStatus;
  KPROCESSOR_MODE RequestorMode;
  BOOLEAN PendingReturned;
  CHAR StackCount;
  CHAR CurrentLocation;
  BOOLEAN Cancel;
  KIRQL CancelIrql;
  CCHAR ApcEnvironment;
  UCHAR AllocationFlags;
  PIO_STATUS_BLOCK UserIosb;
  PKEVENT UserEvent;
  union {
    struct {
      _ANONYMOUS_UNION union {
        PIO_APC_ROUTINE UserApcRoutine;
        PVOID IssuingProcess;
      } DUMMYUNIONNAME;
      PVOID UserApcContext;
    } AsynchronousParameters;
    LARGE_INTEGER AllocationSize;
  } Overlay;
  volatile PDRIVER_CANCEL CancelRoutine;
  PVOID UserBuffer;
  union {
    struct {
      _ANONYMOUS_UNION union {
        KDEVICE_QUEUE_ENTRY DeviceQueueEntry;
        _ANONYMOUS_STRUCT struct {
          PVOID DriverContext[4];
        } DUMMYSTRUCTNAME;
      } DUMMYUNIONNAME;
      PETHREAD Thread;
      PCHAR AuxiliaryBuffer;
      _ANONYMOUS_STRUCT struct {
        LIST_ENTRY ListEntry;
        _ANONYMOUS_UNION union {
          struct _IO_STACK_LOCATION *CurrentStackLocation;
          ULONG PacketType;
        } DUMMYUNIONNAME;
      } DUMMYSTRUCTNAME;
      struct _FILE_OBJECT *OriginalFileObject;
    } Overlay;
    KAPC Apc;
    PVOID CompletionKey;
  } Tail;
} IRP, *PIRP;

typedef struct _FILE_NAME_INFORMATION {
  ULONG FileNameLength;
  WCHAR FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;

typedef struct _OBJECT_ATTRIBUTES {
  ULONG Length;
  HANDLE RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;
  PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
typedef CONST OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;
'''

angr.types.register_types(angr.types.parse_types(ALL_TYPES_STRING))