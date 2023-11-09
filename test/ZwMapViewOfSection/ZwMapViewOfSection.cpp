#include <ntddk.h>
#include <ntstrsafe.h>

#define symlink_name L"\\??\\ZwMapViewOfSection"
#define device_name L"\\device\\ZwMapViewOfSection"

#define ZwMapViewOfSection_SectionHandle_ProcessHandle_BaseAddress \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ZwMapViewOfSection_SectionHandle_ProcessHandle CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ZwMapViewOfSection_SectionHandle_BaseAddress CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ZwMapViewOfSection_SectionHandle CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ZwMapViewOfSection_PhysicalMemory_ProcessHandle \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ZwMapViewOfSection_PhysicalMemory_BaseAddress CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ZwMapViewOfSection_PhysicalMemory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ZwMapViewOfSection_None CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)

PDEVICE_OBJECT pMyDevice;
UNICODE_STRING DeviceName;
UNICODE_STRING SymLinkName;

UCHAR trash[0x200000];

NTSTATUS MyDispatcher(PDEVICE_OBJECT device_object, PIRP irp)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG inputBufferSize, outputBufferSize, ioControlCode;
    UCHAR *inputBuffer = 0, *outputBuffer = 0;
    PIO_STACK_LOCATION irp_stack = IoGetCurrentIrpStackLocation(irp);
    inputBufferSize = irp_stack->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferSize = irp_stack->Parameters.DeviceIoControl.OutputBufferLength;
    if (device_object != pMyDevice)
    {
        status = STATUS_UNSUCCESSFUL;
        return status;
    }
    switch (irp_stack->MajorFunction)
    {
        case IRP_MJ_DEVICE_CONTROL:
            ioControlCode = irp_stack->Parameters.DeviceIoControl.IoControlCode;
            inputBuffer = (UCHAR *)irp->AssociatedIrp.SystemBuffer;
            outputBuffer = (UCHAR *)irp->AssociatedIrp.SystemBuffer;

            if (!inputBuffer)
                break;

            SIZE_T viewSize;
            PVOID viewBase;
            OBJECT_ATTRIBUTES ObjectAttributes;
            UNICODE_STRING PhysMemName;
            NTSTATUS Status;
            HANDLE PhysMemHandle;
            PVOID BaseAddress;
            LARGE_INTEGER Offset;
            SIZE_T ViewSize;

            switch (ioControlCode)
            {
                case ZwMapViewOfSection_SectionHandle_ProcessHandle_BaseAddress:
                    viewSize = 0;
                    ZwMapViewOfSection(*(HANDLE *)inputBuffer, *(HANDLE *)(inputBuffer + 8), *(PVOID **)(inputBuffer + 0xc),
                                       0, 0, NULL, &viewSize, ViewShare, 0, PAGE_READONLY);
                    break;
                case ZwMapViewOfSection_SectionHandle_ProcessHandle:
                    viewSize = 0;
                    ZwMapViewOfSection(*(HANDLE *)inputBuffer, *(HANDLE *)(inputBuffer + 8), &viewBase, 0, 0, NULL,
                                       &viewSize, ViewShare, 0, PAGE_READONLY);
                    break;
                case ZwMapViewOfSection_SectionHandle_BaseAddress:
                    viewSize = 0;
                    ZwMapViewOfSection(*(HANDLE *)inputBuffer, ZwCurrentProcess(), *(PVOID **)(inputBuffer + 0x8), 0, 0,
                                       NULL, &viewSize, ViewShare, 0, PAGE_READONLY);
                    break;
                case ZwMapViewOfSection_SectionHandle:
                    viewSize = 0;
                    ZwMapViewOfSection(*(HANDLE *)inputBuffer, ZwCurrentProcess(), &viewBase, 0, 0, NULL, &viewSize,
                                       ViewShare, 0, PAGE_READONLY);
                    break;
                case ZwMapViewOfSection_PhysicalMemory_ProcessHandle:
                    PhysMemName = RTL_CONSTANT_STRING(L"\\Device\\PhysicalMemory");
                    InitializeObjectAttributes(&ObjectAttributes, &PhysMemName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                               NULL, NULL);
                    Status = ZwOpenSection(&PhysMemHandle, SECTION_ALL_ACCESS, &ObjectAttributes);
                    Offset.QuadPart = 0xa0000;
                    ViewSize = 0x100000 - 0xa0000;
                    BaseAddress = (PVOID)0xa0000;
                    Status = ZwMapViewOfSection(PhysMemHandle, *(HANDLE *)inputBuffer, &BaseAddress, 0, ViewSize, &Offset,
                                                &ViewSize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
                    break;
                case ZwMapViewOfSection_PhysicalMemory_BaseAddress:
                    PhysMemName = RTL_CONSTANT_STRING(L"\\Device\\PhysicalMemory");
                    InitializeObjectAttributes(&ObjectAttributes, &PhysMemName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                               NULL, NULL);
                    Status = ZwOpenSection(&PhysMemHandle, SECTION_ALL_ACCESS, &ObjectAttributes);
                    Offset.QuadPart = 0xa0000;
                    ViewSize = 0x100000 - 0xa0000;
                    Status = ZwMapViewOfSection(PhysMemHandle, NtCurrentProcess(), *(PVOID **)(inputBuffer + 0x8), 0,
                                                ViewSize, &Offset, &ViewSize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
                    break;
                case ZwMapViewOfSection_PhysicalMemory:
                    PhysMemName = RTL_CONSTANT_STRING(L"\\Device\\PhysicalMemory");
                    InitializeObjectAttributes(&ObjectAttributes, &PhysMemName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                               NULL, NULL);
                    Status = ZwOpenSection(&PhysMemHandle, SECTION_ALL_ACCESS, &ObjectAttributes);
                    Offset.QuadPart = 0xa0000;
                    ViewSize = 0x100000 - 0xa0000;
                    BaseAddress = (PVOID)0xa0000;
                    Status = ZwMapViewOfSection(PhysMemHandle, NtCurrentProcess(), &BaseAddress, 0, ViewSize, &Offset,
                                                &ViewSize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
                    break;
                case ZwMapViewOfSection_None:
                    PhysMemName = RTL_CONSTANT_STRING(L"TEST");
                    InitializeObjectAttributes(&ObjectAttributes, &PhysMemName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                               NULL, NULL);
                    Status = ZwOpenSection(&PhysMemHandle, SECTION_ALL_ACCESS, &ObjectAttributes);
                    Offset.QuadPart = 0xa0000;
                    ViewSize = 0x100000 - 0xa0000;
                    BaseAddress = (PVOID)0xa0000;
                    Status = ZwMapViewOfSection(PhysMemHandle, NtCurrentProcess(), &BaseAddress, 0, ViewSize, &Offset,
                                                &ViewSize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
                    break;
                default:
                    break;
            }
            break;
        case IRP_MJ_CREATE:
            break;
        case IRP_MJ_CLOSE:
            break;
        case IRP_MJ_READ:
            break;
        case IRP_MJ_WRITE:
            break;
        default:
            break;
    }
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = outputBufferSize;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}
NTSTATUS MyCreateDevice(PDRIVER_OBJECT driver_object)
{
    NTSTATUS status;
    RtlInitUnicodeString(&DeviceName, device_name);
    RtlInitUnicodeString(&SymLinkName, symlink_name);
    status = IoCreateDevice(driver_object, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, 1, &pMyDevice);
    if (NT_SUCCESS(status))
    {
        driver_object->DeviceObject = pMyDevice;
        status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
        if (NT_SUCCESS(status))
        {
            return status;
        }
    }
    return status;
}
void DriverUnload(PDRIVER_OBJECT db)
{
    IoDeleteSymbolicLink(&SymLinkName);
    IoDeleteDevice(db->DeviceObject);
}
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status = STATUS_SUCCESS;
    driver_object->DriverUnload = DriverUnload;
    status = MyCreateDevice(driver_object);

    driver_object->MajorFunction[IRP_MJ_CREATE] = MyDispatcher;
    driver_object->MajorFunction[IRP_MJ_CLOSE] = MyDispatcher;
    driver_object->MajorFunction[IRP_MJ_READ] = MyDispatcher;
    driver_object->MajorFunction[IRP_MJ_WRITE] = MyDispatcher;
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MyDispatcher;
    return status;
}
