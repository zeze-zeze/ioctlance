#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>

#define symlink_name L"\\??\\ZwOpenProcess"
#define device_name L"\\device\\ZwOpenProcess"

#define ZwOpenProcess_ClientId CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ZwOpenProcess_None CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ZwOpenProcess_UniqueProcess CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PsLookupProcessByProcessId_ProcessId CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PsLookupProcessByProcessId_None CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

PDEVICE_OBJECT pMyDevice;
UNICODE_STRING DeviceName;
UNICODE_STRING SymLinkName;

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

            OBJECT_ATTRIBUTES objAttr;
            CLIENT_ID clientId;
            HANDLE processHandle;
            PEPROCESS p;
            HANDLE h;

            switch (ioControlCode)
            {
                case ZwOpenProcess_ClientId:
                    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
                    ZwOpenProcess(&processHandle, PROCESS_ALL_ACCESS, &objAttr, *(PCLIENT_ID *)inputBuffer);
                    break;
                case ZwOpenProcess_None:
                    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
                    clientId.UniqueProcess = (HANDLE)4;
                    clientId.UniqueThread = NULL;
                    ZwOpenProcess(&processHandle, PROCESS_ALL_ACCESS, &objAttr, &clientId);
                    break;
                case ZwOpenProcess_UniqueProcess:
                    clientId.UniqueProcess = *(HANDLE *)inputBuffer;
                    clientId.UniqueThread = NULL;
                    ZwOpenProcess(&processHandle, PROCESS_ALL_ACCESS, &objAttr, &clientId);
                    break;
                case PsLookupProcessByProcessId_ProcessId:
                    PsLookupProcessByProcessId(*(HANDLE *)inputBuffer, &p);
                    ObOpenObjectByPointer(p, 0x200, 0, 0x10000000, (POBJECT_TYPE)PsProcessType, 0, &h);
                    break;
                case PsLookupProcessByProcessId_None:
                    PsLookupProcessByProcessId((HANDLE)4, &p);
                    ObOpenObjectByPointer(p, 0x200, 0, 0x10000000, (POBJECT_TYPE)PsProcessType, 0, &h);
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
