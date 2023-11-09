#include <ntddk.h>
#include <ntstrsafe.h>

#define symlink_name L"\\??\\rtlinitunicodestring"
#define device_name L"\\device\\rtlinitunicodestring"

#define RtlInitUnicodeString_NotNullTerminated CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define RtlInitUnicodeString_NullTerminated CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

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
            switch (ioControlCode)
            {
                case RtlInitUnicodeString_NotNullTerminated:
                    if (inputBuffer)
                    {
                        UNICODE_STRING DestinationString;
                        RtlInitUnicodeString(&DestinationString, (PCWSTR)inputBuffer);
                    }
                    break;
                case RtlInitUnicodeString_NullTerminated:
                    if (inputBuffer)
                    {
                        UNICODE_STRING DestinationString;
                        *(inputBuffer + 0) = 'a';
                        *(inputBuffer + 0x1) = 'a';
                        *(inputBuffer + 0x2) = 'a';
                        *(inputBuffer + 0x3) = 'a';
                        *(inputBuffer + 0x4) = 'a';
                        *(inputBuffer + 0x5) = 'a';
                        *(inputBuffer + 0x6) = 'a';
                        *(inputBuffer + 0x7) = 'a';
                        *(inputBuffer + 0xf) = 0;
                        *(inputBuffer + 0x10) = 0;
                        RtlInitUnicodeString(&DestinationString, (PCWSTR)inputBuffer);
                    }
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
