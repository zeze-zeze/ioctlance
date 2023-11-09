#include <ntddk.h>
#include <ntstrsafe.h>
#include <intrin.h>

#define symlink_name L"\\??\\writemsr"
#define device_name L"\\device\\writemsr"

#define WRITEMSR_CANNOT_CONTROL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define WRITEMSR_CONSTRAINT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

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

            switch (ioControlCode)
            {
                case WRITEMSR_CANNOT_CONTROL:
                    DbgPrint("%c", *inputBuffer);
                    __writemsr(100, 100);
                    break;
                case WRITEMSR_CONSTRAINT:
                    DbgPrint("%c", *inputBuffer);
                    if (*(int *)inputBuffer == 0x8787)
                        __writemsr(*(int *)inputBuffer, 100);
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
