irp_addr = 0x1337000
irsp_addr = 0x6000000
mycc = None

phase = 1
DriverStartIo = 0
ioctl_handler = 0
DO_NOTHING = 0
INIT_FIRST_ADDR = 0x444f0000
FIRST_ADDR = 0x444f0000

NPD_TARGETS = ['SystemBuffer', 'Type3InputBuffer', 'UserBuffer', 'ExAllocatePool_0x', 'ExAllocatePool2_0x', 'ExAllocatePool3_0x', 'ExAllocatePoolWithTag_0x', 'MmAllocateNonCachedMemory_0x', 'MmAllocateContiguousMemorySpecifyCache_0x']
SystemBuffer = None
Type3InputBuffer = None
UserBuffer = None
InputBufferLength = None
OutputBufferLength = None
IoControlCode = None

args = None

DOS_DEVICES = ['\\DosDevices\\'.encode('utf-16le'), '\\??\\'.encode('utf-16le')]

proj = None
cfg = None
simgr = None

eval_upto = 3
vulns_unique = set()
driver_info = {}
basic_info = {}
vulns_info = []
error_msgs = []