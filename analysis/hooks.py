import angr
import claripy
import utils
import globals

class HookIoStartPacket(angr.SimProcedure):
    # Call DriverStartIo when IoStartPacket is called.
    def run(self, DeviceObject, Irp, Key, CancelFunction):
        if globals.DriverStartIo:
            new_state = self.state.project.factory.call_state(addr=globals.DriverStartIo, args=(DeviceObject, Irp), base_state=self.state)
            globals.simgr.deferred.append(new_state)

class HookIoCreateDevice(angr.SimProcedure):
    def run(self, DriverObject, DeviceExtensionSize, DeviceName, DeviceType, DeviceCharacteristics, Exclusive, DeviceObject):
        # Initialize device object.
        devobjaddr = utils.next_base_addr()
        self.state.globals['device_object_addr'] = devobjaddr
        device_object = claripy.BVS('device_object', 8 * 0x400)
        self.state.memory.store(devobjaddr, device_object, 0x400, disable_actions=True, inspect=False)
        self.state.mem[devobjaddr].DEVICE_OBJECT.Flags = 0
        self.state.mem[DeviceObject].PDEVICE_OBJECT = devobjaddr

        # Initialize device extension.
        new_device_extension_addr = utils.next_base_addr()
        size = self.state.solver.min(DeviceExtensionSize)
        device_extension = claripy.BVV(0, 8 * size)
        self.state.memory.store(new_device_extension_addr, device_extension, size, disable_actions=True, inspect=False)
        self.state.mem[devobjaddr].DEVICE_OBJECT.DeviceExtension = new_device_extension_addr

        # Retrieve the device name.
        device_name_str = utils.read_buffer_from_unicode_string(self.state, DeviceName)
        if (device_name_str == "") and (device_name_str == None):
            return 0
        
        utils.print_info(f'device name: {device_name_str}')
        if "DeviceName" not in globals.basic_info:
            globals.basic_info["DeviceName"] = []
        
        if(device_name_str not in globals.basic_info["DeviceName"]):
            globals.basic_info["DeviceName"].append(device_name_str)
        return 0

class HookIoCreateSymbolicLink(angr.SimProcedure):
    def run(self, SymbolicLinkName, DeviceName):
        # Retrieve the symbolic link name.
        device_name_str = utils.read_buffer_from_unicode_string(self.state, DeviceName)
        if (device_name_str == "") or (device_name_str is None):
            return 0
        
        symbolic_link_str = utils.read_buffer_from_unicode_string(self.state, SymbolicLinkName)
        if (symbolic_link_str == "") and (symbolic_link_str == None):
            return 0
        
        utils.print_info(f'Symbolic link \"{symbolic_link_str}\" to \"{device_name_str}\"')

        if "SymbolicLink" not in globals.basic_info:
            globals.basic_info["SymbolicLink"] = []

        if(symbolic_link_str not in globals.basic_info["SymbolicLink"]):
            globals.basic_info["SymbolicLink"].append(symbolic_link_str)
        return 0
    
class HookIoIs32bitProcess(angr.SimProcedure):
    def run(self):
        return 0

class HookVsnprintf(angr.SimProcedure):
    def run(self, buffer, count, format, argptr):
        return 0

class HookExInitializeResourceLite(angr.SimProcedure):
    def run(self, Resource):
        return 0
    
class HookExQueryDepthSList(angr.SimProcedure):
    def run(self, SListHead):
        return 0
    
class HookExpInterlockedPushEntrySList(angr.SimProcedure):
    def run(self, ListHead, ListEntry):
        return 0
    
class HookExpInterlockedPopEntrySList(angr.SimProcedure):
    def run(self, ListHead, Lock):
        return 0
    
class HookKeWaitForSingleObject(angr.SimProcedure):
    def run(self, Object, WaitReason, WaitMode, Alertable, Timeout):
        return 0
    
class HookRtlWriteRegistryValue(angr.SimProcedure):
    def run(self, RelativeTo, Path, ValueName, ValueType, ValueData, ValueLength):
        return 0
    
class HookIoGetDeviceProperty(angr.SimProcedure):
    def run(self, DeviceObject, DeviceProperty, BufferLength, PropertyBuffer, ResultLength):
        return 0

class HookKeReleaseMutex(angr.SimProcedure):
    def run(self, Mutex, Wait):
        return 0

class HookRtlGetVersion(angr.SimProcedure):
    # Hook RtlGetVersion to bypass version check.
    def run(self, lpVersionInformation):
        ret_addr = hex(self.state.callstack.ret_addr)
        VersionInformation = self.state.mem[lpVersionInformation].struct._OSVERSIONINFOW
        dwMajorVersion = claripy.BVS(f"RtlGetVersion_{ret_addr}", self.state.arch.bits // 2)
        VersionInformation.dwMajorVersion = dwMajorVersion
        dwMinorVersion = claripy.BVS(f"RtlGetVersion_{ret_addr}", self.state.arch.bits // 2)
        VersionInformation.dwMinorVersion = dwMinorVersion
        dwBuildNumber = claripy.BVS(f"RtlGetVersion_{ret_addr}", self.state.arch.bits // 2)
        VersionInformation.dwBuildNumber = dwBuildNumber
        return 0

class HookExGetPreviousMode(angr.SimProcedure):
    def run(self):
        return 1
    
class HookKeQueryActiveGroupCount(angr.SimProcedure):
    def run(self):
        return 1

class HookKeQueryActiveProcessors(angr.SimProcedure):
    def run(self):
        return 1
    
class HookKeQueryActiveProcessorCountEx(angr.SimProcedure):
    def run(self, GroupNumber):
        return 1
    
class HookRtlIsNtDdiVersionAvailable(angr.SimProcedure):
    def run(self):
        return 1
    
class HookExInterlockedPopEntrySList(angr.SimProcedure):
    def run(self, Resource):
        return 0

class HookPsGetVersion(angr.SimProcedure):
    # Hook PsGetVersion to bypass version check.
    def run(self, MajorVersion, MinorVersion, BuildNumber, CSDVersion):
        ret_addr = hex(self.state.callstack.ret_addr)
        major_version = claripy.BVS(f"PsGetVersion_{ret_addr}", self.state.arch.bits)
        self.state.memory.store(MajorVersion, major_version, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
        minor_version = claripy.BVS(f"PsGetVersion_{ret_addr}", self.state.arch.bits)
        self.state.memory.store(MinorVersion, minor_version, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
        build_number = claripy.BVS(f"PsGetVersion_{ret_addr}", self.state.arch.bits)
        self.state.memory.store(BuildNumber, build_number, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
        csd_version= claripy.BVS(f"PsGetVersion_{ret_addr}", self.state.arch.bits * 2)
        self.state.memory.store(CSDVersion, csd_version, self.state.arch.bytes * 2, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
        return 0

class HookZwQueryInformationProcess(angr.SimProcedure):
    def run(self, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength):
        if not ProcessInformationLength.symbolic and self.state.solver.eval(ProcessInformationLength) == 0:
            return 0xC0000004
        return 0

class HookDoNothing(angr.SimProcedure):
    def run(self):
        utils.print_debug(f'HookDoNothing')
        return 0

class HookMmGetSystemRoutineAddress(angr.SimProcedure):
    def run(self, SystemRoutineName):
        try:
            wstring_addr = self.state.mem[SystemRoutineName].struct._UNICODE_STRING.Buffer.resolved
            SystemRoutineName_wstring = self.state.mem[wstring_addr].wstring.concrete
        except:
            SystemRoutineName_wstring = ""

        hooks = {
            "ZwQueryInformationProcess": HookZwQueryInformationProcess,
        }

        for name, proc in hooks.items():
            if name == SystemRoutineName_wstring:
                addr = utils.next_base_addr()
                globals.proj.hook(addr, proc(cc=globals.mycc))
                return addr

        return globals.DO_NOTHING
    
class HookFltGetRoutineAddress(angr.SimProcedure):
    # Return the function address acquired by FltGetRoutineAddress.
    def run(self, FltMgrRoutineName):
        return globals.DO_NOTHING
    
class HookProbeForRead(angr.SimProcedure):
    # Tag the tainted buffer that is validated with ProbeForRead.
    def run(self, Address, Length, Alignment):
        if globals.phase == 2:
            if 'tainted_ProbeForRead' in self.state.globals and utils.tainted_buffer(Address):
                asts = [i for i in Address.children_asts()]
                target_base = asts[0] if len(asts) > 1 else Address

                ret_addr = hex(self.state.callstack.ret_addr)
                self.state.globals['tainted_ProbeForRead'] += (str(target_base), )

class HookProbeForWrite(angr.SimProcedure):
    # Tag the tainted buffer that is validated with ProbeForWrite.
    def run(self, Address, Length, Alignment):
        if globals.phase == 2:
            if 'tainted_ProbeForWrite' in self.state.globals and utils.tainted_buffer(Address):
                asts = [i for i in Address.recursive_children_asts]
                target_base = asts[0] if len(asts) > 1 else Address
                ret_addr = hex(self.state.callstack.ret_addr)
                self.state.globals['tainted_ProbeForWrite'] += (str(target_base), )

class HookMmIsAddressValid(angr.SimProcedure):
    # Tag the tainted buffer that is validated with MmIsAddressValid.
    def run(self, VirtualAddress):
        if globals.phase == 2:
            if 'tainted_MmIsAddressValid' in self.state.globals and utils.tainted_buffer(VirtualAddress):
                asts = [i for i in VirtualAddress.recursive_children_asts]
                target_base = asts[0] if len(asts) > 1 else VirtualAddress
                ret_addr = hex(self.state.callstack.ret_addr)
                self.state.globals['tainted_MmIsAddressValid'] += (str(target_base), )
        return 1

class HookZwOpenSection(angr.SimProcedure):
    def run(self, SectionHandle, DesiredAccess, ObjectAttributes):
        ret_addr = hex(self.state.callstack.ret_addr)

        # Trace the handle opened by ZwOpenSection.
        handle = claripy.BVS(f'ZwOpenSection_{ret_addr}', self.state.arch.bits)
        self.state.memory.store(SectionHandle, handle, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)

        # Get the object name.
        object_name_struct = self.state.mem[ObjectAttributes].OBJECT_ATTRIBUTES.ObjectName.deref
        try:
            object_name = object_name_struct.Buffer.deref.wstring.concrete
        except:
            return 0

        # Store the handle and object name.
        self.state.globals['open_section_handles'] += ((handle, object_name),)
        return 0

class HookRtlInitUnicodeString(angr.SimProcedure):
    def run(self, DestinationString, SourceString):
        ret_addr = hex(self.state.callstack.ret_addr)
        
        # Resolve the SourceString.
        try:
            if SourceString.symbolic and utils.tainted_buffer(SourceString):
                raise
            string_orig = self.state.mem[SourceString].wstring.resolved
        except:
            string_orig = claripy.Concat(claripy.BVS(f"RtlInitUnicodeString_{ret_addr}", 8 * 10), claripy.BVV(0, 16))

        # Initalize the DestinationString.
        byte_length = string_orig.length // 8
        new_buffer = utils.next_base_addr()
        self.state.memory.store(new_buffer, string_orig, byte_length, disable_actions=True, inspect=False)
        unistr = self.state.mem[DestinationString].struct._UNICODE_STRING
        self.state.memory.store(DestinationString, claripy.BVV(0, unistr._type.size), unistr._type.size // 8, disable_actions=True, inspect=False)
        unistr.Length = byte_length
        unistr.MaximumLength = byte_length
        unistr.Buffer = new_buffer

        # Store the unicode string if it is tainted.
        if (not SourceString.symbolic and utils.tainted_buffer(self.state.memory.load(SourceString, 0x10, disable_actions=True, inspect=False))) or utils.tainted_buffer(SourceString) or str(SourceString) in self.state.globals['tainted_unicode_strings']:
            self.state.globals['tainted_unicode_strings'] += (str(unistr.Buffer.resolved), )

        return 0


class HookRtlCopyUnicodeString(angr.SimProcedure):
    def run(self, DestinationString, SourceString):
        # Restrict the length of the unicode string.
        src_unistr = self.state.mem[SourceString].struct._UNICODE_STRING
        src_len = src_unistr.Length
        conc_src_len = self.state.solver.min(src_len.resolved)
        self.state.solver.add(src_len.resolved == conc_src_len)

        dst_unistr = self.state.mem[DestinationString].struct._UNICODE_STRING
        dst_maxi_len = src_unistr.MaximumLength
        conc_dst_max_len = self.state.solver.min(dst_maxi_len.resolved)
        self.state.solver.add(dst_maxi_len.resolved == conc_dst_max_len)

        # Copy the unicode string.
        memcpy = angr.procedures.SIM_PROCEDURES['libc']['memcpy']
        self.inline_call(memcpy, dst_unistr.Buffer.resolved, src_unistr.Buffer.resolved, min(conc_src_len, conc_dst_max_len))

        # Store the unicode string if it is tainted.
        if utils.tainted_buffer(SourceString) or str(SourceString) in self.state.globals['tainted_unicode_strings']:
            self.state.globals['tainted_unicode_strings'] += (str(dst_unistr.Buffer.resolved), )

        return 0
            

class HookExAllocatePool(angr.SimProcedure):
    # Trace the allocated buffer by ExAllocatePool.
    def run(self, PoolType, NumberOfBytes):
        if globals.phase == 2:
            ret_addr = hex(self.state.callstack.ret_addr)
            allocated_ptr = claripy.BVS(f"ExAllocatePool_{ret_addr}", self.state.arch.bits)
            return allocated_ptr
        else:
            return utils.next_base_addr()
    
class HookExAllocatePool2(angr.SimProcedure):
    # Trace the allocated buffer by ExAllocatePool2.
    def run(self, Flags, NumberOfBytes, Tag):
        if globals.phase == 2:
            ret_addr = hex(self.state.callstack.ret_addr)
            allocated_ptr = claripy.BVS(f"ExAllocatePool2_{ret_addr}", self.state.arch.bits)
            return allocated_ptr
        else:
            return utils.next_base_addr()
    
class HookExAllocatePool3(angr.SimProcedure):
    # Trace the allocated buffer by ExAllocatePool3.
    def run(self, Flags, NumberOfBytes, Tag, ExtendedParameters, ExtendedParametersCount):
        if globals.phase == 2:
            ret_addr = hex(self.state.callstack.ret_addr)
            allocated_ptr = claripy.BVS(f"ExAllocatePool3_{ret_addr}", self.state.arch.bits)
            return allocated_ptr
        else:
            return utils.next_base_addr()

class HookExAllocatePoolWithTag(angr.SimProcedure):
    # Trace the allocated buffer by ExAllocatePoolWithTag.
    def run(self, PoolType, NumberOfBytes, Tag):
        if globals.phase == 2:
            ret_addr = hex(self.state.callstack.ret_addr)
            allocated_ptr = claripy.BVS(f"ExAllocatePoolWithTag_{ret_addr}", self.state.arch.bits)
            return allocated_ptr
        else:
            return utils.next_base_addr()
    
class HookMmAllocateNonCachedMemory(angr.SimProcedure):
    # Trace the allocated buffer by MmAllocateNonCachedMemory.
    def run(self, NumberOfBytes):
        if globals.phase == 2:
            ret_addr = hex(self.state.callstack.ret_addr)
            allocated_ptr = claripy.BVS(f"MmAllocateNonCachedMemory_{ret_addr}", self.state.arch.bits)
            return allocated_ptr
        else:
            return utils.next_base_addr()
    
class HookMmAllocateContiguousMemorySpecifyCache(angr.SimProcedure):
    # Trace the allocated buffer by MmAllocateContiguousMemorySpecifyCache.
    def run(self, NumberOfBytes, LowestAcceptableAddress, HighestAcceptableAddress, BoundaryAddressMultiple, CacheType):
        if globals.phase == 2:
            ret_addr = hex(self.state.callstack.ret_addr)
            allocated_ptr = claripy.BVS(f"MmAllocateContiguousMemorySpecifyCache_{ret_addr}", self.state.arch.bits)
            return allocated_ptr
        else:
            return utils.next_base_addr()

class HookMmMapIoSpace(angr.SimProcedure):
    def run(self, PhysicalAddress, NumberOfBytes, MEMORY_CACHING_TYPE):
        if globals.phase == 2:
            # Check if we can control the parameters of MmMapIoSpace.
            ret_addr = hex(self.state.callstack.ret_addr)
            if utils.tainted_buffer(PhysicalAddress) and utils.tainted_buffer(NumberOfBytes):
                utils.print_vuln('map physical memory', 'MmMapIoSpace - PhysicalAddress and NumberOfBytes controllable', self.state, {'PhysicalAddress': str(PhysicalAddress), 'NumberOfBytes': str(NumberOfBytes)}, {'return address': ret_addr})
            elif utils.tainted_buffer(PhysicalAddress) and not utils.tainted_buffer(NumberOfBytes):
                utils.print_vuln('map physical memory', 'MmMapIoSpace - PhysicalAddress controllable', self.state, {'PhysicalAddress': str(PhysicalAddress), 'NumberOfBytes': str(NumberOfBytes)}, {'return address': ret_addr})
            elif not utils.tainted_buffer(PhysicalAddress) and utils.tainted_buffer(NumberOfBytes):
                utils.print_vuln('map physical memory', 'MmMapIoSpace - NumberOfBytes controllable', self.state, {'PhysicalAddress': str(PhysicalAddress), 'NumberOfBytes': str(NumberOfBytes)}, {'return address': ret_addr})

        return utils.next_base_addr()
    
class HookMmMapIoSpaceEx(angr.SimProcedure):
    def run(self, PhysicalAddress, NumberOfBytes, Protect):
        if globals.phase == 2:
            # Check if we can control the parameters of MmMapIoSpaceEx.
            ret_addr = hex(self.state.callstack.ret_addr)
            if utils.tainted_buffer(PhysicalAddress) and utils.tainted_buffer(NumberOfBytes):
                utils.print_vuln('map physical memory', 'MmMapIoSpaceEx - PhysicalAddress and NumberOfBytes controllable', self.state, {'PhysicalAddress': str(PhysicalAddress), 'NumberOfBytes': str(NumberOfBytes)}, {'return address': ret_addr})
            elif utils.tainted_buffer(PhysicalAddress) and not utils.tainted_buffer(NumberOfBytes):
                utils.print_vuln('map physical memory', 'MmMapIoSpaceEx - PhysicalAddress controllable', self.state, {'PhysicalAddress': str(PhysicalAddress), 'NumberOfBytes': str(NumberOfBytes)}, {'return address': ret_addr})
        
        return utils.next_base_addr()

class HookHalTranslateBusAddress(angr.SimProcedure):
    def run(self, InterfaceType, BusNumber, BusAddress, AddressSpace, TranslatedAddress):
        self.state.memory.store(TranslatedAddress, BusNumber + BusAddress, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
        return 1

class HookZwMapViewOfSection(angr.SimProcedure):
    def run(self, SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect):
        if globals.phase == 2:
            # Check if we can control the parameters of ZwMapViewOfSection.
            if SectionHandle.symbolic and (ProcessHandle.symbolic or self.state.solver.eval(ProcessHandle == -1) or BaseAddress.symbolic or (CommitSize.symbolic and ViewSize.symbolic)):
                ret_addr = hex(self.state.callstack.ret_addr)
                if any('ZwOpenSection' not in v for v in SectionHandle.variables):
                    utils.print_vuln('map physical memory', 'ZwMapViewOfSection - SectionHandle controllable', self.state, {'SectionHandle': str(SectionHandle), 'ProcessHandle': str(ProcessHandle), 'BaseAddress': str(BaseAddress), 'CommitSize': str(CommitSize), 'ViewSize': str(ViewSize)}, {'return address': ret_addr})
                else:
                    handles = dict(self.state.globals['open_section_handles'])
                    if SectionHandle not in handles:
                        utils.print_vuln('map physical memory', 'ZwMapViewOfSection - unknown handle', self.state, {'SectionHandle': str(SectionHandle), 'ProcessHandle': str(ProcessHandle), 'BaseAddress': str(BaseAddress), 'CommitSize': str(CommitSize), 'ViewSize': str(ViewSize)}, {'return address': ret_addr})
                    elif handles[SectionHandle] == '\\Device\\PhysicalMemory':
                        utils.print_vuln('map physical memory', 'ZwMapViewOfSection - map \\Device\\PhysicalMemory', self.state, {'SectionHandle': str(SectionHandle), 'ProcessHandle': str(ProcessHandle), 'BaseAddress': str(BaseAddress), 'CommitSize': str(CommitSize), 'ViewSize': str(ViewSize)}, {'return address': ret_addr})
        return 0
            

class HookZwOpenProcess(angr.SimProcedure):
    def run(self, ProcessHandle, DesiredAccess, ObjectAttributes, ClientId):
        if globals.phase == 2:
            # Resolve ClientId and Attrbutes of ObjectAttributes.
            cid = self.state.mem[ClientId].struct._CLIENT_ID.resolved
            Attributes = self.state.mem[ObjectAttributes].struct._OBJECT_ATTRIBUTES.Attributes.resolved

            handle = claripy.BVS(f"ZwOpenProcess_{hex(self.state.callstack.ret_addr)}", self.state.arch.bits)
            self.state.memory.store(ProcessHandle, handle, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)

            # Attrbitues is not OBJ_FORCE_ACCESS_CHECK.
            tmp_state = self.state.copy()
            tmp_state.solver.add(Attributes & 1024 == 0)

            # Check if we can control the parameters of ZwOpenProcess.
            if tmp_state.satisfiable() and (utils.tainted_buffer(ClientId) or utils.tainted_buffer(cid.UniqueProcess)):
                ret_addr = hex(self.state.callstack.ret_addr)
                self.state.globals['tainted_handles'] += (str(handle), )
                utils.print_vuln('controllable process handle', 'ZwOpenProcess - ClientId controllable', self.state, {'ClientId': str(ClientId), 'ClientId.UniqueProcess': str(cid.UniqueProcess)}, {'return address': ret_addr})
        
        return 0

class HookPsLookupProcessByProcessId(angr.SimProcedure):
    def run(self, ProcessId, Process):
        if globals.phase == 2:
            # Store the EPROCESS if ProcessId is tainted.
            if utils.tainted_buffer(ProcessId):
                ret_addr = hex(self.state.callstack.ret_addr)
                eprocess = claripy.BVS(f"PsLookupProcessByProcessId_{ret_addr}", self.state.arch.bits)
                self.state.memory.store(Process, eprocess, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
                self.state.globals['tainted_eprocess'] += (str(eprocess), )
        return 0

class HookObOpenObjectByPointer(angr.SimProcedure):
    def run(self, Object, HandleAttributes, PassedAccessState, DesiredAccess, ObjectType, AccessMode, Handle):
        if globals.phase == 2:
            ret_addr = hex(self.state.callstack.ret_addr)
            handle = claripy.BVS(f"ObOpenObjectByPointer_{ret_addr}", self.state.arch.bits)
            self.state.memory.store(Handle, handle,  self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)

            # HandleAttributes is not OBJ_FORCE_ACCESS_CHECK.
            tmp_state = self.state.copy()
            tmp_state.solver.add(HandleAttributes & 1024 == 0)
            # Check if we can control the parameters of ObOpenObjectByPointer.
            if tmp_state.satisfiable() and ((str(Object) in self.state.globals['tainted_eprocess']) or utils.tainted_buffer(Object)):
                self.state.globals['tainted_handles'] += (str(handle), )
                utils.print_vuln('controllable process handle', 'ObOpenObjectByPointer - Object controllable', self.state, {'Object': str(Object), 'Handle': str(Handle)}, {'return address': ret_addr})
        return 0

class HookZwTerminateProcess(angr.SimProcedure):
    def run(self, ProcessHandle, ExitStatus):
        ret_addr = hex(self.state.callstack.ret_addr)
        if str(ProcessHandle) in self.state.globals['tainted_handles']:
            utils.print_vuln('arbitrary process termination', 'ZwTerminateProcess - handle controllable', self.state, {'ProcessHandle': str(ProcessHandle)}, {'return address': ret_addr})
    
class HookMemcpy(angr.SimProcedure):
    def run(self, dest, src, size):
        ret_addr = hex(self.state.callstack.ret_addr)
        dest_asts = [i for i in dest.children_asts()]
        dest_base = dest_asts[0] if len(dest_asts) > 1 else dest
        dest_vars = dest.variables

        src_asts = [i for i in src.children_asts()]
        src_base = src_asts[0] if len(src_asts) > 1 else src
        src_vars = src.variables

        # Check whether the src or dest address can be controlled.
        if ('*' in str(dest) and utils.tainted_buffer(dest) and str(dest_base) not in self.state.globals['tainted_ProbeForWrite'] and len(dest_vars) == 1) or ('*' in str(src) and utils.tainted_buffer(src) and str(src_base) not in self.state.globals['tainted_ProbeForRead'] and len(src_vars) == 1):
            utils.print_vuln('dest or src controllable', 'memcpy/memmove', self.state, {'dest': str(dest), 'src': str(src), 'size': str(size)}, {'return address': ret_addr})

        # Buffer overflow detected if the size can be controlled and the destination address is not symbolic to avoid false positive.
        tmp_state = self.state.copy()
        tmp_state.solver.add(size == 0x10000000)
        if utils.tainted_buffer(size) and tmp_state.satisfiable() and not dest.symbolic:
            utils.print_vuln('buffer overflow', 'memcpy/memmove', self.state, {'dest': str(dest), 'src': str(src), 'size': str(size)}, {'return address': ret_addr})

        # Call original memcpy after analysis.
        size_min = self.state.solver.min(size)
        if size_min > 0x1000:
            size_min = 0x1000
        elif size.symbolic and size_min < 0x10:
            tmp_state = self.state.copy()
            tmp_state.solver.add(size == 0x10)
            if tmp_state.satisfiable():
                size_min = 0x10

        angr.procedures.SIM_PROCEDURES['libc']['memcpy'](cc=self.cc).execute(self.state, arguments=(dest, src, size_min))

        return 0

class HookZwDeleteFile(angr.SimProcedure):
    def run(self, ObjectAttributes):
        if globals.phase == 2:
            # Check if we can control the parameters of ZwDeleteFile.
            utils.analyze_ObjectAttributes('ZwDeleteFile', self.state, ObjectAttributes)

        return 0

class HookZwOpenFile(angr.SimProcedure):
    def run(self, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions):
        if globals.phase == 2:
            # Check if we can control the parameters of ZwOpenFile.
            utils.analyze_ObjectAttributes('ZwOpenFile', self.state, ObjectAttributes)

        return 0

class HookZwCreateFile(angr.SimProcedure):
    def run(self, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength):
        if globals.phase == 2:
            # Check if we can control the parameters of ZwCreateFile.
            utils.analyze_ObjectAttributes('ZwCreateFile', self.state, ObjectAttributes)

        return 0
    
class HookZwWriteFile(angr.SimProcedure):
    def run(self, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key):
        return 0

class HookIoCreateFile(angr.SimProcedure):
    def run(self, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, Disposition, CreateOptions, EaBuffer, EaLength, CreateFileType, InternalParameters, Options):
        if globals.phase == 2:
            # Check if we can control the parameters of IoCreateFile.
            utils.analyze_ObjectAttributes('IoCreateFile', self.state, ObjectAttributes)

        return 0

class HookIoCreateFileEx(angr.SimProcedure):
    def run(self, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, Disposition, CreateOptions, EaBuffer, EaLength, CreateFileType, InternalParameters, Options, DriverContext):
        if globals.phase == 2:
            # Check if we can control the parameters of IoCreateFileEx.
            utils.analyze_ObjectAttributes('IoCreateFileEx', self.state, ObjectAttributes)

        return 0
    
class HookIoCreateFileSpecifyDeviceObjectHint(angr.SimProcedure):
    def run(self, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, Disposition, CreateOptions, EaBuffer, EaLength, CreateFileType, InternalParameters, Options, DeviceObject):
        if globals.phase == 2:
            # Check if we can control the parameters of IoCreateFileSpecifyDeviceObjectHint.
            utils.analyze_ObjectAttributes('IoCreateFileSpecifyDeviceObjectHint', self.state, ObjectAttributes)

        return 0

class HookZwQueryInformationFile(angr.SimProcedure):
    def run(self, FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass):
        ret_addr = hex(self.state.callstack.ret_addr)
        isb = self.state.mem[IoStatusBlock].struct._IO_STATUS_BLOCK
        isb.u.Status = 0
        isb.Information = utils.next_base_addr()
        if self.state.solver.eval(FileInformationClass) == 9:
            fi = self.state.mem[FileInformation].struct._FILE_NAME_INFORMATION
            fi.FileNameLength = 0x10
        return 0
    
class HookZwCreateKey(angr.SimProcedure):
    def run(self, KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition):
        return 0
    
class HookZwOpenKey(angr.SimProcedure):
    def run(self, KeyHandle, DesiredAccess, ObjectAttributes):
        return 0
    
class HookZwDeleteValueKey(angr.SimProcedure):
    def run(self, KeyHandle, ValueName):
        return 0
    
class HookZwQueryValueKey(angr.SimProcedure):
    def run(self, KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength):
        return 0
    

class HookNdisRegisterProtocolDriver(angr.SimProcedure):
    def run(self, ProtocolDriverContext, ProtocolCharacteristics, NdisProtocolHandle):
        self.state.memory.store(NdisProtocolHandle, 0x87, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
        return 0
    
class HookObCloseHandle(angr.SimProcedure):
    def run(self, Handle, PreviousMode):
        if (globals.phase != 2) or (not utils.tainted_buffer(Handle)):
            return 0
        ret_addr = hex(self.state.callstack.ret_addr)

        attached_process = self.state.globals['tainted_process_context_changing'] != ()

        if not attached_process:
            return 0
        
        vuln_title = "ObCloseHandle - Close controllable handle in different process context"
        vuln_description = "ObCloseHandle - Tainted handle in different process context"
        vuln_parameters = {'Handle': str(Handle)}
        vuln_others = {'return address': ret_addr}
        list_of_constraints = list()

        # Process explorer specific check
        for tainted_object in self.state.globals['tainted_objects']:
            for constraint in self.state.solver.constraints:
                if constraint.op != '__eq__':
                    continue
                if any(v in tainted_object for v in constraint.variables):
                    list_of_constraints.append(str(constraint))

        if len(list_of_constraints) > 0:
            vuln_others['obj_constraints'] = list_of_constraints

        utils.print_vuln(vuln_title, vuln_description, self.state, vuln_parameters, vuln_others)
        return 0

class HookKeStackAttachProcess(angr.SimProcedure):
    def run(self, PROCESS, ApcState):
        if globals.phase != 2:
            return 0
        
        ret_addr = hex(self.state.callstack.ret_addr)

        # Check if the eprocess is tainted (from the PsLookupProcessByProcessId)
        if ('tainted_eprocess' in self.state.globals) and (str(PROCESS) in self.state.globals['tainted_eprocess']):
            # The "process" element was tainted, so we consider it tainted also in this function.
            # In addition, we can consider that the process context is mutating by creating a new global variable.
            # Adding the tainted PROCESS to the global variable to track changes in the process context.
            self.state.globals['tainted_process_context_changing'] += (str(PROCESS), )
        
        # Create a symbolic variable for propagation (out parameter)
        apcstate = claripy.BVS(f'KeStackAttachProcess_{ret_addr}', self.state.arch.bits)
        self.state.memory.store(ApcState, apcstate, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)

        return 0

class HookObReferenceObjectByHandle(angr.SimProcedure):
    # Trace the handle opened by ObReferenceObjectByHandle.
    def run(self, Handle, DesiredAccess, ObjectType, AccessMode, Object, HandleInformation):
        ret_addr = hex(self.state.callstack.ret_addr)
        object = claripy.BVS(f"ObReferenceObjectByHandle_{ret_addr}", self.state.arch.bits)
        self.state.memory.store(Object, object, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)

        # With a tainted handle referencing a process, we propagate the taint to the newly created "object"
        if (globals.star_ps_process_type is not None) and self.state.solver.eval(ObjectType == globals.star_ps_process_type) and utils.tainted_buffer(Handle):
            self.state.globals['tainted_eprocess'] += (str(object), )
        return 0