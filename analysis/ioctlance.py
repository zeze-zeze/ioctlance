from importlib import reload
import utils
import globals
import hooks
import breakpoints
import opcodes
import techniques
import argparse
import time
import ipdb
import resource
import IPython
import sys
import claripy
import json
import archinfo
import kernel_types
import angr
import subprocess
import re
import logging
import os
from io import StringIO
from pathlib import Path

from angr.exploration_techniques.director import ExecuteAddressGoal
import logging.config

logging.config.dictConfig({
    'version': 1,
    'disable_existing_loggers': True,
})
reload(logging)

def find_ioctl_handler():
    globals.phase = 1
    driver_object_addr = utils.next_base_addr()
    registry_path_addr = utils.next_base_addr()

    # Start from DriverEntry.
    state = globals.proj.factory.call_state(globals.proj.entry, driver_object_addr, registry_path_addr, cc=globals.mycc)
    
    # Here we cannot use list, or it will be passed by reference.
    state.globals['open_section_handles'] = ()
    state.globals['tainted_unicode_strings'] = ()
    state.globals['ioctl_handler'] = 0
    
    # Symbolize the data section to find the ioctl handler, but it increases the memory consumption.
    global_var = int(globals.args.global_var, 16)
    if global_var:
        for segment in globals.proj.loader.main_object.segments:
            if '.data' in segment.name:
                size = segment.memsize if segment.memsize <= global_var  else global_var
                data = claripy.BVS('.data', 8 * size).reversed
                state.memory.store(segment.vaddr, data, size)

    if globals.args.complete:
        driver_object = claripy.BVS('driver_object', 8 * 0x100)
        state.memory.store(driver_object_addr, driver_object)
        registry_path = claripy.BVS('registry_path', 8 * 0x100)
        state.memory.store(registry_path_addr, registry_path)

    # Detect IRP_MJ_DEVICE_CONTROL function pointer written.
    state.inspect.b('mem_write', mem_write_address=driver_object_addr + (0xe0 if globals.proj.arch.name == archinfo.ArchAMD64.name else 0x70), when=angr.BP_AFTER, action=breakpoints.b_mem_write_ioctl_handler)
    state.inspect.b('mem_write', mem_write_address=driver_object_addr + (0x60 if globals.proj.arch.name == archinfo.ArchAMD64.name else 0x30), when=angr.BP_AFTER, action=breakpoints.b_mem_write_DriverStartIo)
    state.inspect.b('call', when=angr.BP_BEFORE, action=breakpoints.b_call)

    globals.simgr = globals.proj.factory.simgr(state)
    globals.simgr.use_technique(angr.exploration_techniques.DFS())

    # Set loop bound.
    if globals.args.bound:
        globals.simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=globals.cfg, functions=None, bound=globals.args.bound))
        globals.simgr.use_technique(angr.exploration_techniques.LocalLoopSeer(bound=globals.args.bound))
    
    # Set length limit.
    if globals.args.length:
        globals.simgr.use_technique(angr.exploration_techniques.LengthLimiter(globals.args.length))

    # Set state explosion detection threshold.
    ed = techniques.ExplosionDetector(threshold=10000)
    globals.simgr.use_technique(ed)

    def filter_func(s):
        # Return false if ioctl handler not found.
        if not s.globals['ioctl_handler']:
            return False
        
        # If the complete mode on, we need to keep analyzing until the return value is STATUS_SUCCESS.
        if globals.args.complete:
            retval = globals.mycc.return_val(angr.types.BASIC_TYPES['long int']).get_value(s)
            return s.solver.satisfiable(extra_constraints=[retval == 0])
        else:
            return True

    # Start symbolic execution to find the ioctl handler.
    for i in range(0x100000):
        try:
            globals.simgr.step(num_inst=1)
        except Exception as e:
            utils.print_error(f'error on state {globals.simgr.active}: {str(e)}')
            globals.simgr.move(from_stash='active', to_stash='_Drop')

        utils.print_debug(f'simgr: {globals.simgr}\n\tactive: {globals.simgr.active}\n\tdeferred: {globals.simgr.deferred}\n\terrored: {globals.simgr.errored}\n\tdeadneded: {globals.simgr.deadended}')
        
        # If a state reach deadended, we check if the condition is satisfied with filter_func.
        globals.simgr.move(from_stash='deadended', to_stash='found', filter_func=filter_func)

        # Once there is a state in the found stash, or there is no active and deferred states, we break the loop.
        if len(globals.simgr.found) or (not len(globals.simgr.active) and not len(globals.simgr.deferred)):
            break
    else:
        utils.print_error('ioctl handler not found')
    
    if globals.simgr.errored:
        for s in globals.simgr.errored:
            utils.print_error(f'{repr(s)}')

    # Return the ioctl handler address and the state.
    if len(globals.simgr.found):
        success_state = globals.simgr.found[0]
        return globals.ioctl_handler, success_state
    else:
        return globals.ioctl_handler, None

def fix_object_type_import(state: angr.SimState, object_type_name: str, object_type_import):    
    if not object_type_import:
        return None
    
    # An "object_type_import" points to a kernel memory containing our kernel-defined *ObjectType, which ioctlance intialize to 0
    ps_object_type = state.memory.load(object_type_import, state.arch.bytes, endness=state.arch.memory_endness)
    if not ps_object_type.concrete:
        utils.print_error(f"Unable to correctly evaluate {object_type_name} import")
        return None

    # We need to store a symbolic value to represent the *ObjectType to recognize it later inside a kernel function hook
    star_ps_object_type = claripy.BVS(f'*{object_type_name}', state.arch.bits)
    state.memory.store(ps_object_type, star_ps_object_type, state.arch.bytes, endness=state.arch.memory_endness, disable_actions=True, inspect=False)
    return star_ps_object_type
    
def hunting(driver_base_state: angr.SimState, ioctl_handler_addr):
    globals.phase = 2
    if 'device_object_addr' in driver_base_state.globals:
        device_object_addr = claripy.BVV(driver_base_state.globals['device_object_addr'], driver_base_state.arch.bits)
    else:
        device_object_addr = claripy.BVS('device_object_addr', driver_base_state.arch.bits)
        driver_base_state.globals['open_section_handles'] = ()
        driver_base_state.globals['tainted_unicode_strings'] = ()

        global_var = int(globals.args.global_var, 16)
        if global_var:
            for segment in globals.proj.loader.main_object.segments:
                if '.data' in segment.name:
                    size = segment.memsize if segment.memsize <= global_var else global_var
                    data = claripy.BVS('.data', 8 * size).reversed
                    driver_base_state.memory.store(segment.vaddr, data, size)

    driver_base_state.globals['tainted_ProbeForRead'] = ()
    driver_base_state.globals['tainted_ProbeForWrite'] = ()
    driver_base_state.globals['tainted_MmIsAddressValid'] = ()
    driver_base_state.globals['tainted_eprocess'] = ()
    driver_base_state.globals['tainted_handles'] = ()
    driver_base_state.globals['tainted_objects'] = ()
    driver_base_state.globals['process_context_changing'] = ()
    
    state: angr.SimState = globals.proj.factory.call_state(ioctl_handler_addr, device_object_addr, globals.irp_addr, cc=globals.mycc,
                                                   base_state=driver_base_state)

    cr8 = claripy.BVS('cr8', state.arch.bits)
    state.registers.store('cr8', cr8)

    irp = claripy.BVS('irp_buf', 8 * 0x200)
    globals.SystemBuffer = claripy.BVS('SystemBuffer', state.arch.bits)
    globals.Type3InputBuffer = claripy.BVS('Type3InputBuffer', state.arch.bits)
    globals.UserBuffer = claripy.BVS('UserBuffer', state.arch.bits)
    
    while len(state.inspect._breakpoints['mem_write']) > 0:
        state.inspect._breakpoints['mem_write'].pop()
    while len(state.inspect._breakpoints['call']) > 0:
        state.inspect._breakpoints['call'].pop()
    state.inspect.b('mem_read', when=angr.BP_BEFORE, action=breakpoints.b_mem_read)
    state.inspect.b('mem_write', when=angr.BP_BEFORE, action=breakpoints.b_mem_write)
    state.inspect.b('call', when=angr.BP_BEFORE, action=breakpoints.b_call)

    state.memory.store(globals.irp_addr, irp)

    major_func, minor_func, globals.OutputBufferLength, globals.InputBufferLength, globals.IoControlCode = map(lambda x: claripy.BVS(*x), [
        ("MajorFunction", 8), ("MinorFunction", 8), ('OutputBufferLength', 32), ('InputBufferLength', 32),
        ('IoControlCode', 32)])
    
    # Resolve imported symbols addresses in driver memory
    globals.ps_process_type = utils.resolve_import_symbol_in_object(globals.proj.loader.main_object, "PsProcessType")
    
    # Fixup import symbols
    globals.star_ps_process_type = fix_object_type_import(state, "PsProcessType", globals.ps_process_type)

    # Set the initial value of the IRP.
    state.mem[globals.irp_addr].IRP.Tail.Overlay.s.u.CurrentStackLocation = globals.irsp_addr
    state.mem[globals.irp_addr].IRP.AssociatedIrp.SystemBuffer = globals.SystemBuffer
    state.mem[globals.irp_addr].IRP.UserBuffer = globals.UserBuffer
    state.mem[globals.irp_addr].IRP.RequestorMode = 1
    state.mem[globals.irsp_addr].IO_STACK_LOCATION.MajorFunction = 14
    state.mem[globals.irsp_addr].IO_STACK_LOCATION.MinorFunction = minor_func

    # Set the initial value of the IO_STACK_LOCATION.
    _params = state.mem[globals.irsp_addr].IO_STACK_LOCATION.Parameters
    _params.DeviceIoControl.OutputBufferLength.val = globals.OutputBufferLength
    _params.DeviceIoControl.InputBufferLength.val = globals.InputBufferLength
    _params.DeviceIoControl.Type3InputBuffer = globals.Type3InputBuffer
    
    # Set IoControlCode if specified.
    if globals.args.ioctlcode:
        _params.DeviceIoControl.IoControlCode.val = int(globals.args.ioctlcode, 16)
        state.add_constraints(globals.IoControlCode == int(globals.args.ioctlcode, 16))
    else:
        _params.DeviceIoControl.IoControlCode.val = globals.IoControlCode

    globals.simgr = globals.proj.factory.simgr(state)
    globals.simgr.populate('found', [])    
    globals.simgr.use_technique(angr.exploration_techniques.DFS())
        
    # Set loop bound.
    if globals.args.bound:
        globals.simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=globals.cfg, functions=None, bound=globals.args.bound))
        globals.simgr.use_technique(angr.exploration_techniques.LocalLoopSeer(bound=globals.args.bound))
    
    # Set length limit.
    if globals.args.length:
        globals.simgr.use_technique(angr.exploration_techniques.LengthLimiter(globals.args.length))

    # Set state explosion detection threshold.
    ed = techniques.ExplosionDetector(threshold=10000)
    globals.simgr.use_technique(ed)

    # Start symbolic execution to hunt vulnerabilities.
    while (len(globals.simgr.active) > 0 or len(globals.simgr.deferred) > 0) and not ed.state_exploded_bool:
        try:
            globals.simgr.step(num_inst=1)
        except Exception as e:
            utils.print_error(f'error on state {globals.simgr.active}: {str(e)}')
            globals.simgr.move(from_stash='active', to_stash='_Drop')
        utils.print_debug(f'simgr: {globals.simgr},\n\tactive: {globals.simgr.active}\n\tdeferred: {globals.simgr.deferred}\n\terrored: {globals.simgr.errored}\n\tdeadneded: {globals.simgr.deadended}')

    if ed.state_exploded_bool:
        utils.print_error('state explosion')

    if globals.simgr.errored:
        for s in globals.simgr.errored:
            utils.print_error(f'{repr(s)}')


def find_hook_func():
    # Use signature to find memset and memcpy because they are not imported function in Windows kernel.
    memset_hook_address = None
    memcpy_hook_address = None
    for func_addr in globals.cfg.kb.functions:
        func = globals.cfg.kb.functions[func_addr]

        prefetchnta_count = 0
        for block in func.blocks:
            if len(block.capstone.insns) > 2:
                if block.capstone.insns[0].mnemonic == 'movzx' and block.capstone.insns[0].op_str == 'edx, dl' and block.capstone.insns[1].mnemonic == 'movabs' and block.capstone.insns[1].op_str == 'r9, 0x101010101010101':
                    memset_hook_address = func_addr
                    break

            for insn in block.capstone.insns:
                if insn.mnemonic == 'prefetchnta':
                    prefetchnta_count += 1
        
        if prefetchnta_count >= 2:
            memcpy_hook_address = func_addr

    # memset and memcpy are compiled as a function in a complicated way, so we have to find and hook them.
    if memset_hook_address:
        utils.print_debug(f'memset_hook_address: {hex(memset_hook_address)}')
        globals.proj.hook(memset_hook_address, angr.procedures.SIM_PROCEDURES['libc']['memset'](cc=globals.mycc))
    if memcpy_hook_address:
        utils.print_debug(f'memcpy_hook_address: {hex(memcpy_hook_address)}')
        globals.proj.hook(memcpy_hook_address, hooks.HookMemcpy(cc=globals.mycc))


def find_targets(driver_path):
    # Parse the driver file to get assembly with objdump.
    command = f'objdump --insn-width=16 -d "{driver_path}"'
    proc = subprocess.Popen([command], shell=True, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, encoding='utf8')

    for line in proc.stdout:
        try:
            addr = int(line.strip().split(':')[0], 16)
        except:
            continue

        # Use regular expression to find opcode int and out in the binary.
        is_out = re.search('out[ \t]+%([a-z0-9]+),\(%([a-z0-9]+)\)$', line)
        is_int = re.search('[ \t]*int[ \t]*', line)

        # Hook the target opcode.
        if is_out:
            size = len(line.strip().split('out')[0].split()) - 1
            utils.print_debug(f'{line}')
            globals.proj.hook(addr, opcodes.out_hook, size)
        elif is_int:
            utils.print_debug(f'{line}')
            globals.proj.hook(addr, opcodes.int_hook, 2)
        elif 'wrmsr' in line:
            utils.print_debug(f'{line}')
            globals.proj.hook(addr, opcodes.wrmsr_hook, 2)
        elif 'lock' in line and not 'inc' in line and not 'dec' in line:
            utils.print_debug(f'{line}')
            size = len(line.strip().split('lock')[0].split()) - 1
            globals.proj.hook(addr, opcodes.lock_hook, size)
        elif 'rep movsb' in line:
            utils.print_debug(f'{line}')
            globals.proj.hook(addr, opcodes.rep_movsb_hook, 2)
        elif 'rep movsw' in line:
            utils.print_debug(f'{line}')
            globals.proj.hook(addr, opcodes.rep_movsw_hook, 3)
        elif 'rep movsd' in line or 'rep movsl' in line:
            utils.print_debug(f'{line}')
            globals.proj.hook(addr, opcodes.rep_movsd_hook, 2)
        elif 'rep stos %al' in line:
            globals.proj.hook(addr, opcodes.rep_stosb_hook, 2)
            utils.print_debug(f'{line}')
        elif 'rep stos %ax' in line:
            globals.proj.hook(addr, opcodes.rep_stosw_hook, 3)
            utils.print_debug(f'{line}')
        elif 'rep stos %eax' in line:
            globals.proj.hook(addr, opcodes.rep_stosd_hook, 3)
            utils.print_debug(f'{line}')
        elif 'rep stos %rax' in line:
            globals.proj.hook(addr, opcodes.rep_stosq_hook, 3)
            utils.print_debug(f'{line}')
        elif 'rdpmc' in line:
            globals.proj.hook(addr, opcodes.rdpmc_hook, 2)
            utils.print_debug(f'{line}')
        elif 'pushfw' in line:
            globals.proj.hook(addr, opcodes.pushfw_hook, 2)
            utils.print_debug(f'{line}')
        elif 'popfw' in line:
            globals.proj.hook(addr, opcodes.popfw_hook, 2)
            utils.print_debug(f'{line}')
        elif 'outsb' in line:
            globals.proj.hook(addr, opcodes.outs_hook, 2)
            utils.print_debug(f'{line}')
        elif 'outsl' in line:
            globals.proj.hook(addr, opcodes.outs_hook, 2)
            utils.print_debug(f'{line}')
        elif 'outsw' in line:
            globals.proj.hook(addr, opcodes.outs_hook, 3)
            utils.print_debug(f'{line}')
        elif 'insb' in line:
            globals.proj.hook(addr, opcodes.ins_hook, 2)
            utils.print_debug(f'{line}')
        elif 'insl' in line:
            globals.proj.hook(addr, opcodes.ins_hook, 2)
            utils.print_debug(f'{line}')
        elif 'insw' in line:
            globals.proj.hook(addr, opcodes.ins_hook, 3)
            utils.print_debug(f'{line}')
        elif 'lfence' in line:
            globals.proj.hook(addr, opcodes.lfence_hook, 3)
            utils.print_debug(f'{line}')
        elif 'sidt' in line:
            globals.proj.hook(addr, opcodes.sidt_hook, 3)
            utils.print_debug(f'{line}')
        elif 'lidt' in line:
            globals.proj.hook(addr, opcodes.lidt_hook, 3)
            utils.print_debug(f'{line}')


def analyze_driver(driver_path):
    try:
        globals.proj = angr.Project(driver_path, auto_load_libs=False)
        utils.print_info(f'analyze driver {driver_path}')
    except:
        utils.print_error(f'cannot analyze {driver_path}')
        return

    # Return 'wdm' if it is a WDM driver.
    driver_type = utils.find_driver_type()
    if driver_type != 'wdm':
        return

    # Get control flow graph.
    globals.cfg = globals.proj.analyses.CFGFast()

    # Customize calling convention for the SimProcs.
    if globals.proj.arch.name == archinfo.ArchX86.name:
        globals.mycc = angr.calling_conventions.SimCCStdcall(globals.proj.arch)
    else:
        globals.mycc = angr.calling_conventions.SimCCMicrosoftAMD64(globals.proj.arch)

    # Hook target kernel APIs.
    find_hook_func()
    
    if globals.args.exclude:
        for addr in [int(e, 16) for e in globals.args.exclude.split(',')]:
            utils.print_debug(f'exclude function address: {hex(addr)}')
            globals.proj.hook(addr, hooks.HookDoNothing(cc=globals.mycc))

    globals.DO_NOTHING = utils.next_base_addr()
    globals.proj.hook(globals.DO_NOTHING, hooks.HookDoNothing(cc=globals.mycc))
    globals.proj.hook_symbol('memmove', hooks.HookMemcpy(cc=globals.mycc))
    globals.proj.hook_symbol('memcpy', hooks.HookMemcpy(cc=globals.mycc))
    globals.proj.hook_symbol('ZwOpenSection', hooks.HookZwOpenSection(cc=globals.mycc))
    globals.proj.hook_symbol('RtlInitUnicodeString', hooks.HookRtlInitUnicodeString(cc=globals.mycc))
    globals.proj.hook_symbol('RtlCopyUnicodeString', hooks.HookRtlCopyUnicodeString(cc=globals.mycc))
    globals.proj.hook_symbol('IoStartPacket', hooks.HookIoStartPacket(cc=globals.mycc))
    globals.proj.hook_symbol('IoCreateDevice', hooks.HookIoCreateDevice(cc=globals.mycc))
    globals.proj.hook_symbol('IoCreateSymbolicLink', hooks.HookIoCreateSymbolicLink(cc=globals.mycc))
    globals.proj.hook_symbol('IoIs32bitProcess', hooks.HookIoIs32bitProcess(cc=globals.mycc))
    globals.proj.hook_symbol('RtlGetVersion', hooks.HookRtlGetVersion(cc=globals.mycc))
    globals.proj.hook_symbol('ExGetPreviousMode', hooks.HookExGetPreviousMode(cc=globals.mycc))
    globals.proj.hook_symbol('KeQueryActiveGroupCount', hooks.HookKeQueryActiveGroupCount(cc=globals.mycc))
    globals.proj.hook_symbol('KeQueryActiveProcessors', hooks.HookKeQueryActiveProcessors(cc=globals.mycc))
    globals.proj.hook_symbol('KeQueryActiveProcessorCountEx', hooks.HookKeQueryActiveProcessorCountEx(cc=globals.mycc))
    globals.proj.hook_symbol('ExInterlockedPopEntrySList', hooks.HookExInterlockedPopEntrySList(cc=globals.mycc))
    globals.proj.hook_symbol('ExQueryDepthSList', hooks.HookExQueryDepthSList(cc=globals.mycc))
    globals.proj.hook_symbol('ExpInterlockedPushEntrySList', hooks.HookExpInterlockedPushEntrySList(cc=globals.mycc))
    globals.proj.hook_symbol('ExpInterlockedPopEntrySList', hooks.HookExpInterlockedPopEntrySList(cc=globals.mycc))
    globals.proj.hook_symbol('PsGetVersion', hooks.HookPsGetVersion(cc=globals.mycc))
    globals.proj.hook_symbol('ExInitializeResourceLite', hooks.HookExInitializeResourceLite(cc=globals.mycc))
    globals.proj.hook_symbol('KeWaitForSingleObject', hooks.HookKeWaitForSingleObject(cc=globals.mycc))
    globals.proj.hook_symbol('RtlWriteRegistryValue', hooks.HookRtlWriteRegistryValue(cc=globals.mycc))
    globals.proj.hook_symbol('IoGetDeviceProperty', hooks.HookIoGetDeviceProperty(cc=globals.mycc))
    globals.proj.hook_symbol('KeReleaseMutex', hooks.HookKeReleaseMutex(cc=globals.mycc))
    globals.proj.hook_symbol('MmGetSystemRoutineAddress', hooks.HookMmGetSystemRoutineAddress(cc=globals.mycc))
    globals.proj.hook_symbol('FltGetRoutineAddress', hooks.HookFltGetRoutineAddress(cc=globals.mycc))
    globals.proj.hook_symbol('RtlGetElementGenericTable', hooks.HookDoNothing(cc=globals.mycc))
    globals.proj.hook_symbol('ExAcquireResourceExclusiveLite', hooks.HookDoNothing(cc=globals.mycc))
    globals.proj.hook_symbol('ProbeForRead', hooks.HookProbeForRead(cc=globals.mycc))
    globals.proj.hook_symbol('ProbeForWrite', hooks.HookProbeForWrite(cc=globals.mycc))
    globals.proj.hook_symbol('MmIsAddressValid', hooks.HookMmIsAddressValid(cc=globals.mycc))
    globals.proj.hook_symbol('ZwQueryInformationFile', hooks.HookZwQueryInformationFile(cc=globals.mycc))
    globals.proj.hook_symbol('ZwQueryInformationProcess', hooks.HookZwQueryInformationProcess(cc=globals.mycc))
    globals.proj.hook_symbol("ObReferenceObjectByHandle", hooks.HookObReferenceObjectByHandle(cc=globals.mycc))
    globals.proj.hook_symbol("ZwWriteFile", hooks.HookZwWriteFile(cc=globals.mycc))
    globals.proj.hook_symbol("ZwCreateKey", hooks.HookZwCreateKey(cc=globals.mycc))
    globals.proj.hook_symbol("ZwOpenKey", hooks.HookZwOpenKey(cc=globals.mycc))
    globals.proj.hook_symbol("ZwDeleteValueKey", hooks.HookZwDeleteValueKey(cc=globals.mycc))
    globals.proj.hook_symbol("ZwQueryValueKey", hooks.HookZwQueryValueKey(cc=globals.mycc))
    globals.proj.hook_symbol("NdisRegisterProtocolDriver", hooks.HookNdisRegisterProtocolDriver(cc=globals.mycc))
    globals.proj.hook_symbol("ZwTerminateProcess", hooks.HookZwTerminateProcess(cc=globals.mycc))

    # Only hook for phase 2 to hunt vulnerabilities.
    globals.proj.hook_symbol("ExAllocatePool", hooks.HookExAllocatePool(cc=globals.mycc))
    globals.proj.hook_symbol("ExAllocatePool2", hooks.HookExAllocatePool2(cc=globals.mycc))
    globals.proj.hook_symbol("ExAllocatePool3", hooks.HookExAllocatePool3(cc=globals.mycc))
    globals.proj.hook_symbol("MmAllocateNonCachedMemory", hooks.HookMmAllocateNonCachedMemory(cc=globals.mycc))
    globals.proj.hook_symbol("ExAllocatePoolWithTag", hooks.HookExAllocatePoolWithTag(cc=globals.mycc))
    globals.proj.hook_symbol("MmAllocateContiguousMemorySpecifyCache", hooks.HookMmAllocateContiguousMemorySpecifyCache(cc=globals.mycc))
    globals.proj.hook_symbol('MmMapIoSpace', hooks.HookMmMapIoSpace(cc=globals.mycc))
    globals.proj.hook_symbol('MmMapIoSpaceEx', hooks.HookMmMapIoSpaceEx(cc=globals.mycc))
    globals.proj.hook_symbol('HalTranslateBusAddress', hooks.HookHalTranslateBusAddress(cc=globals.mycc))
    globals.proj.hook_symbol('ZwMapViewOfSection', hooks.HookZwMapViewOfSection(cc=globals.mycc))
    globals.proj.hook_symbol('ZwOpenProcess', hooks.HookZwOpenProcess(cc=globals.mycc))
    globals.proj.hook_symbol('PsLookupProcessByProcessId', hooks.HookPsLookupProcessByProcessId(cc=globals.mycc))
    globals.proj.hook_symbol('ObOpenObjectByPointer', hooks.HookObOpenObjectByPointer(cc=globals.mycc))
    globals.proj.hook_symbol('ZwDeleteFile', hooks.HookZwDeleteFile(cc=globals.mycc))
    globals.proj.hook_symbol('ZwOpenFile', hooks.HookZwOpenFile(cc=globals.mycc))
    globals.proj.hook_symbol('ZwCreateFile', hooks.HookZwCreateFile(cc=globals.mycc))
    globals.proj.hook_symbol('IoCreateFile', hooks.HookIoCreateFile(cc=globals.mycc))
    globals.proj.hook_symbol('IoCreateFileEx', hooks.HookIoCreateFileEx(cc=globals.mycc))
    globals.proj.hook_symbol('IoCreateFileSpecifyDeviceObjectHint', hooks.HookIoCreateFileSpecifyDeviceObjectHint(cc=globals.mycc))
    globals.proj.hook_symbol('ObCloseHandle', hooks.HookObCloseHandle(cc=globals.mycc))
    globals.proj.hook_symbol('KeStackAttachProcess', hooks.HookKeStackAttachProcess(cc=globals.mycc))


    find_targets(driver_path)

    # Hook indirect jump.
    for indirect_jump in globals.cfg.indirect_jumps:
        indirect_jum_ins_addr = globals.cfg.indirect_jumps[indirect_jump].ins_addr
        if len(globals.proj.factory.block(indirect_jum_ins_addr).capstone.insns):
            op = globals.proj.factory.block(indirect_jum_ins_addr).capstone.insns[0].op_str
            if op == 'rax' or op == 'rbx' or op == 'rcx' or op == 'rdx':
                utils.print_debug(f'indirect jmp {hex(globals.cfg.indirect_jumps[indirect_jump].ins_addr)}')
                globals.proj.hook(globals.cfg.indirect_jumps[indirect_jump].ins_addr, opcodes.indirect_jmp_hook, 0)

    if driver_type == 'wdm':
        # Parse the driver file and find device name by searching pattern.
        utils.find_device_names(driver_path)
        start_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        start_time = time.time()

        globals.basic_info['time'] = {}
        globals.basic_info['memory'] = {}
        globals.basic_info['unique addr'] = {}

        # Find and return the address of ioctl handler by traversing DriverEntry and monitorirng ioctl handler.
        if globals.args.address:
            ioctl_handler, ioctl_handler_state = int(globals.args.address, 16), None
        else:
            ioctl_handler, ioctl_handler_state = find_ioctl_handler()

        globals.basic_info['ioctl handler'] = hex(ioctl_handler)
        globals.basic_info['time']['ioctl handler'] = round(time.time() - start_time)
        globals.basic_info['memory']['ioctl handler'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - start_memory
        globals.basic_info['unique addr']['ioctl handler'] = len(set().union(*[list(l.history.bbl_addrs) for k in [globals.simgr.stashes[j] for j in [i for i in globals.simgr.stashes]] for l in k])) if globals.simgr else 0

        # If getting ioctl handler successfully, start hunting vulnerabilities.
        if ioctl_handler:
            utils.print_info(f'ioctl handler: {hex(ioctl_handler)}, ioctl handler state: {ioctl_handler_state}')
            
            if not ioctl_handler_state:
                utils.print_info(f'Use blank state to hunt vulnerabilities.')
                ioctl_handler_state = globals.proj.factory.blank_state()

            # Store the starting time, memory, history addresses.
            start_time = time.time()
            start_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            start_unique_addr = len(set([i for i in ioctl_handler_state.history.bbl_addrs]))

            # Start hunting vulnerabilities.
            globals.basic_info['IoControlCodes'] = []
            hunting(ioctl_handler_state, ioctl_handler)

            # Store the ending time, memory, history addresses to get performance after hunting.
            globals.basic_info['time']['hunting vulns'] = round(time.time() - start_time)
            globals.basic_info['memory']['hunting vulns'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - start_memory
            globals.basic_info['unique addr']['hunting vulns'] = len(set().union(*[list(l.history.bbl_addrs) for k in [globals.simgr.stashes[j] for j in [i for i in globals.simgr.stashes]] for l in k])) - start_unique_addr
        else:
            utils.print_error(f'ioctl handler: {hex(ioctl_handler)}, ioctl handler state: {ioctl_handler_state}\n')
        
        # Output the result to a json file.
        globals.driver_info['basic'] = globals.basic_info
        globals.driver_info['vuln'] = globals.vulns_info
        globals.driver_info['error'] = globals.error_msgs
        open(driver_path + '.json', 'w').write(json.dumps(globals.driver_info, indent=4))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ioctlcode', default=0, help='analyze specified IoControlCode (e.g. 22201c)')
    parser.add_argument('-T', '--total_timeout', type=int, default=1200, help='total timeout for the whole symbolic execution (default 1200, 0 to unlimited)')
    parser.add_argument('-t', '--timeout', type=int, default=40, help='timeout for analyze each IoControlCode (default 40, 0 to unlimited)')
    parser.add_argument('-l', '--length', type=int, default=0, help='the limit of number of instructions for technique LengthLimiter (default 0, 0 to unlimited)')
    parser.add_argument('-b', '--bound', type=int, default=0, help='the bound for technique LoopSeer (default 0, 0 to unlimited)')
    parser.add_argument('-g', '--global_var', default='0', help='symbolize how many bytes in .data section (default 0 hex)')
    parser.add_argument('-a', '--address', default=0, help='address of ioctl handler to directly start hunting with blank state (e.g. 140005c20)')
    parser.add_argument('-e', '--exclude', default='', help='exclude function address split with , (e.g. 140005c20,140006c20)')
    parser.add_argument('-o', '--overwrite', default=False, action='store_true', help='overwrite x.sys.json if x.sys has been analyzed (default False)')
    parser.add_argument('-r', '--recursion', default=False, action='store_true', help='do not kill state if detecting recursion (default False)')
    parser.add_argument('-c', '--complete', default=False, action='store_true', help='get complete base state (default False)')
    parser.add_argument('-d', '--debug', default=False, action='store_true', help='print debug info while analyzing (default False)')
    parser.add_argument('path', type=str, help='dir (including subdirectory) or file path to the driver(s) to analyze')
    globals.args = parser.parse_args()

    if os.path.isdir(globals.args.path):
        # If a directory given, analyze all the drivers in the directory.
        walks = [{'root': root, 'dirs': dirs, 'files': files} for root, dirs, files in os.walk(globals.args.path)]
        for walk in walks:
            root = walk['root']
            if root[-1] == '/':
                root = root[:-1]

            for f in walk['files']:
                if f.lower().endswith('.sys') or f.lower().endswith('.dll'):
                    if os.path.isfile(f'{root}/{f}.json') and not globals.args.overwrite:
                        utils.print_info(f'{root}/{f} had been analyzed.')
                        continue
                    globals.basic_info['path'] = f'{root}/{f}'
                    command = f'timeout {globals.args.total_timeout * 3} python3 {__file__} "{root}/{f}" {" ".join(sys.argv[2:])}'
                    utils.print_info(f'{command}')
                    proc = subprocess.Popen([command], shell=True, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, encoding='utf8')
                    proc.wait()
    elif os.path.isfile(globals.args.path):
        # Analyze the driver file if it is not analyzed before or overwrite specified.
        if not os.path.isfile(f'{globals.args.path}.json') or globals.args.overwrite:
            globals.basic_info['path'] = globals.args.path
            analyze_driver(globals.args.path)
        else:
            utils.print_info(f'{globals.args.path} had been analyzed.')
    else:
        utils.print_error(f'{globals.args.path} is not a dir or a file.')