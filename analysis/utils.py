import collections
import angr
import claripy
import cle
from cle.backends.pe.relocation.generic import DllImport
from typing import Optional
import globals
import sys
import json

def tainted_buffer(s):
    # Buffer must be a BitVector and must contain only one symbolic variable
    if (not isinstance(s, claripy.ast.bv.BV)) or (len(s.variables) != 1):
        return ''
        
    # Check the tainted symbolic variable.
    s = str(s)
    if 'SystemBuffer' in s:
        return 'SystemBuffer'
    elif 'Type3InputBuffer' in s:
        return 'Type3InputBuffer'
    elif 'UserBuffer' in s:
        return 'UserBuffer'
    elif 'InputBufferLength' in s:
        return 'InputBufferLength'
    elif 'OutputBufferLength' in s:
        return 'OutputBufferLength'
    else:
        return ''

def user_memory_address(state: angr.SimState, address) -> bool:
    ''' Returns true if a memory address is contained in a user-provided buffer '''
    
    # Address must evaluate to one symbolic variable.
    if (not isinstance(address, claripy.ast.bv.BV)) or (len(address.variables) != 1):
        return False
    
    addr_base = get_base_address(address)
    # Base address must be tainted and must be a dereference
    if  ((not tainted_buffer(addr_base)) or
        (len(addr_base.args) <= 0) or
        (not isinstance(addr_base.args[0], str)) or
        (not addr_base.args[0].startswith("*<"))):
        return False
    
    return True

def tainted_memory_address(state: angr.SimState, address) -> bool:
    ''' Returns true if a memory address is user-provided and has not been validated through functions like ProbeForWrite, ProbeForWrite, MmIsAddressValid '''
    base_str = str(get_base_address(address))
    
    # Address must evaluate to one symbolic variable.
    # With METHOD_NEITHER ioctl communication, kernel performs no checks on the input buffers. Everything is delegated to the driver
    tainted_direct_input = 'Type3InputBuffer' in base_str
    # In the case of METHOD_BUFFERED, the UserBuffer pointer is copied to the IRP but there is a PROBE before
    tainted_direct_output = ('UserBuffer' in base_str) and state.solver.eval((globals.IoControlCode & 0x3) == 0x3)
    if (not tainted_direct_input) and(not tainted_direct_output) and not user_memory_address(state, address):
        return False
    
    # Let's just check if the address has not been probed
    if ((base_str in state.globals['tainted_ProbeForWrite']) or 
        (base_str in state.globals['tainted_ProbeForRead'])):
        return False

    return True

def get_base_address(address):
    if not isinstance(address, claripy.ast.bv.BV):
        return address
    else:
        symbolic_leafs = [i for i in address.leaf_asts() if i.symbolic]
        return symbolic_leafs[0] if len(symbolic_leafs) == 1 else address
    
def symbolyze_buffer(state: angr.SimState, symb_address: claripy.ast.bv.BV):
    symb_address_str = str(symb_address)
    if symb_address_str not in state.globals:
        addr = next_base_addr()
        tmp_state = state.copy()
        tmp_state.solver.add(symb_address == addr)
        if not tmp_state.satisfiable():
            return

        state.globals[symb_address_str] = True
        mem = claripy.BVS(f'*{symb_address_str}', 8 * 0x200).reversed
        
        state.solver.add(symb_address == addr)
        state.memory.store(addr, mem, 0x200, disable_actions=True, inspect=False)

def check_npd_vuln(state: angr.SimState, address, write: bool):
    '''Checks if a specific address in a specific state is a Null Pointer Dereference target '''

    address_str = str(address)
    # Only checks for NPD targets in top-level buffer pointers
    address_is_npd_target = any(target in address_str for target in globals.NPD_TARGETS) and ('*' not in address_str)
    if not address_is_npd_target:
        return
    
    tmp_state = state.copy()
    tmp_state.solver.add(address == 0)
    if not tmp_state.satisfiable():
        return
    
    operation = "write" if write else "read"
    operation_other = "write to" if write else "read from"
    if tainted_buffer(address):
        print_vuln('null pointer dereference - input buffer', f'{operation} input buffer', state, {}, {operation_other: address_str})
    else:
        print_vuln('null pointer dereference - allocated memory', f'{operation} allocated memory', state, {}, {operation_other: address_str})

def check_arw_vuln(state: angr.SimState, address, write: bool) -> bool:
    '''Checks if a specific address in a specific state is an arbitrary read/write target '''

    address_str = str(address)
    if not tainted_memory_address(state, address):
        return False
    
    # Let's try to assign a concrete value to our address to see if 
    # the constraints are still valid
    tmp_state = state.copy()
    tmp_state.solver.add(address == 0x10000)
    if not tmp_state.satisfiable():
        return False

    operation = "write" if write else "read"
    operation_other = "write to" if write else "read from"
    print_vuln('read/write controllable address', operation, tmp_state, {}, {operation_other: address_str})
    return True

def analyze_ObjectAttributes(func_name, state, ObjectAttributes):
    ObjectName = state.mem[ObjectAttributes].struct._OBJECT_ATTRIBUTES.ObjectName.resolved
    Attributes = state.mem[ObjectAttributes].struct._OBJECT_ATTRIBUTES.Attributes.resolved
    Buffer = state.mem[ObjectName].struct._UNICODE_STRING.Buffer.resolved
    tmp_state = state.copy()

    # Attrbitues is not OBJ_FORCE_ACCESS_CHECK.
    tmp_state.solver.add(Attributes & 1024 == 0)
    
    # Check if the ObjectName is controllable.
    if tmp_state.satisfiable() and (str(state.mem[ObjectName].struct._UNICODE_STRING.Buffer.resolved) in state.globals['tainted_unicode_strings'] or tainted_buffer(state.memory.load(Buffer, 0x80))):
        ret_addr = hex(state.callstack.ret_addr)
        print_vuln(f'ObjectName in ObjectAttributes controllable', func_name, state, {'ObjectAttributes': {'ObjectName': str(ObjectName), 'ObjectName.Buffer': str(state.memory.load(Buffer, 0x80).reversed), 'Attributes': str(Attributes)}}, {'return address': ret_addr})
    
    return

def next_base_addr(size=0x10000):
    v = globals.FIRST_ADDR
    globals.FIRST_ADDR += size
    return v


def print_eval(state, upto):
    # Evalute the target buffers and print.
    SystemBuffer = [hex(i) for i in state.solver.eval_upto(globals.SystemBuffer, upto)]
    InputBufferLength = [hex(i) for i in state.solver.eval_upto(globals.InputBufferLength, upto)]
    OutputBufferLength = [hex(i) for i in state.solver.eval_upto(globals.OutputBufferLength, upto)]
    IoControlCode = [hex(i) for i in state.solver.eval_upto(globals.IoControlCode, upto)]

    print(f'\teval (upto {upto}):\n\t\tIoControlCode: {IoControlCode}\n\t\tSystemBuffer: {SystemBuffer}\n\t\tInputBufferLength: {InputBufferLength}\n\t\tOutputBufferLength: {OutputBufferLength}')

def print_vuln(title, description, state, parameters, others):
    # Validate the address.
    if state.addr < 0x1337:
        return

    # Deduplicate vulnerabilities using (title, state.addr, IoControlCode).
    IoControlCode = hex(state.solver.eval(globals.IoControlCode))
    if (title, state.addr, str(IoControlCode)) not in globals.vulns_unique:
        globals.vulns_unique.add((title, state.addr, str(IoControlCode)))
        
        # Evaluate the target buffers.
        SystemBuffer = hex(state.solver.eval(globals.SystemBuffer))
        Type3InputBuffer = hex(state.solver.eval(globals.Type3InputBuffer))
        UserBuffer = hex(state.solver.eval(globals.UserBuffer))
        InputBufferLength = hex(state.solver.eval(globals.InputBufferLength))
        OutputBufferLength = hex(state.solver.eval(globals.OutputBufferLength))
        
        # Set the information of the vulnerability.
        data = {}
        data['title'] = f'{title}'
        data['description'] = f'{description}'
        data['state'] = str(state)
        data['eval'] = {'IoControlCode': IoControlCode, 'SystemBuffer': SystemBuffer, 'Type3InputBuffer': Type3InputBuffer, 'UserBuffer': UserBuffer, 'InputBufferLength': InputBufferLength, 'OutputBufferLength': OutputBufferLength}
        data['parameters'] = parameters
        data['others'] = others
        if 'tainted_ProbeForRead' in state.globals and len(state.globals['tainted_ProbeForRead']) > 0:
            data['others']['ProbeForRead'] = state.globals['tainted_ProbeForRead']
        if 'tainted_ProbeForWrite' in state.globals and len(state.globals['tainted_ProbeForWrite']) > 0:
            data['others']['ProbeForWrite'] = state.globals['tainted_ProbeForWrite']
        if 'tainted_MmIsAddressValid' in state.globals and len(state.globals['tainted_MmIsAddressValid']) > 0:
            data['others']['MmIsAddressValid'] = state.globals['tainted_MmIsAddressValid']
        print(json.dumps(data, indent=4), '\n')
        globals.vulns_info.append(data)

def print_info(msg):
    print(f'[Info] {msg}\n')

def print_debug(msg):
    if globals.args.debug:
        print(f'[Debug] {msg}\n')

def print_error(msg):
    print(f'[Error] {msg}\n', file=sys.stderr)
    globals.error_msgs.append(msg)

def find_utf_16le_str(data, string):
    cursor = 0
    found = collections.deque()
    device_name = ""
    while cursor < len(data):
        cursor = data.find(string, cursor)
        if cursor == -1:
            break
        terminator = data.find(b'\x00\x00', cursor)
        if (terminator - cursor) % 2:
            terminator += 1
        match = data[cursor:terminator].decode('utf-16le')
        if match not in found:
            device_name = match
            found.append(match)
        cursor += len(string)

    return device_name

def read_buffer_from_unicode_string(state, unicode_string_pointer):
    us = state.mem[unicode_string_pointer].struct._UNICODE_STRING
    length_expr = us.Length.resolved
    max_length_expr = us.MaximumLength.resolved
    buffer_ptr_expr = us.Buffer.resolved

    length = state.solver.eval(length_expr)
    max_length = state.solver.eval(max_length_expr)
    buffer_addr = state.solver.eval(buffer_ptr_expr)

    if (length == 0) or (max_length == 0):
        return None
    
    raw_data = state.memory.load(buffer_addr, length, disable_actions=True, inspect=False)
    device_name_str = state.solver.eval(raw_data, cast_to=bytes).decode("utf-16le", errors="ignore")

    return device_name_str.strip() if device_name_str is not None else None

def find_driver_type():
    # Check if the driver is a WDM driver.
    driver_type = ''
    if globals.proj.loader.find_symbol('IoCreateDevice'):
        print_info(f'WDM driver: {globals.proj}')
        driver_type = 'wdm'
    else:
        print_info(f'Different driver type detected: {globals.proj}')

    return driver_type

def resolve_import_symbol_in_object(pe_object: cle.backends.pe.pe.PE, symbol_name: str) -> Optional[int]:
    if symbol_name not in pe_object.imports:
        return None
    
    sym_import: DllImport = pe_object.imports[symbol_name]
    return pe_object.min_addr + sym_import.relative_addr

def resolve_import_symbol(loader: cle.loader.Loader, symbol_name: str) -> Optional[int]:
    for obj in loader.all_objects:
       result = resolve_import_symbol_in_object(obj, symbol_name)
       if result:
            return result
    
    return None