import collections
import cle
import claripy
from cle.backends.pe.relocation.generic import DllImport
from typing import Optional
import globals
import sys
import json

def tainted_buffer(s):
    # The tainted buffer contains only one symbolic variable.
    if len(s.variables) != 1:
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
    
def tainted_string_pointer(state, string_ptr, kind): 
    """
    Checks if a PCHAR or a PWCHAR is tainted
    """
    taint_collection = "tainted_ansi_strings" if kind == "ansi" else "tainted_unicode_strings"
    return (not string_ptr.symbolic and tainted_buffer(state.memory.load(string_ptr, 0x10, disable_actions=True, inspect=False))) or tainted_buffer(string_ptr) or str(string_ptr) in state.globals[taint_collection]

def tainted_object_name(state, ObjectName): 
    """
    Checks if a provided ObjectName, in the form of a UNICODE_STRING, is tainted 
    """
    Buffer = state.mem[ObjectName].struct._UNICODE_STRING.Buffer.resolved
    return str(Buffer) in state.globals['tainted_unicode_strings'] or tainted_buffer(state.memory.load(Buffer, 0x80))

def fill_os_string(state, DestinationString, string_ptr, kind):
    """
    Fills an OS-defined string structure (UNICODE_STRING or STRING) using characters from a provided string pointer (PCHAR or a PWCHAR)

    :return: UNICODE_STRING or STRING view of DestinationString
    """
    os_string_struct = state.mem[DestinationString].struct._STRING if kind == "ansi" else state.mem[DestinationString].struct._UNICODE_STRING
    os_string_struct_size_bits = os_string_struct._type.size

    # Initalize the DestinationString.
    byte_length = string_ptr.length // 8
    new_buffer = next_base_addr()
    state.memory.store(new_buffer, string_ptr, byte_length, disable_actions=True, inspect=False)

    state.memory.store(DestinationString, claripy.BVV(0, os_string_struct_size_bits), os_string_struct_size_bits // 8, disable_actions=True, inspect=False)
    os_string_struct.Length = byte_length
    os_string_struct.MaximumLength = byte_length
    os_string_struct.Buffer = new_buffer

    return os_string_struct

def init_os_string(state, DestinationString, SourceString, kind):
    """
    Initializes DestinationString using data from SourceString. If SourceString is tainted, updates the taints collection
    """

    ret_addr = hex(state.callstack.ret_addr)
    init_function = "RtlInitAnsiString" if kind == "ansi" else "RtlInitUnicodeString"
    taint_collection = "tainted_ansi_strings" if kind == "ansi" else "tainted_unicode_strings"
    char_size = state.mem.CHAR._type.size if kind == "ansi" else state.mem.WCHAR._type.size

    # Resolve the SourceString.
    try:
        if SourceString.symbolic and tainted_buffer(SourceString):
            raise
       
        string_orig = state.mem[SourceString].string.resolved if kind == "ansi" else state.mem[SourceString].wstring.resolved
    except:
        string_orig = claripy.Concat(claripy.BVS(f"{init_function}_{ret_addr}", 8 * 10), claripy.BVV(0, char_size))

    os_string_struct = fill_os_string(state, DestinationString, string_orig, kind)

    # Store the unicode string if it is tainted.
    if tainted_string_pointer(state, SourceString, kind):
        state.globals[taint_collection] += (str(os_string_struct.Buffer.resolved),)

def analyze_ObjectAttributes(func_name, state, ObjectAttributes):
    ObjectName = state.mem[ObjectAttributes].struct._OBJECT_ATTRIBUTES.ObjectName.resolved
    Attributes = state.mem[ObjectAttributes].struct._OBJECT_ATTRIBUTES.Attributes.resolved
    Buffer = state.mem[ObjectName].struct._UNICODE_STRING.Buffer.resolved
    tmp_state = state.copy()

    # Attrbitues is not OBJ_FORCE_ACCESS_CHECK.
    tmp_state.solver.add(Attributes & 1024 == 0)
    
    # Check if the ObjectName is controllable.
    if tmp_state.satisfiable() and tainted_object_name(state, ObjectName):
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

    data = {}
    data['title'] = f'{title}'
    data['description'] = f'{description}'
    data['state'] = str(state)
    data['parameters'] = parameters

    IoControlCode = None 
    vuln_nnuple = None
    if (globals.IoControlCode is None):
        vuln_nnuple = (title, state.addr)
    else:
        IoControlCode = hex(state.solver.eval(globals.IoControlCode))
        vuln_nnuple = (title, state.addr, str(IoControlCode))
        # Evaluate the target buffers.
        SystemBuffer = hex(state.solver.eval(globals.SystemBuffer))
        Type3InputBuffer = hex(state.solver.eval(globals.Type3InputBuffer))
        UserBuffer = hex(state.solver.eval(globals.UserBuffer))
        InputBufferLength = hex(state.solver.eval(globals.InputBufferLength))
        OutputBufferLength = hex(state.solver.eval(globals.OutputBufferLength))
    
        # Set the information of the vulnerability.
        data['eval'] = {'IoControlCode': IoControlCode, 'SystemBuffer': SystemBuffer, 'Type3InputBuffer': Type3InputBuffer, 'UserBuffer': UserBuffer, 'InputBufferLength': InputBufferLength, 'OutputBufferLength': OutputBufferLength}
    
    
    if vuln_nnuple in globals.vulns_unique:
        return
    
    globals.vulns_unique.add(vuln_nnuple)
   
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