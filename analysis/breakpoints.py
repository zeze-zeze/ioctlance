import claripy
import angr
import globals
import utils
import ipdb

def b_mem_write_ioctl_handler(state):
    # Store the address of ioctl handler when writing into the memory.
    ioctl_handler_addr = state.solver.eval(state.inspect.mem_write_expr)
    globals.ioctl_handler = int(ioctl_handler_addr)
    state.globals['ioctl_handler'] = globals.ioctl_handler
    globals.simgr.move(from_stash='deadended', to_stash='_Drop')

def b_mem_write_DriverStartIo(state):
    # Store the address of DriverStartIo when writing into the memory.
    DriverStartIo_addr = state.solver.eval(state.inspect.mem_write_expr)
    globals.DriverStartIo = int(DriverStartIo_addr)
    globals.basic_info['DriverStartIo'] = hex(globals.DriverStartIo)
    utils.print_info(f'DriverStartIo: {hex(globals.DriverStartIo)}')

def b_mem_read(state):
    utils.print_debug(f'mem_read {state}, {state.inspect.mem_read_address}, {state.inspect.mem_read_expr}, {state.inspect.mem_read_length}, {state.inspect.mem_read_condition}')
    
    # Iterate all target buffers.
    for target in globals.NPD_TARGETS:
        if target in str(state.inspect.mem_read_address):
            asts = [i for i in state.inspect.mem_read_address.children_asts()]
            target_base = asts[0] if len(asts) > 1 else state.inspect.mem_read_address
            vars = state.inspect.mem_read_address.variables

            if str(target_base) not in state.globals['tainted_ProbeForRead'] and str(target_base) not in state.globals['tainted_ProbeForWrite'] and len(vars) == 1:
                # Add constraints to test whether the pointer is null or not.
                tmp_state = state.copy()
                if target == 'SystemBuffer':
                    if '*' in str(state.inspect.mem_read_address):
                        # If SystemBuffer is a pointer, check whether it is controllable.
                        tmp_state.solver.add(tmp_state.inspect.mem_read_address == 0x87)
                        if tmp_state.satisfiable() and not str(target_base) in state.globals['tainted_MmIsAddressValid']:
                            utils.print_vuln('read/write controllable address', 'read', state, {}, {'read from': str(state.inspect.mem_read_address)})
                    else:
                        # If SystemBuffer is not a pointer, check whether it can be null.
                        tmp_state.solver.add(globals.SystemBuffer == 0)
                        tmp_state.solver.add(globals.InputBufferLength == 0)
                        tmp_state.solver.add(globals.OutputBufferLength == 0)
                        if tmp_state.satisfiable() and str(target_base) not in state.globals['tainted_MmIsAddressValid']:
                            utils.print_vuln('null pointer dereference - input buffer', 'read input buffer', state, {}, {'read from': str(state.inspect.mem_read_address)})
                elif target == 'Type3InputBuffer' or target == 'UserBuffer':
                    # If Type3InputBuffer or UserBuffer is a pointer, check whether it is controllable.
                    if target == 'Type3InputBuffer':
                        tmp_state.solver.add(globals.Type3InputBuffer == 0x87)
                    elif target == 'UserBuffer':
                        tmp_state.solver.add(globals.UserBuffer == 0x87)

                    if tmp_state.satisfiable() and not str(target_base) in state.globals['tainted_MmIsAddressValid']:
                        utils.print_vuln('read/write controllable address', 'read', state, {}, {'read from': str(state.inspect.mem_read_address)})
                else:
                    # Only detect the allocated memory in case of false positive.
                    if '+' in str(tmp_state.inspect.mem_read_address):
                        return
                    tmp_state.solver.add(tmp_state.inspect.mem_read_address == 0)
                    if tmp_state.satisfiable():
                        utils.print_vuln('null pointer dereference - allocated memory', 'read allocated memory', state, {}, {'read from': str(state.inspect.mem_read_address)})

            # We symbolize the address of the tainted buffer because we want to detect the vulnerability when the driver reads/writes to/from the buffer.
            if utils.tainted_buffer(target_base) and str(target_base) not in state.globals:
                tmp_state = state.copy()
                tmp_state.solver.add(target_base == globals.FIRST_ADDR)
                if not tmp_state.satisfiable():
                    break

                state.globals[str(target_base)] = True
                mem = claripy.BVS(f'*{str(target_base)}', 8 * 0x200).reversed
                addr = utils.next_base_addr()
                state.solver.add(target_base == addr)
                state.memory.store(addr, mem, 0x200, disable_actions=True, inspect=False)

def b_mem_write(state):
    utils.print_debug(f'mem_write {state}, {state.inspect.mem_write_address}, {state.inspect.mem_write_expr}, {state.inspect.mem_write_length}, {state.inspect.mem_write_condition}')

    # Iterate all target buffers.
    for target in globals.NPD_TARGETS:
        if target in str(state.inspect.mem_write_address):
            asts = [i for i in state.inspect.mem_write_address.children_asts()]
            target_base = asts[0] if len(asts) > 1 else state.inspect.mem_write_address
            vars = state.inspect.mem_write_address.variables

            if str(target_base) not in state.globals['tainted_ProbeForRead'] and str(target_base) not in state.globals['tainted_ProbeForWrite'] and len(vars) == 1:
                # Add constraints to test whether the pointer is null or not.
                tmp_state = state.copy()
                if target == 'SystemBuffer':
                    if '*' in str(state.inspect.mem_write_address):
                        # If SystemBuffer is a pointer, check whether it is controllable.
                        tmp_state.solver.add(tmp_state.inspect.mem_write_address == 0x87)
                        if tmp_state.satisfiable():
                            utils.print_vuln('read/write controllable address', 'write', state, {}, {'write to': str(state.inspect.mem_write_address)})
                    else:
                        # If SystemBuffer is not a pointer, check whether it can be null.
                        tmp_state.solver.add(globals.SystemBuffer == 0)
                        tmp_state.solver.add(globals.InputBufferLength == 0)
                        tmp_state.solver.add(globals.OutputBufferLength == 0)
                        if tmp_state.satisfiable() and str(target_base) not in state.globals['tainted_MmIsAddressValid']:
                            utils.print_vuln('null pointer dereference - input buffer', 'write input buffer', state, {}, {'write to': str(state.inspect.mem_write_address)})
                elif target == 'Type3InputBuffer' or target == 'UserBuffer':
                    # If Type3InputBuffer or UserBuffer is a pointer, check whether it is controllable.
                    if target == 'Type3InputBuffer':
                        tmp_state.solver.add(globals.Type3InputBuffer == 0x87)
                    elif target == 'UserBuffer':
                        tmp_state.solver.add(globals.UserBuffer == 0x87)

                    if tmp_state.satisfiable():
                        utils.print_vuln('read/write controllable address', 'write', state, {}, {'write to': str(state.inspect.mem_write_address)})
                else:
                    # Only detect the allocated memory in case of false positive.
                    if '+' in str(tmp_state.inspect.mem_write_address):
                        return
                    tmp_state.solver.add(tmp_state.inspect.mem_write_address == 0)
                    if tmp_state.satisfiable():
                        utils.print_vuln('null pointer dereference - allocated memory', 'write allocated memory', state, {}, {'write to': str(state.inspect.mem_write_address)})
                
            # We symbolize the address of the tainted buffer because we want to detect the vulnerability when the driver reads/writes to/from the buffer.
            if utils.tainted_buffer(target_base) and str(target_base) not in state.globals:
                tmp_state = state.copy()
                tmp_state.solver.add(target_base == globals.FIRST_ADDR)
                if not tmp_state.satisfiable():
                    break
                
                state.globals[str(target_base)] = True
                mem = claripy.BVS(f'*{str(target_base)}', 8 * 0x200).reversed
                addr = utils.next_base_addr()
                state.solver.add(target_base == addr)
                state.memory.store(addr, mem, 0x200, disable_actions=True, inspect=False)

def b_address_concretization_before(state):
    utils.print_debug(f'address_concretization_before_hook: {state}\n\taddress_concretization_strategy: {state.inspect.address_concretization_strategy}\n\taddress_concretization_action: {state.inspect.address_concretization_action}\n\taddress_concretization_memory: {state.inspect.address_concretization_memory}\n\taddress_concretization_expr: {state.inspect.address_concretization_expr}\n\taddress_concretization_add_constraints: {state.inspect.address_concretization_add_constraints}\n\taddress_concretization_result: {state.inspect.address_concretization_result}\n')

def b_address_concretization_after(state):
    utils.print_debug(f'address_concretization_after_hook: {state}\n\taddress_concretization_strategy: {state.inspect.address_concretization_strategy}\n\taddress_concretization_action: {state.inspect.address_concretization_action}\n\taddress_concretization_memory: {state.inspect.address_concretization_memory}\n\taddress_concretization_expr: {state.inspect.address_concretization_expr}\n\taddress_concretization_add_constraints: {state.inspect.address_concretization_add_constraints}\n\taddress_concretization_result: {state.inspect.address_concretization_result}\n')

def b_call(state):
    ret_addr = state.solver.eval(state.memory.load(state.regs.rsp, state.arch.bytes, endness=state.arch.memory_endness))
    utils.print_debug(f'call: state: {state}, ret_addr: {hex(ret_addr)}, function addr: {state.inspect.function_address})')

    # Check if the function address to call is tainted.
    if utils.tainted_buffer(state.inspect.function_address):
        state.regs.rip = 0x1337
        utils.print_vuln('arbitrary shellcode execution', '', state, {}, {'function address': str(state.inspect.function_address), 'return address': hex(ret_addr)})
    
    # If the number of function address evaluated is more than 1, skip the call.
    if len(state.solver.eval_upto(state.inspect.function_address, 2)) > 1:
        tmp_state = state.copy()
        tmp_state.regs.rip = globals.DO_NOTHING
        globals.simgr.deferred.append(tmp_state)
        return angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']().execute(state)

def b_dirty(state):
    utils.print_debug(f'dirty: state: {state}, dirty name: {state.inspect.dirty_name}, dirty handler: {state.inspect.dirty_handler}, dirty args: {state.inspect.dirty_args}, dirty result: {state.inspect.dirty_result})')
