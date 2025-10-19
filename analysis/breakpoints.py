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

def b_mem_read(state: angr.SimState):
    target_base = utils.get_base_address(state.inspect.mem_read_address)
    utils.print_debug(f'mem_read {state}, {state.inspect.mem_read_address}, {target_base}, {state.inspect.mem_read_expr}, {state.inspect.mem_read_length}, {state.inspect.mem_read_condition}')

    # First we check for an ARW vulnerability. If we cannot find one there, we check for NPD
    if not utils.check_arw_vuln(state, state.inspect.mem_read_address, False):
        utils.check_npd_vuln(state, state.inspect.mem_read_address, False)
    
    # If we are reading at an offset of a user-provided buffer, we need to one-time create a symbolic space that represents that space
    # In this way we can later see if we are reading from an address obtained by dereferencing this space (a tainted address)
    if utils.tainted_buffer(target_base):
        utils.symbolyze_buffer(state, target_base)

def b_mem_write(state: angr.SimState):
    target_base = utils.get_base_address(state.inspect.mem_write_address)
    utils.print_debug(f'mem_write {state}, {state.inspect.mem_write_address}, {target_base}, {state.inspect.mem_write_expr}, {state.inspect.mem_write_length}, {state.inspect.mem_write_condition}')

    # First we check for an ARW vulnerability. If we cannot find one there, we check for NPD
    if not utils.check_arw_vuln(state, state.inspect.mem_write_address, True):
        utils.check_npd_vuln(state, state.inspect.mem_write_address, True)
    
    # Same as b_mem_read prologue
    if utils.tainted_buffer(target_base):
        utils.symbolyze_buffer(state, target_base)

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
