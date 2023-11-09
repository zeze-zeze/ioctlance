import globals
import utils
import claripy
import angr
import ipdb

def wrmsr_hook(state):
    # Check if we can control the parameters of wrmsr.
    if utils.tainted_buffer(state.regs.eax) and utils.tainted_buffer(state.regs.ecx) and utils.tainted_buffer(state.regs.edx):
        # Check whether the regsiter is constrained.
        tmp_state = state.copy()
        tmp_state.solver.add(claripy.Or(tmp_state.regs.ecx == 0x00000174, tmp_state.regs.ecx == 0x00000175, tmp_state.regs.ecx == 0x00000176, tmp_state.regs.ecx == 0xC0000081, tmp_state.regs.ecx == 0xC0000082, tmp_state.regs.ecx == 0xC0000083))

        if tmp_state.satisfiable():
            utils.print_vuln('arbitrary wrmsr', '', state, {'Register': str(state.regs.ecx), 'Value': (str(state.regs.edx), str(state.regs.eax))}, {})


def out_hook(state):
    # Check if we can control the parameters of out.
    if utils.tainted_buffer(state.regs.eax) and utils.tainted_buffer(state.regs.edx):
        # Check whether the port is constrained (can be 0xcf9 or not).
        tmp_state = state.copy()
        tmp_state.solver.add(tmp_state.regs.dx == 0xcf9)
        tmp_state.solver.add(tmp_state.regs.ax == 0xe)
        if tmp_state.satisfiable():
            utils.print_vuln('arbitrary out', '', state, {'Port': str(state.regs.dx), 'Data': str(state.regs.al)}, {})


def rep_movsb_hook(state):
    dst = state.regs.rdi
    src = state.regs.rsi
    count = state.solver.min(state.regs.ecx)
    if count <= 0:
        count = 1
    elif count > 0x1000:
        count = 0x1000
    
    utils.print_debug(f'rep_movsb_hook: {dst}, {src}, {count}')
    val = state.memory.load(src, count)
    state.memory.store(dst, val, count)
    
def rep_movsw_hook(state):
    dst = state.regs.rdi
    src = state.regs.rsi
    count = state.solver.min(state.regs.ecx)
    if count <= 0:
        count = 1
    elif count > 0x1000:
        count = 0x1000

    for i in range(count):
        val = state.memory.load(src + i*2, 2, endness=state.arch.memory_endness)
        state.memory.store(dst + i*2, val, 2, endness=state.arch.memory_endness)
    state.add_constraints(count == 0)

def rep_movsd_hook(state):
    dst = state.regs.rdi
    src = state.regs.rsi
    count = state.solver.min(state.regs.ecx)
    if count <= 0:
        count = 1
    elif count > 0x1000:
        count = 0x1000

    for i in range(count):
        val = state.memory.load(src + i*4, 4, endness=state.arch.memory_endness)
        state.memory.store(dst + i*4, val, 4, endness=state.arch.memory_endness)
    state.add_constraints(count == 0)


def rep_stosb_hook(state):
    rcx = state.solver.min(state.regs.rcx)
    if rcx > 0x1000:
        rcx = 0x1000
    rdi = state.regs.rdi
    value = state.regs.al

    while rcx > 0:
        state.memory.store(rdi, value)
        rdi += 1
        rcx -= 1

    state.regs.rcx = 0
    state.regs.rdi = rdi

def rep_stosw_hook(state):
    rcx = state.solver.min(state.regs.rcx)
    if rcx > 0x1000:
        rcx = 0x1000
    rdi = state.regs.rdi
    value = state.regs.ax

    while rcx > 0:
        state.memory.store(rdi, value, 2, endness=state.arch.memory_endness)
        rdi += 2
        rcx -= 1

    state.regs.rcx = 0
    state.regs.rdi = rdi

def rep_stosd_hook(state):
    rcx = state.solver.min(state.regs.rcx)
    if rcx > 0x1000:
        rcx = 0x1000
    rdi = state.regs.rdi
    value = state.regs.eax

    while rcx > 0:
        state.memory.store(rdi, value, 4, endness=state.arch.memory_endness)
        rdi += 4
        rcx -= 1

    state.regs.rcx = 0
    state.regs.rdi = rdi

def rep_stosq_hook(state):
    rcx = state.solver.min(state.regs.rcx)
    if rcx > 0x1000:
        rcx = 0x1000
    rdi = state.regs.rdi
    value = state.regs.rax

    while rcx > 0:
        state.memory.store(rdi, value, 8, endness=state.arch.memory_endness)
        rdi += 8
        rcx -= 1

    state.regs.rcx = 0
    state.regs.rdi = rdi


def int_hook(state):
    state.kill()
    return

def rdpmc_hook(state):
    return

def outs_hook(state):
    return

def lock_hook(state):
    return

def ins_hook(state):
    return

def lfence_hook(state):
    return

def sidt_hook(state):
    return

def lidt_hook(state):
    return

def pushfw_hook(state):
    flags = state.regs.rflags
    state.regs.rsp -= state.arch.bytes
    state.memory.store(state.regs.rsp, flags, state.arch.bytes, endness=state.arch.memory_endness)
    return

def popfw_hook(state):
    flags = state.memory.load(state.regs.rsp, state.arch.bytes, endness=state.arch.memory_endness)
    state.regs.rsp += state.arch.bytes
    state.regs.rflags = flags
    return

def indirect_jmp_hook(state):
    # Evaluate the indirect jmp address.
    mnemonic = globals.proj.factory.block(state.addr).capstone.insns[0].mnemonic
    op = globals.proj.factory.block(state.addr).capstone.insns[0].op_str
    if op == 'rax' or op == 'rbx' or op == 'rcx' or op == 'rdx':
        if op == 'rax':
            jmp_addrs = state.solver.eval_upto(state.regs.rax, 0x20)
        elif op == 'rbx':
            jmp_addrs = state.solver.eval_upto(state.regs.rbx, 0x20)
        elif op == 'rcx':
            jmp_addrs = state.solver.eval_upto(state.regs.rcx, 0x20)
        elif op == 'rdx':
            jmp_addrs = state.solver.eval_upto(state.regs.rdx, 0x20)

        utils.print_debug(f'indirect jmp\n\tstate: {state}\n\taddr: {hex(state.addr)}\n\tinstruction\n\t\t{globals.proj.factory.block(state.addr).capstone.insns}\n\t\t{globals.proj.factory.block(state.addr).capstone.insns[0].mnemonic} {globals.proj.factory.block(state.addr).capstone.insns[0].op_str}\n\tjmp_addrs: {[hex(i) for i in jmp_addrs]}\n')
        if len(jmp_addrs) > 1:
            # Iterate all possible jmp addresses and insert them into the deferred stash.
            for i in range(1, len(jmp_addrs)):
                tmp_state = state.copy()
                
                if op == 'rax':
                    tmp_state.add_constraints(tmp_state.regs.rax == jmp_addrs[i])
                elif op == 'rbx':
                    tmp_state.add_constraints(tmp_state.regs.rbx == jmp_addrs[i])
                elif op == 'rcx':
                    tmp_state.add_constraints(tmp_state.regs.rcx == jmp_addrs[i])
                elif op == 'rdx':
                    tmp_state.add_constraints(tmp_state.regs.rdx == jmp_addrs[i])

                globals.simgr.deferred.append(tmp_state)

            if op == 'rax':
                state.add_constraints(state.regs.rax == jmp_addrs[0])
            elif op == 'rbx':
                state.add_constraints(state.regs.rbx == jmp_addrs[0])
            elif op == 'rcx':
                state.add_constraints(state.regs.rcx == jmp_addrs[0])
            elif op == 'rdx':
                state.add_constraints(state.regs.rdx == jmp_addrs[0])
        elif len(jmp_addrs) == 1:
            # The jmp address is constrained.
            addr = state.addr
            globals.proj.unhook(addr)
            globals.simgr.step()
            globals.proj.hook(addr, indirect_jmp_hook, 0)
        else:
            # Kill the state if there is no candidate jmp address.
            tmp_state = state.copy()
            tmp_state.regs.rip += globals.proj.factory.block(state.addr).capstone.insns[0].size
            globals.simgr.deferred.append(tmp_state)

            tmp_state = state.copy()
            tmp_state.regs.rip = globals.DO_NOTHING
            globals.simgr.deferred.append(tmp_state)

            state.kill()
    else:
        # Maybe some situations are not considered.
        ipdb.set_trace()

    return
