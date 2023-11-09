import angr
import utils
import ipdb
import time
import globals


class ExplosionDetector(angr.exploration_techniques.ExplorationTechnique):
    def __init__(self, stashes=('active', 'deferred', 'errored'), threshold=1000):
        super(ExplosionDetector, self).__init__()
        self._stashes = stashes
        self._threshold = threshold
        self.total_time = time.time()
        self.ioctl_history = []
        self.ioctl_timer = {}
        self.state_exploded_bool = False

    def detect_recursion(self, state):
        # Kill the state if recursion detected.
        callstack_func_addr = [c.func_addr for c in state.callstack]
        if len(callstack_func_addr) != len(set(callstack_func_addr)):
            utils.print_debug(f'recursion detected {state}\n')
            return True
        return False

    def detect_timeout(self, state, ioctl):
        # Kill the state matching the IoControlCode.
        if 'IoControlCode' in state.globals:
            if state.globals['IoControlCode'] == ioctl:
                return True
        return False

    def step(self, simgr, stash='active', **kwargs):
        # Drop the states with specified IoControlCode if timeout.
        simgr = simgr.step(stash=stash, **kwargs)
        for state in simgr.active:
            if 'IoControlCode' not in state.globals and globals.IoControlCode != None:
                try:
                    # Evaluate an IoControlCode and store it in state.globals.
                    ioctl = state.solver.eval_one(globals.IoControlCode)
                    state.globals['IoControlCode'] = ioctl
                    if ioctl not in self.ioctl_history:
                        utils.print_info(f'start testing IoControlCode {hex(ioctl)}')
                        globals.basic_info['IoControlCodes'].append(hex(ioctl))
                        self.ioctl_timer[ioctl] = time.time()
                except angr.errors.SimValueError:
                    pass
            elif 'IoControlCode' in state.globals:
                # Drop the states if timeout.
                if globals.args.timeout and time.time() - self.ioctl_timer[state.globals['IoControlCode']] > globals.args.timeout:
                    for stash in self._stashes:
                        simgr.move(from_stash=stash, to_stash='_Drop', filter_func=lambda s: self.detect_timeout(s, state.globals['IoControlCode']))
                    utils.print_info(f'IoControlCode {hex(state.globals["IoControlCode"])} timeout: {globals.args.timeout} seconds')

        # Drop the states if recursion detected.
        if not globals.args.recursion:
            for stash in self._stashes:
                simgr.move(from_stash=stash, to_stash='_Drop', filter_func=self.detect_recursion)

        if len(simgr.unconstrained) > 0:
            simgr.move(from_stash='unconstrained', to_stash='_Drop', filter_func=lambda _: True)

        # Drop all states if the number of states more than the threshold.
        total = 0
        for st in self._stashes:
            if hasattr(simgr, st):
                total += len(getattr(simgr, st))

        # Drop all states if the total states more than the threshold or reaching timeout.
        if total >= self._threshold or (globals.args.total_timeout and time.time() - self.total_time > globals.args.total_timeout):
            if total >= self._threshold:
                utils.print_info(f'State explosion detected, over {total} states: {simgr}')
                self.state_exploded_bool = True
            elif time.time() - self.total_time > globals.args.total_timeout:
                utils.print_info(f'reach total timeout: {globals.args.total_timeout} seconds')
            
            for st in self._stashes:
                if hasattr(simgr, st):
                    simgr.move(from_stash=st, to_stash='_Drop', filter_func=lambda _: True)

        return simgr