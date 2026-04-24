from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import relation_image, subtract_domain, function_value


def exit_group(m: Machine,
               _proc: Machine.ProcsItem | None,
               _fds: frozenset[Machine.FileDescriptorsExtendedItem] | None) -> Event:

    proc = Parameter(_proc)
    fds = Parameter(_fds)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~proc) in (m.Procs - frozenset((m.INIT,))))))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    (~fds) <= relation_image(m.ProcFDs, frozenset(((~proc),))))))

    _grd3 = Guard('grd3', lambda _: (_(3, 
    not any (True for fd in (~fds) for p in (m.Procs - frozenset(((~proc),))) if not (
        (p, fd) not in m.ProcFDs
    )))))


    _act1 = Action('act1', m, 'Procs', lambda: ((m.Procs - frozenset(((~proc),)))))

    _act2 = Action('act2', m, 'ProcUser', lambda: (subtract_domain(m.ProcUser, frozenset(((~proc),)))))

    _act3 = Action('act3', m, 'ProcGroup', lambda: (subtract_domain(m.ProcGroup, frozenset(((~proc),)))))

    _act4 = Action('act4', m, 'ProcUmask', lambda: (subtract_domain(m.ProcUmask, frozenset(((~proc),)))))

    _act5 = Action('act5', m, 'ProcEXE', lambda: (subtract_domain(m.ProcEXE, frozenset(((~proc),)))))

    _act6 = Action('act6', m, 'ProcArgv', lambda: (subtract_domain(m.ProcArgv, frozenset(((~proc),)))))

    _act7 = Action('act7', m, 'ProcEnvp', lambda: (subtract_domain(m.ProcEnvp, frozenset(((~proc),)))))

    _act8 = Action('act8', m, 'ProcFDs', lambda: (subtract_domain(m.ProcFDs, frozenset(((~proc),)))))

    _act9 = Action('act9', m, 'ProcCwd', lambda: (subtract_domain(m.ProcCwd, frozenset(((~proc),)))))

    _act10 = Action('act10', m, 'ProcParent', lambda: ((frozenset((x, y) for x in (m.Procs - frozenset((m.INIT, (~proc)))) if function_value(m.ProcParent, x) != (~proc) for y in (function_value(m.ProcParent, x),)) | 
    frozenset((x, y) for x in (m.Procs - frozenset((m.INIT, (~proc)))) if function_value(m.ProcParent, x) == (~proc) for y in (m.INIT,)))))

    _act11 = Action('act11', m, 'FDs', lambda: ((m.FDs - (~fds))))

    _act12 = Action('act12', m, 'FDFlags', lambda: (subtract_domain(m.FDFlags, (~fds))))

    _act13 = Action('act13', m, 'FDFile', lambda: (subtract_domain(m.FDFile, (~fds))))

    _act14 = Action('act14', m, 'FDNumber', lambda: (subtract_domain(m.FDNumber, (~fds))))


    return Event("exit_group", _grd1, _grd2, _grd3, _act1, _act2, _act3, _act4, _act5, _act6, _act7, _act8, _act9, _act10, _act11, _act12, _act13, _act14)
