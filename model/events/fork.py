from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import function_value, override_relation, cartesian_product, relation_image


def fork(m: Machine,
         _proc: Machine.ProcsItem | None,
         _newProc: Machine.ProcsItem | None) -> Event:

    proc = Parameter(_proc)
    newProc = Parameter(_newProc)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~proc) in m.Procs)))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    (~newProc) in (m.PROCS - m.Procs))))


    _act1 = Action('act1', m, 'Procs', lambda: ((m.Procs | frozenset(((~newProc),)))))

    _act2 = Action('act2', m, 'ProcUser', lambda: (override_relation(m.ProcUser, frozenset((((~newProc), function_value(m.ProcUser, (~proc))),)))))

    _act3 = Action('act3', m, 'ProcGroup', lambda: (override_relation(m.ProcGroup, frozenset((((~newProc), function_value(m.ProcGroup, (~proc))),)))))

    _act4 = Action('act4', m, 'ProcUmask', lambda: (override_relation(m.ProcUmask, frozenset((((~newProc), function_value(m.ProcUmask, (~proc))),)))))

    _act5 = Action('act5', m, 'ProcEXE', lambda: (override_relation(m.ProcEXE, frozenset((((~newProc), function_value(m.ProcEXE, (~proc))),)))))

    _act6 = Action('act6', m, 'ProcArgv', lambda: (override_relation(m.ProcArgv, frozenset((((~newProc), function_value(m.ProcArgv, (~proc))),)))))

    _act7 = Action('act7', m, 'ProcEnvp', lambda: (override_relation(m.ProcEnvp, frozenset((((~newProc), function_value(m.ProcEnvp, (~proc))),)))))

    _act8 = Action('act8', m, 'ProcFDs', lambda: ((m.ProcFDs | cartesian_product(frozenset(((~newProc),)), relation_image(m.ProcFDs, frozenset(((~proc),)))))))

    _act9 = Action('act9', m, 'ProcCwd', lambda: (override_relation(m.ProcCwd, frozenset((((~newProc), function_value(m.ProcCwd, (~proc))),)))))

    _act10 = Action('act10', m, 'ProcParent', lambda: (override_relation(m.ProcParent, frozenset((((~newProc), (~proc)),)))))


    return Event("fork", _grd1, _grd2, _act1, _act2, _act3, _act4, _act5, _act6, _act7, _act8, _act9, _act10)
