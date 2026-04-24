from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import subtract_range, subtract_domain


def close(m: Machine,
          _proc: Machine.ProcsItem | None,
          _fd: Machine.FileDescriptorsExtendedItem | None,
          _fds: frozenset[Machine.FileDescriptorsExtendedItem] | None) -> Event:

    proc = Parameter(_proc)
    fd = Parameter(_fd)
    fds = Parameter(_fds)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~proc) in m.Procs)))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    ((~proc), (~fd)) in m.ProcFDs)))

    _grd3 = Guard('grd3', lambda _: (_(3, 
    (~fds) <= m.FDs)))

    _grd4 = Guard('grd4', lambda _: (_(4, 
    (any (True for p in (m.Procs - frozenset(((~proc),))) if (p, (~fd)) in m.ProcFDs)) == (len((~fds)) == 0))))

    _grd5 = Guard('grd5', lambda _: (_(5, 
    (not any (True for p in (m.Procs - frozenset(((~proc),))) if not (
        (p, (~fd)) not in m.ProcFDs
    ))) == ((~fds) == frozenset(((~fd),))))))


    _act1 = Action('act1', m, 'FDs', lambda: ((m.FDs - (~fds))))

    _act2 = Action('act2', m, 'ProcFDs', lambda: (subtract_range(m.ProcFDs, (~fds))))

    _act3 = Action('act3', m, 'FDFlags', lambda: (subtract_domain(m.FDFlags, (~fds))))

    _act4 = Action('act4', m, 'FDFile', lambda: (subtract_domain(m.FDFile, (~fds))))

    _act5 = Action('act5', m, 'FDNumber', lambda: (subtract_domain(m.FDNumber, (~fds))))


    return Event("close", _grd1, _grd2, _grd3, _grd4, _grd5, _act1, _act2, _act3, _act4, _act5)
