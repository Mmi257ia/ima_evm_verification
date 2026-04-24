from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import override_relation


def umask(m: Machine,
          _proc: Machine.ProcsItem | None,
          _mask: frozenset[Machine.PermissionsItem] | None) -> Event:

    proc = Parameter(_proc)
    mask = Parameter(_mask)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~proc) in m.Procs)))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    (~mask) <= (m.PERMISSIONS - m.FILE_MODES))))


    _act1 = Action('act1', m, 'ProcUmask', lambda: (override_relation(m.ProcUmask, frozenset((((~proc), (~mask)),)))))


    return Event("umask", _grd1, _grd2, _act1)
