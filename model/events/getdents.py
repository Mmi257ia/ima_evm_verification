from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard
from anis.model.expressions import function_value


def getdents(m: Machine,
             _proc: Machine.ProcsItem | None,
             _fd: Machine.FileDescriptorsExtendedItem | None) -> Event:

    proc = Parameter(_proc)
    fd = Parameter(_fd)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~proc) in m.Procs)))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    ((~proc), (~fd)) in m.ProcFDs)))

    _grd3 = Guard('grd3', lambda _: (_(3, 
    function_value(m.FDFile, (~fd)) in m.Folders)))


    return Event("getdents", _grd1, _grd2, _grd3)
