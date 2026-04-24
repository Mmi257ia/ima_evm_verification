from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import powerset, override_relation


def login(m: Machine,
          _user: Machine.UsersItem | None,
          _proc: Machine.ProcsItem | None,
          _group: Machine.GroupsItem | None,
          _exeFile: Machine.FilesItem | None,
          _argv: frozenset[Machine.StringsItem] | None,
          _envp: frozenset[Machine.StringsItem] | None,
          _umask: frozenset[Machine.PermissionsItem] | None) -> Event:

    user = Parameter(_user)
    proc = Parameter(_proc)
    group = Parameter(_group)
    exeFile = Parameter(_exeFile)
    argv = Parameter(_argv)
    envp = Parameter(_envp)
    umask = Parameter(_umask)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~user) in m.Users)))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    (~proc) in (m.PROCS - m.Procs))))

    _grd3 = Guard('grd3', lambda _: (_(3, 
    (~group) in m.Groups)))

    _grd4 = Guard('grd4', lambda _: (_(4, 
    (~exeFile) in (m.Files - m.Folders))))

    _grd5 = Guard('grd5', lambda _: (_(5, 
    (~argv) in powerset(m.STRINGS))))

    _grd6 = Guard('grd6', lambda _: (_(6, 
    (~envp) in powerset(m.STRINGS))))

    _grd7 = Guard('grd7', lambda _: (_(7, 
    (~umask) <= (m.PERMISSIONS - m.FILE_MODES))))


    _act1 = Action('act1', m, 'Procs', lambda: ((m.Procs | frozenset(((~proc),)))))

    _act2 = Action('act2', m, 'ProcUser', lambda: (override_relation(m.ProcUser, frozenset((((~proc), (~user)),)))))

    _act3 = Action('act3', m, 'ProcGroup', lambda: (override_relation(m.ProcGroup, frozenset((((~proc), (~group)),)))))

    _act4 = Action('act4', m, 'ProcUmask', lambda: (override_relation(m.ProcUmask, frozenset((((~proc), (~umask)),)))))

    _act5 = Action('act5', m, 'ProcEXE', lambda: (override_relation(m.ProcEXE, frozenset((((~proc), (~exeFile)),)))))

    _act6 = Action('act6', m, 'ProcArgv', lambda: (override_relation(m.ProcArgv, frozenset((((~proc), (~argv)),)))))

    _act7 = Action('act7', m, 'ProcEnvp', lambda: (override_relation(m.ProcEnvp, frozenset((((~proc), (~envp)),)))))

    _act8 = Action('act8', m, 'ProcCwd', lambda: (override_relation(m.ProcCwd, frozenset((((~proc), m.ROOT),)))))

    _act9 = Action('act9', m, 'ProcParent', lambda: (override_relation(m.ProcParent, frozenset((((~proc), m.INIT),)))))


    return Event("login", _grd1, _grd2, _grd3, _grd4, _grd5, _grd6, _grd7, _act1, _act2, _act3, _act4, _act5, _act6, _act7, _act8, _act9)
