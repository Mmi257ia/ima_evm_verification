from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import function_value, override_relation


def fchown(m: Machine,
           _proc: Machine.ProcsItem | None,
           _fd: Machine.FileDescriptorsExtendedItem | None,
           _owner: Machine.UsersItem | None,
           _group: Machine.GroupsItem | None,
           _perms: frozenset[Machine.PermissionsItem] | None) -> Event:

    proc = Parameter(_proc)
    fd = Parameter(_fd)
    owner = Parameter(_owner)
    group = Parameter(_group)
    perms = Parameter(_perms)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~proc) in m.Procs)))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    ((~proc), (~fd)) in m.ProcFDs)))

    _grd3 = Guard('grd3', lambda _: (_(3, 
    function_value(m.FDFile, (~fd)) in m.Files)))

    _grd4 = Guard('grd4', lambda _: (_(4, 
    (~owner) in m.Users)))

    _grd5 = Guard('grd5', lambda _: (_(5, 
    (~group) in m.Groups)))

    _grd6 = Guard('grd6', lambda _: ((_(6, 
    function_value(m.ProcUser, (~proc)) == m.ROOT_USER)) or (_(7, (~owner) == function_value(m.ProcUser, (~proc))))))

    _grd7 = Guard('grd7', lambda _: ((_(8, 
    function_value(m.ProcUser, (~proc)) == m.ROOT_USER)) or (_(9, (function_value(m.ProcUser, (~proc)), (~group)) in m.UserGroups))))

    _grd8 = Guard('grd8', lambda _: ((_(10, 
    function_value(m.ProcUser, (~proc)) == m.ROOT_USER)) or (_(11, function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, function_value(m.FDFile, (~fd)))))))

    _grd9 = Guard('grd9', lambda _: (not ((_(12, 
    function_value(m.FDFile, (~fd)) not in m.Folders)) and (_(13, m.GEXECUTE in function_value(m.DACPermissions, function_value(m.FDFile, (~fd)))))) or (_(14, (~perms) == (function_value(m.DACPermissions, function_value(m.FDFile, (~fd))) - frozenset((m.SET_UID, m.SET_GID)))))))

    _grd10 = Guard('grd10', lambda _: (not ((_(15, 
    function_value(m.FDFile, (~fd)) not in m.Folders)) and (_(16, m.GEXECUTE not in function_value(m.DACPermissions, function_value(m.FDFile, (~fd)))))) or (_(17, (~perms) == (function_value(m.DACPermissions, function_value(m.FDFile, (~fd))) - frozenset((m.SET_UID,)))))))

    _grd11 = Guard('grd11', lambda _: (not (_(18, 
    function_value(m.FDFile, (~fd)) in m.Folders)) or (_(19, (~perms) == function_value(m.DACPermissions, function_value(m.FDFile, (~fd)))))))


    _act1 = Action('act1', m, 'FileUser', lambda: (override_relation(m.FileUser, frozenset(((function_value(m.FDFile, (~fd)), (~owner)),)))))

    _act2 = Action('act2', m, 'FileGroup', lambda: (override_relation(m.FileGroup, frozenset(((function_value(m.FDFile, (~fd)), (~group)),)))))

    _act3 = Action('act3', m, 'DACPermissions', lambda: (override_relation(m.DACPermissions, frozenset(((function_value(m.FDFile, (~fd)), (~perms)),)))))


    return Event("fchown", _grd1, _grd2, _grd3, _grd4, _grd5, _grd6, _grd7, _grd8, _grd9, _grd10, _grd11, _act1, _act2, _act3)
