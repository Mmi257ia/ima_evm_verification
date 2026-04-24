from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import function_value, override_relation, relation_domain, subtract_domain


def fchmod(m: Machine,
           _proc: Machine.ProcsItem | None,
           _fd: Machine.FileDescriptorsExtendedItem | None,
           _mode: frozenset[Machine.PermissionsItem] | None,
           _perms: frozenset[Machine.PermissionsItem] | None) -> Event:

    proc = Parameter(_proc)
    fd = Parameter(_fd)
    mode = Parameter(_mode)
    perms = Parameter(_perms)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~proc) in m.Procs)))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    ((~proc), (~fd)) in m.ProcFDs)))

    _grd3 = Guard('grd3', lambda _: (_(3, 
    function_value(m.FDFile, (~fd)) in m.Files)))

    _grd4 = Guard('grd4', lambda _: (_(4, 
    (~mode) <= m.PERMISSIONS)))

    _grd5 = Guard('grd5', lambda _: ((_(5, 
    function_value(m.ProcUser, (~proc)) == m.ROOT_USER)) or (_(6, function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, function_value(m.FDFile, (~fd)))))))

    _grd6 = Guard('grd6', lambda _: (not (not (((_(7, 
    function_value(m.FDFile, (~fd)) in m.Folders)) or (_(8, function_value(m.ProcUser, (~proc)) == m.ROOT_USER))) or (_(9, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, function_value(m.FDFile, (~fd)))) in m.UserGroups)))) or (_(10, (~perms) == ((~mode) - frozenset((m.SET_GID,)))))))

    _grd7 = Guard('grd7', lambda _: (not (((_(11, 
    function_value(m.FDFile, (~fd)) in m.Folders)) or (_(12, function_value(m.ProcUser, (~proc)) == m.ROOT_USER))) or (_(13, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, function_value(m.FDFile, (~fd)))) in m.UserGroups))) or (_(14, (~perms) == (~mode)))))


    _act1 = Action('act1', m, 'DACPermissions', lambda: (override_relation(m.DACPermissions, frozenset(((function_value(m.FDFile, (~fd)), (~perms)),)))))

    _act2 = Action('act2', m, 'MaskACL', lambda: ((subtract_domain(m.MaskACL, frozenset((function_value(m.FDFile, (~fd)),))) | frozenset(((function_value(m.FDFile, (~fd)), ((~mode) & frozenset((m.GREAD, m.GWRITE, m.GEXECUTE)))),))) if (function_value(m.FDFile, (~fd)) in relation_domain(m.MaskACL)) else m.MaskACL))

    _act3 = Action('act3', m, 'GroupObjACL', lambda: ((subtract_domain(m.GroupObjACL, frozenset((function_value(m.FDFile, (~fd)),))) | frozenset(((function_value(m.FDFile, (~fd)), ((~mode) & frozenset((m.GREAD, m.GWRITE, m.GEXECUTE)))),))) if (function_value(m.FDFile, (~fd)) not in relation_domain(m.MaskACL)) else m.GroupObjACL))


    return Event("fchmod", _grd1, _grd2, _grd3, _grd4, _grd5, _grd6, _grd7, _act1, _act2, _act3)
