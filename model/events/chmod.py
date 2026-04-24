from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import function_value, relation_domain, relation_image, override_relation, subtract_domain


def chmod(m: Machine,
          _proc: Machine.ProcsItem | None,
          _parent: Machine.FilesItem | None,
          _file: Machine.FilesItem | None,
          _name: Machine.StringsItem | None,
          _mode: frozenset[Machine.PermissionsItem] | None,
          _perms: frozenset[Machine.PermissionsItem] | None) -> Event:

    proc = Parameter(_proc)
    parent = Parameter(_parent)
    file = Parameter(_file)
    name = Parameter(_name)
    mode = Parameter(_mode)
    perms = Parameter(_perms)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~proc) in m.Procs)))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    ((~file), ((~parent), (~name))) in m.FileParents)))

    _grd3 = Guard('grd3', lambda _: (_(3, 
    (~mode) <= m.PERMISSIONS)))

    _grd4 = Guard('grd4', lambda _: ((_(4, 
    function_value(m.ProcUser, (~proc)) == m.ROOT_USER)) or (_(5, function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, (~file))))))

    _grd5 = Guard('grd5', lambda _: (_(6, 
    not any (True for f in (function_value(m.PathToRoot, (~parent)) | frozenset(((~parent),))) if function_value(m.ProcUser, (~proc)) != m.ROOT_USER if not (
        (((((function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, f) and 
        m.UEXECUTE in function_value(m.DACPermissions, f) or 
        function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, f) and 
        (f not in relation_domain(m.MaskACL) or len(function_value(m.MaskACL, f)) == 0) and 
        function_value(m.FileGroup, f) != function_value(m.ProcGroup, (~proc)) and (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, f)) not in m.UserGroups and 
        m.OEXECUTE in function_value(m.DACPermissions, f)) or 
        function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, f) and 
        (f, function_value(m.ProcUser, (~proc))) in relation_domain(m.UserACL) and m.UEXECUTE in function_value(m.UserACL, (f, function_value(m.ProcUser, (~proc)))) and 
        m.GEXECUTE in function_value(m.MaskACL, f)) or 
        function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, f) and 
        (f, function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL) and 
        any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if 
        ((f, g) in relation_domain(m.GroupACL) and m.GEXECUTE in function_value(m.GroupACL, (f, g)) or g == function_value(m.FileGroup, f) and f in relation_domain(m.GroupObjACL) and m.GEXECUTE in function_value(m.GroupObjACL, f))) and 
        f in relation_domain(m.MaskACL) and m.GEXECUTE in function_value(m.MaskACL, f)) or 
        function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, f) and 
        f not in relation_domain(m.MaskACL) and 
        (function_value(m.FileGroup, f) == function_value(m.ProcGroup, (~proc)) or (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, f)) in m.UserGroups) and 
        m.GEXECUTE in function_value(m.DACPermissions, f)) or 
        function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, f) and 
        f in relation_domain(m.MaskACL) and len(function_value(m.MaskACL, f)) != 0 and 
        (f, function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL) and 
        not any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if not (
            (f, g) not in relation_domain(m.GroupACL)
        )) and 
        function_value(m.FileGroup, f) != function_value(m.ProcGroup, (~proc)) and (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, f)) not in m.UserGroups and 
        m.OEXECUTE in function_value(m.DACPermissions, f))
    )))))

    _grd6 = Guard('grd6', lambda _: (not (not (((_(7, 
    (~file) in m.Folders)) or (_(8, function_value(m.ProcUser, (~proc)) == m.ROOT_USER))) or (_(9, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) in m.UserGroups)))) or (_(10, (~perms) == ((~mode) - frozenset((m.SET_GID,)))))))

    _grd7 = Guard('grd7', lambda _: (not (((_(11, 
    (~file) in m.Folders)) or (_(12, function_value(m.ProcUser, (~proc)) == m.ROOT_USER))) or (_(13, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) in m.UserGroups))) or (_(14, (~perms) == (~mode)))))


    _act1 = Action('act1', m, 'DACPermissions', lambda: (override_relation(m.DACPermissions, frozenset((((~file), (~perms)),)))))

    _act2 = Action('act2', m, 'MaskACL', lambda: ((subtract_domain(m.MaskACL, frozenset(((~file),))) | frozenset((((~file), ((~mode) & frozenset((m.GREAD, m.GWRITE, m.GEXECUTE)))),))) if ((~file) in relation_domain(m.MaskACL)) else m.MaskACL))

    _act3 = Action('act3', m, 'GroupObjACL', lambda: ((subtract_domain(m.GroupObjACL, frozenset(((~file),))) | frozenset((((~file), ((~mode) & frozenset((m.GREAD, m.GWRITE, m.GEXECUTE)))),))) if ((~file) not in relation_domain(m.MaskACL)) else m.GroupObjACL))


    return Event("chmod", _grd1, _grd2, _grd3, _grd4, _grd5, _grd6, _grd7, _act1, _act2, _act3)
