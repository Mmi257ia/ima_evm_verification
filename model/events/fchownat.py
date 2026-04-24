from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import function_value, relation_domain, relation_image, override_relation


def fchownat(m: Machine,
             _proc: Machine.ProcsItem | None,
             _dirfd: Machine.FileDescriptorsExtendedItem | None,
             _cwd: Machine.FilesItem | None,
             _parent: Machine.FilesItem | None,
             _file: Machine.FilesItem | None,
             _name: Machine.StringsItem | None,
             _owner: Machine.UsersItem | None,
             _group: Machine.GroupsItem | None,
             _perms: frozenset[Machine.PermissionsItem] | None) -> Event:

    proc = Parameter(_proc)
    dirfd = Parameter(_dirfd)
    cwd = Parameter(_cwd)
    parent = Parameter(_parent)
    file = Parameter(_file)
    name = Parameter(_name)
    owner = Parameter(_owner)
    group = Parameter(_group)
    perms = Parameter(_perms)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~proc) in m.Procs)))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    (~dirfd) in m.FILE_DESCRIPTORS_EXTENDED)))

    _grd3 = Guard('grd3', lambda _: (_(3, 
    (~cwd) in m.Folders)))

    _grd4 = Guard('grd4', lambda _: (not (_(4, 
    (~dirfd) == m.AT_FDCWD)) or (_(5, (~cwd) == function_value(m.ProcCwd, (~proc))))))

    _grd5 = Guard('grd5', lambda _: (not (_(6, 
    (~dirfd) != m.AT_FDCWD)) or ((_(7, ((~proc), (~dirfd)) in m.ProcFDs)) and (_(8, (~cwd) == function_value(m.FDFile, (~dirfd)))))))

    _grd6 = Guard('grd6', lambda _: (_(9, 
    ((~file), ((~parent), (~name))) in m.FileParents)))

    _grd7 = Guard('grd7', lambda _: (_(10, 
    (~owner) in m.Users)))

    _grd8 = Guard('grd8', lambda _: (_(11, 
    (~group) in m.Groups)))

    _grd9 = Guard('grd9', lambda _: ((_(12, 
    function_value(m.ProcUser, (~proc)) == m.ROOT_USER)) or (_(13, (~owner) == function_value(m.ProcUser, (~proc))))))

    _grd10 = Guard('grd10', lambda _: ((_(14, 
    function_value(m.ProcUser, (~proc)) == m.ROOT_USER)) or (_(15, (function_value(m.ProcUser, (~proc)), (~group)) in m.UserGroups))))

    _grd11 = Guard('grd11', lambda _: (_(16, 
    not any (True for f in (function_value(m.PathToRoot, (~parent)) | frozenset(((~parent),))) if function_value(m.ProcUser, (~proc)) != m.ROOT_USER if f not in function_value(m.PathToRoot, (~cwd)) if not (
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

    _grd12 = Guard('grd12', lambda _: ((_(17, 
    function_value(m.ProcUser, (~proc)) == m.ROOT_USER)) or (_(18, function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, (~file))))))

    _grd13 = Guard('grd13', lambda _: (not ((_(19, 
    (~file) not in m.Folders)) and (_(20, m.GEXECUTE in function_value(m.DACPermissions, (~file))))) or (_(21, (~perms) == (function_value(m.DACPermissions, (~file)) - frozenset((m.SET_UID, m.SET_GID)))))))

    _grd14 = Guard('grd14', lambda _: (not ((_(22, 
    (~file) not in m.Folders)) and (_(23, m.GEXECUTE not in function_value(m.DACPermissions, (~file))))) or (_(24, (~perms) == (function_value(m.DACPermissions, (~file)) - frozenset((m.SET_UID,)))))))

    _grd15 = Guard('grd15', lambda _: (not (_(25, 
    (~file) in m.Folders)) or (_(26, (~perms) == function_value(m.DACPermissions, (~file))))))


    _act1 = Action('act1', m, 'FileUser', lambda: (override_relation(m.FileUser, frozenset((((~file), (~owner)),)))))

    _act2 = Action('act2', m, 'FileGroup', lambda: (override_relation(m.FileGroup, frozenset((((~file), (~group)),)))))

    _act3 = Action('act3', m, 'DACPermissions', lambda: (override_relation(m.DACPermissions, frozenset((((~file), (~perms)),)))))


    return Event("fchownat", _grd1, _grd2, _grd3, _grd4, _grd5, _grd6, _grd7, _grd8, _grd9, _grd10, _grd11, _grd12, _grd13, _grd14, _grd15, _act1, _act2, _act3)
