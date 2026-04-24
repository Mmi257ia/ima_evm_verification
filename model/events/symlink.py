from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import relation_range, function_value, relation_domain, relation_image, override_relation


def symlink(m: Machine,
            _proc: Machine.ProcsItem | None,
            _target_parent: Machine.FilesItem | None,
            _target_name: Machine.StringsItem | None,
            _parent: Machine.FilesItem | None,
            _file: Machine.FilesItem | None,
            _name: Machine.StringsItem | None) -> Event:

    proc = Parameter(_proc)
    target_parent = Parameter(_target_parent)
    target_name = Parameter(_target_name)
    parent = Parameter(_parent)
    file = Parameter(_file)
    name = Parameter(_name)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~proc) in m.Procs)))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    (~parent) in m.Folders)))

    _grd3 = Guard('grd3', lambda _: (_(3, 
    (~name) in m.STRINGS)))

    _grd4 = Guard('grd4', lambda _: (_(4, 
    not any (True for f in m.Files if not (
        (f, ((~parent), (~name))) not in m.FileParents
    )))))

    _grd5 = Guard('grd5', lambda _: (_(5, 
    (~file) in (((m.FILES - m.Files) - relation_range(m.FDFile)) - relation_range(m.ProcCwd)))))

    _grd6 = Guard('grd6', lambda _: (_(6, 
    (~parent) in m.Folders)))

    _grd7 = Guard('grd7', lambda _: (_(7, 
    (~target_parent) in m.FILES)))

    _grd8 = Guard('grd8', lambda _: (_(8, 
    (~target_name) in m.STRINGS)))

    _grd9 = Guard('grd9', lambda _: (_(9, 
    not any (True for f in function_value(m.PathToRoot, (~parent)) if function_value(m.ProcUser, (~proc)) != m.ROOT_USER if not (
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

    _grd10 = Guard('grd10', lambda _: (not (_(10, 
    function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) or (((((((_(11, 
    function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, (~parent)))) and (_(12, 
    frozenset((m.UWRITE, m.UEXECUTE)) <= function_value(m.DACPermissions, (~parent))))) or (((((_(13, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and ((_(14, 
    (~parent) not in relation_domain(m.MaskACL))) or (_(15, len(function_value(m.MaskACL, (~parent))) == 0)))) and (_(16, 
    function_value(m.FileGroup, (~parent)) != function_value(m.ProcGroup, (~proc))))) and (_(17, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~parent))) not in m.UserGroups))) and (_(18, 
    frozenset((m.OWRITE, m.OEXECUTE)) <= function_value(m.DACPermissions, (~parent)))))) or ((((_(19, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and (_(20, 
    ((~parent), function_value(m.ProcUser, (~proc))) in relation_domain(m.UserACL)))) and (_(21, frozenset((m.UWRITE, m.UEXECUTE)) <= function_value(m.UserACL, ((~parent), function_value(m.ProcUser, (~proc))))))) and (_(22, 
    frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.MaskACL, (~parent)))))) or (((((_(23, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and (_(24, 
    ((~parent), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(25, 
    any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if 
    (((~parent), g) in relation_domain(m.GroupACL) and frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.GroupACL, ((~parent), g)) or g == function_value(m.FileGroup, (~parent)) and (~parent) in relation_domain(m.GroupObjACL) and frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.GroupObjACL, (~parent))))))) and (_(26, 
    (~parent) in relation_domain(m.MaskACL)))) and (_(27, frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.MaskACL, (~parent)))))) or ((((_(28, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and (_(29, 
    (~parent) not in relation_domain(m.MaskACL)))) and ((_(30, 
    function_value(m.FileGroup, (~parent)) == function_value(m.ProcGroup, (~proc)))) or (_(31, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~parent))) in m.UserGroups)))) and (_(32, 
    frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.DACPermissions, (~parent)))))) or ((((((((_(33, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and (_(34, 
    (~parent) in relation_domain(m.MaskACL)))) and (_(35, len(function_value(m.MaskACL, (~parent))) != 0))) and (_(36, 
    ((~parent), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(37, 
    not any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if not (
        ((~parent), g) not in relation_domain(m.GroupACL)
    ))))) and (_(38, 
    function_value(m.FileGroup, (~parent)) != function_value(m.ProcGroup, (~proc))))) and (_(39, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~parent))) not in m.UserGroups))) and (_(40, 
    frozenset((m.OWRITE, m.OEXECUTE)) <= function_value(m.DACPermissions, (~parent))))))))

    _grd11 = Guard('grd11', lambda _: (_(41, 
    len(m.Files) < m.MAX_FILES)))


    _act1 = Action('act1', m, 'Files', lambda: ((m.Files | frozenset(((~file),)))))

    _act2 = Action('act2', m, 'DACPermissions', lambda: (override_relation(m.DACPermissions, frozenset((((~file), m.DEF_SYMLINK_PERMS),)))))

    _act3 = Action('act3', m, 'FileUser', lambda: (override_relation(m.FileUser, frozenset((((~file), function_value(m.ProcUser, (~proc))),)))))

    _act4 = Action('act4', m, 'FileGroup', lambda: (override_relation(m.FileGroup, frozenset((((~file), function_value(m.ProcGroup, (~proc))),)))))

    _act5 = Action('act5', m, 'SymLinks', lambda: ((m.SymLinks | frozenset(((~file),)))))

    _act6 = Action('act6', m, 'FileParents', lambda: ((m.FileParents | frozenset((((~file), ((~parent), (~name))),)))))

    _act7 = Action('act7', m, 'FileXattrs', lambda: (override_relation(m.FileXattrs, frozenset((((~file), frozenset[tuple[Machine.StringsItem, Machine.DataItem]]()),)))))

    _act8 = Action('act8', m, 'FileLink', lambda: (override_relation(m.FileLink, frozenset((((~file), ((~target_parent), (~target_name))),)))))

    _act9 = Action('act9', m, 'GroupObjACL', lambda: ((m.GroupObjACL | frozenset((((~file), (m.DEF_SYMLINK_PERMS & m.GROUP_PERMISSIONS)),)))))


    return Event("symlink", _grd1, _grd2, _grd3, _grd4, _grd5, _grd6, _grd7, _grd8, _grd9, _grd10, _grd11, _act1, _act2, _act3, _act4, _act5, _act6, _act7, _act8, _act9)
