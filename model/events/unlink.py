from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import relation_image, function_value, relation_domain, subtract_domain, cartesian_product


def unlink(m: Machine,
           _proc: Machine.ProcsItem | None,
           _parent: Machine.FilesItem | None,
           _file: Machine.FilesItem | None,
           _name: Machine.StringsItem | None,
           _files: frozenset[Machine.FilesItem] | None) -> Event:

    proc = Parameter(_proc)
    parent = Parameter(_parent)
    file = Parameter(_file)
    name = Parameter(_name)
    files = Parameter(_files)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~proc) in m.Procs)))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    (~parent) in m.Folders)))

    _grd3 = Guard('grd3', lambda _: (_(3, 
    (~file) in (m.Files - m.Folders))))

    _grd4 = Guard('grd4', lambda _: (_(4, 
    ((~file), ((~parent), (~name))) in m.FileParents)))

    _grd5 = Guard('grd5', lambda _: (_(5, 
    (~files) <= m.Files)))

    _grd6 = Guard('grd6', lambda _: (_(6, 
    (any (True for (p, n) in relation_image(m.FileParents, frozenset(((~file),))) if (p, n) != ((~parent), (~name)))) == (len((~files)) == 0))))

    _grd7 = Guard('grd7', lambda _: (_(7, 
    (not (any (True for (p, n) in relation_image(m.FileParents, frozenset(((~file),))) if (p, n) != ((~parent), (~name))))) == ((~files) == frozenset(((~file),))))))

    _grd8 = Guard('grd8', lambda _: (_(8, 
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

    _grd9 = Guard('grd9', lambda _: (not (_(9, 
    function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) or (((((((_(10, 
    function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, (~parent)))) and (_(11, 
    frozenset((m.UWRITE, m.UEXECUTE)) <= function_value(m.DACPermissions, (~parent))))) or (((((_(12, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and ((_(13, 
    (~parent) not in relation_domain(m.MaskACL))) or (_(14, len(function_value(m.MaskACL, (~parent))) == 0)))) and (_(15, 
    function_value(m.FileGroup, (~parent)) != function_value(m.ProcGroup, (~proc))))) and (_(16, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~parent))) not in m.UserGroups))) and (_(17, 
    frozenset((m.OWRITE, m.OEXECUTE)) <= function_value(m.DACPermissions, (~parent)))))) or ((((_(18, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and (_(19, 
    ((~parent), function_value(m.ProcUser, (~proc))) in relation_domain(m.UserACL)))) and (_(20, frozenset((m.UWRITE, m.UEXECUTE)) <= function_value(m.UserACL, ((~parent), function_value(m.ProcUser, (~proc))))))) and (_(21, 
    frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.MaskACL, (~parent)))))) or (((((_(22, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and (_(23, 
    ((~parent), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(24, 
    any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if 
    (((~parent), g) in relation_domain(m.GroupACL) and frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.GroupACL, ((~parent), g)) or g == function_value(m.FileGroup, (~parent)) and (~parent) in relation_domain(m.GroupObjACL) and frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.GroupObjACL, (~parent))))))) and (_(25, 
    (~parent) in relation_domain(m.MaskACL)))) and (_(26, frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.MaskACL, (~parent)))))) or ((((_(27, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and (_(28, 
    (~parent) not in relation_domain(m.MaskACL)))) and ((_(29, 
    function_value(m.FileGroup, (~parent)) == function_value(m.ProcGroup, (~proc)))) or (_(30, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~parent))) in m.UserGroups)))) and (_(31, 
    frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.DACPermissions, (~parent)))))) or ((((((((_(32, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and (_(33, 
    (~parent) in relation_domain(m.MaskACL)))) and (_(34, len(function_value(m.MaskACL, (~parent))) != 0))) and (_(35, 
    ((~parent), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(36, 
    not any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if not (
        ((~parent), g) not in relation_domain(m.GroupACL)
    ))))) and (_(37, 
    function_value(m.FileGroup, (~parent)) != function_value(m.ProcGroup, (~proc))))) and (_(38, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~parent))) not in m.UserGroups))) and (_(39, 
    frozenset((m.OWRITE, m.OEXECUTE)) <= function_value(m.DACPermissions, (~parent))))))))

    _grd10 = Guard('grd10', lambda _: (not (_(40, 
    m.STICKY_BIT in function_value(m.DACPermissions, (~parent)))) or (_(41, function_value(m.ProcUser, (~proc)) in frozenset((m.ROOT_USER, function_value(m.FileUser, (~file)), function_value(m.FileUser, (~parent))))))))


    _act1 = Action('act1', m, 'Files', lambda: ((m.Files - (~files))))

    _act2 = Action('act2', m, 'FileParents', lambda: ((m.FileParents - frozenset((((~file), ((~parent), (~name))),)))))

    _act3 = Action('act3', m, 'DACPermissions', lambda: (subtract_domain(m.DACPermissions, (~files))))

    _act4 = Action('act4', m, 'FileUser', lambda: (subtract_domain(m.FileUser, (~files))))

    _act5 = Action('act5', m, 'FileGroup', lambda: (subtract_domain(m.FileGroup, (~files))))

    _act6 = Action('act6', m, 'FileXattrs', lambda: (subtract_domain(m.FileXattrs, (~files))))

    _act7 = Action('act7', m, 'UserACL', lambda: (subtract_domain(m.UserACL, cartesian_product((~files), m.Users))))

    _act8 = Action('act8', m, 'GroupACL', lambda: (subtract_domain(m.GroupACL, cartesian_product((~files), m.Groups))))

    _act9 = Action('act9', m, 'MaskACL', lambda: (subtract_domain(m.MaskACL, (~files))))

    _act10 = Action('act10', m, 'GroupObjACL', lambda: (subtract_domain(m.GroupObjACL, (~files))))

    _act11 = Action('act11', m, 'SymLinks', lambda: ((m.SymLinks - (~files))))

    _act12 = Action('act12', m, 'FileLink', lambda: (subtract_domain(m.FileLink, (~files))))


    return Event("unlink", _grd1, _grd2, _grd3, _grd4, _grd5, _grd6, _grd7, _grd8, _grd9, _grd10, _act1, _act2, _act3, _act4, _act5, _act6, _act7, _act8, _act9, _act10, _act11, _act12)
