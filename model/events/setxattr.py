from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import relation_domain, function_value, NAT, relation_image, subtract_domain, override_relation


def setxattr(m: Machine,
             _proc: Machine.ProcsItem | None,
             _parent: Machine.FilesItem | None,
             _file: Machine.FilesItem | None,
             _fileName: Machine.StringsItem | None,
             _name: Machine.StringsItem | None,
             _value: Machine.DataItem | None,
             _size: int | None,
             _flags: frozenset[Machine.XattrFlagsItem] | None) -> Event:

    proc = Parameter(_proc)
    parent = Parameter(_parent)
    file = Parameter(_file)
    fileName = Parameter(_fileName)
    name = Parameter(_name)
    value = Parameter(_value)
    size = Parameter(_size)
    flags = Parameter(_flags)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~proc) in m.Procs)))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    ((~file), ((~parent), (~fileName))) in m.FileParents)))

    _grd3 = Guard('grd3', lambda _: (_(3, 
    (~flags) <= m.XATTR_FLAGS)))

    _grd4 = Guard('grd4', lambda _: (not (_(4, 
    m.XATTR_CREATE in (~flags))) or (_(5, (~name) not in relation_domain(function_value(m.FileXattrs, (~file)))))))

    _grd5 = Guard('grd5', lambda _: (not (_(6, 
    m.XATTR_REPLACE in (~flags))) or (_(7, (~name) in relation_domain(function_value(m.FileXattrs, (~file)))))))

    _grd6 = Guard('grd6', lambda _: (_(8, 
    (~value) in m.DATA)))

    _grd7 = Guard('grd7', lambda _: (_(9, 
    (~size) in NAT)))

    _grd8 = Guard('grd8', lambda _: (_(10, 
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

    _grd9 = Guard('grd9', lambda _: (not (_(11, 
    function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) or (((((((_(12, 
    function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, (~file)))) and (_(13, 
    m.UWRITE in function_value(m.DACPermissions, (~file))))) or (((((_(14, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and ((_(15, 
    (~file) not in relation_domain(m.MaskACL))) or (_(16, len(function_value(m.MaskACL, (~file))) == 0)))) and (_(17, 
    function_value(m.FileGroup, (~file)) != function_value(m.ProcGroup, (~proc))))) and (_(18, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) not in m.UserGroups))) and (_(19, 
    m.OWRITE in function_value(m.DACPermissions, (~file)))))) or ((((_(20, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(21, 
    ((~file), function_value(m.ProcUser, (~proc))) in relation_domain(m.UserACL)))) and (_(22, m.UWRITE in function_value(m.UserACL, ((~file), function_value(m.ProcUser, (~proc))))))) and (_(23, 
    m.GWRITE in function_value(m.MaskACL, (~file)))))) or (((((_(24, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(25, 
    ((~file), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(26, 
    any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if 
    (((~file), g) in relation_domain(m.GroupACL) and m.GWRITE in function_value(m.GroupACL, ((~file), g)) or g == function_value(m.FileGroup, (~file)) and (~file) in relation_domain(m.GroupObjACL) and m.GWRITE in function_value(m.GroupObjACL, (~file))))))) and (_(27, 
    (~file) in relation_domain(m.MaskACL)))) and (_(28, m.GWRITE in function_value(m.MaskACL, (~file)))))) or ((((_(29, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(30, 
    (~file) not in relation_domain(m.MaskACL)))) and ((_(31, 
    function_value(m.FileGroup, (~file)) == function_value(m.ProcGroup, (~proc)))) or (_(32, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) in m.UserGroups)))) and (_(33, 
    m.GWRITE in function_value(m.DACPermissions, (~file)))))) or ((((((((_(34, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(35, 
    (~file) in relation_domain(m.MaskACL)))) and (_(36, len(function_value(m.MaskACL, (~file))) != 0))) and (_(37, 
    ((~file), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(38, 
    not any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if not (
        ((~file), g) not in relation_domain(m.GroupACL)
    ))))) and (_(39, 
    function_value(m.FileGroup, (~file)) != function_value(m.ProcGroup, (~proc))))) and (_(40, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) not in m.UserGroups))) and (_(41, 
    m.OWRITE in function_value(m.DACPermissions, (~file))))))))


    _act1 = Action('act1', m, 'FileXattrs', lambda: (override_relation(m.FileXattrs, frozenset((((~file), (subtract_domain(function_value(m.FileXattrs, (~file)), frozenset(((~name),))) | frozenset((((~name), (~value)),)))),)))))


    return Event("setxattr", _grd1, _grd2, _grd3, _grd4, _grd5, _grd6, _grd7, _grd8, _grd9, _act1)
