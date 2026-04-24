from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard
from anis.model.expressions import NAT, relation_domain, function_value, relation_image


def getxattr(m: Machine,
             _proc: Machine.ProcsItem | None,
             _parent: Machine.FilesItem | None,
             _file: Machine.FilesItem | None,
             _fileName: Machine.StringsItem | None,
             _name: Machine.StringsItem | None,
             _value: Machine.DataItem | None,
             _size: int | None) -> Event:

    proc = Parameter(_proc)
    parent = Parameter(_parent)
    file = Parameter(_file)
    fileName = Parameter(_fileName)
    name = Parameter(_name)
    value = Parameter(_value)
    size = Parameter(_size)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~proc) in m.Procs)))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    ((~file), ((~parent), (~fileName))) in m.FileParents)))

    _grd3 = Guard('grd3', lambda _: (_(3, 
    (~size) in NAT)))

    _grd4 = Guard('grd4', lambda _: ((_(4, 
    (~name) in relation_domain(function_value(m.FileXattrs, (~file))))) and (not (_(5, (~size) > 0)) or (_(6, (~value) == function_value(function_value(m.FileXattrs, (~file)), (~name)))))))

    _grd5 = Guard('grd5', lambda _: (_(7, 
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

    _grd6 = Guard('grd6', lambda _: (not (_(8, 
    function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) or (((((((_(9, 
    function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, (~file)))) and (_(10, 
    m.UREAD in function_value(m.DACPermissions, (~file))))) or (((((_(11, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and ((_(12, 
    (~file) not in relation_domain(m.MaskACL))) or (_(13, len(function_value(m.MaskACL, (~file))) == 0)))) and (_(14, 
    function_value(m.FileGroup, (~file)) != function_value(m.ProcGroup, (~proc))))) and (_(15, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) not in m.UserGroups))) and (_(16, 
    m.OREAD in function_value(m.DACPermissions, (~file)))))) or ((((_(17, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(18, 
    ((~file), function_value(m.ProcUser, (~proc))) in relation_domain(m.UserACL)))) and (_(19, m.UREAD in function_value(m.UserACL, ((~file), function_value(m.ProcUser, (~proc))))))) and (_(20, 
    m.GREAD in function_value(m.MaskACL, (~file)))))) or (((((_(21, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(22, 
    ((~file), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(23, 
    any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if 
    (((~file), g) in relation_domain(m.GroupACL) and m.GREAD in function_value(m.GroupACL, ((~file), g)) or g == function_value(m.FileGroup, (~file)) and (~file) in relation_domain(m.GroupObjACL) and m.GREAD in function_value(m.GroupObjACL, (~file))))))) and (_(24, 
    (~file) in relation_domain(m.MaskACL)))) and (_(25, m.GREAD in function_value(m.MaskACL, (~file)))))) or ((((_(26, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(27, 
    (~file) not in relation_domain(m.MaskACL)))) and ((_(28, 
    function_value(m.FileGroup, (~file)) == function_value(m.ProcGroup, (~proc)))) or (_(29, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) in m.UserGroups)))) and (_(30, 
    m.GREAD in function_value(m.DACPermissions, (~file)))))) or ((((((((_(31, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(32, 
    (~file) in relation_domain(m.MaskACL)))) and (_(33, len(function_value(m.MaskACL, (~file))) != 0))) and (_(34, 
    ((~file), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(35, 
    not any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if not (
        ((~file), g) not in relation_domain(m.GroupACL)
    ))))) and (_(36, 
    function_value(m.FileGroup, (~file)) != function_value(m.ProcGroup, (~proc))))) and (_(37, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) not in m.UserGroups))) and (_(38, 
    m.OREAD in function_value(m.DACPermissions, (~file))))))))


    return Event("getxattr", _grd1, _grd2, _grd3, _grd4, _grd5, _grd6)
