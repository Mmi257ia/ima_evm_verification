from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import function_value, relation_domain, relation_image, override_relation


def fchdir(m: Machine,
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

    _grd4 = Guard('grd4', lambda _: (not (_(4, 
    function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) or (((((((_(5, 
    function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, function_value(m.FDFile, (~fd))))) and (_(6, 
    m.UEXECUTE in function_value(m.DACPermissions, function_value(m.FDFile, (~fd)))))) or (((((_(7, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, function_value(m.FDFile, (~fd))))) and ((_(8, 
    function_value(m.FDFile, (~fd)) not in relation_domain(m.MaskACL))) or (_(9, len(function_value(m.MaskACL, function_value(m.FDFile, (~fd)))) == 0)))) and (_(10, 
    function_value(m.FileGroup, function_value(m.FDFile, (~fd))) != function_value(m.ProcGroup, (~proc))))) and (_(11, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, function_value(m.FDFile, (~fd)))) not in m.UserGroups))) and (_(12, 
    m.OEXECUTE in function_value(m.DACPermissions, function_value(m.FDFile, (~fd))))))) or ((((_(13, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, function_value(m.FDFile, (~fd))))) and (_(14, 
    (function_value(m.FDFile, (~fd)), function_value(m.ProcUser, (~proc))) in relation_domain(m.UserACL)))) and (_(15, m.UEXECUTE in function_value(m.UserACL, (function_value(m.FDFile, (~fd)), function_value(m.ProcUser, (~proc))))))) and (_(16, 
    m.GEXECUTE in function_value(m.MaskACL, function_value(m.FDFile, (~fd))))))) or (((((_(17, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, function_value(m.FDFile, (~fd))))) and (_(18, 
    (function_value(m.FDFile, (~fd)), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(19, 
    any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if 
    ((function_value(m.FDFile, (~fd)), g) in relation_domain(m.GroupACL) and m.GEXECUTE in function_value(m.GroupACL, (function_value(m.FDFile, (~fd)), g)) or g == function_value(m.FileGroup, function_value(m.FDFile, (~fd))) and function_value(m.FDFile, (~fd)) in relation_domain(m.GroupObjACL) and m.GEXECUTE in function_value(m.GroupObjACL, function_value(m.FDFile, (~fd)))))))) and (_(20, 
    function_value(m.FDFile, (~fd)) in relation_domain(m.MaskACL)))) and (_(21, m.GEXECUTE in function_value(m.MaskACL, function_value(m.FDFile, (~fd))))))) or ((((_(22, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, function_value(m.FDFile, (~fd))))) and (_(23, 
    function_value(m.FDFile, (~fd)) not in relation_domain(m.MaskACL)))) and ((_(24, 
    function_value(m.FileGroup, function_value(m.FDFile, (~fd))) == function_value(m.ProcGroup, (~proc)))) or (_(25, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, function_value(m.FDFile, (~fd)))) in m.UserGroups)))) and (_(26, 
    m.GEXECUTE in function_value(m.DACPermissions, function_value(m.FDFile, (~fd))))))) or ((((((((_(27, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, function_value(m.FDFile, (~fd))))) and (_(28, 
    function_value(m.FDFile, (~fd)) in relation_domain(m.MaskACL)))) and (_(29, len(function_value(m.MaskACL, function_value(m.FDFile, (~fd)))) != 0))) and (_(30, 
    (function_value(m.FDFile, (~fd)), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(31, 
    not any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if not (
        (function_value(m.FDFile, (~fd)), g) not in relation_domain(m.GroupACL)
    ))))) and (_(32, 
    function_value(m.FileGroup, function_value(m.FDFile, (~fd))) != function_value(m.ProcGroup, (~proc))))) and (_(33, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, function_value(m.FDFile, (~fd)))) not in m.UserGroups))) and (_(34, 
    m.OEXECUTE in function_value(m.DACPermissions, function_value(m.FDFile, (~fd)))))))))


    _act1 = Action('act1', m, 'ProcCwd', lambda: (override_relation(m.ProcCwd, frozenset((((~proc), function_value(m.FDFile, (~fd))),)))))


    return Event("fchdir", _grd1, _grd2, _grd3, _grd4, _act1)
