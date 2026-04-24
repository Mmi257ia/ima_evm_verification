from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import function_value, relation_domain, relation_image


def link(m: Machine,
         _proc: Machine.ProcsItem | None,
         _oldParent: Machine.FilesItem | None,
         _newParent: Machine.FilesItem | None,
         _file: Machine.FilesItem | None,
         _oldName: Machine.StringsItem | None,
         _newName: Machine.StringsItem | None) -> Event:

    proc = Parameter(_proc)
    oldParent = Parameter(_oldParent)
    newParent = Parameter(_newParent)
    file = Parameter(_file)
    oldName = Parameter(_oldName)
    newName = Parameter(_newName)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~proc) in m.Procs)))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    (~oldParent) in m.Folders)))

    _grd3 = Guard('grd3', lambda _: (_(3, 
    (~newParent) in m.Folders)))

    _grd4 = Guard('grd4', lambda _: (_(4, 
    (~file) in (m.Files - m.Folders))))

    _grd5 = Guard('grd5', lambda _: (_(5, 
    ((~file), ((~oldParent), (~oldName))) in m.FileParents)))

    _grd6 = Guard('grd6', lambda _: (_(6, 
    (~newName) in m.STRINGS)))

    _grd7 = Guard('grd7', lambda _: (_(7, 
    not any (True for f in m.Files if not (
        (f, ((~newParent), (~newName))) not in m.FileParents
    )))))

    _grd8 = Guard('grd8', lambda _: (_(8, 
    not any (True for f in (function_value(m.PathToRoot, (~oldParent)) | frozenset(((~oldParent),))) if function_value(m.ProcUser, (~proc)) != m.ROOT_USER if not (
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

    _grd9 = Guard('grd9', lambda _: (_(9, 
    not any (True for f in function_value(m.PathToRoot, (~newParent)) if function_value(m.ProcUser, (~proc)) != m.ROOT_USER if not (
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
    function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, (~newParent)))) and (_(12, 
    frozenset((m.UWRITE, m.UEXECUTE)) <= function_value(m.DACPermissions, (~newParent))))) or (((((_(13, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~newParent)))) and ((_(14, 
    (~newParent) not in relation_domain(m.MaskACL))) or (_(15, len(function_value(m.MaskACL, (~newParent))) == 0)))) and (_(16, 
    function_value(m.FileGroup, (~newParent)) != function_value(m.ProcGroup, (~proc))))) and (_(17, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~newParent))) not in m.UserGroups))) and (_(18, 
    frozenset((m.OWRITE, m.OEXECUTE)) <= function_value(m.DACPermissions, (~newParent)))))) or ((((_(19, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~newParent)))) and (_(20, 
    ((~newParent), function_value(m.ProcUser, (~proc))) in relation_domain(m.UserACL)))) and (_(21, frozenset((m.UWRITE, m.UEXECUTE)) <= function_value(m.UserACL, ((~newParent), function_value(m.ProcUser, (~proc))))))) and (_(22, 
    frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.MaskACL, (~newParent)))))) or (((((_(23, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~newParent)))) and (_(24, 
    ((~newParent), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(25, 
    any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if 
    (((~newParent), g) in relation_domain(m.GroupACL) and frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.GroupACL, ((~newParent), g)) or g == function_value(m.FileGroup, (~newParent)) and (~newParent) in relation_domain(m.GroupObjACL) and frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.GroupObjACL, (~newParent))))))) and (_(26, 
    (~newParent) in relation_domain(m.MaskACL)))) and (_(27, frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.MaskACL, (~newParent)))))) or ((((_(28, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~newParent)))) and (_(29, 
    (~newParent) not in relation_domain(m.MaskACL)))) and ((_(30, 
    function_value(m.FileGroup, (~newParent)) == function_value(m.ProcGroup, (~proc)))) or (_(31, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~newParent))) in m.UserGroups)))) and (_(32, 
    frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.DACPermissions, (~newParent)))))) or ((((((((_(33, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~newParent)))) and (_(34, 
    (~newParent) in relation_domain(m.MaskACL)))) and (_(35, len(function_value(m.MaskACL, (~newParent))) != 0))) and (_(36, 
    ((~newParent), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(37, 
    not any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if not (
        ((~newParent), g) not in relation_domain(m.GroupACL)
    ))))) and (_(38, 
    function_value(m.FileGroup, (~newParent)) != function_value(m.ProcGroup, (~proc))))) and (_(39, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~newParent))) not in m.UserGroups))) and (_(40, 
    frozenset((m.OWRITE, m.OEXECUTE)) <= function_value(m.DACPermissions, (~newParent))))))))

    _grd11 = Guard('grd11', lambda _: (not (_(41, 
    function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) or (((((((_(42, 
    function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, (~file)))) and (_(43, 
    frozenset((m.UREAD, m.UWRITE)) <= function_value(m.DACPermissions, (~file))))) or (((((_(44, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and ((_(45, 
    (~file) not in relation_domain(m.MaskACL))) or (_(46, len(function_value(m.MaskACL, (~file))) == 0)))) and (_(47, 
    function_value(m.FileGroup, (~file)) != function_value(m.ProcGroup, (~proc))))) and (_(48, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) not in m.UserGroups))) and (_(49, 
    frozenset((m.OREAD, m.OWRITE)) <= function_value(m.DACPermissions, (~file)))))) or ((((_(50, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(51, 
    ((~file), function_value(m.ProcUser, (~proc))) in relation_domain(m.UserACL)))) and (_(52, frozenset((m.UREAD, m.UWRITE)) <= function_value(m.UserACL, ((~file), function_value(m.ProcUser, (~proc))))))) and (_(53, 
    frozenset((m.GREAD, m.GWRITE)) <= function_value(m.MaskACL, (~file)))))) or (((((_(54, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(55, 
    ((~file), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(56, 
    any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if 
    (((~file), g) in relation_domain(m.GroupACL) and frozenset((m.GREAD, m.GWRITE)) <= function_value(m.GroupACL, ((~file), g)) or g == function_value(m.FileGroup, (~file)) and (~file) in relation_domain(m.GroupObjACL) and frozenset((m.GREAD, m.GWRITE)) <= function_value(m.GroupObjACL, (~file))))))) and (_(57, 
    (~file) in relation_domain(m.MaskACL)))) and (_(58, frozenset((m.GREAD, m.GWRITE)) <= function_value(m.MaskACL, (~file)))))) or ((((_(59, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(60, 
    (~file) not in relation_domain(m.MaskACL)))) and ((_(61, 
    function_value(m.FileGroup, (~file)) == function_value(m.ProcGroup, (~proc)))) or (_(62, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) in m.UserGroups)))) and (_(63, 
    frozenset((m.GREAD, m.GWRITE)) <= function_value(m.DACPermissions, (~file)))))) or ((((((((_(64, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(65, 
    (~file) in relation_domain(m.MaskACL)))) and (_(66, len(function_value(m.MaskACL, (~file))) != 0))) and (_(67, 
    ((~file), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(68, 
    not any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if not (
        ((~file), g) not in relation_domain(m.GroupACL)
    ))))) and (_(69, 
    function_value(m.FileGroup, (~file)) != function_value(m.ProcGroup, (~proc))))) and (_(70, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) not in m.UserGroups))) and (_(71, 
    frozenset((m.OREAD, m.OWRITE)) <= function_value(m.DACPermissions, (~file))))))))


    _act1 = Action('act1', m, 'FileParents', lambda: ((m.FileParents | frozenset((((~file), ((~newParent), (~newName))),)))))


    return Event("link", _grd1, _grd2, _grd3, _grd4, _grd5, _grd6, _grd7, _grd8, _grd9, _grd10, _grd11, _act1)
