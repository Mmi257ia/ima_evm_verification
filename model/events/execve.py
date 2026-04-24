from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import powerset, function_value, relation_domain, relation_image, override_relation, subtract_domain, subtract_range


def execve(m: Machine,
           _proc: Machine.ProcsItem | None,
           _parent: Machine.FilesItem | None,
           _exeFile: Machine.FilesItem | None,
           _name: Machine.StringsItem | None,
           _argv: frozenset[Machine.StringsItem] | None,
           _envp: frozenset[Machine.StringsItem] | None,
           _fds: frozenset[Machine.FileDescriptorsExtendedItem] | None) -> Event:

    proc = Parameter(_proc)
    parent = Parameter(_parent)
    exeFile = Parameter(_exeFile)
    name = Parameter(_name)
    argv = Parameter(_argv)
    envp = Parameter(_envp)
    fds = Parameter(_fds)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~proc) in m.Procs)))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    (~parent) in m.Folders)))

    _grd3 = Guard('grd3', lambda _: (_(3, 
    (~exeFile) in (m.Files - m.Folders))))

    _grd4 = Guard('grd4', lambda _: (_(4, 
    ((~exeFile), ((~parent), (~name))) in m.FileParents)))

    _grd5 = Guard('grd5', lambda _: (_(5, 
    (~argv) in powerset(m.STRINGS))))

    _grd6 = Guard('grd6', lambda _: (_(6, 
    (~envp) in powerset(m.STRINGS))))

    _grd7 = Guard('grd7', lambda _: (_(7, 
    (~fds) <= m.FDs)))

    _grd8 = Guard('grd8', lambda _: (_(8, 
    not any (True for fd in (~fds) if not (
        ((~proc), fd) in m.ProcFDs and m.O_CLOEXEC in function_value(m.FDFlags, fd)
    )))))

    _grd9 = Guard('grd9', lambda _: (_(9, 
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

    _grd10 = Guard('grd10', lambda _: (not (_(10, 
    function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) or (((((((_(11, 
    function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, (~exeFile)))) and (_(12, 
    m.UEXECUTE in function_value(m.DACPermissions, (~exeFile))))) or (((((_(13, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~exeFile)))) and ((_(14, 
    (~exeFile) not in relation_domain(m.MaskACL))) or (_(15, len(function_value(m.MaskACL, (~exeFile))) == 0)))) and (_(16, 
    function_value(m.FileGroup, (~exeFile)) != function_value(m.ProcGroup, (~proc))))) and (_(17, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~exeFile))) not in m.UserGroups))) and (_(18, 
    m.OEXECUTE in function_value(m.DACPermissions, (~exeFile)))))) or ((((_(19, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~exeFile)))) and (_(20, 
    ((~exeFile), function_value(m.ProcUser, (~proc))) in relation_domain(m.UserACL)))) and (_(21, m.UEXECUTE in function_value(m.UserACL, ((~exeFile), function_value(m.ProcUser, (~proc))))))) and (_(22, 
    m.GEXECUTE in function_value(m.MaskACL, (~exeFile)))))) or (((((_(23, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~exeFile)))) and (_(24, 
    ((~exeFile), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(25, 
    any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if 
    (((~exeFile), g) in relation_domain(m.GroupACL) and m.GEXECUTE in function_value(m.GroupACL, ((~exeFile), g)) or g == function_value(m.FileGroup, (~exeFile)) and (~exeFile) in relation_domain(m.GroupObjACL) and m.GEXECUTE in function_value(m.GroupObjACL, (~exeFile))))))) and (_(26, 
    (~exeFile) in relation_domain(m.MaskACL)))) and (_(27, m.GEXECUTE in function_value(m.MaskACL, (~exeFile)))))) or ((((_(28, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~exeFile)))) and (_(29, 
    (~exeFile) not in relation_domain(m.MaskACL)))) and ((_(30, 
    function_value(m.FileGroup, (~exeFile)) == function_value(m.ProcGroup, (~proc)))) or (_(31, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~exeFile))) in m.UserGroups)))) and (_(32, 
    m.GEXECUTE in function_value(m.DACPermissions, (~exeFile)))))) or ((((((((_(33, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~exeFile)))) and (_(34, 
    (~exeFile) in relation_domain(m.MaskACL)))) and (_(35, len(function_value(m.MaskACL, (~exeFile))) != 0))) and (_(36, 
    ((~exeFile), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(37, 
    not any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if not (
        ((~exeFile), g) not in relation_domain(m.GroupACL)
    ))))) and (_(38, 
    function_value(m.FileGroup, (~exeFile)) != function_value(m.ProcGroup, (~proc))))) and (_(39, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~exeFile))) not in m.UserGroups))) and (_(40, 
    m.OEXECUTE in function_value(m.DACPermissions, (~exeFile))))))))

    _grd11 = Guard('grd11', lambda _: (_(41, 
    len((frozenset((m.UEXECUTE, m.GEXECUTE, m.OEXECUTE)) & function_value(m.DACPermissions, (~exeFile)))) != 0)))


    _act1 = Action('act1', m, 'ProcEXE', lambda: (override_relation(m.ProcEXE, frozenset((((~proc), (~exeFile)),)))))

    _act2 = Action('act2', m, 'ProcArgv', lambda: (override_relation(m.ProcArgv, frozenset((((~proc), (~argv)),)))))

    _act3 = Action('act3', m, 'ProcEnvp', lambda: (override_relation(m.ProcEnvp, frozenset((((~proc), (~envp)),)))))

    _act4 = Action('act4', m, 'ProcUser', lambda: ((subtract_domain(m.ProcUser, frozenset(((~proc),))) | frozenset((((~proc), function_value(m.FileUser, (~exeFile))),))) if (m.SET_UID in function_value(m.DACPermissions, (~exeFile))) else 
        m.ProcUser))

    _act5 = Action('act5', m, 'ProcGroup', lambda: ((subtract_domain(m.ProcGroup, frozenset(((~proc),))) | frozenset((((~proc), function_value(m.FileGroup, (~exeFile))),))) if (m.SET_GID in function_value(m.DACPermissions, (~exeFile))) else 
            m.ProcGroup))

    _act6 = Action('act6', m, 'FDs', lambda: ((m.FDs - (~fds))))

    _act7 = Action('act7', m, 'ProcFDs', lambda: (subtract_range(m.ProcFDs, (~fds))))

    _act8 = Action('act8', m, 'FDFlags', lambda: (subtract_domain(m.FDFlags, (~fds))))

    _act9 = Action('act9', m, 'FDFile', lambda: (subtract_domain(m.FDFile, (~fds))))

    _act10 = Action('act10', m, 'FDNumber', lambda: (subtract_domain(m.FDNumber, (~fds))))


    return Event("execve", _grd1, _grd2, _grd3, _grd4, _grd5, _grd6, _grd7, _grd8, _grd9, _grd10, _grd11, _act1, _act2, _act3, _act4, _act5, _act6, _act7, _act8, _act9, _act10)
