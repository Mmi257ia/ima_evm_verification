from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import relation_range, relation_domain, NAT, function_value, relation_image, override_relation


def openat_create(m: Machine,
                  _proc: Machine.ProcsItem | None,
                  _dirfd: Machine.FileDescriptorsExtendedItem | None,
                  _parent: Machine.FilesItem | None,
                  _file: Machine.FilesItem | None,
                  _name: Machine.StringsItem | None,
                  _flags: frozenset[int] | None,
                  _mode: frozenset[Machine.PermissionsItem] | None,
                  _fd: Machine.FileDescriptorsExtendedItem | None,
                  _fdNumber: int | None,
                  _cwd: Machine.FilesItem | None,
                  _group: Machine.GroupsItem | None,
                  _perms: frozenset[Machine.PermissionsItem] | None) -> Event:

    proc = Parameter(_proc)
    dirfd = Parameter(_dirfd)
    parent = Parameter(_parent)
    file = Parameter(_file)
    name = Parameter(_name)
    flags = Parameter(_flags)
    mode = Parameter(_mode)
    fd = Parameter(_fd)
    fdNumber = Parameter(_fdNumber)
    cwd = Parameter(_cwd)
    group = Parameter(_group)
    perms = Parameter(_perms)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~proc) in m.Procs)))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    (~dirfd) in m.FILE_DESCRIPTORS_EXTENDED)))

    _grd3 = Guard('grd3', lambda _: (_(3, 
    (~parent) in m.Folders)))

    _grd4 = Guard('grd4', lambda _: (_(4, 
    (~file) in (((m.FILES - m.Files) - relation_range(m.FDFile)) - relation_range(m.ProcCwd)))))

    _grd5 = Guard('grd5', lambda _: (_(5, 
    (~name) in m.STRINGS)))

    _grd6 = Guard('grd6', lambda _: (_(6, 
    not any (True for f in relation_domain(m.FileParents) if not (
        (f, ((~parent), (~name))) not in m.FileParents
    )))))

    _grd7 = Guard('grd7', lambda _: (_(7, 
    (~flags) <= m.OPEN_FLAGS)))

    _grd8 = Guard('grd8', lambda _: (_(8, 
    (~mode) <= m.PERMISSIONS)))

    _grd9 = Guard('grd9', lambda _: (_(9, 
    (~fd) in (m.FILE_DESCRIPTORS - m.FDs))))

    _grd10 = Guard('grd10', lambda _: (_(10, 
    (~fdNumber) in NAT)))

    _grd11 = Guard('grd11', lambda _: (_(11, 
    (~cwd) in m.Folders)))

    _grd12 = Guard('grd12', lambda _: (not (_(12, 
    (~dirfd) == m.AT_FDCWD)) or (_(13, (~cwd) == function_value(m.ProcCwd, (~proc))))))

    _grd13 = Guard('grd13', lambda _: (not (_(14, 
    (~dirfd) != m.AT_FDCWD)) or ((_(15, ((~proc), (~dirfd)) in m.ProcFDs)) and (_(16, (~cwd) == function_value(m.FDFile, (~dirfd)))))))

    _grd14 = Guard('grd14', lambda _: (_(17, 
    (~cwd) in m.Folders)))

    _grd15 = Guard('grd15', lambda _: (_(18, 
    (~cwd) in (function_value(m.PathToRoot, (~parent)) | frozenset(((~parent),))))))

    _grd16 = Guard('grd16', lambda _: (_(19, 
    not any (True for (key, pfd) in m.ProcFDs if key == (~proc) if not (
        function_value(m.FDNumber, pfd) != (~fdNumber)
    )))))

    _grd17 = Guard('grd17', lambda _: ((_(20, 
    m.O_CREAT in (~flags))) or (_(21, m.O_TMPFILE in (~flags)))))

    _grd18 = Guard('grd18', lambda _: (((_(22, 
    m.O_RDONLY in (~flags))) or (_(23, m.O_WRONLY in (~flags)))) or (_(24, m.O_RDWR in (~flags)))))

    _grd19 = Guard('grd19', lambda _: (((not ((_(25, 
    m.O_RDONLY in (~flags))) and (_(26, m.O_WRONLY in (~flags))))) and (not ((_(27, 
    m.O_RDONLY in (~flags))) and (_(28, m.O_RDWR in (~flags)))))) and (not ((_(29, 
    m.O_WRONLY in (~flags))) and (_(30, m.O_RDWR in (~flags)))))))

    _grd20 = Guard('grd20', lambda _: (not (_(31, 
    m.O_TMPFILE in (~flags))) or ((_(32, m.O_WRONLY in (~flags))) or (_(33, m.O_RDWR in (~flags))))))

    _grd21 = Guard('grd21', lambda _: (_(34, 
    m.O_PATH not in (~flags))))

    _grd22 = Guard('grd22', lambda _: (_(35, 
    len(m.Files) < m.MAX_FILES)))

    _grd23 = Guard('grd23', lambda _: (_(36, 
    len(relation_image(m.ProcFDs, frozenset(((~proc),)))) < m.PROC_FILE_LIMIT)))

    _grd24 = Guard('grd24', lambda _: (_(37, 
    len(relation_range(m.ProcFDs)) < m.FILE_LIMIT)))

    _grd25 = Guard('grd25', lambda _: (_(38, 
    not any (True for f in function_value(m.PathToRoot, (~parent)) if function_value(m.ProcUser, (~proc)) != m.ROOT_USER if f not in function_value(m.PathToRoot, (~cwd)) if not (
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

    _grd26 = Guard('grd26', lambda _: (not (_(39, 
    function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) or (((((((_(40, 
    function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, (~parent)))) and (_(41, 
    frozenset((m.UWRITE, m.UEXECUTE)) <= function_value(m.DACPermissions, (~parent))))) or (((((_(42, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and ((_(43, 
    (~parent) not in relation_domain(m.MaskACL))) or (_(44, len(function_value(m.MaskACL, (~parent))) == 0)))) and (_(45, 
    function_value(m.FileGroup, (~parent)) != function_value(m.ProcGroup, (~proc))))) and (_(46, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~parent))) not in m.UserGroups))) and (_(47, 
    frozenset((m.OWRITE, m.OEXECUTE)) <= function_value(m.DACPermissions, (~parent)))))) or ((((_(48, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and (_(49, 
    ((~parent), function_value(m.ProcUser, (~proc))) in relation_domain(m.UserACL)))) and (_(50, frozenset((m.UWRITE, m.UEXECUTE)) <= function_value(m.UserACL, ((~parent), function_value(m.ProcUser, (~proc))))))) and (_(51, 
    frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.MaskACL, (~parent)))))) or (((((_(52, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and (_(53, 
    ((~parent), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(54, 
    any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if 
    (((~parent), g) in relation_domain(m.GroupACL) and frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.GroupACL, ((~parent), g)) or g == function_value(m.FileGroup, (~parent)) and (~parent) in relation_domain(m.GroupObjACL) and frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.GroupObjACL, (~parent))))))) and (_(55, 
    (~parent) in relation_domain(m.MaskACL)))) and (_(56, frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.MaskACL, (~parent)))))) or ((((_(57, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and (_(58, 
    (~parent) not in relation_domain(m.MaskACL)))) and ((_(59, 
    function_value(m.FileGroup, (~parent)) == function_value(m.ProcGroup, (~proc)))) or (_(60, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~parent))) in m.UserGroups)))) and (_(61, 
    frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.DACPermissions, (~parent)))))) or ((((((((_(62, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and (_(63, 
    (~parent) in relation_domain(m.MaskACL)))) and (_(64, len(function_value(m.MaskACL, (~parent))) != 0))) and (_(65, 
    ((~parent), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(66, 
    not any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if not (
        ((~parent), g) not in relation_domain(m.GroupACL)
    ))))) and (_(67, 
    function_value(m.FileGroup, (~parent)) != function_value(m.ProcGroup, (~proc))))) and (_(68, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~parent))) not in m.UserGroups))) and (_(69, 
    frozenset((m.OWRITE, m.OEXECUTE)) <= function_value(m.DACPermissions, (~parent))))))))

    _grd27 = Guard('grd27', lambda _: (_(70, 
    (~group) in m.Groups)))

    _grd28 = Guard('grd28', lambda _: (not (_(71, 
    m.SET_GID not in function_value(m.DACPermissions, (~parent)))) or (_(72, (~group) == function_value(m.ProcGroup, (~proc))))))

    _grd29 = Guard('grd29', lambda _: (not (_(73, 
    m.SET_GID in function_value(m.DACPermissions, (~parent)))) or (_(74, (~group) == function_value(m.FileGroup, (~parent))))))

    _grd30 = Guard('grd30', lambda _: (_(75, 
    (~perms) == ((~mode) - ((~mode) & function_value(m.ProcUmask, (~proc)))))))


    _act1 = Action('act1', m, 'Files', lambda: ((m.Files | frozenset(((~file),)))))

    _act2 = Action('act2', m, 'FileParents', lambda: ((m.FileParents | frozenset((((~file), ((~parent), (~name))),)))))

    _act3 = Action('act3', m, 'FDs', lambda: ((m.FDs | frozenset(((~fd),)))))

    _act4 = Action('act4', m, 'FDNumber', lambda: (override_relation(m.FDNumber, frozenset((((~fd), (~fdNumber)),)))))

    _act5 = Action('act5', m, 'ProcFDs', lambda: ((m.ProcFDs | frozenset((((~proc), (~fd)),)))))

    _act6 = Action('act6', m, 'FDFlags', lambda: (override_relation(m.FDFlags, frozenset((((~fd), (~flags)),)))))

    _act7 = Action('act7', m, 'FDFile', lambda: (override_relation(m.FDFile, frozenset((((~fd), (~file)),)))))

    _act8 = Action('act8', m, 'DACPermissions', lambda: (override_relation(m.DACPermissions, frozenset((((~file), (~perms)),)))))

    _act9 = Action('act9', m, 'FileUser', lambda: (override_relation(m.FileUser, frozenset((((~file), function_value(m.ProcUser, (~proc))),)))))

    _act10 = Action('act10', m, 'FileGroup', lambda: (override_relation(m.FileGroup, frozenset((((~file), (~group)),)))))

    _act11 = Action('act11', m, 'FileXattrs', lambda: (override_relation(m.FileXattrs, frozenset((((~file), frozenset[tuple[Machine.StringsItem, Machine.DataItem]]()),)))))

    _act12 = Action('act12', m, 'GroupObjACL', lambda: ((m.GroupObjACL | frozenset((((~file), ((~perms) & m.GROUP_PERMISSIONS)),)))))


    return Event("openat_create", _grd1, _grd2, _grd3, _grd4, _grd5, _grd6, _grd7, _grd8, _grd9, _grd10, _grd11, _grd12, _grd13, _grd14, _grd15, _grd16, _grd17, _grd18, _grd19, _grd20, _grd21, _grd22, _grd23, _grd24, _grd25, _grd26, _grd27, _grd28, _grd29, _grd30, _act1, _act2, _act3, _act4, _act5, _act6, _act7, _act8, _act9, _act10, _act11, _act12)
