from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import NAT, function_value, relation_image, relation_range, relation_domain, override_relation


def openat_exists(m: Machine,
                  _proc: Machine.ProcsItem | None,
                  _dirfd: Machine.FileDescriptorsExtendedItem | None,
                  _parent: Machine.FilesItem | None,
                  _file: Machine.FilesItem | None,
                  _name: Machine.StringsItem | None,
                  _flags: frozenset[int] | None,
                  _fd: Machine.FileDescriptorsExtendedItem | None,
                  _fdNumber: int | None,
                  _cwd: Machine.FilesItem | None) -> Event:

    proc = Parameter(_proc)
    dirfd = Parameter(_dirfd)
    parent = Parameter(_parent)
    file = Parameter(_file)
    name = Parameter(_name)
    flags = Parameter(_flags)
    fd = Parameter(_fd)
    fdNumber = Parameter(_fdNumber)
    cwd = Parameter(_cwd)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~proc) in m.Procs)))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    (~dirfd) in m.FILE_DESCRIPTORS_EXTENDED)))

    _grd3 = Guard('grd3', lambda _: (_(3, 
    (~parent) in m.Folders)))

    _grd4 = Guard('grd4', lambda _: (_(4, 
    (~file) in m.Files)))

    _grd5 = Guard('grd5', lambda _: (_(5, 
    ((~file), ((~parent), (~name))) in m.FileParents)))

    _grd6 = Guard('grd6', lambda _: (_(6, 
    (~flags) <= m.OPEN_FLAGS)))

    _grd7 = Guard('grd7', lambda _: (_(7, 
    (~fd) in (m.FILE_DESCRIPTORS - m.FDs))))

    _grd8 = Guard('grd8', lambda _: (_(8, 
    (~fdNumber) in NAT)))

    _grd9 = Guard('grd9', lambda _: (_(9, 
    (~cwd) in m.Folders)))

    _grd10 = Guard('grd10', lambda _: (not (_(10, 
    (~dirfd) == m.AT_FDCWD)) or (_(11, (~cwd) == function_value(m.ProcCwd, (~proc))))))

    _grd11 = Guard('grd11', lambda _: (not (_(12, 
    (~dirfd) != m.AT_FDCWD)) or ((_(13, ((~proc), (~dirfd)) in m.ProcFDs)) and (_(14, (~cwd) == function_value(m.FDFile, (~dirfd)))))))

    _grd12 = Guard('grd12', lambda _: (_(15, 
    (~cwd) in (function_value(m.PathToRoot, (~parent)) | frozenset(((~parent),))))))

    _grd13 = Guard('grd13', lambda _: (_(16, 
    not any (True for (key, pfd) in m.ProcFDs if key == (~proc) if not (
        function_value(m.FDNumber, pfd) != (~fdNumber)
    )))))

    _grd14 = Guard('grd14', lambda _: (not (_(17, 
    m.O_PATH not in (~flags))) or (not ((_(18, m.O_CREAT in (~flags))) and (_(19, m.O_EXCL in (~flags)))))))

    _grd15 = Guard('grd15', lambda _: (((_(20, 
    m.O_RDONLY in (~flags))) or (_(21, m.O_WRONLY in (~flags)))) or (_(22, m.O_RDWR in (~flags)))))

    _grd16 = Guard('grd16', lambda _: (((not ((_(23, 
    m.O_RDONLY in (~flags))) and (_(24, m.O_WRONLY in (~flags))))) and (not ((_(25, 
    m.O_RDONLY in (~flags))) and (_(26, m.O_RDWR in (~flags)))))) and (not ((_(27, 
    m.O_WRONLY in (~flags))) and (_(28, m.O_RDWR in (~flags)))))))

    _grd17 = Guard('grd17', lambda _: (not ((_(29, 
    (~file) in m.Folders)) and (_(30, m.O_PATH not in (~flags)))) or ((_(31, m.O_WRONLY not in (~flags))) and (_(32, m.O_RDWR not in (~flags))))))

    _grd18 = Guard('grd18', lambda _: (_(33, 
    len(relation_image(m.ProcFDs, frozenset(((~proc),)))) < m.PROC_FILE_LIMIT)))

    _grd19 = Guard('grd19', lambda _: (_(34, 
    len(relation_range(m.ProcFDs)) < m.FILE_LIMIT)))

    _grd20 = Guard('grd20', lambda _: (not (_(35, 
    m.O_DIRECTORY in (~flags))) or (_(36, (~file) in m.Folders))))

    _grd21 = Guard('grd21', lambda _: (not ((_(37, 
    m.O_DIRECTORY in (~flags))) and (_(38, m.O_PATH not in (~flags)))) or (_(39, m.O_RDONLY in (~flags)))))

    _grd22 = Guard('grd22', lambda _: (_(40, 
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

    _grd23 = Guard('grd23', lambda _: (not (((_(41, 
    function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) and (_(42, m.O_RDONLY in (~flags)))) and (_(43, m.O_PATH not in (~flags)))) or (((((((_(44, 
    function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, (~file)))) and (_(45, 
    m.UREAD in function_value(m.DACPermissions, (~file))))) or (((((_(46, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and ((_(47, 
    (~file) not in relation_domain(m.MaskACL))) or (_(48, len(function_value(m.MaskACL, (~file))) == 0)))) and (_(49, 
    function_value(m.FileGroup, (~file)) != function_value(m.ProcGroup, (~proc))))) and (_(50, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) not in m.UserGroups))) and (_(51, 
    m.OREAD in function_value(m.DACPermissions, (~file)))))) or ((((_(52, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(53, 
    ((~file), function_value(m.ProcUser, (~proc))) in relation_domain(m.UserACL)))) and (_(54, m.UREAD in function_value(m.UserACL, ((~file), function_value(m.ProcUser, (~proc))))))) and (_(55, 
    m.GREAD in function_value(m.MaskACL, (~file)))))) or (((((_(56, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(57, 
    ((~file), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(58, 
    any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if 
    (((~file), g) in relation_domain(m.GroupACL) and m.GREAD in function_value(m.GroupACL, ((~file), g)) or g == function_value(m.FileGroup, (~file)) and (~file) in relation_domain(m.GroupObjACL) and m.GREAD in function_value(m.GroupObjACL, (~file))))))) and (_(59, 
    (~file) in relation_domain(m.MaskACL)))) and (_(60, m.GREAD in function_value(m.MaskACL, (~file)))))) or ((((_(61, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(62, 
    (~file) not in relation_domain(m.MaskACL)))) and ((_(63, 
    function_value(m.FileGroup, (~file)) == function_value(m.ProcGroup, (~proc)))) or (_(64, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) in m.UserGroups)))) and (_(65, 
    m.GREAD in function_value(m.DACPermissions, (~file)))))) or ((((((((_(66, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(67, 
    (~file) in relation_domain(m.MaskACL)))) and (_(68, len(function_value(m.MaskACL, (~file))) != 0))) and (_(69, 
    ((~file), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(70, 
    not any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if not (
        ((~file), g) not in relation_domain(m.GroupACL)
    ))))) and (_(71, 
    function_value(m.FileGroup, (~file)) != function_value(m.ProcGroup, (~proc))))) and (_(72, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) not in m.UserGroups))) and (_(73, 
    m.OREAD in function_value(m.DACPermissions, (~file))))))))

    _grd24 = Guard('grd24', lambda _: (not (((_(74, 
    function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) and (_(75, m.O_WRONLY in (~flags)))) and (_(76, m.O_PATH not in (~flags)))) or (((((((_(77, 
    function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, (~file)))) and (_(78, 
    m.UWRITE in function_value(m.DACPermissions, (~file))))) or (((((_(79, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and ((_(80, 
    (~file) not in relation_domain(m.MaskACL))) or (_(81, len(function_value(m.MaskACL, (~file))) == 0)))) and (_(82, 
    function_value(m.FileGroup, (~file)) != function_value(m.ProcGroup, (~proc))))) and (_(83, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) not in m.UserGroups))) and (_(84, 
    m.OWRITE in function_value(m.DACPermissions, (~file)))))) or ((((_(85, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(86, 
    ((~file), function_value(m.ProcUser, (~proc))) in relation_domain(m.UserACL)))) and (_(87, m.UWRITE in function_value(m.UserACL, ((~file), function_value(m.ProcUser, (~proc))))))) and (_(88, 
    m.GWRITE in function_value(m.MaskACL, (~file)))))) or (((((_(89, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(90, 
    ((~file), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(91, 
    any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if 
    (((~file), g) in relation_domain(m.GroupACL) and m.GWRITE in function_value(m.GroupACL, ((~file), g)) or g == function_value(m.FileGroup, (~file)) and (~file) in relation_domain(m.GroupObjACL) and m.GWRITE in function_value(m.GroupObjACL, (~file))))))) and (_(92, 
    (~file) in relation_domain(m.MaskACL)))) and (_(93, m.GWRITE in function_value(m.MaskACL, (~file)))))) or ((((_(94, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(95, 
    (~file) not in relation_domain(m.MaskACL)))) and ((_(96, 
    function_value(m.FileGroup, (~file)) == function_value(m.ProcGroup, (~proc)))) or (_(97, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) in m.UserGroups)))) and (_(98, 
    m.GWRITE in function_value(m.DACPermissions, (~file)))))) or ((((((((_(99, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(100, 
    (~file) in relation_domain(m.MaskACL)))) and (_(101, len(function_value(m.MaskACL, (~file))) != 0))) and (_(102, 
    ((~file), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(103, 
    not any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if not (
        ((~file), g) not in relation_domain(m.GroupACL)
    ))))) and (_(104, 
    function_value(m.FileGroup, (~file)) != function_value(m.ProcGroup, (~proc))))) and (_(105, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) not in m.UserGroups))) and (_(106, 
    m.OWRITE in function_value(m.DACPermissions, (~file))))))))

    _grd25 = Guard('grd25', lambda _: (not (((_(107, 
    function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) and (_(108, m.O_RDWR in (~flags)))) and (_(109, m.O_PATH not in (~flags)))) or (((((((_(110, 
    function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, (~file)))) and (_(111, 
    frozenset((m.UREAD, m.UWRITE)) <= function_value(m.DACPermissions, (~file))))) or (((((_(112, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and ((_(113, 
    (~file) not in relation_domain(m.MaskACL))) or (_(114, len(function_value(m.MaskACL, (~file))) == 0)))) and (_(115, 
    function_value(m.FileGroup, (~file)) != function_value(m.ProcGroup, (~proc))))) and (_(116, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) not in m.UserGroups))) and (_(117, 
    frozenset((m.OREAD, m.OWRITE)) <= function_value(m.DACPermissions, (~file)))))) or ((((_(118, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(119, 
    ((~file), function_value(m.ProcUser, (~proc))) in relation_domain(m.UserACL)))) and (_(120, frozenset((m.UREAD, m.UWRITE)) <= function_value(m.UserACL, ((~file), function_value(m.ProcUser, (~proc))))))) and (_(121, 
    frozenset((m.GREAD, m.GWRITE)) <= function_value(m.MaskACL, (~file)))))) or (((((_(122, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(123, 
    ((~file), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(124, 
    any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if 
    (((~file), g) in relation_domain(m.GroupACL) and frozenset((m.GREAD, m.GWRITE)) <= function_value(m.GroupACL, ((~file), g)) or g == function_value(m.FileGroup, (~file)) and (~file) in relation_domain(m.GroupObjACL) and frozenset((m.GREAD, m.GWRITE)) <= function_value(m.GroupObjACL, (~file))))))) and (_(125, 
    (~file) in relation_domain(m.MaskACL)))) and (_(126, frozenset((m.GREAD, m.GWRITE)) <= function_value(m.MaskACL, (~file)))))) or ((((_(127, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(128, 
    (~file) not in relation_domain(m.MaskACL)))) and ((_(129, 
    function_value(m.FileGroup, (~file)) == function_value(m.ProcGroup, (~proc)))) or (_(130, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) in m.UserGroups)))) and (_(131, 
    frozenset((m.GREAD, m.GWRITE)) <= function_value(m.DACPermissions, (~file)))))) or ((((((((_(132, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(133, 
    (~file) in relation_domain(m.MaskACL)))) and (_(134, len(function_value(m.MaskACL, (~file))) != 0))) and (_(135, 
    ((~file), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(136, 
    not any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if not (
        ((~file), g) not in relation_domain(m.GroupACL)
    ))))) and (_(137, 
    function_value(m.FileGroup, (~file)) != function_value(m.ProcGroup, (~proc))))) and (_(138, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) not in m.UserGroups))) and (_(139, 
    frozenset((m.OREAD, m.OWRITE)) <= function_value(m.DACPermissions, (~file))))))))


    _act1 = Action('act1', m, 'FDs', lambda: ((m.FDs | frozenset(((~fd),)))))

    _act2 = Action('act2', m, 'FDNumber', lambda: (override_relation(m.FDNumber, frozenset((((~fd), (~fdNumber)),)))))

    _act3 = Action('act3', m, 'ProcFDs', lambda: ((m.ProcFDs | frozenset((((~proc), (~fd)),)))))

    _act4 = Action('act4', m, 'FDFlags', lambda: (override_relation(m.FDFlags, frozenset((((~fd), (~flags)),)))))

    _act5 = Action('act5', m, 'FDFile', lambda: (override_relation(m.FDFile, frozenset((((~fd), (~file)),)))))


    return Event("openat_exists", _grd1, _grd2, _grd3, _grd4, _grd5, _grd6, _grd7, _grd8, _grd9, _grd10, _grd11, _grd12, _grd13, _grd14, _grd15, _grd16, _grd17, _grd18, _grd19, _grd20, _grd21, _grd22, _grd23, _grd24, _grd25, _act1, _act2, _act3, _act4, _act5)
