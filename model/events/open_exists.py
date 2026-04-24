from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import NAT, function_value, relation_image, relation_range, relation_domain, override_relation


def open_exists(m: Machine,
                _proc: Machine.ProcsItem | None,
                _parent: Machine.FilesItem | None,
                _file: Machine.FilesItem | None,
                _name: Machine.StringsItem | None,
                _flags: frozenset[int] | None,
                _fd: Machine.FileDescriptorsExtendedItem | None,
                _fdNumber: int | None) -> Event:

    proc = Parameter(_proc)
    parent = Parameter(_parent)
    file = Parameter(_file)
    name = Parameter(_name)
    flags = Parameter(_flags)
    fd = Parameter(_fd)
    fdNumber = Parameter(_fdNumber)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~proc) in m.Procs)))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    (~parent) in m.Folders)))

    _grd3 = Guard('grd3', lambda _: (_(3, 
    (~file) in m.Files)))

    _grd4 = Guard('grd4', lambda _: (_(4, 
    ((~file), ((~parent), (~name))) in m.FileParents)))

    _grd5 = Guard('grd5', lambda _: (_(5, 
    (~flags) <= m.OPEN_FLAGS)))

    _grd6 = Guard('grd6', lambda _: (_(6, 
    (~fd) in (m.FILE_DESCRIPTORS - m.FDs))))

    _grd7 = Guard('grd7', lambda _: (_(7, 
    (~fdNumber) in NAT)))

    _grd8 = Guard('grd8', lambda _: (_(8, 
    not any (True for (key, pfd) in m.ProcFDs if key == (~proc) if not (
        function_value(m.FDNumber, pfd) != (~fdNumber)
    )))))

    _grd9 = Guard('grd9', lambda _: (not (_(9, 
    m.O_PATH not in (~flags))) or (not ((_(10, m.O_CREAT in (~flags))) and (_(11, m.O_EXCL in (~flags)))))))

    _grd10 = Guard('grd10', lambda _: (((_(12, 
    m.O_RDONLY in (~flags))) or (_(13, m.O_WRONLY in (~flags)))) or (_(14, m.O_RDWR in (~flags)))))

    _grd11 = Guard('grd11', lambda _: (((not ((_(15, 
    m.O_RDONLY in (~flags))) and (_(16, m.O_WRONLY in (~flags))))) and (not ((_(17, 
    m.O_RDONLY in (~flags))) and (_(18, m.O_RDWR in (~flags)))))) and (not ((_(19, 
    m.O_WRONLY in (~flags))) and (_(20, m.O_RDWR in (~flags)))))))

    _grd12 = Guard('grd12', lambda _: (not ((_(21, 
    (~file) in m.Folders)) and (_(22, m.O_PATH not in (~flags)))) or ((_(23, m.O_WRONLY not in (~flags))) and (_(24, m.O_RDWR not in (~flags))))))

    _grd13 = Guard('grd13', lambda _: (_(25, 
    len(relation_image(m.ProcFDs, frozenset(((~proc),)))) < m.PROC_FILE_LIMIT)))

    _grd14 = Guard('grd14', lambda _: (_(26, 
    len(relation_range(m.ProcFDs)) < m.FILE_LIMIT)))

    _grd15 = Guard('grd15', lambda _: (not (_(27, 
    m.O_DIRECTORY in (~flags))) or (_(28, (~file) in m.Folders))))

    _grd16 = Guard('grd16', lambda _: (not ((_(29, 
    m.O_DIRECTORY in (~flags))) and (_(30, m.O_PATH not in (~flags)))) or (_(31, m.O_RDONLY in (~flags)))))

    _grd17 = Guard('grd17', lambda _: (_(32, 
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
        any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_range(m.UserGroups)) if 
        (g == function_value(m.ProcGroup, (~proc)) or (function_value(m.ProcUser, (~proc)), g) in m.UserGroups) if 
        ((f, g) in relation_domain(m.GroupACL) and m.GEXECUTE in function_value(m.GroupACL, (f, g)) or g == function_value(m.FileGroup, f) and f in relation_domain(m.GroupObjACL) and m.GEXECUTE in function_value(m.GroupObjACL, f))) and 
        f in relation_domain(m.MaskACL) and m.GEXECUTE in function_value(m.MaskACL, f)) or 
        function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, f) and 
        f not in relation_domain(m.MaskACL) and 
        (function_value(m.FileGroup, f) == function_value(m.ProcGroup, (~proc)) or (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, f)) in m.UserGroups) and 
        m.GEXECUTE in function_value(m.DACPermissions, f)) or 
        function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, f) and 
        f in relation_domain(m.MaskACL) and len(function_value(m.MaskACL, f)) != 0 and 
        (f, function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL) and 
        not any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_range(m.UserGroups)) if (g == function_value(m.ProcGroup, (~proc)) or (function_value(m.ProcUser, (~proc)), g) in m.UserGroups) if not (
            (f, g) not in relation_domain(m.GroupACL)
        )) and 
        function_value(m.FileGroup, f) != function_value(m.ProcGroup, (~proc)) and (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, f)) not in m.UserGroups and 
        m.OEXECUTE in function_value(m.DACPermissions, f))
    )))))

    _grd18 = Guard('grd18', lambda _: (not (((_(33, 
    function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) and (_(34, m.O_RDONLY in (~flags)))) and (_(35, m.O_PATH not in (~flags)))) or (((((((_(36, 
    function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, (~file)))) and (_(37, 
    m.UREAD in function_value(m.DACPermissions, (~file))))) or (((((_(38, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and ((_(39, 
    (~file) not in relation_domain(m.MaskACL))) or (_(40, len(function_value(m.MaskACL, (~file))) == 0)))) and (_(41, 
    function_value(m.FileGroup, (~file)) != function_value(m.ProcGroup, (~proc))))) and (_(42, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) not in m.UserGroups))) and (_(43, 
    m.OREAD in function_value(m.DACPermissions, (~file)))))) or ((((_(44, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(45, 
    ((~file), function_value(m.ProcUser, (~proc))) in relation_domain(m.UserACL)))) and (_(46, m.UREAD in function_value(m.UserACL, ((~file), function_value(m.ProcUser, (~proc))))))) and (_(47, 
    m.GREAD in function_value(m.MaskACL, (~file)))))) or (((((_(48, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(49, 
    ((~file), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(50, 
    any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_range(m.UserGroups)) if 
    (g == function_value(m.ProcGroup, (~proc)) or (function_value(m.ProcUser, (~proc)), g) in m.UserGroups) if 
    (((~file), g) in relation_domain(m.GroupACL) and m.GREAD in function_value(m.GroupACL, ((~file), g)) or g == function_value(m.FileGroup, (~file)) and (~file) in relation_domain(m.GroupObjACL) and m.GREAD in function_value(m.GroupObjACL, (~file))))))) and (_(51, 
    (~file) in relation_domain(m.MaskACL)))) and (_(52, m.GREAD in function_value(m.MaskACL, (~file)))))) or ((((_(53, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(54, 
    (~file) not in relation_domain(m.MaskACL)))) and ((_(55, 
    function_value(m.FileGroup, (~file)) == function_value(m.ProcGroup, (~proc)))) or (_(56, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) in m.UserGroups)))) and (_(57, 
    m.GREAD in function_value(m.DACPermissions, (~file)))))) or ((((((((_(58, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(59, 
    (~file) in relation_domain(m.MaskACL)))) and (_(60, len(function_value(m.MaskACL, (~file))) != 0))) and (_(61, 
    ((~file), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(62, 
    not any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_range(m.UserGroups)) if (g == function_value(m.ProcGroup, (~proc)) or (function_value(m.ProcUser, (~proc)), g) in m.UserGroups) if not (
        ((~file), g) not in relation_domain(m.GroupACL)
    ))))) and (_(63, 
    function_value(m.FileGroup, (~file)) != function_value(m.ProcGroup, (~proc))))) and (_(64, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) not in m.UserGroups))) and (_(65, 
    m.OREAD in function_value(m.DACPermissions, (~file))))))))

    _grd19 = Guard('grd19', lambda _: (not (((_(66, 
    function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) and (_(67, m.O_WRONLY in (~flags)))) and (_(68, m.O_PATH not in (~flags)))) or (((((((_(69, 
    function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, (~file)))) and (_(70, 
    m.UWRITE in function_value(m.DACPermissions, (~file))))) or (((((_(71, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and ((_(72, 
    (~file) not in relation_domain(m.MaskACL))) or (_(73, len(function_value(m.MaskACL, (~file))) == 0)))) and (_(74, 
    function_value(m.FileGroup, (~file)) != function_value(m.ProcGroup, (~proc))))) and (_(75, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) not in m.UserGroups))) and (_(76, 
    m.OWRITE in function_value(m.DACPermissions, (~file)))))) or ((((_(77, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(78, 
    ((~file), function_value(m.ProcUser, (~proc))) in relation_domain(m.UserACL)))) and (_(79, m.UWRITE in function_value(m.UserACL, ((~file), function_value(m.ProcUser, (~proc))))))) and (_(80, 
    m.GWRITE in function_value(m.MaskACL, (~file)))))) or (((((_(81, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(82, 
    ((~file), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(83, 
    any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_range(m.UserGroups)) if 
    (g == function_value(m.ProcGroup, (~proc)) or (function_value(m.ProcUser, (~proc)), g) in m.UserGroups) if 
    (((~file), g) in relation_domain(m.GroupACL) and m.GWRITE in function_value(m.GroupACL, ((~file), g)) or g == function_value(m.FileGroup, (~file)) and (~file) in relation_domain(m.GroupObjACL) and m.GWRITE in function_value(m.GroupObjACL, (~file))))))) and (_(84, 
    (~file) in relation_domain(m.MaskACL)))) and (_(85, m.GWRITE in function_value(m.MaskACL, (~file)))))) or ((((_(86, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(87, 
    (~file) not in relation_domain(m.MaskACL)))) and ((_(88, 
    function_value(m.FileGroup, (~file)) == function_value(m.ProcGroup, (~proc)))) or (_(89, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) in m.UserGroups)))) and (_(90, 
    m.GWRITE in function_value(m.DACPermissions, (~file)))))) or ((((((((_(91, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(92, 
    (~file) in relation_domain(m.MaskACL)))) and (_(93, len(function_value(m.MaskACL, (~file))) != 0))) and (_(94, 
    ((~file), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(95, 
    not any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_range(m.UserGroups)) if (g == function_value(m.ProcGroup, (~proc)) or (function_value(m.ProcUser, (~proc)), g) in m.UserGroups) if not (
        ((~file), g) not in relation_domain(m.GroupACL)
    ))))) and (_(96, 
    function_value(m.FileGroup, (~file)) != function_value(m.ProcGroup, (~proc))))) and (_(97, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) not in m.UserGroups))) and (_(98, 
    m.OWRITE in function_value(m.DACPermissions, (~file))))))))

    _grd20 = Guard('grd20', lambda _: (not (((_(99, 
    function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) and (_(100, m.O_RDWR in (~flags)))) and (_(101, m.O_PATH not in (~flags)))) or (((((((_(102, 
    function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, (~file)))) and (_(103, 
    frozenset((m.UREAD, m.UWRITE)) <= function_value(m.DACPermissions, (~file))))) or (((((_(104, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and ((_(105, 
    (~file) not in relation_domain(m.MaskACL))) or (_(106, len(function_value(m.MaskACL, (~file))) == 0)))) and (_(107, 
    function_value(m.FileGroup, (~file)) != function_value(m.ProcGroup, (~proc))))) and (_(108, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) not in m.UserGroups))) and (_(109, 
    frozenset((m.OREAD, m.OWRITE)) <= function_value(m.DACPermissions, (~file)))))) or ((((_(110, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(111, 
    ((~file), function_value(m.ProcUser, (~proc))) in relation_domain(m.UserACL)))) and (_(112, frozenset((m.UREAD, m.UWRITE)) <= function_value(m.UserACL, ((~file), function_value(m.ProcUser, (~proc))))))) and (_(113, 
    frozenset((m.GREAD, m.GWRITE)) <= function_value(m.MaskACL, (~file)))))) or (((((_(114, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(115, 
    ((~file), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(116, 
    any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if 
    (((~file), g) in relation_domain(m.GroupACL) and frozenset((m.GREAD, m.GWRITE)) <= function_value(m.GroupACL, ((~file), g)) or g == function_value(m.FileGroup, (~file)) and (~file) in relation_domain(m.GroupObjACL) and frozenset((m.GREAD, m.GWRITE)) <= function_value(m.GroupObjACL, (~file))))))) and (_(117, 
    (~file) in relation_domain(m.MaskACL)))) and (_(118, frozenset((m.GREAD, m.GWRITE)) <= function_value(m.MaskACL, (~file)))))) or ((((_(119, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(120, 
    (~file) not in relation_domain(m.MaskACL)))) and ((_(121, 
    function_value(m.FileGroup, (~file)) == function_value(m.ProcGroup, (~proc)))) or (_(122, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) in m.UserGroups)))) and (_(123, 
    frozenset((m.GREAD, m.GWRITE)) <= function_value(m.DACPermissions, (~file)))))) or ((((((((_(124, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(125, 
    (~file) in relation_domain(m.MaskACL)))) and (_(126, len(function_value(m.MaskACL, (~file))) != 0))) and (_(127, 
    ((~file), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(128, 
    not any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if not (
        ((~file), g) not in relation_domain(m.GroupACL)
    ))))) and (_(129, 
    function_value(m.FileGroup, (~file)) != function_value(m.ProcGroup, (~proc))))) and (_(130, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) not in m.UserGroups))) and (_(131, 
    frozenset((m.OREAD, m.OWRITE)) <= function_value(m.DACPermissions, (~file))))))))

    _grd21 = Guard('grd21', lambda _: (not ((_(132, m.O_DIRECTORY in (~flags))) and (_(133, m.O_PATH not in (~flags)))) or (_(134, m.O_CREAT not in (~flags)))))

    _grd22 = Guard('grd22', lambda _: (not (((_(135, 
    m.O_PATH not in (~flags))) and (_(136, m.O_DIRECTORY not in (~flags)))) and (_(137, m.O_CREAT in (~flags)))) or (_(138, (~file) not in m.Folders))))


    _act1 = Action('act1', m, 'FDs', lambda: ((m.FDs | frozenset(((~fd),)))))

    _act2 = Action('act2', m, 'FDNumber', lambda: (override_relation(m.FDNumber, frozenset((((~fd), (~fdNumber)),)))))

    _act3 = Action('act3', m, 'ProcFDs', lambda: ((m.ProcFDs | frozenset((((~proc), (~fd)),)))))

    _act4 = Action('act4', m, 'FDFlags', lambda: (override_relation(m.FDFlags, frozenset((((~fd), (~flags)),)))))

    _act5 = Action('act5', m, 'FDFile', lambda: (override_relation(m.FDFile, frozenset((((~fd), (~file)),)))))


    return Event("open_exists", _grd1, _grd2, _grd3, _grd4, _grd5, _grd6, _grd7, _grd8, _grd9, _grd10, _grd11, _grd12, _grd13, _grd14, _grd15, _grd16, _grd17, _grd18, _grd19, _grd20, _grd21, _grd22, _act1, _act2, _act3, _act4, _act5)
