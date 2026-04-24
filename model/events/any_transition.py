from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import total_relations, cartesian_product, total_functions, relations, powerset, NAT, partial_functions, function_value, relation_domain, relation_image, relation_range


def any_transition(m: Machine,
                   _fUsers: frozenset[Machine.UsersItem] | None,
                   _fGroups: frozenset[Machine.GroupsItem] | None,
                   _fProcs: frozenset[Machine.ProcsItem] | None,
                   _fFiles: frozenset[Machine.FilesItem] | None,
                   _fFolders: frozenset[Machine.FilesItem] | None,
                   _fSymLinks: frozenset[Machine.FilesItem] | None,
                   _fFDs: frozenset[Machine.FileDescriptorsExtendedItem] | None,
                   _fFileParents: frozenset[tuple[Machine.FilesItem, tuple[Machine.FilesItem, Machine.StringsItem]]] | None,
                   _fFileLink: frozenset[tuple[Machine.FilesItem, tuple[Machine.FilesItem, Machine.StringsItem]]] | None,
                   _fProcFDs: frozenset[tuple[Machine.ProcsItem, Machine.FileDescriptorsExtendedItem]] | None,
                   _fFDFlags: frozenset[tuple[Machine.FileDescriptorsExtendedItem, frozenset[int]]] | None,
                   _fFDFile: frozenset[tuple[Machine.FileDescriptorsExtendedItem, Machine.FilesItem]] | None,
                   _fFDNumber: frozenset[tuple[Machine.FileDescriptorsExtendedItem, int]] | None,
                   _fDACPermissions: frozenset[tuple[Machine.FilesItem, frozenset[Machine.PermissionsItem]]] | None,
                   _fUserACL: frozenset[tuple[tuple[Machine.FilesItem, Machine.UsersItem], frozenset[Machine.PermissionsItem]]] | None,
                   _fGroupObjACL: frozenset[tuple[Machine.FilesItem, frozenset[Machine.PermissionsItem]]] | None,
                   _fGroupACL: frozenset[tuple[tuple[Machine.FilesItem, Machine.GroupsItem], frozenset[Machine.PermissionsItem]]] | None,
                   _fMaskACL: frozenset[tuple[Machine.FilesItem, frozenset[Machine.PermissionsItem]]] | None,
                   _fFileUser: frozenset[tuple[Machine.FilesItem, Machine.UsersItem]] | None,
                   _fFileGroup: frozenset[tuple[Machine.FilesItem, Machine.GroupsItem]] | None,
                   _fProcUser: frozenset[tuple[Machine.ProcsItem, Machine.UsersItem]] | None,
                   _fProcGroup: frozenset[tuple[Machine.ProcsItem, Machine.GroupsItem]] | None,
                   _fProcUmask: frozenset[tuple[Machine.ProcsItem, frozenset[Machine.PermissionsItem]]] | None,
                   _fFileXattrs: frozenset[tuple[Machine.FilesItem, frozenset[tuple[Machine.StringsItem, Machine.DataItem]]]] | None,
                   _fProcEXE: frozenset[tuple[Machine.ProcsItem, Machine.FilesItem]] | None,
                   _fProcArgv: frozenset[tuple[Machine.ProcsItem, frozenset[Machine.StringsItem]]] | None,
                   _fProcEnvp: frozenset[tuple[Machine.ProcsItem, frozenset[Machine.StringsItem]]] | None,
                   _fProcCwd: frozenset[tuple[Machine.ProcsItem, Machine.FilesItem]] | None,
                   _fProcParent: frozenset[tuple[Machine.ProcsItem, Machine.ProcsItem]] | None,
                   _fUserGroups: frozenset[tuple[Machine.UsersItem, Machine.GroupsItem]] | None,
                   _fPathToRoot: frozenset[tuple[Machine.FilesItem, frozenset[Machine.FilesItem]]] | None,
                   _fUserCaps: frozenset[tuple[Machine.UsersItem, frozenset[Machine.CapabilitiesItem]]] | None) -> Event:

    fUsers = Parameter(_fUsers)
    fGroups = Parameter(_fGroups)
    fProcs = Parameter(_fProcs)
    fFiles = Parameter(_fFiles)
    fFolders = Parameter(_fFolders)
    fSymLinks = Parameter(_fSymLinks)
    fFDs = Parameter(_fFDs)
    fFileParents = Parameter(_fFileParents)
    fFileLink = Parameter(_fFileLink)
    fProcFDs = Parameter(_fProcFDs)
    fFDFlags = Parameter(_fFDFlags)
    fFDFile = Parameter(_fFDFile)
    fFDNumber = Parameter(_fFDNumber)
    fDACPermissions = Parameter(_fDACPermissions)
    fUserACL = Parameter(_fUserACL)
    fGroupObjACL = Parameter(_fGroupObjACL)
    fGroupACL = Parameter(_fGroupACL)
    fMaskACL = Parameter(_fMaskACL)
    fFileUser = Parameter(_fFileUser)
    fFileGroup = Parameter(_fFileGroup)
    fProcUser = Parameter(_fProcUser)
    fProcGroup = Parameter(_fProcGroup)
    fProcUmask = Parameter(_fProcUmask)
    fFileXattrs = Parameter(_fFileXattrs)
    fProcEXE = Parameter(_fProcEXE)
    fProcArgv = Parameter(_fProcArgv)
    fProcEnvp = Parameter(_fProcEnvp)
    fProcCwd = Parameter(_fProcCwd)
    fProcParent = Parameter(_fProcParent)
    fUserGroups = Parameter(_fUserGroups)
    fPathToRoot = Parameter(_fPathToRoot)
    fUserCaps = Parameter(_fUserCaps)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~fUsers) <= m.USERS)))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    (~fGroups) <= m.GROUPS)))

    _grd3 = Guard('grd3', lambda _: (_(3, 
    (~fProcs) <= m.PROCS)))

    _grd4 = Guard('grd4', lambda _: (_(4, 
    (~fFiles) <= m.FILES)))

    _grd5 = Guard('grd5', lambda _: (_(5, 
    (~fFolders) <= (~fFiles))))

    _grd6 = Guard('grd6', lambda _: (_(6, 
    (~fSymLinks) <= (~fFiles))))

    _grd7 = Guard('grd7', lambda _: (_(7, 
    (~fFDs) <= m.FILE_DESCRIPTORS)))

    _grd8 = Guard('grd8', lambda _: (_(8, 
    m.INIT in (~fProcs))))

    _grd9 = Guard('grd9', lambda _: (_(9, 
    m.ROOT in (~fFolders))))

    _grd10 = Guard('grd10', lambda _: (_(10, 
    m.ROOT_USER in (~fUsers))))

    _grd11 = Guard('grd11', lambda _: (_(11, 
    (~fFileParents) in total_relations(((~fFiles) - frozenset((m.ROOT,))), cartesian_product((~fFolders), m.STRINGS)))))

    _grd12 = Guard('grd12', lambda _: (_(12, 
    (~fFileLink) in total_functions((~fSymLinks), cartesian_product(m.FILES, m.STRINGS)))))

    _grd13 = Guard('grd13', lambda _: (_(13, 
    (~fProcFDs) in relations((~fProcs), (~fFDs)))))

    _grd14 = Guard('grd14', lambda _: (_(14, 
    (~fFDFlags) in total_functions((~fFDs), powerset(m.OPEN_FLAGS)))))

    _grd15 = Guard('grd15', lambda _: (_(15, 
    (~fFDFile) in total_functions((~fFDs), m.FILES))))

    _grd16 = Guard('grd16', lambda _: (_(16, 
    (~fFDNumber) in total_functions((~fFDs), NAT))))

    _grd17 = Guard('grd17', lambda _: (_(17, 
    (~fDACPermissions) in total_functions((~fFiles), powerset(m.PERMISSIONS)))))

    _grd18 = Guard('grd18', lambda _: (_(18, 
    (~fUserACL) in partial_functions(cartesian_product((~fFiles), (~fUsers)), powerset(m.USER_PERMISSIONS)))))

    _grd19 = Guard('grd19', lambda _: (_(19, 
    (~fGroupObjACL) in partial_functions((~fFiles), powerset(m.GROUP_PERMISSIONS)))))

    _grd20 = Guard('grd20', lambda _: (_(20, 
    (~fGroupACL) in partial_functions(cartesian_product((~fFiles), (~fGroups)), powerset(m.GROUP_PERMISSIONS)))))

    _grd21 = Guard('grd21', lambda _: (_(21, 
    (~fMaskACL) in partial_functions((~fFiles), powerset(m.GROUP_PERMISSIONS)))))

    _grd22 = Guard('grd22', lambda _: (_(22, 
    (~fFileUser) in total_functions((~fFiles), (~fUsers)))))

    _grd23 = Guard('grd23', lambda _: (_(23, 
    (~fFileGroup) in total_functions((~fFiles), (~fGroups)))))

    _grd24 = Guard('grd24', lambda _: (_(24, 
    (~fProcUser) in total_functions((~fProcs), (~fUsers)))))

    _grd25 = Guard('grd25', lambda _: (_(25, 
    (~fProcGroup) in total_functions((~fProcs), (~fGroups)))))

    _grd26 = Guard('grd26', lambda _: (_(26, 
    (~fProcUmask) in total_functions((~fProcs), powerset((m.PERMISSIONS - m.FILE_MODES))))))

    _grd27 = Guard('grd27', lambda _: (_(27, 
    (~fFileXattrs) in total_functions((~fFiles), partial_functions(m.STRINGS, m.DATA)))))

    _grd28 = Guard('grd28', lambda _: (_(28, 
    (~fProcEXE) in total_functions((~fProcs), m.FILES))))

    _grd29 = Guard('grd29', lambda _: (_(29, 
    (~fProcArgv) in total_functions((~fProcs), powerset(m.STRINGS)))))

    _grd30 = Guard('grd30', lambda _: (_(30, 
    (~fProcEnvp) in total_functions((~fProcs), powerset(m.STRINGS)))))

    _grd31 = Guard('grd31', lambda _: (_(31, 
    (~fProcCwd) in total_functions((~fProcs), m.FILES))))

    _grd32 = Guard('grd32', lambda _: (_(32, 
    (~fProcParent) in total_functions(((~fProcs) - frozenset((m.INIT,))), (~fProcs)))))

    _grd33 = Guard('grd33', lambda _: (_(33, 
    (~fUserGroups) in relations((~fUsers), (~fGroups)))))

    _grd34 = Guard('grd34', lambda _: (_(34, 
    (~fPathToRoot) in total_functions((~fFolders), powerset((~fFolders))))))

    _grd35 = Guard('grd35', lambda _: (_(35, 
    (~fUserCaps) in total_functions((~fUsers), powerset(m.CAPABILITIES)))))

    _grd36 = Guard('grd36', lambda _: (_(36, 
    len(function_value((~fPathToRoot), m.ROOT)) == 0)))

    _grd37 = Guard('grd37', lambda _: (_(37, 
    not any (True for f in (~fFolders) for p in relation_domain(relation_image((~fFileParents), frozenset((f,)))) if not (
        function_value((~fPathToRoot), f) == (function_value((~fPathToRoot), p) | frozenset((p,)))
    )))))

    _grd38 = Guard('grd38', lambda _: (_(38, 
    not any (True for f in (~fFolders) for p in function_value((~fPathToRoot), f) if not (
        function_value((~fPathToRoot), p) <= function_value((~fPathToRoot), f)
    )))))

    _grd39 = Guard('grd39', lambda _: (_(39, 
    not any (True for f in (~fFolders) for p in function_value((~fPathToRoot), f) if not (
        any (True for c in (function_value((~fPathToRoot), f) | frozenset((f,))) if p in relation_domain(relation_image((~fFileParents), frozenset((c,)))))
    )))))

    _grd40 = Guard('grd40', lambda _: (_(40, 
    len((~fFiles)) <= m.MAX_FILES)))

    _grd41 = Guard('grd41', lambda _: (_(41, 
    len(((~fSymLinks) & (~fFolders))) == 0)))

    _grd42 = Guard('grd42', lambda _: (_(42, 
    not any (True for p in (~fProcs) if not (
        function_value((~fProcEXE), p) not in (~fFolders)
    )))))

    _grd43 = Guard('grd43', lambda _: (_(43, 
    not any (True for p in (~fProcs) if not (
        len(relation_image((~fProcFDs), frozenset((p,)))) <= m.PROC_FILE_LIMIT
    )))))

    _grd44 = Guard('grd44', lambda _: (_(44, 
    len(relation_range((~fProcFDs))) <= m.FILE_LIMIT)))

    _grd45 = Guard('grd45', lambda _: (_(45, 
    not any (True for p in (~fProcs) for (key, fd) in (~fProcFDs) if key == p if function_value((~fFDFile), fd) in (~fFolders) if m.O_PATH not in function_value((~fFDFlags), fd) if not (
        m.O_WRONLY not in function_value((~fFDFlags), fd) and m.O_RDWR not in function_value((~fFDFlags), fd)
    )))))

    _grd46 = Guard('grd46', lambda _: (_(46, 
    not any (True for f in ((~fFolders) - frozenset((m.ROOT,))) if not (
        any (True for (p, n) in relation_image((~fFileParents), frozenset((f,))) if frozenset(((p, n),)) == relation_image((~fFileParents), frozenset((f,))))
    )))))

    _grd47 = Guard('grd47', lambda _: (_(47, 
    not any (True for (f, u) in relation_domain((~fUserACL)) if not (
        f in relation_domain((~fMaskACL))
    )))))

    _grd48 = Guard('grd48', lambda _: (_(48, 
    not any (True for (f, g) in relation_domain((~fGroupACL)) if not (
        f in relation_domain((~fMaskACL))
    )))))

    _grd49 = Guard('grd49', lambda _: (_(49, 
    not any (True for f in relation_domain((~fMaskACL)) if not (
        function_value((~fMaskACL), f) == (function_value((~fDACPermissions), f) & m.GROUP_PERMISSIONS)
    )))))

    _grd50 = Guard('grd50', lambda _: (_(50, 
    not any (True for f in (~fFiles) if f not in relation_domain((~fMaskACL)) if not (
        f in relation_domain((~fGroupObjACL)) and function_value((~fGroupObjACL), f) == (function_value((~fDACPermissions), f) & m.GROUP_PERMISSIONS)
    )))))

    _grd51 = Guard('grd51', lambda _: (_(51, 
    not any (True for p in (~fProcs) if function_value((~fProcCwd), p) in (~fFiles) if not (
        function_value((~fProcCwd), p) in (~fFolders)
    )))))


    _act1 = Action('act1', m, 'Users', lambda: ((~fUsers)))

    _act2 = Action('act2', m, 'Groups', lambda: ((~fGroups)))

    _act3 = Action('act3', m, 'Procs', lambda: ((~fProcs)))

    _act4 = Action('act4', m, 'Files', lambda: ((~fFiles)))

    _act5 = Action('act5', m, 'Folders', lambda: ((~fFolders)))

    _act6 = Action('act6', m, 'SymLinks', lambda: ((~fSymLinks)))

    _act7 = Action('act7', m, 'FDs', lambda: ((~fFDs)))

    _act8 = Action('act8', m, 'FileParents', lambda: ((~fFileParents)))

    _act9 = Action('act9', m, 'FileLink', lambda: ((~fFileLink)))

    _act10 = Action('act10', m, 'ProcFDs', lambda: ((~fProcFDs)))

    _act11 = Action('act11', m, 'FDFlags', lambda: ((~fFDFlags)))

    _act12 = Action('act12', m, 'FDFile', lambda: ((~fFDFile)))

    _act13 = Action('act13', m, 'FDNumber', lambda: ((~fFDNumber)))

    _act14 = Action('act14', m, 'DACPermissions', lambda: ((~fDACPermissions)))

    _act15 = Action('act15', m, 'UserACL', lambda: ((~fUserACL)))

    _act16 = Action('act16', m, 'GroupObjACL', lambda: ((~fGroupObjACL)))

    _act17 = Action('act17', m, 'GroupACL', lambda: ((~fGroupACL)))

    _act18 = Action('act18', m, 'MaskACL', lambda: ((~fMaskACL)))

    _act19 = Action('act19', m, 'FileUser', lambda: ((~fFileUser)))

    _act20 = Action('act20', m, 'FileGroup', lambda: ((~fFileGroup)))

    _act21 = Action('act21', m, 'ProcUser', lambda: ((~fProcUser)))

    _act22 = Action('act22', m, 'ProcGroup', lambda: ((~fProcGroup)))

    _act23 = Action('act23', m, 'ProcUmask', lambda: ((~fProcUmask)))

    _act24 = Action('act24', m, 'FileXattrs', lambda: ((~fFileXattrs)))

    _act25 = Action('act25', m, 'ProcEXE', lambda: ((~fProcEXE)))

    _act26 = Action('act26', m, 'ProcArgv', lambda: ((~fProcArgv)))

    _act27 = Action('act27', m, 'ProcEnvp', lambda: ((~fProcEnvp)))

    _act28 = Action('act28', m, 'ProcCwd', lambda: ((~fProcCwd)))

    _act29 = Action('act29', m, 'ProcParent', lambda: ((~fProcParent)))

    _act30 = Action('act30', m, 'UserGroups', lambda: ((~fUserGroups)))

    _act31 = Action('act31', m, 'PathToRoot', lambda: ((~fPathToRoot)))

    _act32 = Action('act32', m, 'UserCaps', lambda: ((~fUserCaps)))


    return Event("any_transition", _grd1, _grd2, _grd3, _grd4, _grd5, _grd6, _grd7, _grd8, _grd9, _grd10, _grd11, _grd12, _grd13, _grd14, _grd15, _grd16, _grd17, _grd18, _grd19, _grd20, _grd21, _grd22, _grd23, _grd24, _grd25, _grd26, _grd27, _grd28, _grd29, _grd30, _grd31, _grd32, _grd33, _grd34, _grd35, _grd36, _grd37, _grd38, _grd39, _grd40, _grd41, _grd42, _grd43, _grd44, _grd45, _grd46, _grd47, _grd48, _grd49, _grd50, _grd51, _act1, _act2, _act3, _act4, _act5, _act6, _act7, _act8, _act9, _act10, _act11, _act12, _act13, _act14, _act15, _act16, _act17, _act18, _act19, _act20, _act21, _act22, _act23, _act24, _act25, _act26, _act27, _act28, _act29, _act30, _act31, _act32)
