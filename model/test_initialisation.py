from model.machine import Machine


# @act1: Users ≔ {ROOT_USER}
def test_act1(m: Machine):
    assert ((m.Users) == (frozenset((m.ROOT_USER,))))

# @act2: Groups ≔ {ROOT_GROUP}
def test_act2(m: Machine):
    assert ((m.Groups) == (frozenset((m.ROOT_GROUP,))))

# @act3: Procs ≔ {INIT}
def test_act3(m: Machine):
    assert ((m.Procs) == (frozenset((m.INIT,))))

# @act4: Files ≔ {ROOT, INIT_EXE}
def test_act4(m: Machine):
    assert ((m.Files) == (frozenset((m.ROOT, m.INIT_EXE))))

# @act5: Folders ≔ {ROOT}
def test_act5(m: Machine):
    assert ((m.Folders) == (frozenset((m.ROOT,))))

# @act6: SymLinks ≔ ∅
def test_act6(m: Machine):
    assert ((m.SymLinks) == (frozenset[Machine.FilesItem]()))

# @act7: FDs ≔ ∅
def test_act7(m: Machine):
    assert ((m.FDs) == (frozenset[Machine.FileDescriptorsExtendedItem]()))

# @act8: FileParents ≔ {INIT_EXE ↦ (ROOT ↦ INIT_NAME)}
def test_act8(m: Machine):
    assert ((m.FileParents) == (frozenset(((m.INIT_EXE, (m.ROOT, m.INIT_NAME)),))))

# @act9: FileLink ≔ ∅
def test_act9(m: Machine):
    assert ((m.FileLink) == (frozenset[tuple[Machine.FilesItem, tuple[Machine.FilesItem, Machine.StringsItem]]]()))

# @act10: ProcFDs ≔ ∅
def test_act10(m: Machine):
    assert ((m.ProcFDs) == (frozenset[tuple[Machine.ProcsItem, Machine.FileDescriptorsExtendedItem]]()))

# @act11: FDFlags ≔ ∅
def test_act11(m: Machine):
    assert ((m.FDFlags) == (frozenset[tuple[Machine.FileDescriptorsExtendedItem, frozenset[int]]]()))

# @act12: FDFile ≔ ∅
def test_act12(m: Machine):
    assert ((m.FDFile) == (frozenset[tuple[Machine.FileDescriptorsExtendedItem, Machine.FilesItem]]()))

# @act13: FDNumber ≔ ∅
def test_act13(m: Machine):
    assert ((m.FDNumber) == (frozenset[tuple[Machine.FileDescriptorsExtendedItem, int]]()))

# @act14: DACPermissions ≔ {ROOT ↦ DEF_FOLDER_PERMS, INIT_EXE ↦ DEF_FILE_PERMS}
def test_act14(m: Machine):
    assert ((m.DACPermissions) == (frozenset(((m.ROOT, m.DEF_FOLDER_PERMS), (m.INIT_EXE, m.DEF_FILE_PERMS)))))

# @act15: UserACL ≔ ∅
def test_act15(m: Machine):
    assert ((m.UserACL) == (frozenset[tuple[tuple[Machine.FilesItem, Machine.UsersItem], frozenset[Machine.PermissionsItem]]]()))

# @act16: GroupACL ≔ ∅
def test_act16(m: Machine):
    assert ((m.GroupACL) == (frozenset[tuple[tuple[Machine.FilesItem, Machine.GroupsItem], frozenset[Machine.PermissionsItem]]]()))

# @act17: GroupObjACL ≔ {ROOT ↦ DEF_FOLDER_PERMS ∩ GROUP_PERMISSIONS, INIT_EXE ↦ DEF_FILE_PERMS ∩ GROUP_PERMISSIONS}
def test_act17(m: Machine):
    assert ((m.GroupObjACL) == (frozenset(((m.ROOT, (m.DEF_FOLDER_PERMS & m.GROUP_PERMISSIONS)), (m.INIT_EXE, (m.DEF_FILE_PERMS & m.GROUP_PERMISSIONS))))))

# @act18: MaskACL ≔ ∅
def test_act18(m: Machine):
    assert ((m.MaskACL) == (frozenset[tuple[Machine.FilesItem, frozenset[Machine.PermissionsItem]]]()))

# @act19: FileUser ≔ {ROOT ↦ ROOT_USER, INIT_EXE ↦ ROOT_USER}
def test_act19(m: Machine):
    assert ((m.FileUser) == (frozenset(((m.ROOT, m.ROOT_USER), (m.INIT_EXE, m.ROOT_USER)))))

# @act20: FileGroup ≔ {ROOT ↦ ROOT_GROUP, INIT_EXE ↦ ROOT_GROUP}
def test_act20(m: Machine):
    assert ((m.FileGroup) == (frozenset(((m.ROOT, m.ROOT_GROUP), (m.INIT_EXE, m.ROOT_GROUP)))))

# @act21: ProcUser ≔ {INIT ↦ ROOT_USER}
def test_act21(m: Machine):
    assert ((m.ProcUser) == (frozenset(((m.INIT, m.ROOT_USER),))))

# @act22: ProcGroup ≔ {INIT ↦ ROOT_GROUP}
def test_act22(m: Machine):
    assert ((m.ProcGroup) == (frozenset(((m.INIT, m.ROOT_GROUP),))))

# @act23: ProcUmask ≔ {INIT ↦ ∅}
def test_act23(m: Machine):
    assert ((m.ProcUmask) == (frozenset(((m.INIT, frozenset[Machine.PermissionsItem]()),))))

# @act24: FileXattrs ≔ {ROOT ↦ ∅, INIT_EXE ↦ ∅}
def test_act24(m: Machine):
    assert ((m.FileXattrs) == (frozenset(((m.ROOT, frozenset[tuple[Machine.StringsItem, Machine.DataItem]]()), (m.INIT_EXE, frozenset[tuple[Machine.StringsItem, Machine.DataItem]]())))))

# @act25: ProcEXE ≔ {INIT ↦ INIT_EXE}
def test_act25(m: Machine):
    assert ((m.ProcEXE) == (frozenset(((m.INIT, m.INIT_EXE),))))

# @act26: ProcArgv ≔ {INIT ↦ ∅}
def test_act26(m: Machine):
    assert ((m.ProcArgv) == (frozenset(((m.INIT, frozenset[Machine.StringsItem]()),))))

# @act27: ProcEnvp ≔ {INIT ↦ ∅}
def test_act27(m: Machine):
    assert ((m.ProcEnvp) == (frozenset(((m.INIT, frozenset[Machine.StringsItem]()),))))

# @act28: ProcCwd ≔ {INIT ↦ ROOT}
def test_act28(m: Machine):
    assert ((m.ProcCwd) == (frozenset(((m.INIT, m.ROOT),))))

# @act29: ProcParent ≔ ∅
def test_act29(m: Machine):
    assert ((m.ProcParent) == (frozenset[tuple[Machine.ProcsItem, Machine.ProcsItem]]()))

# @act30: UserGroups ≔ {ROOT_USER ↦ ROOT_GROUP}
def test_act30(m: Machine):
    assert ((m.UserGroups) == (frozenset(((m.ROOT_USER, m.ROOT_GROUP),))))

# @act31: PathToRoot ≔ {ROOT ↦ ∅}
def test_act31(m: Machine):
    assert ((m.PathToRoot) == (frozenset(((m.ROOT, frozenset[Machine.FilesItem]()),))))

# @act32: UserCaps ≔ {ROOT_USER ↦ ∅}
def test_act32(m: Machine):
    assert ((m.UserCaps) == (frozenset(((m.ROOT_USER, frozenset[Machine.CapabilitiesItem]()),))))
