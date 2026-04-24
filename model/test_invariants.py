from model.machine import Machine
from anis.stages.invariants import assert_depends
from anis.model.expressions import total_relations, cartesian_product, total_functions, relations, powerset, NAT, partial_functions, function_value, relation_domain, relation_image, relation_range


# @Users_type: Users ⊆ USERS
@assert_depends(lambda m: (m.Users, m.USERS,))
def test_Users_type(m: Machine):
    assert (m.Users <= m.USERS)

# @Groups_type: Groups ⊆ GROUPS
@assert_depends(lambda m: (m.Groups, m.GROUPS,))
def test_Groups_type(m: Machine):
    assert (m.Groups <= m.GROUPS)

# @Procs_type: Procs ⊆ PROCS
@assert_depends(lambda m: (m.Procs, m.PROCS,))
def test_Procs_type(m: Machine):
    assert (m.Procs <= m.PROCS)

# @Files_type: Files ⊆ FILES
@assert_depends(lambda m: (m.Files, m.FILES,))
def test_Files_type(m: Machine):
    assert (m.Files <= m.FILES)

# @Folders_type: Folders ⊆ Files
@assert_depends(lambda m: (m.Folders, m.Files,))
def test_Folders_type(m: Machine):
    assert (m.Folders <= m.Files)

# @SymLinks_type: SymLinks ⊆ Files
@assert_depends(lambda m: (m.SymLinks, m.Files,))
def test_SymLinks_type(m: Machine):
    assert (m.SymLinks <= m.Files)

# @FDs_type: FDs ⊆ FILE_DESCRIPTORS
@assert_depends(lambda m: (m.FDs, m.FILE_DESCRIPTORS,))
def test_FDs_type(m: Machine):
    assert (m.FDs <= m.FILE_DESCRIPTORS)

# @INIT_type: INIT ∈ Procs
@assert_depends(lambda m: (m.INIT, m.Procs,))
def test_INIT_type(m: Machine):
    assert (m.INIT in m.Procs)

# @ROOT_type: ROOT ∈ Folders
@assert_depends(lambda m: (m.ROOT, m.Folders,))
def test_ROOT_type(m: Machine):
    assert (m.ROOT in m.Folders)

# @ROOT_USER_type: ROOT_USER ∈ Users
@assert_depends(lambda m: (m.ROOT_USER, m.Users,))
def test_ROOT_USER_type(m: Machine):
    assert (m.ROOT_USER in m.Users)

# @FileParents_type: FileParents ∈ (Files ∖ {ROOT})  (Folders × STRINGS)
@assert_depends(lambda m: (m.FileParents, m.Files, m.ROOT, m.Folders, m.STRINGS,))
def test_FileParents_type(m: Machine):
    assert (m.FileParents in total_relations((m.Files - frozenset((m.ROOT,))), cartesian_product(m.Folders, m.STRINGS)))

# @FileLink_type: FileLink ∈ SymLinks → FILES × STRINGS
@assert_depends(lambda m: (m.FileLink, m.SymLinks, m.FILES, m.STRINGS,))
def test_FileLink_type(m: Machine):
    assert (m.FileLink in total_functions(m.SymLinks, cartesian_product(m.FILES, m.STRINGS)))

# @ProcFDs_type: ProcFDs ∈ Procs ↔ FDs
@assert_depends(lambda m: (m.ProcFDs, m.Procs, m.FDs,))
def test_ProcFDs_type(m: Machine):
    assert (m.ProcFDs in relations(m.Procs, m.FDs))

# @FDFlags_type: FDFlags ∈ FDs → ℙ(OPEN_FLAGS)
@assert_depends(lambda m: (m.FDFlags, m.FDs, m.OPEN_FLAGS,))
def test_FDFlags_type(m: Machine):
    assert (m.FDFlags in total_functions(m.FDs, powerset(m.OPEN_FLAGS)))

# @FDFile_type: FDFile ∈ FDs → FILES
@assert_depends(lambda m: (m.FDFile, m.FDs, m.FILES,))
def test_FDFile_type(m: Machine):
    assert (m.FDFile in total_functions(m.FDs, m.FILES))

# @FDNumber_type: FDNumber ∈ FDs → ℕ
@assert_depends(lambda m: (m.FDNumber, m.FDs,))
def test_FDNumber_type(m: Machine):
    assert (m.FDNumber in total_functions(m.FDs, NAT))

# @DACPermissions_type: DACPermissions ∈ Files → ℙ(PERMISSIONS)
@assert_depends(lambda m: (m.DACPermissions, m.Files, m.PERMISSIONS,))
def test_DACPermissions_type(m: Machine):
    assert (m.DACPermissions in total_functions(m.Files, powerset(m.PERMISSIONS)))

# @UserACL_type: UserACL ∈ (Files × Users) ⇸ ℙ(USER_PERMISSIONS)
@assert_depends(lambda m: (m.UserACL, m.Files, m.Users, m.USER_PERMISSIONS,))
def test_UserACL_type(m: Machine):
    assert (m.UserACL in partial_functions(cartesian_product(m.Files, m.Users), powerset(m.USER_PERMISSIONS)))

# @GroupObjACL: GroupObjACL ∈ Files ⇸ ℙ(GROUP_PERMISSIONS)
@assert_depends(lambda m: (m.GroupObjACL, m.Files, m.GROUP_PERMISSIONS,))
def test_GroupObjACL(m: Machine):
    assert (m.GroupObjACL in partial_functions(m.Files, powerset(m.GROUP_PERMISSIONS)))

# @GroupACL_type: GroupACL ∈ (Files × Groups) ⇸ ℙ(GROUP_PERMISSIONS)
@assert_depends(lambda m: (m.GroupACL, m.Files, m.Groups, m.GROUP_PERMISSIONS,))
def test_GroupACL_type(m: Machine):
    assert (m.GroupACL in partial_functions(cartesian_product(m.Files, m.Groups), powerset(m.GROUP_PERMISSIONS)))

# @MaskACL_type: MaskACL ∈ Files ⇸ ℙ(GROUP_PERMISSIONS)
@assert_depends(lambda m: (m.MaskACL, m.Files, m.GROUP_PERMISSIONS,))
def test_MaskACL_type(m: Machine):
    assert (m.MaskACL in partial_functions(m.Files, powerset(m.GROUP_PERMISSIONS)))

# @FileUser_type: FileUser ∈ Files → Users
@assert_depends(lambda m: (m.FileUser, m.Files, m.Users,))
def test_FileUser_type(m: Machine):
    assert (m.FileUser in total_functions(m.Files, m.Users))

# @FileGroup_type: FileGroup ∈ Files → Groups
@assert_depends(lambda m: (m.FileGroup, m.Files, m.Groups,))
def test_FileGroup_type(m: Machine):
    assert (m.FileGroup in total_functions(m.Files, m.Groups))

# @ProcUser_type: ProcUser ∈ Procs → Users
@assert_depends(lambda m: (m.ProcUser, m.Procs, m.Users,))
def test_ProcUser_type(m: Machine):
    assert (m.ProcUser in total_functions(m.Procs, m.Users))

# @ProcGroup_type: ProcGroup ∈ Procs → Groups
@assert_depends(lambda m: (m.ProcGroup, m.Procs, m.Groups,))
def test_ProcGroup_type(m: Machine):
    assert (m.ProcGroup in total_functions(m.Procs, m.Groups))

# @ProcUmask_type: ProcUmask ∈ Procs → ℙ(PERMISSIONS ∖ FILE_MODES)
@assert_depends(lambda m: (m.ProcUmask, m.Procs, m.PERMISSIONS, m.FILE_MODES,))
def test_ProcUmask_type(m: Machine):
    assert (m.ProcUmask in total_functions(m.Procs, powerset((m.PERMISSIONS - m.FILE_MODES))))

# @FileXattrs_type: FileXattrs ∈ Files → (STRINGS ⇸ DATA)
@assert_depends(lambda m: (m.FileXattrs, m.Files, m.STRINGS, m.DATA,))
def test_FileXattrs_type(m: Machine):
    assert (m.FileXattrs in total_functions(m.Files, partial_functions(m.STRINGS, m.DATA)))

# @ProcEXE_type: ProcEXE ∈ Procs → FILES
@assert_depends(lambda m: (m.ProcEXE, m.Procs, m.FILES,))
def test_ProcEXE_type(m: Machine):
    assert (m.ProcEXE in total_functions(m.Procs, m.FILES))

# @ProcArgv_type: ProcArgv ∈ Procs → ℙ(STRINGS)
@assert_depends(lambda m: (m.ProcArgv, m.Procs, m.STRINGS,))
def test_ProcArgv_type(m: Machine):
    assert (m.ProcArgv in total_functions(m.Procs, powerset(m.STRINGS)))

# @ProcEnvp_type: ProcEnvp ∈ Procs → ℙ(STRINGS)
@assert_depends(lambda m: (m.ProcEnvp, m.Procs, m.STRINGS,))
def test_ProcEnvp_type(m: Machine):
    assert (m.ProcEnvp in total_functions(m.Procs, powerset(m.STRINGS)))

# @ProcCwd_type: ProcCwd ∈ Procs → FILES
@assert_depends(lambda m: (m.ProcCwd, m.Procs, m.FILES,))
def test_ProcCwd_type(m: Machine):
    assert (m.ProcCwd in total_functions(m.Procs, m.FILES))

# @ProcParent_type: ProcParent ∈ Procs ∖ {INIT} → Procs
@assert_depends(lambda m: (m.ProcParent, m.Procs, m.INIT,))
def test_ProcParent_type(m: Machine):
    assert (m.ProcParent in total_functions((m.Procs - frozenset((m.INIT,))), m.Procs))

# @UserGroups: UserGroups ∈ Users ↔ Groups
@assert_depends(lambda m: (m.UserGroups, m.Users, m.Groups,))
def test_UserGroups(m: Machine):
    assert (m.UserGroups in relations(m.Users, m.Groups))

# @PathToRoot_type: PathToRoot ∈ Folders → ℙ(Folders)
@assert_depends(lambda m: (m.PathToRoot, m.Folders,))
def test_PathToRoot_type(m: Machine):
    assert (m.PathToRoot in total_functions(m.Folders, powerset(m.Folders)))

# @UserCaps_type: UserCaps ∈ Users → ℙ(CAPABILITIES)
@assert_depends(lambda m: (m.UserCaps, m.Users, m.CAPABILITIES,))
def test_UserCaps_type(m: Machine):
    assert (m.UserCaps in total_functions(m.Users, powerset(m.CAPABILITIES)))

# @PathToRoot1: PathToRoot(ROOT) = ∅
@assert_depends(lambda m: (m.PathToRoot, m.ROOT,))
def test_PathToRoot1(m: Machine):
    assert (len(function_value(m.PathToRoot, m.ROOT)) == 0)

# @PathToRoot2: ∀f, p · f ∈ Folders ∧ p ∈ dom(FileParents[{f}]) ⇒ PathToRoot(f) = PathToRoot(p) ∪ {p}
@assert_depends(lambda m: (m.Folders, m.FileParents, m.PathToRoot,))
def test_PathToRoot2(m: Machine):
    assert (not any (True for f in m.Folders for p in relation_domain(relation_image(m.FileParents, frozenset((f,)))) if not (
        function_value(m.PathToRoot, f) == (function_value(m.PathToRoot, p) | frozenset((p,)))
    )))

# @PathToRoot3: ∀f, p · f ∈ Folders ∧ p ∈ PathToRoot(f) ⇒ PathToRoot(p) ⊆ PathToRoot(f)
@assert_depends(lambda m: (m.Folders, m.PathToRoot,))
def test_PathToRoot3(m: Machine):
    assert (not any (True for f in m.Folders for p in function_value(m.PathToRoot, f) if not (
        function_value(m.PathToRoot, p) <= function_value(m.PathToRoot, f)
    )))

# @PathToRoot4: ∀f, p · f ∈ Folders ∧ p ∈ PathToRoot(f) ⇒ (∃c · (c ∈ PathToRoot(f) ∪ {f}) ∧ p ∈ dom(FileParents[{c}]))
@assert_depends(lambda m: (m.Folders, m.PathToRoot, m.FileParents,))
def test_PathToRoot4(m: Machine):
    assert (not any (True for f in m.Folders for p in function_value(m.PathToRoot, f) if not (
        any (True for c in (function_value(m.PathToRoot, f) | frozenset((f,))) if p in relation_domain(relation_image(m.FileParents, frozenset((c,)))))
    )))

# @Files1: card(Files) ≤ MAX_FILES
@assert_depends(lambda m: (m.Files, m.MAX_FILES,))
def test_Files1(m: Machine):
    assert (len(m.Files) <= m.MAX_FILES)

# @SymLinks1: SymLinks ∩ Folders = ∅
@assert_depends(lambda m: (m.SymLinks, m.Folders,))
def test_SymLinks1(m: Machine):
    assert (len((m.SymLinks & m.Folders)) == 0)

# @ProcEXE1: ∀p · p ∈ Procs ⇒ ProcEXE(p) ∉ Folders
@assert_depends(lambda m: (m.Procs, m.ProcEXE, m.Folders,))
def test_ProcEXE1(m: Machine):
    assert (not any (True for p in m.Procs if not (
        function_value(m.ProcEXE, p) not in m.Folders
    )))

# @ProcFDs1: ∀p · p ∈ Procs ⇒ card(ProcFDs[{p}]) ≤ PROC_FILE_LIMIT
@assert_depends(lambda m: (m.Procs, m.ProcFDs, m.PROC_FILE_LIMIT,))
def test_ProcFDs1(m: Machine):
    assert (not any (True for p in m.Procs if not (
        len(relation_image(m.ProcFDs, frozenset((p,)))) <= m.PROC_FILE_LIMIT
    )))

# @ProcFDs2: card(ran(ProcFDs)) ≤ FILE_LIMIT
@assert_depends(lambda m: (m.ProcFDs, m.FILE_LIMIT,))
def test_ProcFDs2(m: Machine):
    assert (len(relation_range(m.ProcFDs)) <= m.FILE_LIMIT)

# @ProcFDs3: ∀p, fd · p ∈ Procs ∧ p ↦ fd ∈ ProcFDs ∧ FDFile(fd) ∈ Folders ∧ O_PATH ∉ FDFlags(fd)
#             ⇒ O_WRONLY ∉ FDFlags(fd) ∧ O_RDWR ∉ FDFlags(fd)
@assert_depends(lambda m: (m.Procs, m.ProcFDs, m.FDFile, m.Folders, m.O_PATH, m.FDFlags, m.O_WRONLY, m.O_RDWR,))
def test_ProcFDs3(m: Machine):
    assert (not any (True for p in m.Procs for (key, fd) in m.ProcFDs if key == p if function_value(m.FDFile, fd) in m.Folders if m.O_PATH not in function_value(m.FDFlags, fd) if not (
        m.O_WRONLY not in function_value(m.FDFlags, fd) and m.O_RDWR not in function_value(m.FDFlags, fd)
    )))

# @FileParents1: ∀f · f ∈ Folders ∖ {ROOT} ⇒ (∃p, n · (p ↦ n) ∈ FileParents[{f}] ∧ {p ↦ n} = FileParents[{f}])
@assert_depends(lambda m: (m.Folders, m.ROOT, m.FileParents,))
def test_FileParents1(m: Machine):
    assert (not any (True for f in (m.Folders - frozenset((m.ROOT,))) if not (
        any (True for (p, n) in relation_image(m.FileParents, frozenset((f,))) if frozenset(((p, n),)) == relation_image(m.FileParents, frozenset((f,))))
    )))

# @ACL1: ∀f, u · f ↦ u ∈ dom(UserACL) ⇒ f ∈ dom(MaskACL)
@assert_depends(lambda m: (m.UserACL, m.MaskACL,))
def test_ACL1(m: Machine):
    assert (not any (True for (f, u) in relation_domain(m.UserACL) if not (
        f in relation_domain(m.MaskACL)
    )))

# @ACL2: ∀f, g · f ↦ g ∈ dom(GroupACL) ⇒ f ∈ dom(MaskACL)
@assert_depends(lambda m: (m.GroupACL, m.MaskACL,))
def test_ACL2(m: Machine):
    assert (not any (True for (f, g) in relation_domain(m.GroupACL) if not (
        f in relation_domain(m.MaskACL)
    )))

# @ACL3: ∀f · f ∈ dom(MaskACL) ⇒ MaskACL(f) = DACPermissions(f) ∩ GROUP_PERMISSIONS
@assert_depends(lambda m: (m.MaskACL, m.DACPermissions, m.GROUP_PERMISSIONS,))
def test_ACL3(m: Machine):
    assert (not any (True for f in relation_domain(m.MaskACL) if not (
        function_value(m.MaskACL, f) == (function_value(m.DACPermissions, f) & m.GROUP_PERMISSIONS)
    )))

# @ACL4: ∀f · f ∈ Files ∧ f ∉ dom(MaskACL) ⇒ f ∈ dom(GroupObjACL) ∧ GroupObjACL(f) = DACPermissions(f) ∩ GROUP_PERMISSIONS
@assert_depends(lambda m: (m.Files, m.MaskACL, m.GroupObjACL, m.DACPermissions, m.GROUP_PERMISSIONS,))
def test_ACL4(m: Machine):
    assert (not any (True for f in m.Files if f not in relation_domain(m.MaskACL) if not (
        f in relation_domain(m.GroupObjACL) and function_value(m.GroupObjACL, f) == (function_value(m.DACPermissions, f) & m.GROUP_PERMISSIONS)
    )))

# @ProcCwd1: ∀p · p ∈ Procs ∧ ProcCwd(p) ∈ Files ⇒ ProcCwd(p) ∈ Folders
@assert_depends(lambda m: (m.Procs, m.ProcCwd, m.Files, m.Folders,))
def test_ProcCwd1(m: Machine):
    assert (not any (True for p in m.Procs if function_value(m.ProcCwd, p) in m.Files if not (
        function_value(m.ProcCwd, p) in m.Folders
    )))
