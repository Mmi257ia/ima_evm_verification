from model.machine import Machine
from anis.stages.invariants import assert_depends
from anis.model.expressions import NAT1, finite, partition


# @INIT_type: INIT ∈ PROCS
@assert_depends(lambda m: (m.INIT, m.PROCS,))
def test_INIT_type(m: Machine):
    assert (m.INIT in m.PROCS)

# @INIT_EXE_type: INIT_EXE ∈ FILES
@assert_depends(lambda m: (m.INIT_EXE, m.FILES,))
def test_INIT_EXE_type(m: Machine):
    assert (m.INIT_EXE in m.FILES)

# @INIT_NAME_type: INIT_NAME ∈ STRINGS
@assert_depends(lambda m: (m.INIT_NAME, m.STRINGS,))
def test_INIT_NAME_type(m: Machine):
    assert (m.INIT_NAME in m.STRINGS)

# @ROOT_type: ROOT ∈ FILES
@assert_depends(lambda m: (m.ROOT, m.FILES,))
def test_ROOT_type(m: Machine):
    assert (m.ROOT in m.FILES)

# @ROOT1: ROOT ≠ INIT_EXE
@assert_depends(lambda m: (m.ROOT, m.INIT_EXE,))
def test_ROOT1(m: Machine):
    assert (m.ROOT != m.INIT_EXE)

# @MAX_FILES_type: MAX_FILES ∈ ℕ1
@assert_depends(lambda m: (m.MAX_FILES,))
def test_MAX_FILES_type(m: Machine):
    assert (m.MAX_FILES in NAT1)

# @FILES_finite1: finite(FILES)
@assert_depends(lambda m: (m.FILES,))
def test_FILES_finite1(m: Machine):
    assert (finite(m.FILES))

# @FILES_finite2: card(FILES) ≤ MAX_FILES
@assert_depends(lambda m: (m.FILES, m.MAX_FILES,))
def test_FILES_finite2(m: Machine):
    assert (len(m.FILES) <= m.MAX_FILES)

# @PROC_FILE_LIMIT_type: PROC_FILE_LIMIT ∈ ℕ1
@assert_depends(lambda m: (m.PROC_FILE_LIMIT,))
def test_PROC_FILE_LIMIT_type(m: Machine):
    assert (m.PROC_FILE_LIMIT in NAT1)

# @FILE_DESCRIPTORS_EXTENDED_finite: finite(FILE_DESCRIPTORS_EXTENDED)
@assert_depends(lambda m: (m.FILE_DESCRIPTORS_EXTENDED,))
def test_FILE_DESCRIPTORS_EXTENDED_finite(m: Machine):
    assert (finite(m.FILE_DESCRIPTORS_EXTENDED))

# @FILE_LIMIT_type: FILE_LIMIT ∈ ℕ1
@assert_depends(lambda m: (m.FILE_LIMIT,))
def test_FILE_LIMIT_type(m: Machine):
    assert (m.FILE_LIMIT in NAT1)

# @PERMISSIONS_partition: partition(PERMISSIONS, USER_PERMISSIONS, GROUP_PERMISSIONS, OTHER_PERMISSIONS, FILE_MODES)
@assert_depends(lambda m: (m.PERMISSIONS, m.USER_PERMISSIONS, m.GROUP_PERMISSIONS, m.OTHER_PERMISSIONS, m.FILE_MODES,))
def test_PERMISSIONS_partition(m: Machine):
    assert (partition(m.PERMISSIONS, m.USER_PERMISSIONS, m.GROUP_PERMISSIONS, m.OTHER_PERMISSIONS, m.FILE_MODES))

# @USER_PERMISSIONS_partition: partition(USER_PERMISSIONS, {UREAD}, {UWRITE}, {UEXECUTE})
@assert_depends(lambda m: (m.USER_PERMISSIONS, m.UREAD, m.UWRITE, m.UEXECUTE,))
def test_USER_PERMISSIONS_partition(m: Machine):
    assert (partition(m.USER_PERMISSIONS, frozenset((m.UREAD,)), frozenset((m.UWRITE,)), frozenset((m.UEXECUTE,))))

# @GROUP_PERMISSIONS_partition: partition(GROUP_PERMISSIONS, {GREAD}, {GWRITE}, {GEXECUTE})
@assert_depends(lambda m: (m.GROUP_PERMISSIONS, m.GREAD, m.GWRITE, m.GEXECUTE,))
def test_GROUP_PERMISSIONS_partition(m: Machine):
    assert (partition(m.GROUP_PERMISSIONS, frozenset((m.GREAD,)), frozenset((m.GWRITE,)), frozenset((m.GEXECUTE,))))

# @OTHER_PERMISSIONS_partition: partition(OTHER_PERMISSIONS, {OREAD}, {OWRITE}, {OEXECUTE})
@assert_depends(lambda m: (m.OTHER_PERMISSIONS, m.OREAD, m.OWRITE, m.OEXECUTE,))
def test_OTHER_PERMISSIONS_partition(m: Machine):
    assert (partition(m.OTHER_PERMISSIONS, frozenset((m.OREAD,)), frozenset((m.OWRITE,)), frozenset((m.OEXECUTE,))))

# @FILE_MODES_partition: partition(FILE_MODES, {SET_UID}, {SET_GID}, {STICKY_BIT})
@assert_depends(lambda m: (m.FILE_MODES, m.SET_UID, m.SET_GID, m.STICKY_BIT,))
def test_FILE_MODES_partition(m: Machine):
    assert (partition(m.FILE_MODES, frozenset((m.SET_UID,)), frozenset((m.SET_GID,)), frozenset((m.STICKY_BIT,))))

# @DEF_FILE_PERMS_type: DEF_FILE_PERMS = {UREAD, UWRITE, GREAD, OREAD}
@assert_depends(lambda m: (m.DEF_FILE_PERMS, m.UREAD, m.UWRITE, m.GREAD, m.OREAD,))
def test_DEF_FILE_PERMS_type(m: Machine):
    assert (m.DEF_FILE_PERMS == frozenset((m.UREAD, m.UWRITE, m.GREAD, m.OREAD)))

# @DEF_FOLDER_PERMS_type: DEF_FOLDER_PERMS = {UREAD, UWRITE, UEXECUTE, GREAD, GEXECUTE, OREAD, OEXECUTE}
@assert_depends(lambda m: (m.DEF_FOLDER_PERMS, m.UREAD, m.UWRITE, m.UEXECUTE, m.GREAD, m.GEXECUTE, m.OREAD, m.OEXECUTE,))
def test_DEF_FOLDER_PERMS_type(m: Machine):
    assert (m.DEF_FOLDER_PERMS == frozenset((m.UREAD, m.UWRITE, m.UEXECUTE, m.GREAD, m.GEXECUTE, m.OREAD, m.OEXECUTE)))

# @DEF_SYMLINK_PERMS_type: DEF_SYMLINK_PERMS = {UREAD, UWRITE, UEXECUTE, GREAD, GWRITE, GEXECUTE, OREAD, OWRITE, OEXECUTE}
@assert_depends(lambda m: (m.DEF_SYMLINK_PERMS, m.UREAD, m.UWRITE, m.UEXECUTE, m.GREAD, m.GWRITE, m.GEXECUTE, m.OREAD, m.OWRITE, m.OEXECUTE,))
def test_DEF_SYMLINK_PERMS_type(m: Machine):
    assert (m.DEF_SYMLINK_PERMS == frozenset((m.UREAD, m.UWRITE, m.UEXECUTE, m.GREAD, m.GWRITE, m.GEXECUTE, m.OREAD, m.OWRITE, m.OEXECUTE)))

# @ROOT_USER_type: ROOT_USER ∈ USERS
@assert_depends(lambda m: (m.ROOT_USER, m.USERS,))
def test_ROOT_USER_type(m: Machine):
    assert (m.ROOT_USER in m.USERS)

# @ROOT_GROUP_type: ROOT_GROUP ∈ GROUPS
@assert_depends(lambda m: (m.ROOT_GROUP, m.GROUPS,))
def test_ROOT_GROUP_type(m: Machine):
    assert (m.ROOT_GROUP in m.GROUPS)

# @FILE_DESCRIPTORS_type: partition(FILE_DESCRIPTORS_EXTENDED, FILE_DESCRIPTORS, {AT_FDCWD})
@assert_depends(lambda m: (m.FILE_DESCRIPTORS_EXTENDED, m.FILE_DESCRIPTORS, m.AT_FDCWD,))
def test_FILE_DESCRIPTORS_type(m: Machine):
    assert (partition(m.FILE_DESCRIPTORS_EXTENDED, m.FILE_DESCRIPTORS, frozenset((m.AT_FDCWD,))))

# @INTEGRITY_MODES_partition: partition(INTEGRITY_MODES, {ENFORCE}, {FIX}, {OFF})
@assert_depends(lambda m: (m.INTEGRITY_MODES, m.ENFORCE, m.FIX, m.OFF,))
def test_INTEGRITY_MODES_partition(m: Machine):
    assert (partition(m.INTEGRITY_MODES, frozenset((m.ENFORCE,)), frozenset((m.FIX,)), frozenset((m.OFF,))))

# @IMA_STRING_type: IMA_STRING ∈ STRINGS
@assert_depends(lambda m: (m.IMA_STRING, m.STRINGS,))
def test_IMA_STRING_type(m: Machine):
    assert (m.IMA_STRING in m.STRINGS)

# @EVM_STRING_type: EVM_STRING ∈ STRINGS
@assert_depends(lambda m: (m.EVM_STRING, m.STRINGS,))
def test_EVM_STRING_type(m: Machine):
    assert (m.EVM_STRING in m.STRINGS)

# @ROOT_CONTENT_HASH_type: ROOT_CONTENT_HASH ∈ HASHES
@assert_depends(lambda m: (m.ROOT_CONTENT_HASH, m.HASHES,))
def test_ROOT_CONTENT_HASH_type(m: Machine):
    assert (m.ROOT_CONTENT_HASH in m.HASHES)

# @ROOT_META_HASH_type: ROOT_META_HASH ∈ HASHES
@assert_depends(lambda m: (m.ROOT_META_HASH, m.HASHES,))
def test_ROOT_META_HASH_type(m: Machine):
    assert (m.ROOT_META_HASH in m.HASHES)

# @INIT_EXE_CONTENT_HASH_type: INIT_EXE_CONTENT_HASH ∈ HASHES
@assert_depends(lambda m: (m.INIT_EXE_CONTENT_HASH, m.HASHES,))
def test_INIT_EXE_CONTENT_HASH_type(m: Machine):
    assert (m.INIT_EXE_CONTENT_HASH in m.HASHES)

# @INIT_EXE_META_HASH_type: INIT_EXE_META_HASH ∈ HASHES
@assert_depends(lambda m: (m.INIT_EXE_META_HASH, m.HASHES,))
def test_INIT_EXE_META_HASH_type(m: Machine):
    assert (m.INIT_EXE_META_HASH in m.HASHES)

# @axm1: MAX_FILES = 1048576
@assert_depends(lambda m: (m.MAX_FILES,))
def test_axm1(m: Machine):
    assert (m.MAX_FILES == 1048576)

# @axm2: FILE_LIMIT = 1024
@assert_depends(lambda m: (m.FILE_LIMIT,))
def test_axm2(m: Machine):
    assert (m.FILE_LIMIT == 1024)

# @axm3: PROC_FILE_LIMIT = 1024
@assert_depends(lambda m: (m.PROC_FILE_LIMIT,))
def test_axm3(m: Machine):
    assert (m.PROC_FILE_LIMIT == 1024)

# @axm4: finite(FILE_DESCRIPTORS) ∧ card(FILE_DESCRIPTORS) ≤ 1024
@assert_depends(lambda m: (m.FILE_DESCRIPTORS,))
def test_axm4(m: Machine):
    assert (finite(m.FILE_DESCRIPTORS) and len(m.FILE_DESCRIPTORS) <= 1024)

# @S_IRUSR_type: S_IRUSR = UREAD
@assert_depends(lambda m: (m.S_IRUSR, m.UREAD,))
def test_S_IRUSR_type(m: Machine):
    assert (m.S_IRUSR == m.UREAD)

# @S_IWUSR_type: S_IWUSR = UWRITE
@assert_depends(lambda m: (m.S_IWUSR, m.UWRITE,))
def test_S_IWUSR_type(m: Machine):
    assert (m.S_IWUSR == m.UWRITE)

# @S_IXUSR_type: S_IXUSR = UEXECUTE
@assert_depends(lambda m: (m.S_IXUSR, m.UEXECUTE,))
def test_S_IXUSR_type(m: Machine):
    assert (m.S_IXUSR == m.UEXECUTE)

# @S_IRGRP_type: S_IRGRP = GREAD
@assert_depends(lambda m: (m.S_IRGRP, m.GREAD,))
def test_S_IRGRP_type(m: Machine):
    assert (m.S_IRGRP == m.GREAD)

# @S_IWGRP_type: S_IWGRP = GWRITE
@assert_depends(lambda m: (m.S_IWGRP, m.GWRITE,))
def test_S_IWGRP_type(m: Machine):
    assert (m.S_IWGRP == m.GWRITE)

# @S_IXGRP_type: S_IXGRP = GEXECUTE
@assert_depends(lambda m: (m.S_IXGRP, m.GEXECUTE,))
def test_S_IXGRP_type(m: Machine):
    assert (m.S_IXGRP == m.GEXECUTE)

# @S_IROTH_type: S_IROTH = OREAD
@assert_depends(lambda m: (m.S_IROTH, m.OREAD,))
def test_S_IROTH_type(m: Machine):
    assert (m.S_IROTH == m.OREAD)

# @S_IWOTH_type: S_IWOTH = OWRITE
@assert_depends(lambda m: (m.S_IWOTH, m.OWRITE,))
def test_S_IWOTH_type(m: Machine):
    assert (m.S_IWOTH == m.OWRITE)

# @S_IXOTH_type: S_IXOTH = OEXECUTE
@assert_depends(lambda m: (m.S_IXOTH, m.OEXECUTE,))
def test_S_IXOTH_type(m: Machine):
    assert (m.S_IXOTH == m.OEXECUTE)

# @S_ISUID_type: S_ISUID = SET_UID
@assert_depends(lambda m: (m.S_ISUID, m.SET_UID,))
def test_S_ISUID_type(m: Machine):
    assert (m.S_ISUID == m.SET_UID)

# @S_ISGID_type: S_ISGID = SET_GID
@assert_depends(lambda m: (m.S_ISGID, m.SET_GID,))
def test_S_ISGID_type(m: Machine):
    assert (m.S_ISGID == m.SET_GID)

# @S_ISVTX_type: S_ISVTX = STICKY_BIT
@assert_depends(lambda m: (m.S_ISVTX, m.STICKY_BIT,))
def test_S_ISVTX_type(m: Machine):
    assert (m.S_ISVTX == m.STICKY_BIT)

# @O_RDONLY_type: O_RDONLY = 1
@assert_depends(lambda m: (m.O_RDONLY,))
def test_O_RDONLY_type(m: Machine):
    assert (m.O_RDONLY == 1)

# @O_WRONLY_type: O_WRONLY = 2
@assert_depends(lambda m: (m.O_WRONLY,))
def test_O_WRONLY_type(m: Machine):
    assert (m.O_WRONLY == 2)

# @O_RDWR_type: O_RDWR = 3
@assert_depends(lambda m: (m.O_RDWR,))
def test_O_RDWR_type(m: Machine):
    assert (m.O_RDWR == 3)

# @O_CREAT_type: O_CREAT = 4
@assert_depends(lambda m: (m.O_CREAT,))
def test_O_CREAT_type(m: Machine):
    assert (m.O_CREAT == 4)

# @O_EXCL_type: O_EXCL = 5
@assert_depends(lambda m: (m.O_EXCL,))
def test_O_EXCL_type(m: Machine):
    assert (m.O_EXCL == 5)

# @O_DIRECT_type: O_DIRECT = 6
@assert_depends(lambda m: (m.O_DIRECT,))
def test_O_DIRECT_type(m: Machine):
    assert (m.O_DIRECT == 6)

# @O_TMPFILE_type: O_TMPFILE = 7
@assert_depends(lambda m: (m.O_TMPFILE,))
def test_O_TMPFILE_type(m: Machine):
    assert (m.O_TMPFILE == 7)

# @O_DIRECTORY_type: O_DIRECTORY = 8
@assert_depends(lambda m: (m.O_DIRECTORY,))
def test_O_DIRECTORY_type(m: Machine):
    assert (m.O_DIRECTORY == 8)

# @O_CLOEXEC_type: O_CLOEXEC = 9
@assert_depends(lambda m: (m.O_CLOEXEC,))
def test_O_CLOEXEC_type(m: Machine):
    assert (m.O_CLOEXEC == 9)

# @O_NOCTTY_type: O_NOCTTY = 10
@assert_depends(lambda m: (m.O_NOCTTY,))
def test_O_NOCTTY_type(m: Machine):
    assert (m.O_NOCTTY == 10)

# @O_NOFOLLOW_type: O_NOFOLLOW = 11
@assert_depends(lambda m: (m.O_NOFOLLOW,))
def test_O_NOFOLLOW_type(m: Machine):
    assert (m.O_NOFOLLOW == 11)

# @O_TRUNC_type: O_TRUNC = 12
@assert_depends(lambda m: (m.O_TRUNC,))
def test_O_TRUNC_type(m: Machine):
    assert (m.O_TRUNC == 12)

# @O_APPEND_type: O_APPEND = 13
@assert_depends(lambda m: (m.O_APPEND,))
def test_O_APPEND_type(m: Machine):
    assert (m.O_APPEND == 13)

# @O_ASYNC_type: O_ASYNC = 14
@assert_depends(lambda m: (m.O_ASYNC,))
def test_O_ASYNC_type(m: Machine):
    assert (m.O_ASYNC == 14)

# @O_SYNC_type: O_SYNC = 15
@assert_depends(lambda m: (m.O_SYNC,))
def test_O_SYNC_type(m: Machine):
    assert (m.O_SYNC == 15)

# @O_DSYNC_type: O_DSYNC = 16
@assert_depends(lambda m: (m.O_DSYNC,))
def test_O_DSYNC_type(m: Machine):
    assert (m.O_DSYNC == 16)

# @O_NOATIME_type: O_NOATIME = 17
@assert_depends(lambda m: (m.O_NOATIME,))
def test_O_NOATIME_type(m: Machine):
    assert (m.O_NOATIME == 17)

# @O_LARGEFILE_type: O_LARGEFILE = 18
@assert_depends(lambda m: (m.O_LARGEFILE,))
def test_O_LARGEFILE_type(m: Machine):
    assert (m.O_LARGEFILE == 18)

# @O_PATH_type: O_PATH = 19
@assert_depends(lambda m: (m.O_PATH,))
def test_O_PATH_type(m: Machine):
    assert (m.O_PATH == 19)

# @O_NOBLOCK_type: O_NOBLOCK = 20
@assert_depends(lambda m: (m.O_NOBLOCK,))
def test_O_NOBLOCK_type(m: Machine):
    assert (m.O_NOBLOCK == 20)

# @O_NDELAY_type: O_NDELAY = 21
@assert_depends(lambda m: (m.O_NDELAY,))
def test_O_NDELAY_type(m: Machine):
    assert (m.O_NDELAY == 21)

# @OPEN_FLAGS_type: OPEN_FLAGS = {
#             O_RDONLY, O_WRONLY, O_RDWR,
#             O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL, O_NOCTTY,
#             O_NOFOLLOW, O_TMPFILE, O_TRUNC,
#             O_APPEND, O_ASYNC, O_DIRECT, O_DSYNC, O_LARGEFILE,
#             O_NOATIME, O_NOBLOCK, O_NDELAY, O_PATH, O_SYNC
#         }
@assert_depends(lambda m: (m.OPEN_FLAGS, m.O_RDONLY, m.O_WRONLY, m.O_RDWR, m.O_CLOEXEC, m.O_CREAT, m.O_DIRECTORY, m.O_EXCL, m.O_NOCTTY, m.O_NOFOLLOW, m.O_TMPFILE, m.O_TRUNC, m.O_APPEND, m.O_ASYNC, m.O_DIRECT, m.O_DSYNC, m.O_LARGEFILE, m.O_NOATIME, m.O_NOBLOCK, m.O_NDELAY, m.O_PATH, m.O_SYNC,))
def test_OPEN_FLAGS_type(m: Machine):
    assert (m.OPEN_FLAGS == frozenset((
    m.O_RDONLY, m.O_WRONLY, m.O_RDWR, 
    m.O_CLOEXEC, m.O_CREAT, m.O_DIRECTORY, m.O_EXCL, m.O_NOCTTY, 
    m.O_NOFOLLOW, m.O_TMPFILE, m.O_TRUNC, 
    m.O_APPEND, m.O_ASYNC, m.O_DIRECT, m.O_DSYNC, m.O_LARGEFILE, 
    m.O_NOATIME, m.O_NOBLOCK, m.O_NDELAY, m.O_PATH, m.O_SYNC)))

# @XATTR_FLAGS_partition: partition(XATTR_FLAGS, {XATTR_CREATE}, {XATTR_REPLACE})
@assert_depends(lambda m: (m.XATTR_FLAGS, m.XATTR_CREATE, m.XATTR_REPLACE,))
def test_XATTR_FLAGS_partition(m: Machine):
    assert (partition(m.XATTR_FLAGS, frozenset((m.XATTR_CREATE,)), frozenset((m.XATTR_REPLACE,))))
