from anis.model.expressions import CarrierSetItem, carrier_set
from collections.abc import Set


class Machine:
    class FilesItem(CarrierSetItem): pass
    class ProcsItem(CarrierSetItem): pass
    class UsersItem(CarrierSetItem): pass
    class GroupsItem(CarrierSetItem): pass
    class FileDescriptorsExtendedItem(CarrierSetItem): pass
    class PermissionsItem(CarrierSetItem): pass
    class StringsItem(CarrierSetItem): pass
    class DataItem(CarrierSetItem): pass
    class CapabilitiesItem(CarrierSetItem): pass
    class IntegrityModesItem(CarrierSetItem): pass
    class HashesItem(CarrierSetItem): pass
    class XattrFlagsItem(CarrierSetItem): pass

    class CarrierSets:
        def __init__(self, m: 'Machine'):
            self.FILES = carrier_set('FILES', m, Machine.FilesItem)
            self.PROCS = carrier_set('PROCS', m, Machine.ProcsItem)
            self.USERS = carrier_set('USERS', m, Machine.UsersItem)
            self.GROUPS = carrier_set('GROUPS', m, Machine.GroupsItem)
            self.FILE_DESCRIPTORS_EXTENDED = carrier_set('FILE_DESCRIPTORS_EXTENDED', m, Machine.FileDescriptorsExtendedItem)
            self.PERMISSIONS = carrier_set('PERMISSIONS', m, Machine.PermissionsItem)
            self.STRINGS = carrier_set('STRINGS', m, Machine.StringsItem)
            self.DATA = carrier_set('DATA', m, Machine.DataItem)
            self.CAPABILITIES = carrier_set('CAPABILITIES', m, Machine.CapabilitiesItem)
            self.INTEGRITY_MODES = carrier_set('INTEGRITY_MODES', m, Machine.IntegrityModesItem)
            self.HASHES = carrier_set('HASHES', m, Machine.HashesItem)
            self.XATTR_FLAGS = carrier_set('XATTR_FLAGS', m, Machine.XattrFlagsItem)

    def __init__(self):
        self.sets = Machine.CarrierSets(self)
        self.FILES: Set[Machine.FilesItem] = frozenset()
        self.PROCS: Set[Machine.ProcsItem] = frozenset()
        self.USERS: Set[Machine.UsersItem] = frozenset()
        self.GROUPS: Set[Machine.GroupsItem] = frozenset()
        self.FILE_DESCRIPTORS_EXTENDED: Set[Machine.FileDescriptorsExtendedItem] = frozenset()
        self.PERMISSIONS: Set[Machine.PermissionsItem] = frozenset()
        self.STRINGS: Set[Machine.StringsItem] = frozenset()
        self.DATA: Set[Machine.DataItem] = frozenset()
        self.CAPABILITIES: Set[Machine.CapabilitiesItem] = frozenset()
        self.INTEGRITY_MODES: Set[Machine.IntegrityModesItem] = frozenset()
        self.HASHES: Set[Machine.HashesItem] = frozenset()
        self.XATTR_FLAGS: Set[Machine.XattrFlagsItem] = frozenset()

        self.INIT = self.sets.PROCS('INIT')
        self.INIT_EXE = self.sets.FILES('INIT_EXE')
        self.INIT_NAME = self.sets.STRINGS('INIT_NAME')
        self.ROOT = self.sets.FILES('ROOT')
        self.MAX_FILES = int()
        self.PROC_FILE_LIMIT = int()
        self.FILE_LIMIT = int()
        self.USER_PERMISSIONS: Set[Machine.PermissionsItem] = frozenset()
        self.GROUP_PERMISSIONS: Set[Machine.PermissionsItem] = frozenset()
        self.OTHER_PERMISSIONS: Set[Machine.PermissionsItem] = frozenset()
        self.FILE_MODES: Set[Machine.PermissionsItem] = frozenset()
        self.UREAD = self.sets.PERMISSIONS('UREAD')
        self.UWRITE = self.sets.PERMISSIONS('UWRITE')
        self.UEXECUTE = self.sets.PERMISSIONS('UEXECUTE')
        self.GREAD = self.sets.PERMISSIONS('GREAD')
        self.GWRITE = self.sets.PERMISSIONS('GWRITE')
        self.GEXECUTE = self.sets.PERMISSIONS('GEXECUTE')
        self.OREAD = self.sets.PERMISSIONS('OREAD')
        self.OWRITE = self.sets.PERMISSIONS('OWRITE')
        self.OEXECUTE = self.sets.PERMISSIONS('OEXECUTE')
        self.SET_UID = self.sets.PERMISSIONS('SET_UID')
        self.SET_GID = self.sets.PERMISSIONS('SET_GID')
        self.STICKY_BIT = self.sets.PERMISSIONS('STICKY_BIT')
        self.DEF_FILE_PERMS: Set[Machine.PermissionsItem] = frozenset()
        self.DEF_FOLDER_PERMS: Set[Machine.PermissionsItem] = frozenset()
        self.DEF_SYMLINK_PERMS: Set[Machine.PermissionsItem] = frozenset()
        self.ROOT_USER = self.sets.USERS('ROOT_USER')
        self.ROOT_GROUP = self.sets.GROUPS('ROOT_GROUP')
        self.FILE_DESCRIPTORS: Set[Machine.FileDescriptorsExtendedItem] = frozenset()
        self.AT_FDCWD = self.sets.FILE_DESCRIPTORS_EXTENDED('AT_FDCWD')
        self.ENFORCE = self.sets.INTEGRITY_MODES('ENFORCE')
        self.FIX = self.sets.INTEGRITY_MODES('FIX')
        self.OFF = self.sets.INTEGRITY_MODES('OFF')
        self.IMA_STRING = self.sets.STRINGS('IMA_STRING')
        self.EVM_STRING = self.sets.STRINGS('EVM_STRING')
        self.ROOT_CONTENT_HASH = self.sets.HASHES('ROOT_CONTENT_HASH')
        self.ROOT_META_HASH = self.sets.HASHES('ROOT_META_HASH')
        self.INIT_EXE_CONTENT_HASH = self.sets.HASHES('INIT_EXE_CONTENT_HASH')
        self.INIT_EXE_META_HASH = self.sets.HASHES('INIT_EXE_META_HASH')
        self.S_IRUSR = self.sets.PERMISSIONS('S_IRUSR')
        self.S_IWUSR = self.sets.PERMISSIONS('S_IWUSR')
        self.S_IXUSR = self.sets.PERMISSIONS('S_IXUSR')
        self.S_IRGRP = self.sets.PERMISSIONS('S_IRGRP')
        self.S_IWGRP = self.sets.PERMISSIONS('S_IWGRP')
        self.S_IXGRP = self.sets.PERMISSIONS('S_IXGRP')
        self.S_IROTH = self.sets.PERMISSIONS('S_IROTH')
        self.S_IWOTH = self.sets.PERMISSIONS('S_IWOTH')
        self.S_IXOTH = self.sets.PERMISSIONS('S_IXOTH')
        self.S_ISUID = self.sets.PERMISSIONS('S_ISUID')
        self.S_ISGID = self.sets.PERMISSIONS('S_ISGID')
        self.S_ISVTX = self.sets.PERMISSIONS('S_ISVTX')
        self.OPEN_FLAGS: Set[int] = frozenset()
        self.O_RDONLY = int()
        self.O_WRONLY = int()
        self.O_RDWR = int()
        self.O_CREAT = int()
        self.O_EXCL = int()
        self.O_DIRECT = int()
        self.O_TMPFILE = int()
        self.O_DIRECTORY = int()
        self.O_CLOEXEC = int()
        self.O_NOCTTY = int()
        self.O_NOFOLLOW = int()
        self.O_TRUNC = int()
        self.O_APPEND = int()
        self.O_ASYNC = int()
        self.O_SYNC = int()
        self.O_DSYNC = int()
        self.O_NOATIME = int()
        self.O_LARGEFILE = int()
        self.O_PATH = int()
        self.O_NOBLOCK = int()
        self.O_NDELAY = int()
        self.XATTR_CREATE = self.sets.XATTR_FLAGS('XATTR_CREATE')
        self.XATTR_REPLACE = self.sets.XATTR_FLAGS('XATTR_REPLACE')

        # @act1: Users ≔ {ROOT_USER}
        self.Users: Set[Machine.UsersItem] = frozenset()
        # @act2: Groups ≔ {ROOT_GROUP}
        self.Groups: Set[Machine.GroupsItem] = frozenset()
        # @act3: Procs ≔ {INIT}
        self.Procs: Set[Machine.ProcsItem] = frozenset()
        # @act4: Files ≔ {ROOT, INIT_EXE}
        self.Files: Set[Machine.FilesItem] = frozenset()
        # @act5: Folders ≔ {ROOT}
        self.Folders: Set[Machine.FilesItem] = frozenset()
        # @act6: SymLinks ≔ ∅
        self.SymLinks: Set[Machine.FilesItem] = frozenset()
        # @act7: FDs ≔ ∅
        self.FDs: Set[Machine.FileDescriptorsExtendedItem] = frozenset()
        # @act8: FileParents ≔ {INIT_EXE ↦ (ROOT ↦ INIT_NAME)}
        self.FileParents: Set[tuple[Machine.FilesItem, tuple[Machine.FilesItem, Machine.StringsItem]]] = frozenset()
        # @act9: FileLink ≔ ∅
        self.FileLink: Set[tuple[Machine.FilesItem, tuple[Machine.FilesItem, Machine.StringsItem]]] = frozenset()
        # @act10: ProcFDs ≔ ∅
        self.ProcFDs: Set[tuple[Machine.ProcsItem, Machine.FileDescriptorsExtendedItem]] = frozenset()
        # @act11: FDFlags ≔ ∅
        self.FDFlags: Set[tuple[Machine.FileDescriptorsExtendedItem, frozenset[int]]] = frozenset()
        # @act12: FDFile ≔ ∅
        self.FDFile: Set[tuple[Machine.FileDescriptorsExtendedItem, Machine.FilesItem]] = frozenset()
        # @act13: FDNumber ≔ ∅
        self.FDNumber: Set[tuple[Machine.FileDescriptorsExtendedItem, int]] = frozenset()
        # @act14: DACPermissions ≔ {ROOT ↦ DEF_FOLDER_PERMS, INIT_EXE ↦ DEF_FILE_PERMS}
        self.DACPermissions: Set[tuple[Machine.FilesItem, frozenset[Machine.PermissionsItem]]] = frozenset()
        # @act15: UserACL ≔ ∅
        self.UserACL: Set[tuple[tuple[Machine.FilesItem, Machine.UsersItem], frozenset[Machine.PermissionsItem]]] = frozenset()
        # @act16: GroupACL ≔ ∅
        self.GroupACL: Set[tuple[tuple[Machine.FilesItem, Machine.GroupsItem], frozenset[Machine.PermissionsItem]]] = frozenset()
        # @act17: GroupObjACL ≔ {ROOT ↦ DEF_FOLDER_PERMS ∩ GROUP_PERMISSIONS, INIT_EXE ↦ DEF_FILE_PERMS ∩ GROUP_PERMISSIONS}
        self.GroupObjACL: Set[tuple[Machine.FilesItem, frozenset[Machine.PermissionsItem]]] = frozenset()
        # @act18: MaskACL ≔ ∅
        self.MaskACL: Set[tuple[Machine.FilesItem, frozenset[Machine.PermissionsItem]]] = frozenset()
        # @act19: FileUser ≔ {ROOT ↦ ROOT_USER, INIT_EXE ↦ ROOT_USER}
        self.FileUser: Set[tuple[Machine.FilesItem, Machine.UsersItem]] = frozenset()
        # @act20: FileGroup ≔ {ROOT ↦ ROOT_GROUP, INIT_EXE ↦ ROOT_GROUP}
        self.FileGroup: Set[tuple[Machine.FilesItem, Machine.GroupsItem]] = frozenset()
        # @act21: ProcUser ≔ {INIT ↦ ROOT_USER}
        self.ProcUser: Set[tuple[Machine.ProcsItem, Machine.UsersItem]] = frozenset()
        # @act22: ProcGroup ≔ {INIT ↦ ROOT_GROUP}
        self.ProcGroup: Set[tuple[Machine.ProcsItem, Machine.GroupsItem]] = frozenset()
        # @act23: ProcUmask ≔ {INIT ↦ ∅}
        self.ProcUmask: Set[tuple[Machine.ProcsItem, frozenset[Machine.PermissionsItem]]] = frozenset()
        # @act24: FileXattrs ≔ {ROOT ↦ ∅, INIT_EXE ↦ ∅}
        self.FileXattrs: Set[tuple[Machine.FilesItem, frozenset[tuple[Machine.StringsItem, Machine.DataItem]]]] = frozenset()
        # @act25: ProcEXE ≔ {INIT ↦ INIT_EXE}
        self.ProcEXE: Set[tuple[Machine.ProcsItem, Machine.FilesItem]] = frozenset()
        # @act26: ProcArgv ≔ {INIT ↦ ∅}
        self.ProcArgv: Set[tuple[Machine.ProcsItem, frozenset[Machine.StringsItem]]] = frozenset()
        # @act27: ProcEnvp ≔ {INIT ↦ ∅}
        self.ProcEnvp: Set[tuple[Machine.ProcsItem, frozenset[Machine.StringsItem]]] = frozenset()
        # @act28: ProcCwd ≔ {INIT ↦ ROOT}
        self.ProcCwd: Set[tuple[Machine.ProcsItem, Machine.FilesItem]] = frozenset()
        # @act29: ProcParent ≔ ∅
        self.ProcParent: Set[tuple[Machine.ProcsItem, Machine.ProcsItem]] = frozenset()
        # @act30: UserGroups ≔ {ROOT_USER ↦ ROOT_GROUP}
        self.UserGroups: Set[tuple[Machine.UsersItem, Machine.GroupsItem]] = frozenset()
        # @act31: PathToRoot ≔ {ROOT ↦ ∅}
        self.PathToRoot: Set[tuple[Machine.FilesItem, frozenset[Machine.FilesItem]]] = frozenset()
        # @act32: UserCaps ≔ {ROOT_USER ↦ ∅}
        self.UserCaps: Set[tuple[Machine.UsersItem, frozenset[Machine.CapabilitiesItem]]] = frozenset()
