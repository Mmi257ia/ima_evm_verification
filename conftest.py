from multiprocessing import Pipe, Process
from multiprocessing.connection import Connection
import os
from subprocess import run
from pytest import fixture
from _pytest.fixtures import SubRequest # type: ignore
from typing import Any

from model.machine import Machine
from anis.model.expressions import carrier_set

@fixture
def t(request: SubRequest, monitor_loaded: Any, m: Machine):
    from testing.spec_impl import LinuxTestSpecImpl
    return LinuxTestSpecImpl(request.node.nodeid, m, request.node.path)


@fixture(scope='session')
def monitor_loaded():
    """
    Tests are not be cancelled immediately by "Cancel Test Run" in VSCode.
    There is a particular period when the button was already pressed but
    several containers were not finished. When all the things are finished,
    the monitor will be unloaded. So do not run tests immediately after
    the "Finished running tests!" message was appeared in "Test Results"! 
    """

    def loader_process(rcvc1: Connection, sndc1: Connection, rcvc2: Connection, sndc2: Connection):
        os.setsid()
        print('Loading monitor ...', end=' ')
        run(['sudo', 'make', '-s', '-C', 'monitoring', 'load'], check=True)
        print('ok')
        rcvc1.close()
        sndc2.close()
        sndc1.close() # loader is ready
        try:
            rcvc2.recv() # wait for closing conn2 (i.e. may unload)
        except EOFError:
            pass
        finally:
            print('Unloading monitor ...', end=' ')
            run(['sudo', 'make', '-s', '-C', 'monitoring', 'unload'], check=True)
            print('ok')

    rcvc1, sndc1 = Pipe(duplex=False)
    rcvc2, sndc2 = Pipe(duplex=False)
    loader = Process(target=loader_process, args=(rcvc1, sndc1, rcvc2, sndc2,),)
    loader.start()
    sndc1.close()
    rcvc2.close()
    try:
        rcvc1.recv() # wait while loading will be fully finished
    except EOFError:
        pass
    finally:
        if loader.exitcode is not None:
            raise ValueError('Monitor loading was failed')
        yield
        sndc2.close()
        loader.join() # wait while unloading will be fully finished

@fixture
def m():
    m = Machine()

    m.MAX_FILES = 1048576
    m.PROC_FILE_LIMIT = 1024
    m.FILE_LIMIT = 1024

    # Permissions should be redefined because
    # there are its items with several names
    # and Machine() creates different objects for them
    m.sets.PERMISSIONS = carrier_set('PERMISSIONS', m, Machine.PermissionsItem)

    m.UREAD = m.sets.PERMISSIONS('UREAD')
    m.UWRITE = m.sets.PERMISSIONS('UWRITE')
    m.UEXECUTE = m.sets.PERMISSIONS('UEXECUTE')
    m.GREAD = m.sets.PERMISSIONS('GREAD')
    m.GWRITE = m.sets.PERMISSIONS('GWRITE')
    m.GEXECUTE = m.sets.PERMISSIONS('GEXECUTE')
    m.OREAD = m.sets.PERMISSIONS('OREAD')
    m.OWRITE = m.sets.PERMISSIONS('OWRITE')
    m.OEXECUTE = m.sets.PERMISSIONS('OEXECUTE')
    m.SET_UID = m.sets.PERMISSIONS('SET_UID')
    m.SET_GID = m.sets.PERMISSIONS('SET_GID')
    m.STICKY_BIT = m.sets.PERMISSIONS('STICKY_BIT')

    m.S_IRUSR = m.UREAD
    m.S_IWUSR = m.UWRITE
    m.S_IXUSR = m.UEXECUTE
    m.S_IRGRP = m.GREAD
    m.S_IWGRP = m.GWRITE
    m.S_IXGRP = m.GEXECUTE
    m.S_IROTH = m.OREAD
    m.S_IWOTH = m.OWRITE
    m.S_IXOTH = m.OEXECUTE
    m.S_ISUID = m.SET_UID
    m.S_ISGID = m.SET_GID
    m.S_ISVTX = m.STICKY_BIT

    m.USER_PERMISSIONS = frozenset((m.UREAD, m.UWRITE, m.UEXECUTE))
    m.GROUP_PERMISSIONS = frozenset((m.GREAD, m.GWRITE, m.GEXECUTE))
    m.OTHER_PERMISSIONS = frozenset((m.OREAD, m.OWRITE, m.OEXECUTE))
    m.FILE_MODES = frozenset((m.SET_UID, m.SET_GID, m.STICKY_BIT))
    m.DEF_FILE_PERMS = frozenset((m.UREAD, m.UWRITE, m.GREAD, m.OREAD))
    m.DEF_FOLDER_PERMS = frozenset((m.UREAD, m.UWRITE, m.UEXECUTE, m.GREAD, m.GEXECUTE, m.OREAD, m.OEXECUTE))
    m.DEF_SYMLINK_PERMS = frozenset((m.UREAD, m.UWRITE, m.UEXECUTE, m.GREAD, m.GWRITE, m.GEXECUTE, m.OREAD, m.OWRITE, m.OEXECUTE))

    m.INTEGRITY_MODES = frozenset((m.ENFORCE, m.FIX, m.OFF))

    # ⚬	O_RDONLY_type:	O_RDONLY = 1 not theorem ›
    m.O_RDONLY = 1
    # ⚬	O_WRONLY_type:	O_WRONLY = 2 not theorem ›
    m.O_WRONLY = 2
    # ⚬	O_RDWR_type:	O_RDWR = 3 not theorem ›
    m.O_RDWR = 3
    # ⚬	O_CREAT_type:	O_CREAT = 4 not theorem ›
    m.O_CREAT = 4
    # ⚬	O_EXCL_type:	O_EXCL = 5 not theorem ›
    m.O_EXCL = 5
    # ⚬	O_DIRECT_type:	O_DIRECT = 6 not theorem ›
    m.O_DIRECT = 6
    # ⚬	O_TMPFILE_type:	O_TMPFILE = 7 not theorem ›
    m.O_TMPFILE = 7
    # ⚬	O_DIRECTORY_type:	O_DIRECTORY = 8 not theorem ›
    m.O_DIRECTORY = 8
    # ⚬	O_CLOEXEC_type:	O_CLOEXEC = 9 not theorem ›
    m.O_CLOEXEC = 9
    # ⚬	O_NOCTTY_type:	O_NOCTTY = 10 not theorem ›
    m.O_NOCTTY = 10
    # ⚬	O_NOFOLLOW_type:	O_NOFOLLOW = 11 not theorem ›
    m.O_NOFOLLOW = 11
    # ⚬	O_TRUNC_type:	O_TRUNC = 12 not theorem ›
    m.O_TRUNC = 12
    # ⚬	O_APPEND_type:	O_APPEND = 13 not theorem ›
    m.O_APPEND = 13
    # ⚬	O_ASYNC_type:	O_ASYNC = 14 not theorem ›
    m.O_ASYNC = 14
    # ⚬	O_SYNC_type:	O_SYNC = 15 not theorem ›
    m.O_SYNC = 15
    # ⚬	O_DSYNC_type:	O_DSYNC = 16 not theorem ›
    m.O_DSYNC = 16
    # ⚬	O_NOATIME_type:	O_NOATIME = 17 not theorem ›
    m.O_NOATIME = 17
    # ⚬	O_LARGEFILE_type:	O_LARGEFILE = 18 not theorem ›
    m.O_LARGEFILE = 18
    # ⚬	O_PATH_type:	O_PATH = 19 not theorem ›
    m.O_PATH = 19
    # ⚬	O_NOBLOCK_type:	O_NOBLOCK = 20 not theorem ›
    m.O_NOBLOCK = 20
    # ⚬	O_NDELAY_type:	O_NDELAY = 21 not theorem ›
    m.O_NDELAY = 21
    # ⚬	OPEN_FLAGS_type:	OPEN_FLAGS = {
    #  	                	    O_RDONLY, O_WRONLY, O_RDWR,
    #  	                	    O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL, O_NOCTTY,
    #  	                	    O_NOFOLLOW, O_TMPFILE, O_TRUNC,
    #  	                	    O_APPEND, O_ASYNC, O_DIRECT, O_DSYNC, O_LARGEFILE,
    #  	                	    O_NOATIME, O_NOBLOCK, O_NDELAY, O_PATH, O_SYNC
    #  	                	} not theorem ›
    m.OPEN_FLAGS = frozenset((
        m.O_RDONLY, m.O_WRONLY, m.O_RDWR,
        m.O_CLOEXEC, m.O_CREAT, m.O_DIRECTORY, m.O_EXCL, m.O_NOCTTY,
        m.O_NOFOLLOW, m.O_TMPFILE, m.O_TRUNC,
        m.O_APPEND, m.O_ASYNC, m.O_DIRECT, m.O_DSYNC, m.O_LARGEFILE,
        m.O_NOATIME, m.O_NOBLOCK, m.O_NDELAY, m.O_PATH, m.O_SYNC
    ))

    # @act1: Users ≔ {ROOT_USER}
    m.Users |= {m.ROOT_USER}
    # @act2: Groups ≔ {ROOT_GROUP}
    m.Groups |= {m.ROOT_GROUP}
    # @act3: Procs ≔ {INIT}
    m.Procs |= {m.INIT}
    # ⚬	act4:	Files ≔ {ROOT, INIT_EXE} ›
    m.Files |= {m.ROOT, m.INIT_EXE}
    # ⚬	act5:	Folders ≔ {ROOT} ›
    m.Folders |= {m.ROOT}
    # ⚬	act8:	FileParents ≔ {INIT_EXE ↦ (ROOT ↦ INIT_NAME)} ›
    m.FileParents |= {(m.INIT_EXE, (m.ROOT, m.INIT_NAME))}
    # ⚬	act14:	DACPermissions ≔ {ROOT ↦ DEF_FOLDER_PERMS, INIT_EXE ↦ DEF_FILE_PERMS} ›
    m.DACPermissions |= {
        (m.ROOT, m.DEF_FOLDER_PERMS),
        (m.INIT_EXE, m.DEF_FILE_PERMS),}
    # ⚬	act17:	GroupObjACL ≔ {ROOT ↦ DEF_FOLDER_PERMS ∩ GROUP_PERMISSIONS, INIT_EXE ↦ DEF_FILE_PERMS ∩ GROUP_PERMISSIONS} ›
    m.GroupObjACL |= {
        (m.ROOT, m.DEF_FOLDER_PERMS & m.GROUP_PERMISSIONS),
        (m.INIT_EXE, m.DEF_FILE_PERMS & m.GROUP_PERMISSIONS),}
    # ⚬	act19:	FileUser ≔ {ROOT ↦ ROOT_USER, INIT_EXE ↦ ROOT_USER} ›
    m.FileUser |= {
        (m.ROOT, m.ROOT_USER),
        (m.INIT_EXE, m.ROOT_USER),}
    # ⚬	act20:	FileGroup ≔ {ROOT ↦ ROOT_GROUP, INIT_EXE ↦ ROOT_GROUP} ›
    m.FileGroup |= {
        (m.ROOT, m.ROOT_GROUP),
        (m.INIT_EXE, m.ROOT_GROUP),}
    # @act21: ProcUser ≔ {INIT ↦ ROOT_USER}
    m.ProcUser |= {(m.INIT, m.ROOT_USER,),}
    # @act22: ProcGroup ≔ {INIT ↦ ROOT_GROUP}
    m.ProcGroup |= {(m.INIT, m.ROOT_GROUP,),}
    # @act23: ProcUmask ≔ {INIT ↦ ∅}
    m.ProcUmask |= {(m.INIT, frozenset())} # frozenset[m.PermissionsItem]())}
    # ⚬	act24:	FileXattrs ≔ {ROOT ↦ ∅, INIT_EXE ↦ ∅} ›
    m.FileXattrs |= {(m.ROOT, frozenset()), (m.INIT_EXE, frozenset())}
    # ⚬	act25:	ProcEXE ≔ {INIT ↦ INIT_EXE} ›
    m.ProcEXE |= {(m.INIT, m.INIT_EXE)}
    # @act26: ProcArgv ≔ {INIT ↦ ∅}
    m.ProcArgv |= {(m.INIT, frozenset())}
    # @act27: ProcEnvp ≔ {INIT ↦ ∅}
    m.ProcEnvp |= {(m.INIT, frozenset())}
    # ⚬	act28:	ProcCwd ≔ {INIT ↦ ROOT} ›
    m.ProcCwd |= {(m.INIT, m.ROOT)}
    # ⚬	act30:	UserGroups ≔ {ROOT_USER ↦ ROOT_GROUP} ›
    m.UserGroups |= {(m.ROOT_USER, m.ROOT_GROUP)}
    # ⚬	act31:	PathToRoot ≔ {ROOT ↦ ∅} ›
    m.PathToRoot |= {(m.ROOT, frozenset())}
    # @act32: UserCaps ≔ {ROOT_USER ↦ ∅}
    m.UserCaps |= {(m.ROOT_USER, frozenset())}

    # @act41: ContentHash ≔ {ROOT ↦ ROOT_CONTENT_HASH, INIT_EXE ↦ INIT_EXE_CONTENT_HASH}
    m.ContentHash |= {(m.ROOT, m.ROOT_CONTENT_HASH), (m.INIT_EXE, m.INIT_EXE_CONTENT_HASH)}
    # @act42: MetaHash ≔ {ROOT ↦ ROOT_META_HASH, INIT_EXE ↦ INIT_EXE_META_HASH}
    m.MetaHash |= {(m.ROOT, m.ROOT_META_HASH), (m.INIT_EXE, m.INIT_EXE_META_HASH)}
    # @act46: IMAMode ≔ OFF
    m.IMAMode = m.OFF
    # @act47: EVMMode ≔ OFF
    m.EVMMode = m.OFF
    return m
