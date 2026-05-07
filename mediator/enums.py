import os
import stat

from model.machine import Machine


def Modes(m: Machine):
    return {
        stat.S_ISUID: m.SET_UID,
        stat.S_ISGID: m.SET_GID,
        stat.S_ISVTX: m.STICKY_BIT,

        stat.S_IRUSR: m.UREAD,
        stat.S_IWUSR: m.UWRITE,
        stat.S_IXUSR: m.UEXECUTE,

        stat.S_IRGRP: m.GREAD,
        stat.S_IWGRP: m.GWRITE,
        stat.S_IXGRP: m.GEXECUTE,

        stat.S_IROTH: m.OREAD,
        stat.S_IWOTH: m.OWRITE,
        stat.S_IXOTH: m.OEXECUTE,
    }

def FileFlags(m: Machine):
    return {
        os.O_RDONLY: m.O_RDONLY,
        os.O_WRONLY: m.O_WRONLY,
        os.O_RDWR: m.O_RDWR,

        os.O_CREAT: m.O_CREAT,
        os.O_EXCL: m.O_EXCL,
        os.O_NOCTTY: m.O_NOCTTY,
        os.O_TRUNC: m.O_TRUNC,
        os.O_APPEND: m.O_APPEND,
        os.O_NONBLOCK: m.O_NOBLOCK, # typo in the model? O_NO(N)BLOCK
        os.O_DSYNC: m.O_DSYNC,
        # 0o00020000: FASYNC, # no such a constant in the model
        os.O_DIRECT: m.O_DIRECT,
        # os.O_LARGEFILE: m.O_LARGEFILE, because os.O_LARGEFILE == 0 (== os.O_RDONLY!)
        os.O_DIRECTORY: m.O_DIRECTORY,
        os.O_NOFOLLOW: m.O_NOFOLLOW,
        os.O_NOATIME: m.O_NOATIME,
        os.O_CLOEXEC: m.O_CLOEXEC,
        os.O_PATH: m.O_PATH,
        os.O_TMPFILE: m.O_TMPFILE,
    }

def XattrFlags(m: Machine):
    return {
        os.XATTR_CREATE: m.XATTR_CREATE,
        os.XATTR_REPLACE: m.XATTR_REPLACE,
    }

