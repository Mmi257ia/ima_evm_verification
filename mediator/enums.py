from model.machine import Machine


def Modes(m: Machine):
    return {
        0o04000: m.SET_UID,
        0o02000: m.SET_GID,
        0o01000: m.STICKY_BIT,

        0o00400: m.UREAD,
        0o00200: m.UWRITE,
        0o00100: m.UEXECUTE,

        0o00040: m.GREAD,
        0o00020: m.GWRITE,
        0o00010: m.GEXECUTE,

        0o00004: m.OREAD,
        0o00002: m.OWRITE,
        0o00001: m.OEXECUTE,
    }

def FileFlags(m: Machine):
    return {
        0o00000000: m.O_RDONLY,
        0o00000001: m.O_WRONLY,
        0o00000002: m.O_RDWR,

        0o00000100: m.O_CREAT,
        0o00000200: m.O_EXCL,
        0o00000400: m.O_NOCTTY,
        0o00001000: m.O_TRUNC,
        0o00002000: m.O_APPEND,
        0o00004000: m.O_NOBLOCK, # typo in the model? O_NO(N)BLOCK
        0o00010000: m.O_DSYNC,
        # 0o00020000: FASYNC, # no such a constant in the model
        0o00040000: m.O_DIRECT,
        0o00100000: m.O_LARGEFILE,
        0o00200000: m.O_DIRECTORY,
        0o00400000: m.O_NOFOLLOW,
        0o01000000: m.O_NOATIME,
        0o02000000: m.O_CLOEXEC,
        0o10000000: m.O_PATH,
    }

def XattrFlags(m: Machine):
    return {
        0o1: m.XATTR_CREATE,
        0o2: m.XATTR_REPLACE,
    }

