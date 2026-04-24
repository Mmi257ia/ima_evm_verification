from collections import defaultdict
from functools import reduce
from os import O_RDONLY, O_RDWR, O_WRONLY
from os.path import basename
from stat import S_IMODE
from typing import Optional, Sequence
from model.events.chdir import chdir
from model.events.chmod import chmod
from model.events.chown import chown
from model.events.close import close
from model.events.creat import creat
from model.events.create_group import create_group
from model.events.create_user import create_user
from model.events.execve import execve
from model.events.exit import exit
from model.events.fchdir import fchdir
from model.events.fchmod import fchmod
from model.events.fchown import fchown
from model.events.getxattr import getxattr
from model.events.link import link
from model.events.login import login
from model.events.mkdir import mkdir
from model.events.open_create import open_create
from model.events.open_exists import open_exists
from model.events.openat_create import openat_create
from model.events.openat_exists import openat_exists
from model.events.rmdir import rmdir
from model.events.set_acl import set_acl
from model.events.setxattr import setxattr
from model.events.symlink import symlink
from model.events.unlink import unlink
from anis.stages.mediator import ModelTraceConsumer
from model.machine import Machine
from mediator.enums import FileFlags, Modes, XattrFlags
from mediator.state import Inode, ProcFD


class DataTranslator:

    def __init__(self, *, m: Machine, root_dev: int, root_ino: int, root_uid: int, root_gid: int):
        self.model_files = defaultdict[Inode, m.FilesItem](m.sets.FILES) # implementation (#dev, #inode) to name of variable
        self.model_strings = defaultdict[str, m.StringsItem](m.sets.STRINGS)
        self.model_data = defaultdict[bytes, m.DataItem](m.sets.DATA)
        self.model_users = defaultdict[int, m.UsersItem](m.sets.USERS) # implementation to model
        self.model_groups = defaultdict[int, m.GroupsItem](m.sets.GROUPS) # implementation to model
        self.model_procs = defaultdict[int, m.ProcsItem](m.sets.PROCS) # implementation to model
        self.model_fds = defaultdict[tuple[int, int], m.FileDescriptorsExtendedItem](m.sets.FILE_DESCRIPTORS_EXTENDED) # implementation (pid, fd) to model

        # it comes from INITIALISATION event...
        self.model_users[root_uid] = m.ROOT_USER
        self.model_groups[root_gid] = m.ROOT_GROUP
        self.model_procs[0] = m.INIT
        self.model_fds[(0, 0)] = m.AT_FDCWD # 0-th item in carrier set FILE_DESCRIPTORS_EXTENDED is AT_FDCWD

        self.rootInode = Inode(root_dev, root_ino)
        self.model_files[self.rootInode] = m.ROOT


class EventsBuilder:
    def __init__(self, *, model_trace: ModelTraceConsumer, m: Machine,
                 root_dev: int, root_ino: int, root_uid: int, root_gid: int):
        self._model_trace = model_trace
        self._data_translator = DataTranslator(m=m, root_dev=root_dev, root_ino=root_ino,
                                               root_uid=root_uid, root_gid=root_gid)
        self._machine = m
        self._Modes = Modes(m)
        self._FileFlags = FileFlags(m)
        self._XattrFlags = XattrFlags(m)
    
    def translate_group(self, gid: int):
        return self._data_translator.model_groups[gid]

    def translate_proc(self, proc: int):
        return self._data_translator.model_procs[proc]

    def translate_string(self, string: str):
        return self._data_translator.model_strings[string]

    def translate_data(self, data: bytes):
        return self._data_translator.model_data[data]

    def translate_user(self, uid: int):
        return self._data_translator.model_users[uid]

    def translate_groups(self, groups: Sequence[int]):
        return frozenset((self.translate_group(g) for g in groups))

    def translate_mode(self, mode: int):
        mode = S_IMODE(mode) # remove bits of file type
        # check: if any bit of "mode" is 1, then it is translatable (Modes has any bits from "mode")
        assert (mode & ~(reduce(lambda x, y: (x | y), self._Modes.keys(), 0))) == 0
        assert 0 not in self._Modes # otherwise the same logics as in translate_file_flags is needed
        return frozenset((model_bit for mask, model_bit in self._Modes.items() if (mode & mask) != 0))
    
    def translate_file_flags(self, flags: int):
        # check: if any bit of "flags" is 1, then it is translatable (FileFlags has any flags from "flags")
        assert (flags & ~(reduce(lambda x, y: (x | y), self._FileFlags.keys(), 0))) == 0
        assert self._FileFlags[0] == self._machine.O_RDONLY
        if (flags & O_WRONLY) != 0:
            e = self._FileFlags[O_WRONLY]
        elif (flags & O_RDWR) != 0:
            e = self._FileFlags[O_RDWR]
        else:
            e = self._FileFlags[O_RDONLY]
        model_flags = [e] + [flag_bit for f, flag_bit in self._FileFlags.items() if (flags & f) != 0]
        return frozenset(model_flags)

    def translate_xattr_flags(self, flags: int):
        # check: if any bit of "flags" is 1, then it is translatable (XattrFlags has any flags from "flags")
        assert (flags & ~(reduce(lambda x, y: (x | y), self._XattrFlags.keys(), 0))) == 0
        return frozenset((flag_bit for f, flag_bit in self._XattrFlags.items() if (flags & f) != 0))

    def translate_inode(self, ino: Inode):
        return self._data_translator.model_files[ino]
    
    def translate_fd(self, proc_fd: tuple[int, int]):
        model_fd = self._data_translator.model_fds[proc_fd]
        self._machine.FILE_DESCRIPTORS |= {model_fd}
        return model_fd
    
    def translate_capability(self, capability: str) -> Machine.CapabilitiesItem:
        raise NotImplementedError()

    def translate_inodes(self, files: Sequence[Inode]):
        return frozenset((self.translate_inode(file) for file in files))

    def translate_fds(self, fds: Sequence[tuple[int, int]]):
        return frozenset((self.translate_fd(fd) for fd in fds))

    def translate_strings(self, strings: Sequence[str]):
        return frozenset((self.translate_string(s) for s in strings))

    def translate_caps(self, caps: Sequence[str]):
        return frozenset((self.translate_capability(c) for c in caps))

    def open_create(self, path: str, flags: int, mode: int,
                              parent: Inode,
                              file: Optional[Inode], gid: Optional[int], perms: Optional[int],
                              proc: int, retval: int, skip_coverage: bool = False):
        self._model_trace.add(open_create,
                _proc = self.translate_proc(proc),
                _parent = self.translate_inode(parent),
                _file = self.translate_inode(file) if file is not None else None,
                _name = self.translate_string(basename(path)),
                _flags = self.translate_file_flags(flags),
                _mode = self.translate_mode(mode),
                _fd = self.translate_fd((proc, retval,)) if retval >= 0 else None,
                _fdNumber = retval if retval >= 0 else None,
                _group = self.translate_group(gid) if gid is not None else None,
                _perms = self.translate_mode(perms) if perms is not None else None,
                expected= retval >= 0,
                skip_coverage=skip_coverage,)

    def open_exists(self, path: str, flags: int,
                              parent: Inode,
                              file: Inode,
                              proc: int, retval: int, skip_coverage: bool = False):
        self._model_trace.add(open_exists,
                _proc = self.translate_proc(proc),
                _parent = self.translate_inode(parent),
                _file = self.translate_inode(file),
                _name = self.translate_string(basename(path)),
                _flags = self.translate_file_flags(flags),
                _fd = self.translate_fd((proc, retval,)) if retval >= 0 else None,
                _fdNumber = retval if retval >= 0 else None,
                expected= retval >= 0,
                skip_coverage= skip_coverage,)

    def creat(self,
                    path: str, mode: int,
                    parent: Inode,
                    file: Optional[Inode], gid: Optional[int], perms: Optional[int],
                    proc: int, retval: int, skip_coverage: bool = False):
        self._model_trace.add(creat,
                _proc = self.translate_proc(proc),
                _parent = self.translate_inode(parent),
                _file = self.translate_inode(file) if file is not None else None,
                _name = self.translate_string(basename(path)),
                _flags = frozenset((self._machine.O_CREAT, self._machine.O_TRUNC, self._machine.O_WRONLY),),
                _mode = self.translate_mode(mode),
                _fd = self.translate_fd((proc, retval,)) if retval >= 0 else None,
                _fdNumber = retval if retval >= 0 else None,
                _group = self.translate_group(gid) if gid is not None else None,
                _perms = self.translate_mode(perms) if perms is not None else None,
                expected= retval >= 0,
                skip_coverage= skip_coverage,)

    def openat_create(self, dirfd: int, path: str, flags: int, mode: int,
                                      parent: Inode,
                                      file: Optional[Inode], gid: Optional[int], perms: Optional[int],
                                      cwd: Inode, proc: int, retval: int, skip_coverage: bool = False):
        self._model_trace.add(openat_create,
                _proc = self.translate_proc(proc),
                _dirfd = self.translate_fd((proc, dirfd)),
                _parent = self.translate_inode(parent),
                _file = self.translate_inode(file) if file is not None else None,
                _name = self.translate_string(basename(path)),
                _flags = self.translate_file_flags(flags),
                _mode = self.translate_mode(mode),
                _fd = self.translate_fd((proc, retval,)) if retval >= 0 else None,
                _fdNumber = retval if retval >= 0 else None,
                _cwd = self.translate_inode(cwd),
                _group = self.translate_group(gid) if gid is not None else None,
                _perms = self.translate_mode(perms) if perms is not None else None,
                expected= retval >= 0,
                skip_coverage= skip_coverage,)

    def openat_exists(self, dirfd: int, path: str, flags: int,
                                      parent: Inode,
                                      file: Inode,
                                      cwd: Inode, proc: int, retval: int, skip_coverage: bool = False):
        self._model_trace.add(openat_exists,
                _proc = self.translate_proc(proc),
                _dirfd = self.translate_fd((proc, dirfd)),
                _parent = self.translate_inode(parent),
                _file = self.translate_inode(file),
                _name = self.translate_string(basename(path)),
                _flags = self.translate_file_flags(flags),
                _fd = self.translate_fd((proc, retval,)) if retval >= 0 else None,
                _fdNumber = retval if retval >= 0 else None,
                _cwd = self.translate_inode(cwd),
                expected= retval >= 0,
                skip_coverage=skip_coverage,)

    def mkdir(self, path: str, mode: int,
                              parent: Inode,
                              folder: Optional[Inode], gid: Optional[int], perms: Optional[int],
                              proc: int, retval: int, skip_coverage: bool = False):
        self._model_trace.add(mkdir,
                _proc = self.translate_proc(proc),
                _parent = self.translate_inode(parent),
                _folder = self.translate_inode(folder) if folder is not None else None,
                _name = self.translate_string(basename(path)),
                _mode = self.translate_mode(mode),
                _group = self.translate_group(gid) if gid is not None else None,
                _perms = self.translate_mode(perms) if perms is not None else None,
                expected= retval >= 0,
                skip_coverage=skip_coverage,)
    
    def chmod(self, path: str, mode: int, parent: Inode, file: Inode, perms: Optional[int], proc: int, retval: int, skip_coverage: bool = False):
        self._model_trace.add(chmod,
                _proc = self.translate_proc(proc),
                _parent = self.translate_inode(parent),
                _file = self.translate_inode(file),
                _name = self.translate_string(basename(path)),
                _mode = self.translate_mode(mode),
                _perms = self.translate_mode(perms) if perms is not None else None,
                expected= retval >= 0,
                skip_coverage=skip_coverage,)

    def fchmod(self, fd: int, mode: int, perms: Optional[int], proc: int, retval: int, skip_coverage: bool = False):
        self._model_trace.add(fchmod,
                _proc = self.translate_proc(proc),
                _fd = self.translate_fd((proc, fd)),
                _mode = self.translate_mode(mode),
                _perms = self.translate_mode(perms) if perms is not None else None,
                expected= retval >= 0,
                skip_coverage=skip_coverage,)

    def chown(self, path: str, uid: int, gid: int, pre_uid: int, pre_gid: int, parent: Inode, file: Inode, perms: Optional[int], proc: int, retval: int, skip_coverage: bool = False):
        self._model_trace.add(chown,
                _proc = self.translate_proc(proc),
                _parent = self.translate_inode(parent),
                _file = self.translate_inode(file),
                _name = self.translate_string(basename(path)),
                _owner = self.translate_user(uid if uid != -1 else pre_uid),
                _group = self.translate_group(gid if gid != -1 else pre_gid),
                _perms = self.translate_mode(perms) if perms is not None else None,
                expected= retval >= 0,
                skip_coverage=skip_coverage,)

    def fchown(self, fd: int, uid: int, gid: int, pre_uid: int, pre_gid: int, perms: Optional[int], proc: int, retval: int, skip_coverage: bool = False):
        self._model_trace.add(fchown,
                _proc = self.translate_proc(proc),
                _fd = self.translate_fd((proc, fd)),
                _owner = self.translate_user(uid if uid != -1 else pre_uid),
                _group = self.translate_group(gid if gid != -1 else pre_gid),
                _perms = self.translate_mode(perms) if perms is not None else None,
                expected= retval >= 0,
                skip_coverage=skip_coverage,)

    def chdir(self, dir: Inode, proc: int, retval: int, skip_coverage: bool = False):
        self._model_trace.add(chdir,
                _proc = self.translate_proc(proc),
                _dir = self.translate_inode(dir),
                expected= retval >= 0,
                skip_coverage=skip_coverage,)

    def fchdir(self, fd: int, proc: int, retval: int, skip_coverage: bool = False):
        self._model_trace.add(fchdir,
                _proc = self.translate_proc(proc),
                _fd = self.translate_fd((proc, fd,)),
                expected= retval >= 0,
                skip_coverage=skip_coverage,)

    def getxattr(self, path: str, name: str, size: int, parent: Inode, file: Inode, value: Optional[bytes], proc: int, retval: int, skip_coverage: bool = False):
        self._model_trace.add(getxattr,
                _proc = self.translate_proc(proc),
                _parent = self.translate_inode(parent),
                _file = self.translate_inode(file),
                _fileName = self.translate_string(basename(path)),
                _name = self.translate_string(name),
                _value = self.translate_data(value) if value is not None else None,
                _size = size,
                expected= retval >= 0,
                skip_coverage=skip_coverage,)

    def setxattr(self, path: str, name: str, value: bytes, size: int, flags: int, parent: Inode, file: Inode, proc: int, retval: int, skip_coverage: bool = False):
        self._model_trace.add(setxattr,
                _proc = self.translate_proc(proc),
                _parent = self.translate_inode(parent),
                _file = self.translate_inode(file),
                _fileName = self.translate_string(basename(path)),
                _name = self.translate_string(name),
                _value = self.translate_data(value),
                _size = size,
                _flags = self.translate_xattr_flags(flags),
                expected= retval >= 0,
                skip_coverage=skip_coverage,)

    def link(self, oldpath: str, newpath: str, oldParent: Inode, file: Inode, newParent: Inode, proc: int, retval: int, skip_coverage: bool = False):
        self._model_trace.add(link,
                _proc = self.translate_proc(proc),
                _oldParent = self.translate_inode(oldParent),
                _newParent = self.translate_inode(newParent),
                _file = self.translate_inode(file),
                _oldName = self.translate_string(basename(oldpath)),
                _newName = self.translate_string(basename(newpath)),
                expected= retval >= 0,
                skip_coverage=skip_coverage,)

    def symlink(self, target: str, linkpath: str, target_parent: Inode, parent: Inode,
                                file: Optional[Inode],
                                proc: int, retval: int, skip_coverage: bool = False):
        self._model_trace.add(symlink,
                _proc = self.translate_proc(proc),
                _target_parent = self.translate_inode(target_parent),
                _target_name = self.translate_string(basename(target)),
                _parent = self.translate_inode(parent),
                _file = self.translate_inode(file) if file is not None else None,
                _name = self.translate_string(basename(linkpath)),
                expected= retval >= 0,
                skip_coverage=skip_coverage,)

    def execve(self, path: str, args: set[str], envp: set[str], fds: set[int], parent: Inode, exeFile: Inode, proc: int, retval: int, skip_coverage: bool = False):
        self._model_trace.add(execve,
                _proc = self.translate_proc(proc),
                _parent = self.translate_inode(parent),
                _exeFile = self.translate_inode(exeFile),
                _name = self.translate_string(basename(path)),
                _argv = frozenset(self.translate_string(arg) for arg in args),
                _envp = frozenset(self.translate_string(env) for env in envp),
                _fds = self.translate_fds([(proc, fd,) for fd in fds]),
                expected=retval >= 0,
                skip_coverage= skip_coverage,)

    def unlink(self, path: str, parent: Inode, file: Inode, files: list[Inode], proc: int, retval: int, skip_coverage: bool = False):
        self._model_trace.add(unlink,
                _proc = self.translate_proc(proc),
                _parent = self.translate_inode(parent),
                _file = self.translate_inode(file),
                _name = self.translate_string(basename(path)),
                _files = self.translate_inodes(files),
                expected= retval >= 0,
                skip_coverage= skip_coverage,)

    def rmdir(self, path: str, parent: Inode, folder: Inode, proc: int, retval: int, skip_coverage: bool = False):
        self._model_trace.add(rmdir,
                _proc = self.translate_proc(proc),
                _parent = self.translate_inode(parent),
                _folder = self.translate_inode(folder),
                _name = self.translate_string(basename(path)),
                expected= retval >= 0,
                skip_coverage= skip_coverage,)

    def close(self, fd: int, fds: Sequence[ProcFD], proc: int, retval: int, skip_coverage: bool = False):
        self._model_trace.add(close,
                _proc = self.translate_proc(proc),
                _fd = self.translate_fd((proc, fd,)),
                _fds = self.translate_fds(fds),
                expected= retval >= 0,
                skip_coverage= skip_coverage,)
    
    def exit(self, fds: Sequence[ProcFD], proc: int, retval: int, skip_coverage: bool = False):
        self._model_trace.add(exit,
                _proc = self.translate_proc(proc),
                _fds = self.translate_fds(fds),
                expected= retval >= 0,
                skip_coverage= skip_coverage,)
    
    def login(self, *, uid: int, gid: int, pid: int, exeFile: Inode, umask: int):
        self._model_trace.add(login,
                _user = self.translate_user(uid),
                _proc = self.translate_proc(pid),
                _group = self.translate_group(gid),
                _exeFile = self.translate_inode(exeFile),
                _argv = frozenset(),
                _envp = frozenset(),
                _umask = self.translate_mode(umask),
                expected=True,
                skip_coverage=True,)

    def create_group(self, gid: int):
        self._model_trace.add(create_group,
                _group = self.translate_group(gid),
                expected=True,
                skip_coverage=True,)

    def create_user(self, uid: int, gids: Sequence[int]):
        self._model_trace.add(create_user,
                _user = self.translate_user(uid),
                _groups = self.translate_groups(gids),
                _caps = frozenset(),
                expected=True,
                skip_coverage=True,)

    
    def translate_userACL(self, userACL: list[tuple[Inode, int, int]]): # (path, user) |-> '[r|-][w|-][x-]'
        return frozenset(
                ((self.translate_inode(inode), self.translate_user(uid)), self.translate_mode(perms))
                          for inode, uid, perms in userACL)
    def translate_groupACL(self, groupACL: list[tuple[Inode, int, int]]): # (path, group) |-> '[r|-][w|-][x-]'
        return frozenset(
                ((self.translate_inode(inode), self.translate_group(gid)), self.translate_mode(perms))
                          for inode, gid, perms in groupACL)
    def translate_groupObjACL(self, groupObjACL: list[tuple[Inode, int]]): # path |-> '[r|-][w|-][x-]'
        return frozenset(
                ((self._machine.ROOT, self.translate_mode(0o070),),
                 (self._machine.INIT_EXE, self.translate_mode(0o070)),) +
                tuple((self.translate_inode(inode), self.translate_mode(perms))
                            for inode, perms in groupObjACL))
    def translate_maskACL(self, maskACL: list[tuple[Inode, int]]): # path |-> '[r|-][w|-][x-]'
        return frozenset(
                (self.translate_inode(inode), self.translate_mode(perms))
                          for inode, perms in maskACL)
    def translate_dacPermissions(self, dacPermissions: dict[Inode, int]):
        return frozenset(
                    ((self._machine.ROOT, self.translate_mode(0o777)),
                     (self._machine.INIT_EXE, self.translate_mode(0o777)),) +
                     tuple((self.translate_inode(inode), self.translate_mode(perms),)
                            for inode, perms in dacPermissions.items()))

    def set_acl(self,
                          userACL: list[tuple[Inode, int, int]], # (path, user) |-> '[r|-][w|-][x-]'
                          groupACL: list[tuple[Inode, int, int]], # (path, group) |-> '[r|-][w|-][x-]'
                          groupObjACL: list[tuple[Inode, int]], # path |-> '[r|-][w|-][x-]'
                          maskACL: list[tuple[Inode, int]], # path |-> '[r|-][w|-][x-]'
                          dacPermissions: dict[Inode, int] # path |-> '[r|-][w|-][x-]' x3 as mode_t
                          ):
        self._model_trace.add(set_acl,
                _userACL = self.translate_userACL(userACL),
                _groupACL = self.translate_groupACL(groupACL),
                _groupObjACL = self.translate_groupObjACL(groupObjACL),
                _maskACL = self.translate_maskACL(maskACL),
                _dacPermissions = self.translate_dacPermissions(dacPermissions),
                expected=True,
                skip_coverage=True,)