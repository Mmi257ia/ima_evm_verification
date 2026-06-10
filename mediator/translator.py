from os.path import dirname, isabs, join
from re import fullmatch
from stat import S_IMODE, S_IRGRP, S_IRUSR, S_IWGRP, S_IWUSR, S_IXGRP, S_IXUSR
from typing import Generator, Optional
from model.machine import Machine
from anis.model.lazy import assert_is_not_none
from anis.stages.mediator import ModelTraceConsumer
from mediator.builder import EventsBuilder
from mediator.state import Inode, MediatorState, ProcFD, FileHash, ImaEvmMode


def calc_fake_meta_hash(uid: int | None, gid: int | None, perms: int | None) -> bytes:
    if any(p is None for p in (uid, gid, perms)):
        return bytes()
    return f"fake_{uid}_{gid}_{S_IMODE(perms)}".encode()

def is_hash_fake(hash: bytes) -> bool:
    return hash[:4] == 'fake'.encode()


class TraceTranslator:

    def __init__(self, *, model_trace: ModelTraceConsumer, m: Machine,
                 root_dev: int, root_ino: int, root_uid: int, root_gid: int):

        self._model_trace = EventsBuilder(model_trace=model_trace, m=m,
                                          root_dev=root_dev, root_ino=root_ino,
                                          root_uid=root_uid, root_gid=root_gid)

        self.mediator_state = MediatorState(Inode(root_dev, root_ino))


    def add_init_group(self, *, gid: int):

        self._model_trace.create_group(gid)


    def add_init_user(self, *, uid: int, primary_gid: int, supplementary_gids: list[int]):

        self._model_trace.create_user(uid, [primary_gid] + supplementary_gids)


    def add_init_folder(self, *, path: str,
                        dev: int, ino: int, uid: int, gid: int, perms: int):

        folder = Inode(dev, ino,)
        parent = self.mediator_state.get_ino(dirname(path))
        
        mkdir_meta = calc_fake_meta_hash(0, 0, 0o777)
        self.mediator_state.do_mkdir(path, folder, uid, gid, perms, FileHash(meta_hash=mkdir_meta))
        self._model_trace.mkdir(path, 0o777, parent, folder, 0, 0o777, 0, bytes(), mkdir_meta, 0, skip_coverage=True)
        
        chown_meta = calc_fake_meta_hash(uid, gid, 0o777)
        self.mediator_state.do_chown(folder, uid, gid, chown_meta)
        self._model_trace.chown(path, uid, gid, 0, 0, parent, folder, 0o777, 0, chown_meta, 0, skip_coverage=True)
        
        chmod_meta = calc_fake_meta_hash(uid, gid, perms)
        self.mediator_state.do_chmod(folder, perms, chmod_meta)
        self._model_trace.chmod(path, perms, parent, folder, perms, 0, chmod_meta, 0, skip_coverage=True)

        self.mediator_state.do_set_integrity_hashes(folder, FileHash(bytes(), chmod_meta))
        self._model_trace.force_set_ima_evm_hash(folder, bytes(), chmod_meta)


    def set_xattrs_init_file(self, *, path: str, xattrs: dict[str, str]):

        folder = self.mediator_state.get_ino(path)
        parent = self.mediator_state.get_ino(dirname(path))
        for name, value in xattrs.items():
            if name in ('security.ima', 'security.evm'):
                continue
            value_b = bytes.fromhex(value)
            self._model_trace.setxattr(path, name, value_b, len(value_b), 0, parent, folder, 0, 0, skip_coverage=True)

    def add_init_file_or_link(self, *, path: str,
                      dev: int, ino: int, uid: int, gid: int, perms: int,
                      content_hash: bytes, meta_hash: bytes):

        parent = self.mediator_state.get_ino(dirname(path))
        file = Inode(dev, ino,)
        try:
            oldpath = self.mediator_state.get_path(file)
        except:
            oldpath = None

        if oldpath is not None:
            oldParent = self.mediator_state.get_ino(dirname(oldpath))
            self.mediator_state.do_link(oldpath, path)
            self._model_trace.link(oldpath, path, oldParent, file, parent, 0, 0, skip_coverage=True)
        else:

            create_meta = calc_fake_meta_hash(0, 0, 0o777)
            chown_meta = calc_fake_meta_hash(uid, gid, 0o777)
            chmod_meta = calc_fake_meta_hash(uid, gid, perms)
            close_meta = meta_hash if content_hash else chmod_meta

            self.mediator_state.do_creat(path, file, uid, gid, perms, FileHash(meta_hash=create_meta))
            self.mediator_state.do_open(ProcFD(0, 3), file)
            self._model_trace.creat(path, 0o777, parent, file, 0, 0o777, 0, bytes(), create_meta, 3, skip_coverage=True)
            self._model_trace.fchown(3, uid, gid, 0, 0, 0o777, 0, chown_meta, 0, skip_coverage=True)
            self._model_trace.fchmod(3, perms, perms, 0, chmod_meta, 0, skip_coverage=True)
            self._model_trace.close(3, [ProcFD(0, 3)], 0, content_hash, close_meta, content_hash, close_meta, 0, skip_coverage=True)
            self.mediator_state.do_close(ProcFD(0, 3), FileHash(content_hash, close_meta))

    def set_init_acl(self, *, data: list[tuple[str, list[str]]]):

        def acls() -> Generator[tuple[Inode, int, list[str]], None, None]:
            for path, acl in data:
                file = self.mediator_state.get_ino(path)
                perms = self.mediator_state.stats[file].st_mode
                yield (file, perms, acl)


        # translate acl
        userACL = list[tuple[Inode, int, int]]()
        groupACL = list[tuple[Inode, int, int]]()
        groupObjACL = list[tuple[Inode, int]]()
        maskACL = list[tuple[Inode, int]]()
        dacPermissions = dict[Inode, int]()
        for ino, perms, acl in acls():
            if ino in dacPermissions:
                continue # acl for links is unnecessary
            dacPermissions[ino] = perms
            for line in acl:
                macl = fullmatch(r'(user|group|mask|other):([^:]*):.*([-r][-w][-x])', line)
                if not macl:
                    continue
                if macl[1] == 'user':
                    if len(macl[2]) > 0:
                        # user:{uid}:rwx
                        uid = int(macl[2])
                        userACL.append((ino, uid, (S_IRUSR if 'r' in macl[3] else 0)
                                                |(S_IWUSR if 'w' in macl[3] else 0)
                                                |(S_IXUSR if 'x' in macl[3] else 0)),)
                elif macl[1] == 'group':
                    perms = ((S_IRGRP if 'r' in macl[3] else 0)
                            |(S_IWGRP if 'w' in macl[3] else 0)
                            |(S_IXGRP if 'x' in macl[3] else 0))
                    if len(macl[2]) > 0:
                        # group:{gid}:rwx
                        gid = int(macl[2])
                        groupACL.append((ino, gid, perms,))
                    else:
                        # group::rwx
                        groupObjACL.append((ino, perms,))
                elif macl[1] == 'mask':
                    # mask::rwx
                    maskACL.append((ino, (S_IRGRP if 'r' in macl[3] else 0)
                                          |(S_IWGRP if 'w' in macl[3] else 0)
                                          |(S_IXGRP if 'x' in macl[3] else 0)))
        self._model_trace.set_acl(userACL, groupACL, groupObjACL, maskACL, dacPermissions)

    def set_init_ima_mode(self, *, ima_mode: str):
        mode = ImaEvmMode[ima_mode]
        self._model_trace.switch_ima_mode(mode)
        self.mediator_state.do_switch_ima_mode(mode)
    
    def set_init_evm_mode(self, *, evm_mode: str):
        mode = ImaEvmMode[evm_mode]
        self._model_trace.switch_evm_mode(mode)
        self.mediator_state.do_switch_evm_mode(mode)

    def set_init_immutable(self, *, path: str):
        ino = self.mediator_state.get_ino(path)
        self._model_trace.mark_immutable(ino)

    def login(self, *, uid: int, gid: int, pid: int, exeFile: str, umask: int):
        exeFile_ino = self.mediator_state.get_ino(exeFile)
        self._model_trace.login(uid=uid, gid=gid, pid=pid, exeFile=exeFile_ino, umask=umask)

    def open(self, pathname: str, flags: int, mode: int, pid: int,
             dev: Optional[int], ino: Optional[int],
             uid: Optional[int], gid: Optional[int],
             perms: Optional[int], retval: int) -> None:

        # append model trace
        abspath = self.mediator_state.normalize(pathname, pid)
        parent = self.mediator_state.get_ino(dirname(abspath))
        fake_meta_hash = calc_fake_meta_hash(uid, gid, perms)
        if self.mediator_state.do_exists(abspath):
            file = self.mediator_state.get_ino(abspath)
            self._model_trace.open_exists(abspath, flags, parent, file, pid, retval)
        else:
            if dev is None:
                dev = parent.dev
            file = Inode(dev, ino) if ino is not None else None
            self._model_trace.open_create(abspath, flags, mode, parent, file, gid, perms, pid, bytes(), fake_meta_hash, retval)

        # update mediator state
        if retval >= 0:
            file = assert_is_not_none(file)
            uid = assert_is_not_none(uid)
            gid = assert_is_not_none(gid)
            perms = assert_is_not_none(perms)
            if not self.mediator_state.do_exists(abspath):
                self.mediator_state.do_creat(abspath, file, uid, gid, perms, FileHash(meta_hash=fake_meta_hash))
            self.mediator_state.do_open(ProcFD(pid, retval), file)

    def creat(self, pathname: str, mode: int, pid: int,
              dev: Optional[int], ino: Optional[int],
              uid: Optional[int], gid: Optional[int],
              perms: Optional[int], retval: int):

        # append model trace
        abspath = self.mediator_state.normalize(pathname, pid)
        parent = self.mediator_state.get_ino(dirname(abspath))
        if dev is None:
            dev = parent.dev
        file = Inode(dev, ino) if ino is not None else None
        fake_meta_hash = calc_fake_meta_hash(uid, gid, perms)
        self._model_trace.creat(abspath, mode, parent, file, gid, perms, pid, bytes(), fake_meta_hash, retval)

        # update mediator state
        if retval >= 0:
            file = assert_is_not_none(file)
            uid = assert_is_not_none(uid)
            gid = assert_is_not_none(gid)
            perms = assert_is_not_none(perms)
            if not self.mediator_state.do_exists(abspath):
                self.mediator_state.do_creat(abspath, file, uid, gid, perms, FileHash(meta_hash=fake_meta_hash))
            self.mediator_state.do_open(ProcFD(pid, retval), file)

    def openat(self, dfd: int, pathname: str, flags: int, mode: int, pid: int,
               dev: Optional[int], ino: Optional[int],
               uid: Optional[int], gid: Optional[int],
               perms: Optional[int], retval: int):
        
        # append model trace
        if isabs(pathname):
            return self.open(pathname, flags, mode, pid, dev, ino, uid, gid, perms, retval)
        if dfd == -100:
            cwd_path = self.mediator_state.do_getcwd(pid)
        else:
            cwd_path = self.mediator_state.get_path(self.mediator_state.get_ino_of_fd(ProcFD(pid, dfd)))
        cwd = self.mediator_state.get_ino(cwd_path)
        abspath = join(cwd_path, pathname)
        parent = self.mediator_state.get_ino(dirname(abspath))
        fake_meta_hash = calc_fake_meta_hash(uid, gid, perms)
        if self.mediator_state.do_exists(abspath):
            file = self.mediator_state.get_ino(abspath) # it works if retval < 0 also
            self._model_trace.openat_exists(dfd, pathname, flags, parent, file, cwd, pid, retval)
        else:
            if dev is None:
                dev = parent.dev
            file = Inode(dev, ino) if ino is not None else None
            self._model_trace.openat_create(dfd, pathname, flags, mode, parent, file, gid, perms, cwd, pid, bytes(), fake_meta_hash, retval)

        # update mediator state
        if retval >= 0:            
            file = assert_is_not_none(file)
            uid = assert_is_not_none(uid)
            gid = assert_is_not_none(gid)
            perms = assert_is_not_none(perms)
            if not self.mediator_state.do_exists(abspath):
                self.mediator_state.do_creat(abspath, file, uid, gid, perms, FileHash(meta_hash=fake_meta_hash))
            self.mediator_state.do_open(ProcFD(pid, retval), file)

    def mkdir(self, pathname: str, mode: int, pid: int,
              dev: Optional[int], ino: Optional[int],
               uid: Optional[int], gid: Optional[int],
                perms: Optional[int], retval: int):

        # append model trace
        abspath = self.mediator_state.normalize(pathname, pid)
        parent = self.mediator_state.get_ino(dirname(abspath))
        if dev is None:
            dev = parent.dev
        folder = Inode(dev, ino) if ino is not None else None

        fake_meta_hash = calc_fake_meta_hash(uid, gid, perms)
        self._model_trace.mkdir(pathname, mode, parent, folder, gid, perms, pid, bytes(), fake_meta_hash, retval)

        # update mediator state
        if retval >= 0:
            folder = assert_is_not_none(folder)
            uid = assert_is_not_none(uid)
            gid = assert_is_not_none(gid)
            perms = assert_is_not_none(perms)
            self.mediator_state.do_mkdir(abspath, folder, uid, gid, perms, FileHash(bytes(), fake_meta_hash))

    def chmod(self, pathname: str, mode: int, pid: int,
              perms: Optional[int], metaHash: bytes, retval: int):

        # append model trace
        abspath = self.mediator_state.normalize(pathname, pid)
        parent = self.mediator_state.get_ino(dirname(abspath))
        file = self.mediator_state.get_ino(abspath)
        filestat = self.mediator_state.do_stat(file)

        # get cached or fake hashes if parameters are not passed 
        if not metaHash:
            stored_hash = self.mediator_state.get_real_hashes(file).meta_hash
            if not stored_hash or is_hash_fake(stored_hash):
                metaHash = calc_fake_meta_hash(filestat.st_uid, filestat.st_gid, perms)
            else:
                metaHash = stored_hash

        self._model_trace.chmod(pathname, mode, parent, file, perms, pid, metaHash, retval)

        # update mediator state
        if retval >= 0:
            perms = assert_is_not_none(perms)
            self.mediator_state.do_chmod(file, perms, metaHash)

    def fchmod(self, fd: int, mode: int, pid: int,
               perms: Optional[int], metaHash: bytes, retval: int):
        
        file = self.mediator_state.get_ino_of_fd(ProcFD(pid, fd))
        filestat = self.mediator_state.do_stat(file)

        # get cached or fake hashes if parameters are not passed 
        if not metaHash:
            stored_hash = self.mediator_state.get_real_hashes(file).meta_hash
            if not stored_hash or is_hash_fake(stored_hash):
                metaHash = calc_fake_meta_hash(filestat.st_uid, filestat.st_gid, perms)
            else:
                metaHash = stored_hash

        # append model trace
        self._model_trace.fchmod(fd, mode, perms, pid, metaHash, retval)

        # update mediator state
        if retval >= 0:
            perms = assert_is_not_none(perms)
            self.mediator_state.do_chmod(file, perms, metaHash)

    def chown(self, pathname: str, owner: int, group: int, pid: int,
              perms: Optional[int], metaHash: bytes, retval: int):

        # append model trace
        abspath = self.mediator_state.normalize(pathname, pid)
        parent = self.mediator_state.get_ino(dirname(abspath))
        file = self.mediator_state.get_ino(abspath)
        pre_uid = self.mediator_state.do_stat(file).st_uid
        pre_gid = self.mediator_state.do_stat(file).st_gid
        
        # get cached or fake hashes if parameters are not passed 
        if not metaHash:
            stored_hash = self.mediator_state.get_real_hashes(file).meta_hash
            if not stored_hash or is_hash_fake(stored_hash):
                metaHash = calc_fake_meta_hash(owner if owner != -1 else pre_uid, group if group != -1 else pre_gid, perms)
            else:
                metaHash = stored_hash
        
        self._model_trace.chown(pathname, owner, group, pre_uid, pre_gid, parent, file, perms, pid, metaHash, retval)

        # update mediator state
        if retval >= 0:
            perms = assert_is_not_none(perms)
            self.mediator_state.do_chown(file, owner, group, metaHash)
            self.mediator_state.do_chmod(file, perms, metaHash)

    def fchown(self, fd: int, owner: int, group: int, pid: int,
               perms: Optional[int], metaHash: bytes, retval: int):
    

        # append model trace
        file = self.mediator_state.get_ino_of_fd(ProcFD(pid, fd))
        pre_uid = self.mediator_state.do_stat(file).st_uid
        pre_gid = self.mediator_state.do_stat(file).st_gid

        # get cached or fake hashes if parameters are not passed 
        if not metaHash:
            stored_hash = self.mediator_state.get_real_hashes(file).meta_hash
            if not stored_hash or is_hash_fake(stored_hash):
                metaHash = calc_fake_meta_hash(owner if owner != -1 else pre_uid, group if group != -1 else pre_gid, perms)
            else:
                metaHash = stored_hash
        
        self._model_trace.fchown(fd, owner, group, pre_uid, pre_gid, perms, pid, metaHash, retval)

        # update mediator state
        if retval >= 0:
            perms = assert_is_not_none(perms)
            self.mediator_state.do_chown(file, owner, group, metaHash)
            self.mediator_state.do_chmod(file, perms, metaHash)

    def chdir(self, dir: str, pid: int, retval: int):
        
        # append model trace
        abspath = self.mediator_state.normalize(dir, pid)
        dir_ino = self.mediator_state.get_ino(abspath)
        self._model_trace.chdir(dir_ino, pid, retval)

        # update mediator state
        if retval >= 0:
            self.mediator_state.do_chdir(pid, abspath)

    def fchdir(self, fd: int, pid: int, retval: int):
        
        # append model trace
        self._model_trace.fchdir(fd, pid, retval)

        # update mediator state
        if retval >= 0:
            file = self.mediator_state.get_ino_of_fd(ProcFD(pid, fd))
            path = self.mediator_state.get_path(file)
            self.mediator_state.do_chdir(pid, path)

    # def getdents(self, fd: int):
    #     retval = run_syscall(f'getdents,{fd}', port=self.port)
    #     self.trace_consumer(self.trace_translator.translate_getdents(fd, self.pid, retval))

    def getxattr(self, pathname: str, name: str, size: int, pid: int,
                 value: Optional[bytes], retval: int):
        
        # append model trace
        abspath = self.mediator_state.normalize(pathname, pid)
        parent = self.mediator_state.get_ino(dirname(abspath))
        file = self.mediator_state.get_ino(abspath)
        self._model_trace.getxattr(pathname, name, size, parent, file, value, pid, retval)

    def setxattr(self, pathname: str, name: str, value: bytes, size: int, flags: int, pid: int, retval: int):

        # append model trace
        abspath = self.mediator_state.normalize(pathname, pid)
        parent = self.mediator_state.get_ino(dirname(abspath))
        file = self.mediator_state.get_ino(abspath)
        self._model_trace.setxattr(pathname, name, value, size, flags, parent, file, pid, retval)


    def link(self, oldname: str, newname: str, pid: int, retval: int):
        
        # append model trace
        absoldpath = self.mediator_state.normalize(oldname, pid)
        oldParent = self.mediator_state.get_ino(dirname(absoldpath))
        file = self.mediator_state.get_ino(absoldpath)
        absnewpath = self.mediator_state.normalize(newname, pid)
        newParent = self.mediator_state.get_ino(dirname(absnewpath))
        self._model_trace.link(oldname, newname, oldParent, file, newParent, pid, retval)

        # update mediator state
        if retval >= 0:
            self.mediator_state.do_link(absoldpath, absnewpath)

    def symlink(self, target: str, linkpath: str, pid: int,
                dev: Optional[int], ino: Optional[int], retval: int):
        
        # append model trace
        abstarget = self.mediator_state.normalize(target, pid)
        target_parent = self.mediator_state.get_ino(dirname(abstarget))
        abslinkpath = self.mediator_state.normalize(linkpath, pid)
        parent = self.mediator_state.get_ino(dirname(abslinkpath))
        if dev is None:
            dev = parent.dev
        file = Inode(dev, ino) if ino is not None else None
        self._model_trace.symlink(target, linkpath, target_parent, parent, file, pid, bytes(), bytes(), retval)

        # update mediator state
        # symlink is partially supported by model
        # if retval >= 0:
        #     self.mediator_state.do_creat(abslinkpath, file, uid, gid, perms)
    
    def execve(self, pathname: str, pid: int, retval: int):
        
        # append model trace
        argv = set[str]() # argv are not modelled yet
        envp = set[str]() # envp are not modelled yet
        abspath = self.mediator_state.normalize(pathname, pid)
        parent = self.mediator_state.get_ino(dirname(abspath))
        exeFile = self.mediator_state.get_ino(abspath)
        fds = set[int]() # O_CLOEXEC is not modelled yet
        self._model_trace.execve(pathname, argv, envp, fds, parent, exeFile, pid, retval)

    def close(self, fd: int, pid: int, contentHash: Optional[bytes], metaHash: Optional[bytes], retval: int):
        proc_fd = ProcFD(pid, fd)
        ino = self.mediator_state.get_ino_of_fd(proc_fd)

        # get cached hashes if parameters are not passed
        contentHash = contentHash or self.mediator_state.get_real_hashes(ino).content_hash
        metaHash = metaHash or self.mediator_state.get_real_hashes(ino).meta_hash

        # append model trace
        fds = [proc_fd] if all(p == pid for (p, pfd) in self.mediator_state.fd2ino if pfd == fd) else []

        # get ima/evm strings
        if proc_fd in self.mediator_state.fd2ino:
            stored = self.mediator_state.get_integrity_hashes(ino)
        else:
            stored = FileHash()
        # stored.content_hash = imaHash (старый хеш из IMAHash до этого вызова)
        # stored.meta_hash    = evmHash (старый хеш из EVMHash до этого вызова)
        self._model_trace.close(fd, fds, pid, stored.content_hash, stored.meta_hash, contentHash, metaHash, retval)

        # update mediator state
        if retval >= 0:
            self.mediator_state.do_close(ProcFD(pid, fd), FileHash(contentHash, metaHash))
        
    def exit(self, pid: int, retval: int):

        # append model trace
        fds = [ProcFD(pid, fd,)
               for p, fd in self.mediator_state.fd2ino if p == pid
               if all(p == pid for (p, pfd) in self.mediator_state.fd2ino if pfd == fd)]
        self._model_trace.exit(fds, pid, retval)

        # update mediator state
        self.mediator_state.do_exit(pid)
        
    def unlink(self, pathname: str, pid: int, retval: int):

        # append model trace
        abspath = self.mediator_state.normalize(pathname, pid)
        parent = self.mediator_state.get_ino(dirname(abspath))
        file = self.mediator_state.get_ino(abspath)
        files = [file] if self.mediator_state.do_stat(file).st_nlink == 1 else []
        self._model_trace.unlink(pathname, parent, file, files, pid, retval)

        # update mediator state
        if retval >= 0:
            self.mediator_state.do_remove(abspath)


    def rmdir(self, pathname: str, pid: int, retval: int):
        
        # append model trace
        abspath = self.mediator_state.normalize(pathname, pid)
        parent = self.mediator_state.get_ino(dirname(abspath))
        folder = self.mediator_state.get_ino(abspath)
        self._model_trace.rmdir(pathname, parent, folder, pid, retval)

        # update mediator state
        if retval >= 0:
            self.mediator_state.do_remove(abspath)

    def exit_group(self, retval: int):
        pass