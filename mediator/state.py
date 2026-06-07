from dataclasses import dataclass
from os.path import isabs, join
from typing import Literal, NamedTuple
from enum import Enum

class Inode(NamedTuple):
    dev: int
    ino: int

class ProcFD(NamedTuple):
    proc: int
    fd: int

class FileHash(NamedTuple):
    content_hash: bytes = bytes()
    meta_hash: bytes = bytes()

@dataclass
class FileStat:
    st_uid: int
    st_gid: int
    st_mode: int
    st_nlink: int
    kind: Literal["file", "folder"]

class ImaEvmMode(Enum):
    OFF = 'off'
    FIX = 'fix'
    ENFORCE = 'enforce'

class MediatorState:
    
    def __init__(self, root: Inode):
        self.cwd = dict[int, str]()
        self.path2ino = {'/': root} # path |-> (dev, ino)
        self.fd2ino = dict[ProcFD, Inode]()  # (proc, fd) |-> (dev, ino)
        self.stats = dict[Inode, FileStat]() # (dev, ino) |-> stat
        self.ima_mode: ImaEvmMode = ImaEvmMode.OFF
        self.evm_mode: ImaEvmMode = ImaEvmMode.OFF
        self.real_hashes = dict[Inode, FileHash]()  # (dev, ino) |-> (content_hash, meta_hash)
        self.intergity_hashes = dict[Inode, FileHash]()  # (dev, ino) |-> (ima_hash, evm_hash)

    def do_getcwd(self, proc: int) -> str:
        if proc == 0:
            return '/'
        else:
            return self.cwd[proc]

    def do_chdir(self, proc: int, path: str):
        if not isabs(path):
            raise ValueError('Relative cwd')
        self.cwd[proc] = path
    
    def do_open(self, fd: ProcFD, file: Inode):
        if fd in self.fd2ino:
            raise ValueError('Duplicate open')
        self.fd2ino[fd] = file
    
    def do_close(self, fd: ProcFD, hashes: FileHash):
        ino = self.fd2ino[fd]
        del self.fd2ino[fd]
        if ino not in self.fd2ino.values() and ino not in self.path2ino.values():
            del self.stats[ino]

        self.do_set_real_hashes(ino, hashes)
        if self.evm_mode is ImaEvmMode.FIX and self.ima_mode is ImaEvmMode.FIX and hashes:     # TODO when different
            self.do_set_integrity_hashes(ino, hashes)

    def do_exit(self, proc: int):
        fds = [fd for fd in self.fd2ino if fd.proc == proc]
        for fd in fds:
            ino = self.get_ino_of_fd(fd)
            hashes = self.get_real_hashes(ino)
            self.do_close(fd, hashes)       # TODO exit has no info about new hashes, but its okay ig?
    
    def do_creat(self, path: str, file: Inode, uid: int, gid: int, perms: int, hashes: FileHash):
        if not isabs(path):
            raise ValueError('Relative path')
        self.path2ino[path] = file
        self.stats[file] = FileStat(st_uid=uid, st_gid=gid, st_mode=perms, st_nlink=1, kind="file")
        self.do_set_real_hashes(file, hashes)

    def do_mkdir(self, path: str, folder: Inode, uid: int, gid: int, perms: int, hashes: FileHash):
        if not isabs(path):
            raise ValueError('Relative path')
        self.path2ino[path] = folder
        self.stats[folder] = FileStat(st_uid=uid, st_gid=gid, st_mode=perms, st_nlink=1, kind="folder")
        self.do_set_real_hashes(folder, hashes)

    def do_chown(self, file: Inode, uid: int, gid: int, meta_hash: bytes):
        self.stats[file].st_uid = uid
        self.stats[file].st_gid = gid
        self.do_set_meta_hash(file, meta_hash)

    def do_chmod(self, file: Inode, perms: int, meta_hash: bytes):
        self.stats[file].st_mode = perms
        self.do_set_meta_hash(file, meta_hash)

    def do_link(self, path: str, newpath: str):
        if not isabs(path):
            raise ValueError('Relative path')
        if not isabs(newpath):
            raise ValueError('Relative newpath')
        if path == newpath:
            raise ValueError('Equal paths')
        if self.do_exists(newpath):
            raise ValueError('Exists newpath')
        self.stats[self.path2ino[path]].st_nlink += 1
        self.path2ino[newpath] = self.path2ino[path]
    
    def do_remove(self, path: str):
        ino = self.path2ino[path]
        del self.path2ino[path]
        if ino not in self.fd2ino.values() and ino not in self.path2ino.values():
            del self.stats[ino]
        del self.real_hashes[ino]   # should always be
        if ino in self.intergity_hashes:
            del self.intergity_hashes[ino]
    
    def do_exists(self, path: str) -> bool:
        if not isabs(path):
            raise ValueError('Relative path')
        return path in self.path2ino

    def normalize(self, path: str, proc: int) -> str:
        if isabs(path):
            return path
        return join(self.do_getcwd(proc), path)
    
    def get_ino(self, path: str) -> Inode:
        if not isabs(path):
            raise ValueError('Relative path')
        return self.path2ino[path]
    
    def get_ino_of_fd(self, fd: ProcFD) -> Inode:
        return self.fd2ino[fd]
    
    def get_path(self, file: Inode) -> str:
        return next(path for path, ino in self.path2ino.items() if ino == file)

    def do_stat(self, ino: Inode) -> FileStat:
        return self.stats[ino]
    
    def get_integrity_hashes(self, file: Inode) -> FileHash:
        return self.intergity_hashes.get(file, FileHash())  # returns default if no ima/evm strings are stored

    def get_real_hashes(self, file: Inode) -> FileHash:
        return self.real_hashes.get(file, FileHash())  # returns default if no content/meta hashes are stored TODO 
    
    def do_set_integrity_hashes(self, file: Inode, hashes: FileHash):
        self.intergity_hashes[file] = hashes
    
    def do_set_real_hashes(self, file: Inode, hashes: FileHash):
        self.real_hashes[file] = hashes

    # def do_set_ima_hash(self, file: Inode, hash: bytes):
    #     cur_hashes = self.intergity_hashes.get(file)
    #     if cur_hashes:
    #         self.intergity_hashes[file] = FileHash(hash, cur_hashes.meta_hash)
    #     else:
    #         raise ValueError()
    
    # def do_set_evm_hash(self, file: Inode, hash: bytes):
    #     cur_hashes = self.intergity_hashes.get(file)
    #     if cur_hashes:
    #         self.intergity_hashes[file] = FileHash(cur_hashes.content_hash, hash)
    #     else:
    #         raise ValueError()

    # def do_set_content_hash(self, file: Inode, hash: bytes):
    #     cur_hashes = self.real_hashes.get(file)
    #     if cur_hashes:
    #         self.real_hashes[file] = FileHash(hash, cur_hashes.meta_hash)
    #     else:
    #         raise ValueError()
    
    def do_set_meta_hash(self, file: Inode, hash: bytes):
        cur_hashes = self.real_hashes.get(file)
        if cur_hashes:
            self.real_hashes[file] = FileHash(cur_hashes.content_hash, hash)
        else:
            raise ValueError()

    def do_switch_ima_mode(self, ima_mode: ImaEvmMode):
        self.ima_mode = ima_mode
    
    def do_switch_evm_mode(self, evm_mode: ImaEvmMode):
        self.evm_mode = evm_mode
