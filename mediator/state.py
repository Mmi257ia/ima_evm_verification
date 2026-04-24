from dataclasses import dataclass
from os.path import isabs, join
from typing import Literal, NamedTuple

class Inode(NamedTuple):
    dev: int
    ino: int

class ProcFD(NamedTuple):
    proc: int
    fd: int

@dataclass
class FileStat:
    st_uid: int
    st_gid: int
    st_mode: int
    st_nlink: int
    kind: Literal["file", "folder"]

class MediatorState:
    
    def __init__(self, root: Inode):
        self.cwd = dict[int, str]()
        self.path2ino = {'/': root} # path |-> (dev, ino)
        self.fd2ino = dict[ProcFD, Inode]()  # (proc, fd) |-> (dev, ino)
        self.stats = dict[Inode, FileStat]() # (dev, ino) |-> stat

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
    
    def do_close(self, fd: ProcFD):
        ino = self.fd2ino[fd]
        del self.fd2ino[fd]
        if ino not in self.fd2ino.values() and ino not in self.path2ino.values():
            del self.stats[ino]
    
    def do_exit(self, proc: int):
        fds = [fd for fd in self.fd2ino if fd.proc == proc]
        for fd in fds:
            self.do_close(fd)
    
    def do_creat(self, path: str, file: Inode, uid: int, gid: int, perms: int):
        if not isabs(path):
            raise ValueError('Relative path')
        self.path2ino[path] = file
        self.stats[file] = FileStat(st_uid=uid, st_gid=gid, st_mode=perms, st_nlink=1, kind="file")

    def do_mkdir(self, path: str, folder: Inode, uid: int, gid: int, perms: int):
        if not isabs(path):
            raise ValueError('Relative path')
        self.path2ino[path] = folder
        self.stats[folder] = FileStat(st_uid=uid, st_gid=gid, st_mode=perms, st_nlink=1, kind="folder")

    def do_chown(self, file: Inode, uid: int, gid: int):
        self.stats[file].st_uid = uid
        self.stats[file].st_gid = gid

    def do_chmod(self, file: Inode, perms: int):
        self.stats[file].st_mode = perms

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