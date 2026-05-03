from contextlib import contextmanager
from typing import Any, Iterator, Optional, Protocol


class ProgramMaker(Protocol):

    def bound_value_as_uid_t(self, init: Any = None, prefix: str = "uid") -> Any:
        ...

    def bound_value_as_int(self, init: Any = None, prefix: str = "num") -> Any:
        ...

    def bound_value_as_charparray(self, init: Any = None, prefix: str = "args") -> Any:
        ...

    def bound_value_as_chararray(self, size: Any, init: Any = None, prefix: str = "buf") -> Any:
        ...

    def xgetenv(self, var: str) -> Any:
        ...

    def to_int(self, arg: Any, base: int = 10) -> Any:
        ...

    def open(self, pathname: str, flags: int, mode: int, fatal: bool = False) -> Any:
        ...

    def openat(self, dirfd: Any, pathname: str, flags: int, mode: int, fatal: bool = False) -> Any:
        ...

    def creat(self, pathname: str, mode: int, fatal: bool = False) -> Any:
        ...

    def mkdir(self, pathname: str, mode: int, fatal: bool = False) -> Any:
        ...

    def chmod(self, pathname: str, mode: int, fatal: bool = False) -> Any:
        ...

    def fchmod(self, fd: Any, mode: int, fatal: bool = False) -> Any:
        ...

    def chdir(self, pathname: str, fatal: bool = False) -> Any:
        ...

    def fchdir(self, fd: Any, fatal: bool = False) -> Any:
        ...

    def chown(self, pathname: str, uid: Any, gid: int, fatal: bool = False) -> Any:
        ...

    def fchown(self, fd: Any, uid: Any, gid: int, fatal: bool = False) -> Any:
        ...

    def getxattr(self, path: str, name: str, value: Any, size: int, fatal: bool = False) -> Any:
        ...

    def setxattr(self, path: str, name: str, value: bytes, size: int, flags: int, fatal: bool = False) -> Any:
        ...

    def execve(self, exeFile: Any, argv: Any, envp: Any, fatal: bool = False) -> Any:
        ...

    def link(self, oldpath: str, newpath: str, fatal: bool = False) -> Any:
        ...

    def unlink(self, pathname: str, fatal: bool = False) -> Any:
        ...

    def rmdir(self, pathname: str, fatal: bool = False) -> Any:
        ...

    def close(self, fd: Any, fatal: bool = False) -> Any:
        ...

    def exit(self, status: int) -> Any:
        ...


class TextProducer(Protocol):

    def get_text(self) -> str:
        ...


class ProgramMakerTextProducer(ProgramMaker, TextProducer):

    pass


class LinuxTestSpec(Protocol):

    def setup_ima_policy(self,
                         fowner_uid: str) -> None:
        ...

    def make_user(self,
                user: str,
                supplementary_groups: Optional[list[str]] = None) -> None:
        ...

    def make_group(self,
                   group: str) -> None:
        ...

    def make_file(self,
                  path: str,
                  owner: str,
                  group: str,
                  mode: int) -> None:
        ...

    def make_dir(self,
                 path: str,
                 owner: str,
                 group: str,
                 mode: int) -> None:
        ...

    def add_setup(self, setup_cmd: str) -> Any:
        ...

    @contextmanager
    def make_program(self) -> Iterator[ProgramMakerTextProducer]:
        ...

    def compile(self, program_maker: TextProducer, path: str, make_file: bool=True) -> Any:
        ...

    def run(self, exeFile: Any, user: str, group: str, umask: int, runner: str, before_run: str|None, after_run: str|None) -> None:
        ...

    @contextmanager
    def make_program_and_run(self, user: str, group: str, umask: int, runner: str = '<>', make_file: bool=True, before_run: str|None=None, after_run: str|None=None) -> Iterator[ProgramMaker]:
        ...
