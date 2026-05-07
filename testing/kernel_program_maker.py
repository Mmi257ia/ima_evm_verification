from collections import defaultdict
from dataclasses import dataclass
from functools import reduce
import os
import stat
from typing import Callable, Dict, List, Optional, Union

from tests.spec import ProgramMakerTextProducer

@dataclass
class MonitoredExeFile:
    path: str


@dataclass
class Expression:
    text: str

ModeBits = {
    stat.S_ISUID: 'S_ISUID',
    stat.S_ISGID: 'S_ISGID',
    stat.S_ISVTX: 'S_ISVTX',
}

def mode2expr(mode: int) -> Expression:
    return Expression(f'0{(mode & 0o777):0o}' + ''.join([f'| {ModeBits[m]}' for m in ModeBits if (mode & m) != 0]))

OpenFlags = {
	os.O_RDONLY    : 'O_RDONLY',
	os.O_WRONLY    : 'O_WRONLY',
	os.O_RDWR      : 'O_RDWR',
	os.O_CREAT     : 'O_CREAT',
	os.O_EXCL      : 'O_EXCL',
	os.O_NOCTTY    : 'O_NOCTTY',
	os.O_TRUNC     : 'O_TRUNC',
	os.O_APPEND    : 'O_APPEND',
	os.O_NONBLOCK  : 'O_NONBLOCK',
	os.O_DSYNC     : 'O_DSYNC',
	# FASYNC      : 'FASYNC',
	os.O_DIRECT    : 'O_DIRECT',
	# os.O_LARGEFILE : 'O_LARGEFILE', # os.O_LARGEFILE == 0 and it will be included into ANY flags! 
	os.O_DIRECTORY : 'O_DIRECTORY',
	os.O_NOFOLLOW  : 'O_NOFOLLOW',
	os.O_NOATIME   : 'O_NOATIME',
	os.O_CLOEXEC   : 'O_CLOEXEC',
	os.O_PATH      : 'O_PATH',
    os.O_TMPFILE   : 'O_TMPFILE',
}

def openflags2expr(flags: int) -> Expression:
    # check: if any bit of "e" is 1, then it has been translated
    assert (flags & ~(reduce(lambda x, y: (x | y), OpenFlags.keys(), 0))) == 0

    # lower 2 bits of flags have special meaning
    assert os.O_RDONLY == 0
    if (flags & (os.O_WRONLY | os.O_RDWR)) == (os.O_WRONLY | os.O_RDWR):
        e = OpenFlags[os.O_RDWR]
        flags1 = flags & ~os.O_WRONLY & ~os.O_RDWR
    if (flags & os.O_WRONLY) != 0:
        e = OpenFlags[os.O_WRONLY]
        flags1 = flags & ~os.O_WRONLY
    elif (flags & os.O_RDWR) != 0:
        e = OpenFlags[os.O_RDWR]
        flags1 = flags & ~os.O_RDWR
    else:
        e = OpenFlags[os.O_RDONLY]
        flags1 = flags

    e = e + (''.join([' | ' + OpenFlags[f] for f in OpenFlags
                      if (flags1 & f) == f and f not in {os.O_RDONLY, os.O_WRONLY, os.O_RDWR}]))
    return Expression(e)

XattrFlags = {
    os.XATTR_CREATE: 'XATTR_CREATE',
    os.XATTR_REPLACE: 'XATTR_REPLACE',
}

def xattrflags2expr(flags: int) -> Expression:
    if flags == 0:
        return Expression('0')
    e = (' | '.join([XattrFlags[f] for f in XattrFlags if (flags & f) != 0]))
    # check: if any bit of "e" is 1, then it has been translated
    assert (flags & ~(reduce(lambda x, y: (x | y), XattrFlags.keys(), 0))) == 0
    return Expression(e)

def s(arg: Union[str, Expression]) -> str:
    if isinstance(arg, str):
        assert '"' not in arg
        return f'"{arg}"'
    else:
        return arg.text


class KernelProgramMaker(ProgramMakerTextProducer):

    # NB: all number-like parameters with type str is c-expressions

    def __init__(self):
        self.includes = set[str]()
        self.main_lines = list[str]()
        self._vars_count: Dict[str, int] = defaultdict(int)
    
    def get_text(self):
        nl = '\n'
        return f'''
            #define _GNU_SOURCE
            #define STRINGIZE(x) STRINGIZE2(x)
            #define STRINGIZE2(x) #x
            #define LINE_STRING STRINGIZE(__LINE__)
            {nl.join(self.includes)}
            int main(void) {{
                {nl.join(self.main_lines)}
                return 0;
            }}'''
    
    def _bound_value(self, type: Callable[[str], str], prefix: str = 'var', init: Optional[str] = None):
        name = f'{prefix}{self._vars_count[prefix]}'
        self._vars_count[prefix] += 1
        self.main_lines.append(f'{type(name)} {init or ""};')
        return Expression(name)

    def bound_value_as_uid_t(self, init: Optional[Expression] = None, prefix: str = 'uid'):
        return self._bound_value(
            type = lambda uid: f'uid_t {uid}',
            prefix = prefix,
            init = f'= {init.text}' if init is not None else None)

    def bound_value_as_int(self, init: Optional[int] = None, prefix: str = 'num'):
        return self._bound_value(
            type = lambda num: f'int {num}',
            prefix = prefix,
            init = f'= {init}' if init is not None else None)

    def bound_value_as_charparray(self, init: Optional[List[str]] = None, prefix: str = 'strings'):
        assert init is None or all('"' not in s for s in init)
        q = '"'
        return self._bound_value(
            type = lambda strings: f'char *{strings}[]',
            prefix = prefix,
            init = f' = {{{"".join([f"{q}{s}{q}, " for s in init])}NULL}}' if init is not None else None)

    def bound_value_as_chararray(self, size: Optional[int] = None, init: Optional[str] = None, prefix: str = 'buf'):
        return self._bound_value(
            type = lambda string: f'char {string}[{str(size) if size is not None else ""}]',
            prefix = prefix,
            init = f' = "{init}"' if init is not None else None)


    def xgetenv(self, var: str):
        assert '"' not in var
        self.includes.add('#include <stdlib.h>')
        return Expression(f'''({{
            char *val = getenv("{var}");
            if (!val) exit(15);
            val;
            }})''')

    def to_int(self, arg: Expression, base: int = 10):
        self.includes.add('#include <stdlib.h>')
        return Expression(f'strtol({arg.text}, 0, {base})')

    def _make_charbuf(self, var: str, value: str):
        if '"' in value:
            raise ValueError('Unsupported string value')
        self.includes.add('#include <string.h>')
        return f'char {var}[{len(value) + 1}]; strcpy({var}, "{value}");'

    def _make_pathname(self, pathname: str):
        return self._make_charbuf('pathname', pathname)


    def open(self, pathname: str, flags: int, mode: int, fatal: bool = False):
        assert '"' not in pathname

        self.includes.add('#include <fcntl.h>')
        self.includes.add('#include <unistd.h>')
        self.includes.add('#include <sys/syscall.h>')
        self.includes.add('#include <sys/stat.h>')
        self.includes.add('#include <sys/types.h>')
        flags_expr = openflags2expr(flags)
        syscall = f'syscall(SYS_open, pathname, {flags_expr.text}, 0{mode:0o})'

        fd = self.bound_value_as_int(prefix='fd')

        if fatal:

            self.includes.add('#include <stdio.h>')
            self.main_lines.append(f'{{ {self._make_pathname(pathname)} if (({fd.text} = {syscall}) < 0) {{ perror(__FILE__ ":" LINE_STRING ":" "{pathname}"); return 2; }} }}')

        else:

            self.main_lines.append(f'{{ {self._make_pathname(pathname)} {fd.text} = {syscall}; }}')

        return fd

    def openat(self, dirfd: Expression, pathname: str, flags: int, mode: int, fatal: bool = False):
        assert '"' not in pathname

        self.includes.add('#include <fcntl.h>')
        self.includes.add('#include <unistd.h>')
        self.includes.add('#include <sys/syscall.h>')
        self.includes.add('#include <sys/stat.h>')
        self.includes.add('#include <sys/types.h>')
        flags_expr = openflags2expr(flags)
        syscall = f'syscall(SYS_openat, {dirfd.text}, pathname, {flags_expr.text}, 0{mode:0o})'

        fd = self.bound_value_as_int(prefix='fd')

        if fatal:

            self.includes.add('#include <stdio.h>')
            self.main_lines.append(f'{{ {self._make_pathname(pathname)} if (({fd.text} = {syscall}) < 0) {{ perror(__FILE__ ":" LINE_STRING ":" "{pathname}"); return 2; }} }}')

        else:

            self.main_lines.append(f'{{ {self._make_pathname(pathname)} {fd.text} = {syscall}; }}')

        return fd

    def creat(self, pathname: str, mode: int, fatal: bool = False):
        assert '"' not in pathname

        self.includes.add('#include <unistd.h>')
        self.includes.add('#include <sys/syscall.h>')
        # syscall = f'syscall(SYS_creat, "{pathname}", 0{mode:0o})' # bpf_probe_read_str returns -EFAULT for .rodata pathname
            # so we use stack-allocated buffer instead of statically-allocated buffer
        syscall = f'syscall(SYS_creat, pathname, 0{mode:0o})'

        fd = self.bound_value_as_int(prefix='fd')

        if fatal:

            self.includes.add('#include <stdio.h>')
            self.main_lines.append(f'{{ {self._make_pathname(pathname)} if (({fd.text} = {syscall}) < 0) {{ perror(__FILE__ ":" LINE_STRING ":" "{pathname}"); return 2; }} }}')

        else:

            self.main_lines.append(f'{{ {self._make_pathname(pathname)} {fd.text} = {syscall}; }}')
            # self.main_lines.append(f'{fd.text} = {syscall};')

        return fd

    def mkdir(self, pathname: str, mode: int, fatal: bool = False):
        assert '"' not in pathname

        self.includes.add('#include <unistd.h>')
        self.includes.add('#include <sys/syscall.h>')
        syscall = f'syscall(SYS_mkdir, pathname, 0{mode:0o})'

        if fatal:

            self.includes.add('#include <stdio.h>')
            self.main_lines.append(f'{{ {self._make_pathname(pathname)} if ({syscall} != 0) {{ perror(__FILE__ ":" LINE_STRING ":" "mkdir"); return 2;}} }}')
        
        else:

            self.includes.add('#include <string.h>')
            self.main_lines.append(f'{{ {self._make_pathname(pathname)} {syscall}; }}')

    def chmod(self, pathname: str, mode: int, fatal: bool = False):
        assert '"' not in pathname

        self.includes.add("#include <unistd.h>")
        self.includes.add("#include <sys/syscall.h>")
        self.includes.add("#include <sys/stat.h>")
        syscall = f'syscall(SYS_chmod, pathname, 0{mode:0o})'

        if fatal:

            self.includes.add('#include <stdio.h>')
            self.main_lines.append(f'{{ {self._make_pathname(pathname)} if ({syscall} != 0) {{ perror(__FILE__ ":" LINE_STRING ":" "chmod"); return 2;}} }}')
        
        else:

            self.main_lines.append(f'{{ {self._make_pathname(pathname)} {syscall}; }}')

    def fchmod(self, fd: Expression, mode: int, fatal: bool = False):
        self.includes.add("#include <unistd.h>")
        self.includes.add("#include <sys/syscall.h>")
        self.includes.add("#include <sys/stat.h>")
        syscall = f'syscall(SYS_fchmod, {fd.text}, 0{mode:0o})'

        if fatal:

            self.includes.add('#include <stdio.h>')
            self.main_lines.append(f'if ({syscall} != 0) {{ perror(__FILE__ ":" LINE_STRING ":" "fchmod"); return 2; }}')
        
        else:

            self.main_lines.append(f'{syscall};')


    def chdir(self, pathname: str, fatal: bool = False):
        assert '"' not in pathname

        self.includes.add("#include <unistd.h>")
        self.includes.add("#include <sys/syscall.h>")
        syscall = f'syscall(SYS_chdir, pathname)'

        if fatal:

            self.includes.add('#include <stdio.h>')
            self.main_lines.append(f'{{ {self._make_pathname(pathname)} if ({syscall} != 0) {{ perror(__FILE__ ":" LINE_STRING ":" "chdir"); return 2;}} }}')
        
        else:

            self.main_lines.append(f'{{ {self._make_pathname(pathname)} {syscall}; }}')

    def fchdir(self, fd: Expression, fatal: bool = False):
        self.includes.add("#include <unistd.h>")
        self.includes.add("#include <sys/syscall.h>")
        syscall = f'syscall(SYS_fchdir, {fd.text})'

        if fatal:

            self.includes.add('#include <stdio.h>')
            self.main_lines.append(f'if ({syscall} != 0) {{ perror(__FILE__ ":" LINE_STRING ":" "fchdir"); return 2; }}')
        
        else:

            self.main_lines.append(f'{syscall};')

    def chown(self, pathname: str, uid: Expression, gid: int, fatal: bool = False):
        assert '"' not in pathname

        self.includes.add("#include <unistd.h>")
        self.includes.add("#include <sys/syscall.h>")
        syscall = f'syscall(SYS_chown, pathname, {uid.text}, {gid})'

        if fatal:

            self.includes.add('#include <stdio.h>')
            self.main_lines.append(f'{{ {self._make_pathname(pathname)} if ({syscall} != 0) {{ perror(__FILE__ ":" LINE_STRING ":" "chown"); return 2;}} }}')
        
        else:

            self.main_lines.append(f'{{ {self._make_pathname(pathname)} {syscall}; }}')

    def fchown(self, fd: Expression, uid: Expression, gid: int, fatal: bool = False):
        self.includes.add("#include <unistd.h>")
        self.includes.add("#include <sys/syscall.h>")
        syscall = f'syscall(SYS_fchown, {fd.text}, {uid.text}, {gid})'

        if fatal:

            self.includes.add('#include <stdio.h>')
            self.main_lines.append(f'if ({syscall} != 0) {{ perror(__FILE__ ":" LINE_STRING ":" "fchown"); return 2; }}')
        
        else:

            self.main_lines.append(f'{syscall};')

    def getxattr(self, path: str, name: str, value: Expression, size: int, fatal: bool = False):
        assert '"' not in path
        assert '"' not in name

        self.includes.add("#include <unistd.h>")
        self.includes.add("#include <sys/types.h>")
        self.includes.add("#include <sys/xattr.h>")
        self.includes.add("#include <sys/syscall.h>")
        syscall = f'syscall(SYS_getxattr, path, name, {value.text}, {size})'

        if fatal:

            self.includes.add('#include <stdio.h>')
            self.main_lines.append(f'{{ {self._make_charbuf("path", path)} {self._make_charbuf("name", name)} if ({syscall} != 0) {{ perror(__FILE__ ":" LINE_STRING ":" "getxattr"); return 2;}} }}')
        
        else:

            self.main_lines.append(f'{{ {self._make_charbuf("path", path)} {self._make_charbuf("name", name)} {syscall}; }}')

    def setxattr(self, path: str, name: str, value: bytes, size: int, flags: int, fatal: bool = False):
        assert '"' not in path
        assert '"' not in name
        self.includes.add("#include <unistd.h>")
        self.includes.add("#include <sys/types.h>")
        self.includes.add("#include <sys/xattr.h>")
        self.includes.add("#include <sys/syscall.h>")
        flags_expr = xattrflags2expr(flags)
        value_literal = ''.join(f'\\x{v:0x}' for v in value)
        syscall = f'syscall(SYS_setxattr, path, name, value_literal, {size}, {flags_expr.text})'

        if fatal:

            self.includes.add('#include <stdio.h>')
            self.main_lines.append(f'{{ {self._make_charbuf("path", path)} {self._make_charbuf("name", name)} {self._make_charbuf("value_literal", value_literal)} if ({syscall} != 0) {{ perror(__FILE__ ":" LINE_STRING ":" "setxattr"); return 2;}} }}')

        else:
 
             self.main_lines.append(f'{{ {self._make_charbuf("path", path)} {self._make_charbuf("name", name)} {self._make_charbuf("value_literal", value_literal)} {syscall}; }}')

    def execve(self, exeFile: MonitoredExeFile, argv: Expression, envp: Expression, fatal: bool = False):
        assert '"' not in exeFile.path
        self.includes.add("#include <unistd.h>")
        self.includes.add("#include <sys/syscall.h>")
        syscall = f'syscall(SYS_execve, path, {argv.text}, {envp.text})'

        if fatal:
 
            self.includes.add('#include <stdio.h>')
            self.main_lines.append(f'{{ {self._make_charbuf("path", exeFile.path)} {syscall}; perror(__FILE__ ":" LINE_STRING ":" "{exeFile.path}"); return 2; }}')
 
        else:
 
             self.main_lines.append(f'{{ {self._make_charbuf("path", exeFile.path)} {syscall}; }}')

    def link(self, oldpath: str, newpath: str, fatal: bool = False):
        assert '"' not in oldpath
        assert '"' not in newpath
        self.includes.add("#include <unistd.h>")
        self.includes.add("#include <sys/syscall.h>")
        syscall = f'syscall(SYS_link, oldpath, newpath)'
        
        if fatal:
 
            self.includes.add('#include <stdio.h>')
            self.main_lines.append(f'{{ {self._make_charbuf("oldpath", oldpath)} {self._make_charbuf("newpath", newpath)} if ({syscall} != 0) {{ perror(__FILE__ ":" LINE_STRING ":" "link"); return 2;}} }}')
 
        else:

             self.main_lines.append(f'{{ {self._make_charbuf("oldpath", oldpath)} {self._make_charbuf("newpath", newpath)} {syscall}; }}')

    def unlink(self, pathname: str, fatal: bool = False):
        assert '"' not in pathname

        self.includes.add("#include <unistd.h>")
        self.includes.add("#include <sys/syscall.h>")
        syscall = f'syscall(SYS_unlink, pathname)'

        if fatal:

            self.includes.add('#include <stdio.h>')
            self.main_lines.append(f'{{ {self._make_pathname(pathname)} if ({syscall} != 0) {{ perror(__FILE__ ":" LINE_STRING ":" "unlink"); return 2;}} }}')
        
        else:

             self.main_lines.append(f'{{ {self._make_pathname(pathname)} {syscall}; }}')

    def rmdir(self, pathname: str, fatal: bool = False):
        assert '"' not in pathname

        self.includes.add("#include <unistd.h>")
        self.includes.add("#include <sys/syscall.h>")
        syscall = f'syscall(SYS_rmdir, pathname)'

        if fatal:

            self.includes.add('#include <stdio.h>')
            self.main_lines.append(f'{{ {self._make_pathname(pathname)} if ({syscall} != 0) {{ perror(__FILE__ ":" LINE_STRING ":" "rmdir"); return 2;}} }}')
        
        else:

             self.main_lines.append(f'{{ {self._make_pathname(pathname)} {syscall}; }}')

    def close(self, fd: Expression, fatal: bool = False):
        self.includes.add('#include <unistd.h>')
        self.includes.add('#include <sys/syscall.h>')
        syscall = f'syscall(SYS_close, {fd.text})'

        if fatal:

            self.includes.add('#include <stdio.h>')
            self.main_lines.append(f'if ({syscall} != 0) {{ perror(__FILE__ ":" LINE_STRING ":" "close"); return 2; }}')
        
        else:

            self.main_lines.append(f'{syscall};')

    def exit(self, status: int):
        self.includes.add('#include <unistd.h>')
        self.includes.add('#include <sys/syscall.h>')
        self.main_lines.append(f'syscall(SYS_exit, {status});')
