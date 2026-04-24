"""
Checks permissions controlling in the file search algorithm (search for file by a full path).

There is a parent directory ("parent") and parent of the parent directory ("pparent").
"""

from os import O_CREAT, O_DIRECTORY, O_RDONLY, O_WRONLY
from os.path import join
from typing import Literal

from pytest import FixtureRequest, fixture

from tests.spec import LinuxTestSpec

@fixture(params=[False, True], ids=['pprN', 'pprY'])
def pparent_read(request: FixtureRequest):
    return request.param

@fixture(params=[False, True], ids=['ppxN', 'ppxY'])
def pparent_exec(request: FixtureRequest):
    return request.param

@fixture(params=[False, True], ids=['prN', 'prY'])
def parent_read(request: FixtureRequest):
    return request.param

@fixture(params=[False, True], ids=['pxN', 'pxY'])
def parent_exec(request: FixtureRequest):
    return request.param

@fixture
def pparent_mode(pparent_read: bool, pparent_exec: bool):
    return ','.join([
        'u+r' if pparent_read else 'u-r',
        'u+x' if pparent_exec else 'u-x'
    ])

@fixture
def parent_mode(parent_read: bool, parent_exec: bool):
    return ','.join([
        'u+r' if parent_read else 'u-r',
        'u+x' if parent_exec else 'u-x'
    ])

AccessKind = Literal['read', 'write']
@fixture(params=['read', 'write'])
def access_kind(request: FixtureRequest):
    return request.param

ObjectKind = Literal['file', 'dir']
@fixture(params=['file', 'dir'])
def object_kind(request: FixtureRequest):
    return request.param

def make_path_and(object_kind: ObjectKind, t: LinuxTestSpec, parent_mode: str, pparent_mode: str) -> str:
    t.make_user('user')
    t.make_dir('/_pparent', 'user', 'user', 0o777)
    t.make_dir('/_pparent/parent', 'user', 'user', 0o777)
    if object_kind == 'file':
        t.make_file('/_pparent/parent/obj', 'user', 'user', 0o777)
    elif object_kind == 'dir':
        t.make_dir('/_pparent/parent/obj', 'user', 'user', 0o777)
    t.add_setup(f'chmod {parent_mode} /_pparent/parent')
    t.add_setup(f'chmod {pparent_mode} /_pparent')
    return '/_pparent/parent/obj'


def test_open(t: LinuxTestSpec, object_kind: ObjectKind, access_kind: AccessKind, parent_mode: str, pparent_mode: str):

    pathname = make_path_and(object_kind, t, parent_mode, pparent_mode)

    if object_kind == 'file':
        if access_kind == 'read':
            flags = O_RDONLY
        elif access_kind == 'write':
            flags = O_WRONLY
    elif object_kind == 'dir':
        if access_kind == 'read':
            flags = O_RDONLY | O_DIRECTORY
        elif access_kind == 'write':
            pathname = join(pathname, 'f')
            flags = O_CREAT

    with t.make_program_and_run('user', 'user', umask=0o022) as child:
        child.open(pathname, flags, 0)


def test_creat(t: LinuxTestSpec, parent_mode: str, pparent_mode: str):

    pathname = make_path_and('dir', t, parent_mode, pparent_mode)
    with t.make_program_and_run('user', 'user', umask=0o022) as child:
        child.creat(join(pathname, 'f'), 0)


def test_mkdir(t: LinuxTestSpec, parent_mode: str, pparent_mode: str):

    pathname = make_path_and('dir', t, parent_mode, pparent_mode)
    with t.make_program_and_run('user', 'user', umask=0o022) as child:
        child.mkdir(join(pathname, 'd'), 0)


# operation = 'getdents' is not applied here

def test_getxattr(object_kind: ObjectKind, t: LinuxTestSpec, parent_mode: str, pparent_mode: str):

    pathname = make_path_and(object_kind, t, parent_mode, pparent_mode)
    t.add_setup(f'setfattr -n user.test -v 12345 {pathname}')
    with t.make_program_and_run('user', 'user', umask=0o022) as child:
        buf = child.bound_value_as_chararray(1024)
        child.getxattr(pathname, 'user.test', buf, 1024)


def test_setxattr(object_kind: ObjectKind, t: LinuxTestSpec, parent_mode: str, pparent_mode: str):

    pathname = make_path_and(object_kind, t, parent_mode, pparent_mode)
    t.add_setup(f'setfattr -n user.test -v ABC {pathname}')
    with t.make_program_and_run('user', 'user', umask=0o022) as child:
        child.setxattr(pathname, 'user.test', b'12345', len('12345'), 0)


def test_link(t: LinuxTestSpec, parent_mode: str, pparent_mode: str):

    pathname = make_path_and('dir', t, parent_mode, pparent_mode)
    t.make_file('/original', 'user', 'user', 0o777)
    with t.make_program_and_run('user', 'user', umask=0o022) as child:
        child.link('/original', join(pathname, 'link'))


# operation = "symlink" is partially supported by model

def test_chmod(object_kind: ObjectKind, t: LinuxTestSpec, parent_mode: str, pparent_mode: str):

    pathname = make_path_and(object_kind, t, parent_mode, pparent_mode)
    with t.make_program_and_run('user', 'user', umask=0o022) as child:
        child.chmod(pathname, 0o123)


# 'fchmod' is not applied here (search is applied to open() not fchmod())

def test_chown(object_kind: ObjectKind, t: LinuxTestSpec, parent_mode: str, pparent_mode: str):

    pathname = make_path_and(object_kind, t, parent_mode, pparent_mode)

    with t.make_program_and_run('user', 'user', umask=0o022,
                                runner='export USER=$(id -u user); <>') as child:
        uid = child.bound_value_as_uid_t(child.to_int(child.xgetenv('USER')))
        child.chown(pathname, uid, -1)


def test_execve(t: LinuxTestSpec, parent_mode: str, pparent_mode: str):

    pathname = make_path_and('file', t, parent_mode, pparent_mode)
    with t.make_program() as true_prog:
        true_prog.exit(0)
    true = t.compile(true_prog, pathname, make_file=False)
    t.add_setup(f'chmod +x {pathname}')
    with t.make_program_and_run('user', 'user', umask=0o022) as child:
        argv = child.bound_value_as_charparray(init = [pathname], prefix = 'argv')
        envp = child.bound_value_as_charparray(init = [], prefix = 'envp')
        child.execve(true, argv, envp)


def test_unlink_file(t: LinuxTestSpec, parent_mode: str, pparent_mode: str):

    pathname = make_path_and('dir', t, parent_mode, pparent_mode)
    removed = join(pathname, 'f')
    t.make_file(removed, 'user', 'user', 0o777)
    with t.make_program_and_run('user', 'user', umask=0o022) as child:
        child.unlink(removed)


def test_unlink_link(t: LinuxTestSpec, parent_mode: str, pparent_mode: str):

    pathname = make_path_and('dir', t, parent_mode, pparent_mode)
    removed = join(pathname, 'ln')
    t.make_file(removed, 'user', 'user', 0o777)
    t.add_setup(f'rm {removed}')
    t.make_file('/file', 'user', 'user', 0o777)
    t.add_setup(f'ln /file {removed}')
    with t.make_program_and_run('user', 'user', umask=0o022) as child:
        child.unlink(removed)


def test_rmdir(t: LinuxTestSpec, parent_mode: str, pparent_mode: str):

    pathname = make_path_and('dir', t, parent_mode, pparent_mode)
    removed = join(pathname, 'd')
    t.make_dir(removed, 'user', 'user', 0o777)
    with t.make_program_and_run('user', 'user', umask=0o022) as child:
        child.rmdir(removed)
