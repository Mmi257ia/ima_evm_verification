"""
Does syscalls requiring chain of other syscalls
"""

from os import O_CREAT, O_DIRECTORY, O_RDONLY, O_TRUNC, O_WRONLY
from pytest import fixture, FixtureRequest

from tests.spec import LinuxTestSpec

@fixture(params=[0o577, 0o777], ids=['writeN', 'writeY'])
def wmode(request: FixtureRequest):
    return request.param

@fixture(params=[0o377, 0o677], ids=['readN', 'readY'])
def rmode(request: FixtureRequest):
    return request.param

@fixture(params=[0o577, 0o677, 0o777], ids=['wN', 'xN', 'wxY'])
def wxmode(request: FixtureRequest):
    return request.param


def test_chdir_creat_unlink_mkdir(t: LinuxTestSpec):

    t.make_user('user')
    t.make_dir('/parent', 'user', 'user', 0o777)
    with t.make_program_and_run('user', 'user', umask=0o022) as child:
        child.chdir('/parent', fatal=True)
        fd = child.creat('new', 0, fatal=True)
        child.close(fd, fatal=True)
        child.unlink('new', fatal=True)
        child.mkdir('new', 0)

def test_chdir_mkdir_chdir_open(t: LinuxTestSpec, wmode: int):

    t.make_user('user')
    t.make_dir('/parent', 'user', 'user', 0o777)
    with t.make_program_and_run(user='user', group='user', umask=0o022) as child:
        child.chdir('/parent', fatal=True)
        child.mkdir('dir', wmode, fatal=True)
        child.chdir('dir', fatal=True)
        child.open('file', O_CREAT, 0o600)


def test_chdir_mkdir_rmdir_open(t: LinuxTestSpec):

    t.make_user('user')
    t.make_dir('/parent', owner='user', group='user', mode=0o777)
    with t.make_program_and_run(user='user', group='user', umask=0o022) as child:
        child.chdir('/parent', fatal=True)
        child.mkdir('new', 0, fatal=True)
        child.rmdir('new', fatal=True)
        child.open('new', O_CREAT, 0o600)


def test_chdir_open(t: LinuxTestSpec, rmode:int):

    t.make_user('user')
    t.make_dir('/parent', owner='user', group='user', mode=0o777)
    t.make_file('/parent/file', owner='user', group='user', mode=rmode)
    with t.make_program_and_run(user='user', group='user', umask=0o022) as child:
        child.chdir('/parent', fatal=True)
        child.open('file', O_RDONLY, 0)

# the following test requires fork() support in monitor/mediator
# prog_label = 'chmod_open_fchown_close_open'
# rgmodes = {0o606: '-read', 0o646: '+read'}
# for mode, mode_label in rgmodes.items():
#     label = f'{prog_label}{mode_label}'
#     ts.add_test_from_text(f"""
#         COMPILE /tst_prog FROM ./c/long/tst_{prog_label}.c
#         USER user
#         USER final_owner
#         DIR /parent                  OWNER user GROUP user MODE {0o777}
#         FILE /parent/file      OWNER user GROUP user MODE {0o777}
#         SETUP echo aaaa > /parent/file
#         RUN /tst_prog /parent/file final_owner {mode}  USER user GROUP user""")
# #include <stdio.h>
# int main(int argc, char *argv[]) {
#     int fd, mode, ret;
#     char *path, *user;
#     if (argc != 4) return 1;
#     path = argv[1];
#     user = argv[2];
#     mode = strtol(argv[3], 0, 10);
#     if (syscall(SYS_chmod, path, mode) == -1) { perror("chmod"); return 2; }
#     // only root may chown...
#     if ((ret = syscall(SYS_fork)) == -1) { perror("fork"); return 3; }
#     if (ret == 0) {
#         return syscall(SYS_execlp, "/usr/bin/sudo", "/usr/bin/sudo", "/usr/bin/chown", user, path, (char *)0);
#     }
#     if (syscall(SYS_wait, 0) == -1) { perror("wait"); return 4; }
#     syscall(SYS_open, path, O_RDONLY);
#     return 0;
# }

def test_chmod_open_openatcreate(t: LinuxTestSpec, wxmode: int):

    t.make_user('user')
    t.make_dir('/parent', owner='user', group='user', mode=0o777)
    with t.make_program_and_run(user='user', group='user', umask=0o022) as child:
        child.chmod('/parent', wxmode, fatal=True)
        dirfd = child.open('/parent', O_DIRECTORY, 0, fatal=True)
        child.openat(dirfd, 'file', O_CREAT, 0o600)


def test_chmod_open_openatexists(t: LinuxTestSpec, rmode: int):

    t.make_user('user')
    t.make_dir('/parent', owner='user', group='user', mode=0o777)
    t.make_file('/parent/file', owner='user', group='user', mode=0o777)
    t.add_setup('echo aaaaaa > /parent/file')
    with t.make_program_and_run(user='user', group='user', umask=0o022) as child:
        child.chmod('/parent/file', rmode, fatal=True)
        dirfd = child.open('/parent', O_DIRECTORY, 0, fatal=True)
        child.openat(dirfd, 'file', O_RDONLY, 0)
        # ret of SYS_openat is not checked because it depends on unknown mode (model will check the ret)


def test_creat_close_unlink_repeated(t: LinuxTestSpec):

    t.make_user('user')
    t.make_dir('/parent', owner='user', group='user', mode=0o777)
    with t.make_program_and_run(user='user', group='user', umask=0o022) as child:
        child.chdir('/parent', fatal=True)
        for _ in range(10):
            fd = child.open('new', O_CREAT, 0o666, fatal=True)
            child.close(fd, fatal=True)
            child.unlink('new', fatal=True)


def test_creat_link_unlink_open(t: LinuxTestSpec, rmode: int):

    t.make_user('user')
    t.make_dir('/parent', owner='user', group='user', mode=0o777)
    with t.make_program_and_run(user='user', group='user', umask=0o022) as child:
        child.chdir('/parent', fatal=True)
        fd = child.creat('new', rmode, fatal=True)
        child.close(fd, fatal=True)
        child.link('new', 'new2', fatal=True)
        child.unlink('new', fatal=True)
        child.open('new2', O_RDONLY, 0)


def test_mkdir_open_close_chmod_open(t: LinuxTestSpec, rmode: int):

    t.make_user('user')
    t.make_dir('/parent', owner='user', group='user', mode=0o777)
    with t.make_program_and_run(user='user', group='user', umask=0o022) as child:
        child.mkdir('/parent/dir', 0o777, fatal=True)
        fd = child.open('/parent/dir/file', O_CREAT | O_TRUNC | O_WRONLY, 0o600, fatal=True)
        child.close(fd, fatal=True)
        child.chmod('/parent/dir/file', rmode, fatal=True)
        child.open('/parent/dir/file', O_RDONLY, 0)


def test_mkdir_open_close_open(t: LinuxTestSpec, rmode: int):

    t.make_user('user')
    t.make_dir('/parent', owner='user', group='user', mode=0o777)
    with t.make_program_and_run(user='user', group='user', umask=0o022) as child:
        child.mkdir('/parent/dir', 0o700, fatal=True)
        fd = child.open('/parent/dir/file', O_CREAT | O_TRUNC | O_WRONLY, rmode, fatal=True)
        child.close(fd, fatal=True)
        child.open('/parent/dir/file', O_RDONLY, 0)


def test_mkdir_open_fchdir_open(t: LinuxTestSpec, wmode: int):

    t.make_user('user')
    t.make_dir('/parent', owner='user', group='user', mode=0o777)
    with t.make_program_and_run(user='user', group='user', umask=0o022) as child:
        child.mkdir('/parent/dir', wmode, fatal=True)
        dfd = child.open('/parent/dir', O_DIRECTORY, 0, fatal=True)
        child.fchdir(dfd, fatal=True)
        child.open('file', O_CREAT | O_WRONLY, 0o600)


def test_open_close_chmod_open(t: LinuxTestSpec, rmode: int):

    t.make_user('user')
    t.make_dir('/parent', owner='user', group='user', mode=0o777)
    with t.make_program_and_run(user='user', group='user', umask=0o022) as child:
        fd = child.open('/parent/file', O_CREAT | O_TRUNC | O_WRONLY, 0o600, fatal=True)
        child.close(fd, fatal=True)
        child.chmod('/parent/file', rmode, fatal=True)
        child.open('/parent/file', O_RDONLY, 0)


def test_open_close_open(t: LinuxTestSpec, rmode: int):

    t.make_user('user')
    t.make_dir('/parent', owner='user', group='user', mode=0o777)
    with t.make_program_and_run(user='user', group='user', umask=0o022) as child:
        fd = child.open('/parent/file', O_CREAT | O_TRUNC | O_WRONLY, rmode, fatal=True)
        child.close(fd, fatal=True)
        child.open('/parent/file', O_RDONLY, 0)


def test_open_fchdir_open(t: LinuxTestSpec, rmode: int):

    t.make_user('user')
    t.make_dir('/parent', owner='user', group='user', mode=0o777)
    t.make_file('/parent/file', owner='user', group='user', mode=rmode)
    with t.make_program_and_run(user='user', group='user', umask=0o022) as child:
        fd = child.open('/parent', O_DIRECTORY, 0, fatal=True)
        child.fchdir(fd, fatal=True)
        child.open('file', O_RDONLY, 0)


def test_open_fchmod_close_open(t: LinuxTestSpec, rmode: int):

    t.make_user('user')
    t.make_dir('/parent', owner='user', group='user', mode=0o777)
    t.make_file('/parent/file', owner='user', group='user', mode=0o777)
    t.add_setup('echo aaaaa > /parent/file')
    with t.make_program_and_run(user='user', group='user', umask=0o022) as child:
        fd = child.open('/parent/file', O_RDONLY, 0, fatal=True)
        child.fchmod(fd, rmode, fatal=True)
        child.close(fd, fatal=True)
        child.open('/parent/file', O_RDONLY, 0)


def test_open_openat(t: LinuxTestSpec):

    t.make_user('user')
    t.make_dir('/parent', owner='user', group='user', mode=0o777)
    t.make_file('/parent/file', owner='user', group='user', mode=0o777)
    t.add_setup('echo aaaaa > /parent/file')
    with t.make_program_and_run(user='user', group='user', umask=0o022) as child:
        dirfd = child.open('/parent', O_DIRECTORY, 0, fatal=True)
        # ret of SYS_open is checked because it prepares the system to the test target (openat) 
        child.openat(dirfd, 'file', O_RDONLY, 0, fatal=True)
        # ret of SYS_openat is not checked because it may be different and is compared with model
