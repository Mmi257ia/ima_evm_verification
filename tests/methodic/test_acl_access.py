"""
Performs syscalls with different ACL (Access Control Lists) at objects and different
users/groups of subjects.
"""

from os import O_CREAT, O_DIRECTORY, O_RDONLY, O_WRONLY
from typing import Literal, Tuple
from pytest import FixtureRequest, fixture

from .cases import AclCasesGroup, UserGroupPair, acl_cases_grouped, \
    user, u1, u2, user_g3_g4, user_g4, g1, g3, g4

from tests.spec import LinuxTestSpec


object_mode = 0o777

@fixture(
        params=acl_cases_grouped.items(),
        ids=[f'{u}__{g}' for u, g in acl_cases_grouped.keys()])
def acl_cases_group(request: FixtureRequest):
    return request.param

@fixture
def acl_users(t: LinuxTestSpec):
    t.make_user(user)
    t.make_user(u1)
    t.make_user(u2)
    t.make_group(g1)
    t.make_group(g3)
    t.make_group(g4)
    t.make_user(user_g4)
    t.add_setup(f'usermod -G {g4} {user_g4}')
    t.make_user(user_g3_g4)
    t.add_setup(f'usermod -G {g3},{g4} {user_g3_g4}')


AccessKind = Literal['read', 'write']
@fixture(params=['read', 'write'])
def access_kind(request: FixtureRequest) -> AccessKind:
    return request.param

ObjectKind = Literal['file', 'dir']
@fixture(params=['file', 'dir'])
def object_kind(request: FixtureRequest) -> ObjectKind:
    return request.param


def test_open_file(access_kind: AccessKind, t: LinuxTestSpec, acl_users: None, acl_cases_group: Tuple[UserGroupPair, AclCasesGroup]):

    if access_kind == 'read':
        flags = O_RDONLY
    elif access_kind == 'write':
        flags = O_WRONLY

    caller_pair, cases = acl_cases_group
    caller_user, caller_group = caller_pair

    for i, case in enumerate(cases):
        _, acl_entries, object_user, object_group = case
        t.make_file(f'/file{i}', owner=object_user, group=object_group, mode=object_mode)
        t.add_setup(f'setfacl -m {",".join(acl_entries)} /file{i}')

    with t.make_program_and_run(user=caller_user, group=caller_group, umask=0o022) as child:
        for i in range(len(cases)):
            child.open(f'/file{i}', flags, 0)


def test_open_dir(access_kind: AccessKind, t: LinuxTestSpec, acl_users: None, acl_cases_group: Tuple[UserGroupPair, AclCasesGroup]):

    if access_kind == 'read':
        flags = O_RDONLY | O_DIRECTORY
        def pathname(i: int) -> str: return f'/dir{i}'
    elif access_kind == 'write':
        flags = O_CREAT
        def pathname(i: int) -> str: return f'/dir{i}/new'

    caller_pair, cases = acl_cases_group
    caller_user, caller_group = caller_pair

    for i, case in enumerate(cases):
        _, acl_entries, object_user, object_group = case
        t.make_dir(f'/dir{i}', owner=object_user, group=object_group, mode=object_mode)
        t.add_setup(f'setfacl -m {",".join(acl_entries)} /dir{i}')        

    with t.make_program_and_run(user=caller_user, group=caller_group, umask=0o022) as child:
        for i in range(len(cases)):
            child.open(pathname(i), flags, 0)


def test_creat(t: LinuxTestSpec, acl_users: None, acl_cases_group: Tuple[UserGroupPair, AclCasesGroup]):

    caller_pair, cases = acl_cases_group
    caller_user, caller_group = caller_pair

    for i, case in enumerate(cases):
        _, acl_entries, object_user, object_group = case
        t.make_dir(f'/dir{i}', owner=object_user, group=object_group, mode=object_mode)
        t.add_setup(f'setfacl -m {",".join(acl_entries)} /dir{i}')

    with t.make_program_and_run(user=caller_user, group=caller_group, umask=0o022) as child:
        for i in range(len(cases)):
           child.creat(f'/dir{i}/new', 0)


def test_mkdir(t: LinuxTestSpec, acl_users: None, acl_cases_group: Tuple[UserGroupPair, AclCasesGroup]):

    caller_pair, cases = acl_cases_group
    caller_user, caller_group = caller_pair

    for i, case in enumerate(cases):
        _, acl_entries, object_user, object_group = case
        t.make_dir(f'/dir{i}', owner=object_user, group=object_group, mode=object_mode)
        t.add_setup(f'setfacl -m {",".join(acl_entries)} /dir{i}')

    with t.make_program_and_run(user=caller_user, group=caller_group, umask=0o022) as child:
        for i in range(len(cases)):
            child.mkdir(f'/dir{i}/new', 0)


def test_getxattr(object_kind: ObjectKind, t: LinuxTestSpec, acl_users: None, acl_cases_group: Tuple[UserGroupPair, AclCasesGroup]):

    caller_pair, cases = acl_cases_group
    caller_user, caller_group = caller_pair

    for i, case in enumerate(cases):
        _, acl_entries, object_user, object_group = case
        if object_kind == 'file':
            t.make_file(f'/obj{i}', owner=object_user, group=object_group, mode=object_mode)
        elif object_kind == 'dir':
            t.make_dir(f'/obj{i}', owner=object_user, group=object_group, mode=object_mode)
        t.add_setup(f'setfattr -n user.test -v 12345 /obj{i}')
        t.add_setup(f'setfacl -m {",".join(acl_entries)} /obj{i}')

    with t.make_program_and_run(user=caller_user, group=caller_group, umask=0o022) as child:
        for i in range(len(cases)):
            buf = child.bound_value_as_chararray(10)
            child.getxattr(f'/obj{i}', 'user.test', buf, 0)


def test_setxattr(object_kind: ObjectKind, t: LinuxTestSpec, acl_users: None, acl_cases_group: Tuple[UserGroupPair, AclCasesGroup]):

    caller_pair, cases = acl_cases_group
    caller_user, caller_group = caller_pair

    for i, case in enumerate(cases):
        _, acl_entries, object_user, object_group = case
        if object_kind == 'file':
            t.make_file(f'/obj{i}', owner=object_user, group=object_group, mode=object_mode)
        elif object_kind == 'dir':
            t.make_dir(f'/obj{i}', owner=object_user, group=object_group, mode=object_mode)
            t.add_setup(f'setfattr -n user.test -v AAA /obj{i}')
        t.add_setup(f'setfacl -m {",".join(acl_entries)} /obj{i}')

    with t.make_program_and_run(user=caller_user, group=caller_group, umask=0o022) as child:
        for i in range(len(cases)):
            child.setxattr(f'/obj{i}', 'user.test', b'123456', 5, 0)


def test_chmod(object_kind: ObjectKind, t: LinuxTestSpec, acl_users: None, acl_cases_group: Tuple[UserGroupPair, AclCasesGroup]):

    caller_pair, cases = acl_cases_group
    caller_user, caller_group = caller_pair

    for i, case in enumerate(cases):
        _, acl_entries, object_user, object_group = case
        if object_kind == 'file':
            t.make_file(f'/obj{i}', owner=object_user, group=object_group, mode=object_mode)
        elif object_kind == 'dir':
            t.make_dir(f'/obj{i}', owner=object_user, group=object_group, mode=object_mode)
        t.add_setup(f'setfacl -m {",".join(acl_entries)} /obj{i}')

    with t.make_program_and_run(user=caller_user, group=caller_group, umask=0o022) as child:
        for i in range(len(cases)):
            child.chmod(f'/obj{i}', 0o123)

# fchmod is not applied here (tests will check open() not fchmod())

def test_chown(object_kind: ObjectKind, t: LinuxTestSpec, acl_users: None, acl_cases_group: Tuple[UserGroupPair, AclCasesGroup]):

    caller_pair, cases = acl_cases_group
    caller_user, caller_group = caller_pair

    t.make_user('newowner')

    for i, case in enumerate(cases):
        _, acl_entries, object_user, object_group = case
        if object_kind == 'file':
            t.make_file(f'/obj{i}', owner=object_user, group=object_group, mode=object_mode)
        elif object_kind == 'dir':
            t.make_dir(f'/obj{i}', owner=object_user, group=object_group, mode=object_mode)
        t.add_setup(f'setfacl -m {",".join(acl_entries)} /obj{i}')

    with t.make_program_and_run(user=caller_user, group=caller_group, umask=0o022,
                                runner='export NEWOWNER=$(id -u newowner); <>') as child:
        uid = child.bound_value_as_uid_t(child.to_int(child.xgetenv('NEWOWNER')))
        for i in range(len(cases)):
            child.chown(f'/obj{i}', uid, -1)

# fchown is not applied here (see fchmod)

def test_unlink_file(t: LinuxTestSpec, acl_users: None, acl_cases_group: Tuple[UserGroupPair, AclCasesGroup]):

    caller_pair, cases = acl_cases_group
    caller_user, caller_group = caller_pair

    for i, case in enumerate(cases):
        _, acl_entries, object_user, object_group = case
        t.make_dir(f'/obj{i}', owner=object_user, group=object_group, mode=object_mode)
        t.make_file(f'/obj{i}/f', owner=object_user, group=object_group, mode=object_mode)
        t.add_setup(f'echo AAAAA > /obj{i}/f')
        t.add_setup(f'setfacl -m {",".join(acl_entries)} /obj{i}')

    with t.make_program_and_run(user=caller_user, group=caller_group, umask=0o022) as child:
        for i in range(len(cases)):
            child.unlink(f'/obj{i}/f')


def test_unlink_link(t: LinuxTestSpec, acl_users: None, acl_cases_group: Tuple[UserGroupPair, AclCasesGroup]):

    caller_pair, cases = acl_cases_group
    caller_user, caller_group = caller_pair

    for i, case in enumerate(cases):
        _, acl_entries, object_user, object_group = case
        t.make_dir(f'/dir{i}', owner=object_user, group=object_group, mode=object_mode)
        t.make_file(f'/original{i}', owner=object_user, group=object_group, mode=object_mode)
        t.add_setup(f'echo AAAAA > /original{i}')
        t.make_file(f'/dir{i}/link', owner=object_user, group=object_group, mode=object_mode)
        t.add_setup(f'rm /dir{i}/link')
        t.add_setup(f'ln /original{i} /dir{i}/link')
        t.add_setup(f'setfacl -m {",".join(acl_entries)} /dir{i}')

    with t.make_program_and_run(user=caller_user, group=caller_group, umask=0o022) as child:
        for i in range(len(cases)):
            child.unlink(f'/dir{i}/link')


def test_rmdir(t: LinuxTestSpec, acl_users: None, acl_cases_group: Tuple[UserGroupPair, AclCasesGroup]):

    caller_pair, cases = acl_cases_group
    caller_user, caller_group = caller_pair

    for i, case in enumerate(cases):
        _, acl_entries, object_user, object_group = case
        t.make_dir(f'/obj{i}', owner=object_user, group=object_group, mode=object_mode)
        t.make_dir(f'/obj{i}/f', owner=object_user, group=object_group, mode=object_mode)
        t.add_setup(f'setfacl -m {",".join(acl_entries)} /obj{i}')

    with t.make_program_and_run(user=caller_user, group=caller_group, umask=0o022) as child:
        for i in range(len(cases)):
            child.rmdir(f'/obj{i}/f')


def test_link(t: LinuxTestSpec, acl_users: None, acl_cases_group: Tuple[UserGroupPair, AclCasesGroup]):

    caller_pair, cases = acl_cases_group
    caller_user, caller_group = caller_pair

    for i, case in enumerate(cases):
        _, acl_entries, object_user, object_group = case
        t.make_dir(f'/dir{i}', owner=object_user, group=object_group, mode=object_mode)
        t.make_file(f'/orig{i}', owner=object_user, group=object_group, mode=object_mode)
        t.add_setup(f'setfacl -m {",".join(acl_entries)} /dir{i}')

    with t.make_program_and_run(user=caller_user, group=caller_group, umask=0o022) as child:
        for i in range(len(cases)):
            child.link(f'/orig{i}', f'/dir{i}/link')


def test_execve(t: LinuxTestSpec, acl_users: None, acl_cases_group: Tuple[UserGroupPair, AclCasesGroup]):

    caller_pair, cases = acl_cases_group
    caller_user, caller_group = caller_pair

    class ExecveChainProgramMaker:

        def get_text(self):
            return '''
#define _GNU_SOURCE
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>


int main(int argc, char *argv[], char *envp[])
{
    int i, num, len;
    char arg[1024] = {0};
    char *i_start = &argv[0][0];
    char *args[3] = {0};

    if (argc < 2) { fprintf(stderr, "Wrong arguments count\\n"); return 1; }

    args[0] = arg;
    args[1] = argv[1];

    while (*i_start != '\\0' && (isalpha(*i_start) || *i_start == '_' || *i_start == '/')) {
        ++i_start;
    }
    if (*i_start == '\\0' || !isdigit(*i_start)) {
        fprintf(stderr, "%s: no num or no num after first word\\n", argv[0]);
        return 2;
    }

    num = strtol(i_start, 0, 10);
    len = strtol(argv[1], 0, 10);
    *i_start = '\\0';

    for (i = num + 1; i <= len; ++i) {
        snprintf(arg, sizeof arg, "%s%d", argv[0], i);
        syscall(SYS_execve, arg, args, envp);
    }
    
    return 0;
}
'''

    execve_chain_prog = ExecveChainProgramMaker()
    execve_chain = t.compile(execve_chain_prog, '/tst_prog0')

    for i, case in enumerate(cases):
        _, acl_entries, object_user, object_group = case
        t.make_file(f'/tst_prog{i + 1}', owner=object_user, group=object_group, mode=object_mode)
        t.add_setup(f'cp /tst_prog0 /tst_prog{i + 1}')
        t.add_setup(f'chown {object_user}:{object_group} /tst_prog{i + 1}')
        t.add_setup(f'setfacl -m {",".join(acl_entries)} /tst_prog{i + 1}')

    with t.make_program_and_run(user=caller_user, group=caller_group, umask=0o022) as child:
        argv = child.bound_value_as_charparray(prefix='argv', init=['/tst_prog0', str(len(cases))])
        envp = child.bound_value_as_charparray(prefix='envp', init=[])
        child.execve(execve_chain, argv, envp, fatal=True)
