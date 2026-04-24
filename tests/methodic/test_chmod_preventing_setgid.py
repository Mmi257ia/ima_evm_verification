"""
Checks the following security behavior of chmod():
    if non-root process chmods the file by adding SetGID bit
    and process's user doesn't belong to the file group,
    then chmod() must not set SetGID bit to this file.

If this file was replaced by intruder with malicious code
and it makes the file executable, it has to change the owner
or the group of the file to superuser. And it has to set SetGID
bit to this file to make its execution from superuser group.
If chmod() will set SetGID in this case, the intruder may execute
arbitrary code under superuser group.
"""

from os import O_DIRECTORY, O_RDONLY
from stat import S_ISGID
from pytest import fixture, FixtureRequest
from typing import Literal
from tests.spec import LinuxTestSpec

@fixture(params=['file', 'dir'])
def object_kind(request: FixtureRequest):
    return request.param

@fixture(params=[False, True], ids=['setgidN', 'setgidY'])
def setgid(request: FixtureRequest):
    return request.param

@fixture(params=['root', 'user'], ids=['root', 'nonroot'])
def caller_user(request: FixtureRequest):
    return request.param

@fixture(params=[False, True], ids=['caller_notin_objgr', 'caller_in_objgr'])
def in_groups(request: FixtureRequest):
    return request.param

def test_chmod(t: LinuxTestSpec, caller_user: str, in_groups: bool, setgid: bool, object_kind: Literal['file', 'dir']):

    requested_mode = (0o123 | S_ISGID) if setgid else 0o123
    object_user = 'object_user'
    t.make_user(object_user)
    if caller_user != 'root':
        supplementary_groups = ([object_user] if in_groups else [])
        t.make_user(caller_user, supplementary_groups)
    if object_kind == 'file':
        t.make_file(path='/obj', owner=object_user, group=object_user, mode=0o777)
    elif object_kind == 'dir':
        t.make_dir(path='/obj', owner=object_user, group=object_user, mode=0o777)

    with t.make_program_and_run(user=caller_user, group=caller_user, umask=0o022) as child:
        child.chmod('/obj', requested_mode)


def test_fchmod(t: LinuxTestSpec, caller_user: str, in_groups: bool, setgid: bool, object_kind: Literal['file', 'dir']):

    requested_mode = (0o623 | S_ISGID) if setgid else 0o623
    object_user = 'object_user'
    t.make_user(object_user)
    if caller_user != 'root':
        supplementary_groups = ([object_user] if in_groups else [])
        t.make_user(caller_user, supplementary_groups)
    if object_kind == 'file':
        t.make_file(path='/obj', owner=object_user, group=object_user, mode=0o777)
        flags = O_RDONLY
    elif object_kind == 'dir':
        t.make_dir(path='/obj', owner=object_user, group=object_user, mode=0o777)
        flags = O_RDONLY | O_DIRECTORY
    
    with t.make_program_and_run(user=caller_user, group=caller_user, umask=0o022) as child:
        fd = child.open('/obj', flags, 0, fatal=True)
        child.fchmod(fd, requested_mode)
