"""
Checks that chown() is not allowed from non-owner of the file
"""

from os import O_DIRECTORY, O_RDONLY
from typing import Literal
from pytest import fixture, FixtureRequest
from tests.spec import LinuxTestSpec

@fixture(params=[False, True], ids=['ownercallsN', 'ownercallsY'])
def owner_is_caller(request: FixtureRequest):
    return request.param

@fixture(params=['file', 'dir'])
def object_kind(request: FixtureRequest):
    return request.param

def test_chown(t: LinuxTestSpec, object_kind: Literal['file', 'dir'], owner_is_caller: bool):

    object_user = object_group = 'owner'
    if owner_is_caller:
        caller_user = caller_group = 'owner'
    else:
        caller_user = caller_group = 'nonowner'

    mode = 0o600
    t.make_user(object_user)
    if caller_user != object_user:
        t.make_user(caller_user)
    if object_kind == 'file':
        t.make_file('/obj', object_user, object_group, mode)
        flags = O_RDONLY
    elif object_kind == 'dir':
        t.make_dir('/obj', object_user, object_group, mode)
        flags = O_RDONLY | O_DIRECTORY

    with t.make_program_and_run(caller_user, caller_group, umask=0o022,
                                runner=f'export CALLER=$(id -u {caller_user}); <>') as child:
        uid = child.bound_value_as_uid_t(child.to_int(child.xgetenv('CALLER')))
        child.chown('/obj', uid, -1)
        child.open('/obj', flags, 0)

def test_fchown(t: LinuxTestSpec, object_kind: Literal['file', 'dir'], owner_is_caller: bool):

    object_user = object_group = 'owner'
    if owner_is_caller:
        caller_user = caller_group = 'owner'
    else:
        caller_user = caller_group = 'nonowner'

    mode = 0o604
    t.make_user(object_user)
    if caller_user != object_user:
        t.make_user(caller_user)
    if object_kind == 'file':
        t.make_file('/obj', object_user, object_group, mode)
        flags1 = 0
        flags2 = O_RDONLY
    elif object_kind == 'dir':
        t.make_dir('/obj', object_user, object_group, mode)
        flags1 = O_DIRECTORY
        flags2 = O_RDONLY | O_DIRECTORY

    with t.make_program_and_run(caller_user, caller_group, umask=0o022,
                                runner=f'export CALLER=$(id -u {caller_user}); <>') as child:
        uid = child.bound_value_as_uid_t(child.to_int(child.xgetenv('CALLER')))
        fd = child.open('/obj', flags1, 0, fatal=True)
        child.fchown(fd, uid, -1)
        child.close(fd)
        child.open('/obj', flags2, 0)
