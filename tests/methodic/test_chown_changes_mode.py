"""
Checks that chown() changes mode of the file in certain conditions
for security reasons.
"""
from os import O_DIRECTORY, O_RDONLY
from typing import Literal

from pytest import fixture, FixtureRequest
from tests.spec import LinuxTestSpec

@fixture(params=['root', 'nonroot'])
def userkind(request: FixtureRequest):
    return request.param

@fixture(params=[False, True], ids=['setgidN', 'setgidY'])
def setgid(request: FixtureRequest):
    return request.param

@fixture(params=[False, True], ids=['setuidN', 'setuidY'])
def setuid(request: FixtureRequest):
    return request.param

@fixture(params=[False, True], ids=['xgrpN', 'xgrpY'])
def xgrp(request: FixtureRequest):
    return request.param

@fixture(params=["file", "dir"])
def object_kind(request: FixtureRequest):
    return request.param

def test_chown(t: LinuxTestSpec, object_kind: str, userkind: str, setgid: bool, setuid: bool, xgrp: bool):

    mode = 0o600
    caller_user = caller_group = object_user = object_group = userkind
    owner = 'owner'

    t.make_user(owner)
    if caller_user != 'root':
        t.make_user(caller_user)
    if object_kind == 'file':
        t.make_file('/obj', owner, object_group, mode)
    elif object_kind == 'dir':
        t.make_dir('/obj', owner, object_group, mode)

    special_mode = ','.join([
        "g+s" if setgid else "g-s",
        "u+s" if setuid else "u-s",
        'g+x' if xgrp else 'g-x'])
    t.add_setup(f'chmod {special_mode} /obj')

    with t.make_program_and_run(caller_user, caller_group, umask=0o022,
                                runner=f'export OBJECT_USER=$(id -u {object_user}); <>') as child:
        child.chown('/obj', child.to_int(child.xgetenv('OBJECT_USER')), -1)


def test_fchown(t: LinuxTestSpec, object_kind: Literal["file", "dir"], userkind: str, setgid: bool, setuid: bool, xgrp: bool):

    mode = 0o660
    caller_user = caller_group = object_user = object_group = userkind
    owner = 'owner'

    t.make_user(owner)
    if caller_user != 'root':
        t.make_user(caller_user)
    if object_kind == 'file':
        t.make_file('/obj', owner, object_group, mode)
        flags = O_RDONLY
    elif object_kind == 'dir':
        t.make_dir('/obj', owner, object_group, mode)
        flags = O_RDONLY | O_DIRECTORY

    special_mode = ','.join([
        "g+s" if setgid else "g-s",
        "u+s" if setuid else "u-s",
        'g+x' if xgrp else 'g-x'])
    t.add_setup(f'chmod {special_mode} /obj')

    with t.make_program_and_run(caller_user, caller_group, umask=0o022,
                                runner=f'export OBJECT_USER=$(id -u {object_user}); <>') as child:
        fd = child.open('/obj', flags, 0, fatal=True)
        child.fchown(fd, child.to_int(child.xgetenv('OBJECT_USER')), -1)
