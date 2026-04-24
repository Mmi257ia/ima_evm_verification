from os import XATTR_CREATE, XATTR_REPLACE
from typing import Literal
from pytest import fixture, FixtureRequest

import sys
print(f'sys.path = {sys.path}')

from tests.spec import LinuxTestSpec

@fixture(params=['create', 'replace'])
def flag(request: FixtureRequest):
    return {'create': XATTR_CREATE, 'replace': XATTR_REPLACE}[request.param]

@fixture(params=[False, True], ids=['attrN', 'attrY'])
def has_attr(request: FixtureRequest):
    return request.param

@fixture(params=['file', 'dir'])
def object_kind(request: FixtureRequest):
    return request.param

def test_setxattr(object_kind: Literal['file', 'dir'], t: LinuxTestSpec, has_attr: bool, flag: int):
    if object_kind == 'file':
        t.make_file('/obj', owner='root', group='root', mode=0o777)
    elif object_kind == 'dir':
        t.make_dir('/obj', owner='root', group='root', mode=0o777)
    if has_attr:
        t.add_setup('setfattr -n user.test -v F /obj')
    with t.make_program_and_run('root', 'root', umask=0o022) as child:
        child.setxattr('/obj', 'user.test', b'ABC', len('ABC'), flag)
