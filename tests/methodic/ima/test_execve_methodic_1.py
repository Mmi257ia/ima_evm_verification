from tests.spec import LinuxTestSpec
import os
from typing import Literal
from pytest import FixtureRequest, fixture

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


def test_execve_methodic_1(t: LinuxTestSpec, parent_mode: str, pparent_mode: str):
    ima_user = 'ima_user'
    t.make_user(ima_user, uid=2000)
    t.enable_ima_evm()

    ima_evm_dir = 'ima_evm_dir'

    with t.make_program() as empty_prog:
        empty_prog.exit(0)
    empty = t.compile(empty_prog, '/tst_empty')
    
    with t.make_program_and_run(ima_user, ima_user, ima_evm_dir=ima_evm_dir, umask=0) as child:
        args = child.bound_value_as_charparray(init = ['/tst_empty'], prefix = 'args')
        envp = child.bound_value_as_charparray(init = [], prefix = 'envp')
        child.execve(empty, args, envp, fatal=True)
