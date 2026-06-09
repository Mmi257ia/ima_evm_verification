from pytest import fixture, FixtureRequest
from tests.spec import LinuxTestSpec
from os import O_CREAT, O_DIRECTORY, O_RDONLY, O_TRUNC, O_WRONLY


@fixture(params=[0o377, 0o677], ids=['readN', 'readY'])
def rmode(request: FixtureRequest):
    return request.param


"""
correct hashes
"""
def test_fchmod_methodic_1(t: LinuxTestSpec, rmode:int):
    policy_uid = 2000
    ima_user = 'ima_user'
    t.make_user(ima_user, uid=policy_uid)
    t.enable_ima_evm()

    ima_evm_dir = 'ima_evm_dir'
    t.make_dir(f'/{ima_evm_dir}/dir', ima_user, ima_user, 0o777)
    t.make_file(f'/{ima_evm_dir}/dir/file', owner=ima_user, group=ima_user, mode=0o777)
    t.add_setup(f'echo aaaaa > /{ima_evm_dir}/dir/file')
    
    with t.make_program_and_run(ima_user, ima_user, ima_evm_dir=ima_evm_dir, umask=0) as child:
        # should pass
        fd = child.open(f'/{ima_evm_dir}/dir/file', O_RDONLY, 0, fatal=True)
        child.fchmod(fd, rmode, fatal=True)