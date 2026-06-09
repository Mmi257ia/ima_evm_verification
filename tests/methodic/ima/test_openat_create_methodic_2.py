from os import O_WRONLY, O_CREAT, O_RDONLY, O_DIRECTORY
from pytest import fixture
from tests.spec import LinuxTestSpec
import pytest

@fixture(params=[
    ("create", O_CREAT),
], ids=["create"])
def access_mode(request):
    return request.param

def test_openat_create_methodic_2(t: LinuxTestSpec, access_mode):
    mode_name, flags = access_mode

    policy_uid = 2000
    ima_user = 'ima_user'
    t.make_user(ima_user, uid=policy_uid)
    t.enable_ima_evm()

    ima_evm_dir = 'ima_evm_dir'
    t.make_dir(f'/{ima_evm_dir}/dir', ima_user, ima_user, 0o777)
    t.add_setup(f'chattr +i /{ima_evm_dir}/dir')
    
    with t.make_program_and_run(ima_user, ima_user, ima_evm_dir=ima_evm_dir, umask=0) as child:
        # should fail (bit it passes because grd is false and openat return error)
        dir_fd = child.open(f'/{ima_evm_dir}/dir', O_DIRECTORY, 0, fatal=True)
        # with fatal it is ValueError
        child.openat(dir_fd, 'new_file', flags, 0o666)
