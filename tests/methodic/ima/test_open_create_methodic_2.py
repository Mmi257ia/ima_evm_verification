from os import O_WRONLY, O_CREAT
from pytest import fixture
from tests.spec import LinuxTestSpec
import pytest

@fixture(params=[
    ("create", O_WRONLY | O_CREAT),
], ids=["create"])
def access_mode(request):
    return request.param

def test_open_create_methodic_2(t: LinuxTestSpec, access_mode):
    mode_name, flags = access_mode

    policy_uid = 2000
    ima_user = 'ima_user'
    t.make_user(ima_user, uid=policy_uid)
    t.enable_ima_evm()

    ima_evm_dir = 'ima_evm_dir'
    t.make_dir(f'/{ima_evm_dir}/dir', ima_user, ima_user, 0o777)
    t.add_setup(f'chattr +i /{ima_evm_dir}/dir')
    
    new_file_path = f'/{ima_evm_dir}/dir/new_file'

    with t.make_program_and_run(ima_user, ima_user, ima_evm_dir=ima_evm_dir, umask=0) as child:
        # should fail - but it passes because grd is fail and open return error 
        #with fatal is it ValueError
        child.open(new_file_path, flags, 0o666)


