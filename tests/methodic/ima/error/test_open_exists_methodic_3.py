from os import O_RDONLY, O_WRONLY, O_RDWR
from pytest import fixture
from tests.spec import LinuxTestSpec
import os


@fixture(params=[
    ("read", os.O_RDONLY, False),
    ("write", os.O_WRONLY, False),
    ("rdwr", os.O_RDWR, False),
], ids=["read", "write", "rdwr"])
def access_mode(request):
    return request.param

"""
из методики пункт 3
INCORRECT hash 
"""
def test_open_exists_methodic_3(t: LinuxTestSpec, access_mode):
    mode_name, flags, should_succeed = access_mode

    policy_uid = 2000


    # user with ima
    ima_user = 'ima_user'
    t.make_user(ima_user, uid=policy_uid)
    t.enable_ima_evm()

    ima_evm_dir = 'ima_evm_dir'
    new_file_path = f'/{ima_evm_dir}/dir/file'
    t.make_dir(f'/{ima_evm_dir}/dir', ima_user, ima_user, 0o755)
    t.make_file(f'/{ima_evm_dir}/dir/file', owner=ima_user, group=ima_user, mode=0o666)

    t.add_setup(f'echo "test content" > /{ima_evm_dir}/dir/file')
    t.add_setup(f'cat /{ima_evm_dir}/dir/file > /dev/null')

    fake_ima_hex = '0x01' + ('00' * 20)
    t.add_setup(f"setfattr -n security.ima -v {fake_ima_hex} {new_file_path}")
    
    with t.make_program_and_run(ima_user, ima_user, ima_evm_dir=ima_evm_dir, umask=0) as child:
        # all should fail
        child.open(new_file_path, flags, 0)

        