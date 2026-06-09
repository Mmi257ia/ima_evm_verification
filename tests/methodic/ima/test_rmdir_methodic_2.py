from pytest import fixture
from tests.spec import LinuxTestSpec


"""
parent is ImmutableFiles.
"""
def test_rmdir_methodic_2(t: LinuxTestSpec):
    policy_uid = 2000
    ima_user = 'ima_user'
    ima_evm_dir = 'ima_evm_dir'
    new_dir_path = f'/{ima_evm_dir}/parent_dir/new_subdir'

    t.make_user(ima_user, uid=policy_uid)
    t.enable_ima_evm()

    t.make_dir(f'/{ima_evm_dir}/parent_dir', ima_user, ima_user, 0o755)
    t.make_dir(new_dir_path, ima_user, ima_user, 0o755)

    t.add_setup(f'chattr +i /{ima_evm_dir}/parent_dir')

    with t.make_program_and_run(ima_user, ima_user, ima_evm_dir=ima_evm_dir, umask=0) as child:
         # should fail but it passes because grd is fail and rmdir return error 
         #with fatal it is ValueError
        child.rmdir(new_dir_path)
