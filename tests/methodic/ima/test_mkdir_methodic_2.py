from pytest import fixture
from tests.spec import LinuxTestSpec

"""
parent ∈ ImmutableFiles
"""
def test_mkdir_methodic_2(t: LinuxTestSpec):
    policy_uid = 2000
    ima_user = 'ima_user'
    t.make_user(ima_user, uid=policy_uid)

    ima_evm_dir = 'ima_evm_dir'
    t.make_dir(f'/{ima_evm_dir}/parent_dir', ima_user, ima_user, 0o755)
    
    t.add_setup(f'chattr +i /{ima_evm_dir}/parent_dir')
    
    new_dir_path = f'/{ima_evm_dir}/parent_dir/new_subdir'

    try:
        with t.make_program_and_run(ima_user, ima_user, ima_evm_dir=ima_evm_dir, umask=0) as child:
            # should fail 
            child.mkdir(new_dir_path, 0o755, fatal=True)
            raise Exception("ERROR")
    except Exception:
        pass