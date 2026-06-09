from pytest import fixture
from tests.spec import LinuxTestSpec

from pytest import fixture, FixtureRequest
from tests.spec import LinuxTestSpec

"""
file is not ImmutableFiles
"""
def test_chown_methodic_1(t: LinuxTestSpec):
    dir_mode = 0o700
    file_mode = 0o600
    
    ima_user = 'ima_user'

    t.make_user(ima_user, uid=2000)
    t.enable_ima_evm()

    ima_evm_dir = 'ima_evm_dir'

    t.make_dir(f'/{ima_evm_dir}/dir', ima_user, ima_user, dir_mode)
    t.make_file(f'/{ima_evm_dir}/dir/file', ima_user, ima_user, file_mode)

    with t.make_program_and_run(ima_user, ima_user, ima_evm_dir=ima_evm_dir, umask=0,
                                runner=f'export OBJECT_USER=$(id -u {ima_user}); <>') as child:
        #should pass
        child.chown(f'/{ima_evm_dir}/dir/file', child.to_int(child.xgetenv('OBJECT_USER')), -1, fatal=True)