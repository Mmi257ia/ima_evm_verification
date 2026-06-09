from pytest import fixture
from tests.spec import LinuxTestSpec

from pytest import fixture, FixtureRequest
from os import O_CREAT, O_DIRECTORY, O_RDONLY, O_TRUNC, O_WRONLY

"""
file is not ImmutableFiles
"""
def test_fchown_methodic_1(t: LinuxTestSpec):
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
        fd = child.open(f'/{ima_evm_dir}/dir/file', O_RDONLY, 0, fatal=True)
        child.fchown(fd, child.to_int(child.xgetenv('OBJECT_USER')), -1, fatal=True)
