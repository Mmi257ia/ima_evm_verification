
from os import O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_DIRECTORY
from pytest import fixture
from tests.spec import LinuxTestSpec
import os


@fixture(params=[
    ("read", os.O_RDONLY),
    ("write", os.O_WRONLY),
    ("rdwr", os.O_RDWR),
], ids=["read", "write", "rdwr"])
def access_mode(request):
    return request.param

"""
из методики пункт 5
некорректные контролируемые подсистемой обеспечения целостности 
(с сохраненным некорректным хэш-кодом), 
неизменяемые (immutable)
"""
def test_openat_exists_methodic_5(t: LinuxTestSpec, access_mode):
    mode_name, flags = access_mode

    policy_uid = 2000

    # user with ima
    ima_user = 'ima_user'
    t.make_user(ima_user, uid=policy_uid)

    t.make_dir('/dir', ima_user, ima_user, 0o755)
    t.make_file('/dir/file', owner=ima_user, group=ima_user, mode=0o666)

    t.add_setup(f'echo "test content" > /dir/file')
    t.add_setup(f'cat /dir/file > /dev/null')

    t.add_setup(f'echo "add data" > /dir/file')
    
    t.add_setup(f'chattr +i /dir/file')

    with t.make_program_and_run(ima_user, ima_user, umask=0) as child:
        # all should fail
        dir_fd = child.open('/dir', O_DIRECTORY | O_RDONLY, 0, fatal=True)
        child.openat(dir_fd, 'file', flags, 0, fatal=False)
        