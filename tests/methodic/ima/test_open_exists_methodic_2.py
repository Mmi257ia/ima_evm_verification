from os import O_RDONLY, O_WRONLY, O_RDWR
from pytest import fixture
from tests.spec import LinuxTestSpec
import os


@fixture(params=[
    ("read", os.O_RDONLY, True),
    ("write", os.O_WRONLY, False),
    ("rdwr", os.O_RDWR, False),
], ids=["read", "write", "rdwr"])
def access_mode(request):
    return request.param

"""
из методики пункт 2
корректные контролируемые подсистемой обеспечения целостности 
(с сохраненным корректным хэш-кодом), 
но изменяемые (без атрибута immutable)
"""
def test_open_exists_methodic_2(t: LinuxTestSpec, access_mode):
    mode_name, flags, should_succeed = access_mode

    policy_uid = 2000


    # user with ima
    ima_user = 'ima_user'
    t.make_user(ima_user, uid=policy_uid)

    t.make_dir('/dir', ima_user, ima_user, 0o755)
    t.make_file('/dir/file', owner=ima_user, group=ima_user, mode=0o666)

    t.add_setup(f'echo "test content" > /dir/file')

    try:
        with t.make_program_and_run(ima_user, ima_user, umask=0) as child:
            # read should success
            # write/rdwd should fail 
            if should_succeed:
                fd = child.open('/dir/file', flags, 0, fatal=True)
                child.close(fd)
            else:
                fd = child.open('/dir/file', flags, 0, fatal=True)

    except AssertionError as e:
        if should_succeed:
            raise e
        else:
            print(f"Rightfully caught exception: {e}")
