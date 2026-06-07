from os import O_WRONLY, O_CREAT
from pytest import fixture
from tests.spec import LinuxTestSpec
import pytest

@fixture(params=[
    ("create", O_WRONLY | O_CREAT),
], ids=["create"])
def access_mode(request):
    return request.param

def test_open_create_methodic_1(t: LinuxTestSpec, access_mode):
    mode_name, flags = access_mode

    policy_uid = 2000
    ima_user = 'ima_user'
    t.make_user(ima_user, uid=policy_uid)

    t.make_dir('/dir', ima_user, ima_user, 0o777)
    
    new_file_path = '/dir/new_file'

    with t.make_program_and_run(ima_user, ima_user, umask=0) as child:
        # should pass
        child.open(new_file_path, flags, 0o666)

