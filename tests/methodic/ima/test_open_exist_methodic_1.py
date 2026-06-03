from os import O_RDONLY, O_WRONLY, O_RDWR
from pytest import fixture
from tests.spec import LinuxTestSpec


@fixture(params=[
    ("read", O_RDONLY),
    ("write", O_WRONLY),
    ("rdwr", O_RDWR),
], ids=["read", "write", "rdwr"])
def access_mode(request):
    return request.param

"""
из методики пункт 1 
не контролируемые подсистемой обеспечения целостности; 
"""
def test_open_exists_methodic_1(t: LinuxTestSpec, access_mode):
    name, flags = access_mode

    policy_uid = 2000

    # user with ima
    ima_user = 'ima_user'
    t.make_user(ima_user, uid=policy_uid)

    # user without ima 
    other_user = 'other_user'
    t.make_user(other_user, uid=3000)

    t.make_dir('/dir', other_user, other_user, 0o755)
    t.make_file('/dir/file', owner=other_user, group=other_user, mode=0o666)

    with t.make_program_and_run(other_user, other_user, umask=0) as child:
        # should pass - not under ima control 
        child.open('/dir/file', flags, 0) 