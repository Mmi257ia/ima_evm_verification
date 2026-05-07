from stat import S_ISGID
from pytest import fixture, FixtureRequest

from tests.spec import LinuxTestSpec

@fixture(params=[False, True], ids=["setgidN", "setgidY"])
def setgid(request: FixtureRequest):
    return request.param

@fixture
def mode(setgid: bool):
    return (0o777 | S_ISGID) if setgid else 0o777

def test_creat(t: LinuxTestSpec, mode: int):
    t.make_user('object_user')
    t.make_dir(path='/dir', owner='object_user', group='object_user', mode=mode)
    t.make_user('caller_user')
    with t.make_program_and_run(user='caller_user', group='caller_user', umask=0o022) as child:
        child.creat('/dir/new', 0)


def test_mkdir(t: LinuxTestSpec, mode: int):
    t.make_user(user='caller_user')
    t.make_user(user='object_user')
    t.make_dir(path='/dir', owner='object_user', group='object_user', mode=mode)
    with t.make_program_and_run(user='caller_user', group='caller_user', umask=0o022) as child:
        child.mkdir('/dir/new', 0)


def test_link(t: LinuxTestSpec, mode: int):
    
    t.make_user(user='caller_user')
    t.make_user(user='object_user')
    t.make_dir(path='/dir', owner='object_user', group='object_user', mode=mode)
    t.make_file(path='/original', owner='object_user', group='object_user', mode=0o777)
    with t.make_program_and_run(user='caller_user', group='caller_user', umask=0o022) as child:
        child.link('/original', '/dir/new')
