from stat import S_ISGID
from pytest import fixture, FixtureRequest

from tests.spec import LinuxTestSpec

@fixture(params=[False, True], ids=["setgidN", "setgidY"])
def setgid(request: FixtureRequest):
    return request.param

@fixture
def mode(setgid: bool):
    return (0o777 | S_ISGID) if setgid else 0o777

# tests in Python - so there must be a python-wrapped library of os-specific procedures like adding the user, making the file, etc.

# mediator is adapter between abstracted (model) level and concrete (implementation) level
# mediators are needed for model-level testing
# this approach is not model-level testing, because tests are not generated from the model exploration
# tests are written manually using python interface to the system under test
# test are executed and trace will be given only after the test ends, mediator translated trace from implementation level into the model level
# moreover this python interface (InitProcess class) doesn't execute procedures immediately to minimize interaction with sudo-process
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
    t.make_file(path='/original', owner='object_user', group='object_user', mode=0)
    with t.make_program_and_run(user='caller_user', group='caller_user', umask=0o022) as child:
        child.link('/original', '/dir/new')
