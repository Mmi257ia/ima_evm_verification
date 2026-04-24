"""
Performs syscalls which remove file inside directories with/without StickyBit.
These syscalls are unlink and rmdir which means operations unlink_file, unlink_link, and rmdir.
Removed file owner is different from the parent directory owner.
Removing user must be different: the same as file owner, same as the parent directory owner, root, not file owner and not parent directory owner.
"""

from stat import S_ISVTX
from pytest import fixture, FixtureRequest

from tests.spec import LinuxTestSpec

@fixture(params=[False, True], ids=['stickyN', 'stickyY'])
def sticked(request: FixtureRequest):
    return request.param

file_owner = 'file_owner'
parent_owner = 'parent_owner'
anything_user = 'anything_user'

@fixture(params=['root', file_owner, parent_owner, anything_user])
def caller_user(request: FixtureRequest):
    return request.param

@fixture
def object_mode(sticked: bool):
    return (0o777 | S_ISVTX) if sticked else 0o777


def test_unlink_file(t: LinuxTestSpec, caller_user: str, object_mode: int):

    t.make_user(parent_owner)
    t.make_user(file_owner)
    if caller_user != 'root' and caller_user != parent_owner and caller_user != file_owner:
        t.make_user(caller_user)
    t.make_dir(path='/parent', owner=parent_owner, group=parent_owner, mode=object_mode)
    t.make_file(path='/parent/file', owner=parent_owner, group=parent_owner, mode=0o777)
    t.add_setup(f'chown {file_owner}:{file_owner} /parent/file')
    t.add_setup(f'chmod 777 /parent/file')
    with t.make_program_and_run(user=caller_user, group=caller_user, umask=0o0220) as child:
        child.unlink('/parent/file')


def test_unlink_link(t: LinuxTestSpec, caller_user: str, object_mode: int):

    t.make_user(parent_owner)
    t.make_user(file_owner)
    if caller_user != 'root' and caller_user != parent_owner and caller_user != file_owner:
        t.make_user(caller_user)
    t.make_dir(path='/parent', owner=parent_owner, group=parent_owner, mode=object_mode)
    t.make_file(path='/original', owner=parent_owner, group=parent_owner, mode=0o777)
    t.make_file(path='/parent/file', owner=parent_owner, group=parent_owner, mode=0o777)
    t.add_setup(f'rm /parent/file')
    t.add_setup(f'ln /original /parent/file')
    t.add_setup(f'chown {file_owner}:{file_owner} /parent/file')
    t.add_setup(f'chmod 777 /parent/file')
    with t.make_program_and_run(user=caller_user, group=caller_user, umask=0o022) as child:
        child.unlink('/parent/file')


def test_rmdir(t: LinuxTestSpec, caller_user: str, object_mode: int):

    t.make_user(parent_owner)
    t.make_user(file_owner)
    if caller_user != 'root' and caller_user != parent_owner and caller_user != file_owner:
        t.make_user(caller_user)
    t.make_dir(path='/parent', owner=parent_owner, group=parent_owner, mode=object_mode)
    t.make_dir(path='/parent/dir', owner=parent_owner, group=parent_owner, mode=0o777)
    t.add_setup(f'chown {file_owner}:{file_owner} /parent/dir')
    t.add_setup(f'chmod 777 /parent/dir')
    with t.make_program_and_run(user=caller_user, group=caller_user, umask=0o022) as child:
        child.rmdir('/parent/dir')
