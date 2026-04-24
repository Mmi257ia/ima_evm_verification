"""
open(file) with O_CREAT must not be allowed if all the following met:
    - the file already exists
    - parent directory of the file has sticky bit
    - and is world writable
    - subject user doesn't own the file
    - the owner of the parent directory doesn't own the file
It seems the file was created earlier by intruder.
The requirements to the parent directory like the properties of /tmp.
The subject process wants to create its own temporary file (regular or FIFO)
and doesn't use O_EXCL to create really its own file.

protect = 1("othprotect") requires the parent directory to be world writable (subject user may create file
in this directory (i.e. write to the directory) because it is in "others") .
protect = 2("grpprotect") requires the parent directory to be group writable (subject user may create file
in this directory (i.e. write to the directory) because it is in "group-owner" of the directiory).
"""

from os import O_CREAT
from stat import S_ISVTX
from pytest import FixtureRequest, fixture

from tests.spec import LinuxTestSpec

@fixture(params=[0, 1, 2], ids=["noprotect", "othprotect", "grpprotect"])
def protect(request: FixtureRequest):
    return request.param

def test_open(t: LinuxTestSpec, protect: int):
    parent_owner = parent_group = 'owner'
    caller_user = 'user'
    if protect == 2:
        caller_group = parent_group
    else:
        caller_group = caller_user
    attacker = 'attacker'
    t.make_user(caller_user)
    t.make_user(parent_owner)
    # move attacker to the group of parent_owner if needed
    if protect == 2:
        t.make_user(attacker, [parent_group])
    else:
        t.make_user(attacker)
    # disable umask
    # all setup commands are executed as one command! we use it here!
    t.add_setup('umask 0')
    parent_mode = [
        0o777 | S_ISVTX, # any
        0o777 | S_ISVTX, # world writable
        0o770 | S_ISVTX][protect] # group writable
    t.make_dir('/dir', parent_owner, parent_group, parent_mode)
    t.make_file('/dir/file', owner=attacker, group=parent_group, mode=0o777)

    with t.make_program_and_run(caller_user, caller_group, umask=0,
                                before_run=(
                                # set protected
                                'cat /proc/sys/fs/protected_regular > /tmp/old_protect.anis && '
                                f'echo {protect} > /proc/sys/fs/protected_regular'),
                                after_run=(
                                    'cat /tmp/old_protect.anis > /proc/sys/fs/protected_regular && '
                                    'rm -f /tmp/old_protect.anis')) as child:
        child.open('/dir/file', O_CREAT, 0)

# there is now "test_creat" function because it requires "creat_exists" event in the model
# The current model has "creat_create" only