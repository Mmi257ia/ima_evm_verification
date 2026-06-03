from pytest import fixture
from tests.spec import LinuxTestSpec


"""
parent ∉ ImmutableFiles.
"""
def test_mkdir_methodic_1(t: LinuxTestSpec):
    policy_uid = 2000
    ima_user = 'ima_user'
    t.make_user(ima_user, uid=policy_uid)

    t.make_dir('/parent_dir', ima_user, ima_user, 0o755)
    
    new_dir_path = '/parent_dir/new_subdir'

    with t.make_program_and_run(ima_user, ima_user, umask=0) as child:
        # should pass
        child.mkdir(new_dir_path, 0o755, fatal=True)