from pytest import fixture
from tests.spec import LinuxTestSpec


"""
 file ∉ ImmutableFiles.
"""
def test_chmod_methodic_1(t: LinuxTestSpec):
    policy_uid = 2000
    ima_user = 'ima_user'
    t.make_user(ima_user, uid=policy_uid)

    t.make_dir('/dir', ima_user, ima_user, 0o755)
    t.make_file('/dir/file', owner=ima_user, group=ima_user, mode=0o644)

    with t.make_program_and_run(ima_user, ima_user, umask=0) as child:
        # should pass 
        child.chmod('/dir/file', 0o600, fatal=True)