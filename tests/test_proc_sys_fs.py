from _pytest.fixtures import FixtureRequest
from pytest import fixture, mark
from model.events import link
from tests.spec import LinuxTestSpec

@fixture(params=[0o0, 0o4, 0o3, 0o7], ids=['rNwN', 'rYwN', 'rNwY', 'rYwY'])
def rwmode(request: FixtureRequest):
    return request.param

@fixture(params=['owner', 'nonowner'])
def subject_user(request: FixtureRequest):
    return request.param

from tests.methodic.cases import AclCasesGroup, UserGroupPair, acl_cases_grouped, \
    user, u1, u2, user_g3_g4, user_g4, g1, g3, g4

object_mode = 0o777

@fixture(
        params=acl_cases_grouped.items(),
        ids=[f'{u}__{g}' for u, g in acl_cases_grouped.keys()])
def acl_cases_group(request: FixtureRequest):
    return request.param

@fixture
def acl_users(t: LinuxTestSpec):
    t.make_user(user)
    t.make_user(u1)
    t.make_user(u2)
    t.make_group(g1)
    t.make_group(g3)
    t.make_group(g4)
    t.make_user(user_g4)
    t.add_setup(f'usermod -G {g4} {user_g4}')
    t.make_user(user_g3_g4)
    t.add_setup(f'usermod -G {g3},{g4} {user_g3_g4}')

@mark.skipif(condition=('ProtectedHardlinks' not in link.machines), reason='Intended only for ProtectedHarlinks machine')
def test_protected_hardlinks(t: LinuxTestSpec, acl_users: None, acl_cases_group: tuple[UserGroupPair, AclCasesGroup]):

    caller_pair, cases = acl_cases_group
    caller_user, caller_group = caller_pair

    for i, case in enumerate(cases):
        _, acl_entries, object_user, object_group = case
        t.make_dir(f'/dir{i}', owner=object_user, group=object_group, mode=object_mode)
        t.make_file(f'/orig{i}', owner=object_user, group=object_group, mode=object_mode)
        t.add_setup(f'setfacl -m {",".join(acl_entries)} /orig{i}') # test_acl_access() sets acls to /dir, not to /orig

    with t.make_program_and_run(user=caller_user, group=caller_group, umask=0o022) as child:
        for i in range(len(cases)):
            child.link(f'/orig{i}', f'/dir{i}/link')