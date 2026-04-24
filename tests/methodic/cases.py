from collections import defaultdict
from typing import Tuple, List

user = 'dac_user'
user_g4 = 'dac_user_g4'
user_g3_g4 = 'dac_user_g3_g4'
u1 = 'dac_u1'
u2 = 'dac_u2'
g1 = 'dac_g1'
g3 = 'dac_g3'
g4 = 'dac_g4'


class AclCase:
    def __init__(self, acl_user_obj: int, acl_mask: int, acl_user: int, acl_group: int, acl_group_obj: int, acl_other: int):
        super().__init__()
        self.acl_user_obj = acl_user_obj
        self.acl_mask = acl_mask
        self.acl_user = acl_user
        self.acl_group = acl_group
        self.acl_group_obj = acl_group_obj
        self.acl_other = acl_other

    def label(self):
        return f'U{self.acl_user_obj}m{self.acl_mask}u{self.acl_user}g{self.acl_group}G{self.acl_group_obj}o{self.acl_other}'

acl_cases = [
        AclCase(acl_user_obj, acl_mask, acl_user, acl_group, acl_group_obj, acl_other)

        for acl_user_obj in range(3)
        for acl_mask in range(3)
        for acl_user in range(4)
        for acl_group in range(9)
        for acl_group_obj in range(7)
        for acl_other in range(2)

        # ACL_MASK is mandatory if ACL_USER or ACL_GROUP is present
        if not ((acl_user != 0 or acl_group != 0) and acl_mask == 0)

        # Contradiction: subject user == object owner and !=
        if not (acl_user_obj in [1, 2] and acl_user == 3)

        # Contradiction: subject group == object group and !=
        if not (acl_group in [6, 8] and acl_group_obj in [1, 3, 4, 6])

        # Contradiction: subject user in object group and not in
        if not (acl_user == 3 and acl_group_obj in [2, 3, 5, 6])
]

def compute_acl_case(acl_case: AclCase) -> Tuple[List[str], str, str, str, str]:

    acl_entries: List[str] = []

    if acl_case.acl_group == 0:
        # no acl groups
        caller_user = user
    elif acl_case.acl_group == 1:
        # count(acl_groups) > 0 && caller_group ∉ acl_groups && (∀ group of caller_user · group ∉ acl_groups)
        caller_user = user_g4
    elif acl_case.acl_group == 2:
        caller_user = user_g4
    elif acl_case.acl_group == 3:
        caller_user = user_g4
    elif acl_case.acl_group == 4:
        caller_user = user_g4
    elif acl_case.acl_group == 5:
        caller_user = user_g4
    elif acl_case.acl_group == 6:
        caller_user = user_g4
    elif acl_case.acl_group == 7:
        caller_user = user_g3_g4
    elif acl_case.acl_group == 8:
        caller_user = user_g3_g4
    else:
        raise ValueError(f'Unsupported acl_group: {acl_case.acl_group}')


    if acl_case.acl_user_obj == 0:
        # caller user /= object user
        object_user = u1
        acl_entries.append('u::rwx')
    elif acl_case.acl_user_obj == 1:
        # caller user = object user, acl_user_obj without access
        object_user = caller_user
        acl_entries.append('u::---')
    elif acl_case.acl_user_obj == 2:
        # caller user = object user, acl_user_obj with access
        object_user = caller_user
        acl_entries.append('u::rwx')
    else:
        raise ValueError(f'Unsupported acl_user_obj: {acl_case.acl_user_obj}')

    if acl_case.acl_mask == 0:
        pass
    elif acl_case.acl_mask == 1:
        acl_entries.append('m::---')
    elif acl_case.acl_mask == 2:
        acl_entries.append('m::rwx')
    else:
        raise ValueError(f'Unsupported acl_mask: {acl_case.acl_mask}')

    if acl_case.acl_user == 0:
        # no acl_user records
        pass
    elif acl_case.acl_user == 1:
        # acl_user records are presented but without caller user
        acl_entries.append(f'u:{u2}:rwx')
    elif acl_case.acl_user == 2:
        # acl_user record has caller user without access
        acl_entries.append(f'u:{caller_user}:---')
        acl_entries.append(f'u:{u2}:rwx')
    elif acl_case.acl_user == 3:
        # acl_user record has caller user with access
        acl_entries.append(f'u:{caller_user}:rwx')
    else:
        raise ValueError(f'Unsupported acl_user: {acl_case.acl_user}')

    if acl_case.acl_group_obj == 0:
        # object_group ≠ caller_group && caller_user ∉ object_group 
        caller_group = caller_user
        object_group = g1
        acl_entries.append('g::rwx')
    elif acl_case.acl_group_obj == 1:
        # object_group = caller_group && caller_user ∉ object_group && no access 
        caller_group = g1
        object_group = g1
        acl_entries.append('g::---')
    elif acl_case.acl_group_obj == 2:
        # object_group ≠ caller_group && caller_user ∈ object_group && no access
        caller_group = g1
        object_group = caller_user
        acl_entries.append('g::---')
    elif acl_case.acl_group_obj == 3:
        # object_group = caller_group && caller_user ∈ object_group && no access
        caller_group = caller_user
        object_group = caller_user
        acl_entries.append('g::---')
    elif acl_case.acl_group_obj == 4:
        # object_group = caller_group && caller_user ∉ object_group && has access 
        caller_group = g1
        object_group = g1
        acl_entries.append('g::rwx')
    elif acl_case.acl_group_obj == 5:
        # object_group ≠ caller_group && caller_user ∈ object_group && has access
        caller_group = g1
        object_group = caller_user
        acl_entries.append('g::rwx')
    elif acl_case.acl_group_obj == 6:
        # object_group = caller_group && caller_user ∈ object_group && has access
        caller_group = caller_user
        object_group = caller_user
        acl_entries.append('g::rwx')
    else:
        raise ValueError(f'Unsupported acl_group_obj: {acl_case.acl_group_obj}')

    if acl_case.acl_group == 0:
        # no acl groups
        pass
    elif acl_case.acl_group == 1:
        # count(acl_groups) > 0 && caller_group ∉ acl_groups && (∀ group of caller_user · group ∉ acl_groups)
        acl_entries.append(f'g:{g3}:rwx')
    elif acl_case.acl_group == 2:
        acl_entries.append(f'g:{caller_group}:---')
        acl_entries.append(f'g:{g3}:rwx')
    elif acl_case.acl_group == 3:
        acl_entries.append(f'g:{caller_group}:rwx')
        acl_entries.append(f'g:{g3}:---')
    elif acl_case.acl_group == 4:
        acl_entries.append(f'g:{g4}:---')
        acl_entries.append(f'g:{g3}:rwx')
    elif acl_case.acl_group == 5:
        acl_entries.append(f'g:{g4}:---')
        acl_entries.append(f'g:{g3}:rwx')
        acl_entries.append(f'g:{caller_group}:---')
    elif acl_case.acl_group == 6:
        acl_entries.append(f'g:{g4}:---')
        acl_entries.append(f'g:{g3}:rwx')
        acl_entries.append(f'g:{caller_group}:rwx')
    elif acl_case.acl_group == 7:
        acl_entries.append(f'g:{caller_group}:---')
        acl_entries.append(f'g:{g3}:rwx')
        acl_entries.append(f'g:{g4}:---')
    elif acl_case.acl_group == 8:
        acl_entries.append(f'g:{caller_group}:rwx')
        acl_entries.append(f'g:{g3}:rwx')
        acl_entries.append(f'g:{g4}:---')
    else:
        raise ValueError(f'Unsupported acl_group: {acl_case.acl_group}')

    if acl_case.acl_other == 0:
        acl_entries.append('o::---')
    elif acl_case.acl_other == 1:
        acl_entries.append('o:rwx')
    else:
        raise ValueError(f'Unsupported acl_other: {acl_case.acl_other}')

    return (acl_entries, caller_user, caller_group, object_user, object_group)


# users and groups are created in the session, not here!

# group acl cases by sets with the same pair (caller_user, caller_group)
UserGroupPair = Tuple[str, str]
AclCasesGroup = List[Tuple[AclCase, List[str], str, str]]
acl_cases_grouped: defaultdict[UserGroupPair, AclCasesGroup] = defaultdict(list)
for acl_case in acl_cases:
    acl_entries, caller_user, caller_group, object_user, object_group = compute_acl_case(acl_case)
    acl_cases_grouped[(caller_user, caller_group)].append((acl_case, acl_entries, object_user, object_group))
