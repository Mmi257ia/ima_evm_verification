from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import cartesian_product, override_relation


def create_user(m: Machine,
                _user: Machine.UsersItem | None,
                _groups: frozenset[Machine.GroupsItem] | None,
                _caps: frozenset[Machine.CapabilitiesItem] | None) -> Event:

    user = Parameter(_user)
    groups = Parameter(_groups)
    caps = Parameter(_caps)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~user) in (m.USERS - m.Users))))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    (~groups) <= m.Groups)))

    _grd3 = Guard('grd3', lambda _: (_(3, 
    (~caps) <= m.CAPABILITIES)))


    _act1 = Action('act1', m, 'Users', lambda: ((m.Users | frozenset(((~user),)))))

    _act2 = Action('act2', m, 'UserGroups', lambda: ((m.UserGroups | cartesian_product(frozenset(((~user),)), (~groups)))))

    _act3 = Action('act3', m, 'UserCaps', lambda: (override_relation(m.UserCaps, frozenset((((~user), (~caps)),)))))


    return Event("create_user", _grd1, _grd2, _grd3, _act1, _act2, _act3)
