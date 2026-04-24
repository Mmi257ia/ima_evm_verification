from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import override_relation


def change_capabilities(m: Machine,
                        _user: Machine.UsersItem | None,
                        _caps: frozenset[Machine.CapabilitiesItem] | None) -> Event:

    user = Parameter(_user)
    caps = Parameter(_caps)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~user) in m.Users)))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    (~caps) <= m.CAPABILITIES)))


    _act1 = Action('act1', m, 'UserCaps', lambda: (override_relation(m.UserCaps, frozenset((((~user), (~caps)),)))))


    return Event("change_capabilities", _grd1, _grd2, _act1)
