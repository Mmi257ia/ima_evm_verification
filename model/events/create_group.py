from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action


def create_group(m: Machine,
                 _group: Machine.GroupsItem | None) -> Event:

    group = Parameter(_group)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~group) in (m.GROUPS - m.Groups))))


    _act1 = Action('act1', m, 'Groups', lambda: ((m.Groups | frozenset(((~group),)))))


    return Event("create_group", _grd1, _act1)
