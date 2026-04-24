from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import partial_functions, cartesian_product, powerset, total_functions, relation_domain, function_value


def set_acl(m: Machine,
            _userACL: frozenset[tuple[tuple[Machine.FilesItem, Machine.UsersItem], frozenset[Machine.PermissionsItem]]] | None,
            _groupACL: frozenset[tuple[tuple[Machine.FilesItem, Machine.GroupsItem], frozenset[Machine.PermissionsItem]]] | None,
            _groupObjACL: frozenset[tuple[Machine.FilesItem, frozenset[Machine.PermissionsItem]]] | None,
            _maskACL: frozenset[tuple[Machine.FilesItem, frozenset[Machine.PermissionsItem]]] | None,
            _dacPermissions: frozenset[tuple[Machine.FilesItem, frozenset[Machine.PermissionsItem]]] | None) -> Event:

    userACL = Parameter(_userACL)
    groupACL = Parameter(_groupACL)
    groupObjACL = Parameter(_groupObjACL)
    maskACL = Parameter(_maskACL)
    dacPermissions = Parameter(_dacPermissions)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~userACL) in partial_functions(cartesian_product(m.Files, m.Users), powerset(m.USER_PERMISSIONS)))))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    (~groupACL) in partial_functions(cartesian_product(m.Files, m.Groups), powerset(m.GROUP_PERMISSIONS)))))

    _grd3 = Guard('grd3', lambda _: (_(3, 
    (~groupObjACL) in partial_functions(m.Files, powerset(m.GROUP_PERMISSIONS)))))

    _grd4 = Guard('grd4', lambda _: (_(4, 
    (~maskACL) in partial_functions(m.Files, powerset(m.GROUP_PERMISSIONS)))))

    _grd5 = Guard('grd5', lambda _: (_(5, 
    (~dacPermissions) in total_functions(m.Files, powerset(m.PERMISSIONS)))))

    _grd6 = Guard('grd6', lambda _: (_(6, 
    not any (True for (f, u) in relation_domain((~userACL)) if not (
        f in relation_domain((~maskACL))
    )))))

    _grd7 = Guard('grd7', lambda _: (_(7, 
    not any (True for (f, g) in relation_domain((~groupACL)) if not (
        f in relation_domain((~maskACL))
    )))))

    _grd8 = Guard('grd8', lambda _: (_(8, 
    not any (True for f in relation_domain((~maskACL)) if not (
        function_value((~maskACL), f) == (function_value((~dacPermissions), f) & m.GROUP_PERMISSIONS)
    )))))

    _grd9 = Guard('grd9', lambda _: (_(9, 
    not any (True for f in m.Files if f not in relation_domain((~maskACL)) if not (
        f in relation_domain((~groupObjACL)) and function_value((~groupObjACL), f) == (function_value((~dacPermissions), f) & m.GROUP_PERMISSIONS)
    )))))


    _act1 = Action('act1', m, 'UserACL', lambda: ((~userACL)))

    _act2 = Action('act2', m, 'GroupACL', lambda: ((~groupACL)))

    _act3 = Action('act3', m, 'GroupObjACL', lambda: ((~groupObjACL)))

    _act4 = Action('act4', m, 'MaskACL', lambda: ((~maskACL)))

    _act5 = Action('act5', m, 'DACPermissions', lambda: ((~dacPermissions)))


    return Event("set_acl", _grd1, _grd2, _grd3, _grd4, _grd5, _grd6, _grd7, _grd8, _grd9, _act1, _act2, _act3, _act4, _act5)
