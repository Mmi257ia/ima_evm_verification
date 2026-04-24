from dataclasses import dataclass, field
from os.path import dirname, isabs

from testing.dump import LineStream

@dataclass
class StatLine:
    name: str
    dev: int
    ino: int
    uid: int
    gid: int
    perms: int

@dataclass
class GidLine:
    name: str
    gid: int

@dataclass
class UidLine:
    name: str
    uid: int
    gid: int
    gids: list[int]

@dataclass
class Xattrs:
    path: str
    xattrs: dict[str, str]

@dataclass
class Snapshot:
    root: StatLine
    groups: list[GidLine] = field(default_factory=list[GidLine])
    users: list[UidLine] = field(default_factory=list[UidLine])
    folders: dict[str, StatLine] = field(default_factory=dict[str, StatLine])
    folders_xattrs: list[Xattrs] = field(default_factory=list[Xattrs])
    files: dict[str, StatLine] = field(default_factory=dict[str, StatLine])
    files_xattrs: list[Xattrs] = field(default_factory=list[Xattrs])
    acl: list[tuple[str, list[str]]] = field(default_factory=list[tuple[str, list[str]]])


class SnapshotBuilder:

    def __init__(self):
        self._init_users = list[str]()
        self._init_groups = list[str]()
        self._init_files = list[str]()
        self._init_dirs = list[str]()

    def add_user(self, user: str) -> None:
        self._init_users.append(user)
        if user in self._init_groups:
            raise ValueError('Group already added')
        self._init_groups.append(user)

    def add_group(self, group: str) -> None:
        if group in self._init_groups:
            raise ValueError('Group already added')
        self._init_groups.append(group)

    def add_file(self, path: str) -> None:
        if not isabs(path):
            raise ValueError('Absolute path required')
        if path in self._init_files:
            raise ValueError('File already added')
        self._init_files.append(path)
        while True:
            path = dirname(path)
            if path == '/':
                break
            if path not in self._init_dirs:
                self._init_dirs.append(path)

    def add_dir(self, path: str) -> None:
        if not isabs(path):
            raise ValueError('Absolute path required')
        if path in self._init_dirs:
            raise ValueError('Dir already added')
        self._init_dirs.append(path)
        while True:
            path = dirname(path)
            if path == '/':
                break
            if path not in self._init_dirs:
                self._init_dirs.append(path)

    def make_text_of_gatherinfo_file(self):
        root = f'stat --format=%n,%d,%i,%u,%g,%f /'

        users = [f'echo {u}:$(id -u {u}):$(id -g {u}):$(id -G {u})' for u in self._init_users]
        groups = [f'getent group {" ".join(self._init_groups)}'] if len(self._init_groups) > 0 else []

        files_stat = [f'stat --format=%n,%d,%i,%u,%g,%f {" ".join(self._init_files)}'] if len(self._init_files) > 0 else []
        files_attrs = [f'getfattr --absolute-names -d -e hex {" ".join(self._init_files)}'] if len(self._init_files) > 0 else []
        files_acl = [f'getfacl -n -p -e {" ".join(self._init_files)}'] if len(self._init_files) > 0 else []

        self._init_dirs.sort() # sorting moves parent folder earlier in the list
        dirs_stat = [f'stat --format=%n,%d,%i,%u,%g,%f {" ".join(self._init_dirs)}'] if len(self._init_dirs) > 0 else []
        dirs_attrs = [f'getfattr --absolute-names -d -e hex {" ".join(self._init_dirs)}'] if len(self._init_dirs) > 0 else []
        dirs_acl = [f'getfacl -n -p -e {" ".join(self._init_dirs)}'] if len(self._init_dirs) > 0 else []

        return [root, *groups, *users, *dirs_stat, *dirs_attrs, 'echo "<>"', 
                    *files_stat, *files_attrs, 'echo "<>"',
                    *dirs_acl, *files_acl]

    def _xreadline(self, trace: LineStream):
        line = trace.readline()
        if not line:
            raise ValueError('EOF')
        return line.rstrip('\n')

    def read_gathered_info(self, trace: LineStream) -> Snapshot:

        snapshot = Snapshot(root=self._parse_stat_line(self._xreadline(trace)))

        for group in self._init_groups:
            g = self._parse_gid_line(self._xreadline(trace))
            if g.name != group:
                raise ValueError('Wrong gid line')
            snapshot.groups.append(g)

        for user in self._init_users:
            u = self._parse_uid_line(self._xreadline(trace))
            if u.name != user:
                raise ValueError('Wrong uid line')
            snapshot.users.append(u)

        for path in self._init_dirs:
            s = self._parse_stat_line(self._xreadline(trace))
            if s.name != path:
                raise ValueError('Wrong stat line')
            snapshot.folders[path] = s

        line = self._xreadline(trace)
        while True:
            if line == '<>':
                break
            attrs, line = self._parse_getfattr_output(line, trace)
            snapshot.folders_xattrs.append(attrs)

        for path in self._init_files:
            s = self._parse_stat_line(self._xreadline(trace))
            if s.name != path:
                raise ValueError('Wrong stat line')
            snapshot.files[path] = s

        line = self._xreadline(trace)
        while True:
            if line == '<>':
                break
            attrs, line = self._parse_getfattr_output(line, trace)
            snapshot.files_xattrs.append(attrs)

        for path in self._init_dirs + self._init_files:
            snapshot.acl.append(self._parse_getfacl_output(trace))

        return snapshot

    def _parse_stat_line(self, line: str):
        path, sdev, sino, suid, sgid, srawmode = line.strip().split(',')
        return StatLine(
                path,
                int(sdev),
                int(sino),
                int(suid),
                int(sgid),
                int(srawmode, base=16)
        )
    
    def _parse_gid_line(self, line: str):
        if len(line) == 0:
            raise ValueError('EOF')
        name, _, sgid, _ = line.strip().split(':')
        return GidLine(
            name,
            int(sgid),
        )

    def _parse_uid_line(self, line: str):
        if len(line) == 0:
            raise ValueError('EOF')
        name, suid, sgid, sgids = line.strip().split(':')
        return UidLine(
            name,
            int(suid),
            int(sgid),
            [int(g) for g in sgids.split(' ')]
        )

    def _parse_getfattr_output(self, first_line: str, trace: LineStream):
        attrs = dict[str, str]()
        # first line -- with file name
        fn = first_line.split('# file: ')
        if len(fn) != 2 or len(fn[0]) != 0:
            raise ValueError('getfattr: wrong first line')
        path = fn[1]

        while True:
            line = self._xreadline(trace)
            if len(line) == 0:
                return (Xattrs(path, attrs), self._xreadline(trace))

            name, svalue = line.split('=')
            if not svalue.startswith('0x'):
                raise ValueError('Incorrect xattr value encoding')
            attrs[name] = svalue[2:]


    def _parse_getfacl_output(self, trace: LineStream):
        file_line = self._xreadline(trace)
        fn = file_line.split('# file: ')
        if len(fn) != 2 or len(fn[0]) != 0:
            raise ValueError('getfacl: Wrong file line')
        path = fn[1]
        owner_line = self._xreadline(trace)
        if not owner_line.startswith('# owner: '):
            raise ValueError('getfacl: Wrong owner line')
        group_line = self._xreadline(trace)
        if not group_line.startswith('# group: '):
            raise ValueError('getfacl: Wrong group line')

        acls = list[str]()
        while True:
            line = self._xreadline(trace)
            if len(line) == 0:
                return (path, acls)
            acls.append(line)
