from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
import io
import json
from os.path import basename, isabs
from pathlib import Path
from shutil import copytree
import subprocess
import sys
import tempfile
import textwrap
from typing import Any, Iterator

from anis.stages.trace_checkers import ModelTraceInterpreter
from anis.stages.systrace import TraceOperation
from anis.stages.monitor import make_call

from testing.dump import LineStream, model_trace_py_saving, trace_py_saving, trace_txt_saving
from testing.kernel_program_maker import KernelProgramMaker, MonitoredExeFile
from mediator.translator import TraceTranslator
from tests.spec import LinuxTestSpec, ProgramMakerTextProducer, TextProducer
from testing.initialiser import Snapshot, SnapshotBuilder

from anis.stages.invariants import check_axioms


class LinuxTestSpecImpl(LinuxTestSpec):

    def __init__(self, nodeid: str, m: Any, testpath: Path):
        super().__init__()
        self._nodeid = nodeid
        self._testpath = testpath
        self._setup_commands = list[str]()
        self._initialiser = SnapshotBuilder()
        self._additional_files = dict[str, str]()
        self._machine = m
        self._label = sha256(nodeid.encode()).hexdigest()[:10]


    def make_user(self,
                user: str,
                supplementary_groups: None | list[str] = None) -> None:
        self._initialiser.add_user(user)
        if not supplementary_groups:
            self.add_setup(f'useradd {user}')
        else:
            self.add_setup(f'useradd -G {",".join(supplementary_groups)} {user}')

    def make_group(self, group: str) -> None:
        self._initialiser.add_group(group)
        self.add_setup(f'groupadd {group}')

    def make_file(self,
                  path: str,
                  owner: str,
                  group: str,
                  mode: int) -> None:
        if not isabs(path):
            raise ValueError('Relative paths are not supported')
        self._initialiser.add_file(path)
        self.add_setup(f'touch {path}')
        self.add_setup(f'chown {owner}:{group} {path}')
        self.add_setup(f'chmod {mode:0o} {path}')
        

    def make_dir(self,
                 path: str,
                 owner: str,
                 group: str,
                 mode: int) -> None:
        if not isabs(path):
            raise ValueError('Relative paths are not supported')
        self._initialiser.add_dir(path)
        self.add_setup(f'mkdir {path}')
        self.add_setup(f'chown {owner}:{group} {path}')
        self.add_setup(f'chmod {mode:0o} {path}')
    
    def add_setup(self, setup_cmd: str) -> Any:
        self._setup_commands.append(setup_cmd)

    @contextmanager
    def make_program(self) -> Iterator[ProgramMakerTextProducer]:
        yield KernelProgramMaker()

    def compile(self, program_maker: TextProducer, path: str, make_file: bool=True) -> MonitoredExeFile:
        source_path = f'{path}.c'
        if basename(source_path) in self._additional_files:
            raise ValueError('Additional file redefined')

        program_text = program_maker.get_text()
        self._additional_files[basename(source_path)] = program_text
        if make_file:
            self.make_file(path, 'root', 'root', 0o777)
        self.add_setup(f'gcc -static -o {path} /progs/{basename(source_path)}')
        return MonitoredExeFile(path)


    @contextmanager
    def make_program_and_run(self, user: str, group: str, umask: int, runner: str = '<>', make_file: bool = True,
                             before_run: str|None=None, after_run: str|None=None):
        with self.make_program() as prog:
            yield prog
        exeFile = self.compile(prog, '/tst_prog', make_file)
        self.run(exeFile, user, group, umask, runner, before_run, after_run)


    def run(self, exeFile: MonitoredExeFile,
            user: str, group: str, umask: int, runner: str,
            before_run: str|None, after_run: str|None):

        # with self._run_with_preparing_image(exeFile=exeFile,
        #         user=user, group=group, umask=umask, runner=runner,
        #         before_run=before_run, after_run=after_run) as trace:

        with self._run_without_preparing_image(exeFile=exeFile,
                user=user, group=group, umask=umask, runner=runner,
                before_run=before_run, after_run=after_run) as trace:

            self._check(trace)


    @contextmanager
    def _run_with_preparing_image(self, exeFile: MonitoredExeFile,
            user: str, group: str, umask: int, runner: str,
            before_run: str|None, after_run: str|None):

        setup_cmd = ' && '.join(self._setup_commands)
        runner_cmd = runner.replace('<>', f'(chfn --other="umask={umask:0o}" {user}; /monitoring/monitor run sudo -HE -u {user} -g {group} {exeFile.path})')


        def main():

            build_image()

            if before_run:
                subprocess.run(['sudo', '/bin/bash'], input=before_run, encoding='utf-8', check=True)

            container_name = f"anis_{self._label}"
            proc = None
            try:
                proc = subprocess.Popen(['sudo', 'podman', 'run',
                            '--rm',
                            f'--name={container_name}',
                            '--cap-add=CAP_BPF', '--cap-add=CAP_SYS_ADMIN',
                            '-v', '/sys/fs/bpf:/sys/fs/bpf:rw',
                            '-v', '/sys/kernel:/sys/kernel:ro',
                            # '--pid=host',
                            # '--network=host',
                            # '--security-opt', 'label=disable',
                            f'anis:{self._label}'
                            ], stdout=subprocess.PIPE, text=True, bufsize=1, encoding='utf-8')

                if not proc.stdout:
                    raise ValueError('No stdout')

                yield proc.stdout
            except:
                subprocess.run(['sudo', 'podman', 'kill', container_name])
                raise
            finally:
                if proc:
                    if proc.stdout:
                        proc.stdout.close()
                    proc.wait(timeout=5)

                if after_run:
                    subprocess.run(['sudo', '/bin/bash'], input=after_run, encoding='utf-8')

        def build_image():

            gatherinfo_commands = self._initialiser.make_text_of_gatherinfo_file() # this make important
                # changings in self._initialiser, so it is necessary to call it also if image is newer

            if image_is_newer_than(self._testpath, Path('conftest.py'),
                                    *all_monitoring_files(),
                                    *all_py_files(Path('testing')),
                                    *all_files(Path('testing') / 'base_image')):
                return

            with tempfile.TemporaryDirectory() as base:

                container_file = make_text_of_container_file()
                base_path = Path(base)
                (base_path / 'Containerfile').write_text(container_file)
                (base_path / 'gather_info.sh').write_text('\n'.join(['#! /bin/bash -e'] + gatherinfo_commands))
                (base_path / 'setup.sh').write_text(setup_cmd)
                copytree('monitoring', str(base_path / 'monitoring'))
                (base_path / 'progs').mkdir()
                for path, contents in self._additional_files.items():
                    (base_path / 'progs' / basename(path)).write_text(contents)

                subprocess.run(['sudo', 'podman', 'build',
                                '-t', f'anis:{self._label}',
                                base,
                                ], check=True)

        def all_files(parent: Path):
            return [p for p in parent.iterdir() if p.is_file()]

        def all_py_files(parent: Path):
            return [p for p in parent.iterdir() if p.is_file() and p.suffix == '.py']

        def all_monitoring_files():
            return [p for p in Path('monitoring').iterdir() if p.is_file()
                    and (p.name == 'Makefile' or
                            p.suffix in {'.c', 'h'} and not p.name.endswith('.skel.h'))]


        def image_is_newer_than(*paths: Path):
            image_ts = get_image_timestamp()
            return (image_ts is not None and
                    all(file.stat().st_mtime < image_ts for file in paths))


        def get_image_timestamp():

            proc = subprocess.run(['sudo', 'podman', 'image', 'inspect', f'anis:{self._label}', '--format="{{.Created}}'],
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, encoding='utf-8')
            if proc.returncode != 0:
                return None

            s_clean = proc.stdout.strip('"').replace(" UTC", "")
            time_part = s_clean.split(" +")[0]
            if '.' in time_part:
                date_part, micro_part = time_part.split('.')
                micro_part = micro_part[:6].ljust(6, '0')  # если меньше 6 цифр, добавляем нули
                time_part = f"{date_part}.{micro_part}"
            return (datetime.strptime(time_part, "%Y-%m-%d %H:%M:%S.%f")
                    .replace(tzinfo=timezone.utc)
                    .timestamp())



        def make_text_of_container_file():
            return textwrap.dedent(f"""
                FROM anis:base
                COPY ./ /
                RUN chmod +x /gather_info.sh && chmod +x /setup.sh && /setup.sh
                CMD /gather_info.sh && ({runner_cmd})""")


        return main()



    @contextmanager
    def _run_without_preparing_image(self, exeFile: MonitoredExeFile,
            user: str, group: str, umask: int, runner: str,
            before_run: str|None, after_run: str|None):

        container_name = f"anis_{self._label}"

        with tempfile.TemporaryDirectory() as base:

            base_path = Path(base)
            for path, contents in self._additional_files.items():
                (base_path / basename(path)).write_text(contents)

            gatherinfo_commands = self._initialiser.make_text_of_gatherinfo_file() # this make important
            runner_cmd = runner.replace('<>', f'(chfn --other="umask={umask:0o}" {user}; /monitoring/monitor run sudo -HE -u {user} -g {group} {exeFile.path})')

            if not before_run:

                # 1. run setup
                # 2. run gather_info with printing output
                # 3. run runner

                cmd = ' && '.join(self._setup_commands + gatherinfo_commands + [runner_cmd])
                proc = None
                try:
                    print('run...', file=sys.stderr, end=' ')
                    proc = subprocess.run(['sudo', 'podman', 'run',
                        '--rm',
                        '-i',
                        f'--name={container_name}',
                        '--cap-add=CAP_BPF', '--cap-add=CAP_SYS_ADMIN',
                        '-v', f'{base_path}:/progs:ro',
                        '-v', '/sys/fs/bpf:/sys/fs/bpf:rw',
                        '-v', '/sys/kernel:/sys/kernel:ro',
                        '-v', './monitoring:/monitoring:ro',
                        # '--pid=host',
                        # '--network=host',
                        # '--security-opt', 'label=disable',
                        'anis:base',
                        '/bin/bash',
                        ], input=cmd, encoding='utf-8', check=True, capture_output=True)
                    if proc.stderr:
                        raise ValueError(proc.stderr)
                    print('ok', file=sys.stderr)

                    yield io.StringIO(proc.stdout)
                    # yield self._PrependedStream(info, proc.stdout)

                except:
                    # subprocess.run(['sudo', 'podman', 'stop', container_name])
                    subprocess.run(['sudo', 'podman', 'rm', '-f', container_name])
                    raise

            else:

                subprocess.run(['sudo', 'podman', 'run',
                    '-d',
                    '-i',
                    f'--name={container_name}',
                    '--cap-add=CAP_BPF', '--cap-add=CAP_SYS_ADMIN',
                    '-v', f'{base_path}:/progs:ro',
                    '-v', '/sys/fs/bpf:/sys/fs/bpf:rw',
                    '-v', '/sys/kernel:/sys/kernel:ro',
                    '-v', './monitoring:/monitoring:ro',
                    # '--pid=host',
                    # '--network=host',
                    # '--security-opt', 'label=disable',
                    'anis:base',
                    '/bin/bash'
                    ], check=True, stdout=subprocess.DEVNULL)

                try:
                    # 1. run setup
                    # 2. run gather_info with printing output
                    cmd = ' && '.join(self._setup_commands + gatherinfo_commands)
                    print('setup...', file=sys.stderr, end=' ')
                    proc = subprocess.run(['sudo', 'podman', 'exec',
                        '-i',
                        container_name,
                        '/bin/bash',
                        ], input=cmd, encoding='utf-8', check=True, capture_output=True)
                    if proc.stderr:
                        raise ValueError(proc.stderr)
                    info = proc.stdout
                    print('ok', file=sys.stderr)

                    # 3. run before_run
                    if before_run:
                        subprocess.run(['sudo', '/bin/bash'], input=before_run, encoding='utf-8', check=True)

                except:
                    # subprocess.run(['sudo', 'podman', 'stop', container_name])
                    subprocess.run(['sudo', 'podman', 'rm', '-f', container_name])
                    raise

                # 4. run runner
                proc = None
                try:
                    print('run...', file=sys.stderr, end=' ')
                    proc = subprocess.run(['sudo', 'podman', 'exec',
                        '-i',
                        container_name,
                        '/bin/bash',
                        ], input=runner_cmd, encoding='utf-8', capture_output=True)
                    print('ok', file=sys.stderr)

                    if proc.stderr:
                        raise ValueError(proc.stderr)
                    if not proc.stdout:
                        raise ValueError('No stdout')

                    yield io.StringIO(info + proc.stdout)
                except:
                    subprocess.run(['sudo', 'podman', 'kill', container_name])
                    raise
                finally:
                    if proc:
                        # if proc.stdout:
                        #     proc.stdout.close()
                        print('end...', file=sys.stderr, end=' ')
                        subprocess.run(['sudo', 'podman', 'attach', '--no-stdin', container_name], stdout=subprocess.DEVNULL)
                        subprocess.run(['sudo', 'podman', 'rm', '-f', container_name], stdout=subprocess.DEVNULL)
                        print('ok', file=sys.stderr)
                        # proc.wait(timeout=5)

                    # 5. run after_run
                    if after_run:
                        subprocess.run(['sudo', '/bin/bash'], input=after_run, encoding='utf-8')

    # class _PrependedStream(LineStream):
    #     def __init__(self, beginning: str, stream: LineStream):
    #         super().__init__()
    #         self._beginning = beginning.splitlines()
    #         self._stream = stream
    #         self._used = 0

    #     def readline(self, *args: Any, **kwargs: Any) -> str:
    #         if self._used < len(self._beginning):
    #             self._used += 1
    #             return self._beginning[self._used - 1] + '\n'
    #         else:
    #             return self._stream.readline(*args, **kwargs)

    #     def __iter__(self) -> Iterator[str]:
    #         while self._used < len(self._beginning):
    #             self._used += 1
    #             yield self._beginning[self._used - 1] + '\n'

    #         yield from self._stream

    def _check(self, raw_trace: LineStream):

        with trace_txt_saving(self._label, raw_trace) as trace, \
             trace_py_saving(self._label, TraceTranslator) as TT, \
             model_trace_py_saving(self._label, ModelTraceInterpreter) as MT:

            snapshot = self._initialiser.read_gathered_info(trace)

            tt = TT(model_trace=MT(self._machine), m=self._machine,
                    root_dev=snapshot.root.dev, root_ino=snapshot.root.ino,
                    root_uid=snapshot.root.uid, root_gid=snapshot.root.gid)

            self._replay_setup(snapshot, tt)
            self._replay_login(trace, tt)
            self._replay_trace(trace, tt)


    def _replay_setup(self, snapshot: Snapshot, tt: TraceTranslator):

        for group in snapshot.groups:
            tt.add_init_group(gid=group.gid)

        for user in snapshot.users:
            tt.add_init_user(uid=user.uid, primary_gid=user.gid, supplementary_gids=user.gids)

        for path, s in snapshot.folders.items():
            tt.add_init_folder(path=path, dev=s.dev, ino=s.ino,
                               uid=s.uid, gid=s.gid, perms=s.perms)

        for attrs in snapshot.folders_xattrs:
            tt.set_xattrs_init_file(path=attrs.path, xattrs = attrs.xattrs)

        for path, s in snapshot.files.items():
            tt.add_init_file_or_link(path=path, dev=s.dev, ino=s.ino,
                                     uid=s.uid, gid=s.gid, perms=s.perms)

        for attrs in snapshot.files_xattrs:
            tt.set_xattrs_init_file(path=attrs.path, xattrs = attrs.xattrs)

        tt.set_init_acl(data=snapshot.acl)

        check_axioms(self._machine)


    def _replay_login(self, trace: LineStream, tt: TraceTranslator):

        line = trace.readline()
        if not line:
            raise ValueError('EOF')
        login = json.loads(line)
        if login['syscall'] != 'execve':
            raise ValueError('No login execve in the trace')
        if login['ret'] != 0:
            raise ValueError('Failed login in the trace')

        tt.login(uid=login['euid'], gid=login['egid'], pid=login['pid'], exeFile=login['pathname'], umask=login['umask'])


    def _replay_trace(self, trace: LineStream, tt: TraceTranslator):

        for line in trace:
            event = json.loads(line)
            t_operation = TraceOperation(name=event['syscall'], ret=event['ret'], args=event)
            operation = make_call(t_operation)
            getattr(tt, operation.name)(**operation.args)
            check_axioms(self._machine)
