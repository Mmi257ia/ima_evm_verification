from collections.abc import Callable, Generator, Iterator
from contextlib import contextmanager
from copy import copy
import os
from os.path import join, dirname
import textwrap
from typing import IO, Any, Protocol

from anis.stages.config import resources_path
from anis.stages.trace_checkers import ModelTraceInterpreter
from anis.stages.mediator import ModelTraceConsumer
from anis.model.lazy import Event

from mediator.translator import TraceTranslator


class LineStream(Protocol):

    def readline(self, *args: Any, **kwargs: Any) -> str:
        ...

    def __iter__(self) -> Iterator[str]:
        ...


class LineDumpingStream:

    def __init__(self, raw_trace: LineStream, f: IO[str]):
        super().__init__()
        self._raw_trace = raw_trace
        self._f = f

    def readline(self, *args: Any, **kwargs: Any):
        line = self._raw_trace.readline(*args, **kwargs)
        if line:
            self._f.write(line)
        return line

    def __iter__(self):
        for line in self._raw_trace:
            self._f.write(line)
            yield line

    # def __getattr__(self, name: str):
    #     return getattr(self._raw_trace, name)


@contextmanager
def trace_txt_saving(label: str, orig_stream: LineStream) -> Generator[LineStream, None, None]:

    path_txt = join(resources_path(), 'stages', f'trace_{label}.txt')
    os.makedirs(dirname(path_txt), exist_ok=True)

    with open(path_txt, "w", encoding='utf-8') as f:

        yield LineDumpingStream(orig_stream, f)

        # def getline(required: bool=False):
        #     line = raw_trace.readline()
        #     if not line and required:
        #         raise ValueError('EOF')
        #     f.write(line)
        #     if required:
        #         return line.rstrip('\n')
        #     else:
        #         return line

        # yield getline


@contextmanager
def trace_py_saving(label: str, TT: type[TraceTranslator]) -> Generator[type[TraceTranslator], None, None]:

    path_py = join(resources_path(), 'stages', f'trace_{label}.py')
    os.makedirs(dirname(path_py), exist_ok=True)

    with open(path_py, "w", encoding='utf-8') as f:

        class WrappedTraceTranslator(TT):

            def __init__(self, model_trace: ModelTraceConsumer, m: Any, root_dev: int, root_ino: int, root_uid: int, root_gid: int):
                super().__init__(
                    model_trace=model_trace,
                    m=m,
                    root_dev=root_dev, root_ino=root_ino, root_uid=root_uid, root_gid=root_gid)

                self._wrapped_methods = dict[str, Callable[..., Any]]()

                f.write(textwrap.dedent(f"""
                    import conftest
                    from mediator.translator import TraceTranslator
                    from anis.stages.trace_checkers import ModelTraceInterpreter

                    m = conftest.m._get_wrapped_function()() # pyright: ignore[reportPrivateUsage]
                    tt = TraceTranslator(model_trace=ModelTraceInterpreter(machine=m), m=m,
                                        root_dev={root_dev}, root_ino={root_ino}, root_uid={root_uid}, root_gid={root_gid})
                """))

            def _wrap(self, method: Any, name: str):
                if name in self._wrapped_methods:
                    return self._wrapped_methods[name]
                def wrapped(*args: Any, **kwargs: Any):
                    args_printed = ", ".join(f"{k} = {repr(v)}" for k, v in kwargs.items())
                    f.write(f'tt.{name}({args_printed})\n')
                    return method(*args, **kwargs)
                self._wrapped_methods[name] = wrapped
                return wrapped

            def __getattribute__(self, name: str):
                attr = super().__getattribute__(name)
                if not name.startswith('_') and not name.endswith('_') and callable(attr):
                    return self._wrap(attr, name)
                return attr

        yield WrappedTraceTranslator


@contextmanager
def model_trace_py_saving(label: str, MT: type[ModelTraceInterpreter]) -> Generator[type[ModelTraceInterpreter], None, None]:

    path_model_py = join(resources_path(), 'stages', f'mtrace_{label}.py')
    os.makedirs(dirname(path_model_py), exist_ok=True)

    with open(path_model_py, "w", encoding='utf-8') as f:

        class WrappedModelTraceInterpreter(MT):

            def __init__(self, machine: Any):
                super().__init__(machine)
                self._machine_copy = copy(machine)
                self._imported = set[str]()

                f.write(textwrap.dedent(f"""
                    import conftest
                    m = conftest.m._get_wrapped_function()() # pyright: ignore[reportPrivateUsage]

                """))

            def add(self, event_function: Callable[..., Event], *, expected: bool, skip_coverage: bool = False, **args: Any):

                m_changed = False
                carrier_sets = getattr(self.machine, '_carrier_sets')
                for carrier_set_name, real_item_type in carrier_sets.values():
                    cs_new = getattr(self.machine, carrier_set_name)
                    cs_old = getattr(self._machine_copy, carrier_set_name)
                    if cs_new == cs_old:
                        continue
                    for v in cs_new - cs_old:
                        c = 'carrier_set_item'
                        if c not in self._imported:
                            f.write(f'from anis.model.expressions import {c}\n')
                            self._imported.add(c)
                        f.write(f'{repr(v)} = {c}(m, m.{real_item_type.__name__})\n')
                        m_changed = True

                for attr in dir(self.machine):
                    if attr.startswith('_') or attr.endswith('_'):
                        continue
                    v_new = getattr(self.machine, attr)
                    v_old = getattr(self._machine_copy, attr)
                    if v_new != v_old:
                        f.write(f'm.{attr} = {repr(v_new)}\n')
                        m_changed = True

                check_axioms = 'check_axioms'

                if m_changed:
                    if check_axioms not in self._imported:
                        f.write(f'from anis.stages.invariants import {check_axioms}\n')
                        self._imported.add(check_axioms)
                    f.write(f'{check_axioms}(m)\n')

                name = event_function.__name__
                assertion = 'assertTrue' if expected else 'assertFalse'
                if assertion not in self._imported:
                    f.write(f'from anis.stages.assertions import {assertion}\n')
                    self._imported.add(assertion)
                if name not in self._imported:
                    f.write(f'from model.events.{name} import {name}\n')
                    self._imported.add(name)
                args_printed = ", ".join(f"{k} = {k}" for k in args)
                for k, v in args.items():
                    # TODO empty frozensets should be explicitly typed (also inside other structures)
                    f.write(f'{k} = {repr(v)}\n')
                f.write(f'{assertion}({name}(m, {args_printed}))\n')

                if expected:
                    if check_axioms not in self._imported:
                        f.write(f'from anis.stages.invariants import {check_axioms}\n')
                        self._imported.add(check_axioms)
                    f.write(f'{check_axioms}(m)\n')

                f.write('\n')

                ret = super().add(event_function, expected=expected, skip_coverage=skip_coverage, **args)

                self._machine_copy = copy(self.machine)

                return ret

        yield WrappedModelTraceInterpreter