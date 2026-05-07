"""
Generates tests with directed coverage of different "flags" of open-like events
"""

import textwrap
from typing import Any
from z3 import Bool, Or, And, Not, Solver, is_true, sat, ModelRef, BoolRef # type: ignore

creat = Bool('creat')
tmpfile = Bool('tmpfile')
rdonly = Bool('rdonly')
wronly = Bool('wronly')
rdwr = Bool('rdwr')
path = Bool('path')
excl = Bool('excl')
directory = Bool('directory')
is_folder = Bool('is_folder')


def model_to_flags(m: ModelRef) -> tuple[str, str]:
    n = set[str]()
    is_folder_value = 'file'
    for d in m.decls():
        if is_true(m[d]):
            if d == is_folder.decl():
                is_folder_value = 'dir'
            else:
                n.add(f'os.O_{d.name().upper()}')
    return (
        '0' if not n else ' | '.join(n),
        is_folder_value
    )

def solve(event: str, cases: dict[str, Any]):
    flags = set[tuple[str, str]]() # set - to remove duplicate flags

    for name, formula in cases.items():
        s = Solver()
        s.add(formula)
        if s.check() == sat:
            flags.add(model_to_flags(s.model()))
        else:
            print(f'{event}:{name}: unsat')
    
    return flags


def open_create_flags():

    grd11 = Or(creat, tmpfile)
    grd12 = Or(rdonly, wronly, rdwr)
    grd13 = And(Not(And(rdonly, wronly)), Not(And(rdonly, rdwr)), Not(And(wronly, rdwr)))
    grd14 = Or(Not(tmpfile), wronly, rdwr)
    grd18 = Not(path)

    return solve('open_create', {

        'grd11[FF]': And(Not(creat), Not(tmpfile), grd12, grd13, grd14, grd18),
        'grd11[TF]': And(creat, Not(tmpfile), grd12, grd13, grd14, grd18),
        'grd11[FT]': And(Not(creat), tmpfile, grd12, grd13, grd14, grd18),

        'grd12[FFF]': And(grd11, Not(rdonly), Not(wronly), Not(rdwr), grd13, grd14, grd18),
        'grd12[TFF]': And(grd11, rdonly, Not(wronly), Not(rdwr), grd13, grd14, grd18),
        'grd12[FTF]': And(grd11, Not(rdonly), wronly, Not(rdwr), grd13, grd14, grd18),
        'grd12[FFT]': And(grd11, Not(rdonly), Not(wronly), rdwr, grd13, grd14, grd18),

        'grd14[FFF]': And(grd11, grd12, grd13, Not(Not(tmpfile)), Not(wronly), Not(rdwr), grd18),
        'grd14[TFF]': And(grd11, grd12, grd13, Not(tmpfile), Not(wronly), Not(rdwr), grd18),
        'grd14[FTF]': And(grd11, grd12, grd13, Not(Not(tmpfile)), wronly, Not(rdwr), grd18),
        'grd14[FFT]': And(grd11, grd12, grd13, Not(Not(tmpfile)), Not(wronly), rdwr, grd18),

        'grd18[T]': And(grd11, grd12, grd13, grd14, Not(path)),
        'grd18[F]': And(grd11, grd12, grd13, grd14, Not(Not(path))),
    })

def open_exists_flags():

    # @grd9: O_PATH ∉ flags ⇒ ¬(O_CREAT ∈ flags ∧ O_EXCL ∈ flags) // допустимая конфигурация флагов, чтобы выполнение пошло по пути open_exists
    grd9 = Or(path, Not(creat), Not(excl))

    # @grd10: O_RDONLY ∈ flags ∨ O_WRONLY ∈ flags ∨ O_RDWR ∈ flags // данные флаги взаимоисключаемы TODO: Also only if O_PATH ∉ flags?
    grd10 = Or(rdonly, wronly, rdwr)

    # @grd11: ¬(O_RDONLY ∈ flags ∧ O_WRONLY ∈ flags)
    #            ∧ ¬(O_RDONLY ∈ flags ∧ O_RDWR ∈ flags)
    #            ∧ ¬(O_WRONLY ∈ flags ∧ O_RDWR ∈ flags) // данные флаги не могут быть выставлены одновременно
    grd11 = And(Not(And(rdonly, wronly)), Not(And(rdonly, rdwr)), Not(And(wronly, rdwr)))

    # @grd12: file ∈ Folders ∧ O_PATH ∉ flags ⇒ O_WRONLY ∉ flags ∧ O_RDWR ∉ flags // директорию открывать на запись с помощью open нельзя
    grd12 = Or(Not(is_folder), path, And(Not(wronly), Not(rdwr)))

    # @grd15: O_DIRECTORY ∈ flags ⇒ file ∈ Folders // если выставлен флаг O_DIRECTORY, то файл должен быть директорией
    grd15 = Or(Not(directory), is_folder)

    # @grd16: O_DIRECTORY ∈ flags ∧ O_PATH ∉ flags ⇒ O_RDONLY ∈ flags // если выставлен флаг O_DIRECTORY, то открывать директорию можно только на чтение
    grd16 = Or(Not(directory), path, rdonly)

    # @grd21: O_DIRECTORY ∈ flags ∧ O_PATH ∉ flags ⇒ O_CREAT ∉ flags // from Linux implementation
    grd21 = Or(Not(directory), path, Not(creat))

    # @grd22: O_PATH ∉ flags ∧ O_CREAT ∈ flags ⇒ file ∉ Folders // from Linux implementation
    grd22 = Or(path, Not(creat), Not(is_folder))

    return solve('open_exists', {

        'grd9[FFF]': And(Not(path), Not(Not(creat)), Not(Not(excl)), grd10, grd11, grd12, grd15, grd16, grd21, grd22),
        'grd9[TFF]': And(path, Not(Not(creat)), Not(Not(excl)), grd10, grd11, grd12, grd15, grd16, grd21, grd22),
        'grd9[FTF]': And(Not(path), Not(creat), Not(Not(excl)), grd10, grd11, grd12, grd15, grd16, grd21, grd22),
        'grd9[FFT]': And(Not(path), Not(Not(creat)), Not(excl), grd10, grd11, grd12, grd15, grd16, grd21, grd22),

        'grd10[FFF]': And(grd9, Not(rdonly), Not(wronly), Not(rdwr), grd11, grd12, grd15, grd16, grd21, grd22),
        'grd10[TFF]': And(grd9, rdonly, Not(wronly), Not(rdwr), grd11, grd12, grd15, grd16, grd21, grd22),
        'grd10[FTF]': And(grd9, Not(rdonly), wronly, Not(rdwr), grd11, grd12, grd15, grd16, grd21, grd22),
        'grd10[FFT]': And(grd9, Not(rdonly), Not(wronly), rdwr, grd11, grd12, grd15, grd16, grd21, grd22),

        'grd12[FF(FT)]': And(grd9, grd10, grd11, Not(Not(is_folder)), Not(path), Not(Not(wronly)), Not(rdwr), grd15, grd16, grd21, grd22),
        'grd12[FF(TF)]': And(grd9, grd10, grd11, Not(Not(is_folder)), Not(path), Not(wronly), Not(Not(rdwr)), grd15, grd16, grd21, grd22),
        'grd12[TFF]': And(grd9, grd10, grd11, Not(is_folder), Not(path), Not(And(Not(wronly), Not(rdwr))), grd15, grd16, grd21, grd22),
        'grd12[FTF]': And(grd9, grd10, grd11, Not(Not(is_folder)), path, Not(And(Not(wronly), Not(rdwr))), grd15, grd16, grd21, grd22),
        'grd12[FF(TT)]': And(grd9, grd10, grd11, Not(Not(is_folder)), Not(path), And(Not(wronly), Not(rdwr)), grd15, grd16, grd21, grd22),

        'grd15[FF]': And(grd9, grd10, grd11, grd12, Not(Not(directory)), Not(is_folder), grd16, grd21, grd22),
        'grd15[TF]': And(grd9, grd10, grd11, grd12, Not(directory), Not(is_folder), grd16, grd21, grd22),
        'grd15[FT]': And(grd9, grd10, grd11, grd12, Not(Not(directory)), is_folder, grd16, grd21, grd22),

        'grd22[FFF]': And(grd9, grd10, grd11, grd12, grd15, grd16, grd21, Not(path), Not(Not(creat)), Not(Not(is_folder))),
        'grd22[TFF]': And(grd9, grd10, grd11, grd12, grd15, grd16, grd21, path, Not(Not(creat)), Not(Not(is_folder))),
        'grd22[FTF]': And(grd9, grd10, grd11, grd12, grd15, grd16, grd21, Not(path), Not(creat), Not(Not(is_folder))),
        'grd22[FFT]': And(grd9, grd10, grd11, grd12, grd15, grd16, grd21, Not(path), Not(Not(creat)), Not(is_folder)),
    })

def open_create_test_function():

    flags = open_create_flags()
    nl = '\n'
    return textwrap.dedent(f'''
        def test_open_create(t: LinuxTestSpec):
            with t.make_program_and_run('root', 'root', umask=0o022) as child:{"".join([nl +
f'                child.open("/file{i}", {f[0]}, 0o777)' for i, f in enumerate(flags)])}
        ''')

def openat_create_test_function():

    flags = open_create_flags()
    nl = '\n'
    return textwrap.dedent(f'''
        def test_openat_create(t: LinuxTestSpec):
            t.make_dir("/dir", "root", "root", 0o777)
            with t.make_program_and_run('root', 'root', umask=0o022) as child:
                fd = child.open("/dir", os.O_DIRECTORY | os.O_RDONLY, 0){"".join([nl +
f'                child.openat(fd, "file{i}", {f[0]}, 0o777)' for i, f in enumerate(flags)])}
        ''')



def open_exists_test_function():

    flags = open_exists_flags()
    nl = '\n'
    return textwrap.dedent(f'''
        def test_open_exists(t: LinuxTestSpec):{"".join([nl +
f'            t.make_{f[1]}("/{f[1]}{i}", "root", "root", 0o777)' for i, f in enumerate(flags)])}
            with t.make_program_and_run('root', 'root', umask=0o022) as child:{"".join([nl +
f'                child.open("/{f[1]}{i}", {f[0]}, 0)' for i, f in enumerate(flags)])}
        ''')

def openat_exists_test_function():

    flags = open_exists_flags()
    nl = '\n'
    return textwrap.dedent(f'''
        def test_openat_exists(t: LinuxTestSpec):
            t.make_dir("/dir", "root", "root", 0o777){"".join([nl +
f'            t.make_{f[1]}("/dir/{f[1]}{i}", "root", "root", 0o777)' for i, f in enumerate(flags)])}
            with t.make_program_and_run('root', 'root', umask=0o022) as child:
                fd = child.open("/dir", os.O_DIRECTORY | os.O_RDONLY, 0){"".join([nl +
f'                child.openat(fd, "{f[1]}{i}", {f[0]}, 0)' for i, f in enumerate(flags)])}
        ''')


with open('tests/for_mcdc/test_open_flags.py', 'w') as f:
    nl = '\n'
    f.write(textwrap.dedent(f'''
        from tests.spec import LinuxTestSpec
        import os
    '''))
    f.write(open_create_test_function())
    f.write(open_exists_test_function())
    f.write(openat_create_test_function())
    f.write(openat_exists_test_function())
