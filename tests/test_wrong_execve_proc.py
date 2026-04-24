from tests.spec import LinuxTestSpec


def test(t: LinuxTestSpec):

    with t.make_program() as empty_prog:
        empty_prog.exit(0)
    empty = t.compile(empty_prog, '/tst_empty')

    with t.make_program_and_run(user='root', group='root', umask=0o022) as child:
        args = child.bound_value_as_charparray(init = ['/tst_empty'], prefix = 'args')
        envp = child.bound_value_as_charparray(init = [], prefix = 'envp')
        child.execve(empty, args, envp)