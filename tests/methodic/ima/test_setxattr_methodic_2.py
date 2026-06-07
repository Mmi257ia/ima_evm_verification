from tests.spec import LinuxTestSpec

def test_setxattr_methodic_2(t: LinuxTestSpec):
    ima_user = 'ima_user'
    t.make_user(ima_user, uid=2000)
    
    # Создаем директорию и файл
    t.make_dir('/dir', ima_user, ima_user, 0o755)
    t.make_file('/dir/file', owner=ima_user, group=ima_user, mode=0o644)
    t.add_setup('chattr +i /dir/file')

    try:
        with t.make_program_and_run(ima_user, ima_user, umask=0) as child:
            value = b'ABC'
            child.setxattr('/dir/file', 'user.test', value, len(value), 0, fatal=True)
            raise Exception("ERROR")
    except Exception:
        pass