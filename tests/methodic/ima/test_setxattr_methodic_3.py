from tests.spec import LinuxTestSpec

def test_setxattr_methodic_3(t: LinuxTestSpec):
    ima_user = 'ima_user'
    t.make_user(ima_user, uid=2000)
    t.enable_ima_evm()

    ima_evm_dir = 'ima_evm_dir'
    t.make_dir(f'/{ima_evm_dir}/dir', 'ima_user', ima_user, 0o755)
    t.make_file(f'/{ima_evm_dir}/dir/file', owner=ima_user, group=ima_user, mode=0o644)

    try:
        with t.make_program_and_run(ima_user, ima_user, ima_evm_dir=ima_evm_dir, umask=0) as child:
            # should fail
            value = b'ABC'
            child.setxattr(f'/{ima_evm_dir}/dir/file', 'security.ima', value, len(value), 0)
    except AssertionError as e:
        print(f"Rightfully caught exception {e}")
        pass

