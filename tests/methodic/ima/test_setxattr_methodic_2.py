from tests.spec import LinuxTestSpec

def test_setxattr_methodic_2(t: LinuxTestSpec):
    ima_user = 'ima_user'
    t.make_user(ima_user, uid=2000)
    t.enable_ima_evm()

    ima_evm_dir = 'ima_evm_dir'
    t.make_dir(f'/{ima_evm_dir}/dir', ima_user, ima_user, 0o755)
    t.make_file(f'/{ima_evm_dir}/dir/file', owner=ima_user, group=ima_user, mode=0o644)
    t.add_setup(f'chattr +i /{ima_evm_dir}/dir/file')

    with t.make_program_and_run(ima_user, ima_user, ima_evm_dir=ima_evm_dir, umask=0) as child:
        # should fail - but it passes because grd is fail and setxattr return error 
        value = b'ABC'
        #with fatal it is ValueError
        child.setxattr(f'/{ima_evm_dir}/dir/file', 'user.test', value, len(value), 0)
