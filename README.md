# Ограничения модели

1. Политика IMA/EVM распространяется на файлы, созданные пользователями с id=2000, 2001.

2. Переключение режима в рантайме отсустствует, по умолчанию установлен режим ENFORCE.

3. Директории и симлинки не имеют хэша, хэш есть только у файлов.

4. @grd31: parent ∉ ImmutableFiles
Данное условие в модели запрещает открытие файла (open_exists) из immutable директории, но в реальности файл открывать можно.

```bash
ima_user@debian:~$ cd dir1
ima_user@debian:~/dir1$ touch file1
ima_user@debian:~/dir1$ echo "llll" > file1
ima_user@debian:~/dir1$ cd ..
ima_user@debian:~$ sudo chattr +i ./dir1
ima_user@debian:~$ lsattr -d dir1
----i---------e------- dir1
ima_user@debian:~$ cat ./dir1/file1 
llll
```

5. @grd30: IMAMode = ENFORCE ⇒ O_WRONLY ∉ flags ∧ O_RDWR ∉ flags
Данное условие в модели запрещает открывать файл за запись (open_exists) в режиме ENFORCE, но это не соответвтвует реальности.

```bash
ima_user@debian:~$ cd dir1/
ima_user@debian:~/dir1$ vi ./file1 
ima_user@debian:~/dir1$ 
```


# Заметки

## Настройка IMA/EVM
Конфигурация подсистем IMA и EVM задаётся при запуске системы из `initramfs` при помощи `dracut` (хотя можно это делать и на ходу, но лишь единожды до ближайшей перезагрузки).

Инструкция:

1) все действия будут от имени суперпользователя, поэтому ввести
```bash
su -
```

2) установить требуемые пакеты
```bash
apt update
apt install keyutils ima-evm-utils dracut
dracut -f
apt autoremove
```

3) сгенерировать encrypted ключ для EVM, подписанный user-ключом; эти действия важно выполнить за одну сессию терминала, в том числе поэтому выше был именно `su -`, так как `sudo` не подойдёт
```bash
mkdir -p /etc/keys
keyctl add user kmk-user "$(dd if=/dev/urandom bs=1 count=32 2> /dev/null)" @u   # генерация случайного ключа
keyctl pipe "$(keyctl search @u user kmk-user)" > /etc/keys/kmk-user.blob        # вывод ключа в файл
keyctl add encrypted evm-key "new user:kmk-user 32" @u                           # генерация ключа на основе kmk-user
keyctl pipe `keyctl search @u encrypted evm-key` > /etc/keys/evm-user.blob       # вывод ключа в файл
```

4) настроить `dracut`
```bash
# имя файла может быть любым, но должно кончаться на .conf
echo 'add_dracutmodules+=" masterkey integrity "' > /etc/dracut.conf.d/imaevm.conf
mkdir -p /etc/sysconfig

# MULTIKERNELMODE="NO"
# MASTERKEYTYPE="user"
# MASTERKEY="/etc/keys/kmk-${MASTERKEYTYPE}.blob"
echo -e 'MULTIKERNELMODE="NO"\nMASTERKEYTYPE="user"\nMASTERKEY="/etc/keys/kmk-${MASTERKEYTYPE}.blob"' > /etc/sysconfig/masterkey
# EVMKEY="/etc/keys/evm-user.blob"
echo 'EVMKEY="/etc/keys/evm-user.blob"' > /etc/sysconfig/evm
# appraise fowner=2000
# appraise fowner=2001
echo -e 'appraise fowner=2000\nappraise fowner=2001' > /etc/sysconfig/ima-policy
```

5) перегенерировать `initramfs`
```bash
dracut -f
```

6) к сожалению, в ядре 6.1 (и вообще до 6.5 включительно) существует баг, из-за которого подсистемы IMA/EVM и BPF вместе могут приводить к kernel panic при загрузке ядра, однако существует работающий костыль:
```bash
vim /etc/default/grub
```
найти строчку `GRUB_CMDLINE_LINUX_DEFAULT="quiet"` (в кавычках может оказаться что-то другое)  
поменять на: `GRUB_CMDLINE_LINUX_DEFAULT="quiet console=tty0 console=ttyS0 lsm=lockdown,yama,integrity,selinux,bpf,apparmor"`  
сохранить  
ввести:
```bash
update-grub
```
(помимо всего прочего, после этого вывод системы подключен не только к экрану, но и к последовательному порту (serial); в виртуальной машине можно присоединить к нему терминал и пользоваться системой без графического интерфейса)

После этого при запуске системы всегда будет активна IMA/EVM с вышеуказанной политикой.

Для тестирования может понадобиться пользователь с, например, `uid=2000`. Создать его можно следующей командой:
```bash
useradd -u 2000 --shell /usr/bin/bash -m <имя_нового_пользователя>
passwd <имя_нового_пользователя> # задать ему пароль
```
Перейти в терминал от его имени можно будет командой
```bash
su - <имя_нового_пользователя>
```

## Задание режима IMA/EVM
Режим работы IMA/EVM может быть задан только при загрузке ядра, так что для его изменения тоже нужно перезапускать всю систему: при открытии меню `grub` нажать `e` и приписать в конец строчки, начинающейся с `linux`: `ima_appraise=fix` (или не `fix`, а `off`/`enforce`; режим по умолчанию -- `enforce`), затем нажать `Ctrl+X`.

# Start
1. Open this directory in VSCode

2. Create Python environment

   1. Open any .py file in editor
   
   2. Install Python extensions which will be suggested
   
   3. Create virtual environment with installing dependencies
      (right-bottom corner)

3. Allow using of sudo:

   1. Make current user capabilities of sudoers:
   
       sudo usermod -G sudo <current user>

   2. Allow of sudo without password for current user:

       sudo visudo
       add line to the end: <current user> ALL=(ALL:ALL) NOPASSWD:ALL

4. Install utilities depedencies:

   sudo apt install podman

5. Make base image:

   make -C testing/base_image
