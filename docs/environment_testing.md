# Окружение

Тестирование проводилось на ОС Debian 12, поскольку в ней используется требуемая версия ядра Linux, 6.1.

Тесты проводились при режимах IMA и EVM `enforce`, поскольку именно они представляют наибольший интерес.

Использовалась политика IMA/EVM, состоящая в том, что верификации (`appraise`) должны подвергаться пользователи, чей `uid` равен 2000 или 2001, дабы не затрагивать всю систему.

## Активация IMA/EVM

Настройка IMA/EVM в окружении проводилась при запуске системы из `initramfs` при помощи `dracut`. Последовательность действий для настройки приведена ниже.

1) Все действия будут от имени суперпользователя, поэтому ввести:
```bash
su -
```

2) Установить требуемые пакеты:
```bash
apt update
apt install keyutils ima-evm-utils dracut
dracut -f
apt autoremove
```

3) Сгенерировать encrypted ключ для EVM, подписанный user-ключом; эти действия важно выполнить за одну сессию терминала, в том числе поэтому выше был именно `su -`, так как `sudo` не подойдёт:
```bash
mkdir -p /etc/keys
keyctl add user kmk-user "$(dd if=/dev/urandom bs=1 count=32 2> /dev/null)" @u   # генерация случайного ключа
keyctl pipe "$(keyctl search @u user kmk-user)" > /etc/keys/kmk-user.blob        # вывод ключа в файл
keyctl add encrypted evm-key "new user:kmk-user 32" @u                           # генерация ключа на основе kmk-user
keyctl pipe "$(keyctl search @u encrypted evm-key)" > /etc/keys/evm-user.blob    # вывод ключа в файл
```

4) Настроить `dracut`
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

5) Перегенерировать `initramfs`:
```bash
dracut -f
```

6) К сожалению, в ядре Linux версии 6.1 (и вообще до 6.5 включительно) существует баг \[[1](https://kernsec.org/pipermail/linux-security-module-archive/2022-October/034806.html), [2](https://kernsec.org/pipermail/linux-security-module-archive/2022-October/034833.html)\], из-за которого подсистемы IMA/EVM и BPF вместе могут приводить к kernel panic при загрузке ядра, однако существует практически работающее решение:
```bash
vim /etc/default/grub
```
найти строчку `GRUB_CMDLINE_LINUX_DEFAULT="quiet"` (в кавычках может оказаться что-то другое)  
поменять на: `GRUB_CMDLINE_LINUX_DEFAULT="quiet console=tty0 lsm=lockdown,yama,integrity,selinux,bpf,apparmor"`  
сохранить и ввести:
```bash
update-grub
```

После этого при запуске системы всегда будет активна IMA/EVM с вышеуказанной политикой.

# Изменения в тестовой системе

Тестирование проводится при помощи контейнеров. Современные версии используемого для контейнеризации `podman` по умолчанию используют для контейнеров файловую систему `overlayfs`. Однако известно, что IMA (по крайней мере, в ядре Linux 6.1) работает с ней некорректно \[[3](https://marc.info/?m=169459053927023&w=2)\]. Известны два пути решения этой проблемы:
- использовать `vfs`: для этого нужно менять настройки `podman` на всю систему, пересобирать образ, это будет медленнее и занимать больше места,
- мониторовать директорию с хостовой системы: в ней IMA/EVM работает корректно.

Выбран второй вариант. Для этого внесены изменения в `testing/spec_impl.py`, в частности, добавлен параметр для указания имени этой монтируемой директории в контейнере. Все тесты на IMA/EVM проводятся над файлами в этой директории. Кроме того, потребовалось вносить изменения, чтобы после окончания теста удалять временную монтируемую директорию хоста, корректно обрабатывая файлы, принадлежащие не существующим в хостовой системе пользователям (из-за пространств имён) и потенциально являющиеся неизменяемыми.

Кроме того, внесены изменения в функции:
- `LinuxTestSpecImpl.make_user()`, чтобы создавать пользователей с заданным `uid`,
- `LinuxTestSpecImpl.make_file()` и `LinuxTestSpecImpl.mkdir()`, чтобы создавать файлы и директории сразу от имени пользователя, чьи файлы подвергаются хешированию со стороны IMA/EVM.
