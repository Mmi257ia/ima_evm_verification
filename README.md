# Заметки

## Подключение IMA/EVM
Менять политику IMA и включать EVM можно и в райнтайме (единожды за запуск системы, правда), но в таклм случае включение EVM загадочным образом фризит систему, поэтому пока что будем включать их при запуске системы. Инструкция:

1) абсолютно все действия будут из-под рута, поэтому ввести
```bash
su -
```

2) установить всякое
```bash
apt update
apt install keyutils ima-evm-utils dracut
dracut -f
apt autoremove
```

3) сгенерировать encrypted ключ для EVM, подписанный user-ключом; эти действия важно выполнить за одну сессию терминала, в том числе поэтому выше был `su -`, `sudo` не подойдёт
```bash
mkdir -p /etc/keys
keyctl add user kmk-user "$(dd if=/dev/urandom bs=1 count=32 2> /dev/null)" @u   # генерация рандомного ключа
keyctl pipe "$(keyctl search @u user kmk-user)" > /etc/keys/kmk-user.blob        # вывод ключа в файл
keyctl add encrypted evm-key "new user:kmk-user 32" @u                           # генерация ключа на основе kmk-user
keyctl pipe `keyctl search @u encrypted evm-key` > /etc/keys/evm-user.blob       # вывод ключа в файл
```

4) настроить dracut (настройка инициализации системы, грубо говоря)
```bash
vim /etc/dracut.conf.d/imaevm.conf  # имя файла может быть любым, лишь бы кончалось на .conf
```
вписываем содержимое файла:
```bash
add_dracutmodules+=" masterkey integrity "
```
сохраняем  
дальше
```bash
mkdir -p /etc/sysconfig
vim /etc/sysconfig/masterkey
```
содержимое файла:
```bash
MULTIKERNELMODE="NO"
MASTERKEYTYPE="user"
MASTERKEY="/etc/keys/kmk-${MASTERKEYTYPE}.blob"
```
сохраняем  
дальше
```bash
vim /etc/sysconfig/evm
```
содержимое файла:
```bash
EVMKEY="/etc/keys/evm-user.blob"
```
сохраняем  
дальше
```bash
vim /etc/sysconfig/ima_policy
```
содержимое файла:
```
appraise fowner=2000
```
сохраняем; это политика работы IMA/EVM, состоящая в том, что проверяются только файлы, чей владелец имеет `uid=2000`

5) перегенерируем `initrd`
```bash
dracut -f
```

6) к сожалению, в ядре 6.1 (и вообще до 6.5 включительно) существует баг, из-за которого подсистемы IMA/EVM и BPF не очень совместимы, но дипсик накидал костыльное решение, которое вроде как работает (но может когда-нибудь ломаться и приводить к kernel panic при загрузке системы -- это норма)
```bash
vim /etc/default/grub
```
находим строчку `GRUB_CMDLINE_LINUX_DEFAULT="quiet"` (в кавычках может оказаться что-то другое)  
меняем на: `GRUB_CMDLINE_LINUX_DEFAULT="quiet console=tty0 console=ttyS0 lsm=lockdown,yama,integrity,selinux,bpf,apparmor"`  
сохраняем  
вводим:
```bash
update-grub
```
(помимо всего прочего, после этого вывод системы подключен не только к экрану, но и к последовательному порту (serial). в виртуалке можно присоединить к нему терминал и пользоваться. наверное, можно даже отключить экран, если вы на маке и у вас эмуляция тормозит)

После этого при запуске системы всегда будет активна IMA/EVM с вышеуказанной политикой.

Для тестирования может понадобиться пользователь с `uid=2000`. Создать его можно следующей командой:
```bash
useradd -u 2000 --shell /usr/bin/bash -m <имя_нового_пользователя>
passwd <имя_нового_пользователя> # задать ему пароль
```
Перейти в терминал от его имени можно будет командой
```bash
su - <имя_нового_пользователя>
```

## Создание тестов на IMA
~~В начале любого теста на IMA должен быть вызван метод `LinuxTestSpec.setup_ima_policy(uid)`. Он применяет IMA policy (политику работы IMA), при которой подсистема работает только на файлы, владелец которых имеет указанный `uid`. Следует, соответственно, создавать пользователя с таким `uid` (возможность задавать `uid` создаваемым пользователям добавлена в `LinuxTestSpec.make_user()`).~~

Политика IMA может быть задана *единожды* за время работы ядра (то есть системы целиком) и распространяется как на хостовую систему, так и на все контейнеры. Для её изменения нужно перезапускать всю систему и задавать её заново.

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
