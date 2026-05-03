# Заметки

## Создание тестов на IMA
В начале любого теста на IMA должен быть вызван метод `LinuxTestSpec.setup_ima_policy(uid)`. Он применяет IMA policy (политику работы IMA), при которой подсистема работает только на файлы, владелец которых имеет указанный `uid`. Следует, соответственно, создавать пользователя с таким `uid` (возможность задавать `uid` создаваемым пользователям добавлена в `LinuxTestSpec.make_user()`).

Политика IMA может быть задана *единожды* за время работы ядра (то есть системы целиком) и распространяется как на хостовую систему, так и на все контейнеры. Для её изменения нужно перезапускать всю систему и задавать её заново.

Режим работы IMA/EVM может быть задан только при загрузке ядра, так что для его изменения тоже нужно перезапускать всю систему: при открытии меню `grub` нажать `e` и приписать в конец строчки, начинающейся с `linux`: `ima_appraise=fix` (или не `fix`, а `off`/`enforce`; режим по умолчанию -- `enforce`), затем нажать `Ctrl+X`.


## Инициализация IMAMode и EVMMode
Anis генерирует некорректный код для этого участка инициализации:
```
@act46: IMAMode ≔ OFF
@act47: EVMMode ≔ OFF
```
В `model/machine.py` генерируется такой код:
```python
# @act46: IMAMode ≔ OFF
self.IMAMode = Machine.IntegrityModesItem()
# @act47: EVMMode ≔ OFF
self.EVMMode = Machine.IntegrityModesItem()
```
...но `IntegrityModesItem` наследуется от `CarrierSetItem`, а в его `__init__` требуются два аргумента, так что такой код крашится сам по себе.

Решение: пока что руками менять это на инициализацию `None`-ом:
```python
# @act46: IMAMode ≔ OFF
self.IMAMode: Machine.IntegrityModesItem = None
# @act47: EVMMode ≔ OFF
self.EVMMode: Machine.IntegrityModesItem = None
```