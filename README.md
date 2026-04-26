## Заметки
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