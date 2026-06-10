## Доработка компонента медиатор

### 1. Ограничения

1. **IMA-политика покрывает только определенный набор пользователей и файлов** - хэши `security.ima` / `security.evm` вычисляются только для файлов с `uid=2000,2001`; директории и симлинки IMA/EVM не трогает. Тестирование в контейнерах также ограничивает обрабатываемые файлы специальной примонтированной директорией. Модель Event-B при этом требует хэши для любых файлов.

**Решение**: функция `calc_fake_meta_hash(uid, gid, perms)` возвращает детерминированный псевдохэш `f"fake_{uid}_{gid}_{S_IMODE(perms)}".encode()` для всех непокрытых объектов. Префикс `fake_` позволяет отличить псевдохэш от реального — это используется в `is_hash_fake(hash)`.

2. **Хэши доступны только в `__fput`, а не в `close`** (см. ограничение 2 в мониторе) - IMA/EVM записывает хэши в момент освобождения последней ссылки на файл (`__fput`), а не при системном вызове `close`. Монитор выдаёт `__fput` отдельным событием с ключом `"call"`.

**Решение**: изменен порядок разбора трассы: при обработке события `close` в `LinuxTestSpecImpl._replay_trace` медиатор ищет соответствующий `__fput` по inode и подставляет из него реальные хэши.

3. **Монитор не всегда возвращает хэш** (см. раздел 4 в мониторе) - если хэш не изменился, он может быть не обновлен при системном вызове, поэтому `contentHash`/`metaHash` в событии приходят пустыми.

**Решение**: `MediatorState` хранит `real_hashes: dict[Inode, FileHash]` — последние известные хэши по каждому inode. Если монитор не вернул хэш, проверяется словарь `real_hashes`.

4. **Модель не сохраняет IMA/EVM хэши для директорий** - хотя он требуется в событии `open_exists`.

**Решение**: выставлять хэши при помощь служебного события модели.


### 2. Изменения

#### Моделирование режимов IMA/EVM

Добавлен метод `LinuxTestSpec.enable_ima_evm()`, который позволяет в тестах включить поддержку моделирования режимов IMA/EVM.

Добавлен enum `ImaEvmMode` (`OFF`/`FIX`/`ENFORCE`) и поля `ima_mode`/`evm_mode` в `MediatorState`. В `builder.py` добавлены методы `switch_ima_mode`/`switch_evm_mode`, в `translator.py` - `set_init_ima_mode`/`set_init_evm_mode`. Таблица `IntegrityModes` в `enums.py` связывает enum с константами модели.

#### Хранение хэшей в состоянии

`MediatorState` расширен двумя словарями `Inode -> FileHash`:
- `real_hashes` - актуальный content/meta хэш файла, нужен согласно ограничению 3.
- `intergity_hashes` - IMA/EVM хэши, зафиксированные в xattr; обновляется при каждом `close`, когда IMA и EVM находятся в режиме FIX.

Для обновления словарей были изменены методы:
- `do_creat`, `do_mkdir` - добавляют записи;
- `do_chmod`, `do_chown` - обновляют meta hash;
- `do_close`, `do_exit`
- `do_remove` - удаляет записи при удалении файла.

#### Обновление хэндлеров событий

Для поддержки хэшей методы класса `TraceTranslator` и `EventsBuilder` были обновлены в соответствии с моделью.

Чтобы обойти первое ограничение, формируются псевдохэши. `calc_fake_meta_hash` возвращает строку с префиксом `fake_`, что позволяет отличить псевдохэш от реального. Вспомогательная функция `is_hash_fake(hash)` проверяет этот префикс.

В `chmod`, `fchmod`, `chown`, `fchown` применяется единая логика: если монитор не вернул хэш, берётся значение из `real_hashes`. Но если и оно является псевдохэшем (или отсутствует), пересчитывается свежий `calc_fake_meta_hash` по актуальным метаданным файла — это важно, так как uid/gid/perms могли измениться.

```python
if not metaHash:
    stored_hash = self.mediator_state.get_real_hashes(file).meta_hash
    if not stored_hash or is_hash_fake(stored_hash):
        metaHash = calc_fake_meta_hash(filestat.st_uid, filestat.st_gid, perms)
    else:
        metaHash = stored_hash
```

#### Инициализация файлов

В `SnapshotBuilder` добавлен метод `_extract_hashes(xattrs)`, читающий `security.ima` и `security.evm` из xattr. Результат накапливается в `Snapshot.hashes: dict[str, tuple[bytes, bytes]]`.

`LinuxTestSpecImpl._replay_setup` сначала переключает модель в FIX-режим, прогоняет все init-события (группы, пользователи, папки, файлы, ACL), затем переключает в ENFORCE. В FIX-режиме сохраняются хэши в медиаторе и в модели; в ENFORCE уже только проверяется их совпадение.

В `TraceTranslator.add_init_file_or_link` добавлены параметры `content_hash`/`meta_hash`. Для каждого нового inode воспроизводится полная последовательность событий модели:
```
creat -> fchown -> fchmod -> close(content_hash, close_meta)
```
Промежуточные хэши вычисляются через `calc_fake_meta_hash` на каждом шаге. `close_meta` выбирается как реальный EVM-хэш для IMA-покрытых файлов и псевдохэш для остальных - это необходимо для гарда `grd14` модели. Жёсткие ссылки обрабатываются отдельно: вместо полной последовательности выполняется только `link(oldpath, newpath)`.

Аналогично был изменен `TraceTranslator.add_init_folder`, в котором вычисляются псевдохеши директорий: 
```
mkdir -> chown -> chmod -> force_set_ima_evm_hash
```
В соответствии с ограничением 4 был добавлен последний шаг `force_set_ima_evm_hash`, который вызывает служебное событие модели `any_transition` с обновленными `content_hash`/`meta_hash`.


#### Поддержка immutable-атрибута

В `make_text_of_gatherinfo_file` добавлены команды `lsattr`/`lsattr -d`. В `read_gathered_info` парсится вывод: если 5-й символ строки флагов - `'i'`, путь записывается в `Snapshot.immutable: list[str]`.

Были добавлены методы:
- `TraceTranslator.set_init_immutable`, с помощью которого в медиаторе выставляется флаг иммутабл по записям в снапшоте;
- `EventsBuilder.mark_immutable`, `EventsBuilder.unmark_immutable`, вызывающие соответствующие события модели.
