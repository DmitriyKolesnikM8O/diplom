# Каталог правил `peaudit`

Рабочий документ. Служит backlog'ом и источником для `docs/rules.md` (генерация из
`RuleMeta`). Приоритеты: **P0** — MVP, **P1** — полная версия, **P2** — по остатку времени.

**Профили:**
- `S` — `spec` (соответствие спецификации PE/COFF);
- `L` — `loader` (примет/отработает ли загрузчик Windows);
- `Sec` — `security` (структурные аномалии и сокрытие).

**Severity** — стартовая гипотеза. После фазы 11 (калибровка на System32/Corkami)
значения могут измениться; изменение фиксируется в CHANGELOG и в тексте ВКР.

**Confidence** — уверенность в находке: `high` — детерминированная проверка,
`medium` — зависит от трактовки, `low` — эвристика.

**FP** — риск ложного срабатывания на легитимном ПО: `—` нет, `low`, `med`, `high`.

---

## 0. Покрыто диагностикой парсера (ADR-0005)

Эти условия **не реализуются как правила**: их уже сообщает парсер
диагностикой, а правило-дубль запрещено
([ADR-0005](../docs/adr/0005-diagnostics-vs-findings.md)). Строки остаются в
каталоге как история решения, но в `docs/rules.md` их нет.

| ID | Условие | Диагностика парсера | Почему не правило |
|---|---|---|---|
| PE-DOS-001 | `e_lfanew` вне файла или `< 0x40` | `dos.pe-offset-out-of-range`, `dos.pe-offset-too-small` | Парсер уже отступил от декларации: PE-заголовок не прочитан |
| PE-DOS-002 | `e_lfanew % 4 != 0` | `dos.pe-offset-unaligned` | Выравнивание зафиксировано при разборе DOS-заголовка |
| PE-DOS-003 | по `e_lfanew` не `PE\0\0` | `pe.signature-missing` | Сигнатуры нет — COFF-заголовок не разбирается |
| PE-DOS-006 | нет `MZ`, но есть валидный PE | `dos.mz-missing` | Отсутствие `MZ` — решение парсера, а не оценка соответствия |
| PE-COFF-002 | `SizeOfOptionalHeader` не соответствует | `optional.size-mismatch` | Парсер читает optional по объявленному размеру и сообщает расхождение |
| PE-OPT-001 | неверный `Magic` | `optional.bad-magic` | Раскладка не определена — дальше разбирать нечего |
| PE-OPT-007 | `NumberOfRvaAndSizes > 16` | `optional.too-many-directories` | Парсер урезает каталог до 16, как загрузчик, и сообщает об этом |

---

## 1. DOS-заголовок и расположение PE

| ID | Правило | Условие (кратко) | Sev | Профили | Conf | FP | P |
|---|---|---|---|---|---|---|---|
| PE-DOS-001 | `e_lfanew` вне файла | `e_lfanew < 0x40` или `e_lfanew + 4 > file_size` | Critical | S L Sec | high | — | P0 |
| PE-DOS-002 | `e_lfanew` не выровнен | `e_lfanew % 4 != 0` (фиксируем, не падаем) | Medium | S Sec | high | low | P1 |
| PE-DOS-003 | Нет сигнатуры PE | по `e_lfanew` не `PE\0\0` | Critical | S L Sec | high | — | P0 |
| PE-DOS-004 | Аномальный DOS stub | stub > 4 КиБ, содержит `MZ`/`PE`, нет стандартного сообщения | Info | Sec | low | med | P2 |
| PE-DOS-005 | PE-заголовок вне заголовков | `e_lfanew` указывает в секцию/overlay, а не в headers | High | S L Sec | high | low | P1 |
| PE-DOS-006 | Нет `MZ`, но есть валидный PE | первые 2 байта не `MZ`, при этом по смещению валидный `PE\0\0` | High | S L Sec | high | low | P1 |

**Тесты:** builder с `e_lfanew` = 0, 0x3F, EOF−2, EOF+100, в хвосте секции.

---

## 2. COFF-заголовок

| ID | Правило | Условие (кратко) | Sev | Профили | Conf | FP | P |
|---|---|---|---|---|---|---|---|
| PE-COFF-001 | Аномальное число секций | `NumberOfSections == 0` или `> 96` | High | S L Sec | high | — | P0 |
| PE-COFF-002 | `SizeOfOptionalHeader` неверен | меньше минимума для magic или не согласован с `NumberOfRvaAndSizes` | High | S L Sec | high | — | P0 |
| PE-COFF-003 | Machine ↔ Magic | I386+PE32+, AMD64+PE32, ARM/ARM64+чужой magic и т.п. | High | S L Sec | high | low | P0 |
| PE-COFF-004 | COFF-символы в образе | `PointerToSymbolTable != 0 && NumberOfSymbols != 0` | Low | Sec | high | low | P2 |
| PE-COFF-005 | Аномальная дата сборки | `TimeDateStamp == 0` или в будущем (> +1 день) | Info | Sec | low | high* | P2 |
| PE-COFF-006 | Нет `EXECUTABLE_IMAGE` | для EXE/DLL флаг не выставлен | Medium | S L | high | low | P1 |

\* Reproducible builds массово ставят 0 — поэтому Info/low confidence.

---

## 3. Optional header и data directories

| ID | Правило | Условие (кратко) | Sev | Профили | Conf | FP | P |
|---|---|---|---|---|---|---|---|
| PE-OPT-001 | Неизвестный magic | не `0x10B` / `0x20B` / `0x107` | Critical | S L Sec | high | — | P0 |
| PE-OPT-002 | `SizeOfImage` неверен | не равен `align_up(last.VA + last.VirtualSize, SectionAlignment)` | Medium | S L | high | low | P0 |
| PE-OPT-003 | `SizeOfHeaders` неверен | меньше фактического конца заголовков или не кратен `FileAlignment` | High | S L | high | low | P0 |
| PE-OPT-004 | `FileAlignment` неверен | не степень двойки или вне `[512, 64K]` (кроме low-alignment образов, где `SectionAlignment < 0x1000` и `FileAlignment == SectionAlignment`) | High | S L | high | low | P1 |
| PE-OPT-005 | `SectionAlignment` неверен | 0, не степень двойки, меньше `FileAlignment` | High | S L | high | low | P1 |
| PE-OPT-006 | Точка входа | `AddressOfEntryPoint == 0` у EXE (кроме managed сборок с CLR-заголовком) или вне исполняемой секции | High | S L Sec | high | med* | P0 |
| PE-OPT-007 | Каталоги за пределами | `NumberOfRvaAndSizes > 16` или директории выходят за `SizeOfOptionalHeader` | High | S L | high | low | P0 |
| PE-OPT-008 | Контрольная сумма | `CheckSum != 0` и не совпадает с расчётной | Low | S Sec | high | med** | P1 |
| PE-OPT-009 | `ImageBase` не выровнен | не кратен 64 КиБ | Medium | S L | high | low | P2 |
| PE-OPT-010 | Аномальный Subsystem/версия | неизвестный Subsystem, нереалистичные версии ОС | Info | S | high | low | P2 |
| PE-OPT-011 | Ослабленный hardening | нет ASLR/DEP/CFG в `DllCharacteristics` | Info | Sec | high | high*** | P2 |
| PE-OPT-012 | Аномальный стек/куча | reserve/commit = 0 или > 1 ГиБ | Low | S Sec | medium | low | P2 |
| PE-OPT-013 | Заголовки больше файла | `SizeOfHeaders > file_size` | Critical | S L Sec | high | — | P1 |
| PE-OPT-014 | `LoaderFlags != 0` | зарезервированное поле не 0 | Info | S | high | low | P2 |
| PE-OPT-015 | Адрес директории без размера | `VirtualAddress != 0`, `Size == 0` (загрузчик игнорирует, парсер может разбирать) | Medium | S L Sec | high | low | P1 |

\* DLL без entry point — норма; EXE с EP вне кода — нет.
\** Многие легитимные файлы имеют `CheckSum == 0` — такие не флагуем.
\*** Это posture, а не аномалия: score 0, отдельная категория.

---

## 4. Секции

| ID | Правило | Условие (кратко) | Sev | Профили | Conf | FP | P |
|---|---|---|---|---|---|---|---|
| PE-SEC-001 | Сырые данные вне файла | `PointerToRawData + SizeOfRawData > file_size` | Critical | S L Sec | high | — | P0 |
| PE-SEC-002 | `VirtualSize == 0` | при `SizeOfRawData > 0` | Medium | S Sec | high | low | P1 |
| PE-SEC-003 | `SizeOfRawData` не выровнен | не кратен `FileAlignment` | Medium | S Sec | high | low | P1 |
| PE-SEC-004 | `VirtualAddress` не выровнен | не кратен `SectionAlignment` | High | S L | high | low | P1 |
| PE-SEC-005 | Пересечение виртуальных диапазонов | секции перекрываются по VA | High | S L Sec | high | — | P0 |
| PE-SEC-006 | Пересечение сырых диапазонов | секции перекрываются по файлу | High | S Sec | high | low | P1 |
| PE-SEC-007 | W+X | `MEM_WRITE && MEM_EXECUTE` | High | Sec | high | med* | P0 |
| PE-SEC-008 | Флаги не соответствуют роли | executable без CODE или CODE без executable | Low | Sec | medium | med | P2 |
| PE-SEC-009 | Аномальные имена | пустое, непечатаемое, дубликат, известное имя упаковщика | Low | Sec | medium | med | P1 |
| PE-SEC-010 | Секции не по порядку | VA убывает | Low | S Sec | high | low | P2 |
| PE-SEC-011 | Таблица секций пересекает данные | заголовки секций попадают в raw-данные | High | S L Sec | high | low | P1 |
| PE-SEC-012 | Raw внутри заголовков | `PointerToRawData < SizeOfHeaders` | High | S L Sec | high | low | P1 |
| PE-SEC-013 | Хвостовые пустые секции | в конце таблицы секции с `raw=0, vs=0`, но `NumberOfSections` их считает | Medium | S Sec | high | low | P1 |
| PE-SEC-014 | `VirtualSize >> SizeOfRawData` | > 16× и > 1 МиБ | Medium | Sec | medium | low | P1 |
| PE-SEC-015 | Большая zero-filled секция | raw > 64 КиБ и > 99% нулей | Info | Sec | high | high | P2 |
| PE-SEC-016 | VA = 0 при размере > 0 | секция «наезжает» на заголовки | Medium | S Sec | high | low | P2 |
| PE-SEC-017 | «Скрытые» заголовки секций | валидные 40-байтные записи сверх `NumberOfSections` (загрузчик игнорирует, сканирующий парсер прочитает) | Medium | S L Sec | medium | low | P2 |
| PE-SEC-018 | Виртуальная исполняемая секция | `SizeOfRawData == 0`, `VirtualSize > 0`, флаг EXECUTE, имя не `.bss` | Medium | Sec | medium | med | P2 |

**Особый случай (из `notes.md` №4):** PE-SEC-013 — ровно тот трюк, когда добавляют пустые
секции и увеличивают `NumberOfSections`: загрузчик принимает, парсеры ломаются. Обязательный
кейс для главы 1/4.

---

## 5. Rich Header

| ID | Правило | Условие (кратко) | Sev | Профили | Conf | FP | P |
|---|---|---|---|---|---|---|---|
| PE-RICH-001 | Невалидный ключ/checksum | ключ не сходится с DanS-блоком | Medium | Sec | high | low | P1 |
| PE-RICH-002 | Зануление/ключ = 0 | DanS-блок нулевой или ключ 0 | Medium | Sec | high | low | P1 |
| PE-RICH-003 | Rich отсутствует у MSVC | эвристика по импортам/PDB, а Rich нет | Info | Sec | low | high | P2 |
| PE-RICH-004 | Несогласованные build ID | дубликаты/аномальные `comp.id` | Low | Sec | medium | med | P2 |
| PE-RICH-005 | Rich перекрывает PE | выход за stub / пересечение с PE-заголовком | High | S L Sec | high | — | P1 |
| PE-RICH-006 | Абсурдное число записей | > 10 000 | Low | Sec | high | — | P2 |
| PE-RICH-007 | Разрыв между Rich и PE | мусорные байты между концом Rich-блока и `PE\0\0` | Low | Sec | medium | low | P2 |

**Тесты:** собрать Rich через builder; испортить ключ; занулить блок; сравнить checksum
с `pefile` на 100 системных DLL (фаза 7).

---

## 6. Overlay

| ID | Правило | Условие (кратко) | Sev | Профили | Conf | FP | P |
|---|---|---|---|---|---|---|---|
| PE-OVL-001 | Overlay присутствует | данные после последней секции (без certificate table) | Info | Sec | high | high* | P1 |
| PE-OVL-002 | Высокая энтропия overlay | > 7.0 при размере > 1 КиБ | Medium | Sec | medium | med | P1 |
| PE-OVL-003 | Исполняемый/архивный заголовок | overlay начинается с `MZ`, `PE`, `ELF`, `PK`, `7z`, `Rar!` | High | Sec | high | low | P1 |
| PE-OVL-004 | Конфликт с сертификатом | overlay пересекает certificate table или сертификат вне файла | Medium | S Sec | high | low | P1 |
| PE-OVL-005 | Огромный overlay | > 50% файла и > 1 МиБ | Medium | Sec | high | med | P1 |
| PE-OVL-006 | Вложенный PE в overlay | `MZ`/`PE` по ненулевому смещению в первых 1 МиБ overlay | High | Sec | high | low | P2 |

\* Наличие overlay — метрика (score 0); интересна только в комбинации.

---

## 7. Импорты и экспорты

| ID | Правило | Условие (кратко) | Sev | Профили | Conf | FP | P |
|---|---|---|---|---|---|---|---|
| PE-IMP-001 | Import directory вне образа | RVA/размер не маппится или выходит за файл | High | S L Sec | high | — | P1 |
| PE-IMP-002 | Цикл/переполнение дескрипторов | нет terminator или > лимита | High | S L Sec | high | — | P1 |
| PE-IMP-003 | Thunk/имя вне границ | RVA thunk или строки не маппится | High | S L Sec | high | — | P1 |
| PE-IMP-004 | Нет импортов/только ординалы | EXE без импортов; все импорты по ординалам | Low | Sec | medium | med | P2 |
| PE-IMP-005 | Подозрительный набор API | комбинация аллокации/записи/удалённого потока и т.п. | Info | Sec | low | high** | P2 |
| PE-EXP-001 | Export directory вне образа | RVA/размер невалиден | High | S L Sec | high | — | P1 |
| PE-EXP-002 | Forwarded export вне образа | цель форварда не маппится | Medium | S Sec | high | low | P2 |
| PE-EXP-003 | Несогласованные массивы экспорта | counts/ordinals выходят за лимиты | Medium | S Sec | high | low | P2 |

\** Capability hint, не вердикт: score 0, только как контекст. Не превращать в «детектор
вредоносного ПО» — иначе размывается позиционирование.

---

## 8. Ресурсы, TLS, debug, сертификаты

| ID | Правило | Условие (кратко) | Sev | Профили | Conf | FP | P |
|---|---|---|---|---|---|---|---|
| PE-RES-001 | Цикл/границы/глубина ресурсов | повтор узла, depth > лимита, запись вне файла | High | S L Sec | high | — | P1 |
| PE-RES-002 | Высокая энтропия ресурса | > 7.2 при размере > 4 КиБ | Low | Sec | medium | high* | P2 |
| PE-RES-003 | Абсурдное число записей | count > лимита | Medium | S Sec | high | — | P2 |
| PE-TLS-001 | TLS callbacks присутствуют | directory непустая | Info | Sec | high | high** | P1 |
| PE-TLS-002 | TLS вне образа | директория/callback не маппится | High | S L Sec | high | — | P1 |
| PE-TLS-003 | Callback в неисполняемой памяти | целевая секция без EXECUTE | Medium | Sec | medium | med | P2 |
| PE-TLS-004 | Массив callbacks без терминатора | нет завершающего нуля или массив выходит за секцию | High | S L Sec | high | low | P1 |
| PE-DBG-001 | Debug directory вне образа | RVA/размер невалиден | Medium | S Sec | high | low | P2 |
| PE-DBG-002 | Аномальный PDB-путь | абсолютный пользовательский путь, огромная длина, несоответствие | Info | Sec | low | high | P2 |
| PE-CERT-001 | Certificate table невалиден | вне файла, размер не кратен 8, `WIN_CERTIFICATE` битый | High | S L Sec | high | low | P1 |
| PE-CERT-002 | Данные после подписи | overlay за пределами certificate table | Medium | Sec | medium | med | P1 |
| PE-CERT-003 | Директория без подписи | size > 0, но структура пустая/нулевая | Medium | S Sec | high | low | P2 |
| PE-CERT-004 | Certificate table пересекается с секцией | диапазон cert table пересекается с raw-диапазоном секции или overlay | Medium | S Sec | high | low | P2 |

\* Сжатые ресурсы — норма; поэтому Low и confidence medium.
\** TLS callbacks массово используются легитимно (антидебаг/инициализация), score 0.

---

## 9. Энтропия

| ID | Правило | Условие (кратко) | Sev | Профили | Conf | FP | P |
|---|---|---|---|---|---|---|---|
| PE-ENT-001 | Высокая энтропия файла | > 7.2 | Low | Sec | medium | med | P1 |
| PE-ENT-002 | Высокая энтропия секции | > 7.2 при размере > 4 КиБ | Medium | Sec | medium | med | P1 |
| PE-ENT-003 | Всплеск в скользящем окне | окно > 7.8 | Medium | Sec | medium | med | P2 |
| PE-ENT-004 | Упакованный код | высокая энтропия `.text` при низкой `.data`/`.rdata` | Medium | Sec | low | med | P2 |
| PE-ENT-005 | Аномально низкая энтропия кода | `.text` почти весь нулевой | Info | Sec | medium | med | P2 |

Порог 7.2 — стартовый; калибруется на Corkami/System32. Для `.rsrc` и известных сжатых
данных — confidence ниже, не «выключаем правило».

---

## 10. Loader / parser differential

| ID | Правило | Условие (кратко) | Sev | Профили | Conf | FP | P |
|---|---|---|---|---|---|---|---|
| PE-LDR-001 | RVA маппится по-разному | RVA в хвосте, где `VirtualSize < SizeOfRawData`; стратегии дают разные offset | Medium | L Sec | high | low | P1 |
| PE-LDR-002 | Загружаем, но нарушает spec | сводка: `loader` чист, `spec` — нет | Medium | L Sec | high | med | P1 |
| PE-LDR-003 | Заголовки длиннее `SizeOfHeaders` | фактический конец заголовков выходит за `SizeOfHeaders` (с учётом округления до страницы); часть заголовков может не отобразиться | High | L Sec | medium | low | P1 |
| PE-LDR-004 | Таблица секций за `SizeOfHeaders` | секции физически вне отображаемых заголовков | High | L Sec | medium | low | P1 |
| PE-LDR-005 | Entry point маппится по-разному | EP даёт разные offset в стратегиях | High | L Sec | high | low | P1 |
| PE-LDR-006 | Import directory маппится по-разному | разные offset для import RVA | High | L Sec | high | low | P2 |

Это «лицо» работы: правила фиксируют не «файл плохой», а **расхождение интерпретаций**.

---

## 11. Сводка по приоритетам

| Приоритет | Кол-во | Что входит |
|---|---|---|
| P0 | 13 | Минимальный парсер + базовые проверки заголовков/секций |
| P1 | ~43 | Rich, overlay, директории, TLS/cert, энтропия, loader |
| P2 | ~34 | Тонкие эвристики, posture, вложенные PE, PDB |

Итого ~90 правил в backlog; для полной версии достаточно 40+ правил из P0/P1.
Остальное — задел и «future work».

---

## 12. Сознательно не делаем

- сигнатуры упаковщиков (это Detect It Easy, не наша ниша);
- проверку PKCS#7/цепочки сертификатов;
- анализ поведения API (это sandbox/эмуляция);
- YARA-правила;
- ML-скоринг;
- «вердикт malware/benign» — только структурный риск и объяснение.

---

## 13. Чек-лист добавления правила

- [ ] ID из этого каталога, приоритет и профили согласованы;
- [ ] `RuleMeta` заполнен, есть `references`;
- [ ] positive-тест (сломанная фикстура) и negative-тест (чистая);
- [ ] evidence содержит offset и значение;
- [ ] проверено на System32 (нет массовых FP);
- [ ] `docs/rules.md` перегенерирован;
- [ ] `cargo xtask ci` зелёный.
