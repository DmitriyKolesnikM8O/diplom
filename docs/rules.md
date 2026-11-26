# Правила `peaudit`

> Файл сгенерирован командой `cargo xtask rules-doc`. Не редактировать вручную.
> Источник — `RuleMeta` каждого правила в `crates/peaudit-core/src/analysis/rules/`.
> Каталог-бэклог (что ещё планируется) — `materials/rules_catalog.md`.

Всего правил: 15.

| ID | Severity | Confidence | Profiles | Правило |
|---|---|---|---|---|
| `PE-COFF-001` | high | high | spec, loader, security | Аномальное число секций |
| `PE-COFF-003` | high | high | spec, loader, security | Machine не соответствует magic |
| `PE-OPT-002` | medium | high | spec, loader | Неверный SizeOfImage |
| `PE-OPT-003` | high | high | spec, loader | Неверный SizeOfHeaders |
| `PE-OPT-004` | high | high | spec, loader | Неверный FileAlignment |
| `PE-OPT-005` | high | high | spec, loader | Неверный SectionAlignment |
| `PE-OPT-006` | high | high | spec, loader, security | Точка входа вне исполняемой секции |
| `PE-OPT-008` | low | high | spec, security | Контрольная сумма не совпадает |
| `PE-OPT-013` | critical | high | spec, loader, security | Заголовки больше файла |
| `PE-SEC-001` | critical | high | spec, loader, security | Сырые данные секции вне файла |
| `PE-SEC-002` | medium | high | spec, security | VirtualSize = 0 при наличии данных |
| `PE-SEC-005` | high | high | spec, loader, security | Пересечение секций в памяти |
| `PE-SEC-007` | high | high | security | Секция одновременно записываемая и исполняемая |
| `PE-SEC-012` | high | high | spec, loader, security | Сырые данные секции внутри заголовков |
| `PE-SEC-013` | medium | high | spec, security | Хвостовые пустые секции |

## PE-COFF-001 — Аномальное число секций

- **Severity:** high
- **Confidence:** high
- **Category:** coff
- **Since:** 0.1.0
- **References:** https://learn.microsoft.com/windows/win32/debug/pe-format, materials/rules_catalog.md

Спецификация требует хотя бы одну секцию и допускает не более 96. Ноль секций означает, что загрузчику нечего отображать, а число больше 96 не поддерживает ни загрузчик, ни таблица секций: разные парсеры читают разное количество записей, и структура файла перестаёт быть однозначной.

## PE-COFF-003 — Machine не соответствует magic

- **Severity:** high
- **Confidence:** high
- **Category:** coff
- **Since:** 0.1.0
- **References:** https://learn.microsoft.com/windows/win32/debug/pe-format, materials/rules_catalog.md

Поле Machine задаёт архитектуру, а magic необязательного заголовка — разрядность и раскладку полей. Их расхождение (например, amd64 с PE32) означает, что часть полей прочитана по чужой раскладке: загрузчик и сторонний парсер увидят разные значения одной и той же структуры.

## PE-OPT-002 — Неверный SizeOfImage

- **Severity:** medium
- **Confidence:** high
- **Category:** optional
- **Since:** 0.1.0
- **References:** https://learn.microsoft.com/windows/win32/debug/pe-format, materials/rules_catalog.md

SizeOfImage должен быть равен align_up(max(VirtualAddress + VirtualSize), SectionAlignment). Если значение меньше, часть образа не отображается; если больше — загрузчик резервирует лишнюю память. Расхождение также означает, что два парсера по-разному определят границу образа и места для overlay.

## PE-OPT-003 — Неверный SizeOfHeaders

- **Severity:** high
- **Confidence:** high
- **Category:** optional
- **Since:** 0.1.0
- **References:** https://learn.microsoft.com/windows/win32/debug/pe-format, materials/rules_catalog.md

SizeOfHeaders задаёт конец области заголовков и начало данных секций. Значение меньше фактического конца таблицы секций означает, что таблица выходит за объявленные заголовки: загрузчик ищет секции по SizeOfOptionalHeader, а инструмент, доверяющий SizeOfHeaders, увидит данные там, где на самом деле заголовки. Значение должно быть кратно FileAlignment, иначе граница заголовков не совпадает с границей отображения.

## PE-OPT-004 — Неверный FileAlignment

- **Severity:** high
- **Confidence:** high
- **Category:** optional
- **Since:** 0.1.0
- **References:** https://learn.microsoft.com/windows/win32/debug/pe-format, materials/rules_catalog.md

FileAlignment задаёт выравнивание данных секций в файле. Спецификация требует степень двойки в диапазоне [0x200, 0x10000]. Исключение — low-alignment образы, где SectionAlignment меньше 0x1000 и FileAlignment равен ему. Любое другое значение делает границы секций неоднозначными.

## PE-OPT-005 — Неверный SectionAlignment

- **Severity:** high
- **Confidence:** high
- **Category:** optional
- **Since:** 0.1.0
- **References:** https://learn.microsoft.com/windows/win32/debug/pe-format, materials/rules_catalog.md

SectionAlignment задаёт шаг отображения секций в памяти. Он должен быть степенью двойки и не меньше FileAlignment; иначе секции в памяти перекрываются или начинаются внутри страницы, и загрузчик отображает не то, что описано в таблице.

## PE-OPT-006 — Точка входа вне исполняемой секции

- **Severity:** high
- **Confidence:** high
- **Category:** optional
- **Since:** 0.1.0
- **References:** https://learn.microsoft.com/windows/win32/debug/pe-format, materials/rules_catalog.md

AddressOfEntryPoint — RVA первой выполняемой инструкции. У исполняемого образа без флага DLL нулевая точка входа означает, что запускать нечего. Ненулевая точка входа, не попадающая ни в одну секцию с правом выполнения или с кодом, означает, что загрузчик передаст управление данным, а не коду. У DLL нулевая точка входа допустима.

## PE-OPT-008 — Контрольная сумма не совпадает

- **Severity:** low
- **Confidence:** high
- **Category:** optional
- **Since:** 0.1.0
- **References:** https://learn.microsoft.com/windows/win32/debug/pe-format, materials/rules_catalog.md

Ненулевой CheckSum должен совпадать с суммой, посчитанной по файлу с замаскированным полем. Несовпадение означает, что файл изменили после вычисления суммы (или сумму скопировали из другого файла). Нулевое значение — «не задано»: многие легитимные сборки его не заполняют, поэтому оно не является находкой.

## PE-OPT-013 — Заголовки больше файла

- **Severity:** critical
- **Confidence:** high
- **Category:** optional
- **Since:** 0.1.0
- **References:** https://learn.microsoft.com/windows/win32/debug/pe-format, materials/rules_catalog.md

SizeOfHeaders больше размера файла означает, что данные секций начинаются за концом файла: загрузчик либо откажется отображать образ, либо отобразит только заголовки. Это же значение используют инструменты для поиска overlay, поэтому расхождение с реальным размером файла делает разбор неоднозначным.

## PE-SEC-001 — Сырые данные секции вне файла

- **Severity:** critical
- **Confidence:** high
- **Category:** section
- **Since:** 0.1.0
- **References:** https://learn.microsoft.com/windows/win32/debug/pe-format, materials/rules_catalog.md

PointerToRawData + SizeOfRawData выходит за конец файла. Загрузчик отобразит только присутствующие байты, а инструмент, читающий по объявленному размеру, получит ошибку или мусор. Обрезанная секция — типичный способ спрятать настоящий код в хвосте, который никто не проверяет.

## PE-SEC-002 — VirtualSize = 0 при наличии данных

- **Severity:** medium
- **Confidence:** high
- **Category:** section
- **Since:** 0.1.0
- **References:** https://learn.microsoft.com/windows/win32/debug/pe-format, materials/rules_catalog.md

VirtualSize задаёт размер секции в памяти. Если он равен нулю, а SizeOfRawData больше нуля, загрузчик использует SizeOfRawData, а парсер, доверяющий VirtualSize, решит, что секция пуста. Разные ответы на вопрос «что отображено» — основа parser differential.

## PE-SEC-005 — Пересечение секций в памяти

- **Severity:** high
- **Confidence:** high
- **Category:** section
- **Since:** 0.1.0
- **References:** https://learn.microsoft.com/windows/win32/debug/pe-format, materials/rules_catalog.md

Две секции занимают пересекающиеся диапазоны RVA. Загрузчик отобразит их поверх друг друга, и содержимое по общим адресам будет зависеть от порядка отображения. Один парсер увидит код одной секции, другой — данные другой.

## PE-SEC-007 — Секция одновременно записываемая и исполняемая

- **Severity:** high
- **Confidence:** high
- **Category:** section
- **Since:** 0.1.0
- **References:** https://learn.microsoft.com/windows/win32/debug/pe-format, materials/rules_catalog.md

Флаги MEM_WRITE и MEM_EXECUTE вместе дают страницу W+X: код может переписать сам себя, а данные — стать кодом. Легитимные образы держат код и данные раздельно; W+X чаще встречается у распаковщиков, шеллкодов и инжекторов.

## PE-SEC-012 — Сырые данные секции внутри заголовков

- **Severity:** high
- **Confidence:** high
- **Category:** section
- **Since:** 0.1.0
- **References:** https://learn.microsoft.com/windows/win32/debug/pe-format, materials/rules_catalog.md

PointerToRawData меньше SizeOfHeaders: объявленные данные секции лежат там, где находятся заголовки. Загрузчик отобразит секцию из области, которую другой инструмент считает заголовками, и содержимое по одному адресу будет разным в зависимости от того, что именно читать.

## PE-SEC-013 — Хвостовые пустые секции

- **Severity:** medium
- **Confidence:** high
- **Category:** section
- **Since:** 0.1.0
- **References:** https://learn.microsoft.com/windows/win32/debug/pe-format, materials/rules_catalog.md

В конце таблицы объявлены секции с нулевыми VirtualSize и SizeOfRawData. Они ничего не отображают, но входят в NumberOfSections: инструменты, читающие таблицу целиком, и инструменты, останавливающиеся на первой пустой секции, увидят разное число секций. Это классический приём расхождения парсеров.
