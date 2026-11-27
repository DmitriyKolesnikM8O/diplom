# Changelog

Формат — [Keep a Changelog](https://keepachangelog.com/), версионирование — SemVer.

## [Unreleased]

### Added

- Каркас workspace: `peaudit-core`, `peaudit-cli`, `peaudit-ffi`, `xtask`.
- Линты (`unsafe_code`, `unwrap_used`, `expect_used`, `panic`) и `cargo xtask ci`.
- CI на GitHub Actions: Ubuntu + Windows, fmt/clippy/test/doc/release build.
- Лицензии MIT/Apache-2.0, `CONTRIBUTING.md`, `SECURITY.md`, `docs/`.
- `peaudit-core`: безопасный `Reader` — zero-copy, проверка границ, `peek`/`slice`/`sub_reader`, курсор не двигается при ошибке.
- `peaudit-core`: ошибки и диагностики как данные (`ParseError`, `Diagnostic`) с ожидаемым и фактическим значением; реестр стабильных кодов.
- `peaudit-core`: safety-лимиты, отделённые от порогов спецификации (`spec.rs`).
- `peaudit-core`: SHA-256/SHA-1/MD5 и энтропия со скользящим окном; базовый бенчмарк 10 МиБ — 159 мс, 62.9 МиБ/с.
- Политика хэшей: по умолчанию только SHA-256, SHA-1/MD5 — по флагу `--hashes all` (в 5.5 раза быстрее на 10 МиБ).
- CI: job'ы MSRV 1.85, 32-битная цель `i686-unknown-linux-gnu`, `cargo-deny`; Dependabot для `cargo` и `github-actions`.
- `peaudit-core`: разбор заголовков PE с partial parsing — `pe::dos`, `pe::coff`, `pe::optional` (PE32/PE32+), `pe::section`, `PeFile::parse` и `StructureOffsets`. Ошибка в одной структуре не скрывает остальные.
- `peaudit-core`: `ParseState` (`failed`/`partial`/`complete`) описывает глубину разбора, а не валидность файла; находки — дело правил.
- `peaudit-core`: имена секций хранятся как `[u8; 8]` без потерь и аллокаций (`name_bytes`/`name_str`).
- `peaudit-core`: 17 стабильных кодов диагностики для разбора заголовков (`dos.*`, `pe.*`, `coff.*`, `optional.*`, `directories.*`, `sections.*`); реестр не содержит заготовок.
- `peaudit-core`: `testutil::PeBuilder` — минимальный валидный PE32/PE32+ с доступом к смещениям и патчами полей; используется и тестами, и `xtask`.
- Тесты: golden-снапшоты модели PE32/PE32+ (`tests/parse_headers.rs`) и корпусный прогон по системным файлам (`tests/system_corpus.rs`, под `--ignored`).
- Корпусная проверка: 4000 файлов из `C:\Windows\System32` — все `complete`, ни одной диагностики; замер — `docs/experiments/2026-11-23-pe-corpus-baseline.md`.
- `peaudit-core`: `pe::rva` — перевод RVA в файловое смещение по трём моделям (`Spec`, `Loader`, `MaxVirtualRaw`) с явным `ZeroFill` и `Unmapped`; `resolve_rva` возвращает все три ответа сразу, `offset_to_rva` делает обратный перевод.
- `peaudit-core`: `derived::Derived` — производные величины: `HeadersSize` (объявленный `SizeOfHeaders` против фактического конца таблицы секций, округления по `FileAlignment`) и `ImageSize` (объявленный `SizeOfImage` против `align_up(max(VA + VirtualSize), SectionAlignment)`). Величина, которую нельзя вычислить, — `None`, а не диагностика.
- `peaudit-core`: `Derived::section_entropy` — энтропия каждой секции считается один раз при разборе: диапазон обрезан по файлу, мерится по присутствующим байтам, `truncated` отмечает секцию, чьи raw-данные не влезли в файл. `Derived` из-за `Vec` больше не `Copy` (остался `Clone`).
- `peaudit-core`: `pe::overlay` — данные после образа разбиты на `leading`/`certificate`/`trailing`: подпись — не overlay, данные после подписи — overlay; каталог сертификатов обрезается по концу файла, overlay никогда не начинается внутри заголовков.
- `peaudit-core`: `pe::checksum` — PE checksum с маскированием поля (а не пропуском слов) и прибавлением длины файла; `0` трактуется как «не задано». Векторы закреплены `MapFileAndCheckSumW` (PE32 `0x9205`, PE32+ `0x36EF`, `notepad.exe` `0x618DE`).
- `examples/dump_headers`: печатает и производные величины — размер заголовков, образ, разбиение overlay и checksum.
- Корпусная проверка производных величин на 1000 файлах `System32`: 0 расхождений по `SizeOfHeaders` и `SizeOfImage`, 149 встроенных подписей и ни одного overlay, 0 секций с усечёнными raw-данными, 999 заданных checksum без расхождений; замер — `docs/experiments/2026-11-24-derived-values-corpus.md`.
- `peaudit-core::analysis`: движок правил — `Finding`/`Evidence`, `trait Rule: Sync`, `RuleMeta`, `AnalysisContext`, `Findings` с защитой от точных дублей и детерминированной сортировкой, статический реестр (`LazyLock`) с проверками уникальности ID и стабильности порядка.
- `peaudit-core::analysis`: три профиля (`spec`, `loader`, `security`) и скоринг: веса `0/1/4/10/20`, множитель confidence `0.5/0.75/1.0`, кап семьи 25, итог ≤ 100, уровни `clean`…`critical`.
- `peaudit-core::analysis::rules`: первые 15 правил — `PE-COFF-001`, `PE-COFF-003`, `PE-OPT-002`, `PE-OPT-003`, `PE-OPT-004`, `PE-OPT-005`, `PE-OPT-006`, `PE-OPT-008`, `PE-OPT-013`, `PE-SEC-001`, `PE-SEC-002`, `PE-SEC-005`, `PE-SEC-007`, `PE-SEC-012`, `PE-SEC-013`. Условия, уже покрытые диагностиками парсера, правилами не дублируются (ADR-0005).
- `peaudit-core::report`: `Report` и JSON-контракт `schema_version = "1.0"` — разбор, три вердикта, находки, метрики (headers/image/overlay/checksum/entropy) и применённые лимиты; `verdicts = null` при `ParseState::Failed` (ADR-0006).
- `docs/report-schema.md` и `docs/report.schema.json`: человекочитаемый и машинный контракт отчёта; тест валидирует реальные отчёты и отдельно проверяет, что валидатор отвергает сломанный документ.
- `cargo xtask rules-doc`: генерация `docs/rules.md` из `RuleMeta`; тест `rules_doc` падает, если файл разошёлся с кодом.
- Корпусная проверка правил на 1000 файлах `System32`: 0 находок на всех 15 правилах; счётчики и примеры срабатываний выводятся в `tests/system_corpus.rs`.
- `peaudit-cli`: команды `scan` (файл или stdin), `batch` (каталог, рекурсия, `std::thread`, до 32 потоков), `rules list|explain`, `schema` (схема вкомпилирована в бинарник), `version`.
- `peaudit-cli`: форматы вывода — человекочитаемая сводка, `--json` (с `--pretty`), `--jsonl`; `--output FILE`; `--min-severity` фильтрует только человекочитаемый вывод, JSON всегда содержит все находки.
- `peaudit-cli`: коды возврата как контракт — `0` гейт не сработал, `1` находка на уровне `--fail-on` (или отказ `--strict`), `2` ошибка аргументов/ввода-вывода, `3` внутренняя ошибка; в `batch` код `2` приоритетнее `1`.
- `peaudit-cli`: гейт по severity отдельной находки выбранного профиля (`--profile`, `--fail-on`), а не по score; `--fail-on never` отключает гейт.
- `peaudit-cli`: размер входа проверяется до чтения, stdin читается через `Read::take(max + 1)`; `--limit KEY=VALUE` переопределяет safety-лимиты.
- `peaudit-core`: `HashSelection::NONE` для `--no-hashes`.
- `docs/cli.md`: справочник по командам, флагам, лимитам, профилям и кодам возврата.
- Тесты CLI: 23 unit-теста и 29 интеграционных (`assert_cmd`, `predicates`, `tempfile`) — коды возврата, stdin, JSON/JSONL, `--output`, лимиты, `batch`.

### Fixed

- `peaudit-core`: файл, обрезанный внутри каталога директорий, больше не может получить состояние `complete` — `directories.truncated` стал уровнем `error`, как и усечение любой другой структуры.
- `peaudit-core`: убран мёртвый путь в разборе подписи `PE\0\0` вместе с недостижимой веткой чтения.
- `peaudit-core`: `PE-OPT-006` больше не срабатывает на managed-сборках: при непустом каталоге `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR` точку входа задаёт CLI-заголовок, и `AddressOfEntryPoint = 0` законен (`powershell_ise.exe` — реальный пример). Условие уточнено в `materials/rules_catalog.md`.

### Changed

- **ADR-0005**: диагностика фиксирует решение парсера, находка — несоответствие спецификации; правило не дублирует диагностику. Следствие — убрана диагностика `coff.no-sections` (её заменит правило `PE-COFF-001`).
- `peaudit-core`: из `Limits` удалён `max_directories` — каталог директорий ограничен спецификацией (16 записей, 128 байт) и в safety-лимите не нуждается.
- Тесты ядра: 145 unit-тестов; добавлены мутационный property-тест, тест достижимости каждого кода реестра и 7 тестов на ранее непокрытые ветки.
- **ADR-0006**: `verdicts` в отчёте — `Option`, `null` при `ParseState::Failed`; детерминизм JSON — часть контракта (нет времени, длительностей и неупорядоченных коллекций); `schema_version` — часть документа.
- `peaudit-core` получил зависимость `serde` (сериализация отчёта) и dev-зависимость `serde_json` (тесты схемы); `xtask` зависит от `peaudit-core` для генерации `docs/rules.md`.
- `materials/rules_catalog.md`: добавлен раздел 0 «Покрыто диагностикой парсера (ADR-0005)» — `PE-DOS-001/002/003/006`, `PE-COFF-002`, `PE-OPT-001`, `PE-OPT-007`.
- Тесты ядра: 254 unit-теста (+2 `ignored`), 11 тестов схемы отчёта, 1 тест актуальности `docs/rules.md`.
- Тесты ядра: 256 unit-тестов (+2 `ignored`); `peaudit-cli` — 23 unit-теста и 29 интеграционных.
- `peaudit-cli` получил dev-зависимости `assert_cmd`, `predicates`, `tempfile` (MIT/Apache-2.0, только тесты; ядро не затронуто).
- `--strict` реализован как гейт по диагностикам уровня `error`, а не как отказ от partial parsing: парсер всегда разбирает столько, сколько может, а флаг только меняет код возврата. ADR-0003 уточнён под это поведение.
