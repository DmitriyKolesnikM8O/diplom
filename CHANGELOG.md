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

### Fixed

- `peaudit-core`: файл, обрезанный внутри каталога директорий, больше не может получить состояние `complete` — `directories.truncated` стал уровнем `error`, как и усечение любой другой структуры.
- `peaudit-core`: убран мёртвый путь в разборе подписи `PE\0\0` вместе с недостижимой веткой чтения.

### Changed

- **ADR-0005**: диагностика фиксирует решение парсера, находка — несоответствие спецификации; правило не дублирует диагностику. Следствие — убрана диагностика `coff.no-sections` (её заменит правило `PE-COFF-001`).
- `peaudit-core`: из `Limits` удалён `max_directories` — каталог директорий ограничен спецификацией (16 записей, 128 байт) и в safety-лимите не нуждается.
- Тесты ядра: 145 unit-тестов; добавлены мутационный property-тест, тест достижимости каждого кода реестра и 7 тестов на ранее непокрытые ветки.
