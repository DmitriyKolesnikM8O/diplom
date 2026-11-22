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
