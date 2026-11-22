# Contributing

## Перед началом

```powershell
cargo xtask ci
```

Команда запускает те же проверки, что и CI: `fmt --check`, `clippy -D warnings`,
`test --workspace`, `doc`.

Отдельно в CI (локально не обязательно) проверяются: MSRV 1.85, 32-битная цель
`i686-unknown-linux-gnu` и `cargo-deny check` (лицензии, уязвимости, источники).
Если поставил `cargo-deny` локально — прогоняй `cargo deny check` после изменения
`Cargo.toml` или `deny.toml`.

## Правила

- Ядро (`peaudit-core`) не делает I/O, не ходит в сеть и не содержит `unsafe`.
- Никаких `unwrap`/`expect`/`panic!` в библиотечной логике: только `Result` и диагностики.
- Новое правило — с positive- и negative-тестом, см. `materials/rules_catalog.md`.
- Один коммит — одна логическая единица. Сообщения в стиле Conventional Commits:
  `feat(core): add PE-SEC-007 W+X rule`.
- Не коммитить корпуса, артефакты экспериментов и реальные вредоносные образцы.

## Структура

- `crates/peaudit-core` — парсер, модель, правила, отчёт.
- `crates/peaudit-cli` — CLI.
- `crates/peaudit-ffi` — C ABI.
- `xtask` — служебные команды.
- `materials/roadmap.md` — план работ.
