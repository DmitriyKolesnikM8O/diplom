# Архитектура `peaudit`

> Черновик. Полное описание появится по мере прохождения фаз 2–5
> (см. [`materials/roadmap.md`](../materials/roadmap.md)).

## Слои

```
peaudit-core   парсинг PE, модель, правила, скоринг, отчёт
peaudit-cli    аргументы, ввод-вывод, коды возврата
peaudit-ffi    C ABI (cdylib/staticlib)
xtask          служебные команды (ci, corpus, experiment, schema)
```

Зависимости направлены только внутрь: `cli`/`ffi` → `core`; `core` не знает
про файловую систему, CLI и FFI.

## Принципы

- zero-copy разбор по `&[u8]`;
- проверка границ на каждом чтении, никаких паник на входных данных;
- partial parsing: ошибка фиксируется как диагностика, анализ продолжается
  ([ADR-0003](adr/0003-partial-parsing.md));
- детерминированный отчёт;
- лимиты на число секций, директорий, импортов, узлов ресурсов и глубину рекурсии;
- три независимых профиля вердикта — `spec`, `loader`, `security`
  ([ADR-0004](adr/0004-three-profiles.md));
- `#![forbid(unsafe_code)]` в ядре.

## Поток данных

```
байты → Reader → PeFile → Derived (RVA, overlay, checksum, энтропия)
      → AnalysisContext → правила → Finding[] → скоринг → Report → JSON
```

Подробности и обоснование решений — в roadmap и ADR (`docs/adr/`).
