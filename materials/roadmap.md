# Roadmap реализации ВКР

**Тема:** «Разработка открытого инструмента статического анализа PE-файлов для выявления
намеренных искажений структуры и заголовков».

**Рабочее имя проекта:** `peaudit` (решение фиксируется в ADR-0001, переименование возможно
только на фазе 0).

**Стек:** Rust stable (edition 2024), CLI + разделяемая библиотека с C ABI, JSON-отчёт.

**Статус документа:** v1 (план). Чекбоксы обновляются по мере выполнения. Это единственный
источник истины по порядку работ; `AGENTS.md` ссылается сюда.

---

## 0. Как пользоваться этим документом

1. Идти строго по фазам. Не начинать следующую, пока не выполнены **DoD** и `cargo xtask ci`.
2. Внутри фазы шаги тоже упорядочены: сначала тест/контракт, потом реализация.
3. После каждой фазы — коммит (Conventional Commits) и отметка чекбоксов здесь.
4. Если по ходу выясняется, что решение неверно — не «подкручивать» молча, а зафиксировать
   ADR в `docs/adr/` и обновить этот документ.
5. Всё, что не нужно для глав ВКР, уходит в `docs/backlog.md`, а не в текущую фазу.

**Легенда приоритетов правил:** `P0` — обязательно для MVP, `P1` — для полной версии,
`P2` — по остатку времени.

### Прогресс

| Фаза | Статус |
|---|---|
| 0. Bootstrap | готово (CI зелёный: ubuntu + windows) |
| 1. Таксономия | готово (кроме согласования с руководителем) |
| 2. Фундамент ядра | готово (итерации A+B: лимиты, evidence, Reader, коды, хэши, CI) |
| 3. Заголовки PE | готово (DOS/COFF/optional/секции, `PeFile::parse`, корпус 4000 файлов без диагностик) |
| 4. Производная модель | — |
| 5. Правила и отчёт | — |
| 6. CLI | — |
| 7. Rich/энтропия/overlay | — |
| 8. Директории | — |
| 9. FFI | — |
| 10. Ужесточение | — |
| 11. Корпуса и эксперименты | — |
| 12. Производительность | — |
| 13. Документация и релиз | — |

---

## 1. Резюме проекта

### 1.1. Что делаем

Компактный автономный инструмент первичного (экспресс) статического анализа PE-файлов:

- **устойчивый парсер** собственной разработки: zero-copy, с проверкой границ, без паник
  и зависаний на враждебном входе;
- **partial parsing**: разбираем максимально глубоко, ошибки фиксируем как диагностику;
- **движок правил**: каждая находка объяснима (ID, поле, смещение, ожидание/факт, ссылка);
- **три независимых вердикта**:
  - `spec` — соответствие спецификации Microsoft PE/COFF;
  - `loader` — примет ли файл загрузчик Windows и не сломается ли он;
  - `security` — структурные аномалии и признаки сокрытия данных (скоринг для триажа);
- **CLI** с JSON/JSONL и кодами возврата для CI/CD;
- **разделяемая библиотека** (DLL на Windows, `.so` на Linux) с C ABI;
- **воспроизводимые эксперименты**: системные файлы Windows, корпус Corkami,
  синтетические мутации, сравнение с `pefile`, `Manalyze`, `diec`.

### 1.2. Чего НЕ делаем (осознанно)

- дизассемблирование и эмуляция инструкций;
- распаковка/деобфускация кода;
- песочница, запуск исследуемых файлов;
- ML-классификаторы;
- сетевая репутация, облака, внешние API;
- криптографическая проверка Authenticode (PKCS#7/цепочки сертификатов);
- GUI;
- YARA-движок (только структурный анализ);
- лечение/карантин.

Эти ограничения — часть позиционирования: инструмент делает **одну вещь хорошо** и
встраивается в чужие конвейеры.

### 1.3. Научно-практическая рамка

Работа опирается на **parser differential** (LangSec): разные парсеры по-разному
интерпретируют один и тот же деформированный файл, а загрузчик ОС — по-своему.
Отсюда три модели (spec/loader/security) и отдельные правила класса `PE-LDR-*`,
фиксирующие расхождения. Это и есть содержательное ядро ВКР, а не просто «набор проверок».

---

## 2. Рамки, допущения, критерии успеха

### 2.1. Ограничения среды

- ОС разработки: Windows 11, Rust 1.99.1 stable, PowerShell.
- Свободно ~6 ГБ на `C:` → **экономить место**:
  - не вендорить корпуса в git;
  - не тащить тяжёлые инструменты без нужды;
  - `cargo clean` после крупных экспериментов;
  - фаззинг — опционально (см. риски);
  - при возможности вынести `target/` на другой диск через `CARGO_TARGET_DIR`.
- Реальные вредоносные образцы не используются и не коммитятся. Только Corkami,
  синтетика и системные файлы. Запуск исследуемых файлов запрещён.

### 2.2. Критерии успеха (проверяемые)

| Критерий | Цель |
|---|---|
| Падения на корпусе | **0** паник/аварий на System32 + Corkami + синтетике |
| Разбор системных файлов | ≥ 98% файлов — `parse.status = ok` или объяснимый `partial` |
| Покрытие Corkami | ≥ 90% файлов получают вердикт `security ≥ suspicious` |
| Ложные срабатывания на System32 | ≤ 2% файлов со `security score ≥ 30`; каждый FP разобран |
| Полнота правил | ≥ 35 правил P0/P1 с тестами |
| Производительность | файл 10 МБ: ≤ 20 мс; throughput ≥ 200 МБ/с (один поток) |
| Память | пиковое потребление ≤ 3× размера файла |
| Воспроизводимость | эксперимент повторяется одной командой `cargo xtask experiment ...` |
| Документация | README + architecture + rules + schema + ADR + отчёт эксперимента |

Цифры — стартовые гипотезы; после фазы 11 они калибруются и фиксируются в тексте ВКР
с обоснованием.

---

## 3. Ключевые архитектурные решения (ADR-кандидаты)

| № | Решение | Почему |
|---|---|---|
| ADR-0001 | Имя `peaudit`, workspace из 4 крейтов | Чёткое разделение «логика / интерфейсы / сервисные команды»; ядро тестируется без I/O |
| ADR-0002 | Zero-copy парсер по `&[u8]`, `Reader` с проверкой границ | Безопасность и скорость; никаких копий файла |
| ADR-0003 | Partial parsing + диагностики вместо «упал на первой ошибке» | Главное отличие от `pefile`/LIEF; требование темы |
| ADR-0004 | Три модели (`spec`/`loader`/`security`) в одном отчёте | Формализует parser differential, даёт научную рамку |
| ADR-0005 | Rule engine: trait + статический реестр, без плагинов/динамической загрузки | Детерминизм, безопасность, простота |
| ADR-0006 | Версионируемая JSON-схема отчёта | Интеграция в CI/CD и стабильность контракта |
| ADR-0007 | C ABI (`cdylib`/`staticlib`) как единственный внешний бинарный интерфейс | Требование «DLL/.so»; без сложных биндингов |
| ADR-0008 | `#![forbid(unsafe_code)]` в ядре; `unsafe` только в FFI-слое | Безопасность памяти как заявленное преимущество |
| ADR-0009 | Минимальные зависимости; никакой сети и I/O в ядре | Автономность, аудируемость, малый вес |
| ADR-0010 | Скоринг объяснимый (веса по severity × confidence), без ML | Защищаемость и воспроизводимость |
| ADR-0011 | Код, ID и JSON-ключи — английские; human-сообщения — русские | Открытый код + русскоязычная ВКР; i18n — в backlog |

ADR оформляются по мере принятия: `docs/adr/0001-....md` (контекст → решение → последствия).

---

## 4. Архитектура

### 4.1. Принципы

1. **Безопасность входа.** Любой файл — враждебный. Проверка границ на каждом чтении,
   `checked_add`/`checked_mul`, лимиты на циклы и рекурсию.
2. **Partial parsing.** Модель содержит то, что удалось разобрать, плюс список диагностик
   с абсолютными смещениями.
3. **Zero-copy.** Строки/срезы — `&'a [u8]`; копирование только для итогового отчёта.
4. **Детерминизм.** Никаких `HashMap` в порядке вывода, никакого времени в бизнес-логике.
5. **Разделение слоёв.** Ядро не знает, откуда взялись байты. CLI/FFI — тонкие адаптеры.
6. **Объяснимость.** Каждая находка ссылается на правило, поле и смещение.

### 4.2. Граф крейтов

```
                 ┌──────────────────┐
                 │   peaudit-core   │  парсинг, модель, правила, отчёт
                 │  (rlib, no I/O)  │  #![forbid(unsafe_code)]
                 └────────┬─────────┘
                          │
          ┌───────────────┼────────────────┐
          │               │                │
 ┌────────▼───────┐ ┌─────▼────────┐ ┌─────▼─────────┐
 │  peaudit-cli   │ │ peaudit-ffi  │ │     xtask     │
 │  (bin)         │ │ (cdylib+     │ │ (bin, dev)    │
 │  I/O, вывод    │ │  staticlib)  │ │ ci, corpus,   │
 │  коды возврата │ │ C ABI        │ │ experiment    │
 └────────────────┘ └──────────────┘ └───────────────┘
```

Правило: `core` не зависит ни от кого; `cli`/`ffi` зависят только от `core`;
`xtask` может зависеть от `core` и внешних крейтов, но не наоборот.

### 4.3. Поток данных

```
файл/байты
   │
   ▼
[Reader] ── ошибки ──> Diagnostic { offset, code, context }
   │
   ▼
[PeFile<'a>]  DOS → PE sig → COFF → Optional → DataDirs → Sections → Rich
   │
   ▼
[Derived]  RVA-карты, SizeOfImage/Headers, overlay, checksum, энтропия, хэши
   │
   ▼
[AnalysisContext]  = PeFile + Derived + Limits + Options
   │
   ▼
[Rule registry] ──> Vec<Finding> (детерминированный порядок)
   │
   ▼
[Scoring] ──> verdicts { spec, loader, security }
   │
   ▼
[Report] ──serde──> JSON / JSONL / human
```

### 4.4. Структура репозитория (целевая)

```
.
├── Cargo.toml                 # workspace, lints, profile
├── Cargo.lock                 # коммитится
├── rust-toolchain.toml
├── rustfmt.toml
├── deny.toml
├── .cargo/config.toml         # alias xtask
├── .gitignore
├── AGENTS.md                  # локальный, в .gitignore
├── README.md
├── LICENSE-MIT
├── LICENSE-APACHE
├── CONTRIBUTING.md
├── SECURITY.md
├── CHANGELOG.md
├── crates/
│   ├── peaudit-core/
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── error.rs            # ParseError, Diagnostic, ErrorKind
│   │   │   ├── bytes.rs            # Reader
│   │   │   ├── limits.rs
│   │   │   ├── hash.rs
│   │   │   ├── entropy.rs
│   │   │   ├── pe/
│   │   │   │   ├── mod.rs          # PeFile, parse
│   │   │   │   ├── dos.rs
│   │   │   │   ├── coff.rs
│   │   │   │   ├── optional.rs
│   │   │   │   ├── section.rs
│   │   │   │   ├── rich.rs
│   │   │   │   ├── rva.rs          # стратегии маппинга
│   │   │   │   ├── overlay.rs
│   │   │   │   ├── checksum.rs
│   │   │   │   ├── imports.rs
│   │   │   │   ├── exports.rs
│   │   │   │   ├── resources.rs
│   │   │   │   ├── tls.rs
│   │   │   │   ├── debug.rs
│   │   │   │   └── cert.rs
│   │   │   ├── analysis/
│   │   │   │   ├── mod.rs          # analyze(), AnalysisContext
│   │   │   │   ├── finding.rs
│   │   │   │   ├── rule.rs
│   │   │   │   ├── registry.rs
│   │   │   │   ├── scoring.rs
│   │   │   │   ├── profile.rs
│   │   │   │   └── rules/
│   │   │   │       ├── dos.rs
│   │   │   │       ├── coff.rs
│   │   │   │       ├── optional.rs
│   │   │   │       ├── sections.rs
│   │   │   │       ├── rich.rs
│   │   │   │       ├── overlay.rs
│   │   │   │       ├── entropy.rs
│   │   │   │       ├── imports.rs
│   │   │   │       ├── exports.rs
│   │   │   │       ├── resources.rs
│   │   │   │       ├── tls.rs
│   │   │   │       ├── debug.rs
│   │   │   │       ├── cert.rs
│   │   │   │       └── loader.rs
│   │   │   ├── report/
│   │   │   │   ├── mod.rs
│   │   │   │   └── json.rs
│   │   │   └── testutil/           # feature = "testutil"
│   │   │       ├── mod.rs
│   │   │       └── builder.rs      # PeBuilder
│   │   └── tests/
│   │       ├── parse_headers.rs
│   │       ├── parse_directories.rs
│   │       ├── rules_*.rs
│   │       ├── no_panic.rs
│   │       └── snapshots/
│   ├── peaudit-cli/
│   │   ├── src/
│   │   │   ├── main.rs
│   │   │   ├── args.rs
│   │   │   ├── input.rs            # файл/stdin
│   │   │   ├── output/
│   │   │   │   ├── human.rs
│   │   │   │   └── json.rs
│   │   │   └── exit.rs
│   │   └── tests/cli.rs
│   └── peaudit-ffi/
│       ├── src/lib.rs
│       ├── include/peaudit.h        # генерируется cbindgen
│       └── tests/ffi.rs
├── xtask/src/main.rs
├── fuzz/                            # опционально, фаза 10
├── docs/                            # документация инструмента (публикуемая)
│   ├── architecture.md
│   ├── rules.md                     # reference реализованных правил, генерируется
│   ├── report-schema.md
│   ├── report.schema.json
│   ├── ffi.md
│   ├── backlog.md
│   ├── adr/
│   └── experiments/
│       └── YYYY-MM-DD-<dataset>/
│           ├── README.md            # окружение, команды, выводы
│           ├── summary.csv
│           ├── raw.jsonl
│           └── tables.md
├── testdata/                        # только если builder не справляется
└── materials/                       # рабочие материалы ВКР (не документация продукта)
    ├── roadmap.md                   # этот план
    ├── rules_catalog.md             # backlog правил: приоритеты, риск FP
    ├── analysis.md                  # анализ ниши, цель и задачи
    ├── evasion-taxonomy.md          # таксономия техник (фаза 1)
    ├── source_list.md
    └── notes.md
```

**Граница между `docs/` и `materials/`:**

| | `docs/` | `materials/` |
|---|---|---|
| Для кого | пользователи и контрибьюторы | автор, руководитель, комиссия |
| Что | как устроен и как использовать инструмент | план, исследование, заметки, backlog |
| Стиль | выверенный, версионируемый | рабочий, может быть черновым |
| Можно публиковать отдельно | да | не обязательно |

Правило: **описывает готовый инструмент → `docs/`; план, исследование или
черновик → `materials/`**. Два похожих файла про правила разведены осознанно:
`materials/rules_catalog.md` — что *планируется* сделать (приоритеты, риск FP),
`docs/rules.md` — что *уже реализовано* (генерируется из `RuleMeta`).

### 4.5. Ключевые типы (эскизы контрактов)

**Reader — единственный способ читать байты:**

```rust
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self;
    pub fn at(data: &'a [u8], offset: usize) -> Result<Self, ParseError>;

    pub fn u8(&mut self) -> Result<u8, ParseError>;
    pub fn u16(&mut self) -> Result<u16, ParseError>;
    pub fn u32(&mut self) -> Result<u32, ParseError>;
    pub fn u64(&mut self) -> Result<u64, ParseError>;
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError>;
    pub fn skip(&mut self, n: usize) -> Result<(), ParseError>;
    pub fn seek(&mut self, offset: usize) -> Result<(), ParseError>;
    pub fn cstr(&mut self, max_len: usize) -> Result<&'a [u8], ParseError>;
}
```

**Ошибка без аллокаций и с контекстом:**

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub offset: u64,
    pub context: &'static str,
    pub kind: ErrorKind, // OutOfBounds, Overflow, BadMagic, LimitExceeded, ...
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub code: DiagCode,
    pub severity: DiagSeverity,
    pub offset: u64,
    pub context: &'static str,
}
```

**Модель PE (упрощённо):**

```rust
pub struct PeFile<'a> {
    pub bytes: &'a [u8],
    pub dos: DosHeader,
    pub coff: CoffHeader,
    pub optional: OptionalHeader,     // enum Pe32 | Pe32Plus | Rom
    pub directories: Vec<DataDirectory>,
    pub sections: Vec<SectionHeader>,
    pub rich: Option<RichHeader>,
    pub diagnostics: Vec<Diagnostic>,
    pub offsets: StructureOffsets,    // где что лежит — для evidence
}
```

**Правило:**

```rust
pub trait Rule: Send + Sync {
    fn meta(&self) -> &'static RuleMeta;
    fn evaluate(&self, ctx: &AnalysisContext<'_>, out: &mut Findings);
}

pub struct RuleMeta {
    pub id: &'static str,          // "PE-SEC-007"
    pub title: &'static str,
    pub description: &'static str,
    pub severity: Severity,        // Info | Low | Medium | High | Critical
    pub category: Category,
    pub profiles: &'static [Profile], // Spec | Loader | Security
    pub references: &'static [&'static str],
    pub since: &'static str,       // версия инструмента
}
```

**Публичный API ядра:**

```rust
pub fn analyze(bytes: &[u8], options: &AnalysisOptions) -> Report;
pub fn analyze_strict(bytes: &[u8], options: &AnalysisOptions) -> Result<Report, AnalysisError>;
```

`analyze` не возвращает `Err` никогда: даже полностью невалидный файл даёт отчёт
с `parse.status = failed` и диагностикой. `analyze_strict` — для тестов парсера.

### 4.6. Модель ошибок и лимиты

- **Ошибка парсинга** — локальная: `Result<T, ParseError>`; наверх превращается в
  `Diagnostic`, разбор продолжается там, где это возможно.
- **Лимиты** (`Limits`) — отдельный тип с дефолтами; превышение = диагностика
  `LimitExceeded` + остановка только соответствующей подструктуры.
- **Паника** — дефект, а не стратегия. В ядре запрещена линтами; в FFI дополнительно
  `catch_unwind`.

**Лимиты — это потолки безопасности, а не пороги спецификации.** Превышение
порога спецификации (например, 97 секций) — находка правила; превышение
safety-лимита — диагностика `LimitExceeded` и пропуск только этой подструктуры.
Смешивать их нельзя: иначе анализатор перестанет видеть улики в самом интересном
файле, а легитимная DLL с большим числом экспортов получит ложное «limit exceeded».

Пороги спецификации — константы в `spec.rs`: `MAX_SECTIONS = 96`,
`MAX_DATA_DIRECTORIES = 16`, `RESOURCE_TREE_DEPTH = 3`.

Каталог директорий отдельного лимита не требует: спецификация фиксирует их
число (16), и парсер больше не читает, поэтому массив ограничен 128 байтами
независимо от `NumberOfRvaAndSizes`.

Safety-лимиты (стартовые):

```rust
pub struct Limits {
    pub max_file_size: u64,        // 512 MiB
    pub max_sections: usize,       // 4096 (safety; спецификация — 96)
    pub max_imports: usize,        // 65536
    pub max_exports: usize,        // 65536
    pub max_resource_nodes: usize, // 65536
    pub max_resource_depth: u8,    // 32 (safety; спецификация — 3)
    pub max_string_len: usize,     // 4096
    pub max_thunks_per_import: usize, // 65536
    pub max_entropy_window: usize, // 4096
}
```

Значения калибруются на системном корпусе (фаза 11): лимит должен быть высоко
настолько, чтобы не срабатывать на легитимных файлах, и низко настолько, чтобы
ограничивать работу на враждебном входе.

### 4.7. Профили строгости — ответ на вопрос из `materials/notes.md` №1

**Да, градация нужна, и это не «out of scope», а центральная идея работы.**
Но реализуется не как произвольные «уровни строгости», а как **три явные семантические
модели**, потому что именно их расхождение и эксплуатируется.

| Профиль | Что означает | Пример отношения |
|---|---|---|
| `spec` | Соответствие спецификации Microsoft PE/COFF | `SizeOfRawData` не кратен `FileAlignment` → нарушение |
| `loader` | Примет ли файл загрузчик Windows и отработает ли без сбоя | Хвостовые пустые секции загрузчик принимает → не находка |
| `security` | Структурные аномалии и признаки сокрытия | Хвостовые пустые секции — типичный трюк обхода парсеров → находка |

Правила помечаются профилями, в которых они учитываются. Отчёт **всегда содержит все три
вердикта**, независимо от выбранного `--profile` (профиль влияет только на то, какой
вердикт используется для `--fail-on` и что показывать в human-выводе по умолчанию).

Дополнительно:

- **Режим парсера:** `lenient` (по умолчанию) / `strict` (`--strict`). Это ортогонально
  профилям: strict нужен для проверки самого парсера и для тестов.
- **Severity** — свойство находки, **confidence** — уверенность (low/medium/high).
  Скоринг учитывает оба.

Правила класса `PE-LDR-*` фиксируют **расхождение моделей**: например, RVA попадает в
хвост секции, где `VirtualSize < SizeOfRawData`; разные стратегии маппинга дают разные
файловые смещения. Это самый ценный класс находок для темы.

### 4.8. Зависимости

Ядро (минимум):

- `serde`, `serde_json` — отчёт;
- `sha2`, `sha1`, `md-5` — хэши (для триажа). По умолчанию считается только
  SHA-256: каждый хэш — полный проход по файлу, а SHA-1/MD5 нужны лишь для сверки
  с внешними базами (`--hashes all`). Замер: 8.6 мс против 47.2 мс на 10 МиБ,
  см. `docs/experiments/2026-11-22-hash-baseline.md`;
- `thiserror` — не нужен: ошибки в ядре реализуют `Display`/`Error` вручную,
  чтобы остаться `Copy` и без зависимостей.

CLI: `clap` (derive), `walkdir`, `anyhow` (только верхний уровень).

Dev: `proptest`, `insta`, `assert_cmd`, `predicates`, `tempfile`, `criterion`.

FFI: `cbindgen` (в `xtask`, не в рантайме).

Правила: не тянуть `regex`, `rayon`, `tokio`, `goblin`/`pelite` в основной код.
Дифференциальные парсеры — только dev-dependencies или внешние инструменты в эксперименте.

---

## 5. Формат отчёта (v1, черновик)

### 5.1. Пример JSON

```json
{
  "schema_version": "1.0",
  "tool": { "name": "peaudit", "version": "0.1.0" },
  "file": {
    "path": "sample.exe",
    "size": 13312,
    "sha256": "…",
    "md5": "…"
  },
  "parse": {
    "status": "partial",
    "format": "pe32+",
    "machine": "amd64",
    "diagnostics": [
      { "code": "SEC_TABLE_TRUNCATED", "severity": "warning", "offset": 392, "context": "section table" }
    ]
  },
  "verdicts": {
    "spec":     { "score": 24, "level": "low" },
    "loader":   { "score": 0,  "level": "clean" },
    "security": { "score": 41, "level": "suspicious" }
  },
  "findings": [
    {
      "id": "PE-SEC-007",
      "title": "Секция одновременно записываемая и исполняемая (W+X)",
      "severity": "high",
      "confidence": "high",
      "category": "sections",
      "message": "Секция .text имеет права RWX",
      "evidence": [
        { "kind": "field", "path": "sections[2].characteristics", "offset": 456, "value": "0xE0000020" }
      ],
      "references": ["https://learn.microsoft.com/windows/win32/debug/pe-format"],
      "profiles": ["security"]
    }
  ],
  "metrics": {
    "entropy": {
      "file": 6.12,
      "sections": [
        { "name": ".text", "offset": 1024, "size": 8192, "entropy": 7.41, "max_window": 7.83 }
      ]
    },
    "overlay": { "offset": 12288, "size": 1024, "entropy": 7.62 },
    "rich": { "present": true, "key_valid": false, "entries": 12 }
  },
  "limits": { "max_file_size": 536870912 },
  "timings_ms": { "parse": 0.8, "rules": 0.6, "total": 1.4 }
}
```

### 5.2. Правила совместимости

- `schema_version` — SemVer-подобно: `major.minor`. Ломающее изменение → major.
- Новые необязательные поля — minor.
- Порядок `findings` детерминирован: severity desc, затем `id`.
- `path`, `timings_ms` могут отсутствовать/быть `null` в библиотечном режиме.
- JSON Schema лежит в `docs/report.schema.json`; тест проверяет, что пример и реальный
  отчёт ей соответствуют.

### 5.3. Коды возврата CLI

| Код | Значение |
|---|---|
| 0 | нет находок на уровне `--fail-on` и выше |
| 1 | есть находки на уровне `--fail-on` и выше |
| 2 | ошибка использования/ввода-вывода |
| 3 | внутренняя ошибка (баг) |

`--fail-on` по умолчанию `high`; `--fail-on never` отключает гейт. Порог применяется
к находкам **выбранного профиля** (по умолчанию `security`); в JSON при этом всё равно
присутствуют все находки и все три вердикта.
Невалидный PE — это **не** ошибка CLI: печатается отчёт, код зависит от находок.

---

## 6. Движок правил, каталог, скоринг

### 6.1. Анатомия находки

- `id` — стабильный, никогда не переиспользуется;
- `severity` — Info/Low/Medium/High/Critical;
- `confidence` — Low/Medium/High (эвристики ниже уверенностью);
- `evidence` — поле/смещение/значение, чтобы можно было проверить руками;
- `references` — спецификация/статья/ Corkami;
- `profiles` — где учитывается.

### 6.2. Каталог

Полный список с условиями, приоритетами и риском FP — в `materials/rules_catalog.md`.
Это **backlog**: что планируется реализовать и в каком порядке.
Справочник по уже реализованным правилам — `docs/rules.md`, он генерируется
из `RuleMeta` (`cargo xtask rules-doc`) и является документацией для пользователя.
Стартовый набор для MVP (фаза 5): 12–15 правил по заголовкам и секциям.

### 6.3. Скоринг (стартовая модель, калибруется на фазе 11)

```
weight:      info=0, low=1, medium=4, high=10, critical=20
confidence:  low=0.5, medium=0.75, high=1.0
score = min(100, Σ weight(severity) × confidence)
```

Уровни: `0 clean`, `1–9 notice`, `10–29 low`, `30–59 suspicious`, `60–84 high`,
`85–100 critical`.

Правила против двойного счёта: если несколько находок описывают одно и то же событие
(например, «секция вне файла» и «сырые данные обрезаны»), они группируются в `family`,
и вклад семьи ограничивается (например, 25 баллов). Реализация — в `scoring.rs`,
с тестами на предсказуемость.

`--fail-on` работает по **severity отдельной находки**, а не по score: это объяснимо
и стабильно для CI.

---

## 7. Стратегия тестирования

### 7.1. Пирамида

| Уровень | Что проверяет | Инструмент |
|---|---|---|
| Unit | Reader, каждый заголовок, RVA, checksum, entropy, каждое правило | `#[test]` |
| Property | произвольные байты/мутации не паникуют; инварианты маппинга | `proptest` |
| Snapshot | JSON-отчёт на эталонных фикстурах | `insta` |
| Integration | CLI: аргументы, stdin, JSON, коды возврата | `assert_cmd` |
| Corpus | System32, Corkami, синтетика | `xtask experiment` |
| Differential | расхождения с другими парсерами | внешние инструменты / dev-deps |
| Fuzz | длительный поиск паник | `cargo-fuzz` (опционально) |
| Bench | скорость и память | `criterion` |

### 7.2. Фикстуры через builder, а не бинарные блобы

В `peaudit-core` есть `testutil::PeBuilder` (feature `testutil`):

```rust
let bytes = PeBuilder::pe32()
    .section(".text", SectionSpec::code(0x1000, 0x200))
    .entry(0x1000)
    .build();
```

Тест может точечно портить поле: `patch_u32(&mut bytes, off, val)`. Это делает тесты
читаемыми и проверяемыми. Бинарные файлы в `testdata/` — только если builder объективно
не справляется (например, реальный подписанный PE).

### 7.3. Обязательные тесты на каждом этапе

- Каждый публичный метод `Reader` — границы, переполнение, нулевая длина.
- Каждый заголовок — валидный кейс, обрезанный кейс, абсурдные значения.
- Каждое правило — срабатывание + отсутствие на чистом файле.
- `no_panic`: произвольные байты (10k случаев в CI, больше локально); все префиксы
  маленького валидного PE; мутации валидного PE.
- Snapshot: хотя бы один полный отчёт.
- CLI: `--help`, `scan` файла, `scan -` (stdin), `--json`, `--fail-on`, отсутствующий файл.
- FFI: вызов из Rust + C smoke-тест (Linux CI).

### 7.4. Корпусные тесты

- Не входят в обычный `cargo test` (нет корпуса в CI).
- Feature `corpus-tests` или `#[ignore]` + отдельная команда.
- Corkami: пиннится commit, скачивается `cargo xtask corpus fetch` в `/corpus` (gitignored).
- System32: читается на месте, путь через env `PEAUDIT_SYSTEM_CORPUS`.
- Манифест ожиданий: `corpus/corkami.toml` (генерируется/поддерживается вручную),
  поля: файл, ожидаемые категории/правила, комментарий.

### 7.5. Политика «0 паник»

- В ядре: `#![forbid(unsafe_code)]`, линты `unwrap_used`, `expect_used`, `panic`.
- В тестах/CLI верхнего уровня допустимы, но не в библиотечной логике.
- CI: property-тесты + (опционально) короткий fuzz-прогон.
- Любая найденная паника — issue, фикс, регрессионный тест.

---

## 8. CI/CD и инженерные практики

### 8.1. Локально

- `cargo xtask ci` — единая команда: `fmt --check`, `clippy -D warnings`, `test`,
  `doc`, проверка JSON Schema, проверка, что пример отчёта валиден.
- `cargo xtask experiment ...` — воспроизводимый прогон на корпусе.
- `cargo xtask corpus fetch` — скачивание Corkami (пиннинг commit).
- `cargo xtask schema` — генерация `docs/report.schema.json`.
- `cargo xtask rules-doc` — генерация `docs/rules.md` из метаданных (единый источник).

### 8.2. GitHub Actions

- Matrix: `ubuntu-latest`, `windows-latest`.
- Шаги: checkout → toolchain (1.99.1, синхронизирован с `rust-toolchain.toml`; rustfmt + clippy) → cache → fmt → clippy →
  test → doc → build release.
- Отдельные job'ы:
  - `msrv` — `cargo check` на 1.85.0, чтобы заявленный `rust-version` проверялся;
  - `check-32bit` — `cargo check --target i686-unknown-linux-gnu`, чтобы код не
    полагался на 64-битный `usize`;
  - `deny` — `cargo-deny check` (лицензии, уязвимости RUSTSEC, источники, дубликаты);
    отдельный `cargo-audit` не нужен, advisories уже входят в `cargo-deny`.
- Dependabot: еженедельные PR на `cargo` и `github-actions` (`.github/dependabot.yml`).
- Опционально: coverage (`cargo-llvm-cov`) на Linux, без блокировки merge.
- Release workflow: по тегу `v*` собирает `peaudit.exe` (Windows) и `peaudit` (Linux),
  прикладывает `peaudit.h`, `report.schema.json`, checksums.

### 8.3. Git-гигиена

- Conventional Commits, маленькие коммиты.
- `main` зелёный; работа в ветках `feat/...`.
- `CHANGELOG.md` ведётся вручную/`git-cliff` (опционально).
- Теги `v0.1.0` (MVP), `v1.0.0` (защита).

---

## 9. Фазы реализации

> Ниже — «дорога». Каждая фаза заканчивается зелёным CI и коммитом.
> Оценки — в человеко-днях при 2–3 часах в день.

---

### Фаза 0. Bootstrap репозитория и инструментов

**Цель:** пустой, но полностью рабочий скелет workspace с CI и линтами.

**Шаги.**

1. Создать workspace `Cargo.toml` (`resolver = "2"`, `members`), `rust-toolchain.toml`
   (`channel = "1.99.1"` — точная версия для воспроизводимости, components `rustfmt`,
   `clippy`), `rustfmt.toml`.
   Стартовый `Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = ["crates/peaudit-core", "crates/peaudit-cli", "crates/peaudit-ffi", "xtask"]

[workspace.package]
version = "0.1.0"
edition = "2024"
rust-version = "1.85"
license = "MIT OR Apache-2.0"
repository = "https://github.com/DmitriyKolesnikM8O/diplom"

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
sha2 = "0.10"
clap = { version = "4", features = ["derive"] }

[profile.release]
lto = "thin"
codegen-units = 1
strip = "symbols"
```

2. Создать крейты: `peaudit-core` (lib), `peaudit-cli` (bin `peaudit`),
   `peaudit-ffi` (lib, `crate-type = ["cdylib", "staticlib", "rlib"]`), `xtask` (bin).
   Удобно через `cargo new --vcs none`, затем поправить `Cargo.toml` каждого крейта
   (`[lints] workspace = true`, `[dependencies] workspace = true`).
3. Настроить линты. Базовые — в workspace, самые строгие — точечно:

```toml
# Cargo.toml (workspace)
[workspace.lints.rust]
unsafe_code = "deny"
unused_must_use = "deny"

[workspace.lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
indexing_slicing = "warn"
```

   В `peaudit-core/src/lib.rs` — `#![forbid(unsafe_code)]` (сильнее workspace-настройки).
   В `peaudit-ffi` — `#![allow(unsafe_code)]` на уровне крейта с комментарием: `unsafe`
   только для C ABI. В тестовых модулях — локальные
   `#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]`.
   Каждый крейт подключает `[lints] workspace = true`.
   `arithmetic_side_effects` глобально не включаем (слишком шумно); в парсере
   дисциплина «только `checked_*`» проверяется ревью и тестами.
4. `.cargo/config.toml` с алиасом `xtask = "run --package xtask --"`.
5. `xtask`: подкоманда `ci` (fmt/clippy/test/doc), заглушки `schema`, `rules-doc`,
   `corpus`, `experiment`, `bench`.
6. `.github/workflows/ci.yml` (matrix ubuntu/windows). `cargo-deny` добавлен позже,
   в фазе 2 (итерация B), вместе с MSRV, 32-битной целью и Dependabot.
7. Лицензии MIT/Apache-2.0, `README.md` (кратко: что/зачем/как), `CONTRIBUTING.md`,
   `SECURITY.md`, `CHANGELOG.md`.
8. `.gitignore` (уже создан) и `AGENTS.md` (уже создан).
9. Первый коммит `chore: bootstrap workspace`.

**Файлы:** `Cargo.toml`, `rust-toolchain.toml`, `rustfmt.toml`, `.cargo/config.toml`,
`xtask/src/main.rs`, `.github/workflows/ci.yml`, `deny.toml`, лицензии, README.

**DoD.**

- [x] `cargo xtask ci` проходит на пустых крейтах;
- [x] CI зелёный на GitHub (ubuntu + windows);
- [x] `cargo build --workspace` и `cargo test --workspace` работают;
- [x] линты реально включены (проверено на тестовом `unwrap`).

**Проверка:** `cargo xtask ci`.

**Артефакт для ВКР:** раздел «Средства разработки и организация проекта».

---

### Фаза 1. Исследовательская база и таксономия техник

**Цель:** превратить список источников в рабочую таксономию, которая напрямую порождает
правила. Это задача №1 из README («исследование предметной области и систематизация»).

**Шаги.**

1. Прочитать/законспектировать источники из `materials/source_list.md`:
   спецификация PE, «Lost in the Loader», LangSec parser differential, MITRE T1027,
   статьи про упаковщики и энтропию, Corkami.
2. Составить `materials/evasion-taxonomy.md` — таблицу:

   | Техника | Что меняется | Поведение загрузчика | Поведение парсеров | Наблюдаемый признак | Правило |
   |---|---|---|---|---|---|

   Минимум 25 строк. Примеры: хвостовые пустые секции; `SizeOfOptionalHeader` меньше
   фактического; `VirtualSize < SizeOfRawData`; перекрывающиеся секции; RVA в заголовках;
   подделка Rich Header; overlay с PE внутри; W+X; аномальный `e_lfanew`; truncated sections;
   циклические ресурсы; TLS callbacks; сертификат, не покрывающий overlay.
3. Для каждой техники указать источник и уровень достоверности (документировано/эксперимент).
4. Свести правила в `materials/rules_catalog.md`: ID, приоритет, профили, риск FP.
5. Зафиксировать гипотезы скоринга и метрики (что считаем FP, что — TP).
6. ADR-0003/0004: partial parsing и три профиля — оформить.

**DoD.**

- [x] ≥ 25 техник, у каждой есть правило или явная пометка «вне scope»
  (сессия A: 56 техник в `materials/evasion-taxonomy.md`, 7 новых правил найдено);
- [x] каждое правило P0 имеет ссылку на источник/обоснование
  (Приложение A в `materials/evasion-taxonomy.md`);
- [ ] таксономия согласована с руководителем (хотя бы устно);
- [x] `docs/backlog.md` содержит идеи, которые сознательно отложены;
- [x] ADR-0003 (partial parsing) и ADR-0004 (три профиля) оформлены.

**Артефакт для ВКР:** глава 1 (анализ предметной области), таблица техник, обоснование
трех профилей.

---

### Фаза 2. Фундамент ядра: Reader, ошибки, лимиты, энтропия, хэши

**Цель:** безопасный строительный материал, на котором дальше всё держится.

**Шаги.**

1. `error.rs`: `ErrorKind`, `ParseError`, `Diagnostic`, `DiagCode`, `DiagSeverity`.
   Без аллокаций в `ParseError`.
2. `bytes.rs`: `Reader` со всеми чтениями через `checked_*`; `take`/`seek`/`cstr`;
   `remaining()`; `offset()`.
3. `limits.rs`: `Limits` + `Default`; хелперы `check_sections`, `check_string`, и т.д.
4. `hash.rs`: SHA-256, SHA-1, MD5 (тонкие обёртки; тест-векторы) и политика
   `HashSelection` — по умолчанию только SHA-256, все три по запросу.
5. `entropy.rs`: Shannon entropy; скользящее окно (настраиваемый размер); возврат
   `EntropyProfile { overall, max_window, max_window_offset, windows_above_threshold }`.
6. Тесты:
   - границы Reader (0, 1, len-1, len, len+1, `usize::MAX`, переполнение);
   - `cstr` без нуля/с нулём/длиннее лимита;
   - энтропия: все нули = 0, равномерные 256 байт = 8, известные векторы;
   - property: любые байты → `Reader` не паникует.

**DoD.**

- [x] 100% методов Reader покрыты тестами;
- [x] property-тест на 10k случайных входов зелёный;
- [x] `cargo doc` без warning;
- [x] бенчмарк энтропии на 10 МБ — есть базовое число;
- [x] бенчмарк хэшей на 10 МБ — есть базовое число и политика «SHA-256 по умолчанию»;
- [x] safety-лимиты отделены от порогов спецификации (`spec.rs`);
- [x] реестр кодов диагностики с проверкой формата;
- [x] CI проверяет MSRV 1.85, 32-битную цель и `cargo-deny`.

**Проверка:** `cargo test -p peaudit-core bytes entropy`.

**Артефакт для ВКР:** раздел «Безопасный парсер: контроль границ».

---

### Фаза 3. Парсинг заголовков PE и модель

**Цель:** разобрать DOS/PE/COFF/Optional/DataDirectories/Sections с partial parsing.

**Шаги.**

1. `pe/dos.rs`: `MZ`, 64 байта, `e_lfanew` (0x3C). Проверки: в файле, ≥ 0x40,
   выравнивание (фиксируем, но не падаем).
2. `pe/coff.rs`: 20 байт; `Machine`, `NumberOfSections`, `TimeDateStamp`,
   `SizeOfOptionalHeader`, `Characteristics`.
3. `pe/optional.rs`: магия `0x10B`/`0x20B`/`0x107`; стандартные поля; поля Windows-specific;
   `NumberOfRvaAndSizes`; data directories (8 байт каждая, не более 16 — как у загрузчика).
4. `pe/section.rs`: 40 байт; имя (8 байт, не обязательно NUL-terminated); все поля;
   вычисление абсолютного смещения заголовка.
5. `pe/mod.rs`: `PeFile::parse` — последовательность с накоплением диагностик:
   - нет `MZ` → `failed`, дальше нельзя;
   - `e_lfanew` вне файла → `failed` (но отчёт с диагностикой);
   - нет `PE\0\0` → `failed`;
   - COFF/optional/sections — насколько возможно, `partial`.
6. Смещения структур сохранять в `StructureOffsets` (для evidence и отчёта).
7. `testutil::PeBuilder` — минимальный валидный PE32 и PE32+; секции; патчи полей.
8. Тесты: валидные PE32/PE32+, обрезанные на каждом ключевом смещении, абсурдные
   `NumberOfSections`/`SizeOfOptionalHeader`, `e_lfanew` в оверлее, PE32 с machine AMD64.

**DoD.**

- [x] парсится 200 случайных файлов из `C:\Windows\System32` без паник;
- [x] на валидных файлах нет диагностик уровня error (кроме известных исключений);
- [x] количество секций/директорий совпадает с ручной проверкой на 10 файлах;
- [x] все тесты зелёные, snapshot модели есть.

**Результат.** Разобрано 4000 файлов из `System32`: все `complete`, ноль
диагностик любого уровня; модель сверена с независимым разбором байтов на
10 файлах. Golden-снапшоты модели PE32/PE32+ — `tests/parse_headers.rs`,
корпусный прогон — `tests/system_corpus.rs` (`--ignored`). Замер —
`docs/experiments/2026-11-23-pe-corpus-baseline.md`.

**Граница с правилами.** По ходу фазы выяснилось, что парсер и правила легко
начинают сообщать об одном и том же, поэтому граница зафиксирована отдельно:
[ADR-0005](../docs/adr/0005-diagnostics-vs-findings.md) — диагностика фиксирует
решение парсера (остановился, урезал, пропустил), а несоответствие
спецификации без такого решения — дело правила. Следствия: усечение любой
структуры стало уровнем `error` (иначе `complete` перестаёт быть правдой),
диагностика `coff.no-sections` удалена в пользу правила `PE-COFF-001`, из
реестра убраны коды-заготовки, а `Limits::max_directories` — каталог директорий
ограничен спецификацией (16 записей), и отдельный лимит не нужен.

**Проверка:** `cargo test -p peaudit-core parse_headers`.

**Артефакт для ВКР:** раздел «Модель PE и устойчивый парсер».

---

### Фаза 4. Производная модель: RVA, размеры, overlay, checksum

**Цель:** вычисляемые величины, без которых невозможны правила и «модель загрузчика».

**Шаги.**

1. `pe/rva.rs` (сделано): три стратегии маппинга:
   - `Spec`: RVA < SizeOfHeaders → файловое смещение = RVA; иначе секция, где
     `VA ≤ RVA < VA + VirtualSize` (и проверка `SizeOfRawData`);
   - `Loader`: спан `max(VirtualSize, SizeOfRawData)` — загрузчик не режет raw при
     `VirtualSize < SizeOfRawData` (T24) и добивает нулями при обратном
     соотношении; `VirtualSize == 0` трактуется как `SizeOfRawData` (T25);
   - `MaxVirtualRaw`: спан `max(VirtualSize, SizeOfRawData)`, весь спан считается
     присутствующим в файле — модель парсеров, читающих `max()` байт без проверки
     `SizeOfRawData`.
   API: `map_rva(rva, strategy) -> RvaMapping`, где
   `RvaMapping = FileOffset(u64) | ZeroFill | Unmapped`; плюс `offset_to_rva`.
   `ZeroFill` — RVA в пределах `VirtualSize`, но за `SizeOfRawData` (BSS): в файле
   данных нет, загрузчик заполнит нулями. Это принципиально для корректных правил.
   Расхождение моделей возвращается явно: `resolve_rva` отдаёт все три ответа
   (`RvaResolution`), а не выбирает одну стратегию молча.
2. `headers_size` (сделано, `derived::HeadersSize`): `SizeOfHeaders`; конец
   таблицы секций по **объявленному** числу записей (а не по числу прочитанных);
   сравнение, округление по `FileAlignment`.
3. `image_size` (сделано, `derived::ImageSize`): вычисленный
   `align_up(max(VA + VirtualSize), SectionAlignment)` — берётся максимум по
   таблице, чтобы переупорядочивание секций не меняло ответ; сравнение с
   `SizeOfImage`. Без секций или при нулевом выравнивании значение — `None`, а
   не диагностика.
4. `pe/overlay.rs` (сделано, `OverlayInfo`): overlay — не одна пара
   `(offset, size)`, а разбиение `leading` / `certificate` / `trailing`. Старт —
   максимум из конца raw-данных секций, конца объявленной таблицы секций и
   `SizeOfHeaders`: overlay не начинается внутри заголовков. Каталог
   сертификатов — единственный, чей `VirtualAddress` является файловым
   смещением, а не RVA; его размер обрезается по концу файла, а каталог,
   начинающийся раньше секций, не вычитается из overlay — он перекрывает образ,
   и это отдельная находка. Данные после подписи (T44) — overlay.
5. `pe/checksum.rs` (сделано, `ChecksumInfo`): 16-битные little-endian слова плюс
   длина файла; поле `CheckSum` **маскируется** (а не пропускается по индексу
   слова), иначе у невыровненного поля в соседних словах остались бы чужие
   байты; переносы сворачиваются, длина прибавляется после финальной свёртки;
   `stored == 0` — «не задано», а не расхождение. Векторы от системного
   `MapFileAndCheckSumW` (`imagehlp.dll`): PE32 `0x9205`, PE32+ `0x36EF`,
   `notepad.exe` `0x618DE`.
6. `entropy` по секциям (сделано, `Derived::section_entropy`): одна запись на
   секцию — обрезанный по файлу диапазон, энтропия Шеннона по присутствующим
   байтам (не по `VirtualSize`: нулевой хвост создаёт загрузчик) и признак
   `truncated`, если файл короче объявленного raw. Считается при `Derived::compute`,
   чтобы правила не сканировали файл повторно и не расходились в диапазонах.
7. Тесты (сделано, шаги 1–6): RVA в заголовках, в секции, в хвосте
   `VirtualSize < RawSize`, вне образа; overlay с сертификатом и без, данные до и
   после подписи, каталог за концом файла и внутри образа; checksum на векторах
   Windows и на реальном файле с ненулевой суммой; энтропия секции с данными,
   нулевой, усечённой и начинающейся за концом файла; корпусный assert, что на
   легитимных файлах raw-данные секций не усечены.

**DoD.**

- [x] property: для каждой секции `map_rva(VA, Spec) == FileOffset(PointerToRawData)` (в пределах raw);
- [x] расхождения стратегий возвращаются явно (не «молча выбираем одну»);
- [x] overlay не включает certificate table;
- [x] checksum совпадает на эталонном файле — векторы Windows и 1000 файлов
  `System32` с заданной суммой, 0 расхождений (`docs/experiments/2026-11-24-derived-values-corpus.md`);
- [x] тесты на все границы: 205 unit-тестов, корпусный прогон на 1000 файлах без
  расхождений.

**Артефакт для ВКР:** раздел «Моделирование загрузчика и parser differential».

---

### Фаза 5. Движок правил, отчёт, скоринг, первые правила

**Цель:** превратить модель в объяснимый отчёт.

**Шаги.**

1. `analysis/finding.rs` (сделано): `Severity`, `Confidence`, `Category`, `Evidence`,
   `Finding`; severity и confidence разделены, evidence хранит поле/смещение/ожидание/факт.
2. `analysis/rule.rs` (сделано): `trait Rule: Sync`, `RuleMeta` (Copy), `AnalysisContext`,
   `Findings` с защитой от точных дублей и детерминированной сортировкой.
3. `analysis/registry.rs` (сделано): `LazyLock`-список, порядок COFF → OPT → SEC,
   тесты на уникальность ID и стабильность порядка.
4. `analysis/profile.rs` (сделано): `Profile { Spec, Loader, Security }` и константные
   наборы профилей для `RuleMeta`.
5. `analysis/scoring.rs` (сделано): веса, confidence, `family`-кап 25, итог ≤ 100,
   уровни; unit-тесты на границы уровней, кап семьи, независимость профилей.
6. `report/` (сделано): `Report`, serde, `SCHEMA_VERSION = "1.0"`, сортировка находок
   severity desc → id → message, метрики (headers/image/overlay/checksum/entropy),
   лимиты; `verdicts = null`, если `ParseState::Failed` (ADR-0006).
7. Первые 15 правил (сделано):
   - `PE-COFF-001` число секций 0/>96;
   - `PE-COFF-003` Machine ↔ Magic;
   - `PE-OPT-002` SizeOfImage;
   - `PE-OPT-003` SizeOfHeaders;
   - `PE-OPT-004` FileAlignment;
   - `PE-OPT-005` SectionAlignment;
   - `PE-OPT-006` EntryPoint;
   - `PE-OPT-008` CheckSum (ненулевой и несовпадающий);
   - `PE-OPT-013` SizeOfHeaders больше файла;
   - `PE-SEC-001` raw вне файла;
   - `PE-SEC-002` VirtualSize = 0 при данных;
   - `PE-SEC-005` пересечение виртуальных диапазонов;
   - `PE-SEC-007` W+X;
   - `PE-SEC-012` raw внутри заголовков;
   - `PE-SEC-013` хвостовые пустые секции.

   Из первоначального списка **не реализованы как правила** `PE-DOS-001`,
   `PE-DOS-003`, `PE-COFF-002`, `PE-OPT-001`, `PE-OPT-007`: их условия уже
   сообщает парсер диагностиками (`dos.pe-offset-out-of-range`,
   `pe.signature-missing`, `optional.size-mismatch`, `optional.bad-magic`,
   `optional.too-many-directories`), а правило-дубль запрещено ADR-0005.
8. Snapshot полного отчёта на «грязной» фикстуре (сделано): `tests/report_schema.rs`
   проверяет точный порядок находок, детерминизм JSON и три вердикта.
9. `docs/report-schema.md` + `docs/report.schema.json` (сделано, вручную); тест
   валидирует реальный отчёт мини-валидатором и отдельно проверяет, что валидатор
   отвергает сломанный документ.

**DoD.**

- [x] `analyze()` на чистом PE даёт 0 находок;
- [x] на каждой сломанной фикстуре — ожидаемое правило (по два теста на правило);
- [x] JSON валиден по схеме (тест);
- [x] скоринг воспроизводим (unit-тесты формул + golden-тест отчёта);
- [x] нет `unwrap`/`expect` в новых модулях;
- [x] 0 находок на 1000 файлах `System32` (корпусный тест).

**Артефакт для ВКР:** глава 2 (архитектура, правило, скоринг), пример отчёта.

---

### Фаза 6. CLI и JSON-контракт

**Цель:** инструмент, которым можно пользоваться и который встраивается в скрипты.

**Шаги.**

1. `clap`-структура:

```
peaudit scan <FILE> [--json|--jsonl] [--pretty] [--profile spec|loader|security]
                    [--strict] [--fail-on info|low|medium|high|critical|never]
                    [--min-severity ...] [--output FILE] [--no-hashes] [--limits ...]
peaudit batch <DIR> [--recursive] [--jobs N] [--jsonl] [--fail-on ...]
peaudit rules list [--json]
peaudit rules explain <ID>
peaudit schema [--output FILE]
peaudit version
```

2. Ввод: файл или `-` (stdin); защита от гигантских файлов (лимит).
3. Вывод:
   - human: сводка (файл, вердикты, таблица находок с offset);
   - JSON: полный отчёт; JSONL: одна строка на файл (для batch).
4. Коды возврата по таблице; `--fail-on` — по severity находок выбранного профиля.
5. Ошибки I/O — понятные сообщения, код 2; внутренние — 3.
6. `batch`: рекурсия, параллелизм на `std::thread` (без rayon), агрегированная сводка.
7. Интеграционные тесты: `assert_cmd` + `predicates`; stdin; отсутствующий файл;
   невалидный PE; `--json` парсится `serde_json`.

**DoD.**

- [ ] `peaudit scan notepad.exe` работает и читаем;
- [ ] `peaudit scan file --json | jq .verdicts` — валидный JSON;
- [ ] коды возврата покрыты тестами;
- [ ] `--help` без ошибок, примеры в README;
- [ ] batch не падает на битом файле (отчёт с ошибкой, остальные обрабатываются).

**Артефакт для ВКР:** глава 3 (CLI, JSON, интеграция), демонстрация.

---

### Фаза 7. Rich Header, энтропия, overlay

**Цель:** закрыть самые «дипломные» эвристики сокрытия данных.

**Шаги.**

1. `pe/rich.rs`:
   - найти `Rich` перед `e_lfanew`; ключ — 4 байта после;
   - обратным проходом найти `DanS` (XOR с ключом);
   - проверить checksum (алгоритм сверить с `pefile`/документацией; тест-векторы
     с реальных файлов);
   - разобрать записи `(comp_id, count)`.
2. Правила `PE-RICH-001..005` (см. каталог): невалидный ключ, зануление, перекрытие,
   отсутствие у MSVC-файла, аномальные build ID.
3. `PE-ENT-001..004`: энтропия файла/секции/окна; исключения для `.rsrc` и сжатых
   ресурсов — через confidence, а не через «не проверять».
4. `PE-OVL-001..005`: наличие, энтропия, сигнатуры внутри (`MZ`, `PE`, `ELF`, `PK`, `7z`,
   `Rar!`), пересечение с сертификатом, доля от файла.
5. Тесты: собрать PE с Rich через builder; оверлей с вложенным MZ; высокоэнтропийный
   оверлей; чистый файл без срабатываний.
6. Сверить Rich с `pefile` на 100 системных DLL (скрипт, если Python доступен;
   иначе — ручная выборка и фиксация в `docs/experiments`).

**DoD.**

- [ ] Rich checksum совпадает с эталоном на выборке;
- [ ] на System32 нет массовых FP по Rich/overlay (≤ 1%);
- [ ] правила имеют positive/negative тесты;
- [ ] энтропийные метрики попадают в отчёт.

**Артефакт для ВКР:** раздел «Детекция сокрытия данных», графики энтропии.

---

### Фаза 8. Импорты, экспорты, ресурсы, TLS, debug, сертификаты

**Цель:** глубина разбора без дизассемблирования.

**Шаги.**

1. `pe/imports.rs`: дескрипторы (20 байт), `OriginalFirstThunk`/`FirstThunk`
   (если `OriginalFirstThunk == 0` — использовать `FirstThunk`), thunk-массивы 4/8 байт,
   ординалы, имена; лимиты и защита от циклов.
2. `pe/exports.rs`: директория (40 байт), массивы функций/имён/ординалов,
   forwarded exports.
3. `pe/resources.rs`: дерево (3 уровня), смещения относительны базы ресурсов;
   защита от циклов, глубины, выхода за границы; имена (UTF-16).
4. `pe/tls.rs`: директория; callbacks — **VA**, не RVA; пересчёт через `ImageBase`;
   проверка границ.
5. `pe/debug.rs`: записи (28 байт), CodeView `RSDS`, PDB-путь.
6. `pe/cert.rs`: certificate table — **файловое смещение**, `WIN_CERTIFICATE`,
   выравнивание 8; структурные проверки (без PKCS#7).
7. Правила `PE-IMP-*`, `PE-EXP-*`, `PE-RES-*`, `PE-TLS-*`, `PE-DBG-*`, `PE-CERT-*`.
8. Тесты: циклические ресурсы, глубокая рекурсия, thunk за границей, TLS callback
   вне образа, сертификат за EOF.

**DoD.**

- [ ] ни один парсер директории не может зациклиться (тест с циклом);
- [ ] все чтения ограничены лимитами;
- [ ] на System32 — без паник и массовых FP;
- [ ] находки содержат осмысленные offset/evidence.

**Артефакт для ВКР:** раздел «Анализ директорий и метаданных».

---

### Фаза 9. FFI: разделяемая библиотека и C ABI

**Цель:** выполнить требование «DLL/.so» и показать встраиваемость.

**Шаги.**

1. `peaudit-ffi`: `crate-type = ["cdylib", "staticlib", "rlib"]`.
2. C ABI:

```c
int32_t peaudit_scan(const uint8_t *data, size_t len,
                     const char *options_json, char **out_json);
void    peaudit_string_free(char *s);
const char *peaudit_version(void);
```

3. Внутри: `catch_unwind(AssertUnwindSafe(...))`; любые паники → код ошибки + JSON
   с ошибкой; никакого unwinding через границу.
   **Важно:** не включать `panic = "abort"` в release-профиле — иначе `catch_unwind`
   не сможет перехватить панику на границе FFI.
4. Владение памятью: строка выделяется Rust, освобождается `peaudit_string_free`;
   документировать в `docs/ffi.md`.
5. `#[unsafe(no_mangle)]` (Rust 2024), `unsafe extern "C"`; `unsafe` разрешён только
   в этом крейте, каждый блок — с комментарием-обоснованием.
6. `cbindgen` в `xtask` → `include/peaudit.h`.
7. Тесты: Rust-тест вызывает C ABI; C-программа на Linux CI (`cc`) сканирует файл
   и печатает JSON; проверка `peaudit_string_free`.
8. `docs/ffi.md`: пример на C, коды ошибок, потоки, владение.

**DoD.**

- [ ] `cargo build -p peaudit-ffi --release` даёт `.dll` на Windows и `.so` на Linux;
- [ ] C smoke-тест зелёный в CI;
- [ ] паника внутри не ломает процесс (тест со специальным входом/искусственной паникой);
- [ ] заголовок сгенерирован и закоммичен.

**Артефакт для ВКР:** глава 3 (библиотека, интеграция), пример на C.

---

### Фаза 10. Ужесточение: property-тесты, мутации, лимиты, фаззинг

**Цель:** доказать устойчивость, а не заявить её.

**Шаги.**

1. `proptest`-стратегии:
   - произвольные `Vec<u8>` (в т.ч. большие, но в лимитах);
   - валидный PE + случайные мутации (байт-флипы, обрезка, замена полей);
   - все префиксы маленького PE.
2. Инвариант: `analyze` всегда возвращает `Report`, никогда не паникует и укладывается
   в лимит времени (проверять косвенно: нет циклов; для теста — таймаут в CI).
3. Тесты лимитов: 100000 секций, глубина ресурсов 1000, строка 10 МБ, гигантский
   `SizeOfRawData`.
4. Аудит паник: `rg "unwrap|expect|panic!|unreachable!" crates/peaudit-core/src` —
   только в тестах/`testutil`.
5. `cargo-fuzz` (опционально, nightly): таргеты `fuzz_analyze`, `fuzz_parse`; короткий
   прогон локально, результаты — в `docs/experiments`. Если не хватает места/времени —
   заменить на 1M proptest-кейсов и зафиксировать это в тексте.
6. Snapshot-покрытие: по одному эталонному отчёту на каждую категорию правил.

**DoD.**

- [ ] 1M случайных/мутированных входов без паник (или 15 минут fuzz);
- [ ] тесты лимитов не приводят к OOM/зависанию;
- [ ] CI стабилен (property-тесты с фиксированным seed/случаями);
- [ ] отчёт о найденных и исправленных дефектах.

**Артефакт для ВКР:** раздел «Экспериментальное тестирование устойчивости».

---

### Фаза 11. Корпуса, дифференциальные эксперименты, калибровка

**Цель:** получить цифры для главы 4 и защищаемые выводы.

**Шаги.**

1. `xtask corpus fetch`:
   - Corkami (`corkami/pocs`, пиннинг commit) → `/corpus/corkami` (gitignored);
   - манифест `corpus/corkami.toml` с ожиданиями;
   - System32 — без копирования, путь через env.
2. `xtask experiment --dataset system32 --out docs/experiments/...`:
   - читает файлы, запускает `analyze`, пишет `raw.jsonl`, `summary.csv`;
   - фиксирует окружение (ОС build, CPU, версия, commit, дата).
3. Метрики:
   - parse status distribution;
   - паники (должно быть 0);
   - распределение security score;
   - FP по правилам;
   - время (median/p95), throughput, память.
4. Corkami: recall по категориям/правилам, разбор промахов.
5. Сравнение:
   - `pefile` (Python venv), `Manalyze` (бинарник), `diec` (Detect It Easy);
   - если инструмент недоступен — зафиксировать и использовать `goblin` как
     дифференциальный парсер (dev-dep) + ручную выборку;
   - таблица: успешность разбора, падения, время, найденные категории.
6. Калибровка скоринга и порогов; каждый FP — либо фикс правила, либо documented
   limitation/allowlist.
7. `docs/experiments/<date>/README.md`: команды, сырые данные, выводы, скриншоты.

**DoD.**

- [ ] эксперимент воспроизводится одной командой;
- [ ] таблицы для ВКР готовы (`tables.md`);
- [ ] FP ≤ 2% на System32 (или обоснованное исключение);
- [ ] recall на Corkami ≥ 90% (или разбор промахов);
- [ ] сравнение с 2–3 аналогами оформлено.

**Артефакт для ВКР:** глава 4 целиком, графики, таблицы.

---

### Фаза 12. Производительность

**Цель:** подтвердить «экспресс» и найти узкие места.

**Шаги.**

1. `criterion`-бенчи: `parse`, `analyze`, `entropy`, `rich`, `imports`.
2. Датасеты: 1 КБ, 100 КБ, 1 МБ, 10 МБ, 100 МБ (синтетические + реальные).
3. Замеры: median, throughput, аллокации (по возможности), пиковая память.
4. Оптимизации по результатам: убрать лишние `Vec`, кэшировать энтропию, не читать
   директории, если правило выключено, и т.д.
5. Зафиксировать бюджет в CI (не блокирующий, но информативный).
6. `docs/experiments/.../performance.md` + графики.

**DoD.**

- [ ] 10 МБ ≤ 20 мс (или объяснение);
- [ ] throughput ≥ 200 МБ/с;
- [ ] память ≤ 3× файла;
- [ ] нет регрессии после оптимизаций (бенч-сравнение до/после).

**Артефакт для ВКР:** раздел «Оценка производительности».

---

### Фаза 13. Документация, релиз, интеграция в текст ВКР

**Цель:** превратить код и эксперименты в защищаемую работу.

**Шаги.**

1. `README.md`: что это, зачем, установка, примеры CLI/JSON, ограничения, ссылка на
   документацию. Исходный анализ темы уже перенесён в `materials/analysis.md` — не удалять.
2. `docs/architecture.md`: диаграмма, слои, потоки, решения (со ссылками на ADR).
3. `docs/rules.md`: **reference уже реализованных** правил (ID, severity, профили,
   описание), генерируется из `RuleMeta` командой `cargo xtask rules-doc`.
   Не путать с `materials/rules_catalog.md` — это backlog с приоритетами и риском FP.
4. `docs/report-schema.md` + `report.schema.json`: контракт, примеры, версионирование.
5. `docs/ffi.md`, `CONTRIBUTING.md`, `SECURITY.md`.
6. `CHANGELOG.md`, тег `v1.0.0`; release workflow собирает артефакты.
7. Текст ВКР:
   - глава 1 ← фаза 1;
   - глава 2 ← фазы 2–5 (архитектура, профили, скоринг);
   - глава 3 ← фазы 6–9 (реализация, CLI, FFI);
   - глава 4 ← фазы 10–12 (устойчивость, корпуса, сравнение, производительность);
   - введение/заключение/приложения (каталог правил, схема, руководство).
8. Демо-сценарий на 3–5 минут: чистый файл → битый → Corkami → JSON → интеграция.
9. Презентация и ответы на вероятные вопросы (см. §13).

**DoD.**

- [ ] свежий клон собирается по README;
- [ ] все документы актуальны, ссылки живые;
- [ ] релизные артефакты приложены;
- [ ] текст ВКР содержит все цифры из экспериментов;
- [ ] демо работает без сети.

**Артефакт для ВКР:** готовый репозиторий, релиз, текст, презентация.

---

## 10. План по неделям и MVP

### 10.1. Ориентировочный график (10–12 часов в неделю)

| Неделя | Фазы | Результат |
|---|---|---|
| 1 | 0 + старт 1 | Workspace, CI, таксономия |
| 2 | 1 + 2 | Таксономия, Reader, энтропия |
| 3 | 3 | Парсинг заголовков |
| 4 | 4 | RVA/overlay/checksum |
| 5 | 5 | Движок правил + 15 правил + отчёт |
| 6 | 6 | CLI + JSON + тесты → **MVP** |
| 7 | 7 | Rich/энтропия/overlay |
| 8 | 8 | Директории |
| 9 | 9 + старт 10 | FFI, property-тесты |
| 10 | 10 | Ужесточение |
| 11 | 11 | Корпуса, сравнение, калибровка |
| 12 | 12 | Производительность |
| 13 | 13 | Документация, релиз |
| 14 | — | Буфер: текст ВКР, презентация, защита |

Если времени меньше — **MVP после недели 6** уже защищаем: устойчивый парсер,
15 правил, CLI+JSON, тесты, прогон на System32/Corkami (начальный).

### 10.2. MVP vs полная версия

| | MVP | Полная |
|---|---|---|
| Парсер | DOS/COFF/Optional/Sections | + Rich, директории |
| Правила | 15 (заголовки, секции) | 35+ |
| Профили | spec/loader/security (базово) | полный скоринг и калибровка |
| CLI | scan + JSON | batch, rules, schema |
| FFI | — | DLL/.so + C-пример |
| Тесты | unit + property | + snapshot, corpus, fuzz |
| Эксперименты | System32 + 10 Corkami | полный Corkami + сравнение |

---

## 11. Артефакты для ВКР (что кому соответствует)

| Артефакт | Где | Когда |
|---|---|---|
| Таксономия техник | `materials/evasion-taxonomy.md` | фаза 1 |
| Архитектура и ADR | `docs/architecture.md`, `docs/adr/` | фазы 0–5 |
| Каталог правил | backlog — `materials/rules_catalog.md`; reference — `docs/rules.md` | фазы 1–8 |
| Схема отчёта | `docs/report-schema.md`, `report.schema.json` | фаза 5 |
| Результаты System32 | `docs/experiments/.../summary.csv` | фаза 11 |
| Результаты Corkami | `docs/experiments/.../` | фаза 11 |
| Сравнение с аналогами | `docs/experiments/.../comparison.md` | фаза 11 |
| Производительность | `docs/experiments/.../performance.md` | фаза 12 |
| Руководство пользователя | `README.md`, `docs/ffi.md` | фаза 13 |
| Демо | сценарий + примеры | фаза 13 |

**Формулировка вклада (для введения/заключения):**

1. формализована трёхмодельная проверка PE (spec/loader/security), позволяющая явно
   выявлять parser differential;
2. разработан устойчивый к враждебному входу парсер с partial parsing и лимитами;
3. построен объяснимый каталог структурных правил и модель скоринга;
4. создан открытый воспроизводимый инструмент (CLI + библиотека) и методика его
   валидации на системном и adversarial-корпусах.

---

## 12. Риски и меры

| Риск | Вероятность | Мера |
|---|---|---|
| Scope creep (дизассемблер, ML, GUI) | высокая | жёсткое «вне scope», backlog, проверка по главам ВКР |
| FP на легитимных упакованных файлах | средняя | confidence, калибровка на System32, documented allowlist |
| Неопределённость семантики загрузчика | средняя | опора на «Lost in the Loader», ReactOS/Wine, эксперименты только на безопасных файлах; честно помечать эвристики |
| Мало места на диске | высокая | не вендорить корпуса, `cargo clean`, без Docker, fuzz опционален |
| Внешние инструменты сравнения недоступны | средняя | fallback: `goblin`/ручная выборка; зафиксировать ограничение |
| Нехватка времени | средняя | MVP-линия после фазы 6; P2-правила в backlog |
| Паника/зависание на хитром входе | средняя | property/fuzz, лимиты, ревью каждого цикла |
| Поломка JSON-контракта | низкая | schema_version, snapshot-тесты |
| Windows-only особенности FFI | низкая | CI на Linux для `.so`, ручная проверка DLL на Windows |
| Опасность при работе с malware | низкая (не используем) | только Corkami/синтетика; никакого запуска |

---

## 13. Чек-лист готовности к защите

- [ ] Репозиторий публичный, `main` зелёный, README понятен постороннему.
- [ ] Релиз `v1.0.0` с бинарниками и заголовком.
- [ ] 0 паник на всех корпусах; это показано в таблице.
- [ ] 35+ правил с тестами; каталог сгенерирован.
- [ ] Три вердикта работают и объяснены на слайде.
- [ ] Сравнение с `pefile`/`Manalyze`/`diec` оформлено.
- [ ] Производительность измерена, цифры совпадают с текстом.
- [ ] Ограничения названы честно (нет дизассемблирования, нет PKCS#7, эвристики).
- [ ] Демо: чистый → битый → Corkami → JSON → CI-гейт.
- [ ] Ответы готовы:
  - почему Rust, а не C++;
  - чем отличается от `pefile`/LIEF;
  - почему не YARA;
  - как обеспечивается 0 паник;
  - как моделируется загрузчик;
  - что такое parser differential и где он в работе;
  - как считаются FP и почему пороги такие.

---

## 14. Следующее действие

Начать с **фазы 0**: создать workspace, включить линты, поднять `cargo xtask ci` и CI.
После этого — фаза 1 (таксономия), не пропуская: она определяет состав правил и
формулировки для главы 1.
