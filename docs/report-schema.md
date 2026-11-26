# Схема отчёта `peaudit`

- **Версия схемы:** `1.0` (`Report::SCHEMA_VERSION`)
- **Машинная схема:** [`report.schema.json`](report.schema.json)
- **Реализация:** `crates/peaudit-core/src/report/mod.rs`
- **Проверка:** `crates/peaudit-core/tests/report_schema.rs`

Отчёт — единственная структура с публичным JSON-контрактом. Всё остальное
(`PeFile`, `Derived`, `Finding` как промежуточный тип) может меняться между
версиями; JSON-документ — нет.

## 1. Инварианты

1. **Детерминизм.** Одни и те же байты и одни и те же опции дают побайтно
   одинаковый JSON. В документе нет времени, длительности, абсолютных путей
   (если их не передал вызывающий) и неупорядоченных коллекций.
2. **Порядок находок.** `severity` по убыванию, затем `id`, затем `message`.
   Сообщение — последний ключ, потому что одно правило законно сообщает о
   нескольких секциях.
3. **Три вердикта всегда вместе.** `verdicts` содержит `spec`, `loader` и
   `security` независимо от того, какой профиль выбрал пользователь.
4. **Невалидный PE — не ошибка.** Отчёт всё равно печатается; `parse.status`
   показывает, как далеко зашёл разбор.
5. **`verdicts = null`, если файл не PE.** При `parse.status == "failed"` судить
   нечего, и три нуля были бы ложным утверждением «чисто» (ADR-0006).
6. **Новые необязательные поля — minor, ломающие — major.** Потребитель обязан
   отвергать `schema_version`, который не понимает.

## 2. Пример

Фрагмент реального отчёта для «грязной» фикстуры из `tests/report_schema.rs`
(показана одна находка из пяти; `references` сокращены до спецификации).
Значения можно перепроверить: это вывод `analyze`, а не иллюстрация.

```json
{
  "schema_version": "1.0",
  "tool": { "name": "peaudit", "version": "0.1.0" },
  "file": {
    "size": 1024,
    "sha256": "2b3d9cf377f806b38a29204da6a83ab1aa333f2d5a70769256a1e50dabf340b0"
  },
  "parse": {
    "status": "complete",
    "format": "pe32",
    "machine": "i386",
    "diagnostics": []
  },
  "verdicts": {
    "spec": { "score": 25, "level": "low" },
    "loader": { "score": 24, "level": "low" },
    "security": { "score": 21, "level": "low" }
  },
  "findings": [
    {
      "id": "PE-OPT-003",
      "title": "Неверный SizeOfHeaders",
      "severity": "high",
      "confidence": "high",
      "category": "optional",
      "profiles": ["spec", "loader"],
      "message": "SizeOfHeaders = 0x100 меньше конца таблицы секций (0x160) и не кратно FileAlignment (0x200)",
      "evidence": [
        {
          "field": "optional.sizeOfHeaders",
          "offset": 148,
          "expected": ">= 0x160 и кратно 0x200",
          "actual": "0x100"
        }
      ],
      "references": ["https://learn.microsoft.com/windows/win32/debug/pe-format"]
    }
  ],
  "metrics": {
    "headers": { "declared": 256, "required": 352 },
    "image": { "declared": 4096, "computed": 8192 },
    "overlay": {
      "leading": { "offset": 640, "size": 384 },
      "certificate": { "offset": null, "size": 0 },
      "trailing": { "offset": null, "size": 0 }
    },
    "checksum": { "stored": 4660, "computed": 48997, "consistent": false },
    "entropy": {
      "file": 0.4559,
      "sections": [
        {
          "index": 0,
          "name": ".text",
          "offset": 128,
          "size": 512,
          "entropy": 0.4473,
          "truncated": false,
          "high": false
        }
      ]
    }
  },
  "limits": {
    "max_file_size": 536870912,
    "max_sections": 4096,
    "max_imports": 65536,
    "max_exports": 65536,
    "max_resource_nodes": 65536,
    "max_resource_depth": 32,
    "max_string_len": 4096,
    "max_thunks_per_import": 65536,
    "max_entropy_window": 4096
  }
}
```

## 3. Поля верхнего уровня

| Поле | Тип | Смысл |
|---|---|---|
| `schema_version` | string | `"1.0"`; часть контракта, а не метаданные сборки |
| `tool` | object | `name` и `version` инструмента |
| `file` | object | `size` всегда; `path`, `sha256`, `sha1`, `md5` — по наличию |
| `parse` | object | `status`, `format`, `machine`, `diagnostics` |
| `verdicts` | object \| null | три независимых вердикта или `null` для не-PE |
| `findings` | array | находки в детерминированном порядке |
| `metrics` | object | измерения, на которые опираются правила |
| `limits` | object | применённые потолки безопасности |

### `parse`

| Поле | Значения | Смысл |
|---|---|---|
| `status` | `failed`, `partial`, `complete` | как далеко зашёл разбор, а не «валиден ли файл» |
| `format` | `pe32`, `pe32+` | раскладка необязательного заголовка |
| `machine` | `i386`, `amd64`, `arm64`, … | `Machine` из COFF |
| `diagnostics` | array | решения парсера: `code`, `severity`, `offset`, `context` |

Диагностика — не находка (ADR-0005). Она отвечает на вопрос «что парсер не смог
прочитать или был вынужден пропустить», а находка — «что не соответствует
спецификации».

### `verdicts`

| Поле | Тип | Смысл |
|---|---|---|
| `score` | integer `0..=100` | взвешенная сумма находок профиля |
| `level` | `clean`, `notice`, `low`, `suspicious`, `high`, `critical` | грубая трактовка score |

Скоринг: `weight(info/low/medium/high/critical) = 0/1/4/10/20`,
`confidence(low/medium/high) = 0.5/0.75/1.0`, вклад одной семьи (`family`)
ограничен 25, итог — 100. Уровни: `0 clean`, `1–9 notice`, `10–29 low`,
`30–59 suspicious`, `60–84 high`, `85–100 critical`.

`--fail-on` в CLI работает по `severity` отдельной находки, а не по `score`:
это объяснимо и не меняется при калибровке весов.

### `findings[]`

| Поле | Смысл |
|---|---|
| `id` | стабильный идентификатор правила (`PE-SEC-007`) |
| `title` | короткое название правила |
| `severity` | насколько плохо, если находка верна |
| `confidence` | насколько правило уверено |
| `category` | `dos`, `coff`, `optional`, `section` |
| `profiles` | профили, в которых находка учитывается |
| `message` | что именно найдено, с числами |
| `evidence[]` | `field`, `offset`, `expected`, `actual` — проверяемо руками |
| `references` | спецификация или статья |

`family` (группа для кап-а) в JSON не выводится: это деталь модели скоринга,
а не контракт.

### `metrics`

| Блок | Поля | Смысл |
|---|---|---|
| `headers` | `declared`, `required` | `SizeOfHeaders` против конца таблицы секций |
| `image` | `declared`, `computed` | `SizeOfImage` против `align_up(max(VA + VS))` |
| `overlay` | `leading`, `certificate`, `trailing` | разбиение хвоста вокруг подписи |
| `checksum` | `stored`, `computed`, `consistent` | `CheckSum` и сумма по файлу |
| `entropy` | `file`, `sections[]` | энтропия Шеннона; у секции ещё `truncated` и `high` |

Отсутствующая область overlay представлена объектом с `offset: null` и
`size: 0`: форма не меняется, потребителю не нужен особый случай.

`checksum.consistent` — это буквальное сравнение `stored == computed`. Поэтому
при `stored: 0` (поле не заполнено) оно равно `false`, хотя правило `PE-OPT-008`
такой файл не отмечает: `0` означает «не задано», а не «не совпало». Потребитель,
которому нужен именно вердикт, должен смотреть на находки, а не на это поле.

## 4. Валидация

`docs/report.schema.json` написан вручную (draft-07, только `type`, `required`,
`properties`, `additionalProperties`, `items`, `enum`, `anyOf`, `$ref`,
`minimum`, `maximum`, `minItems`). Тест `tests/report_schema.rs`:

1. сериализует реальные отчёты (чистый PE, «грязный» PE, не-PE) и проверяет их
   мини-валидатором;
2. отдельно проверяет, что валидатор **отвергает** отчёт без обязательного поля,
   с неизвестной severity, со score > 100 и с лишним полем.

Второй пункт важен: без него «схема проходит» могла бы означать «валидатор
ничего не проверяет».

## 5. Что пока не входит

- `timings_ms` — сознательно нет: длительности ломают детерминизм JSON.
- `rich` (Rich Header) — появится вместе с правилами о нём (фаза 7+).
- `path` заполняет вызывающий (CLI); библиотека оставляет его `null`, потому что
  ядро не знает про файловую систему.
