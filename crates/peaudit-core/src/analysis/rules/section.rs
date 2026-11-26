//! Rules over the section table.
//!
//! Sections are the part of the image the loader actually maps, so a mistake
//! here is where parser differentials become exploitable: one tool sees data
//! inside the file, another sees it outside, one maps a page twice, another
//! does not. These rules compare the declared table with the file and with
//! itself.

use crate::analysis::finding::{Category, Confidence, Severity};
use crate::analysis::profile::{SECURITY_ONLY, SPEC_LOADER_SECURITY, SPEC_SECURITY};
use crate::analysis::rule::{AnalysisContext, Findings, Rule, RuleMeta, field};
use crate::pe::{SectionHeader, section};

use super::PE_SPEC;

/// Returns the file offset of a field inside a section table entry.
fn entry_offset(ctx: &AnalysisContext<'_>, index: usize, field_offset: usize) -> Option<u64> {
    ctx.file
        .offsets
        .sections
        .and_then(|base| base.checked_add(index.checked_mul(section::SECTION_HEADER_SIZE)?))
        .and_then(|entry| entry.checked_add(field_offset))
        .map(|offset| offset as u64)
}

/// Returns the virtual span a section occupies once mapped.
fn mapped_span(section: &SectionHeader) -> (u64, u64) {
    let start = u64::from(section.virtual_address);
    let size = u64::from(section.virtual_size.max(section.size_of_raw_data));
    (start, start.saturating_add(size))
}

/// Returns the section name, or a placeholder for a non-UTF-8 name.
fn name(section: &SectionHeader) -> &str {
    section.name_str().unwrap_or("<unnamed>")
}

/// `PE-SEC-001`: a section's raw data does not fit in the file.
pub struct RawBeyondFile;

impl RawBeyondFile {
    const META: RuleMeta = RuleMeta {
        id: "PE-SEC-001",
        title: "Сырые данные секции вне файла",
        description: "PointerToRawData + SizeOfRawData выходит за конец файла. Загрузчик \
                      отобразит только присутствующие байты, а инструмент, читающий по \
                      объявленному размеру, получит ошибку или мусор. Обрезанная секция — \
                      типичный способ спрятать настоящий код в хвосте, который никто не \
                      проверяет.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: Category::Section,
        family: "section-raw-bounds",
        profiles: SPEC_LOADER_SECURITY,
        references: &[PE_SPEC, "materials/rules_catalog.md"],
        since: "0.1.0",
    };
}

impl Rule for RawBeyondFile {
    fn meta(&self) -> &'static RuleMeta {
        &Self::META
    }

    fn evaluate(&self, ctx: &AnalysisContext<'_>, out: &mut Findings) {
        let file_size = ctx.data.len() as u64;

        for (index, section) in ctx.file.sections.iter().enumerate() {
            let Some(entry) = ctx.derived.section(index) else {
                continue;
            };
            if !entry.truncated {
                continue;
            }

            let pointer = u64::from(section.pointer_to_raw_data);
            let size = u64::from(section.size_of_raw_data);
            let end = pointer.saturating_add(size);
            let available = entry.data.size;

            out.push(
                Self::META
                    .finding(format!(
                        "Секция {} объявляет {size:#x} байт с {pointer:#x}, а в файле есть \
                         только {available:#x}",
                        name(section)
                    ))
                    .with_evidence(
                        field("sections[].pointerToRawData")
                            .at(
                                entry_offset(ctx, index, section::POINTER_TO_RAW_DATA_OFFSET)
                                    .unwrap_or_default(),
                            )
                            .expected(format!("pointer + size <= {file_size:#x}"))
                            .actual(format!("{pointer:#x} + {size:#x} = {end:#x}")),
                    ),
            );
        }
    }
}

/// `PE-SEC-002`: `VirtualSize` is zero but raw data is present.
pub struct EmptyVirtualSize;

impl EmptyVirtualSize {
    const META: RuleMeta = RuleMeta {
        id: "PE-SEC-002",
        title: "VirtualSize = 0 при наличии данных",
        description: "VirtualSize задаёт размер секции в памяти. Если он равен нулю, а \
                      SizeOfRawData больше нуля, загрузчик использует SizeOfRawData, а парсер, \
                      доверяющий VirtualSize, решит, что секция пуста. Разные ответы на вопрос \
                      «что отображено» — основа parser differential.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: Category::Section,
        family: "section-virtual-size",
        profiles: SPEC_SECURITY,
        references: &[PE_SPEC, "materials/rules_catalog.md"],
        since: "0.1.0",
    };
}

impl Rule for EmptyVirtualSize {
    fn meta(&self) -> &'static RuleMeta {
        &Self::META
    }

    fn evaluate(&self, ctx: &AnalysisContext<'_>, out: &mut Findings) {
        for (index, section) in ctx.file.sections.iter().enumerate() {
            if section.virtual_size != 0 || section.size_of_raw_data == 0 {
                continue;
            }

            out.push(
                Self::META
                    .finding(format!(
                        "Секция {} имеет VirtualSize = 0 при SizeOfRawData = {:#x}",
                        name(section),
                        section.size_of_raw_data
                    ))
                    .with_evidence(
                        field("sections[].virtualSize")
                            .at(entry_offset(ctx, index, section::VIRTUAL_SIZE_OFFSET)
                                .unwrap_or_default())
                            .expected("ненулевой размер при наличии данных")
                            .actual("0"),
                    ),
            );
        }
    }
}

/// `PE-SEC-005`: two sections overlap in memory.
pub struct VirtualOverlap;

impl VirtualOverlap {
    const META: RuleMeta = RuleMeta {
        id: "PE-SEC-005",
        title: "Пересечение секций в памяти",
        description: "Две секции занимают пересекающиеся диапазоны RVA. Загрузчик отобразит их \
                      поверх друг друга, и содержимое по общим адресам будет зависеть от \
                      порядка отображения. Один парсер увидит код одной секции, другой — \
                      данные другой.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: Category::Section,
        family: "section-overlap",
        profiles: SPEC_LOADER_SECURITY,
        references: &[PE_SPEC, "materials/rules_catalog.md"],
        since: "0.1.0",
    };
}

impl Rule for VirtualOverlap {
    fn meta(&self) -> &'static RuleMeta {
        &Self::META
    }

    fn evaluate(&self, ctx: &AnalysisContext<'_>, out: &mut Findings) {
        for (index, first) in ctx.file.sections.iter().enumerate() {
            let (first_start, first_end) = mapped_span(first);
            if first_start == first_end {
                continue;
            }

            for second in ctx.file.sections.iter().skip(index.saturating_add(1)) {
                let (second_start, second_end) = mapped_span(second);
                if second_start == second_end {
                    continue;
                }

                let start = first_start.max(second_start);
                let end = first_end.min(second_end);
                if start >= end {
                    continue;
                }

                out.push(
                    Self::META
                        .finding(format!(
                            "Секции {} ({first_start:#x}..{first_end:#x}) и {} \
                             ({second_start:#x}..{second_end:#x}) пересекаются на {:#x} байт",
                            name(first),
                            name(second),
                            end.saturating_sub(start)
                        ))
                        .with_evidence(
                            field("sections[].virtualAddress")
                                .expected("непересекающиеся диапазоны RVA")
                                .actual(format!(
                                    "{first_start:#x}..{first_end:#x} и \
                                     {second_start:#x}..{second_end:#x}"
                                )),
                        ),
                );
            }
        }
    }
}

/// `PE-SEC-007`: a section is both writable and executable.
pub struct WritableExecutable;

impl WritableExecutable {
    const META: RuleMeta = RuleMeta {
        id: "PE-SEC-007",
        title: "Секция одновременно записываемая и исполняемая",
        description: "Флаги MEM_WRITE и MEM_EXECUTE вместе дают страницу W+X: код может \
                      переписать сам себя, а данные — стать кодом. Легитимные образы держат \
                      код и данные раздельно; W+X чаще встречается у распаковщиков, \
                      шеллкодов и инжекторов.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: Category::Section,
        family: "section-permissions",
        profiles: SECURITY_ONLY,
        references: &[PE_SPEC, "materials/rules_catalog.md"],
        since: "0.1.0",
    };
}

impl Rule for WritableExecutable {
    fn meta(&self) -> &'static RuleMeta {
        &Self::META
    }

    fn evaluate(&self, ctx: &AnalysisContext<'_>, out: &mut Findings) {
        for (index, section) in ctx.file.sections.iter().enumerate() {
            if !section.is_writable_and_executable() {
                continue;
            }

            out.push(
                Self::META
                    .finding(format!(
                        "Секция {} имеет права на запись и исполнение одновременно",
                        name(section)
                    ))
                    .with_evidence(
                        field("sections[].characteristics")
                            .at(entry_offset(ctx, index, section::CHARACTERISTICS_OFFSET)
                                .unwrap_or_default())
                            .expected("MEM_WRITE и MEM_EXECUTE не вместе")
                            .actual(format!("{:#010x}", section.characteristics)),
                    ),
            );
        }
    }
}

/// `PE-SEC-012`: a section's raw data starts inside the headers.
pub struct RawInsideHeaders;

impl RawInsideHeaders {
    const META: RuleMeta = RuleMeta {
        id: "PE-SEC-012",
        title: "Сырые данные секции внутри заголовков",
        description: "PointerToRawData меньше SizeOfHeaders: объявленные данные секции лежат \
                      там, где находятся заголовки. Загрузчик отобразит секцию из области, \
                      которую другой инструмент считает заголовками, и содержимое по одному \
                      адресу будет разным в зависимости от того, что именно читать.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: Category::Section,
        family: "section-raw-bounds",
        profiles: SPEC_LOADER_SECURITY,
        references: &[PE_SPEC, "materials/rules_catalog.md"],
        since: "0.1.0",
    };
}

impl Rule for RawInsideHeaders {
    fn meta(&self) -> &'static RuleMeta {
        &Self::META
    }

    fn evaluate(&self, ctx: &AnalysisContext<'_>, out: &mut Findings) {
        let Some(header) = ctx.file.optional else {
            return;
        };
        let headers_end = u64::from(header.size_of_headers);
        if headers_end == 0 {
            return;
        }

        for (index, section) in ctx.file.sections.iter().enumerate() {
            if section.size_of_raw_data == 0 {
                continue;
            }
            let pointer = u64::from(section.pointer_to_raw_data);
            if pointer >= headers_end {
                continue;
            }

            out.push(
                Self::META
                    .finding(format!(
                        "Секция {} начинается с {pointer:#x}, внутри заголовков \
                         (SizeOfHeaders = {headers_end:#x})",
                        name(section)
                    ))
                    .with_evidence(
                        field("sections[].pointerToRawData")
                            .at(
                                entry_offset(ctx, index, section::POINTER_TO_RAW_DATA_OFFSET)
                                    .unwrap_or_default(),
                            )
                            .expected(format!(">= {headers_end:#x}"))
                            .actual(format!("{pointer:#x}")),
                    ),
            );
        }
    }
}

/// `PE-SEC-013`: the section table ends with empty sections.
pub struct TrailingEmptySections;

impl TrailingEmptySections {
    const META: RuleMeta = RuleMeta {
        id: "PE-SEC-013",
        title: "Хвостовые пустые секции",
        description: "В конце таблицы объявлены секции с нулевыми VirtualSize и SizeOfRawData. \
                      Они ничего не отображают, но входят в NumberOfSections: инструменты, \
                      читающие таблицу целиком, и инструменты, останавливающиеся на первой \
                      пустой секции, увидят разное число секций. Это классический приём \
                      расхождения парсеров.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: Category::Section,
        family: "section-virtual-size",
        profiles: SPEC_SECURITY,
        references: &[PE_SPEC, "materials/rules_catalog.md"],
        since: "0.1.0",
    };
}

impl Rule for TrailingEmptySections {
    fn meta(&self) -> &'static RuleMeta {
        &Self::META
    }

    fn evaluate(&self, ctx: &AnalysisContext<'_>, out: &mut Findings) {
        let empty =
            |section: &SectionHeader| section.virtual_size == 0 && section.size_of_raw_data == 0;

        let trailing = ctx
            .file
            .sections
            .iter()
            .rev()
            .take_while(|section| empty(section))
            .count();
        if trailing == 0 {
            return;
        }

        let first = ctx.file.sections.len().saturating_sub(trailing);
        out.push(
            Self::META
                .finding(format!(
                    "В конце таблицы {trailing} пустых секций, начиная с индекса {first}"
                ))
                .with_evidence(
                    field("sections[].virtualSize")
                        .expected("последняя секция непустая")
                        .actual(format!(
                            "{trailing} секций с VirtualSize = 0 и SizeOfRawData = 0"
                        )),
                ),
        );
    }
}

static RAW_BEYOND_FILE: RawBeyondFile = RawBeyondFile;
static EMPTY_VIRTUAL_SIZE: EmptyVirtualSize = EmptyVirtualSize;
static VIRTUAL_OVERLAP: VirtualOverlap = VirtualOverlap;
static WRITABLE_EXECUTABLE: WritableExecutable = WritableExecutable;
static RAW_INSIDE_HEADERS: RawInsideHeaders = RawInsideHeaders;
static TRAILING_EMPTY_SECTIONS: TrailingEmptySections = TrailingEmptySections;

/// Every section rule, in registry order.
pub(crate) static RULES: &[&dyn Rule] = &[
    &RAW_BEYOND_FILE,
    &EMPTY_VIRTUAL_SIZE,
    &VIRTUAL_OVERLAP,
    &WRITABLE_EXECUTABLE,
    &RAW_INSIDE_HEADERS,
    &TRAILING_EMPTY_SECTIONS,
];

#[cfg(test)]
mod tests {
    use super::{
        EmptyVirtualSize, RawBeyondFile, RawInsideHeaders, TrailingEmptySections, VirtualOverlap,
        WritableExecutable,
    };
    use crate::analysis::rules::test_support;
    use crate::pe::{optional, section};
    use crate::testutil::PeBuilder;

    fn write_section(builder: &mut PeBuilder, index: usize, bytes: [u32; 5]) {
        let entry = builder.sections_offset() + index * section::SECTION_HEADER_SIZE;
        // virtual size, virtual address, raw size, raw pointer, characteristics
        assert!(builder.patch_u32(entry + section::VIRTUAL_SIZE_OFFSET, bytes[0]));
        assert!(builder.patch_u32(entry + section::VIRTUAL_ADDRESS_OFFSET, bytes[1]));
        assert!(builder.patch_u32(entry + section::SIZE_OF_RAW_DATA_OFFSET, bytes[2]));
        assert!(builder.patch_u32(entry + section::POINTER_TO_RAW_DATA_OFFSET, bytes[3]));
        assert!(builder.patch_u32(entry + section::CHARACTERISTICS_OFFSET, bytes[4]));
    }

    #[test]
    fn a_section_inside_the_file_is_accepted() {
        let findings = test_support::run(&RawBeyondFile, &PeBuilder::pe32());
        assert!(findings.is_empty());
    }

    #[test]
    fn a_truncated_section_is_a_finding() {
        let mut builder = PeBuilder::pe32();
        write_section(
            &mut builder,
            0,
            [0x1000, 0x1000, 0x1000, 0x200, 0x6000_0020],
        );

        let findings = test_support::run(&RawBeyondFile, &builder);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings.as_slice().first().map(|f| f.id),
            Some("PE-SEC-001")
        );
    }

    #[test]
    fn a_zero_virtual_size_with_data_is_a_finding() {
        let mut builder = PeBuilder::pe32();
        write_section(&mut builder, 0, [0, 0x1000, 0x200, 0x200, 0x6000_0020]);

        let findings = test_support::run(&EmptyVirtualSize, &builder);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn an_empty_section_is_accepted_by_the_virtual_size_rule() {
        let mut builder = PeBuilder::pe32();
        write_section(&mut builder, 0, [0, 0x1000, 0, 0, 0]);

        let findings = test_support::run(&EmptyVirtualSize, &builder);
        assert!(findings.is_empty());
    }

    #[test]
    fn the_default_table_has_no_overlap() {
        let findings = test_support::run(&VirtualOverlap, &PeBuilder::pe32());
        assert!(findings.is_empty());
    }

    #[test]
    fn overlapping_sections_are_a_finding() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(
            builder.coff_offset() + crate::pe::coff::NUMBER_OF_SECTIONS_OFFSET,
            2
        ));
        write_section(&mut builder, 0, [0x1000, 0x1000, 0x200, 0x200, 0x6000_0020]);
        write_section(&mut builder, 1, [0x1000, 0x1800, 0x200, 0x400, 0x4000_0040]);

        let findings = test_support::run(&VirtualOverlap, &builder);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn a_normal_text_section_is_not_writable_and_executable() {
        let findings = test_support::run(&WritableExecutable, &PeBuilder::pe32());
        assert!(findings.is_empty());
    }

    #[test]
    fn a_writable_executable_section_is_a_finding() {
        let mut builder = PeBuilder::pe32();
        write_section(
            &mut builder,
            0,
            [
                0x1000,
                0x1000,
                0x200,
                0x200,
                section::SCN_MEM_EXECUTE | section::SCN_MEM_WRITE | section::SCN_CNT_CODE,
            ],
        );

        let findings = test_support::run(&WritableExecutable, &builder);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings.as_slice().first().map(|f| f.id),
            Some("PE-SEC-007")
        );
    }

    #[test]
    fn raw_data_after_the_headers_is_accepted() {
        let findings = test_support::run(&RawInsideHeaders, &PeBuilder::pe32());
        assert!(findings.is_empty());
    }

    #[test]
    fn raw_data_inside_the_headers_is_a_finding() {
        let mut builder = PeBuilder::pe32();
        write_section(&mut builder, 0, [0x1000, 0x1000, 0x200, 0x100, 0x6000_0020]);
        assert!(builder.patch_u32(
            builder.optional_offset() + optional::SIZE_OF_HEADERS_OFFSET,
            0x200
        ));

        let findings = test_support::run(&RawInsideHeaders, &builder);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn a_non_empty_last_section_is_accepted() {
        let findings = test_support::run(&TrailingEmptySections, &PeBuilder::pe32());
        assert!(findings.is_empty());
    }

    #[test]
    fn a_trailing_empty_section_is_a_finding() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(
            builder.coff_offset() + crate::pe::coff::NUMBER_OF_SECTIONS_OFFSET,
            2
        ));
        write_section(&mut builder, 0, [0x1000, 0x1000, 0x200, 0x200, 0x6000_0020]);
        write_section(&mut builder, 1, [0, 0, 0, 0, 0]);

        let findings = test_support::run(&TrailingEmptySections, &builder);
        assert_eq!(findings.len(), 1);
    }
}
