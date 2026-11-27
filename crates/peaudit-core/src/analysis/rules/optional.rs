//! Rules over the optional header.
//!
//! The optional header is where a file declares the layout of the image: how
//! big it is, where execution starts and how sections align. Almost every value
//! here can be cross-checked against the section table, which is why these rules
//! are deterministic rather than heuristic.

use crate::analysis::finding::{Category, Confidence, Severity};
use crate::analysis::profile::{SPEC_LOADER, SPEC_LOADER_SECURITY, SPEC_SECURITY};
use crate::analysis::rule::{AnalysisContext, Findings, Rule, RuleMeta, field};
use crate::pe::optional;
use crate::spec;

use super::{PE_SPEC, mapped_span};

/// `PE-OPT-002`: `SizeOfImage` is not the aligned end of the last section.
pub struct ImageSize;

impl ImageSize {
    const META: RuleMeta = RuleMeta {
        id: "PE-OPT-002",
        title: "Неверный SizeOfImage",
        description: "SizeOfImage должен быть равен align_up(max(VirtualAddress + VirtualSize), \
                      SectionAlignment). Если значение меньше, часть образа не отображается; \
                      если больше — загрузчик резервирует лишнюю память. Расхождение также \
                      означает, что два парсера по-разному определят границу образа и места \
                      для overlay.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: Category::OptionalHeader,
        family: "optional-image-size",
        profiles: SPEC_LOADER,
        references: &[PE_SPEC, "materials/rules_catalog.md"],
        since: "0.1.0",
    };
}

impl Rule for ImageSize {
    fn meta(&self) -> &'static RuleMeta {
        &Self::META
    }

    fn evaluate(&self, ctx: &AnalysisContext<'_>, out: &mut Findings) {
        let (Some(header), Some(image)) = (ctx.file.optional, ctx.derived.image_size) else {
            return;
        };
        let Some(computed) = image.computed else {
            return;
        };
        let declared = u64::from(image.declared);
        if declared == computed {
            return;
        }

        out.push(
            Self::META
                .finding(format!(
                    "SizeOfImage объявлен как {declared:#x}, по секциям получается {computed:#x}"
                ))
                .with_evidence(
                    field("optional.sizeOfImage")
                        .at((header.offset.saturating_add(optional::SIZE_OF_IMAGE_OFFSET)) as u64)
                        .expected(format!("{computed:#x}"))
                        .actual(format!("{declared:#x}")),
                ),
        );
    }
}

/// `PE-OPT-003`: `SizeOfHeaders` does not cover the section table or is not
/// aligned to `FileAlignment`.
pub struct HeadersSize;

impl HeadersSize {
    const META: RuleMeta = RuleMeta {
        id: "PE-OPT-003",
        title: "Неверный SizeOfHeaders",
        description: "SizeOfHeaders задаёт конец области заголовков и начало данных секций. \
                      Значение меньше фактического конца таблицы секций означает, что таблица \
                      выходит за объявленные заголовки: загрузчик ищет секции по \
                      SizeOfOptionalHeader, а инструмент, доверяющий SizeOfHeaders, увидит \
                      данные там, где на самом деле заголовки. Значение должно быть кратно \
                      FileAlignment, иначе граница заголовков не совпадает с границей \
                      отображения.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: Category::OptionalHeader,
        family: "optional-headers-size",
        profiles: SPEC_LOADER,
        references: &[PE_SPEC, "materials/rules_catalog.md"],
        since: "0.1.0",
    };
}

impl Rule for HeadersSize {
    fn meta(&self) -> &'static RuleMeta {
        &Self::META
    }

    fn evaluate(&self, ctx: &AnalysisContext<'_>, out: &mut Findings) {
        let (Some(header), Some(headers)) = (ctx.file.optional, ctx.derived.headers_size) else {
            return;
        };

        let short = !headers.covers_headers();
        let misaligned = headers.declared_is_aligned() == Some(false);
        if !short && !misaligned {
            return;
        }

        let mut problems = Vec::new();
        if short {
            problems.push(format!(
                "меньше конца таблицы секций ({:#x})",
                headers.required
            ));
        }
        if misaligned {
            problems.push(format!(
                "не кратно FileAlignment ({:#x})",
                headers.file_alignment
            ));
        }

        out.push(
            Self::META
                .finding(format!(
                    "SizeOfHeaders = {:#x} {}",
                    headers.declared,
                    problems.join(" и ")
                ))
                .with_evidence(
                    field("optional.sizeOfHeaders")
                        .at((header
                            .offset
                            .saturating_add(optional::SIZE_OF_HEADERS_OFFSET))
                            as u64)
                        .expected(format!(
                            ">= {:#x} и кратно {:#x}",
                            headers.required, headers.file_alignment
                        ))
                        .actual(format!("{:#x}", headers.declared)),
                ),
        );
    }
}

/// `PE-OPT-004`: `FileAlignment` is not a power of two or is out of range.
pub struct FileAlignment;

impl FileAlignment {
    const META: RuleMeta = RuleMeta {
        id: "PE-OPT-004",
        title: "Неверный FileAlignment",
        description: "FileAlignment задаёт выравнивание данных секций в файле. Спецификация \
                      требует степень двойки в диапазоне [0x200, 0x10000]. Исключение — \
                      low-alignment образы, где SectionAlignment меньше 0x1000 и \
                      FileAlignment равен ему. Любое другое значение делает границы секций \
                      неоднозначными.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: Category::OptionalHeader,
        family: "optional-alignment",
        profiles: SPEC_LOADER,
        references: &[PE_SPEC, "materials/rules_catalog.md"],
        since: "0.1.0",
    };
}

impl Rule for FileAlignment {
    fn meta(&self) -> &'static RuleMeta {
        &Self::META
    }

    fn evaluate(&self, ctx: &AnalysisContext<'_>, out: &mut Findings) {
        let Some(header) = ctx.file.optional else {
            return;
        };
        let alignment = header.file_alignment;
        let section_alignment = header.section_alignment;
        let low_alignment = section_alignment != 0
            && section_alignment < spec::PAGE_ALIGNMENT
            && alignment == section_alignment;
        let in_range = (spec::MIN_FILE_ALIGNMENT..=spec::MAX_FILE_ALIGNMENT).contains(&alignment);

        if alignment != 0 && alignment.is_power_of_two() && (in_range || low_alignment) {
            return;
        }

        out.push(
            Self::META
                .finding(format!(
                    "FileAlignment = {alignment:#x}: ожидается степень двойки в диапазоне \
                     [{:#x}, {:#x}] или low-alignment значение, равное SectionAlignment",
                    spec::MIN_FILE_ALIGNMENT,
                    spec::MAX_FILE_ALIGNMENT
                ))
                .with_evidence(
                    field("optional.fileAlignment")
                        .at((header
                            .offset
                            .saturating_add(optional::FILE_ALIGNMENT_OFFSET))
                            as u64)
                        .expected(format!(
                            "степень двойки в [{:#x}, {:#x}]",
                            spec::MIN_FILE_ALIGNMENT,
                            spec::MAX_FILE_ALIGNMENT
                        ))
                        .actual(format!("{alignment:#x}")),
                ),
        );
    }
}

/// `PE-OPT-005`: `SectionAlignment` is zero, not a power of two, or smaller
/// than `FileAlignment`.
pub struct SectionAlignment;

impl SectionAlignment {
    const META: RuleMeta = RuleMeta {
        id: "PE-OPT-005",
        title: "Неверный SectionAlignment",
        description: "SectionAlignment задаёт шаг отображения секций в памяти. Он должен быть \
                      степенью двойки и не меньше FileAlignment; иначе секции в памяти \
                      перекрываются или начинаются внутри страницы, и загрузчик отображает не \
                      то, что описано в таблице.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: Category::OptionalHeader,
        family: "optional-alignment",
        profiles: SPEC_LOADER,
        references: &[PE_SPEC, "materials/rules_catalog.md"],
        since: "0.1.0",
    };
}

impl Rule for SectionAlignment {
    fn meta(&self) -> &'static RuleMeta {
        &Self::META
    }

    fn evaluate(&self, ctx: &AnalysisContext<'_>, out: &mut Findings) {
        let Some(header) = ctx.file.optional else {
            return;
        };
        let alignment = header.section_alignment;
        let file_alignment = header.file_alignment;
        let valid = alignment != 0
            && alignment.is_power_of_two()
            && (file_alignment == 0 || alignment >= file_alignment);
        if valid {
            return;
        }

        out.push(
            Self::META
                .finding(format!(
                    "SectionAlignment = {alignment:#x}: ожидается степень двойки не меньше \
                     FileAlignment ({file_alignment:#x})"
                ))
                .with_evidence(
                    field("optional.sectionAlignment")
                        .at((header
                            .offset
                            .saturating_add(optional::SECTION_ALIGNMENT_OFFSET))
                            as u64)
                        .expected(format!("степень двойки >= {file_alignment:#x}"))
                        .actual(format!("{alignment:#x}")),
                ),
        );
    }
}

/// `PE-OPT-006`: the entry point is missing or not inside executable code.
pub struct EntryPoint;

impl EntryPoint {
    const META: RuleMeta = RuleMeta {
        id: "PE-OPT-006",
        title: "Точка входа вне исполняемой секции",
        description: "AddressOfEntryPoint — RVA первой выполняемой инструкции. У исполняемого \
                      образа без флага DLL нулевая точка входа означает, что запускать нечего. \
                      Ненулевая точка входа, не попадающая ни в одну секцию с правом \
                      выполнения или с кодом, означает, что загрузчик передаст управление \
                      данным, а не коду. У DLL нулевая точка входа допустима, как и у managed \
                      сборки: CLR берёт точку входа из CLI-заголовка, а не из \
                      AddressOfEntryPoint.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: Category::OptionalHeader,
        family: "optional-entry-point",
        profiles: SPEC_LOADER_SECURITY,
        references: &[PE_SPEC, "materials/rules_catalog.md"],
        since: "0.1.0",
    };
}

/// Returns `true` when the image declares a CLR runtime header.
///
/// A non-empty `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR` entry marks a managed
/// assembly, whose entry point lives in the CLI header.
fn is_managed(file: &crate::pe::PeFile) -> bool {
    file.directories.iter().any(|directory| {
        directory.index == spec::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
            && (directory.virtual_address != 0 || directory.size != 0)
    })
}

impl Rule for EntryPoint {
    fn meta(&self) -> &'static RuleMeta {
        &Self::META
    }

    fn evaluate(&self, ctx: &AnalysisContext<'_>, out: &mut Findings) {
        let (Some(header), Some(coff)) = (ctx.file.optional, ctx.file.coff) else {
            return;
        };
        let entry = header.address_of_entry_point;
        let offset = (header
            .offset
            .saturating_add(optional::ADDRESS_OF_ENTRY_POINT_OFFSET)) as u64;

        if entry == 0 {
            // A managed assembly takes its entry point from the CLI header, so
            // zero here says nothing about the image (PowerShell ISE is a real
            // example).
            if is_managed(ctx.file) {
                return;
            }
            if !coff.is_dll() && coff.is_executable_image() {
                out.push(
                    Self::META
                        .finding(
                            "AddressOfEntryPoint = 0 у исполняемого образа без флага DLL"
                                .to_owned(),
                        )
                        .with_evidence(
                            field("optional.addressOfEntryPoint")
                                .at(offset)
                                .expected("ненулевой RVA кода")
                                .actual("0"),
                        ),
                );
            }
            return;
        }

        if ctx.file.sections.is_empty() {
            return;
        }

        let address = u64::from(entry);
        let container = ctx.file.sections.iter().find(|section| {
            let (start, end) = mapped_span(section);
            start <= address && address < end
        });

        match container {
            Some(section) if section.is_executable() || section.contains_code() => {}
            Some(section) => {
                let name = section.name_str().unwrap_or("<unnamed>");
                out.push(
                    Self::META
                        .finding(format!(
                            "Точка входа {address:#x} находится в секции {name}, у которой нет \
                             права выполнения"
                        ))
                        .with_evidence(
                            field("optional.addressOfEntryPoint")
                                .at(offset)
                                .expected("RVA внутри исполняемой секции")
                                .actual(format!("{address:#x}")),
                        )
                        .with_evidence(
                            field("sections[].characteristics")
                                .expected("MEM_EXECUTE или CNT_CODE")
                                .actual(format!("{:#010x}", section.characteristics)),
                        ),
                );
            }
            None => {
                out.push(
                    Self::META
                        .finding(format!(
                            "Точка входа {address:#x} не попадает ни в одну секцию образа"
                        ))
                        .with_evidence(
                            field("optional.addressOfEntryPoint")
                                .at(offset)
                                .expected("RVA внутри образа")
                                .actual(format!("{address:#x}")),
                        ),
                );
            }
        }
    }
}

/// `PE-OPT-008`: a non-zero checksum does not match the computed one.
pub struct Checksum;

impl Checksum {
    const META: RuleMeta = RuleMeta {
        id: "PE-OPT-008",
        title: "Контрольная сумма не совпадает",
        description: "Ненулевой CheckSum должен совпадать с суммой, посчитанной по файлу с \
                      замаскированным полем. Несовпадение означает, что файл изменили после \
                      вычисления суммы (или сумму скопировали из другого файла). Нулевое \
                      значение — «не задано»: многие легитимные сборки его не заполняют, \
                      поэтому оно не является находкой.",
        severity: Severity::Low,
        confidence: Confidence::High,
        category: Category::OptionalHeader,
        family: "optional-checksum",
        profiles: SPEC_SECURITY,
        references: &[PE_SPEC, "materials/rules_catalog.md"],
        since: "0.1.0",
    };
}

impl Rule for Checksum {
    fn meta(&self) -> &'static RuleMeta {
        &Self::META
    }

    fn evaluate(&self, ctx: &AnalysisContext<'_>, out: &mut Findings) {
        let Some(header) = ctx.file.optional else {
            return;
        };
        let info = &ctx.derived.checksum;
        let (Some(stored), Some(computed)) = (info.stored, info.computed) else {
            return;
        };
        // Zero means "not set", not "mismatch": the analyzer must not flag the
        // common case of a linker that never fills the field.
        if stored == 0 || stored == computed {
            return;
        }

        out.push(
            Self::META
                .finding(format!(
                    "CheckSum = {stored:#010x}, вычислено {computed:#010x}"
                ))
                .with_evidence(
                    field("optional.checkSum")
                        .at((header.offset.saturating_add(optional::CHECKSUM_OFFSET)) as u64)
                        .expected(format!("{computed:#010x}"))
                        .actual(format!("{stored:#010x}")),
                ),
        );
    }
}

/// `PE-OPT-013`: `SizeOfHeaders` points past the end of the file.
pub struct HeadersBeyondFile;

impl HeadersBeyondFile {
    const META: RuleMeta = RuleMeta {
        id: "PE-OPT-013",
        title: "Заголовки больше файла",
        description: "SizeOfHeaders больше размера файла означает, что данные секций начинаются \
                      за концом файла: загрузчик либо откажется отображать образ, либо \
                      отобразит только заголовки. Это же значение используют инструменты для \
                      поиска overlay, поэтому расхождение с реальным размером файла делает \
                      разбор неоднозначным.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: Category::OptionalHeader,
        family: "optional-headers-size",
        profiles: SPEC_LOADER_SECURITY,
        references: &[PE_SPEC, "materials/rules_catalog.md"],
        since: "0.1.0",
    };
}

impl Rule for HeadersBeyondFile {
    fn meta(&self) -> &'static RuleMeta {
        &Self::META
    }

    fn evaluate(&self, ctx: &AnalysisContext<'_>, out: &mut Findings) {
        let Some(header) = ctx.file.optional else {
            return;
        };
        let declared = u64::from(header.size_of_headers);
        let file_size = ctx.data.len() as u64;
        if declared <= file_size {
            return;
        }

        out.push(
            Self::META
                .finding(format!(
                    "SizeOfHeaders = {declared:#x} больше размера файла ({file_size:#x})"
                ))
                .with_evidence(
                    field("optional.sizeOfHeaders")
                        .at((header
                            .offset
                            .saturating_add(optional::SIZE_OF_HEADERS_OFFSET))
                            as u64)
                        .expected(format!("<= {file_size:#x}"))
                        .actual(format!("{declared:#x}")),
                ),
        );
    }
}

static IMAGE_SIZE: ImageSize = ImageSize;
static HEADERS_SIZE: HeadersSize = HeadersSize;
static FILE_ALIGNMENT: FileAlignment = FileAlignment;
static SECTION_ALIGNMENT: SectionAlignment = SectionAlignment;
static ENTRY_POINT: EntryPoint = EntryPoint;
static CHECKSUM: Checksum = Checksum;
static HEADERS_BEYOND_FILE: HeadersBeyondFile = HeadersBeyondFile;

/// Every optional header rule, in registry order.
pub(crate) static RULES: &[&dyn Rule] = &[
    &IMAGE_SIZE,
    &HEADERS_SIZE,
    &FILE_ALIGNMENT,
    &SECTION_ALIGNMENT,
    &ENTRY_POINT,
    &CHECKSUM,
    &HEADERS_BEYOND_FILE,
];

#[cfg(test)]
mod tests {
    use super::{
        Checksum, EntryPoint, FileAlignment, HeadersBeyondFile, HeadersSize, ImageSize,
        SectionAlignment,
    };
    use crate::analysis::rules::test_support;
    use crate::pe::optional;
    use crate::testutil::PeBuilder;

    fn patch_u32(builder: &mut PeBuilder, field: usize, value: u32) -> bool {
        let offset = builder.optional_offset() + field;
        builder.patch_u32(offset, value)
    }

    #[test]
    fn a_consistent_image_size_is_accepted() {
        let findings = test_support::run(&ImageSize, &PeBuilder::pe32());
        assert!(findings.is_empty());
    }

    #[test]
    fn a_wrong_image_size_is_a_finding() {
        let mut builder = PeBuilder::pe32();
        assert!(patch_u32(
            &mut builder,
            optional::SIZE_OF_IMAGE_OFFSET,
            0x1000
        ));

        let findings = test_support::run(&ImageSize, &builder);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn headers_covering_the_table_are_accepted() {
        let findings = test_support::run(&HeadersSize, &PeBuilder::pe32());
        assert!(findings.is_empty());
    }

    #[test]
    fn headers_shorter_than_the_table_are_a_finding() {
        let mut builder = PeBuilder::pe32();
        assert!(patch_u32(
            &mut builder,
            optional::SIZE_OF_HEADERS_OFFSET,
            0x100
        ));

        let findings = test_support::run(&HeadersSize, &builder);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn a_misaligned_size_of_headers_is_a_finding() {
        let mut builder = PeBuilder::pe32();
        assert!(patch_u32(
            &mut builder,
            optional::SIZE_OF_HEADERS_OFFSET,
            0x201
        ));

        let findings = test_support::run(&HeadersSize, &builder);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn the_default_file_alignment_is_accepted() {
        let findings = test_support::run(&FileAlignment, &PeBuilder::pe32());
        assert!(findings.is_empty());
    }

    #[test]
    fn a_non_power_of_two_file_alignment_is_a_finding() {
        let mut builder = PeBuilder::pe32();
        assert!(patch_u32(
            &mut builder,
            optional::FILE_ALIGNMENT_OFFSET,
            0x300
        ));

        let findings = test_support::run(&FileAlignment, &builder);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn a_low_alignment_image_is_accepted() {
        let mut builder = PeBuilder::pe32();
        assert!(patch_u32(
            &mut builder,
            optional::SECTION_ALIGNMENT_OFFSET,
            0x20
        ));
        assert!(patch_u32(
            &mut builder,
            optional::FILE_ALIGNMENT_OFFSET,
            0x20
        ));

        let findings = test_support::run(&FileAlignment, &builder);
        assert!(findings.is_empty());
    }

    #[test]
    fn the_default_section_alignment_is_accepted() {
        let findings = test_support::run(&SectionAlignment, &PeBuilder::pe32());
        assert!(findings.is_empty());
    }

    #[test]
    fn a_section_alignment_below_the_file_alignment_is_a_finding() {
        let mut builder = PeBuilder::pe32();
        assert!(patch_u32(
            &mut builder,
            optional::SECTION_ALIGNMENT_OFFSET,
            0x100
        ));
        assert!(patch_u32(
            &mut builder,
            optional::FILE_ALIGNMENT_OFFSET,
            0x200
        ));

        let findings = test_support::run(&SectionAlignment, &builder);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn an_entry_point_inside_text_is_accepted() {
        let findings = test_support::run(&EntryPoint, &PeBuilder::pe32());
        assert!(findings.is_empty());
    }

    #[test]
    fn an_entry_point_outside_every_section_is_a_finding() {
        let mut builder = PeBuilder::pe32();
        assert!(patch_u32(
            &mut builder,
            optional::ADDRESS_OF_ENTRY_POINT_OFFSET,
            0x9000
        ));

        let findings = test_support::run(&EntryPoint, &builder);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn an_empty_entry_point_is_allowed_in_a_dll() {
        let mut builder = PeBuilder::pe32();
        assert!(patch_u32(
            &mut builder,
            optional::ADDRESS_OF_ENTRY_POINT_OFFSET,
            0
        ));
        assert!(builder.patch_u16(
            builder.coff_offset() + crate::pe::coff::CHARACTERISTICS_OFFSET,
            crate::pe::coff::FILE_DLL | crate::pe::coff::FILE_EXECUTABLE_IMAGE
        ));

        let findings = test_support::run(&EntryPoint, &builder);
        assert!(findings.is_empty());
    }

    #[test]
    fn an_empty_entry_point_in_a_native_executable_is_a_finding() {
        let mut builder = PeBuilder::pe32();
        assert!(patch_u32(
            &mut builder,
            optional::ADDRESS_OF_ENTRY_POINT_OFFSET,
            0
        ));

        let findings = test_support::run(&EntryPoint, &builder);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn an_empty_entry_point_is_allowed_in_a_managed_image() {
        let mut builder = PeBuilder::pe32();
        assert!(patch_u32(
            &mut builder,
            optional::ADDRESS_OF_ENTRY_POINT_OFFSET,
            0
        ));

        // `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR` is entry 14, eight bytes each.
        let com = builder.directories_offset()
            + crate::spec::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR as usize * 8;
        assert!(builder.patch_u32(com, 0x2000));
        assert!(builder.patch_u32(com + 4, 0x48));

        let findings = test_support::run(&EntryPoint, &builder);
        assert!(findings.is_empty());
    }

    #[test]
    fn a_zero_checksum_is_not_a_finding() {
        let findings = test_support::run(&Checksum, &PeBuilder::pe32());
        assert!(findings.is_empty());
    }

    #[test]
    fn a_wrong_checksum_is_a_finding() {
        let mut builder = PeBuilder::pe32();
        assert!(patch_u32(&mut builder, optional::CHECKSUM_OFFSET, 0x1234));

        let findings = test_support::run(&Checksum, &builder);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn headers_inside_the_file_are_accepted() {
        let findings = test_support::run(&HeadersBeyondFile, &PeBuilder::pe32());
        assert!(findings.is_empty());
    }

    #[test]
    fn headers_beyond_the_file_are_a_finding() {
        let mut builder = PeBuilder::pe32();
        assert!(patch_u32(
            &mut builder,
            optional::SIZE_OF_HEADERS_OFFSET,
            0x10000
        ));

        let findings = test_support::run(&HeadersBeyondFile, &builder);
        assert_eq!(findings.len(), 1);
    }
}
