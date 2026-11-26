//! Rules over the COFF file header.
//!
//! The COFF header is small and every field is load-bearing: the section count
//! bounds the table, `Machine` selects the architecture and the optional header
//! layout. A value that disagrees with the rest of the file is a classic
//! parser-differential trigger — two tools can disagree on where the section
//! table starts.

use crate::analysis::finding::{Category, Confidence, Severity};
use crate::analysis::profile::SPEC_LOADER_SECURITY;
use crate::analysis::rule::{AnalysisContext, Findings, Rule, RuleMeta, field};
use crate::pe::coff::{
    self, MACHINE_AMD64, MACHINE_ARM64, MACHINE_ARMNT, MACHINE_I386, MACHINE_IA64, MACHINE_RISCV32,
    MACHINE_RISCV64,
};
use crate::spec;

use super::PE_SPEC;

/// `PE-COFF-001`: the declared section count is outside the range the
/// specification allows.
pub struct SectionCount;

impl SectionCount {
    const META: RuleMeta = RuleMeta {
        id: "PE-COFF-001",
        title: "Аномальное число секций",
        description: "Спецификация требует хотя бы одну секцию и допускает не более 96. \
                      Ноль секций означает, что загрузчику нечего отображать, а число \
                      больше 96 не поддерживает ни загрузчик, ни таблица секций: разные \
                      парсеры читают разное количество записей, и структура файла \
                      перестаёт быть однозначной.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: Category::Coff,
        family: "coff-section-count",
        profiles: SPEC_LOADER_SECURITY,
        references: &[PE_SPEC, "materials/rules_catalog.md"],
        since: "0.1.0",
    };
}

impl Rule for SectionCount {
    fn meta(&self) -> &'static RuleMeta {
        &Self::META
    }

    fn evaluate(&self, ctx: &AnalysisContext<'_>, out: &mut Findings) {
        let Some(header) = ctx.file.coff else {
            return;
        };
        let declared = usize::from(header.number_of_sections);
        if (spec::MIN_SECTIONS..=spec::MAX_SECTIONS).contains(&declared) {
            return;
        }

        let evidence = field("coff.numberOfSections")
            .at((header
                .offset
                .saturating_add(coff::NUMBER_OF_SECTIONS_OFFSET)) as u64)
            .expected(format!("{}..={}", spec::MIN_SECTIONS, spec::MAX_SECTIONS))
            .actual(declared.to_string());

        out.push(
            Self::META
                .finding(format!(
                    "Объявлено {declared} секций: спецификация допускает от {} до {}",
                    spec::MIN_SECTIONS,
                    spec::MAX_SECTIONS
                ))
                .with_evidence(evidence),
        );
    }
}

/// `PE-COFF-003`: `Machine` and the optional header magic describe different
/// architectures.
pub struct MachineMagic;

impl MachineMagic {
    const META: RuleMeta = RuleMeta {
        id: "PE-COFF-003",
        title: "Machine не соответствует magic",
        description: "Поле Machine задаёт архитектуру, а magic необязательного заголовка — \
                      разрядность и раскладку полей. Их расхождение (например, amd64 с PE32) \
                      означает, что часть полей прочитана по чужой раскладке: загрузчик и \
                      сторонний парсер увидят разные значения одной и той же структуры.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: Category::Coff,
        family: "coff-machine-magic",
        profiles: SPEC_LOADER_SECURITY,
        references: &[PE_SPEC, "materials/rules_catalog.md"],
        since: "0.1.0",
    };
}

/// Returns `true` when `machine` requires a `PE32+` header.
///
/// [`None`] for machines whose width is not fixed here (unknown values, EBC):
/// the rule must stay silent rather than guess.
fn requires_pe32plus(machine: u16) -> Option<bool> {
    match machine {
        MACHINE_I386 | MACHINE_ARMNT | MACHINE_RISCV32 => Some(false),
        MACHINE_AMD64 | MACHINE_ARM64 | MACHINE_IA64 | MACHINE_RISCV64 => Some(true),
        _ => None,
    }
}

impl Rule for MachineMagic {
    fn meta(&self) -> &'static RuleMeta {
        &Self::META
    }

    fn evaluate(&self, ctx: &AnalysisContext<'_>, out: &mut Findings) {
        let (Some(header), Some(optional)) = (ctx.file.coff, ctx.file.optional) else {
            return;
        };
        let Some(expected_plus) = requires_pe32plus(header.machine) else {
            return;
        };
        if expected_plus == optional.is_pe32_plus() {
            return;
        }

        let layout = if expected_plus { "PE32+" } else { "PE32" };
        let actual_layout = if optional.is_pe32_plus() {
            "PE32+"
        } else {
            "PE32"
        };
        let machine = header.machine_name().unwrap_or("unknown");

        out.push(
            Self::META
                .finding(format!(
                    "Machine {machine} требует {layout}, а заголовок объявлен как {actual_layout}"
                ))
                .with_evidence(
                    field("coff.machine")
                        .at(header.offset as u64)
                        .expected(layout)
                        .actual(format!("{machine} ({:#06x})", header.machine)),
                )
                .with_evidence(
                    field("optional.magic")
                        .at(optional.offset as u64)
                        .expected(layout)
                        .actual(format!("{actual_layout} ({:#06x})", optional.magic)),
                ),
        );
    }
}

static SECTION_COUNT: SectionCount = SectionCount;
static MACHINE_MAGIC: MachineMagic = MachineMagic;

/// Every COFF rule, in registry order.
pub(crate) static RULES: &[&dyn Rule] = &[&SECTION_COUNT, &MACHINE_MAGIC];

#[cfg(test)]
mod tests {
    use super::{MachineMagic, SectionCount};
    use crate::analysis::rules::test_support;
    use crate::pe::coff;
    use crate::testutil::PeBuilder;

    #[test]
    fn a_normal_section_count_is_accepted() {
        let findings = test_support::run(&SectionCount, &PeBuilder::pe32());
        assert!(findings.is_empty());
    }

    #[test]
    fn zero_sections_is_a_finding() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(builder.coff_offset() + coff::NUMBER_OF_SECTIONS_OFFSET, 0));

        let findings = test_support::run(&SectionCount, &builder);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings.as_slice().first().map(|f| f.id),
            Some("PE-COFF-001")
        );
    }

    #[test]
    fn ninety_seven_sections_is_a_finding() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(builder.coff_offset() + coff::NUMBER_OF_SECTIONS_OFFSET, 97));

        let findings = test_support::run(&SectionCount, &builder);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn a_matching_machine_and_magic_are_accepted() {
        let findings = test_support::run(&MachineMagic, &PeBuilder::pe32());
        assert!(findings.is_empty());

        let findings = test_support::run(&MachineMagic, &PeBuilder::pe32plus());
        assert!(findings.is_empty());
    }

    #[test]
    fn amd64_with_pe32_is_a_finding() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(builder.coff_offset(), coff::MACHINE_AMD64));

        let findings = test_support::run(&MachineMagic, &builder);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings.as_slice().first().map(|f| f.id),
            Some("PE-COFF-003")
        );
    }

    #[test]
    fn an_unknown_machine_is_not_judged() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(builder.coff_offset(), 0x7777));

        let findings = test_support::run(&MachineMagic, &builder);
        assert!(findings.is_empty());
    }
}
