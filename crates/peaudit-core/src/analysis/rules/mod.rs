//! The rules that ship with `peaudit`.
//!
//! Each module covers one structure: COFF header, optional header, section
//! table. Rules are independent functions over [`crate::analysis::rule::AnalysisContext`]
//! and never read each other's output.
//!
//! A rule must not repeat a parser diagnostic (ADR-0005). Conditions the parser
//! already reports — a missing `MZ`, a mismatched optional header size, an
//! unknown magic, more than sixteen data directories — are therefore not
//! implemented as rules, even though `materials/rules_catalog.md` lists them.

pub mod coff;
pub mod optional;
pub mod section;

use crate::analysis::registry;
use crate::pe::SectionHeader;

/// The normative description of the PE format.
pub const PE_SPEC: &str = "https://learn.microsoft.com/windows/win32/debug/pe-format";

/// Returns the virtual span a section occupies once mapped.
///
/// The loader maps `max(VirtualSize, SizeOfRawData)` bytes, so an RVA in the
/// raw-only tail is still reachable even when `VirtualSize` is smaller. Rules
/// that judge reachability or overlap must use this span, not `VirtualSize`
/// alone, or they would contradict [`crate::pe::RvaStrategy::Loader`].
pub(crate) fn mapped_span(section: &SectionHeader) -> (u64, u64) {
    let start = u64::from(section.virtual_address);
    let size = u64::from(section.virtual_size.max(section.size_of_raw_data));
    (start, start.saturating_add(size))
}

/// Renders `docs/rules.md`.
///
/// The output is a pure function of the rule registry, which makes it testable:
/// the repository keeps the generated file under version control and a test
/// fails when it drifts from [`markdown`].
#[must_use]
pub fn markdown() -> String {
    use core::fmt::Write as _;

    let rules = registry::rules();
    let mut out = String::new();

    out.push_str("# Правила `peaudit`\n\n");
    out.push_str(
        "> Файл сгенерирован командой `cargo xtask rules-doc`. \
         Не редактировать вручную.\n\
         > Источник — `RuleMeta` каждого правила в \
         `crates/peaudit-core/src/analysis/rules/`.\n\
         > Каталог-бэклог (что ещё планируется) — `materials/rules_catalog.md`.\n\n",
    );
    let _ = writeln!(out, "Всего правил: {}.\n", rules.len());

    out.push_str("| ID | Severity | Confidence | Profiles | Правило |\n");
    out.push_str("|---|---|---|---|---|\n");
    for rule in rules {
        let meta = rule.meta();
        let profiles = meta
            .profiles
            .iter()
            .map(|profile| profile.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} | {} |",
            meta.id,
            meta.severity.as_str(),
            meta.confidence.as_str(),
            profiles,
            meta.title
        );
    }

    for rule in rules {
        let meta = rule.meta();
        out.push('\n');
        let _ = writeln!(out, "## {} — {}", meta.id, meta.title);
        out.push('\n');
        let _ = writeln!(out, "- **Severity:** {}", meta.severity.as_str());
        let _ = writeln!(out, "- **Confidence:** {}", meta.confidence.as_str());
        let _ = writeln!(out, "- **Category:** {}", meta.category.as_str());
        let _ = writeln!(out, "- **Since:** {}", meta.since);
        if !meta.references.is_empty() {
            let _ = writeln!(out, "- **References:** {}", meta.references.join(", "));
        }
        out.push('\n');
        out.push_str(meta.description);
        out.push('\n');
    }

    out
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::analysis::rule::{AnalysisContext, Findings, Rule};
    use crate::derived::Derived;
    use crate::limits::Limits;
    use crate::pe::PeFile;
    use crate::testutil::PeBuilder;

    /// Runs one rule over a builder fixture.
    pub fn run(rule: &dyn Rule, builder: &PeBuilder) -> Findings {
        run_bytes(rule, builder.bytes())
    }

    /// Runs one rule over raw bytes.
    pub fn run_bytes(rule: &dyn Rule, bytes: &[u8]) -> Findings {
        let file = PeFile::parse(bytes, &Limits::default());
        let derived = Derived::compute(bytes, &file);
        let ctx = AnalysisContext {
            data: bytes,
            file: &file,
            derived: &derived,
        };
        let mut out = Findings::new();
        rule.evaluate(&ctx, &mut out);
        out
    }
}
