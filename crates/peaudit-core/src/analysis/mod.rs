//! The analysis pipeline: model → rules → verdicts → report.
//!
//! [`analyze`] is the whole tool in one function: it parses, derives, runs every
//! registered rule, sorts the findings and builds the [`Report`]. The CLI is
//! then only argument parsing and output formatting, and the FFI layer is only
//! a C wrapper around the same call.

pub mod finding;
pub mod profile;
pub mod registry;
pub mod rule;
pub mod rules;
pub mod scoring;

use crate::derived::Derived;
use crate::hash::HashSelection;
use crate::limits::Limits;
use crate::pe::{ParseState, PeFile};
use crate::report::Report;

use self::rule::{AnalysisContext, Findings, Rule};
use self::scoring::Verdicts;

/// Options for one analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisOptions {
    /// Safety caps applied while parsing.
    pub limits: Limits,
    /// Which digests to compute for the report.
    pub hashes: HashSelection,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            hashes: HashSelection::SHA256_ONLY,
        }
    }
}

/// Analyzes `data` with the default rule set.
///
/// This function never fails: a file that cannot be parsed produces a report
/// with `parse.status == "failed"` and `verdicts == null`, which is more useful
/// than an error, because it still tells the caller what was found before the
/// parse gave up.
#[must_use]
pub fn analyze(data: &[u8], options: &AnalysisOptions) -> Report {
    analyze_with(data, options, registry::rules())
}

/// Analyzes `data` with an explicit rule list.
///
/// Used by unit tests that exercise a single rule end to end and by callers
/// that want a subset. The rule order only affects the order findings are
/// produced in; [`Report::findings`] is always sorted, so the output does not
/// depend on it.
#[must_use]
pub fn analyze_with(data: &[u8], options: &AnalysisOptions, rules: &[&dyn Rule]) -> Report {
    let file = PeFile::parse(data, &options.limits);
    let derived = Derived::compute(data, &file);

    let context = AnalysisContext {
        data,
        file: &file,
        derived: &derived,
    };

    let mut collected = Findings::new();
    for rule in rules {
        rule.evaluate(&context, &mut collected);
    }
    let findings = collected.into_sorted();

    // A file without a DOS or COFF header is not a PE image: there is nothing
    // to conform to and nothing to hide, so three zero scores would be a lie.
    let verdicts = match file.state() {
        ParseState::Failed => None,
        ParseState::Partial | ParseState::Complete => Some(Verdicts::compute(&findings)),
    };

    Report::build(
        data,
        &file,
        &derived,
        &options.limits,
        options.hashes,
        findings,
        verdicts,
    )
}
