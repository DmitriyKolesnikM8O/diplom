//! The rule interface.
//!
//! A rule is data plus a pure function: it reads [`AnalysisContext`] and pushes
//! findings, nothing else. No I/O, no global state, no dependence on other
//! rules, so the result does not depend on evaluation order and a single rule
//! can be tested in isolation.
//!
//! Rules do not duplicate parser diagnostics (ADR-0005). If the parser already
//! reported a condition — a truncated table, an unknown magic — the rule is not
//! written, because two messages about one event are worse than one.

use crate::derived::Derived;
use crate::pe::PeFile;

use super::finding::{Category, Confidence, Evidence, Finding, Severity};
use super::profile::Profile;

/// Static description of a rule.
///
/// Kept `Copy` and allocation-free: a registry of rules must not allocate, and
/// a report must be able to read metadata without cloning.
#[derive(Debug, Clone, Copy)]
pub struct RuleMeta {
    /// Stable identifier such as `PE-OPT-002`.
    pub id: &'static str,
    /// Short title, used as a heading in `docs/rules.md` and in a finding.
    pub title: &'static str,
    /// One-paragraph explanation of what the rule checks and why it matters.
    pub description: &'static str,
    /// Severity of the finding this rule produces.
    pub severity: Severity,
    /// Confidence of this rule.
    pub confidence: Confidence,
    /// Structure the rule inspects.
    pub category: Category,
    /// Scoring family: related findings are capped together.
    pub family: &'static str,
    /// Profiles in which this finding counts.
    pub profiles: &'static [Profile],
    /// Specification or article that justifies the rule.
    pub references: &'static [&'static str],
    /// Version in which the rule first appeared.
    pub since: &'static str,
}

impl RuleMeta {
    /// Creates a finding carrying this rule's metadata.
    ///
    /// The caller only supplies the message and the evidence; the identity and
    /// the judgement cannot drift from the metadata.
    #[must_use]
    pub fn finding(&self, message: impl Into<String>) -> Finding {
        Finding {
            id: self.id,
            title: self.title,
            severity: self.severity,
            confidence: self.confidence,
            category: self.category,
            family: self.family,
            profiles: self.profiles,
            message: message.into(),
            evidence: Vec::new(),
            references: self.references,
        }
    }
}

/// Everything a rule may read.
///
/// The data, the parsed model and the derived values are borrowed together:
/// a rule cannot accidentally inspect a buffer different from the one that was
/// parsed, and cannot recompute a value that derivation already produced.
#[derive(Debug, Clone, Copy)]
pub struct AnalysisContext<'a> {
    /// The input bytes.
    pub data: &'a [u8],
    /// The parsed model.
    pub file: &'a PeFile,
    /// Values computed from the model and the bytes.
    pub derived: &'a Derived,
}

/// A structural check over a parsed PE image.
///
/// The trait is `Sync` because the registry stores rules in a `static` and the
/// analyzer may run on several threads. A rule is stateless by construction, so
/// the bound costs nothing.
pub trait Rule: Sync {
    /// Returns the static description of this rule.
    fn meta(&self) -> &'static RuleMeta;

    /// Appends this rule's findings to `out`.
    ///
    /// Implementations must not panic on hostile input: every access goes
    /// through the parsed model, which is already bounded.
    fn evaluate(&self, ctx: &AnalysisContext<'_>, out: &mut Findings);
}

/// Findings collected from all rules.
///
/// The collection rejects exact duplicates: a rule that walks a table must not
/// report the same message twice, and a bug in a loop must not inflate the
/// score. Duplicates are identified by rule id and message, so a rule that
/// reports several sections still reports each one — as long as the message
/// names the instance (the section rules include the table index for exactly
/// this reason).
#[derive(Debug, Default, Clone)]
pub struct Findings {
    items: Vec<Finding>,
}

impl Findings {
    /// Creates an empty collection.
    #[must_use]
    pub const fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Adds a finding unless an identical one is already present.
    pub fn push(&mut self, finding: Finding) {
        let duplicate = self
            .items
            .iter()
            .any(|existing| existing.id == finding.id && existing.message == finding.message);
        if !duplicate {
            self.items.push(finding);
        }
    }

    /// Returns the findings in insertion order.
    #[must_use]
    pub fn as_slice(&self) -> &[Finding] {
        &self.items
    }

    /// Returns the number of findings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns `true` if no rule fired.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Returns an iterator over the findings.
    pub fn iter(&self) -> core::slice::Iter<'_, Finding> {
        self.items.iter()
    }

    /// Consumes the collection, returning findings sorted for a report.
    ///
    /// The order is severity descending, then rule id, then message. The message
    /// is the final tie-breaker because one rule legitimately reports several
    /// sections and the report must still be byte-identical between runs.
    #[must_use]
    pub fn into_sorted(self) -> Vec<Finding> {
        let mut items = self.items;
        items.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.id.cmp(b.id))
                .then_with(|| a.message.cmp(&b.message))
        });
        items
    }
}

impl<'a> IntoIterator for &'a Findings {
    type Item = &'a Finding;
    type IntoIter = core::slice::Iter<'a, Finding>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Shorthand for building evidence in a rule.
#[must_use]
pub fn field(name: &'static str) -> Evidence {
    Evidence::field(name)
}
