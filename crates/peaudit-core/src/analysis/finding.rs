//! What a rule reports.
//!
//! A finding is deliberately explicit: it names the rule, the field, the
//! expected and the actual value. A report is supposed to be checkable by hand
//! without re-running the analyzer, so every finding carries enough evidence to
//! reproduce the judgement at the byte level.
//!
//! Severity and confidence are separate on purpose. Severity answers "how bad
//! is this if true", confidence answers "how sure are we that it is true".
//! A heuristic can be high-severity and still contribute little to the score
//! (see [`crate::analysis::scoring`]).

use core::fmt;

use serde::Serialize;

use crate::analysis::profile::Profile;

/// How much attention a finding deserves.
///
/// The ordering is meaningful: `Info < Low < Medium < High < Critical`, so a
/// collection can be filtered with `severity >= Severity::High`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// A note; no conformance or security consequence.
    Info,
    /// A minor deviation or a weak signal.
    Low,
    /// A deviation that requires interpretation.
    Medium,
    /// A clear violation or a strong signal of deliberate manipulation.
    High,
    /// A violation that makes the file unusable or hides the real structure.
    Critical,
}

impl Severity {
    /// Returns the stable machine-readable name of this severity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Returns the scoring weight of this severity.
    ///
    /// `Info` weighs nothing: a note must never move the score.
    #[must_use]
    pub const fn weight(self) -> u32 {
        match self {
            Self::Info => 0,
            Self::Low => 1,
            Self::Medium => 4,
            Self::High => 10,
            Self::Critical => 20,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How sure a rule is about a finding.
///
/// `High` is a deterministic check on parsed fields, `Medium` depends on an
/// interpretation of the specification, `Low` is a heuristic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// A heuristic; the finding may be a false positive.
    Low,
    /// A defensible interpretation, but not fixed by the specification.
    Medium,
    /// A deterministic check on parsed values.
    High,
}

impl Confidence {
    /// Returns the stable machine-readable name of this confidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    /// Returns the scoring factor applied to a finding's weight.
    #[must_use]
    pub const fn factor(self) -> f64 {
        match self {
            Self::Low => 0.5,
            Self::Medium => 0.75,
            Self::High => 1.0,
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The part of the PE structure a finding belongs to.
///
/// The category is also the default scoring family: findings about the same
/// structure are related and must not be counted as independent events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    /// DOS header and the location of the PE signature.
    Dos,
    /// COFF file header.
    Coff,
    /// Optional header and data directories.
    #[serde(rename = "optional")]
    OptionalHeader,
    /// Section table and section contents.
    Section,
}

impl Category {
    /// Returns the stable machine-readable name of this category.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dos => "dos",
            Self::Coff => "coff",
            Self::OptionalHeader => "optional",
            Self::Section => "section",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One reproducible fact behind a finding.
///
/// `expected` and `actual` are strings rather than numbers because a rule may
/// compare values of different kinds ("power of two", "PE32", "inside the
/// file"). The offset is a file offset, not an RVA, so the bytes can be checked
/// with any hex editor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Evidence {
    /// Name of the field, for example `optional.sizeOfImage`.
    pub field: &'static str,
    /// File offset of the field, when the finding is tied to one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// What the specification requires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    /// What the file declares.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
}

impl Evidence {
    /// Creates evidence for `field`.
    #[must_use]
    pub const fn field(field: &'static str) -> Self {
        Self {
            field,
            offset: None,
            expected: None,
            actual: None,
        }
    }

    /// Attaches the file offset of the field.
    #[must_use]
    pub const fn at(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Attaches the value required by the specification.
    #[must_use]
    pub fn expected(mut self, expected: impl Into<String>) -> Self {
        self.expected = Some(expected.into());
        self
    }

    /// Attaches the value found in the file.
    #[must_use]
    pub fn actual(mut self, actual: impl Into<String>) -> Self {
        self.actual = Some(actual.into());
        self
    }
}

/// One rule hit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Stable rule identifier such as `PE-SEC-007`.
    pub id: &'static str,
    /// Short human-readable title of the rule.
    pub title: &'static str,
    /// How bad the finding is if true.
    pub severity: Severity,
    /// How sure the rule is.
    pub confidence: Confidence,
    /// Structure the finding belongs to.
    pub category: Category,
    /// Scoring family, used to cap related findings.
    ///
    /// Not serialized: it is an implementation detail of the scoring model,
    /// not part of the report contract.
    #[serde(skip)]
    pub family: &'static str,
    /// Profiles that count this finding.
    pub profiles: &'static [Profile],
    /// What exactly was found, with the observed values.
    pub message: String,
    /// Reproducible facts behind the message.
    pub evidence: Vec<Evidence>,
    /// Specification or article that justifies the rule.
    pub references: &'static [&'static str],
}

impl Finding {
    /// Attaches one more piece of evidence.
    #[must_use]
    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }
}
