//! Scoring model.
//!
//! The score is a triage aid, not a verdict: it summarises how much of the
//! file's structure disagrees with the specification or looks like
//! manipulation. The recipe is deliberately small and stable, because a number
//! nobody can reproduce is worse than no number at all.
//!
//! ```text
//! weight:      info = 0, low = 1, medium = 4, high = 10, critical = 20
//! confidence:  low = 0.5, medium = 0.75, high = 1.0
//! points     = Σ weight(severity) × confidence, per scoring family, capped
//! score      = min(100, Σ capped family points)
//! ```
//!
//! The family cap stops one broken structure from dominating the score:
//! twenty sections beyond the end of the file are one problem, not twenty.
//! Points are multiples of 0.25, so every sum is exact in binary floating point
//! and the rounding to an integer is deterministic.

use serde::Serialize;

use super::finding::Finding;
use super::profile::Profile;

/// Maximum contribution of one scoring family.
pub const FAMILY_CAP: f64 = 25.0;

/// Maximum total score.
pub const MAX_SCORE: f64 = 100.0;

/// Coarse interpretation of a score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Nothing found.
    Clean,
    /// 1–9: notes and minor deviations.
    Notice,
    /// 10–29: low-risk deviations.
    Low,
    /// 30–59: worth a closer look.
    Suspicious,
    /// 60–84: strong structural anomalies.
    High,
    /// 85–100: the file is barely usable or actively hides its structure.
    Critical,
}

impl Level {
    /// Maps a rounded score to a level.
    #[must_use]
    pub const fn from_score(score: u32) -> Self {
        match score {
            0 => Self::Clean,
            1..=9 => Self::Notice,
            10..=29 => Self::Low,
            30..=59 => Self::Suspicious,
            60..=84 => Self::High,
            _ => Self::Critical,
        }
    }

    /// Returns the stable machine-readable name of this level.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Notice => "notice",
            Self::Low => "low",
            Self::Suspicious => "suspicious",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl core::fmt::Display for Level {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Score and level for one profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Verdict {
    /// Total score, `0..=100`.
    pub score: u32,
    /// Coarse interpretation of [`Verdict::score`].
    pub level: Level,
}

impl Verdict {
    /// Computes the verdict for `profile` from `findings`.
    #[must_use]
    pub fn compute(profile: Profile, findings: &[Finding]) -> Self {
        let mut families: Vec<(&'static str, f64)> = Vec::new();

        for finding in findings {
            if !finding.profiles.contains(&profile) {
                continue;
            }
            let points = f64::from(finding.severity.weight()) * finding.confidence.factor();
            match families
                .iter_mut()
                .find(|(family, _)| *family == finding.family)
            {
                Some((_, total)) => *total += points,
                None => families.push((finding.family, points)),
            }
        }

        // Score must not depend on the order in which rules ran.
        families.sort_by_key(|(family, _)| *family);

        let mut total = 0.0;
        for (_, points) in families {
            total += points.min(FAMILY_CAP);
        }

        let score = total.min(MAX_SCORE).round() as u32;
        Self {
            score,
            level: Level::from_score(score),
        }
    }
}

/// The three independent verdicts a report always contains.
///
/// They are computed from the same findings but answer different questions
/// (ADR-0004), so they legitimately differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Verdicts {
    /// Conformance to the PE/COFF specification.
    pub spec: Verdict,
    /// Will the Windows loader accept and run the file.
    pub loader: Verdict,
    /// Structural signs of manipulation or concealment.
    pub security: Verdict,
}

impl Verdicts {
    /// Computes all three verdicts from `findings`.
    #[must_use]
    pub fn compute(findings: &[Finding]) -> Self {
        Self {
            spec: Verdict::compute(Profile::Spec, findings),
            loader: Verdict::compute(Profile::Loader, findings),
            security: Verdict::compute(Profile::Security, findings),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FAMILY_CAP, Level, Verdicts};
    use crate::analysis::finding::{Category, Confidence, Finding, Severity};
    use crate::analysis::profile::{Profile, SECURITY_ONLY, SPEC_ONLY};

    fn finding(
        id: &'static str,
        severity: Severity,
        confidence: Confidence,
        family: &'static str,
        profiles: &'static [Profile],
        message: &'static str,
    ) -> Finding {
        Finding {
            id,
            title: "test",
            severity,
            confidence,
            category: Category::Section,
            family,
            profiles,
            message: message.to_owned(),
            evidence: Vec::new(),
            references: &[],
        }
    }

    #[test]
    fn clean_when_no_findings_apply() {
        let verdicts = Verdicts::compute(&[]);
        assert_eq!(verdicts.spec.score, 0);
        assert_eq!(verdicts.spec.level, Level::Clean);
        assert_eq!(verdicts.loader.level, Level::Clean);
        assert_eq!(verdicts.security.level, Level::Clean);
    }

    #[test]
    fn level_boundaries_are_stable() {
        assert_eq!(Level::from_score(0), Level::Clean);
        assert_eq!(Level::from_score(1), Level::Notice);
        assert_eq!(Level::from_score(9), Level::Notice);
        assert_eq!(Level::from_score(10), Level::Low);
        assert_eq!(Level::from_score(29), Level::Low);
        assert_eq!(Level::from_score(30), Level::Suspicious);
        assert_eq!(Level::from_score(59), Level::Suspicious);
        assert_eq!(Level::from_score(60), Level::High);
        assert_eq!(Level::from_score(84), Level::High);
        assert_eq!(Level::from_score(85), Level::Critical);
        assert_eq!(Level::from_score(100), Level::Critical);
    }

    #[test]
    fn confidence_scales_the_weight() {
        let high = finding(
            "PE-SEC-001",
            Severity::High,
            Confidence::High,
            "family",
            SECURITY_ONLY,
            "a",
        );
        let medium = finding(
            "PE-SEC-002",
            Severity::High,
            Confidence::Medium,
            "family",
            SECURITY_ONLY,
            "b",
        );

        assert_eq!(Verdicts::compute(&[high]).security.score, 10);
        assert_eq!(Verdicts::compute(&[medium]).security.score, 8);
    }

    #[test]
    fn info_contributes_nothing() {
        let info = finding(
            "PE-SEC-010",
            Severity::Info,
            Confidence::High,
            "notes",
            SECURITY_ONLY,
            "a",
        );

        assert_eq!(Verdicts::compute(&[info]).security.score, 0);
    }

    #[test]
    fn a_family_is_capped() {
        let findings: Vec<_> = (0..5)
            .map(|index| {
                finding(
                    "PE-SEC-001",
                    Severity::Critical,
                    Confidence::High,
                    "raw-bounds",
                    SECURITY_ONLY,
                    Box::leak(format!("message {index}").into_boxed_str()),
                )
            })
            .collect();

        let verdict = Verdicts::compute(&findings).security;
        assert_eq!(verdict.score, FAMILY_CAP as u32);
        assert_eq!(verdict.level, Level::Low);
    }

    #[test]
    fn the_total_is_capped_at_one_hundred() {
        let families = ["a", "b", "c", "d", "e"];
        let findings: Vec<_> = families
            .iter()
            .enumerate()
            .map(|(index, family)| {
                finding(
                    "PE-SEC-001",
                    Severity::Critical,
                    Confidence::High,
                    family,
                    SECURITY_ONLY,
                    Box::leak(format!("message {index}").into_boxed_str()),
                )
            })
            .collect();

        assert_eq!(Verdicts::compute(&findings).security.score, 100);
    }

    #[test]
    fn profiles_are_independent() {
        let spec = finding(
            "PE-OPT-003",
            Severity::High,
            Confidence::High,
            "layout",
            SPEC_ONLY,
            "a",
        );

        let verdicts = Verdicts::compute(&[spec]);
        assert_eq!(verdicts.spec.score, 10);
        assert_eq!(verdicts.loader.score, 0);
        assert_eq!(verdicts.security.score, 0);
    }
}
