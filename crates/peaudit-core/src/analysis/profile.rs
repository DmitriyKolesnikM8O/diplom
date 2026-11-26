//! The three semantic profiles (ADR-0004).
//!
//! A profile is not a strictness level: it is a different question asked about
//! the same file. A rule declares the profiles in which its finding is
//! meaningful, and the report always contains all three verdicts.
//!
//! The sets below exist so that a rule's `RuleMeta` can say `SPEC_LOADER` and
//! stay a constant expression.

use serde::Serialize;

/// One question a report answers about a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// Does the file conform to the Microsoft PE/COFF specification?
    Spec,
    /// Will the Windows loader accept it and run it without failing?
    Loader,
    /// Are there structural signs of deliberate manipulation or concealment?
    Security,
}

impl Profile {
    /// Every profile, in report order.
    pub const ALL: [Self; 3] = [Self::Spec, Self::Loader, Self::Security];

    /// Returns the stable machine-readable name of this profile.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Spec => "spec",
            Self::Loader => "loader",
            Self::Security => "security",
        }
    }
}

impl core::fmt::Display for Profile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `spec`, `loader` and `security`.
pub const SPEC_LOADER_SECURITY: &[Profile] = &[Profile::Spec, Profile::Loader, Profile::Security];
/// `spec` and `loader`.
pub const SPEC_LOADER: &[Profile] = &[Profile::Spec, Profile::Loader];
/// `spec` and `security`.
pub const SPEC_SECURITY: &[Profile] = &[Profile::Spec, Profile::Security];
/// `spec` only.
pub const SPEC_ONLY: &[Profile] = &[Profile::Spec];
/// `security` only.
pub const SECURITY_ONLY: &[Profile] = &[Profile::Security];
