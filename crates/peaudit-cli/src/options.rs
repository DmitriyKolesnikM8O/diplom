//! Analysis options assembled from the command line: the exit-code gate and
//! safety-limit overrides.

use peaudit_core::DiagSeverity;
use peaudit_core::analysis::finding::{Finding, Severity};
use peaudit_core::analysis::profile::Profile;
use peaudit_core::limits::Limits;
use peaudit_core::report::Report;

use crate::cli::{GateArgs, LimitsArgs};
use crate::error::CliError;

/// Decides whether a run is a failure.
#[derive(Debug, Clone, Copy)]
pub struct Gate {
    /// Profile whose findings are counted.
    pub profile: Profile,
    /// Minimum severity that fails the run; [`None`] disables the gate.
    pub threshold: Option<Severity>,
}

impl Gate {
    /// Builds the gate from the parsed flags.
    #[must_use]
    pub fn from_args(args: &GateArgs) -> Self {
        Self {
            profile: args.profile.into(),
            threshold: args.fail_on.threshold(),
        }
    }

    /// Returns `true` when a finding of the selected profile crosses the
    /// threshold.
    ///
    /// The gate works on the severity of a single finding, not on the score:
    /// a score depends on calibration, a severity does not (ADR-0004).
    #[must_use]
    pub fn fails(&self, findings: &[Finding]) -> bool {
        let Some(threshold) = self.threshold else {
            return false;
        };
        findings.iter().any(|finding| {
            finding.profiles.contains(&self.profile) && finding.severity >= threshold
        })
    }
}

/// Returns `true` when a parser diagnostic of severity `error` is present.
///
/// `--strict` turns such a diagnostic into a rejection: the parser had to make
/// a decision (stop early, skip a structure), so the file did not survive a
/// full parse (ADR-0003).
#[must_use]
pub fn has_error_diagnostic(report: &Report) -> bool {
    let error = DiagSeverity::Error.as_str();
    report
        .parse
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == error)
}

/// Names accepted by `--limit`, for the error message.
const LIMIT_KEYS: &str = "max-file-size, max-sections, max-imports, max-exports, \
                          max-resource-nodes, max-resource-depth, max-string-len, \
                          max-thunks-per-import, max-entropy-window";

/// Applies `--limit KEY=VALUE` overrides on top of the defaults.
pub fn limits_from(args: &LimitsArgs) -> Result<Limits, CliError> {
    let mut limits = Limits::default();

    for assignment in &args.limit {
        let Some((key, value)) = assignment.split_once('=') else {
            return Err(CliError::usage(format!(
                "limit must be KEY=VALUE, got `{assignment}`; known keys: {LIMIT_KEYS}"
            )));
        };
        let key = key.trim();
        let value = value.trim();

        match key {
            "max-file-size" => limits.max_file_size = number(value, key)?,
            "max-sections" => limits.max_sections = number(value, key)?,
            "max-imports" => limits.max_imports = number(value, key)?,
            "max-exports" => limits.max_exports = number(value, key)?,
            "max-resource-nodes" => limits.max_resource_nodes = number(value, key)?,
            "max-resource-depth" => limits.max_resource_depth = number(value, key)?,
            "max-string-len" => limits.max_string_len = number(value, key)?,
            "max-thunks-per-import" => limits.max_thunks_per_import = number(value, key)?,
            "max-entropy-window" => limits.max_entropy_window = number(value, key)?,
            other => {
                return Err(CliError::usage(format!(
                    "unknown limit `{other}`; known keys: {LIMIT_KEYS}"
                )));
            }
        }
    }

    Ok(limits)
}

fn number<T>(value: &str, key: &str) -> Result<T, CliError>
where
    T: std::str::FromStr,
{
    value.parse().map_err(|_| {
        CliError::usage(format!(
            "limit `{key}` expects a non-negative integer, got `{value}`"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::{Gate, limits_from};
    use crate::cli::LimitsArgs;
    use peaudit_core::analysis::finding::{Category, Confidence, Finding, Severity};
    use peaudit_core::analysis::profile::{Profile, SECURITY_ONLY, SPEC_ONLY};
    use peaudit_core::limits::Limits;

    fn finding(severity: Severity, profiles: &'static [Profile]) -> Finding {
        Finding {
            id: "PE-SEC-007",
            title: "test",
            severity,
            confidence: Confidence::High,
            category: Category::Section,
            family: "test",
            profiles,
            message: "m".to_owned(),
            evidence: Vec::new(),
            references: &[],
        }
    }

    fn gate(profile: Profile, threshold: Option<Severity>) -> Gate {
        Gate { profile, threshold }
    }

    #[test]
    fn a_gate_without_a_threshold_never_fails() {
        let findings = [finding(Severity::Critical, SECURITY_ONLY)];
        assert!(!gate(Profile::Security, None).fails(&findings));
    }

    #[test]
    fn the_threshold_is_inclusive() {
        let findings = [finding(Severity::High, SECURITY_ONLY)];
        assert!(gate(Profile::Security, Some(Severity::High)).fails(&findings));
        assert!(!gate(Profile::Security, Some(Severity::Critical)).fails(&findings));
    }

    #[test]
    fn findings_of_other_profiles_are_ignored() {
        let findings = [finding(Severity::High, SPEC_ONLY)];
        assert!(!gate(Profile::Security, Some(Severity::High)).fails(&findings));
        assert!(gate(Profile::Spec, Some(Severity::High)).fails(&findings));
    }

    #[test]
    fn limits_are_overridden_by_key() {
        let args = LimitsArgs {
            limit: vec!["max-file-size=1024".to_owned(), "max-sections=2".to_owned()],
        };
        let limits = limits_from(&args).expect("valid limits");
        assert_eq!(limits.max_file_size, 1024);
        assert_eq!(limits.max_sections, 2);
        // Untouched limits keep their defaults.
        assert_eq!(limits.max_imports, Limits::default().max_imports);
    }

    #[test]
    fn an_unknown_key_is_a_usage_error() {
        let args = LimitsArgs {
            limit: vec!["max-everything=1".to_owned()],
        };
        let error = limits_from(&args).expect_err("unknown key");
        assert_eq!(error.exit_code(), 2);
        assert!(error.to_string().contains("unknown limit"));
    }

    #[test]
    fn a_missing_equals_sign_is_a_usage_error() {
        let args = LimitsArgs {
            limit: vec!["max-sections".to_owned()],
        };
        let error = limits_from(&args).expect_err("malformed assignment");
        assert!(error.to_string().contains("KEY=VALUE"));
    }

    #[test]
    fn a_non_numeric_value_is_a_usage_error() {
        let args = LimitsArgs {
            limit: vec!["max-sections=many".to_owned()],
        };
        assert!(limits_from(&args).is_err());
    }
}
