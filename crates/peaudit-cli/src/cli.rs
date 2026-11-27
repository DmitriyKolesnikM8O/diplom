//! Command-line grammar.
//!
//! The grammar follows `materials/roadmap.md` §6 (phase 6). Every option that
//! affects analysis lives in a flattened group, so `scan` and `batch` accept the
//! same limits, hashes and gate options without duplicating definitions.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use peaudit_core::HashSelection;
use peaudit_core::analysis::finding::Severity;
use peaudit_core::analysis::profile::Profile;

/// Static analyzer for PE files.
#[derive(Debug, Parser)]
#[command(
    name = "peaudit",
    version,
    about = "Static analyzer for PE files",
    long_about = None,
    propagate_version = true
)]
pub struct Cli {
    /// Subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Analyze one file, or stdin when the path is `-`.
    Scan(ScanArgs),
    /// Analyze every PE file in a directory.
    Batch(BatchArgs),
    /// List the registered rules or explain one of them.
    Rules {
        /// Rule subcommand.
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// Print the JSON report schema.
    Schema(SchemaArgs),
    /// Print version information.
    Version,
}

/// `peaudit scan`.
#[derive(Debug, Args)]
pub struct ScanArgs {
    /// File to analyze, or `-` for stdin.
    #[arg(value_name = "FILE")]
    pub input: String,
    /// Print the full report as one JSON document.
    #[arg(long, conflicts_with = "jsonl")]
    pub json: bool,
    /// Print the report as one JSON line (the batch format).
    #[arg(long, conflicts_with = "json")]
    pub jsonl: bool,
    /// Indent the JSON document.
    #[arg(long, requires = "json")]
    pub pretty: bool,
    /// Hide findings below this severity in the human output.
    #[arg(long, value_enum, default_value_t = SeverityArg::Info)]
    pub min_severity: SeverityArg,
    /// Write the output to a file instead of stdout.
    #[arg(long, value_name = "FILE")]
    pub output: Option<String>,
    /// Which profile decides the exit code and the summary line.
    #[command(flatten)]
    pub gate: GateArgs,
    /// Which digests to compute.
    #[command(flatten)]
    pub hashes: HashArgs,
    /// Safety limits applied while parsing.
    #[command(flatten)]
    pub limits: LimitsArgs,
}

impl ScanArgs {
    /// Returns the output format selected by the flags.
    #[must_use]
    pub const fn format(&self) -> OutputFormat {
        if self.jsonl {
            OutputFormat::JsonLines
        } else if self.json {
            OutputFormat::Json {
                pretty: self.pretty,
            }
        } else {
            OutputFormat::Human
        }
    }
}

/// `peaudit batch`.
#[derive(Debug, Args)]
pub struct BatchArgs {
    /// Directory to scan.
    #[arg(value_name = "DIR")]
    pub directory: PathBuf,
    /// Recurse into subdirectories.
    #[arg(long)]
    pub recursive: bool,
    /// Worker threads; `0` selects the number of available CPUs.
    #[arg(long, default_value_t = 0)]
    pub jobs: usize,
    /// Print one JSON report per line instead of a human summary.
    #[arg(long)]
    pub jsonl: bool,
    /// Write the output to a file instead of stdout.
    #[arg(long, value_name = "FILE")]
    pub output: Option<String>,
    /// Scan every regular file, not only known PE extensions.
    #[arg(long)]
    pub all_files: bool,
    /// Which profile decides the exit code.
    #[command(flatten)]
    pub gate: GateArgs,
    /// Which digests to compute.
    #[command(flatten)]
    pub hashes: HashArgs,
    /// Safety limits applied while parsing.
    #[command(flatten)]
    pub limits: LimitsArgs,
}

/// `peaudit rules`.
#[derive(Debug, Subcommand)]
pub enum RulesCommand {
    /// List every registered rule.
    List {
        /// Print a JSON array instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Print the full description of one rule.
    Explain {
        /// Rule identifier such as `PE-SEC-007`.
        #[arg(value_name = "ID")]
        id: String,
    },
}

/// `peaudit schema`.
#[derive(Debug, Args)]
pub struct SchemaArgs {
    /// Write the schema to a file instead of stdout.
    #[arg(long, value_name = "FILE")]
    pub output: Option<String>,
}

/// Options that decide whether the run is a failure.
#[derive(Debug, Clone, Args)]
pub struct GateArgs {
    /// Profile whose findings are gated and summarised.
    #[arg(long, value_enum, default_value_t = ProfileArg::Security)]
    pub profile: ProfileArg,
    /// Exit with code 1 when a finding of this profile reaches this severity.
    #[arg(long, value_enum, default_value_t = FailOn::High)]
    pub fail_on: FailOn,
    /// Treat any `error` parser diagnostic as a rejection (exit code 1).
    #[arg(long)]
    pub strict: bool,
}

/// Which digests to compute.
#[derive(Debug, Clone, Args)]
pub struct HashArgs {
    /// Which file digests to compute.
    #[arg(long, value_enum, default_value_t = HashMode::Sha256)]
    pub hashes: HashMode,
    /// Skip all digests (faster, but the report loses the file identity).
    #[arg(long, conflicts_with = "hashes")]
    pub no_hashes: bool,
}

impl HashArgs {
    /// Resolves the flags into a [`HashSelection`].
    #[must_use]
    pub const fn selection(&self) -> HashSelection {
        if self.no_hashes {
            HashSelection::NONE
        } else {
            match self.hashes {
                HashMode::Sha256 => HashSelection::SHA256_ONLY,
                HashMode::All => HashSelection::ALL,
            }
        }
    }
}

/// `--limit KEY=VALUE`, repeatable.
#[derive(Debug, Clone, Args)]
pub struct LimitsArgs {
    /// Override one safety limit, for example `--limit max-sections=64`.
    #[arg(long = "limit", value_name = "KEY=VALUE")]
    pub limit: Vec<String>,
}

/// Digest selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum HashMode {
    /// SHA-256 only (default).
    Sha256,
    /// SHA-256, SHA-1 and MD5.
    All,
}

/// Output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Readable summary.
    Human,
    /// One JSON document.
    Json {
        /// Indent the document.
        pretty: bool,
    },
    /// One JSON document per line.
    JsonLines,
}

/// Profile argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProfileArg {
    /// Conformance to the specification.
    Spec,
    /// What the Windows loader does.
    Loader,
    /// Structural signs of manipulation.
    Security,
}

impl From<ProfileArg> for Profile {
    fn from(argument: ProfileArg) -> Self {
        match argument {
            ProfileArg::Spec => Self::Spec,
            ProfileArg::Loader => Self::Loader,
            ProfileArg::Security => Self::Security,
        }
    }
}

/// Exit-code threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailOn {
    /// Any finding.
    Info,
    /// Low severity and above.
    Low,
    /// Medium severity and above.
    Medium,
    /// High severity and above (default).
    High,
    /// Critical findings only.
    Critical,
    /// Never fail because of findings.
    Never,
}

impl FailOn {
    /// Returns the severity threshold, or [`None`] when the gate is disabled.
    #[must_use]
    pub const fn threshold(self) -> Option<Severity> {
        match self {
            Self::Info => Some(Severity::Info),
            Self::Low => Some(Severity::Low),
            Self::Medium => Some(Severity::Medium),
            Self::High => Some(Severity::High),
            Self::Critical => Some(Severity::Critical),
            Self::Never => None,
        }
    }
}

/// Severity argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SeverityArg {
    /// Informational notes.
    Info,
    /// Low severity.
    Low,
    /// Medium severity.
    Medium,
    /// High severity.
    High,
    /// Critical severity.
    Critical,
}

impl From<SeverityArg> for Severity {
    fn from(argument: SeverityArg) -> Self {
        match argument {
            SeverityArg::Info => Self::Info,
            SeverityArg::Low => Self::Low,
            SeverityArg::Medium => Self::Medium,
            SeverityArg::High => Self::High,
            SeverityArg::Critical => Self::Critical,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, Command, FailOn, HashMode, ProfileArg, ScanArgs};
    use clap::Parser;
    use peaudit_core::analysis::finding::Severity;
    use peaudit_core::analysis::profile::Profile;

    fn scan(args: &[&str]) -> ScanArgs {
        let mut argv = vec!["peaudit", "scan"];
        argv.extend_from_slice(args);
        let cli = Cli::try_parse_from(argv).expect("valid arguments");
        match cli.command {
            Command::Scan(scan) => scan,
            other => panic!("expected scan, got {other:?}"),
        }
    }

    #[test]
    fn defaults_are_the_documented_ones() {
        let args = scan(&["file.exe"]);
        assert_eq!(args.gate.profile, ProfileArg::Security);
        assert_eq!(args.gate.fail_on, FailOn::High);
        assert!(!args.gate.strict);
        assert_eq!(args.hashes.hashes, HashMode::Sha256);
        assert_eq!(args.format(), super::OutputFormat::Human);
    }

    #[test]
    fn json_and_jsonl_are_mutually_exclusive() {
        assert!(Cli::try_parse_from(["peaudit", "scan", "f", "--json", "--jsonl"]).is_err());
    }

    #[test]
    fn pretty_requires_json() {
        assert!(Cli::try_parse_from(["peaudit", "scan", "f", "--pretty"]).is_err());
        assert!(Cli::try_parse_from(["peaudit", "scan", "f", "--json", "--pretty"]).is_ok());
    }

    #[test]
    fn no_hashes_conflicts_with_hashes() {
        assert!(
            Cli::try_parse_from(["peaudit", "scan", "f", "--no-hashes", "--hashes", "all"])
                .is_err()
        );
    }

    #[test]
    fn fail_on_never_disables_the_gate() {
        let args = scan(&["file.exe", "--fail-on", "never"]);
        assert_eq!(args.gate.fail_on.threshold(), None);
        assert_eq!(FailOn::High.threshold(), Some(Severity::High));
    }

    #[test]
    fn profile_is_converted_to_the_core_type() {
        let args = scan(&["file.exe", "--profile", "loader"]);
        assert_eq!(Profile::from(args.gate.profile), Profile::Loader);
    }

    #[test]
    fn input_is_required() {
        assert!(Cli::try_parse_from(["peaudit", "scan"]).is_err());
    }

    #[test]
    fn a_subcommand_is_required() {
        assert!(Cli::try_parse_from(["peaudit"]).is_err());
    }
}
