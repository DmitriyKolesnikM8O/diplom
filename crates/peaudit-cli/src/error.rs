//! CLI errors and the exit codes they map to.
//!
//! The codes are the contract from `materials/roadmap.md` §5.3: an invalid PE
//! file is *not* an error, so a parse failure still exits with `0` unless a
//! finding crosses the `--fail-on` threshold.

use std::fmt;
use std::io::{self, Write};

/// Exit codes of the `peaudit` binary.
pub mod exit {
    /// Nothing at or above the `--fail-on` threshold.
    pub const OK: u8 = 0;
    /// At least one finding at or above the `--fail-on` threshold.
    pub const FINDINGS: u8 = 1;
    /// Bad arguments or an input/output problem.
    pub const USAGE: u8 = 2;
    /// A bug in the tool.
    pub const INTERNAL: u8 = 3;
}

/// Something that stopped a command before it produced a usable result.
#[derive(Debug)]
pub enum CliError {
    /// Bad arguments or an input that the caller can fix.
    Usage(String),
    /// Reading or writing failed.
    Io {
        /// Path or stream name the operation was performed on.
        target: String,
        /// Underlying error.
        source: io::Error,
    },
    /// An invariant broke: this is a bug, not a user mistake.
    Internal(String),
}

impl CliError {
    /// Creates a usage or input error.
    pub fn usage(message: impl Into<String>) -> Self {
        Self::Usage(message.into())
    }

    /// Wraps an I/O error together with the path it happened on.
    pub fn io(target: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            target: target.into(),
            source,
        }
    }

    /// Creates an internal error.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }

    /// Returns the process exit code for this error.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) | Self::Io { .. } => exit::USAGE,
            Self::Internal(_) => exit::INTERNAL,
        }
    }

    /// Returns `true` when the output stream was closed by the consumer.
    ///
    /// A closed pipe (`peaudit scan x.exe | head`) is not a failure: the caller
    /// asked for less output, so the tool exits successfully.
    #[must_use]
    pub fn is_broken_pipe(&self) -> bool {
        matches!(
            self,
            Self::Io { source, .. } if source.kind() == io::ErrorKind::BrokenPipe
        )
    }
}

/// Writes a diagnostic line to stderr, ignoring a failure to do so.
///
/// `eprintln!` panics when stderr is closed. A closed stderr is an environment
/// problem, not a reason for the tool to abort with a panic, so the result is
/// deliberately ignored.
pub fn report_to_stderr(message: &str) {
    let _ = writeln!(io::stderr().lock(), "{message}");
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => f.write_str(message),
            Self::Io { target, source } => write!(f, "{target}: {source}"),
            Self::Internal(message) => write!(f, "internal error: {message}"),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Usage(_) | Self::Internal(_) => None,
        }
    }
}
