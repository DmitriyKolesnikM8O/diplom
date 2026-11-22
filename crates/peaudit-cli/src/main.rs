//! Command-line interface for `peaudit`.
//!
//! This crate is a thin adapter: argument parsing, input/output and exit codes.
//! All analysis logic lives in `peaudit-core`.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use peaudit_core::{HashSelection, Limits, hash_file};

/// Which file digests to compute.
///
/// Every digest is a full pass over the file, so SHA-256 alone is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum HashMode {
    /// SHA-256 only (default).
    Sha256,
    /// SHA-256, SHA-1 and MD5.
    All,
}

impl From<HashMode> for HashSelection {
    fn from(mode: HashMode) -> Self {
        match mode {
            HashMode::Sha256 => Self::SHA256_ONLY,
            HashMode::All => Self::ALL,
        }
    }
}

/// Open-source static analyzer for PE files.
#[derive(Debug, Parser)]
#[command(
    name = "peaudit",
    version,
    about = "Open-source static analyzer for PE files",
    long_about = None
)]
struct Cli {
    /// PE file to analyze.
    file: PathBuf,
    /// Which file hashes to compute.
    #[arg(long, value_enum, default_value_t = HashMode::Sha256)]
    hashes: HashMode,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let data = match std::fs::read(&cli.file) {
        Ok(data) => data,
        Err(error) => {
            eprintln!("peaudit: cannot read {}: {error}", cli.file.display());
            return ExitCode::FAILURE;
        }
    };

    let limits = Limits::default();
    if let Err(error) = limits.check_file_size(data.len() as u64) {
        eprintln!("peaudit: {}: {error}", cli.file.display());
        return ExitCode::FAILURE;
    }

    let hashes = hash_file(&data, cli.hashes.into());
    println!(
        "peaudit {}: analysis is not implemented yet",
        peaudit_core::version()
    );
    println!("file: {} ({} bytes)", cli.file.display(), data.len());
    if let Some(sha256) = hashes.sha256 {
        println!("sha256: {}", hex(&sha256));
    }
    if let Some(sha1) = hashes.sha1 {
        println!("sha1:   {}", hex(&sha1));
    }
    if let Some(md5) = hashes.md5 {
        println!("md5:    {}", hex(&md5));
    }

    ExitCode::SUCCESS
}

/// Formats bytes as lowercase hexadecimal.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing into a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Cli, HashMode};
    use clap::Parser;

    #[test]
    fn hashes_default_to_sha256_only() {
        let cli = Cli::try_parse_from(["peaudit", "file.exe"]).unwrap();
        assert_eq!(cli.hashes, HashMode::Sha256);
    }

    #[test]
    fn hashes_accepts_all() {
        let cli = Cli::try_parse_from(["peaudit", "file.exe", "--hashes", "all"]).unwrap();
        assert_eq!(cli.hashes, HashMode::All);
    }

    #[test]
    fn unknown_hash_mode_is_rejected() {
        assert!(Cli::try_parse_from(["peaudit", "file.exe", "--hashes", "sha512"]).is_err());
    }

    #[test]
    fn file_argument_is_required() {
        assert!(Cli::try_parse_from(["peaudit"]).is_err());
    }
}
