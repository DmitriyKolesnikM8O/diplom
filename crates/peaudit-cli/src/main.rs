//! Command-line interface for `peaudit`.
//!
//! This crate is a thin adapter: argument parsing, input/output and exit codes.
//! All analysis logic lives in `peaudit-core`.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::path::PathBuf;

use clap::Parser;

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
}

fn main() {
    let cli = Cli::parse();
    println!(
        "peaudit {}: analysis is not implemented yet (input: {})",
        peaudit_core::version(),
        cli.file.display()
    );
}
