//! Command-line interface for `peaudit`.
//!
//! This crate is a thin adapter: argument parsing, input/output and exit codes.
//! All analysis logic lives in `peaudit-core`, and this binary only decides
//! what to read, how to render it and whether the run counts as a failure.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod batch;
mod cli;
mod error;
mod input;
mod options;
mod output;
mod rules;
mod scan;
mod schema;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};
use crate::error::{CliError, report_to_stderr};
use crate::output::Sink;

fn main() -> ExitCode {
    let cli = Cli::parse();

    match dispatch(&cli) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            // A closed pipe means the consumer asked for less output; that is
            // not a failure.
            if error.is_broken_pipe() {
                return ExitCode::SUCCESS;
            }
            report_to_stderr(&format!("peaudit: {error}"));
            ExitCode::from(error.exit_code())
        }
    }
}

fn dispatch(cli: &Cli) -> Result<u8, CliError> {
    match &cli.command {
        Command::Scan(args) => scan::run(args),
        Command::Batch(args) => batch::run(args),
        Command::Rules { command } => rules::run(command),
        Command::Schema(args) => schema::run(args),
        Command::Version => {
            // Goes through `Sink` so a closed stdout (`peaudit version | head`)
            // is a broken pipe, not a panic from `println!`.
            let mut sink = Sink::open(None)?;
            sink.write_line(&format!(
                "peaudit {} (report schema {})",
                peaudit_core::version(),
                peaudit_core::SCHEMA_VERSION
            ))?;
            sink.finish()?;
            Ok(error::exit::OK)
        }
    }
}
