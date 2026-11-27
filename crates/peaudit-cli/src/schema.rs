//! `peaudit schema`: the JSON report schema, embedded in the binary.
//!
//! The file is included at compile time, so the schema a user gets from the
//! binary is exactly the one the repository validates reports against.

use std::fs;

use crate::cli::SchemaArgs;
use crate::error::{CliError, exit};
use crate::output::Sink;

/// `docs/report.schema.json`, included at compile time.
const SCHEMA: &str = include_str!("../../../docs/report.schema.json");

/// Runs the `schema` command and returns the process exit code.
pub fn run(args: &SchemaArgs) -> Result<u8, CliError> {
    match &args.output {
        Some(path) => fs::write(path, SCHEMA).map_err(|error| CliError::io(path, error))?,
        None => {
            let mut sink = Sink::open(None)?;
            for line in SCHEMA.lines() {
                sink.write_line(line)?;
            }
            sink.finish()?;
        }
    }

    Ok(exit::OK)
}
