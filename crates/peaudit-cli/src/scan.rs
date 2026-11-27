//! `peaudit scan`: one input, one report.

use peaudit_core::AnalysisOptions;
use peaudit_core::analysis::analyze;

use crate::cli::{OutputFormat, ScanArgs};
use crate::error::{CliError, exit};
use crate::input;
use crate::options::{Gate, has_error_diagnostic, limits_from};
use crate::output::Sink;

/// Runs the `scan` command and returns the process exit code.
pub fn run(args: &ScanArgs) -> Result<u8, CliError> {
    let limits = limits_from(&args.limits)?;
    let input = input::read_argument(&args.input, limits.max_file_size)?;

    let options = AnalysisOptions {
        limits,
        hashes: args.hashes.selection(),
    };
    let mut report = analyze(&input.data, &options);
    report.file.path = input.path;

    let gate = Gate::from_args(&args.gate);
    let findings_failed = gate.fails(&report.findings);
    let strict_failed = args.gate.strict && has_error_diagnostic(&report);

    let format = args.format();
    let mut sink = Sink::open(args.output.as_deref())?;
    sink.write_report(&report, format, gate.profile, args.min_severity.into())?;
    if format == OutputFormat::Human && args.gate.strict {
        let verdict = if strict_failed {
            "strict: rejected, the parser reported an error"
        } else {
            "strict: accepted"
        };
        sink.write_line(verdict)?;
    }
    sink.finish()?;

    Ok(if findings_failed || strict_failed {
        exit::FINDINGS
    } else {
        exit::OK
    })
}
