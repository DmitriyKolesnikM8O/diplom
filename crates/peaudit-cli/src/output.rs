//! Rendering a report: human summary, one JSON document, or JSONL.
//!
//! The human form is a reading aid, not a contract; the JSON form is the
//! contract from `docs/report-schema.md`. That is why `--min-severity` filters
//! only the human table: a JSON report always contains every finding, so a
//! consumer never has to guess what was hidden.

use std::fs::File;
use std::io::{self, BufWriter, Write};

use peaudit_core::analysis::finding::Severity;
use peaudit_core::analysis::profile::Profile;
use peaudit_core::report::Report;

use crate::cli::OutputFormat;
use crate::error::CliError;

/// Where the output goes: stdout, or a file when `--output` is given.
pub struct Sink {
    writer: Box<dyn Write>,
    name: String,
}

impl Sink {
    /// Opens stdout, or creates `path` when one is given.
    ///
    /// `-` is accepted as a synonym for stdout, so `--output -` works in
    /// scripts.
    pub fn open(path: Option<&str>) -> Result<Self, CliError> {
        match path {
            Some(path) if path != "-" => {
                let file = File::create(path).map_err(|error| CliError::io(path, error))?;
                Ok(Self {
                    writer: Box::new(BufWriter::new(file)),
                    name: path.to_owned(),
                })
            }
            _ => Ok(Self {
                writer: Box::new(BufWriter::new(io::stdout())),
                name: "<stdout>".to_owned(),
            }),
        }
    }

    /// Writes one report in the requested format.
    pub fn write_report(
        &mut self,
        report: &Report,
        format: OutputFormat,
        profile: Profile,
        min_severity: Severity,
    ) -> Result<(), CliError> {
        match format {
            OutputFormat::Human => write_human(self, report, profile, min_severity),
            OutputFormat::Json { pretty } => write_json(self, report, pretty),
            OutputFormat::JsonLines => write_json_line(self, report),
        }
    }

    /// Writes one line of text.
    pub fn write_line(&mut self, text: &str) -> Result<(), CliError> {
        writeln!(self.writer, "{text}").map_err(|error| CliError::io(&self.name, error))
    }

    /// Flushes buffered output.
    pub fn finish(mut self) -> Result<(), CliError> {
        self.writer
            .flush()
            .map_err(|error| CliError::io(&self.name, error))
    }
}

fn write_json(sink: &mut Sink, report: &Report, pretty: bool) -> Result<(), CliError> {
    let text = if pretty {
        serde_json::to_string_pretty(report)
    } else {
        serde_json::to_string(report)
    }
    .map_err(|error| CliError::internal(format!("cannot serialize the report: {error}")))?;

    sink.write_line(&text)
}

fn write_json_line(sink: &mut Sink, report: &Report) -> Result<(), CliError> {
    let text = serde_json::to_string(report)
        .map_err(|error| CliError::internal(format!("cannot serialize the report: {error}")))?;

    sink.write_line(&text)
}

fn write_human(
    sink: &mut Sink,
    report: &Report,
    profile: Profile,
    min_severity: Severity,
) -> Result<(), CliError> {
    let path = report.file.path.as_deref().unwrap_or("<stdin>");
    sink.write_line(&format!("peaudit {} — {path}", report.tool.version))?;
    sink.write_line(&format!("size: {} bytes", report.file.size))?;
    for (label, digest) in [
        ("sha256", report.file.sha256.as_deref()),
        ("sha1", report.file.sha1.as_deref()),
        ("md5", report.file.md5.as_deref()),
    ] {
        if let Some(digest) = digest {
            sink.write_line(&format!("{label}: {digest}"))?;
        }
    }

    let parse = &report.parse;
    let mut summary = format!("parse: {}", parse.status);
    if let Some(format) = parse.format {
        summary.push_str(&format!("; format {format}"));
    }
    if let Some(machine) = parse.machine {
        summary.push_str(&format!("; machine {machine}"));
    }
    summary.push_str(&format!("; diagnostics {}", parse.diagnostics.len()));
    sink.write_line(&summary)?;

    match &report.verdicts {
        Some(verdicts) => sink.write_line(&format!(
            "verdicts: spec {} ({}), loader {} ({}), security {} ({})",
            verdicts.spec.score,
            verdicts.spec.level,
            verdicts.loader.score,
            verdicts.loader.level,
            verdicts.security.score,
            verdicts.security.level
        ))?,
        None => sink.write_line("verdicts: unavailable, the input is not a PE image")?,
    }

    if !parse.diagnostics.is_empty() {
        sink.write_line("diagnostics:")?;
        for diagnostic in &parse.diagnostics {
            let offset = diagnostic
                .offset
                .map(|offset| format!(" @{offset}"))
                .unwrap_or_default();
            let context = diagnostic
                .context
                .map(|context| format!(" ({context})"))
                .unwrap_or_default();
            sink.write_line(&format!(
                "  {:<8} {}{}{}",
                diagnostic.severity, diagnostic.code, offset, context
            ))?;
        }
    }

    let total = report.findings.len();
    let shown: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.severity >= min_severity)
        .collect();
    if shown.len() == total {
        sink.write_line(&format!("findings: {total}"))?;
    } else {
        sink.write_line(&format!(
            "findings: {} of {total} shown (severity >= {min_severity})",
            shown.len()
        ))?;
    }

    for finding in shown {
        sink.write_line(&format!(
            "  {:<8} {}  {}",
            finding.severity.as_str(),
            finding.id,
            finding.title
        ))?;
        sink.write_line(&format!("           {}", finding.message))?;
        for evidence in &finding.evidence {
            sink.write_line(&format!("           {}", evidence_line(evidence)))?;
        }
    }

    if let Some(verdicts) = &report.verdicts {
        let verdict = match profile {
            Profile::Spec => verdicts.spec,
            Profile::Loader => verdicts.loader,
            Profile::Security => verdicts.security,
        };
        sink.write_line(&format!(
            "gate: {profile} {} ({})",
            verdict.score, verdict.level
        ))?;
    }

    Ok(())
}

/// Formats one evidence entry as a single checkable line.
fn evidence_line(evidence: &peaudit_core::analysis::finding::Evidence) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(offset) = evidence.offset {
        parts.push(format!("@{offset}"));
    }
    if let Some(expected) = &evidence.expected {
        parts.push(format!("expected {expected}"));
    }
    if let Some(actual) = &evidence.actual {
        parts.push(format!("actual {actual}"));
    }

    if parts.is_empty() {
        evidence.field.to_owned()
    } else {
        format!("{}: {}", evidence.field, parts.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::evidence_line;
    use peaudit_core::analysis::finding::Evidence;

    #[test]
    fn evidence_renders_every_present_part() {
        let evidence = Evidence::field("optional.sizeOfHeaders")
            .at(148)
            .expected(">= 0x160")
            .actual("0x100");
        assert_eq!(
            evidence_line(&evidence),
            "optional.sizeOfHeaders: @148, expected >= 0x160, actual 0x100"
        );
    }

    #[test]
    fn evidence_without_details_is_just_the_field() {
        let evidence = Evidence::field("sections[]");
        assert_eq!(evidence_line(&evidence), "sections[]");
    }

    #[test]
    fn an_unknown_offset_is_omitted() {
        let evidence = Evidence::field("sections[].virtualSize")
            .at_opt(None)
            .actual("0");
        assert_eq!(evidence_line(&evidence), "sections[].virtualSize: actual 0");
    }
}
