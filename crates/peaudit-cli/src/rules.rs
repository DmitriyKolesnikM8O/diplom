//! `peaudit rules`: the rule registry as a table, a JSON array, or one rule in
//! full.
//!
//! The data comes from `RuleMeta`, the same source `docs/rules.md` is generated
//! from, so the CLI cannot describe a rule differently from the documentation.

use peaudit_core::analysis::finding::{Category, Confidence, Severity};
use peaudit_core::analysis::profile::Profile;
use peaudit_core::analysis::registry;
use serde::Serialize;

use crate::cli::RulesCommand;
use crate::error::{CliError, exit};
use crate::output::Sink;

/// Runs the `rules` command and returns the process exit code.
pub fn run(command: &RulesCommand) -> Result<u8, CliError> {
    match command {
        RulesCommand::List { json } => list(*json),
        RulesCommand::Explain { id } => explain(id),
    }
}

/// Machine-readable view of one rule.
#[derive(Debug, Serialize)]
struct RuleView {
    id: &'static str,
    title: &'static str,
    description: &'static str,
    severity: Severity,
    confidence: Confidence,
    category: Category,
    profiles: &'static [Profile],
    references: &'static [&'static str],
    since: &'static str,
}

fn list(json: bool) -> Result<u8, CliError> {
    let mut sink = Sink::open(None)?;

    if json {
        let views: Vec<RuleView> = registry::rules()
            .iter()
            .map(|rule| {
                let meta = rule.meta();
                RuleView {
                    id: meta.id,
                    title: meta.title,
                    description: meta.description,
                    severity: meta.severity,
                    confidence: meta.confidence,
                    category: meta.category,
                    profiles: meta.profiles,
                    references: meta.references,
                    since: meta.since,
                }
            })
            .collect();
        let text = serde_json::to_string_pretty(&views)
            .map_err(|error| CliError::internal(format!("cannot serialize the rules: {error}")))?;
        sink.write_line(&text)?;
    } else {
        sink.write_line(&format!(
            "{:<12} {:<8} {:<6} {:<22} {}",
            "ID", "SEVERITY", "CONF", "PROFILES", "TITLE"
        ))?;
        for rule in registry::rules() {
            let meta = rule.meta();
            sink.write_line(&format!(
                "{:<12} {:<8} {:<6} {:<22} {}",
                meta.id,
                meta.severity.as_str(),
                meta.confidence.as_str(),
                profiles_text(meta.profiles),
                meta.title
            ))?;
        }
    }

    sink.finish()?;
    Ok(exit::OK)
}

fn explain(id: &str) -> Result<u8, CliError> {
    let Some(rule) = registry::rule(id) else {
        return Err(CliError::usage(format!(
            "unknown rule `{id}`; run `peaudit rules list` to see the identifiers"
        )));
    };
    let meta = rule.meta();

    let mut sink = Sink::open(None)?;
    sink.write_line(&format!("{} — {}", meta.id, meta.title))?;
    sink.write_line(&format!("severity:   {}", meta.severity))?;
    sink.write_line(&format!("confidence: {}", meta.confidence))?;
    sink.write_line(&format!("category:   {}", meta.category))?;
    sink.write_line(&format!("profiles:   {}", profiles_text(meta.profiles)))?;
    sink.write_line(&format!("since:      {}", meta.since))?;
    sink.write_line("")?;
    sink.write_line(meta.description)?;
    sink.write_line("")?;
    sink.write_line("references:")?;
    for reference in meta.references {
        sink.write_line(&format!("  - {reference}"))?;
    }
    sink.finish()?;

    Ok(exit::OK)
}

fn profiles_text(profiles: &[Profile]) -> String {
    profiles
        .iter()
        .map(|profile| profile.as_str())
        .collect::<Vec<_>>()
        .join(",")
}
