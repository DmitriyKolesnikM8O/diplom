//! Integration tests for the `peaudit` binary.
//!
//! Fixtures are built with `peaudit_core::testutil::PeBuilder`, so each test
//! breaks exactly one field and the expected finding is obvious from the code.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;

use assert_cmd::Command;
use peaudit_core::pe::{optional, section};
use peaudit_core::testutil::PeBuilder;
use predicates::prelude::*;
use serde_json::Value;
use tempfile::TempDir;

fn peaudit() -> Command {
    Command::cargo_bin("peaudit").expect("binary is built")
}

fn clean_pe() -> Vec<u8> {
    PeBuilder::pe32().into_bytes()
}

/// Writable and executable section: `PE-SEC-007`, high, `security` profile.
fn writable_executable_pe() -> Vec<u8> {
    let mut builder = PeBuilder::pe32();
    let offset = builder.sections_offset() + section::CHARACTERISTICS_OFFSET;
    assert!(builder.patch_u32(
        offset,
        section::SCN_MEM_EXECUTE | section::SCN_MEM_WRITE | section::SCN_CNT_CODE
    ));
    builder.into_bytes()
}

/// `SizeOfHeaders` below the section table: `PE-OPT-003`, high, `spec`+`loader`.
fn bad_headers_pe() -> Vec<u8> {
    let mut builder = PeBuilder::pe32();
    let offset = builder.optional_offset() + optional::SIZE_OF_HEADERS_OFFSET;
    assert!(builder.patch_u32(offset, 0x100));
    builder.into_bytes()
}

fn write(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).expect("write fixture");
    path
}

fn json_report(output: &[u8]) -> Value {
    serde_json::from_slice(output).expect("valid JSON report")
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

#[test]
fn help_lists_every_subcommand() {
    peaudit()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("scan"))
        .stdout(predicate::str::contains("batch"))
        .stdout(predicate::str::contains("rules"))
        .stdout(predicate::str::contains("schema"));
}

#[test]
fn a_clean_file_exits_zero_and_reports_clean_verdicts() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "clean.exe", &clean_pe());

    let output = peaudit()
        .arg("scan")
        .arg(&path)
        .arg("--json")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    let report = json_report(&output.stdout);
    assert_eq!(report["schema_version"], "1.0");
    assert_eq!(report["parse"]["status"], "complete");
    assert_eq!(report["verdicts"]["spec"]["score"], 0);
    assert_eq!(report["verdicts"]["loader"]["score"], 0);
    assert_eq!(report["verdicts"]["security"]["score"], 0);

    let expected = path.display().to_string();
    assert_eq!(report["file"]["path"].as_str(), Some(expected.as_str()));
    assert!(report["file"]["sha256"].is_string());
}

#[test]
fn a_high_finding_fails_the_default_gate() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "dirty.exe", &writable_executable_pe());

    peaudit()
        .arg("scan")
        .arg(&path)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("PE-SEC-007"))
        .stdout(predicate::str::contains("gate: security"));
}

#[test]
fn fail_on_never_disables_the_gate() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "dirty.exe", &writable_executable_pe());

    peaudit()
        .arg("scan")
        .arg(&path)
        .args(["--fail-on", "never"])
        .assert()
        .success();
}

#[test]
fn fail_on_critical_ignores_a_high_finding() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "dirty.exe", &writable_executable_pe());

    peaudit()
        .arg("scan")
        .arg(&path)
        .args(["--fail-on", "critical"])
        .assert()
        .success();
}

#[test]
fn the_gate_follows_the_selected_profile() {
    let dir = TempDir::new().unwrap();
    // `PE-OPT-003` belongs to `spec` and `loader`, not to `security`.
    let path = write(&dir, "layout.exe", &bad_headers_pe());

    peaudit()
        .arg("scan")
        .arg(&path)
        .args(["--profile", "spec", "--fail-on", "high"])
        .assert()
        .code(1);

    peaudit()
        .arg("scan")
        .arg(&path)
        .args(["--profile", "security", "--fail-on", "high"])
        .assert()
        .success();
}

#[test]
fn a_missing_file_is_a_usage_error() {
    peaudit()
        .args(["scan", "definitely-missing.exe"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("definitely-missing.exe"));
}

#[test]
fn stdin_is_read_with_a_dash() {
    peaudit()
        .args(["scan", "-", "--json"])
        .write_stdin(clean_pe())
        .assert()
        .success()
        .stdout(predicate::str::contains("\"schema_version\":\"1.0\""));
}

#[test]
fn a_non_pe_input_is_a_report_not_an_error() {
    let output = peaudit()
        .args(["scan", "-", "--json"])
        .write_stdin(b"not a PE file".to_vec())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    let report = json_report(&output.stdout);
    assert_eq!(report["parse"]["status"], "failed");
    assert_eq!(report["verdicts"], Value::Null);
    assert!(
        !report["parse"]["diagnostics"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn strict_rejects_a_partial_parse() {
    let dir = TempDir::new().unwrap();
    let bytes = clean_pe();
    let path = write(&dir, "truncated.exe", &bytes[..0x100]);

    // Partial parsing is the default: the report is produced and, with the
    // gate disabled, the exit code is zero even though the parser stopped early.
    peaudit()
        .arg("scan")
        .arg(&path)
        .args(["--fail-on", "never"])
        .assert()
        .success();

    peaudit()
        .arg("scan")
        .arg(&path)
        .arg("--strict")
        .assert()
        .code(1)
        .stdout(predicate::str::contains("strict: rejected"));
}

#[test]
fn strict_accepts_a_complete_parse() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "clean.exe", &clean_pe());

    peaudit()
        .arg("scan")
        .arg(&path)
        .arg("--strict")
        .assert()
        .success()
        .stdout(predicate::str::contains("strict: accepted"));
}

#[test]
fn strict_is_visible_only_through_the_exit_code_in_json_mode() {
    let dir = TempDir::new().unwrap();
    let bytes = clean_pe();
    let path = write(&dir, "truncated.exe", &bytes[..0x100]);

    let output = peaudit()
        .arg("scan")
        .arg(&path)
        .args(["--strict", "--json"])
        .output()
        .unwrap();

    // The document stays a normal report; the rejection is the exit code.
    assert_eq!(output.status.code(), Some(1));
    let report = json_report(&output.stdout);
    assert_eq!(report["parse"]["status"], "partial");
}

#[test]
fn the_file_size_limit_is_checked_before_reading() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "clean.exe", &clean_pe());

    peaudit()
        .arg("scan")
        .arg(&path)
        .args(["--limit", "max-file-size=16"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("exceeds the limit"));
}

#[test]
fn an_unknown_limit_is_a_usage_error() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "clean.exe", &clean_pe());

    peaudit()
        .arg("scan")
        .arg(&path)
        .args(["--limit", "bogus=1"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown limit"));
}

#[test]
fn jsonl_is_one_line_per_report() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "clean.exe", &clean_pe());

    let output = peaudit()
        .arg("scan")
        .arg(&path)
        .arg("--jsonl")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(text.lines().count(), 1);
    serde_json::from_str::<Value>(text.trim()).expect("valid JSON line");
}

#[test]
fn output_goes_to_a_file_when_requested() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "clean.exe", &clean_pe());
    let report_path = dir.path().join("report.json");

    let output = peaudit()
        .arg("scan")
        .arg(&path)
        .args(["--json", "--output"])
        .arg(&report_path)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    let text = std::fs::read_to_string(&report_path).unwrap();
    serde_json::from_str::<Value>(&text).expect("valid JSON report");
}

#[test]
fn pretty_requires_json() {
    peaudit().args(["scan", "-", "--pretty"]).assert().code(2);
}

#[test]
fn min_severity_filters_only_the_human_output() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "dirty.exe", &writable_executable_pe());

    peaudit()
        .arg("scan")
        .arg(&path)
        .args(["--min-severity", "critical"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("findings: 0 of 1 shown"));

    // The JSON contract is unaffected: the finding is still there.
    let output = peaudit()
        .arg("scan")
        .arg(&path)
        .args(["--json", "--min-severity", "critical"])
        .output()
        .unwrap();
    let report = json_report(&output.stdout);
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
}

#[test]
fn no_hashes_drops_the_digest_from_the_report() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "clean.exe", &clean_pe());

    let output = peaudit()
        .arg("scan")
        .arg(&path)
        .args(["--no-hashes", "--json"])
        .output()
        .unwrap();

    let report = json_report(&output.stdout);
    assert!(report["file"].get("sha256").is_none());
}

// ---------------------------------------------------------------------------
// batch
// ---------------------------------------------------------------------------

#[test]
fn batch_reports_every_pe_file_and_fails_on_a_gate_hit() {
    let dir = TempDir::new().unwrap();
    write(&dir, "clean.exe", &clean_pe());
    write(&dir, "dirty.dll", &writable_executable_pe());
    // Not a PE extension: skipped unless --all-files is given.
    std::fs::write(dir.path().join("notes.txt"), b"ignored").unwrap();

    let output = peaudit()
        .args(["batch"])
        .arg(dir.path())
        .arg("--jsonl")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(text.lines().count(), 2);
    for line in text.lines() {
        serde_json::from_str::<Value>(line).expect("valid JSON line");
    }
}

#[test]
fn batch_recursion_is_opt_in() {
    let dir = TempDir::new().unwrap();
    write(&dir, "top.exe", &clean_pe());
    let nested = dir.path().join("nested");
    std::fs::create_dir(&nested).unwrap();
    std::fs::write(nested.join("deep.sys"), clean_pe()).unwrap();

    let flat = peaudit()
        .args(["batch"])
        .arg(dir.path())
        .arg("--jsonl")
        .output()
        .unwrap();
    assert_eq!(String::from_utf8(flat.stdout).unwrap().lines().count(), 1);

    let recursive = peaudit()
        .args(["batch"])
        .arg(dir.path())
        .args(["--recursive", "--jsonl"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8(recursive.stdout).unwrap().lines().count(),
        2
    );
}

#[test]
fn batch_does_not_stop_at_an_unparsable_file() {
    let dir = TempDir::new().unwrap();
    write(&dir, "clean.exe", &clean_pe());
    std::fs::write(dir.path().join("garbage.bin"), b"not a PE file").unwrap();

    let output = peaudit()
        .args(["batch"])
        .arg(dir.path())
        .args(["--all-files", "--jsonl"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap().lines().count(), 2);
}

#[test]
fn batch_on_a_file_is_a_usage_error() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "clean.exe", &clean_pe());

    peaudit()
        .arg("batch")
        .arg(&path)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not a directory"));
}

#[test]
fn batch_human_output_ends_with_a_summary() {
    let dir = TempDir::new().unwrap();
    write(&dir, "clean.exe", &clean_pe());

    peaudit()
        .args(["batch"])
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("analyzed: 1"))
        .stdout(predicate::str::contains("worst:"));
}

#[test]
fn batch_io_error_takes_priority_over_a_gate_hit() {
    let dir = TempDir::new().unwrap();
    write(&dir, "dirty.exe", &writable_executable_pe());

    // Above the per-run limit: this file cannot be read at all.
    let mut oversized = clean_pe();
    oversized.resize(4096, 0);
    std::fs::write(dir.path().join("oversized.exe"), &oversized).unwrap();

    let output = peaudit()
        .args(["batch"])
        .arg(dir.path())
        .args(["--limit", "max-file-size=2048"])
        .output()
        .unwrap();

    // The finding on `dirty.exe` would give 1; an unreadable input wins with 2.
    assert_eq!(output.status.code(), Some(2));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("findings 1"), "{text}");
    assert!(text.contains("exceeds the limit"), "{text}");
    assert!(text.contains("errors: 1"), "{text}");
    // The path appears once, not as `path: error: path: ...`.
    assert_eq!(text.matches("oversized.exe").count(), 1, "{text}");
}

#[test]
fn batch_output_is_sorted_whatever_the_job_count() {
    let dir = TempDir::new().unwrap();
    for name in ["c.exe", "a.exe", "b.dll"] {
        write(&dir, name, &clean_pe());
    }

    let output = peaudit()
        .args(["batch"])
        .arg(dir.path())
        .args(["--jobs", "4", "--jsonl"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    let paths: Vec<String> = text
        .lines()
        .map(|line| {
            let report: Value = serde_json::from_str(line).expect("valid JSON line");
            report["file"]["path"]
                .as_str()
                .expect("path is present")
                .to_owned()
        })
        .collect();

    let mut sorted = paths.clone();
    sorted.sort();
    assert_eq!(paths, sorted);
    assert_eq!(paths.len(), 3);
}

#[test]
fn batch_output_can_go_to_a_file() {
    let dir = TempDir::new().unwrap();
    write(&dir, "clean.exe", &clean_pe());
    let report_path = dir.path().join("reports.jsonl");

    let output = peaudit()
        .args(["batch"])
        .arg(dir.path())
        .args(["--jsonl", "--output"])
        .arg(&report_path)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    let text = std::fs::read_to_string(&report_path).unwrap();
    assert_eq!(text.lines().count(), 1);
    serde_json::from_str::<Value>(text.trim()).expect("valid JSON line");
}

// ---------------------------------------------------------------------------
// rules, schema, version
// ---------------------------------------------------------------------------

#[test]
fn rules_list_json_is_machine_readable() {
    let output = peaudit()
        .args(["rules", "list", "--json"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    let rules = json_report(&output.stdout);
    let entries = rules.as_array().expect("array");
    assert!(entries.len() >= 15);
    let ids: Vec<&str> = entries
        .iter()
        .filter_map(|rule| rule["id"].as_str())
        .collect();
    assert!(ids.contains(&"PE-SEC-007"));
    assert!(ids.contains(&"PE-OPT-003"));
}

#[test]
fn rules_list_prints_a_table() {
    peaudit()
        .args(["rules", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("SEVERITY"))
        .stdout(predicate::str::contains("PE-COFF-001"));
}

#[test]
fn rules_explain_describes_one_rule() {
    peaudit()
        .args(["rules", "explain", "PE-SEC-007"])
        .assert()
        .success()
        .stdout(predicate::str::contains("PE-SEC-007"))
        .stdout(predicate::str::contains("severity:"))
        .stdout(predicate::str::contains("references:"));
}

#[test]
fn rules_explain_rejects_an_unknown_id() {
    peaudit()
        .args(["rules", "explain", "PE-XXX-999"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown rule"));
}

#[test]
fn schema_prints_valid_json() {
    let output = peaudit().arg("schema").output().unwrap();

    assert_eq!(output.status.code(), Some(0));
    let schema = json_report(&output.stdout);
    assert!(schema.get("properties").is_some());
}

#[test]
fn schema_can_be_written_to_a_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("schema.json");

    peaudit()
        .arg("schema")
        .args(["--output"])
        .arg(&path)
        .assert()
        .success();

    let text = std::fs::read_to_string(&path).unwrap();
    serde_json::from_str::<Value>(&text).expect("valid schema");
}

#[test]
fn version_names_the_report_schema() {
    peaudit()
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains("peaudit"))
        .stdout(predicate::str::contains("report schema"));
}
