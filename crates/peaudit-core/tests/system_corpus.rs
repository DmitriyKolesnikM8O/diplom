//! Parse real system binaries and report what the parser saw.
//!
//! The test is ignored by default: it needs a corpus that is not part of the
//! repository. Point `PEAUDIT_SYSTEM_CORPUS` at a directory of PE files (the
//! default is `C:\Windows\System32`) and run
//!
//! ```powershell
//! $env:PEAUDIT_SYSTEM_CORPUS = "C:\Windows\System32"
//! cargo test -p peaudit-core --test system_corpus -- --ignored --nocapture
//! ```
//!
//! `PEAUDIT_CORPUS_LIMIT` caps the number of files (default 200).
//!
//! The purpose is not to assert a specific result per file: it is to prove that
//! a large, real, varied set of images never makes the parser panic and never
//! produces an error-level diagnostic. Warnings and infos are printed as a
//! histogram so that a regression is visible as a change in the summary.

// Test code may panic: a failed assertion is the intended outcome there.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use peaudit_core::{DiagSeverity, Limits, ParseState, PeFile};

/// Default corpus directory used when the environment variable is absent.
const DEFAULT_CORPUS: &str = r"C:\Windows\System32";

/// Default number of files to parse.
const DEFAULT_LIMIT: usize = 200;

/// Returns the corpus directory and the file limit from the environment.
fn corpus_settings() -> (PathBuf, usize) {
    let directory = std::env::var_os("PEAUDIT_SYSTEM_CORPUS")
        .map_or_else(|| PathBuf::from(DEFAULT_CORPUS), PathBuf::from);
    let limit = std::env::var("PEAUDIT_CORPUS_LIMIT")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value: &usize| *value > 0)
        .unwrap_or(DEFAULT_LIMIT);
    (directory, limit)
}

/// Returns `true` for the extensions this test treats as PE images.
fn is_pe_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("exe")
                || extension.eq_ignore_ascii_case("dll")
                || extension.eq_ignore_ascii_case("sys")
        })
}

/// Collects up to `limit` PE files from `directory`, sorted for determinism.
fn collect_files(directory: &Path, limit: usize) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && is_pe_extension(path))
        .collect();
    files.sort();
    files.truncate(limit);
    files
}

/// Builds a one-line description of where the parser stopped.
fn describe(file: &PeFile) -> String {
    let sections = file.coff.map_or(0, |coff| coff.number_of_sections);
    format!(
        "state={} sections={}/{} directories={} errors={}",
        file.state(),
        file.sections.len(),
        sections,
        file.directories.len(),
        file.diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity() == DiagSeverity::Error)
            .count()
    )
}

#[test]
#[ignore = "needs a PE corpus; set PEAUDIT_SYSTEM_CORPUS and run with --ignored"]
fn system_corpus_parses_without_errors() {
    let (directory, limit) = corpus_settings();
    let files = collect_files(&directory, limit);

    assert!(
        !files.is_empty(),
        "no PE files found in {}; set PEAUDIT_SYSTEM_CORPUS",
        directory.display()
    );

    let limits = Limits::default();
    let mut states: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut codes: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut failures: Vec<String> = Vec::new();
    let mut total_sections = 0usize;
    let mut total_directories = 0usize;

    for path in &files {
        let name = path.file_name().map_or_else(
            || path.display().to_string(),
            |name| name.to_string_lossy().into_owned(),
        );
        let Ok(bytes) = fs::read(path) else {
            failures.push(format!("{name}: unreadable"));
            continue;
        };

        let file = PeFile::parse(&bytes, &limits);
        *states.entry(file.state().as_str()).or_default() += 1;
        total_sections += file.sections.len();
        total_directories += file.directories.len();

        for diagnostic in &file.diagnostics {
            if diagnostic.severity() == DiagSeverity::Error {
                failures.push(format!(
                    "{name}: {} ({})",
                    diagnostic.code(),
                    describe(&file)
                ));
            }
            *codes.entry(diagnostic.code().as_str()).or_default() += 1;
        }
    }

    println!("corpus: {}", directory.display());
    println!("files parsed: {}", files.len());
    for (state, count) in &states {
        println!("  state {state}: {count}");
    }
    println!("  sections: {total_sections}, directories: {total_directories}");
    if !codes.is_empty() {
        println!("diagnostics:");
        for (code, count) in &codes {
            println!("  {code}: {count}");
        }
    }

    assert!(
        failures.is_empty(),
        "error-level diagnostics on real binaries:\n{}",
        failures.join("\n")
    );

    let complete = states
        .get(ParseState::Complete.as_str())
        .copied()
        .unwrap_or(0);
    assert!(
        complete * 10 >= files.len() * 9,
        "only {complete} of {} files parsed completely: {states:?}",
        files.len()
    );
}
