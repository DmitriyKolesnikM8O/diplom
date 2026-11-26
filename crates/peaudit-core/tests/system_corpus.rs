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

use peaudit_core::analysis::registry;
use peaudit_core::analysis::rule::{AnalysisContext, Findings};
use peaudit_core::{Derived, DiagSeverity, Limits, ParseState, PeFile, RvaMapping, RvaStrategy};

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
    let mut rva_failures: Vec<String> = Vec::new();
    let mut header_mismatches = 0usize;
    let mut image_mismatches = 0usize;
    let mut checksums_set = 0usize;
    let mut checksum_mismatches = 0usize;
    let mut overlays = 0usize;
    let mut certificates = 0usize;
    let mut truncated_sections = 0usize;
    let mut high_entropy_sections = 0usize;
    let mut total_sections = 0usize;
    let mut total_directories = 0usize;
    let mut findings_total = 0usize;
    let mut finding_ids: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut finding_examples: Vec<String> = Vec::new();

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

        let derived = Derived::compute(&bytes, &file);
        if let Some(headers) = derived.headers_size {
            if !headers.covers_headers() {
                header_mismatches += 1;
            }
        }
        if derived.image_size.and_then(|image| image.is_consistent()) == Some(false) {
            image_mismatches += 1;
        }
        if derived.overlay.is_present() {
            overlays += 1;
        }
        if derived.overlay.certificate.is_some() {
            certificates += 1;
        }
        for entry in &derived.section_entropy {
            if entry.truncated {
                truncated_sections += 1;
            }
            if entry.is_high_entropy() {
                high_entropy_sections += 1;
            }
        }
        if derived.checksum.is_set() {
            checksums_set += 1;
            if derived.checksum.is_consistent() == Some(false) {
                checksum_mismatches += 1;
            }
        }

        let context = AnalysisContext {
            data: &bytes,
            file: &file,
            derived: &derived,
        };
        let mut collected = Findings::new();
        for rule in registry::rules() {
            rule.evaluate(&context, &mut collected);
        }
        findings_total += collected.len();
        for finding in collected.as_slice() {
            *finding_ids.entry(finding.id).or_default() += 1;
            if finding_examples.len() < 20 {
                finding_examples.push(format!("{name}: {} — {}", finding.id, finding.message));
            }
        }

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

        // The property the RVA model rests on: the start of a section must map
        // to its raw pointer under every strategy, at least for real images
        // where both sizes are non-zero.
        for section in &file.sections {
            if section.size_of_raw_data == 0 || section.virtual_size == 0 {
                continue;
            }
            let expected = RvaMapping::FileOffset(u64::from(section.pointer_to_raw_data));
            for strategy in [
                RvaStrategy::Spec,
                RvaStrategy::Loader,
                RvaStrategy::MaxVirtualRaw,
            ] {
                if file.map_rva(section.virtual_address, strategy) != expected {
                    rva_failures.push(format!(
                        "{name}: section at VA {:#x} does not map to {expected} under {strategy}",
                        section.virtual_address
                    ));
                }
            }
        }
    }

    println!("corpus: {}", directory.display());
    println!("files parsed: {}", files.len());
    for (state, count) in &states {
        println!("  state {state}: {count}");
    }
    println!("  sections: {total_sections}, directories: {total_directories}");
    println!("  headers not covering the table: {header_mismatches}");
    println!("  SizeOfImage mismatches: {image_mismatches}");
    println!("  overlays: {overlays}");
    println!("  certificate tables: {certificates}");
    println!("  sections with truncated raw data: {truncated_sections}");
    println!("  sections with entropy >= 7.0 bits/byte: {high_entropy_sections}");
    println!("  checksums set: {checksums_set}, mismatches: {checksum_mismatches}");
    println!("  findings: {findings_total}");
    for (id, count) in &finding_ids {
        println!("  {id}: {count}");
    }
    for example in &finding_examples {
        println!("    {example}");
    }
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
    assert!(
        rva_failures.is_empty(),
        "section starts do not map to their raw pointers:\n{}",
        rva_failures.join("\n")
    );
    assert_eq!(
        header_mismatches, 0,
        "SizeOfHeaders does not cover the section table on real binaries"
    );
    assert_eq!(
        image_mismatches, 0,
        "SizeOfImage does not match the computed extent on real binaries"
    );
    assert_eq!(
        checksum_mismatches, 0,
        "a stored checksum does not match the computed one on real binaries"
    );
    assert_eq!(
        truncated_sections, 0,
        "a section declares more raw data than the file holds on real binaries"
    );
    assert_eq!(
        findings_total,
        0,
        "rules fire on real binaries; every hit is a false positive until proven otherwise:\n{}",
        finding_examples.join("\n")
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
