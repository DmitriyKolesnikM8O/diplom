//! `peaudit batch`: a directory, one report per file, one exit code.
//!
//! Parallelism is plain `std::thread`: a shared atomic index hands out files,
//! so no work queue and no dependency are needed. Results are stored by file
//! index and printed in sorted order, which keeps the output deterministic
//! regardless of how the threads interleave.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use peaudit_core::AnalysisOptions;
use peaudit_core::analysis::analyze;
use peaudit_core::analysis::finding::Severity;
use peaudit_core::analysis::profile::Profile;
use peaudit_core::analysis::scoring::Level;
use peaudit_core::report::Report;

use crate::cli::{BatchArgs, OutputFormat};
use crate::error::{CliError, exit};
use crate::input;
use crate::options::{Gate, has_error_diagnostic, limits_from};
use crate::output::Sink;

/// Extensions treated as PE images when `--all-files` is not given.
const PE_EXTENSIONS: &[&str] = &["exe", "dll", "sys", "ocx", "cpl", "scr"];

/// Upper bound on worker threads, whatever `--jobs` says.
const MAX_JOBS: usize = 32;

/// Runs the `batch` command and returns the process exit code.
pub fn run(args: &BatchArgs) -> Result<u8, CliError> {
    let limits = limits_from(&args.limits)?;
    let files = collect_files(&args.directory, args.recursive, args.all_files)?;
    let options = AnalysisOptions {
        limits,
        hashes: args.hashes.selection(),
    };
    let gate = Gate::from_args(&args.gate);
    let jobs = effective_jobs(args.jobs, files.len());
    let results = analyze_all(&files, &options, jobs)?;

    let mut sink = Sink::open(None)?;
    let mut summary = Summary::default();
    let mut failed = false;
    let mut io_error = false;

    for (path, result) in files.iter().zip(results) {
        match result {
            Ok(report) => {
                summary.add(&report);
                failed |= gate.fails(&report.findings);
                failed |= args.gate.strict && has_error_diagnostic(&report);
                if args.jsonl {
                    sink.write_report(
                        &report,
                        OutputFormat::JsonLines,
                        gate.profile,
                        Severity::Info,
                    )?;
                } else {
                    sink.write_line(&summary_line(path, &report, gate.profile))?;
                }
            }
            Err(error) => {
                io_error = true;
                summary.errors += 1;
                if args.jsonl {
                    // JSONL carries reports only; an unreadable file has no
                    // report, so it goes to stderr and the exit code.
                    eprintln!("peaudit: {error}");
                } else {
                    sink.write_line(&format!("{}: error: {error}", path.display()))?;
                }
            }
        }
    }

    if !args.jsonl {
        summary.write(&mut sink)?;
    }
    sink.finish()?;

    Ok(if io_error {
        exit::USAGE
    } else if failed {
        exit::FINDINGS
    } else {
        exit::OK
    })
}

fn analyze_one(path: &Path, options: &AnalysisOptions) -> Result<Report, CliError> {
    let data = input::read_file(path, options.limits.max_file_size)?;
    let mut report = analyze(&data, options);
    report.file.path = Some(path.display().to_string());
    Ok(report)
}

fn analyze_all(
    files: &[PathBuf],
    options: &AnalysisOptions,
    jobs: usize,
) -> Result<Vec<Result<Report, CliError>>, CliError> {
    if jobs <= 1 {
        return Ok(files
            .iter()
            .map(|path| analyze_one(path, options))
            .collect());
    }

    let next = AtomicUsize::new(0);
    let (slots, panicked) = thread::scope(|scope| {
        let handles: Vec<_> = (0..jobs)
            .map(|_| {
                scope.spawn(|| {
                    let mut local: Vec<(usize, Result<Report, CliError>)> = Vec::new();
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(path) = files.get(index) else {
                            break;
                        };
                        local.push((index, analyze_one(path, options)));
                    }
                    local
                })
            })
            .collect();

        let mut slots: Vec<Option<Result<Report, CliError>>> = Vec::with_capacity(files.len());
        slots.resize_with(files.len(), || None);
        let mut panicked = false;

        for handle in handles {
            match handle.join() {
                Ok(local) => {
                    for (index, result) in local {
                        if let Some(slot) = slots.get_mut(index) {
                            *slot = Some(result);
                        }
                    }
                }
                Err(_) => panicked = true,
            }
        }

        (slots, panicked)
    });

    if panicked {
        return Err(CliError::internal("a batch worker thread panicked"));
    }

    let mut results = Vec::with_capacity(slots.len());
    for slot in slots {
        match slot {
            Some(result) => results.push(result),
            None => return Err(CliError::internal("a batch worker produced no result")),
        }
    }
    Ok(results)
}

/// Collects regular files under `root`, sorted for deterministic output.
fn collect_files(root: &Path, recursive: bool, all_files: bool) -> Result<Vec<PathBuf>, CliError> {
    let name = root.display().to_string();
    let metadata = fs::metadata(root).map_err(|error| CliError::io(&name, error))?;
    if !metadata.is_dir() {
        return Err(CliError::usage(format!("{name}: not a directory")));
    }

    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();

    while let Some(directory) = pending.pop() {
        let directory_name = directory.display().to_string();
        let entries =
            fs::read_dir(&directory).map_err(|error| CliError::io(&directory_name, error))?;
        for entry in entries {
            let entry = entry.map_err(|error| CliError::io(&directory_name, error))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| CliError::io(path.display().to_string(), error))?;

            if file_type.is_dir() {
                if recursive {
                    pending.push(path);
                }
            } else if file_type.is_file() && (all_files || is_pe_extension(&path)) {
                files.push(path);
            }
        }
    }

    files.sort();
    Ok(files)
}

fn is_pe_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            PE_EXTENSIONS
                .iter()
                .any(|known| extension.eq_ignore_ascii_case(known))
        })
}

fn effective_jobs(requested: usize, files: usize) -> usize {
    if files <= 1 {
        return 1;
    }
    let requested = if requested == 0 {
        thread::available_parallelism().map_or(1, |value| value.get())
    } else {
        requested
    };
    requested.clamp(1, MAX_JOBS).min(files)
}

fn summary_line(path: &Path, report: &Report, profile: Profile) -> String {
    let findings = report.findings.len();
    match &report.verdicts {
        Some(verdicts) => {
            let verdict = match profile {
                Profile::Spec => verdicts.spec,
                Profile::Loader => verdicts.loader,
                Profile::Security => verdicts.security,
            };
            format!(
                "{}: {} {} ({}), findings {findings}",
                path.display(),
                profile,
                verdict.score,
                verdict.level
            )
        }
        None => format!("{}: not a PE image, findings {findings}", path.display()),
    }
}

#[derive(Debug, Default)]
struct Summary {
    analyzed: usize,
    with_findings: usize,
    errors: usize,
    worst_spec: u32,
    worst_loader: u32,
    worst_security: u32,
}

impl Summary {
    fn add(&mut self, report: &Report) {
        self.analyzed += 1;
        if !report.findings.is_empty() {
            self.with_findings += 1;
        }
        if let Some(verdicts) = &report.verdicts {
            self.worst_spec = self.worst_spec.max(verdicts.spec.score);
            self.worst_loader = self.worst_loader.max(verdicts.loader.score);
            self.worst_security = self.worst_security.max(verdicts.security.score);
        }
    }

    fn write(&self, sink: &mut Sink) -> Result<(), CliError> {
        sink.write_line(&format!(
            "analyzed: {}, with findings: {}, errors: {}",
            self.analyzed, self.with_findings, self.errors
        ))?;

        if self.analyzed > 0 {
            sink.write_line(&format!(
                "worst: spec {} ({}), loader {} ({}), security {} ({})",
                self.worst_spec,
                Level::from_score(self.worst_spec),
                self.worst_loader,
                Level::from_score(self.worst_loader),
                self.worst_security,
                Level::from_score(self.worst_security)
            ))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_JOBS, effective_jobs, is_pe_extension};
    use std::path::Path;

    #[test]
    fn known_pe_extensions_are_case_insensitive() {
        assert!(is_pe_extension(Path::new("a.exe")));
        assert!(is_pe_extension(Path::new("a.DLL")));
        assert!(is_pe_extension(Path::new("a.sys")));
        assert!(!is_pe_extension(Path::new("a.txt")));
        assert!(!is_pe_extension(Path::new("a")));
    }

    #[test]
    fn jobs_are_clamped_to_the_file_count() {
        assert_eq!(effective_jobs(8, 2), 2);
        assert_eq!(effective_jobs(0, 0), 1);
        assert_eq!(effective_jobs(1000, 1000), MAX_JOBS);
    }
}
