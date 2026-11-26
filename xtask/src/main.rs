//! Repository automation tasks.
//!
//! Run tasks with `cargo xtask <task>` (the alias is defined in
//! `.cargo/config.toml`).

use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("xtask: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);

    match args.next().as_deref() {
        Some("ci") => ci(),
        Some("rules-doc") => rules_doc(),
        Some("help") | None => {
            print_help();
            Ok(())
        }
        Some(other) => Err(format!("unknown task `{other}`; try `cargo xtask help`").into()),
    }
}

fn ci() -> Result<(), Box<dyn std::error::Error>> {
    run_cargo(&["fmt", "--all", "--check"])?;
    run_cargo(&[
        "clippy",
        "--workspace",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ])?;
    run_cargo(&["test", "--workspace"])?;
    run_cargo_with_env(
        &["doc", "--workspace", "--no-deps"],
        "RUSTDOCFLAGS",
        "-D warnings",
    )?;
    Ok(())
}

fn rules_doc() -> Result<(), Box<dyn std::error::Error>> {
    let path = "docs/rules.md";
    let text = peaudit_core::analysis::rules::markdown();
    std::fs::write(path, text)?;
    println!("wrote {path}");
    Ok(())
}

fn run_cargo(args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    run_cargo_with_env(args, "CARGO_TERM_COLOR", "always")
}

fn run_cargo_with_env(
    args: &[&str],
    key: &str,
    value: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("+ {key}={value} cargo {}", args.join(" "));

    let status = Command::new("cargo").args(args).env(key, value).status()?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("command failed with {status}: cargo {}", args.join(" ")).into())
    }
}

fn print_help() {
    println!(
        "\
Usage: cargo xtask <task>

Tasks:
  ci          Run the same checks as CI (fmt, clippy, test, doc)
  rules-doc   Regenerate docs/rules.md from RuleMeta
  help        Show this help
"
    );
}
