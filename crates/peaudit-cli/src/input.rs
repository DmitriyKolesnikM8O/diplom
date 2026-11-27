//! Reading the input: a file or stdin, always bounded by `Limits::max_file_size`.
//!
//! The size check happens **before** the file is read, so pointing the tool at
//! a huge or special file costs nothing. stdin cannot be sized up front, so it
//! is read through `Read::take` with one extra byte: if that byte appears, the
//! input is too large and is rejected without buffering all of it.

use std::fs;
use std::io::{self, Read};
use std::path::Path;

use crate::error::CliError;

/// Input bytes together with the name that should appear in the report.
pub struct Input {
    /// Path as given on the command line; [`None`] for stdin.
    pub path: Option<String>,
    /// The bytes to analyze.
    pub data: Vec<u8>,
}

/// Reads the positional argument, treating `-` as stdin.
pub fn read_argument(argument: &str, max: u64) -> Result<Input, CliError> {
    if argument == "-" {
        let data = read_bounded(io::stdin().lock(), max, "<stdin>")?;
        return Ok(Input { path: None, data });
    }

    let data = read_file(Path::new(argument), max)?;
    Ok(Input {
        path: Some(argument.to_owned()),
        data,
    })
}

/// Reads a regular file, refusing anything larger than `max`.
pub fn read_file(path: &Path, max: u64) -> Result<Vec<u8>, CliError> {
    let name = path.display().to_string();
    let metadata = fs::metadata(path).map_err(|error| CliError::io(&name, error))?;
    if !metadata.is_file() {
        return Err(CliError::usage(format!("{name}: not a regular file")));
    }
    if metadata.len() > max {
        return Err(too_large(&name, Some(metadata.len()), max));
    }

    let data = fs::read(path).map_err(|error| CliError::io(&name, error))?;
    // The file may have grown between `metadata` and `read`.
    if data.len() as u64 > max {
        return Err(too_large(&name, Some(data.len() as u64), max));
    }
    Ok(data)
}

fn read_bounded(mut reader: impl Read, max: u64, name: &str) -> Result<Vec<u8>, CliError> {
    let mut buffer = Vec::new();
    reader
        .by_ref()
        .take(max.saturating_add(1))
        .read_to_end(&mut buffer)
        .map_err(|error| CliError::io(name, error))?;

    if buffer.len() as u64 > max {
        return Err(too_large(name, None, max));
    }
    Ok(buffer)
}

fn too_large(name: &str, size: Option<u64>, max: u64) -> CliError {
    // For a file the size is known. For stdin only "more than the limit" is
    // known, because the probe stops at `max + 1` bytes: reporting that probe
    // size as the input size would be a lie.
    let hint = "raise it with --limit max-file-size=<BYTES>";
    match size {
        Some(size) => CliError::usage(format!(
            "{name}: {size} bytes exceeds the limit of {max} bytes; {hint}"
        )),
        None => CliError::usage(format!(
            "{name}: the input is larger than the limit of {max} bytes; {hint}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::read_bounded;

    #[test]
    fn a_bounded_read_accepts_the_exact_limit() {
        let data = read_bounded(&b"1234"[..], 4, "<test>").expect("within the limit");
        assert_eq!(data, b"1234");
    }

    #[test]
    fn a_bounded_read_rejects_one_byte_more() {
        let error = read_bounded(&b"12345"[..], 4, "<test>").expect_err("over the limit");
        assert_eq!(error.exit_code(), 2);
        assert!(
            error
                .to_string()
                .contains("larger than the limit of 4 bytes")
        );
    }

    #[test]
    fn a_bounded_read_does_not_buffer_beyond_the_limit() {
        // 1 MiB of input with a 16-byte cap: the reader must stop at 17 bytes,
        // not read the whole slice.
        let input = vec![0u8; 1024 * 1024];
        let error = read_bounded(&input[..], 16, "<test>").expect_err("over the limit");
        assert!(
            error
                .to_string()
                .contains("larger than the limit of 16 bytes")
        );
        // The probe size (17) is not the input size and must not be reported
        // as one.
        assert!(!error.to_string().contains("17 bytes"));
    }
}
