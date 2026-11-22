//! Core parsing and analysis engine for `peaudit`.
//!
//! The crate is intentionally free of I/O, networking and `unsafe` code: it
//! operates on a byte slice supplied by the caller. This keeps the analysis
//! deterministic, testable and safe against hostile input.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod bytes;
pub mod codes;
pub mod entropy;
pub mod error;
pub mod hash;
pub mod limits;
pub mod spec;

pub use bytes::Reader;
pub use entropy::{EntropyProfile, shannon_entropy};
pub use error::{DiagCode, DiagSeverity, Diagnostic, ErrorKind, ParseError};
pub use hash::{FileHashes, HashSelection, hash_all, hash_file};
pub use limits::Limits;

/// Returns the crate version.
///
/// The version is taken from `Cargo.toml` at compile time.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::version;

    #[test]
    fn version_is_not_empty() {
        assert!(!version().is_empty());
    }
}
