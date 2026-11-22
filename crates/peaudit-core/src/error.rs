//! Parse errors and diagnostics.
//!
//! The core never panics on input data. Every failure is represented as a
//! [`ParseError`] value, and recoverable problems are recorded as
//! [`Diagnostic`]s so that partial parsing can continue (see ADR-0003).
//!
//! All types in this module are [`Copy`] and allocation-free: an error never
//! owns a message string, it carries a stable code and a static context.

use core::fmt;

use thiserror::Error;

/// Category of a structural failure.
///
/// The set is intentionally small: it describes *how* a read failed, while the
/// specific field or structure is described by the error `context` and, at a
/// higher level, by a [`DiagCode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The input ended before the requested bytes were available.
    UnexpectedEof,
    /// A seek went past the end of the input.
    OutOfBounds,
    /// Arithmetic on an offset or size overflowed `usize`.
    ArithmeticOverflow,
    /// A field holds a value outside its allowed range.
    InvalidValue,
    /// A configured parsing limit was exceeded.
    LimitExceeded,
    /// The structure is well-formed but not supported by this version.
    Unsupported,
}

impl ErrorKind {
    /// Returns the stable machine-readable name of this kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnexpectedEof => "unexpected-eof",
            Self::OutOfBounds => "out-of-bounds",
            Self::ArithmeticOverflow => "arithmetic-overflow",
            Self::InvalidValue => "invalid-value",
            Self::LimitExceeded => "limit-exceeded",
            Self::Unsupported => "unsupported",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A failed read or seek on the input buffer.
///
/// `offset` points at the position where the operation started (for a failed
/// read) or at the requested position (for a failed seek). `context` is a
/// short static description of what was being read, for example `"u32"` or
/// `"section table"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("{kind} at offset {offset:#x} while reading {context}")]
pub struct ParseError {
    kind: ErrorKind,
    offset: usize,
    context: &'static str,
}

impl ParseError {
    const fn new(kind: ErrorKind, offset: usize, context: &'static str) -> Self {
        Self {
            kind,
            offset,
            context,
        }
    }

    /// Creates an "unexpected end of input" error.
    pub(crate) const fn unexpected_eof(offset: usize, context: &'static str) -> Self {
        Self::new(ErrorKind::UnexpectedEof, offset, context)
    }

    /// Creates an "out of bounds" error.
    pub(crate) const fn out_of_bounds(offset: usize, context: &'static str) -> Self {
        Self::new(ErrorKind::OutOfBounds, offset, context)
    }

    /// Creates an arithmetic overflow error.
    pub(crate) const fn overflow(offset: usize, context: &'static str) -> Self {
        Self::new(ErrorKind::ArithmeticOverflow, offset, context)
    }

    /// Creates a "limit exceeded" error.
    pub(crate) const fn limit_exceeded(offset: usize, context: &'static str) -> Self {
        Self::new(ErrorKind::LimitExceeded, offset, context)
    }

    /// Returns the failure category.
    #[must_use]
    pub const fn kind(self) -> ErrorKind {
        self.kind
    }

    /// Returns the input offset associated with the failure.
    #[must_use]
    pub const fn offset(self) -> usize {
        self.offset
    }

    /// Returns the static description of what was being read.
    #[must_use]
    pub const fn context(self) -> &'static str {
        self.context
    }
}

/// Severity of a [`Diagnostic`].
///
/// Ordering follows severity: `Info < Warning < Error`, so a collection can be
/// filtered with `diagnostic.severity() >= DiagSeverity::Warning`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum DiagSeverity {
    /// Informational note; does not indicate a problem.
    Info,
    /// Suspicious or non-conforming structure that still allowed parsing.
    Warning,
    /// A structure could not be parsed at all.
    Error,
}

impl DiagSeverity {
    /// Returns the stable machine-readable name of this severity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

impl fmt::Display for DiagSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stable identifier of a diagnostic category.
///
/// Codes are dot-separated lowercase identifiers such as `"dos.mz-missing"`.
/// Once released, a code is never renamed or reused: consumers may match on it
/// in JSON reports. Codes are created as constants at the call site, so a typo
/// is a missing constant rather than a silently different string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DiagCode(&'static str);

impl DiagCode {
    /// Creates a code from a stable string identifier.
    #[must_use]
    pub const fn new(code: &'static str) -> Self {
        Self(code)
    }

    /// Returns the underlying string identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for DiagCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// A recoverable problem found while parsing.
///
/// A diagnostic is data, not an exception: the parser records it and keeps
/// going. It never owns a string, so collecting diagnostics cannot fail and
/// does not allocate per message beyond the collection itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Diagnostic {
    code: DiagCode,
    severity: DiagSeverity,
    offset: Option<usize>,
    error: Option<ParseError>,
}

impl Diagnostic {
    /// Creates a diagnostic with the given code and severity.
    #[must_use]
    pub const fn new(code: DiagCode, severity: DiagSeverity) -> Self {
        Self {
            code,
            severity,
            offset: None,
            error: None,
        }
    }

    /// Creates an informational diagnostic.
    #[must_use]
    pub const fn info(code: DiagCode) -> Self {
        Self::new(code, DiagSeverity::Info)
    }

    /// Creates a warning-level diagnostic.
    #[must_use]
    pub const fn warning(code: DiagCode) -> Self {
        Self::new(code, DiagSeverity::Warning)
    }

    /// Creates an error-level diagnostic.
    #[must_use]
    pub const fn error(code: DiagCode) -> Self {
        Self::new(code, DiagSeverity::Error)
    }

    /// Attaches an input offset to this diagnostic.
    #[must_use]
    pub const fn at(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Attaches the parse error that caused this diagnostic.
    #[must_use]
    pub const fn caused_by(mut self, error: ParseError) -> Self {
        self.error = Some(error);
        self
    }

    /// Returns the diagnostic code.
    #[must_use]
    pub const fn code(self) -> DiagCode {
        self.code
    }

    /// Returns the diagnostic severity.
    #[must_use]
    pub const fn severity(self) -> DiagSeverity {
        self.severity
    }

    /// Returns the attached offset, if any.
    #[must_use]
    pub const fn offset(self) -> Option<usize> {
        self.offset
    }

    /// Returns the attached parse error, if any.
    #[must_use]
    pub const fn parse_error(self) -> Option<ParseError> {
        self.error
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}]", self.severity, self.code)?;
        match (self.offset, self.error) {
            (_, Some(error)) => write!(f, ": {error}"),
            (Some(offset), None) => write!(f, " at offset {offset:#x}"),
            (None, None) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DiagCode, DiagSeverity, Diagnostic, ErrorKind, ParseError};

    #[test]
    fn error_kind_names_are_stable() {
        assert_eq!(ErrorKind::UnexpectedEof.as_str(), "unexpected-eof");
        assert_eq!(ErrorKind::OutOfBounds.as_str(), "out-of-bounds");
        assert_eq!(
            ErrorKind::ArithmeticOverflow.as_str(),
            "arithmetic-overflow"
        );
        assert_eq!(ErrorKind::InvalidValue.as_str(), "invalid-value");
        assert_eq!(ErrorKind::LimitExceeded.as_str(), "limit-exceeded");
        assert_eq!(ErrorKind::Unsupported.as_str(), "unsupported");
    }

    #[test]
    fn parse_error_display_mentions_offset_and_context() {
        let error = ParseError::unexpected_eof(0x10, "u32");
        let text = error.to_string();
        assert!(text.contains("unexpected-eof"), "{text}");
        assert!(text.contains("0x10"), "{text}");
        assert!(text.contains("u32"), "{text}");
        assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
        assert_eq!(error.offset(), 0x10);
        assert_eq!(error.context(), "u32");
    }

    #[test]
    fn diagnostic_builder_keeps_fields() {
        let code = DiagCode::new("dos.mz-missing");
        let error = ParseError::unexpected_eof(0, "MZ signature");
        let diagnostic = Diagnostic::warning(code).at(0).caused_by(error);

        assert_eq!(diagnostic.code(), code);
        assert_eq!(diagnostic.severity(), DiagSeverity::Warning);
        assert_eq!(diagnostic.offset(), Some(0));
        assert_eq!(diagnostic.parse_error(), Some(error));
    }

    #[test]
    fn diagnostic_display_prefers_error_details() {
        let code = DiagCode::new("pe.signature-missing");
        let error = ParseError::unexpected_eof(0x80, "PE signature");
        let diagnostic = Diagnostic::error(code).at(0x80).caused_by(error);
        let text = diagnostic.to_string();
        assert!(text.contains("error"), "{text}");
        assert!(text.contains("pe.signature-missing"), "{text}");
        assert!(text.contains("unexpected-eof"), "{text}");
    }

    #[test]
    fn severity_is_ordered_from_info_to_error() {
        assert!(DiagSeverity::Info < DiagSeverity::Warning);
        assert!(DiagSeverity::Warning < DiagSeverity::Error);
    }

    #[test]
    fn diag_code_compares_by_value() {
        let a = DiagCode::new("opt.bad-magic");
        let b = DiagCode::new("opt.bad-magic");
        let c = DiagCode::new("opt.bad-magic-v2");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.to_string(), "opt.bad-magic");
    }
}
