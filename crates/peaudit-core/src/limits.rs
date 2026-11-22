//! Safety limits.
//!
//! Every unbounded structure in a PE file is a denial-of-service vector: a
//! crafted file can declare millions of sections, imports or resource nodes.
//! [`Limits`] caps each of them. Exceeding a limit produces a [`ParseError`] of
//! kind `LimitExceeded`; the parser records a diagnostic and skips only the
//! affected substructure (ADR-0003).
//!
//! These caps are deliberately **higher** than the values fixed by the PE
//! specification (see [`crate::spec`]). A file with 100 sections violates the
//! specification, but the analyzer still wants to read all 100 of them; the
//! violation is reported by a rule, not by refusing to parse. The caps here
//! exist only to bound work and memory on hostile input.

use crate::error::ParseError;

/// Hard caps applied while parsing.
///
/// The type is `Copy`, so a parser can carry it by value and derive stricter
/// limits for a nested structure without touching global state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum accepted input size, in bytes. Default: 512 MiB.
    ///
    /// Real PE images are far smaller; the cap protects against being pointed
    /// at a huge or special file.
    pub max_file_size: u64,
    /// Maximum number of section table entries to read. Default: 4096.
    ///
    /// This is a safety cap. The specification threshold is
    /// [`crate::spec::MAX_SECTIONS`]; exceeding it is a finding, not a parse
    /// failure.
    pub max_sections: usize,
    /// Maximum number of data directories to read. Default: 4096.
    ///
    /// Safety cap; the specification defines
    /// [`crate::spec::MAX_DATA_DIRECTORIES`].
    pub max_directories: usize,
    /// Maximum number of import descriptors. Default: 65536.
    pub max_imports: usize,
    /// Maximum number of export entries. Default: 65536.
    pub max_exports: usize,
    /// Maximum number of resource directory nodes. Default: 65536.
    pub max_resource_nodes: usize,
    /// Maximum resource tree depth. Default: 32.
    ///
    /// Safety cap; the specification defines
    /// [`crate::spec::RESOURCE_TREE_DEPTH`].
    pub max_resource_depth: u8,
    /// Maximum length of a single string (section name, import name, PDB path).
    /// Default: 4096 bytes.
    pub max_string_len: usize,
    /// Maximum number of thunks per import descriptor. Default: 65536.
    pub max_thunks_per_import: usize,
    /// Maximum sliding window size used for entropy analysis. Default: 4096.
    pub max_entropy_window: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_size: 512 * 1024 * 1024,
            max_sections: 4096,
            max_directories: 4096,
            max_imports: 65536,
            max_exports: 65536,
            max_resource_nodes: 65536,
            max_resource_depth: 32,
            max_string_len: 4096,
            max_thunks_per_import: 65536,
            max_entropy_window: 4096,
        }
    }
}

impl Limits {
    /// Checks the input size against [`Limits::max_file_size`].
    ///
    /// # Errors
    ///
    /// Returns `LimitExceeded` at offset 0 if `size` is too large.
    pub fn check_file_size(&self, size: u64) -> Result<(), ParseError> {
        if size > self.max_file_size {
            return Err(
                ParseError::limit_exceeded(0, "file size").with_values(self.max_file_size, size)
            );
        }
        Ok(())
    }

    /// Checks a section count against [`Limits::max_sections`].
    ///
    /// # Errors
    ///
    /// Returns `LimitExceeded` if `count` is too large.
    pub fn check_sections(&self, count: usize, offset: usize) -> Result<(), ParseError> {
        self.check_usize(count, self.max_sections, offset, "section count")
    }

    /// Checks a data directory count against [`Limits::max_directories`].
    ///
    /// # Errors
    ///
    /// Returns `LimitExceeded` if `count` is too large.
    pub fn check_directories(&self, count: usize, offset: usize) -> Result<(), ParseError> {
        self.check_usize(count, self.max_directories, offset, "directory count")
    }

    /// Checks an import descriptor count against [`Limits::max_imports`].
    ///
    /// # Errors
    ///
    /// Returns `LimitExceeded` if `count` is too large.
    pub fn check_imports(&self, count: usize, offset: usize) -> Result<(), ParseError> {
        self.check_usize(count, self.max_imports, offset, "import count")
    }

    /// Checks an export count against [`Limits::max_exports`].
    ///
    /// # Errors
    ///
    /// Returns `LimitExceeded` if `count` is too large.
    pub fn check_exports(&self, count: usize, offset: usize) -> Result<(), ParseError> {
        self.check_usize(count, self.max_exports, offset, "export count")
    }

    /// Checks a resource node count against [`Limits::max_resource_nodes`].
    ///
    /// # Errors
    ///
    /// Returns `LimitExceeded` if `count` is too large.
    pub fn check_resource_nodes(&self, count: usize, offset: usize) -> Result<(), ParseError> {
        self.check_usize(
            count,
            self.max_resource_nodes,
            offset,
            "resource node count",
        )
    }

    /// Checks a resource tree depth against [`Limits::max_resource_depth`].
    ///
    /// # Errors
    ///
    /// Returns `LimitExceeded` if `depth` is too large.
    pub fn check_resource_depth(&self, depth: u8, offset: usize) -> Result<(), ParseError> {
        if depth > self.max_resource_depth {
            return Err(ParseError::limit_exceeded(offset, "resource depth")
                .with_values(u64::from(self.max_resource_depth), u64::from(depth)));
        }
        Ok(())
    }

    /// Checks a string length against [`Limits::max_string_len`].
    ///
    /// # Errors
    ///
    /// Returns `LimitExceeded` if `len` is too large.
    pub fn check_string(&self, len: usize, offset: usize) -> Result<(), ParseError> {
        self.check_usize(len, self.max_string_len, offset, "string length")
    }

    /// Checks a thunk count against [`Limits::max_thunks_per_import`].
    ///
    /// # Errors
    ///
    /// Returns `LimitExceeded` if `count` is too large.
    pub fn check_thunks(&self, count: usize, offset: usize) -> Result<(), ParseError> {
        self.check_usize(count, self.max_thunks_per_import, offset, "thunk count")
    }

    fn check_usize(
        &self,
        value: usize,
        limit: usize,
        offset: usize,
        context: &'static str,
    ) -> Result<(), ParseError> {
        if value > limit {
            return Err(
                ParseError::limit_exceeded(offset, context).with_values(limit as u64, value as u64)
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Limits;
    use crate::{ErrorKind, spec};

    #[test]
    fn defaults_are_safety_caps() {
        let limits = Limits::default();
        assert_eq!(limits.max_file_size, 512 * 1024 * 1024);
        assert_eq!(limits.max_sections, 4096);
        assert_eq!(limits.max_directories, 4096);
        assert_eq!(limits.max_imports, 65536);
        assert_eq!(limits.max_exports, 65536);
        assert_eq!(limits.max_resource_nodes, 65536);
        assert_eq!(limits.max_resource_depth, 32);
        assert_eq!(limits.max_string_len, 4096);
        assert_eq!(limits.max_thunks_per_import, 65536);
        assert_eq!(limits.max_entropy_window, 4096);
    }

    #[test]
    fn safety_caps_are_above_spec_thresholds() {
        let limits = Limits::default();
        assert!(limits.max_sections > spec::MAX_SECTIONS);
        assert!(limits.max_directories > spec::MAX_DATA_DIRECTORIES);
        assert!(limits.max_resource_depth > spec::RESOURCE_TREE_DEPTH);
    }

    #[test]
    fn file_size_limit_is_inclusive() {
        let limits = Limits::default();
        assert!(limits.check_file_size(0).is_ok());
        assert!(limits.check_file_size(limits.max_file_size).is_ok());
        let error = limits
            .check_file_size(limits.max_file_size + 1)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::LimitExceeded);
        assert_eq!(error.offset(), 0);
        assert_eq!(error.expected(), Some(limits.max_file_size));
        assert_eq!(error.actual(), Some(limits.max_file_size + 1));
    }

    #[test]
    fn section_count_boundary() {
        let limits = Limits::default();
        assert!(limits.check_sections(0, 0x100).is_ok());
        assert!(limits.check_sections(limits.max_sections, 0x100).is_ok());
        let error = limits
            .check_sections(limits.max_sections + 1, 0x100)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::LimitExceeded);
        assert_eq!(error.offset(), 0x100);
        assert_eq!(error.expected(), Some(limits.max_sections as u64));
        assert_eq!(error.actual(), Some((limits.max_sections + 1) as u64));
    }

    #[test]
    fn spec_violation_is_below_the_safety_cap() {
        let limits = Limits::default();
        // 97 sections violate the specification but must still be parseable.
        assert!(limits.check_sections(spec::MAX_SECTIONS + 1, 0).is_ok());
    }

    #[test]
    fn string_length_boundary() {
        let limits = Limits::default();
        assert!(limits.check_string(limits.max_string_len, 0).is_ok());
        assert_eq!(
            limits
                .check_string(limits.max_string_len + 1, 0)
                .unwrap_err()
                .kind(),
            ErrorKind::LimitExceeded
        );
    }

    #[test]
    fn resource_depth_boundary() {
        let limits = Limits::default();
        assert!(
            limits
                .check_resource_depth(limits.max_resource_depth, 0)
                .is_ok()
        );
        let error = limits
            .check_resource_depth(limits.max_resource_depth + 1, 0)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::LimitExceeded);
        assert_eq!(error.expected(), Some(u64::from(limits.max_resource_depth)));
    }

    #[test]
    fn every_check_reports_its_context() {
        let limits = Limits::default();
        assert_eq!(
            limits
                .check_directories(limits.max_directories + 1, 0)
                .unwrap_err()
                .context(),
            "directory count"
        );
        assert_eq!(
            limits
                .check_imports(limits.max_imports + 1, 0)
                .unwrap_err()
                .context(),
            "import count"
        );
        assert_eq!(
            limits
                .check_exports(limits.max_exports + 1, 0)
                .unwrap_err()
                .context(),
            "export count"
        );
        assert_eq!(
            limits
                .check_resource_nodes(limits.max_resource_nodes + 1, 0)
                .unwrap_err()
                .context(),
            "resource node count"
        );
        assert_eq!(
            limits
                .check_thunks(limits.max_thunks_per_import + 1, 0)
                .unwrap_err()
                .context(),
            "thunk count"
        );
    }

    #[test]
    fn custom_limits_can_be_stricter() {
        let limits = Limits {
            max_sections: 2,
            ..Limits::default()
        };
        assert!(limits.check_sections(2, 0).is_ok());
        assert!(limits.check_sections(3, 0).is_err());
    }
}
