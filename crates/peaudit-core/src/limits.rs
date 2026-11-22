//! Parsing limits.
//!
//! Every unbounded structure in a PE file is a denial-of-service vector: a
//! crafted file can declare millions of sections, imports or resource nodes.
//! [`Limits`] caps each of them. Exceeding a limit produces a
//! [`ParseError`] of kind `LimitExceeded`; the parser records a diagnostic and
//! skips only the affected substructure (ADR-0003).
//!
//! The defaults follow `materials/roadmap.md` §4.6 and can be tightened or
//! raised by the caller.

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
    /// Maximum number of section table entries. Default: 96.
    ///
    /// The PE specification allows up to 96 sections; the Windows loader
    /// rejects images with more.
    pub max_sections: usize,
    /// Maximum number of data directories. Default: 16.
    ///
    /// The loader ignores entries beyond 16 even if `NumberOfRvaAndSizes`
    /// claims more.
    pub max_directories: usize,
    /// Maximum number of import descriptors. Default: 4096.
    pub max_imports: usize,
    /// Maximum number of export entries. Default: 4096.
    pub max_exports: usize,
    /// Maximum number of resource directory nodes. Default: 4096.
    pub max_resource_nodes: usize,
    /// Maximum resource tree depth. Default: 8.
    pub max_resource_depth: u8,
    /// Maximum length of a single string (section name, import name, PDB path).
    /// Default: 4096 bytes.
    pub max_string_len: usize,
    /// Maximum number of thunks per import descriptor. Default: 8192.
    pub max_thunks_per_import: usize,
    /// Maximum sliding window size used for entropy analysis. Default: 4096.
    pub max_entropy_window: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_size: 512 * 1024 * 1024,
            max_sections: 96,
            max_directories: 16,
            max_imports: 4096,
            max_exports: 4096,
            max_resource_nodes: 4096,
            max_resource_depth: 8,
            max_string_len: 4096,
            max_thunks_per_import: 8192,
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
            return Err(ParseError::limit_exceeded(0, "file size"));
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
            return Err(ParseError::limit_exceeded(offset, "resource depth"));
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
            return Err(ParseError::limit_exceeded(offset, context));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Limits;
    use crate::ErrorKind;

    #[test]
    fn defaults_match_the_roadmap() {
        let limits = Limits::default();
        assert_eq!(limits.max_file_size, 512 * 1024 * 1024);
        assert_eq!(limits.max_sections, 96);
        assert_eq!(limits.max_directories, 16);
        assert_eq!(limits.max_imports, 4096);
        assert_eq!(limits.max_exports, 4096);
        assert_eq!(limits.max_resource_nodes, 4096);
        assert_eq!(limits.max_resource_depth, 8);
        assert_eq!(limits.max_string_len, 4096);
        assert_eq!(limits.max_thunks_per_import, 8192);
        assert_eq!(limits.max_entropy_window, 4096);
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
    }

    #[test]
    fn section_count_boundary() {
        let limits = Limits::default();
        assert!(limits.check_sections(0, 0x100).is_ok());
        assert!(limits.check_sections(96, 0x100).is_ok());
        let error = limits.check_sections(97, 0x100).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::LimitExceeded);
        assert_eq!(error.offset(), 0x100);
    }

    #[test]
    fn string_length_boundary() {
        let limits = Limits::default();
        assert!(limits.check_string(4096, 0).is_ok());
        assert_eq!(
            limits.check_string(4097, 0).unwrap_err().kind(),
            ErrorKind::LimitExceeded
        );
    }

    #[test]
    fn resource_depth_boundary() {
        let limits = Limits::default();
        assert!(limits.check_resource_depth(8, 0).is_ok());
        assert_eq!(
            limits.check_resource_depth(9, 0).unwrap_err().kind(),
            ErrorKind::LimitExceeded
        );
    }

    #[test]
    fn every_check_reports_its_context() {
        let limits = Limits::default();
        assert_eq!(
            limits.check_directories(17, 0).unwrap_err().context(),
            "directory count"
        );
        assert_eq!(
            limits.check_imports(4097, 0).unwrap_err().context(),
            "import count"
        );
        assert_eq!(
            limits.check_exports(4097, 0).unwrap_err().context(),
            "export count"
        );
        assert_eq!(
            limits.check_resource_nodes(4097, 0).unwrap_err().context(),
            "resource node count"
        );
        assert_eq!(
            limits.check_thunks(8193, 0).unwrap_err().context(),
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
