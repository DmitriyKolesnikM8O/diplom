//! Values fixed by the PE/COFF specification.
//!
//! These are conformance thresholds, not safety caps. Exceeding one is a
//! finding for a rule, never a reason to stop parsing: a file with 100 sections
//! still has to be analyzed. Safety caps live in [`crate::limits::Limits`].

/// Minimum number of sections in an image.
///
/// The specification requires at least one section; zero is malformed.
pub const MIN_SECTIONS: usize = 1;

/// Maximum number of sections allowed by the specification and the Windows
/// loader.
///
/// Values above this are a conformance finding (`PE-COFF-001`), but the parser
/// still reads the table up to the safety cap.
pub const MAX_SECTIONS: usize = 96;

/// Number of data directories defined by the PE specification.
///
/// The loader ignores entries beyond this count even when
/// `NumberOfRvaAndSizes` claims more.
pub const MAX_DATA_DIRECTORIES: usize = 16;

/// Resource tree depth defined by the PE specification: type, name, language.
pub const RESOURCE_TREE_DEPTH: u8 = 3;
