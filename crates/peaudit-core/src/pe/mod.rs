//! PE image model and parser.
//!
//! The parser walks the headers in order — DOS, PE signature, COFF, optional
//! header, data directories, section table — and never stops at the first
//! problem. Each failure becomes a [`Diagnostic`] and parsing continues with
//! whatever is still reachable (ADR-0003). This is what makes the analyzer
//! useful on hostile input: a broken optional header must not hide the section
//! table.
//!
//! Two different notions of "wrong" are kept apart:
//!
//! - [`ParseState`] describes **how far the parser got**, not whether the file
//!   conforms to the specification. A file with zero sections parses
//!   completely and is still malformed; that finding belongs to a rule.
//! - Safety limits in [`Limits`] stop work on hostile input. Exceeding one is
//!   reported as [`codes::LIMIT_EXCEEDED`], not as a specification finding.
//!
//! The same line splits diagnostics from findings (ADR-0005): a diagnostic
//! records a **decision the parser had to make** — it stopped early, clamped a
//! count, or skipped a substructure — because the resulting model then differs
//! from what the file declares. An anomaly that requires no decision, such as
//! zero sections, produces no diagnostic: the model represents it faithfully
//! (an empty vector) and a rule reports it.

pub mod checksum;
pub mod coff;
pub mod dos;
pub mod optional;
pub mod overlay;
pub mod rva;
pub mod section;

use crate::bytes::Reader;
use crate::codes;
use crate::error::{DiagCode, DiagSeverity, Diagnostic, ErrorKind, ParseError};
use crate::limits::Limits;
use crate::spec;

pub use checksum::{ChecksumInfo, compute_checksum};
pub use coff::CoffHeader;
pub use dos::DosHeader;
pub use optional::{DataDirectory, OptionalHeader};
pub use overlay::{DataRegion, OverlayInfo};
pub use rva::{RvaMapping, RvaResolution, RvaStrategy};
pub use section::SectionHeader;

/// The four-byte PE signature that follows the DOS header.
pub const PE_SIGNATURE: [u8; 4] = *b"PE\0\0";

/// How far the parser got with a file.
///
/// The state says nothing about conformance: a `Complete` parse only means
/// that every declared structure was read. Findings are produced by rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ParseState {
    /// No DOS header or no COFF header: the file is not a PE image.
    Failed,
    /// The image was recognized, but some structures are missing or truncated.
    Partial,
    /// Every declared structure was parsed without an error-level diagnostic.
    Complete,
}

impl ParseState {
    /// Returns the stable machine-readable name of this state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Failed => "failed",
            Self::Partial => "partial",
            Self::Complete => "complete",
        }
    }
}

impl core::fmt::Display for ParseState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// File offsets of the parsed structures.
///
/// Kept separately from the model so that a report can point at the exact
/// bytes behind a finding without recomputing offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StructureOffsets {
    /// Start of the DOS header, always `0` when present.
    pub dos: Option<usize>,
    /// Position of the `PE\0\0` signature.
    pub pe_signature: Option<usize>,
    /// Start of the COFF header.
    pub coff: Option<usize>,
    /// Start of the optional header.
    pub optional: Option<usize>,
    /// Start of the data directory array.
    pub directories: Option<usize>,
    /// Start of the section table.
    pub sections: Option<usize>,
}

/// A parsed PE image.
///
/// Fields are [`Option`]al because parsing is partial: a file may have a valid
/// DOS header and nothing else. `sections` and `directories` contain only the
/// entries that were actually read.
#[derive(Debug, Clone, Default)]
pub struct PeFile {
    /// The DOS header, present if the file starts with `MZ`.
    pub dos: Option<DosHeader>,
    /// The COFF header, present if the PE signature was found.
    pub coff: Option<CoffHeader>,
    /// The optional header of a `PE32` or `PE32+` image.
    pub optional: Option<OptionalHeader>,
    /// Data directory entries that were read.
    pub directories: Vec<DataDirectory>,
    /// Section table entries that were read.
    pub sections: Vec<SectionHeader>,
    /// File offsets of each structure.
    pub offsets: StructureOffsets,
    /// Parse-level problems, in the order they were found.
    ///
    /// Non-conformance that required no parsing decision is a finding for a
    /// rule, not a diagnostic (ADR-0005).
    pub diagnostics: Vec<Diagnostic>,
}

impl PeFile {
    /// Parses `data` with the given safety limits.
    ///
    /// This function never panics and never allocates more than the limits
    /// allow: at most `limits.max_sections` section headers and at most
    /// [`spec::MAX_DATA_DIRECTORIES`] directory entries are stored.
    #[must_use]
    pub fn parse(data: &[u8], limits: &Limits) -> Self {
        let mut parser = Parser {
            data,
            limits,
            file: Self::default(),
        };
        parser.run();
        parser.file
    }

    /// Returns how far the parser got.
    #[must_use]
    pub fn state(&self) -> ParseState {
        if self.dos.is_none() || self.coff.is_none() {
            return ParseState::Failed;
        }
        let declared = self
            .coff
            .map_or(0, |coff| usize::from(coff.number_of_sections));
        let complete =
            self.optional.is_some() && self.sections.len() == declared && !self.has_errors();
        if complete {
            ParseState::Complete
        } else {
            ParseState::Partial
        }
    }

    /// Returns `true` if any diagnostic has error severity.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity() == DiagSeverity::Error)
    }

    /// Returns the first section with the given name.
    ///
    /// Comparison is exact and case-sensitive; names are not trimmed.
    #[must_use]
    pub fn find_section(&self, name: &str) -> Option<&SectionHeader> {
        self.sections
            .iter()
            .find(|section| section.name_str() == Some(name))
    }

    /// Returns the end of the section table as the file declares it.
    ///
    /// Computed from the **declared** section count, not from the entries that
    /// were read: the loader needs room for every declared entry, and a
    /// truncated table is reported by `sections.truncated` on its own.
    ///
    /// Returns [`None`] when the COFF header or the table position is unknown.
    #[must_use]
    pub fn section_table_end(&self) -> Option<u64> {
        let start = self.offsets.sections?;
        let sections = self.coff?.number_of_sections;
        Some((start as u64).saturating_add(
            u64::from(sections).saturating_mul(section::SECTION_HEADER_SIZE as u64),
        ))
    }

    /// Returns `true` if a diagnostic with `code` was recorded.
    #[must_use]
    pub fn has_diagnostic(&self, code: DiagCode) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code() == code)
    }
}

struct Parser<'a> {
    data: &'a [u8],
    limits: &'a Limits,
    file: PeFile,
}

impl Parser<'_> {
    fn run(&mut self) {
        if let Err(error) = self.limits.check_file_size(self.data.len() as u64) {
            self.report_error(codes::LIMIT_EXCEEDED, error);
            return;
        }

        let Some(dos) = self.parse_dos() else {
            return;
        };
        let pe_offset = dos.pe_offset as usize;
        if pe_offset >= self.data.len() {
            // The out-of-range diagnostic was recorded while checking e_lfanew.
            return;
        }
        if !self.parse_pe_signature(pe_offset) {
            return;
        }

        let Some(coff_offset) = pe_offset.checked_add(PE_SIGNATURE.len()) else {
            self.report_error(
                codes::LIMIT_EXCEEDED,
                ParseError::overflow(pe_offset, "COFF header offset"),
            );
            return;
        };
        let Some(coff) = self.parse_coff(coff_offset) else {
            return;
        };

        let Some(optional_offset) = coff_offset.checked_add(coff::COFF_HEADER_SIZE) else {
            self.report_error(
                codes::LIMIT_EXCEEDED,
                ParseError::overflow(coff_offset, "optional header offset"),
            );
            return;
        };
        if let Some(header) = self.parse_optional(optional_offset, coff.size_of_optional_header) {
            let directories_offset = optional_offset.saturating_add(header.fixed_size());
            self.parse_directories(directories_offset, header);
        }

        // The loader finds the section table using SizeOfOptionalHeader, not
        // the size we actually parsed. Following the declared value is what
        // makes a mismatch visible instead of silently correcting it.
        let section_offset = if coff.size_of_optional_header == 0 {
            optional_offset
        } else {
            optional_offset.saturating_add(usize::from(coff.size_of_optional_header))
        };
        self.parse_sections(section_offset, coff);
    }

    fn parse_dos(&mut self) -> Option<DosHeader> {
        match DosHeader::parse(self.data) {
            Ok(dos) => {
                self.file.offsets.dos = Some(dos.offset);
                self.file.dos = Some(dos);
                self.check_pe_offset(dos);
                Some(dos)
            }
            Err(error) => {
                let code = if error.kind() == ErrorKind::UnexpectedEof {
                    codes::DOS_TRUNCATED
                } else {
                    codes::DOS_MZ_MISSING
                };
                self.report_error(code, error);
                None
            }
        }
    }

    fn check_pe_offset(&mut self, dos: DosHeader) {
        let offset = dos::E_LFANEW_OFFSET;
        let pe_offset = dos.pe_offset as usize;

        if pe_offset < dos::DOS_HEADER_SIZE {
            let error = ParseError::invalid_value(offset, "e_lfanew")
                .with_values(dos::DOS_HEADER_SIZE as u64, pe_offset as u64);
            self.file.diagnostics.push(
                Diagnostic::warning(codes::DOS_PE_OFFSET_TOO_SMALL)
                    .at(offset)
                    .caused_by(error),
            );
        } else if pe_offset % 4 != 0 {
            self.file
                .diagnostics
                .push(Diagnostic::info(codes::DOS_PE_OFFSET_UNALIGNED).at(offset));
        }

        if pe_offset >= self.data.len() {
            let error = ParseError::out_of_bounds(offset, "e_lfanew");
            self.report_error(codes::DOS_PE_OFFSET_OUT_OF_RANGE, error);
        }
    }

    fn parse_pe_signature(&mut self, offset: usize) -> bool {
        let mut probe = match Reader::new(self.data).sub_reader(offset, PE_SIGNATURE.len()) {
            Ok(probe) => probe,
            Err(_) => {
                self.report_error(
                    codes::PE_SIGNATURE_TRUNCATED,
                    ParseError::unexpected_eof(offset, "PE signature"),
                );
                return false;
            }
        };
        // The sub-reader was bounded to exactly four bytes, so this read cannot
        // fail; treating it as fallible keeps the parser free of `unwrap`.
        let Ok(actual) = probe.read_u32() else {
            self.report_error(
                codes::PE_SIGNATURE_TRUNCATED,
                ParseError::unexpected_eof(offset, "PE signature"),
            );
            return false;
        };
        let expected = u32::from_le_bytes(PE_SIGNATURE);
        if actual != expected {
            let error = ParseError::invalid_value(offset, "PE signature")
                .with_values(u64::from(expected), u64::from(actual));
            self.report_error(codes::PE_SIGNATURE_MISSING, error);
            return false;
        }
        self.file.offsets.pe_signature = Some(offset);
        true
    }

    fn parse_coff(&mut self, offset: usize) -> Option<CoffHeader> {
        match CoffHeader::parse(self.data, offset) {
            Ok(coff) => {
                self.file.offsets.coff = Some(offset);
                if coff.size_of_optional_header == 0 {
                    self.warn(
                        codes::COFF_MISSING_OPTIONAL_HEADER,
                        offset.saturating_add(coff::SIZE_OF_OPTIONAL_HEADER_OFFSET),
                    );
                }
                self.file.coff = Some(coff);
                Some(coff)
            }
            Err(error) => {
                self.report_error(codes::COFF_TRUNCATED, error);
                None
            }
        }
    }

    fn parse_optional(&mut self, offset: usize, declared_size: u16) -> Option<OptionalHeader> {
        if declared_size == 0 {
            return None;
        }
        let declared = usize::from(declared_size);

        match OptionalHeader::parse(self.data, offset) {
            Ok(header) => {
                if declared < header.fixed_size() {
                    let error = ParseError::invalid_value(offset, "SizeOfOptionalHeader")
                        .with_values(header.fixed_size() as u64, declared as u64);
                    self.file.diagnostics.push(
                        Diagnostic::warning(codes::OPTIONAL_SIZE_MISMATCH)
                            .at(offset)
                            .caused_by(error),
                    );
                }
                self.file.offsets.optional = Some(offset);
                self.file.optional = Some(header);
                Some(header)
            }
            Err(error) => {
                if error.actual() == Some(u64::from(optional::ROM_MAGIC)) {
                    self.warn(codes::OPTIONAL_ROM_UNSUPPORTED, offset);
                } else if error.kind() == ErrorKind::InvalidValue {
                    self.report_error(codes::OPTIONAL_BAD_MAGIC, error);
                } else {
                    self.report_error(codes::OPTIONAL_TRUNCATED, error);
                }
                None
            }
        }
    }

    /// Reads the data directory array.
    ///
    /// At most [`spec::MAX_DATA_DIRECTORIES`] entries are read: the loader never
    /// looks past them, so anything beyond the sixteenth entry is not part of
    /// the model. A larger declared count is reported by
    /// `optional.too-many-directories`, because the model then contains less
    /// than the file declares.
    fn parse_directories(&mut self, start: usize, header: OptionalHeader) {
        let declared = header.number_of_rva_and_sizes;
        let spec_limit = spec::MAX_DATA_DIRECTORIES as u32;

        if declared > spec_limit {
            let error = ParseError::invalid_value(header.offset, "NumberOfRvaAndSizes")
                .with_values(u64::from(spec_limit), u64::from(declared));
            self.file.diagnostics.push(
                Diagnostic::warning(codes::OPTIONAL_TOO_MANY_DIRECTORIES)
                    .at(header.offset)
                    .caused_by(error),
            );
        }

        let count = declared.min(spec_limit) as usize;
        if count == 0 {
            return;
        }

        self.file.offsets.directories = Some(start);
        for index in 0..count {
            let Some(delta) = index.checked_mul(optional::DIRECTORY_SIZE) else {
                break;
            };
            let Some(offset) = start.checked_add(delta) else {
                break;
            };
            match DataDirectory::parse(self.data, offset, index as u32) {
                Ok(directory) => self.file.directories.push(directory),
                Err(error) => {
                    // Truncation is an error, not a warning: the model is now
                    // missing entries the file declares, exactly as for a
                    // truncated section table.
                    self.report_error(codes::DIRECTORIES_TRUNCATED, error);
                    break;
                }
            }
        }
    }

    fn parse_sections(&mut self, start: usize, coff: CoffHeader) {
        let declared = usize::from(coff.number_of_sections);
        let mut count = declared;
        let safety = self.limits.max_sections;
        if count > safety {
            let error = ParseError::limit_exceeded(start, "section count")
                .with_values(safety as u64, count as u64);
            self.report_error(codes::LIMIT_EXCEEDED, error);
            count = safety;
        }
        // The table position is a property of the headers, not of the entries:
        // record it even when the table is empty, so derived values can tell
        // where the header region ends.
        self.file.offsets.sections = Some(start);
        if count == 0 {
            return;
        }

        for index in 0..count {
            let Some(delta) = index.checked_mul(section::SECTION_HEADER_SIZE) else {
                break;
            };
            let Some(offset) = start.checked_add(delta) else {
                break;
            };
            match SectionHeader::parse(self.data, offset) {
                Ok(header) => self.file.sections.push(header),
                Err(error) => {
                    self.report_error(codes::SECTIONS_TRUNCATED, error);
                    break;
                }
            }
        }
    }

    fn report_error(&mut self, code: DiagCode, error: ParseError) {
        self.file
            .diagnostics
            .push(Diagnostic::error(code).at(error.offset()).caused_by(error));
    }

    fn warn(&mut self, code: DiagCode, offset: usize) {
        self.file
            .diagnostics
            .push(Diagnostic::warning(code).at(offset));
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{ParseState, PeFile};
    use crate::DiagSeverity;
    use crate::codes;
    use crate::limits::Limits;
    use crate::pe::{coff, dos, optional, section};
    use crate::testutil::PeBuilder;

    fn parse(bytes: &[u8]) -> PeFile {
        PeFile::parse(bytes, &Limits::default())
    }

    fn xorshift(state: &mut u64) -> u64 {
        let mut value = *state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        *state = value;
        value
    }

    #[test]
    fn minimal_pe32_is_complete() {
        let builder = PeBuilder::pe32();
        let file = parse(builder.bytes());

        assert_eq!(file.state(), ParseState::Complete);
        assert!(file.diagnostics.is_empty(), "{:?}", file.diagnostics);

        let dos = file.dos.unwrap();
        assert_eq!(dos.pe_offset as usize, builder.pe_offset());

        let coff = file.coff.unwrap();
        assert_eq!(coff.machine, coff::MACHINE_I386);
        assert_eq!(coff.number_of_sections, 1);
        assert_eq!(
            coff.size_of_optional_header as usize,
            builder.optional_size()
        );

        let optional = file.optional.unwrap();
        assert_eq!(optional.magic, optional::PE32_MAGIC);
        assert_eq!(optional.image_base, 0x0040_0000);
        assert_eq!(optional.base_of_data, Some(0x2000));
        assert_eq!(optional.number_of_rva_and_sizes, 16);

        assert_eq!(file.directories.len(), 16);
        assert_eq!(file.sections.len(), 1);
        let text = file.sections.first().unwrap();
        assert_eq!(text.name_str(), Some(".text"));
        assert_eq!(text.virtual_address, 0x1000);
        assert_eq!(text.pointer_to_raw_data, 0x200);
        assert!(text.is_executable());
    }

    #[test]
    fn minimal_pe32plus_is_complete() {
        let builder = PeBuilder::pe32plus();
        let file = parse(builder.bytes());

        assert_eq!(file.state(), ParseState::Complete);
        assert!(file.diagnostics.is_empty(), "{:?}", file.diagnostics);

        let optional = file.optional.unwrap();
        assert_eq!(optional.magic, optional::PE32PLUS_MAGIC);
        assert!(optional.is_pe32_plus());
        assert_eq!(optional.base_of_data, None);
        assert_eq!(optional.image_base, 0x0000_0001_4000_0000);
    }

    #[test]
    fn offsets_are_recorded() {
        let builder = PeBuilder::pe32();
        let file = parse(builder.bytes());
        assert_eq!(file.offsets.dos, Some(0));
        assert_eq!(file.offsets.pe_signature, Some(builder.pe_offset()));
        assert_eq!(file.offsets.coff, Some(builder.coff_offset()));
        assert_eq!(file.offsets.optional, Some(builder.optional_offset()));
        assert_eq!(file.offsets.directories, Some(builder.directories_offset()));
        assert_eq!(file.offsets.sections, Some(builder.sections_offset()));
    }

    #[test]
    fn find_section_matches_exactly() {
        let file = parse(PeBuilder::pe32().bytes());
        assert!(file.find_section(".text").is_some());
        assert!(file.find_section(".TEXT").is_none());
        assert!(file.find_section("text").is_none());
    }

    #[test]
    fn missing_mz_fails() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_bytes(0, b"XX"));
        let file = parse(builder.bytes());

        assert_eq!(file.state(), ParseState::Failed);
        assert!(file.dos.is_none());
        assert!(file.has_diagnostic(codes::DOS_MZ_MISSING));
    }

    #[test]
    fn truncated_dos_fails() {
        let mut builder = PeBuilder::pe32();
        builder.truncate(10);
        let file = parse(builder.bytes());

        assert_eq!(file.state(), ParseState::Failed);
        assert!(file.has_diagnostic(codes::DOS_TRUNCATED));
    }

    #[test]
    fn bad_pe_signature_fails() {
        let mut builder = PeBuilder::pe32();
        let offset = builder.pe_offset();
        assert!(builder.patch_bytes(offset, b"PX\0\0"));
        let file = parse(builder.bytes());

        assert_eq!(file.state(), ParseState::Failed);
        assert!(file.coff.is_none());
        assert!(file.has_diagnostic(codes::PE_SIGNATURE_MISSING));
    }

    #[test]
    fn pe_offset_out_of_range_fails() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u32(dos::E_LFANEW_OFFSET, 0x00FF_FFFF));
        let file = parse(builder.bytes());

        assert_eq!(file.state(), ParseState::Failed);
        assert!(file.has_diagnostic(codes::DOS_PE_OFFSET_OUT_OF_RANGE));
    }

    #[test]
    fn pe_offset_inside_dos_header_is_a_warning() {
        let mut builder = PeBuilder::pe32();
        // Move the PE header into the middle of the DOS header. A loader still
        // follows e_lfanew, so the parser must keep going.
        assert!(builder.patch_bytes(0x20, b"PE\0\0"));
        assert!(builder.patch_u32(dos::E_LFANEW_OFFSET, 0x20));
        let file = parse(builder.bytes());

        assert!(file.has_diagnostic(codes::DOS_PE_OFFSET_TOO_SMALL));
        assert_eq!(file.offsets.pe_signature, Some(0x20));
    }

    #[test]
    fn unaligned_pe_offset_is_informational() {
        let builder = PeBuilder::pe32();
        let pe_offset = builder.pe_offset();
        let mut bytes = builder.into_bytes();
        // Insert one byte before the PE signature so that e_lfanew becomes
        // unaligned while the rest of the header chain stays contiguous.
        bytes.insert(pe_offset, 0);
        if let Some(slot) = bytes.get_mut(dos::E_LFANEW_OFFSET..dos::E_LFANEW_OFFSET + 4) {
            slot.copy_from_slice(&((pe_offset + 1) as u32).to_le_bytes());
        }

        let file = parse(&bytes);
        assert!(file.has_diagnostic(codes::DOS_PE_OFFSET_UNALIGNED));
        assert!(!file.has_diagnostic(codes::DOS_PE_OFFSET_TOO_SMALL));
        assert_eq!(file.offsets.pe_signature, Some(pe_offset + 1));
    }

    #[test]
    fn zero_sections_is_not_a_parse_problem() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(builder.coff_offset() + coff::NUMBER_OF_SECTIONS_OFFSET, 0));
        let file = parse(builder.bytes());

        // Nothing was skipped, so the parser has nothing to report: the model
        // shows an empty section table, and the conformance finding belongs to
        // a rule (ADR-0005).
        assert!(file.diagnostics.is_empty(), "{:?}", file.diagnostics);
        assert!(file.sections.is_empty());
        assert_eq!(file.state(), ParseState::Complete);
    }

    #[test]
    fn section_count_is_capped_by_safety_limit() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(
            builder.coff_offset() + coff::NUMBER_OF_SECTIONS_OFFSET,
            0xFFFF
        ));
        let limits = Limits {
            max_sections: 1,
            ..Limits::default()
        };
        let file = PeFile::parse(builder.bytes(), &limits);

        assert!(file.has_diagnostic(codes::LIMIT_EXCEEDED));
        assert_eq!(file.sections.len(), 1);
        assert_eq!(file.state(), ParseState::Partial);
    }

    #[test]
    fn truncated_section_table_is_partial() {
        let builder = PeBuilder::pe32();
        let section_offset = builder.sections_offset();
        let mut bytes = builder.into_bytes();
        bytes.truncate(section_offset + 20);
        let file = parse(&bytes);

        assert!(file.has_diagnostic(codes::SECTIONS_TRUNCATED));
        assert!(file.sections.is_empty());
        assert_eq!(file.state(), ParseState::Partial);
    }

    #[test]
    fn missing_optional_header_is_a_warning() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(
            builder.coff_offset() + coff::SIZE_OF_OPTIONAL_HEADER_OFFSET,
            0
        ));
        let file = parse(builder.bytes());

        assert!(file.has_diagnostic(codes::COFF_MISSING_OPTIONAL_HEADER));
        assert!(file.optional.is_none());
        // The section table is now read from directly after the COFF header,
        // which is what a loader would do.
        assert_eq!(file.offsets.sections, Some(builder.optional_offset()));
        assert_eq!(file.state(), ParseState::Partial);
    }

    #[test]
    fn bad_optional_magic_is_reported() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(builder.optional_offset(), 0x0999));
        let file = parse(builder.bytes());

        assert!(file.has_diagnostic(codes::OPTIONAL_BAD_MAGIC));
        assert!(file.optional.is_none());
        assert_eq!(file.state(), ParseState::Partial);
    }

    #[test]
    fn rom_magic_is_recognized_but_not_modeled() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(builder.optional_offset(), optional::ROM_MAGIC));
        let file = parse(builder.bytes());

        assert!(file.has_diagnostic(codes::OPTIONAL_ROM_UNSUPPORTED));
        assert!(file.optional.is_none());
        assert_eq!(file.state(), ParseState::Partial);
    }

    #[test]
    fn too_many_directories_is_clamped_to_sixteen() {
        let mut builder = PeBuilder::pe32();
        let offset = builder.optional_offset() + optional::PE32_NUMBER_OF_RVA_AND_SIZES_OFFSET;
        assert!(builder.patch_u32(offset, 100));
        let file = parse(builder.bytes());

        assert!(file.has_diagnostic(codes::OPTIONAL_TOO_MANY_DIRECTORIES));
        assert_eq!(file.directories.len(), 16);
    }

    #[test]
    fn truncated_directories_are_reported_as_an_error() {
        let builder = PeBuilder::pe32();
        let directories_offset = builder.directories_offset();
        let mut bytes = builder.into_bytes();
        bytes.truncate(directories_offset + 24);
        let file = parse(&bytes);

        let diagnostic = file
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code() == codes::DIRECTORIES_TRUNCATED)
            .expect("directories.truncated");
        assert_eq!(diagnostic.severity(), DiagSeverity::Error);
        assert_eq!(file.directories.len(), 3);
        assert_eq!(file.state(), ParseState::Partial);
    }

    #[test]
    fn truncated_directories_without_sections_are_not_complete() {
        // Regression: with `DIRECTORIES_TRUNCATED` as a warning and zero
        // declared sections, a file cut inside its own directory array used to
        // be reported as fully parsed.
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(builder.coff_offset() + coff::NUMBER_OF_SECTIONS_OFFSET, 0));
        let directories_offset = builder.directories_offset();
        let mut bytes = builder.into_bytes();
        bytes.truncate(directories_offset + 24);

        let file = parse(&bytes);
        assert!(file.has_diagnostic(codes::DIRECTORIES_TRUNCATED));
        assert_eq!(file.state(), ParseState::Partial);
    }

    #[test]
    fn zero_declared_directories_are_not_read() {
        let mut builder = PeBuilder::pe32();
        let offset = builder.optional_offset() + optional::PE32_NUMBER_OF_RVA_AND_SIZES_OFFSET;
        assert!(builder.patch_u32(offset, 0));
        let file = parse(builder.bytes());

        assert!(file.directories.is_empty());
        assert_eq!(file.offsets.directories, None);
        assert!(file.diagnostics.is_empty(), "{:?}", file.diagnostics);
        assert_eq!(file.state(), ParseState::Complete);
    }

    #[test]
    fn pe32_with_amd64_machine_is_still_parsed() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(builder.coff_offset(), coff::MACHINE_AMD64));
        let file = parse(builder.bytes());

        // The inconsistency is a finding for a rule, not a parse failure.
        assert_eq!(file.state(), ParseState::Complete);
        assert_eq!(file.coff.unwrap().machine, coff::MACHINE_AMD64);
    }

    #[test]
    fn optional_size_smaller_than_fixed_part_is_a_warning() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(
            builder.coff_offset() + coff::SIZE_OF_OPTIONAL_HEADER_OFFSET,
            40
        ));
        let file = parse(builder.bytes());

        assert!(file.has_diagnostic(codes::OPTIONAL_SIZE_MISMATCH));
        assert!(file.optional.is_some());
    }

    #[test]
    fn every_truncation_is_safe() {
        let builder = PeBuilder::pe32();
        let section_table_end = builder.sections_offset() + section::SECTION_HEADER_SIZE;
        let bytes = builder.into_bytes();
        let limits = Limits::default();
        for length in 0..bytes.len() {
            let Some(prefix) = bytes.get(..length) else {
                continue;
            };
            let file = PeFile::parse(prefix, &limits);
            if length < dos::DOS_HEADER_SIZE {
                assert_eq!(file.state(), ParseState::Failed, "length {length}");
            }
            // Below the end of the section table the declared structures cannot
            // all have been read, so the parse must not claim completeness.
            if length < section_table_end {
                assert_ne!(file.state(), ParseState::Complete, "length {length}");
            }
        }
        assert_eq!(
            PeFile::parse(&bytes, &limits).state(),
            ParseState::Complete,
            "the untruncated image must parse completely"
        );
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let limits = Limits::default();
        let mut state = 0x1234_5678_9ABC_DEF0_u64;
        for _ in 0..200 {
            let length = (xorshift(&mut state) % 1024) as usize;
            let mut bytes = vec![0u8; length];
            for byte in &mut bytes {
                *byte = (xorshift(&mut state) & 0xFF) as u8;
            }
            let _ = PeFile::parse(&bytes, &limits);
        }
    }

    /// Random bytes almost never reach the header chain; mutations of a valid
    /// image do, which is what makes this test worth its runtime.
    #[test]
    fn mutations_of_a_valid_image_never_panic() {
        let original = PeBuilder::pe32().into_bytes();
        let limits = Limits::default();
        let mut state = 0x0BAD_C0DE_1234_5678_u64;
        for _ in 0..1000 {
            let mut bytes = original.clone();
            let flips = 1 + (xorshift(&mut state) % 4) as usize;
            for _ in 0..flips {
                let index = (xorshift(&mut state) as usize) % bytes.len();
                let mask = 1u8 << (xorshift(&mut state) % 8);
                if let Some(byte) = bytes.get_mut(index) {
                    *byte ^= mask;
                }
            }
            let file = PeFile::parse(&bytes, &limits);
            let declared = file
                .coff
                .map_or(0, |coff| usize::from(coff.number_of_sections));
            assert!(
                file.sections.len() <= declared.min(limits.max_sections),
                "more sections than declared or allowed"
            );
            if file.state() == ParseState::Complete {
                assert_eq!(file.sections.len(), declared);
            }
        }
    }

    #[test]
    fn file_size_limit_is_enforced_before_parsing() {
        let limits = Limits {
            max_file_size: 16,
            ..Limits::default()
        };
        let file = PeFile::parse(PeBuilder::pe32().bytes(), &limits);

        assert_eq!(file.state(), ParseState::Failed);
        assert!(file.has_diagnostic(codes::LIMIT_EXCEEDED));
        assert!(file.dos.is_none() && file.coff.is_none() && file.optional.is_none());
        assert!(file.sections.is_empty() && file.directories.is_empty());
    }

    #[test]
    fn absurd_optional_size_moves_the_section_table() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(
            builder.coff_offset() + coff::SIZE_OF_OPTIONAL_HEADER_OFFSET,
            0x1000
        ));
        let file = parse(builder.bytes());

        // The optional header itself is intact, so it is still modeled; the
        // section table now sits past the end of the file.
        assert!(file.optional.is_some());
        assert!(file.has_diagnostic(codes::SECTIONS_TRUNCATED));
        assert!(file.sections.is_empty());
        assert_eq!(file.state(), ParseState::Partial);
    }

    #[test]
    fn pe_offset_zero_is_reported_and_stops() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u32(dos::E_LFANEW_OFFSET, 0));
        let file = parse(builder.bytes());

        assert!(file.has_diagnostic(codes::DOS_PE_OFFSET_TOO_SMALL));
        assert!(file.has_diagnostic(codes::PE_SIGNATURE_MISSING));
        assert_eq!(file.state(), ParseState::Failed);
    }

    #[test]
    fn duplicate_section_names_return_the_first() {
        let mut builder = PeBuilder::pe32();
        let first = builder.sections_offset();
        let second = first + section::SECTION_HEADER_SIZE;
        let entry = builder
            .bytes()
            .get(first..second)
            .expect("first section entry")
            .to_vec();
        assert!(builder.patch_bytes(second, &entry));
        assert!(builder.patch_u16(builder.coff_offset() + coff::NUMBER_OF_SECTIONS_OFFSET, 2));

        let file = parse(builder.bytes());
        assert_eq!(file.sections.len(), 2);
        assert_eq!(file.state(), ParseState::Complete);
        let found = file.find_section(".text").expect("section .text");
        assert_eq!(found.offset, first);
    }

    #[test]
    fn machine_names_cover_the_supported_architectures() {
        let mut builder = PeBuilder::pe32();
        let cases = [
            (coff::MACHINE_I386, Some("i386")),
            (coff::MACHINE_AMD64, Some("amd64")),
            (coff::MACHINE_ARMNT, Some("armnt")),
            (coff::MACHINE_ARM64, Some("arm64")),
            (coff::MACHINE_IA64, Some("ia64")),
            (coff::MACHINE_EBC, Some("ebc")),
            (coff::MACHINE_RISCV32, Some("riscv32")),
            (coff::MACHINE_RISCV64, Some("riscv64")),
            (coff::MACHINE_UNKNOWN, Some("unknown")),
            (0x7777, None),
        ];
        for (machine, expected) in cases {
            assert!(builder.patch_u16(builder.coff_offset(), machine));
            let file = parse(builder.bytes());
            let name = file.coff.expect("coff header").machine_name();
            assert_eq!(name, expected, "machine {machine:#06x}");
        }
    }

    /// Builds one input per registered code. The registry must not contain a
    /// code that no parser path can emit: such a code would be a lie in the
    /// report schema and a trap for whoever implements the matching rule.
    fn inputs_covering_every_code() -> Vec<(Vec<u8>, Limits)> {
        let default = Limits::default();
        let mut cases = Vec::new();

        // dos.truncated
        cases.push((Vec::new(), default));
        // dos.mz-missing
        cases.push((vec![b'X'; dos::DOS_HEADER_SIZE], default));

        // dos.pe-offset-too-small: signature moved into the DOS header.
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_bytes(0x20, &super::PE_SIGNATURE));
        assert!(builder.patch_u32(dos::E_LFANEW_OFFSET, 0x20));
        cases.push((builder.into_bytes(), default));

        // dos.pe-offset-out-of-range
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u32(dos::E_LFANEW_OFFSET, 0x00FF_FFFF));
        cases.push((builder.into_bytes(), default));

        // dos.pe-offset-unaligned
        let builder = PeBuilder::pe32();
        let pe_offset = builder.pe_offset();
        let mut bytes = builder.into_bytes();
        bytes.insert(pe_offset, 0);
        if let Some(slot) = bytes.get_mut(dos::E_LFANEW_OFFSET..dos::E_LFANEW_OFFSET + 4) {
            slot.copy_from_slice(&((pe_offset + 1) as u32).to_le_bytes());
        }
        cases.push((bytes, default));

        // pe.signature-missing
        let mut builder = PeBuilder::pe32();
        let offset = builder.pe_offset();
        assert!(builder.patch_bytes(offset, b"PX\0\0"));
        cases.push((builder.into_bytes(), default));

        // pe.signature-truncated
        let builder = PeBuilder::pe32();
        let end = builder.pe_offset() + 2;
        let mut bytes = builder.into_bytes();
        bytes.truncate(end);
        cases.push((bytes, default));

        // coff.truncated
        let builder = PeBuilder::pe32();
        let end = builder.coff_offset() + 10;
        let mut bytes = builder.into_bytes();
        bytes.truncate(end);
        cases.push((bytes, default));

        // coff.missing-optional-header
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(
            builder.coff_offset() + coff::SIZE_OF_OPTIONAL_HEADER_OFFSET,
            0
        ));
        cases.push((builder.into_bytes(), default));

        // optional.truncated
        let builder = PeBuilder::pe32();
        let end = builder.optional_offset() + 40;
        let mut bytes = builder.into_bytes();
        bytes.truncate(end);
        cases.push((bytes, default));

        // optional.bad-magic
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(builder.optional_offset(), 0x0999));
        cases.push((builder.into_bytes(), default));

        // optional.rom-unsupported
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(builder.optional_offset(), optional::ROM_MAGIC));
        cases.push((builder.into_bytes(), default));

        // optional.size-mismatch
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(
            builder.coff_offset() + coff::SIZE_OF_OPTIONAL_HEADER_OFFSET,
            40
        ));
        cases.push((builder.into_bytes(), default));

        // optional.too-many-directories
        let mut builder = PeBuilder::pe32();
        let offset = builder.optional_offset() + optional::PE32_NUMBER_OF_RVA_AND_SIZES_OFFSET;
        assert!(builder.patch_u32(offset, 100));
        cases.push((builder.into_bytes(), default));

        // directories.truncated
        let builder = PeBuilder::pe32();
        let end = builder.directories_offset() + 24;
        let mut bytes = builder.into_bytes();
        bytes.truncate(end);
        cases.push((bytes, default));

        // sections.truncated
        let builder = PeBuilder::pe32();
        let end = builder.sections_offset() + 20;
        let mut bytes = builder.into_bytes();
        bytes.truncate(end);
        cases.push((bytes, default));

        // limit.exceeded
        let small = Limits {
            max_file_size: 16,
            ..Limits::default()
        };
        cases.push((PeBuilder::pe32().into_bytes(), small));

        cases
    }

    #[test]
    fn every_registered_code_is_produced_by_some_input() {
        let mut produced: BTreeSet<&'static str> = BTreeSet::new();
        for (bytes, limits) in inputs_covering_every_code() {
            let file = PeFile::parse(&bytes, &limits);
            for diagnostic in &file.diagnostics {
                produced.insert(diagnostic.code().as_str());
            }
        }
        let registered: BTreeSet<&'static str> =
            codes::ALL.iter().map(|code| code.as_str()).collect();
        let missing: Vec<&str> = registered.difference(&produced).copied().collect();
        assert!(
            missing.is_empty(),
            "registered codes no input can produce: {missing:?}"
        );
    }

    #[test]
    fn empty_input_fails_cleanly() {
        let file = parse(&[]);
        assert_eq!(file.state(), ParseState::Failed);
        assert_eq!(file.diagnostics.len(), 1);
        assert_eq!(
            file.diagnostics.first().unwrap().severity(),
            DiagSeverity::Error
        );
    }

    #[test]
    fn section_size_constant_matches_entry() {
        assert_eq!(section::SECTION_HEADER_SIZE, 40);
        assert_eq!(optional::DIRECTORY_SIZE, 8);
        assert_eq!(super::PE_SIGNATURE.as_slice(), b"PE\0\0");
    }
}
