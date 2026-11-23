//! Section table entries.
//!
//! Each entry is 40 bytes and describes one section: where it lives in the
//! file, where it is mapped in memory and what it contains. The name is eight
//! bytes and is **not** NUL-terminated when it uses all eight; it is kept as
//! raw bytes, because hostile files put arbitrary data there.

use crate::bytes::Reader;
use crate::error::ParseError;

/// Size of one section table entry.
pub const SECTION_HEADER_SIZE: usize = 40;

/// Number of bytes reserved for the section name.
pub const SECTION_NAME_LEN: usize = 8;

/// `IMAGE_SCN_CNT_CODE`: the section contains executable code.
pub const SCN_CNT_CODE: u32 = 0x0000_0020;
/// `IMAGE_SCN_CNT_INITIALIZED_DATA`: the section contains initialized data.
pub const SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
/// `IMAGE_SCN_CNT_UNINITIALIZED_DATA`: the section contains uninitialized data.
pub const SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
/// `IMAGE_SCN_MEM_DISCARDABLE`: the section can be discarded after loading.
pub const SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
/// `IMAGE_SCN_MEM_NOT_CACHED`: the section must not be cached.
pub const SCN_MEM_NOT_CACHED: u32 = 0x0400_0000;
/// `IMAGE_SCN_MEM_NOT_PAGED`: the section must stay resident.
pub const SCN_MEM_NOT_PAGED: u32 = 0x0800_0000;
/// `IMAGE_SCN_MEM_SHARED`: the section is shared between processes.
pub const SCN_MEM_SHARED: u32 = 0x1000_0000;
/// `IMAGE_SCN_MEM_EXECUTE`: the section is executable.
pub const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// `IMAGE_SCN_MEM_READ`: the section is readable.
pub const SCN_MEM_READ: u32 = 0x4000_0000;
/// `IMAGE_SCN_MEM_WRITE`: the section is writable.
pub const SCN_MEM_WRITE: u32 = 0x8000_0000;

/// One entry of the section table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionHeader {
    /// File offset of this entry, not of the section data.
    pub offset: usize,
    /// Raw eight-byte name, without any transformation.
    pub name: [u8; SECTION_NAME_LEN],
    /// `VirtualSize`: the size of the section in memory.
    pub virtual_size: u32,
    /// `VirtualAddress`: the RVA where the section is mapped.
    pub virtual_address: u32,
    /// `SizeOfRawData`: the size of the section in the file.
    pub size_of_raw_data: u32,
    /// `PointerToRawData`: the file offset of the section data.
    pub pointer_to_raw_data: u32,
    /// `PointerToRelocations`.
    pub pointer_to_relocations: u32,
    /// `PointerToLinenumbers`.
    pub pointer_to_linenumbers: u32,
    /// `NumberOfRelocations`.
    pub number_of_relocations: u16,
    /// `NumberOfLinenumbers`.
    pub number_of_linenumbers: u16,
    /// `Characteristics`: section flags.
    pub characteristics: u32,
}

impl SectionHeader {
    /// Parses one section entry at `offset`.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than 40 bytes are available at `offset`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, ParseError> {
        let mut reader = Reader::new(data).sub_reader(offset, SECTION_HEADER_SIZE)?;
        Ok(Self {
            offset,
            name: reader.read_array::<SECTION_NAME_LEN>()?,
            virtual_size: reader.read_u32()?,
            virtual_address: reader.read_u32()?,
            size_of_raw_data: reader.read_u32()?,
            pointer_to_raw_data: reader.read_u32()?,
            pointer_to_relocations: reader.read_u32()?,
            pointer_to_linenumbers: reader.read_u32()?,
            number_of_relocations: reader.read_u16()?,
            number_of_linenumbers: reader.read_u16()?,
            characteristics: reader.read_u32()?,
        })
    }

    /// Returns the section name with trailing NUL bytes removed.
    ///
    /// The result may contain any byte, including non-UTF-8 sequences and
    /// embedded NULs; it is a view of the raw field, not a decoded string.
    #[must_use]
    pub fn name_bytes(&self) -> &[u8] {
        let end = self
            .name
            .iter()
            .rposition(|byte| *byte != 0)
            .map_or(0, |index| index + 1);
        self.name.get(..end).unwrap_or(&[])
    }

    /// Returns the section name as a string, or [`None`] if it is not valid
    /// UTF-8.
    #[must_use]
    pub fn name_str(&self) -> Option<&str> {
        core::str::from_utf8(self.name_bytes()).ok()
    }

    /// Returns `true` if [`SCN_MEM_EXECUTE`] is set.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.characteristics & SCN_MEM_EXECUTE != 0
    }

    /// Returns `true` if [`SCN_MEM_READ`] is set.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.characteristics & SCN_MEM_READ != 0
    }

    /// Returns `true` if [`SCN_MEM_WRITE`] is set.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.characteristics & SCN_MEM_WRITE != 0
    }

    /// Returns `true` if the section is both writable and executable.
    #[must_use]
    pub const fn is_writable_and_executable(&self) -> bool {
        self.is_writable() && self.is_executable()
    }

    /// Returns `true` if [`SCN_CNT_CODE`] is set.
    #[must_use]
    pub const fn contains_code(&self) -> bool {
        self.characteristics & SCN_CNT_CODE != 0
    }

    /// Returns `true` if [`SCN_CNT_INITIALIZED_DATA`] is set.
    #[must_use]
    pub const fn contains_initialized_data(&self) -> bool {
        self.characteristics & SCN_CNT_INITIALIZED_DATA != 0
    }

    /// Returns `true` if [`SCN_CNT_UNINITIALIZED_DATA`] is set.
    #[must_use]
    pub const fn contains_uninitialized_data(&self) -> bool {
        self.characteristics & SCN_CNT_UNINITIALIZED_DATA != 0
    }

    /// Returns `true` if the section has no data in the file.
    #[must_use]
    pub const fn has_raw_data(&self) -> bool {
        self.size_of_raw_data != 0 && self.pointer_to_raw_data != 0
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SCN_CNT_CODE, SCN_MEM_EXECUTE, SCN_MEM_READ, SCN_MEM_WRITE, SECTION_HEADER_SIZE,
        SectionHeader,
    };
    use crate::ErrorKind;

    fn section_bytes(name: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(SECTION_HEADER_SIZE);
        let mut raw_name = [0u8; 8];
        let copy_len = name.len().min(8);
        if let (Some(slot), Some(source)) = (raw_name.get_mut(..copy_len), name.get(..copy_len)) {
            slot.copy_from_slice(source);
        }
        bytes.extend_from_slice(&raw_name);
        bytes.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
        bytes.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        bytes.extend_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        bytes.extend_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData
        bytes.extend_from_slice(&0u32.to_le_bytes()); // PointerToRelocations
        bytes.extend_from_slice(&0u32.to_le_bytes()); // PointerToLinenumbers
        bytes.extend_from_slice(&0u16.to_le_bytes()); // NumberOfRelocations
        bytes.extend_from_slice(&0u16.to_le_bytes()); // NumberOfLinenumbers
        bytes.extend_from_slice(
            &(SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ | SCN_MEM_WRITE).to_le_bytes(),
        );
        bytes
    }

    #[test]
    fn parses_all_fields() {
        let bytes = section_bytes(b".text");
        assert_eq!(bytes.len(), SECTION_HEADER_SIZE);
        let section = SectionHeader::parse(&bytes, 0).unwrap();
        assert_eq!(section.offset, 0);
        assert_eq!(section.name_bytes(), b".text".as_slice());
        assert_eq!(section.name_str(), Some(".text"));
        assert_eq!(section.virtual_size, 0x1000);
        assert_eq!(section.virtual_address, 0x1000);
        assert_eq!(section.size_of_raw_data, 0x200);
        assert_eq!(section.pointer_to_raw_data, 0x200);
        assert!(section.is_executable());
        assert!(section.is_readable());
        assert!(section.is_writable());
        assert!(section.is_writable_and_executable());
        assert!(section.contains_code());
        assert!(!section.contains_initialized_data());
        assert!(section.has_raw_data());
    }

    #[test]
    fn name_of_eight_bytes_is_not_terminated() {
        let bytes = section_bytes(b"12345678");
        let section = SectionHeader::parse(&bytes, 0).unwrap();
        assert_eq!(section.name_bytes(), b"12345678".as_slice());
        assert_eq!(section.name_str(), Some("12345678"));
    }

    #[test]
    fn name_with_inner_nul_keeps_it() {
        let bytes = section_bytes(b".a\0b");
        let section = SectionHeader::parse(&bytes, 0).unwrap();
        assert_eq!(section.name_bytes(), b".a\0b".as_slice());
        assert_eq!(section.name_str(), Some(".a\0b"));
    }

    #[test]
    fn empty_name_is_allowed() {
        let bytes = section_bytes(b"");
        let section = SectionHeader::parse(&bytes, 0).unwrap();
        assert!(section.name_bytes().is_empty());
        assert_eq!(section.name_str(), Some(""));
    }

    #[test]
    fn non_utf8_name_has_no_str() {
        let bytes = section_bytes(&[0xFF, 0xFE]);
        let section = SectionHeader::parse(&bytes, 0).unwrap();
        assert_eq!(section.name_bytes(), [0xFF, 0xFE].as_slice());
        assert_eq!(section.name_str(), None);
    }

    #[test]
    fn zero_section_is_not_executable() {
        let bytes = [0u8; SECTION_HEADER_SIZE];
        let section = SectionHeader::parse(&bytes, 0).unwrap();
        assert!(!section.is_executable());
        assert!(!section.is_writable());
        assert!(!section.is_readable());
        assert!(!section.has_raw_data());
    }

    #[test]
    fn truncated_entry_is_rejected() {
        let bytes = section_bytes(b".text");
        let error = SectionHeader::parse(&bytes, 1).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::OutOfBounds);
    }

    #[test]
    fn parses_at_an_offset() {
        let mut bytes = vec![0xAA; 4];
        bytes.extend_from_slice(&section_bytes(b".data"));
        let section = SectionHeader::parse(&bytes, 4).unwrap();
        assert_eq!(section.offset, 4);
        assert_eq!(section.name_bytes(), b".data".as_slice());
    }
}
