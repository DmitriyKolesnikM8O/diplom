//! Builders for synthetic PE images.
//!
//! Tests need valid images that are easy to break in one specific place. A
//! hand-written byte blob is unreadable and silently rots; this builder emits a
//! minimal but structurally valid image and exposes the offsets of every
//! structure, so a test can patch exactly one field.
//!
//! The module is part of the public API because integration tests and `xtask`
//! experiments use it too. It is not needed by the analyzer itself.

use crate::pe::{PE_SIGNATURE, coff, dos, optional, section};

/// Size of the file headers before the section data.
const HEADERS_SIZE: usize = 0x200;

/// Size of the single `.text` section.
const RAW_SIZE: usize = 0x200;

/// Number of data directories in a generated image.
const DIRECTORY_COUNT: u32 = 16;

/// Builds a minimal, structurally valid PE image.
///
/// The generated image has one `.text` section, 16 empty data directories and
/// a 512-byte header area. Use [`PeBuilder::pe32`] or [`PeBuilder::pe32plus`]
/// and then patch individual fields.
#[derive(Debug, Clone)]
pub struct PeBuilder {
    bytes: Vec<u8>,
    pe_offset: usize,
    coff_offset: usize,
    optional_offset: usize,
    directories_offset: usize,
    sections_offset: usize,
    optional_size: usize,
}

impl PeBuilder {
    /// Creates a `PE32` image with an x86 COFF header.
    #[must_use]
    pub fn pe32() -> Self {
        Self::new(false)
    }

    /// Creates a `PE32+` image with an AMD64 COFF header.
    #[must_use]
    pub fn pe32plus() -> Self {
        Self::new(true)
    }

    fn new(pe32plus: bool) -> Self {
        let fixed_size = if pe32plus {
            optional::PE32PLUS_FIXED_SIZE
        } else {
            optional::PE32_FIXED_SIZE
        };
        let optional_size = fixed_size + (DIRECTORY_COUNT as usize) * optional::DIRECTORY_SIZE;
        let pe_offset = dos::DOS_HEADER_SIZE;
        let coff_offset = pe_offset + PE_SIGNATURE.len();
        let optional_offset = coff_offset + coff::COFF_HEADER_SIZE;
        let directories_offset = optional_offset + fixed_size;
        let sections_offset = optional_offset + optional_size;

        let mut bytes = Vec::with_capacity(HEADERS_SIZE + RAW_SIZE);

        // DOS header: "MZ", zero padding, e_lfanew at 0x3C.
        bytes.extend_from_slice(b"MZ");
        bytes.resize(dos::E_LFANEW_OFFSET, 0);
        bytes.extend_from_slice(&(pe_offset as u32).to_le_bytes());

        // PE signature.
        bytes.extend_from_slice(&PE_SIGNATURE);

        // COFF header.
        let machine = if pe32plus {
            coff::MACHINE_AMD64
        } else {
            coff::MACHINE_I386
        };
        let characteristics = if pe32plus {
            coff::FILE_EXECUTABLE_IMAGE
        } else {
            coff::FILE_EXECUTABLE_IMAGE | coff::FILE_32BIT_MACHINE
        };
        bytes.extend_from_slice(&machine.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes()); // NumberOfSections
        bytes.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        bytes.extend_from_slice(&0u32.to_le_bytes()); // PointerToSymbolTable
        bytes.extend_from_slice(&0u32.to_le_bytes()); // NumberOfSymbols
        bytes.extend_from_slice(&(optional_size as u16).to_le_bytes());
        bytes.extend_from_slice(&characteristics.to_le_bytes());

        // Optional header.
        if pe32plus {
            Self::write_pe32plus_optional(&mut bytes);
        } else {
            Self::write_pe32_optional(&mut bytes);
        }
        // Data directories: all empty.
        bytes.resize(
            directories_offset + (DIRECTORY_COUNT as usize) * optional::DIRECTORY_SIZE,
            0,
        );

        // Section table: one ".text" section.
        bytes.extend_from_slice(b".text\0\0\0");
        bytes.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
        bytes.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        bytes.extend_from_slice(&(RAW_SIZE as u32).to_le_bytes()); // SizeOfRawData
        bytes.extend_from_slice(&(HEADERS_SIZE as u32).to_le_bytes()); // PointerToRawData
        bytes.extend_from_slice(&0u32.to_le_bytes()); // PointerToRelocations
        bytes.extend_from_slice(&0u32.to_le_bytes()); // PointerToLinenumbers
        bytes.extend_from_slice(&0u16.to_le_bytes()); // NumberOfRelocations
        bytes.extend_from_slice(&0u16.to_le_bytes()); // NumberOfLinenumbers
        let section_characteristics =
            section::SCN_CNT_CODE | section::SCN_MEM_EXECUTE | section::SCN_MEM_READ;
        bytes.extend_from_slice(&section_characteristics.to_le_bytes());

        // Header padding and section data.
        bytes.resize(HEADERS_SIZE + RAW_SIZE, 0);

        Self {
            bytes,
            pe_offset,
            coff_offset,
            optional_offset,
            directories_offset,
            sections_offset,
            optional_size,
        }
    }

    fn write_pe32_optional(bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&optional::PE32_MAGIC.to_le_bytes());
        bytes.extend_from_slice(&[14, 0]); // linker version
        bytes.extend_from_slice(&(RAW_SIZE as u32).to_le_bytes()); // SizeOfCode
        bytes.extend_from_slice(&(RAW_SIZE as u32).to_le_bytes()); // SizeOfInitializedData
        bytes.extend_from_slice(&0u32.to_le_bytes()); // SizeOfUninitializedData
        bytes.extend_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
        bytes.extend_from_slice(&0x1000u32.to_le_bytes()); // BaseOfCode
        bytes.extend_from_slice(&0x2000u32.to_le_bytes()); // BaseOfData
        bytes.extend_from_slice(&0x0040_0000u32.to_le_bytes()); // ImageBase
        bytes.extend_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        bytes.extend_from_slice(&(RAW_SIZE as u32).to_le_bytes()); // FileAlignment
        Self::write_versions(bytes);
        bytes.extend_from_slice(&0u32.to_le_bytes()); // Win32VersionValue
        bytes.extend_from_slice(&0x2000u32.to_le_bytes()); // SizeOfImage
        bytes.extend_from_slice(&(HEADERS_SIZE as u32).to_le_bytes()); // SizeOfHeaders
        bytes.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
        bytes.extend_from_slice(&optional::SUBSYSTEM_WINDOWS_CUI.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes()); // DllCharacteristics
        for _ in 0..4 {
            bytes.extend_from_slice(&0x10_0000u32.to_le_bytes()); // stack/heap
        }
        bytes.extend_from_slice(&0u32.to_le_bytes()); // LoaderFlags
        bytes.extend_from_slice(&DIRECTORY_COUNT.to_le_bytes());
    }

    fn write_pe32plus_optional(bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&optional::PE32PLUS_MAGIC.to_le_bytes());
        bytes.extend_from_slice(&[14, 0]); // linker version
        bytes.extend_from_slice(&(RAW_SIZE as u32).to_le_bytes()); // SizeOfCode
        bytes.extend_from_slice(&(RAW_SIZE as u32).to_le_bytes()); // SizeOfInitializedData
        bytes.extend_from_slice(&0u32.to_le_bytes()); // SizeOfUninitializedData
        bytes.extend_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
        bytes.extend_from_slice(&0x1000u32.to_le_bytes()); // BaseOfCode
        bytes.extend_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes()); // ImageBase
        bytes.extend_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        bytes.extend_from_slice(&(RAW_SIZE as u32).to_le_bytes()); // FileAlignment
        Self::write_versions(bytes);
        bytes.extend_from_slice(&0u32.to_le_bytes()); // Win32VersionValue
        bytes.extend_from_slice(&0x2000u32.to_le_bytes()); // SizeOfImage
        bytes.extend_from_slice(&(HEADERS_SIZE as u32).to_le_bytes()); // SizeOfHeaders
        bytes.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
        bytes.extend_from_slice(&optional::SUBSYSTEM_WINDOWS_CUI.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes()); // DllCharacteristics
        for _ in 0..4 {
            bytes.extend_from_slice(&0x10_0000u64.to_le_bytes()); // stack/heap
        }
        bytes.extend_from_slice(&0u32.to_le_bytes()); // LoaderFlags
        bytes.extend_from_slice(&DIRECTORY_COUNT.to_le_bytes());
    }

    fn write_versions(bytes: &mut Vec<u8>) {
        for _ in 0..6 {
            bytes.extend_from_slice(&6u16.to_le_bytes());
        }
    }

    /// Returns the generated image.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the builder and returns the generated image.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Returns the length of the generated image.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the generated image is empty, which never happens.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns the file offset of the PE signature.
    #[must_use]
    pub fn pe_offset(&self) -> usize {
        self.pe_offset
    }

    /// Returns the file offset of the COFF header.
    #[must_use]
    pub fn coff_offset(&self) -> usize {
        self.coff_offset
    }

    /// Returns the file offset of the optional header.
    #[must_use]
    pub fn optional_offset(&self) -> usize {
        self.optional_offset
    }

    /// Returns the file offset of the data directory array.
    #[must_use]
    pub fn directories_offset(&self) -> usize {
        self.directories_offset
    }

    /// Returns the file offset of the section table.
    #[must_use]
    pub fn sections_offset(&self) -> usize {
        self.sections_offset
    }

    /// Returns the value of `SizeOfOptionalHeader` in the generated image.
    #[must_use]
    pub fn optional_size(&self) -> usize {
        self.optional_size
    }

    /// Overwrites bytes at `offset`, returning `false` if the range is invalid.
    pub fn patch_bytes(&mut self, offset: usize, value: &[u8]) -> bool {
        let Some(end) = offset.checked_add(value.len()) else {
            return false;
        };
        let Some(slot) = self.bytes.get_mut(offset..end) else {
            return false;
        };
        slot.copy_from_slice(value);
        true
    }

    /// Overwrites a little-endian `u16` at `offset`.
    pub fn patch_u16(&mut self, offset: usize, value: u16) -> bool {
        self.patch_bytes(offset, &value.to_le_bytes())
    }

    /// Overwrites a little-endian `u32` at `offset`.
    pub fn patch_u32(&mut self, offset: usize, value: u32) -> bool {
        self.patch_bytes(offset, &value.to_le_bytes())
    }

    /// Overwrites a little-endian `u64` at `offset`.
    pub fn patch_u64(&mut self, offset: usize, value: u64) -> bool {
        self.patch_bytes(offset, &value.to_le_bytes())
    }

    /// Shortens the image to `len` bytes.
    pub fn truncate(&mut self, len: usize) {
        self.bytes.truncate(len.min(self.bytes.len()));
    }
}

#[cfg(test)]
mod tests {
    use super::{HEADERS_SIZE, PeBuilder, RAW_SIZE};
    use crate::limits::Limits;
    use crate::pe::{PeFile, coff, dos, optional, section};

    #[test]
    fn generated_pe32_is_valid() {
        let builder = PeBuilder::pe32();
        assert_eq!(builder.len(), HEADERS_SIZE + RAW_SIZE);
        assert_eq!(builder.pe_offset(), dos::DOS_HEADER_SIZE);
        assert_eq!(
            builder.coff_offset(),
            builder.pe_offset() + super::PE_SIGNATURE.len()
        );
        assert_eq!(
            builder.sections_offset(),
            builder.optional_offset() + builder.optional_size()
        );
        assert_eq!(
            builder.optional_size(),
            optional::PE32_FIXED_SIZE + 16 * optional::DIRECTORY_SIZE
        );

        let file = PeFile::parse(builder.bytes(), &Limits::default());
        assert!(file.diagnostics.is_empty(), "{:?}", file.diagnostics);
        assert_eq!(file.coff.unwrap().machine, coff::MACHINE_I386);
        assert_eq!(file.sections.len(), 1);
        assert_eq!(
            file.sections.first().unwrap().characteristics & section::SCN_MEM_EXECUTE,
            section::SCN_MEM_EXECUTE
        );
    }

    #[test]
    fn generated_pe32plus_is_valid() {
        let builder = PeBuilder::pe32plus();
        let file = PeFile::parse(builder.bytes(), &Limits::default());
        assert!(file.diagnostics.is_empty(), "{:?}", file.diagnostics);
        assert_eq!(file.coff.unwrap().machine, coff::MACHINE_AMD64);
        assert_eq!(file.optional.unwrap().magic, optional::PE32PLUS_MAGIC);
    }

    #[test]
    fn patch_helpers_write_little_endian() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(builder.pe_offset(), 0x1234));
        assert!(builder.patch_u32(builder.pe_offset() + 2, 0xDEAD_BEEF));
        let bytes = builder.bytes();
        assert_eq!(
            bytes.get(builder.pe_offset()..builder.pe_offset() + 2),
            Some([0x34, 0x12].as_slice())
        );
        assert_eq!(
            bytes.get(builder.pe_offset() + 2..builder.pe_offset() + 6),
            Some([0xEF, 0xBE, 0xAD, 0xDE].as_slice())
        );
    }

    #[test]
    fn patch_out_of_bounds_is_rejected() {
        let mut builder = PeBuilder::pe32();
        assert!(!builder.patch_bytes(builder.len(), b"x"));
        assert!(!builder.patch_u32(usize::MAX, 0));
    }

    #[test]
    fn truncate_stops_at_the_end() {
        let mut builder = PeBuilder::pe32();
        let len = builder.len();
        builder.truncate(len + 100);
        assert_eq!(builder.len(), len);
        builder.truncate(10);
        assert_eq!(builder.len(), 10);
    }
}
