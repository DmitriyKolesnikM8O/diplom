//! COFF file header.
//!
//! The 20-byte header that follows the PE signature. It declares the target
//! machine, the number of sections and the size of the optional header — the
//! last field decides where the section table starts, so a wrong value is a
//! classic parser-differential trigger.

use crate::bytes::Reader;
use crate::error::ParseError;

/// Size of the COFF file header.
pub const COFF_HEADER_SIZE: usize = 20;

/// Offset of `NumberOfSections` inside the COFF header.
pub const NUMBER_OF_SECTIONS_OFFSET: usize = 2;

/// Offset of `SizeOfOptionalHeader` inside the COFF header.
pub const SIZE_OF_OPTIONAL_HEADER_OFFSET: usize = 16;

/// Offset of `Characteristics` inside the COFF header.
pub const CHARACTERISTICS_OFFSET: usize = 18;

/// The target machine is unknown.
pub const MACHINE_UNKNOWN: u16 = 0x0000;
/// Intel 386 or later, x86.
pub const MACHINE_I386: u16 = 0x014C;
/// ARM Thumb-2 (little endian).
pub const MACHINE_ARMNT: u16 = 0x01C4;
/// Intel Itanium.
pub const MACHINE_IA64: u16 = 0x0200;
/// EFI byte code.
pub const MACHINE_EBC: u16 = 0x0EBC;
/// RISC-V 32-bit.
pub const MACHINE_RISCV32: u16 = 0x5032;
/// RISC-V 64-bit.
pub const MACHINE_RISCV64: u16 = 0x5064;
/// x64.
pub const MACHINE_AMD64: u16 = 0x8664;
/// ARM64.
pub const MACHINE_ARM64: u16 = 0xAA64;

/// Relocation information was stripped.
pub const FILE_RELOCS_STRIPPED: u16 = 0x0001;
/// The image is executable.
pub const FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
/// The image can handle addresses larger than 2 GiB.
pub const FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
/// The machine is based on a 32-bit word architecture.
pub const FILE_32BIT_MACHINE: u16 = 0x0100;
/// The image is a system file, not a user program.
pub const FILE_SYSTEM: u16 = 0x1000;
/// The image is a DLL.
pub const FILE_DLL: u16 = 0x2000;

/// The parsed COFF file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoffHeader {
    /// File offset of the header.
    pub offset: usize,
    /// `Machine`: the target architecture.
    pub machine: u16,
    /// `NumberOfSections`.
    pub number_of_sections: u16,
    /// `TimeDateStamp`: seconds since the Unix epoch, or a reproducible-build hash.
    pub time_date_stamp: u32,
    /// `PointerToSymbolTable`: file offset of the COFF symbol table.
    pub pointer_to_symbol_table: u32,
    /// `NumberOfSymbols`.
    pub number_of_symbols: u32,
    /// `SizeOfOptionalHeader`: number of bytes between this header and the
    /// section table.
    pub size_of_optional_header: u16,
    /// `Characteristics`: image flags.
    pub characteristics: u16,
}

impl CoffHeader {
    /// Parses the COFF header at `offset` in `data`.
    ///
    /// # Errors
    ///
    /// Returns `UnexpectedEof` if fewer than 20 bytes are available at
    /// `offset`, and `OutOfBounds` if `offset` is past the end of the input.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, ParseError> {
        let mut reader = Reader::new(data).sub_reader(offset, COFF_HEADER_SIZE)?;
        Ok(Self {
            offset,
            machine: reader.read_u16()?,
            number_of_sections: reader.read_u16()?,
            time_date_stamp: reader.read_u32()?,
            pointer_to_symbol_table: reader.read_u32()?,
            number_of_symbols: reader.read_u32()?,
            size_of_optional_header: reader.read_u16()?,
            characteristics: reader.read_u16()?,
        })
    }

    /// Returns `true` if [`FILE_DLL`] is set.
    #[must_use]
    pub const fn is_dll(&self) -> bool {
        self.characteristics & FILE_DLL != 0
    }

    /// Returns `true` if [`FILE_EXECUTABLE_IMAGE`] is set.
    #[must_use]
    pub const fn is_executable_image(&self) -> bool {
        self.characteristics & FILE_EXECUTABLE_IMAGE != 0
    }

    /// Returns `true` if [`FILE_32BIT_MACHINE`] is set.
    #[must_use]
    pub const fn is_32bit_machine(&self) -> bool {
        self.characteristics & FILE_32BIT_MACHINE != 0
    }

    /// Returns `true` if [`FILE_SYSTEM`] is set.
    #[must_use]
    pub const fn is_system_file(&self) -> bool {
        self.characteristics & FILE_SYSTEM != 0
    }

    /// Returns `true` if [`FILE_RELOCS_STRIPPED`] is set.
    #[must_use]
    pub const fn relocations_stripped(&self) -> bool {
        self.characteristics & FILE_RELOCS_STRIPPED != 0
    }

    /// Returns a short human-readable name of the target machine.
    #[must_use]
    pub const fn machine_name(&self) -> Option<&'static str> {
        match self.machine {
            MACHINE_I386 => Some("i386"),
            MACHINE_AMD64 => Some("amd64"),
            MACHINE_ARMNT => Some("armnt"),
            MACHINE_ARM64 => Some("arm64"),
            MACHINE_IA64 => Some("ia64"),
            MACHINE_EBC => Some("ebc"),
            MACHINE_RISCV32 => Some("riscv32"),
            MACHINE_RISCV64 => Some("riscv64"),
            MACHINE_UNKNOWN => Some("unknown"),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        COFF_HEADER_SIZE, CoffHeader, FILE_32BIT_MACHINE, FILE_DLL, FILE_EXECUTABLE_IMAGE,
        FILE_SYSTEM, MACHINE_AMD64, MACHINE_I386,
    };
    use crate::ErrorKind;

    fn coff_bytes() -> Vec<u8> {
        let mut bytes = Vec::with_capacity(COFF_HEADER_SIZE);
        bytes.extend_from_slice(&MACHINE_I386.to_le_bytes());
        bytes.extend_from_slice(&3u16.to_le_bytes());
        bytes.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0xE0u16.to_le_bytes());
        bytes.extend_from_slice(&(FILE_EXECUTABLE_IMAGE | FILE_32BIT_MACHINE).to_le_bytes());
        bytes
    }

    #[test]
    fn parses_all_fields() {
        let header = CoffHeader::parse(&coff_bytes(), 0).unwrap();
        assert_eq!(header.offset, 0);
        assert_eq!(header.machine, MACHINE_I386);
        assert_eq!(header.number_of_sections, 3);
        assert_eq!(header.time_date_stamp, 0x1234_5678);
        assert_eq!(header.pointer_to_symbol_table, 0);
        assert_eq!(header.number_of_symbols, 0);
        assert_eq!(header.size_of_optional_header, 0xE0);
        assert!(header.is_executable_image());
        assert!(header.is_32bit_machine());
        assert!(!header.is_dll());
        assert!(!header.is_system_file());
        assert!(!header.relocations_stripped());
        assert_eq!(header.machine_name(), Some("i386"));
    }

    #[test]
    fn parses_at_an_offset() {
        let mut bytes = vec![0xAA; 8];
        bytes.extend_from_slice(&coff_bytes());
        let header = CoffHeader::parse(&bytes, 8).unwrap();
        assert_eq!(header.offset, 8);
        assert_eq!(header.machine, MACHINE_I386);
    }

    #[test]
    fn machine_names() {
        let mut bytes = coff_bytes();
        if let Some(slot) = bytes.get_mut(..2) {
            slot.copy_from_slice(&MACHINE_AMD64.to_le_bytes());
        }
        let header = CoffHeader::parse(&bytes, 0).unwrap();
        assert_eq!(header.machine_name(), Some("amd64"));

        if let Some(slot) = bytes.get_mut(..2) {
            slot.copy_from_slice(&0x7777u16.to_le_bytes());
        }
        let header = CoffHeader::parse(&bytes, 0).unwrap();
        assert_eq!(header.machine_name(), None);
    }

    #[test]
    fn flags_are_independent() {
        let mut bytes = coff_bytes();
        if let Some(slot) = bytes.get_mut(18..20) {
            slot.copy_from_slice(&(FILE_DLL | FILE_SYSTEM).to_le_bytes());
        }
        let header = CoffHeader::parse(&bytes, 0).unwrap();
        assert!(header.is_dll());
        assert!(header.is_system_file());
        assert!(!header.is_executable_image());
        assert!(!header.is_32bit_machine());
    }

    #[test]
    fn short_input_at_offset_is_out_of_bounds() {
        let bytes = coff_bytes();
        let error = CoffHeader::parse(&bytes, 1).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::OutOfBounds);
    }

    #[test]
    fn offset_past_end_is_out_of_bounds() {
        let bytes = coff_bytes();
        let error = CoffHeader::parse(&bytes, 100).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::OutOfBounds);
    }
}
