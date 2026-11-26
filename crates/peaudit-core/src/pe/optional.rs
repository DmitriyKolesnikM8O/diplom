//! Optional header and data directories.
//!
//! The optional header is optional only in name: object files omit it, but
//! every image has one. Two layouts exist, `PE32` (`0x10B`) and `PE32+`
//! (`0x20B`); they differ in the width of `ImageBase`, the presence of
//! `BaseOfData` and the width of the stack and heap fields. The parser widens
//! all of them to 64 bits so that rules do not have to match on the layout.
//!
//! ROM images (`0x107`) are recognised but not modeled: they are a legacy
//! format with a different header, and the analyzer reports them as
//! unsupported instead of inventing fields.

use crate::bytes::Reader;
use crate::error::ParseError;

/// `PE32` optional header magic.
pub const PE32_MAGIC: u16 = 0x010B;
/// `PE32+` optional header magic.
pub const PE32PLUS_MAGIC: u16 = 0x020B;
/// ROM image optional header magic.
pub const ROM_MAGIC: u16 = 0x0107;

/// Size of the fixed part of a `PE32` optional header, without directories.
pub const PE32_FIXED_SIZE: usize = 96;
/// Size of the fixed part of a `PE32+` optional header, without directories.
pub const PE32PLUS_FIXED_SIZE: usize = 112;
/// Size of one data directory entry.
pub const DIRECTORY_SIZE: usize = 8;

/// Offset of `SizeOfImage` inside a `PE32` optional header.
pub const PE32_SIZE_OF_IMAGE_OFFSET: usize = 56;
/// Offset of `SizeOfImage` inside a `PE32+` optional header.
pub const PE32PLUS_SIZE_OF_IMAGE_OFFSET: usize = 56;
/// Offset of `SizeOfImage` inside either optional header layout.
pub const SIZE_OF_IMAGE_OFFSET: usize = 56;
/// Offset of `AddressOfEntryPoint` inside either optional header layout.
pub const ADDRESS_OF_ENTRY_POINT_OFFSET: usize = 16;
/// Offset of `SectionAlignment` inside either optional header layout.
pub const SECTION_ALIGNMENT_OFFSET: usize = 32;
/// Offset of `FileAlignment` inside either optional header layout.
pub const FILE_ALIGNMENT_OFFSET: usize = 36;
/// Offset of `SizeOfHeaders` inside either optional header layout.
pub const SIZE_OF_HEADERS_OFFSET: usize = 60;
/// Offset of `CheckSum` inside either optional header layout.
pub const CHECKSUM_OFFSET: usize = 64;

/// Index of the attribute certificate table in the data directory array.
///
/// Unlike every other directory, its `VirtualAddress` field holds a **file
/// offset**, not an RVA, and its `Size` is the length of the table.
pub const DIRECTORY_SECURITY: u32 = 4;
/// Offset of `NumberOfRvaAndSizes` inside a `PE32` optional header.
pub const PE32_NUMBER_OF_RVA_AND_SIZES_OFFSET: usize = 92;
/// Offset of `NumberOfRvaAndSizes` inside a `PE32+` optional header.
pub const PE32PLUS_NUMBER_OF_RVA_AND_SIZES_OFFSET: usize = 108;

/// `IMAGE_SUBSYSTEM_NATIVE`: a driver, no subsystem.
pub const SUBSYSTEM_NATIVE: u16 = 1;
/// `IMAGE_SUBSYSTEM_WINDOWS_GUI`: a windowed application.
pub const SUBSYSTEM_WINDOWS_GUI: u16 = 2;
/// `IMAGE_SUBSYSTEM_WINDOWS_CUI`: a console application.
pub const SUBSYSTEM_WINDOWS_CUI: u16 = 3;
/// `IMAGE_SUBSYSTEM_EFI_APPLICATION`.
pub const SUBSYSTEM_EFI_APPLICATION: u16 = 10;

/// `IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA`.
pub const DLL_HIGH_ENTROPY_VA: u16 = 0x0020;
/// `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`: ASLR.
pub const DLL_DYNAMIC_BASE: u16 = 0x0040;
/// `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY`.
pub const DLL_FORCE_INTEGRITY: u16 = 0x0080;
/// `IMAGE_DLLCHARACTERISTICS_NX_COMPAT`: DEP.
pub const DLL_NX_COMPAT: u16 = 0x0100;
/// `IMAGE_DLLCHARACTERISTICS_NO_ISOLATION`.
pub const DLL_NO_ISOLATION: u16 = 0x0200;
/// `IMAGE_DLLCHARACTERISTICS_NO_SEH`.
pub const DLL_NO_SEH: u16 = 0x0400;
/// `IMAGE_DLLCHARACTERISTICS_NO_BIND`.
pub const DLL_NO_BIND: u16 = 0x0800;
/// `IMAGE_DLLCHARACTERISTICS_APPCONTAINER`.
pub const DLL_APPCONTAINER: u16 = 0x1000;
/// `IMAGE_DLLCHARACTERISTICS_WDM_DRIVER`.
pub const DLL_WDM_DRIVER: u16 = 0x2000;
/// `IMAGE_DLLCHARACTERISTICS_GUARD_CF`: Control Flow Guard.
pub const DLL_GUARD_CF: u16 = 0x4000;
/// `IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE`.
pub const DLL_TERMINAL_SERVER_AWARE: u16 = 0x8000;

/// One entry of the data directory array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataDirectory {
    /// Index in the array: 0 is the export table, 1 the import table, and so on.
    pub index: u32,
    /// `VirtualAddress`: an RVA, not a file offset.
    pub virtual_address: u32,
    /// `Size` of the directory in bytes.
    pub size: u32,
}

impl DataDirectory {
    /// Parses one directory entry at `offset`.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than 8 bytes are available at `offset`.
    pub fn parse(data: &[u8], offset: usize, index: u32) -> Result<Self, ParseError> {
        let mut reader = Reader::new(data).sub_reader(offset, DIRECTORY_SIZE)?;
        Ok(Self {
            index,
            virtual_address: reader.read_u32()?,
            size: reader.read_u32()?,
        })
    }

    /// Returns `true` if the entry is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.virtual_address == 0 && self.size == 0
    }
}

/// The parsed optional header of a `PE32` or `PE32+` image.
///
/// The layout is unified: `PE32` fields are widened to 64 bits, and
/// `base_of_data` is [`None`] for `PE32+`, which does not have that field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionalHeader {
    /// File offset of the header.
    pub offset: usize,
    /// `Magic`: [`PE32_MAGIC`] or [`PE32PLUS_MAGIC`].
    pub magic: u16,
    /// `MajorLinkerVersion`.
    pub major_linker_version: u8,
    /// `MinorLinkerVersion`.
    pub minor_linker_version: u8,
    /// `SizeOfCode`.
    pub size_of_code: u32,
    /// `SizeOfInitializedData`.
    pub size_of_initialized_data: u32,
    /// `SizeOfUninitializedData`.
    pub size_of_uninitialized_data: u32,
    /// `AddressOfEntryPoint`: an RVA.
    pub address_of_entry_point: u32,
    /// `BaseOfCode`: an RVA.
    pub base_of_code: u32,
    /// `BaseOfData`: an RVA, present in `PE32` only.
    pub base_of_data: Option<u32>,
    /// `ImageBase`.
    pub image_base: u64,
    /// `SectionAlignment`.
    pub section_alignment: u32,
    /// `FileAlignment`.
    pub file_alignment: u32,
    /// `MajorOperatingSystemVersion`.
    pub major_os_version: u16,
    /// `MinorOperatingSystemVersion`.
    pub minor_os_version: u16,
    /// `MajorImageVersion`.
    pub major_image_version: u16,
    /// `MinorImageVersion`.
    pub minor_image_version: u16,
    /// `MajorSubsystemVersion`.
    pub major_subsystem_version: u16,
    /// `MinorSubsystemVersion`.
    pub minor_subsystem_version: u16,
    /// `Win32VersionValue`: reserved, must be zero.
    pub win32_version_value: u32,
    /// `SizeOfImage`.
    pub size_of_image: u32,
    /// `SizeOfHeaders`.
    pub size_of_headers: u32,
    /// `CheckSum`.
    pub checksum: u32,
    /// `Subsystem`.
    pub subsystem: u16,
    /// `DllCharacteristics`.
    pub dll_characteristics: u16,
    /// `SizeOfStackReserve`.
    pub size_of_stack_reserve: u64,
    /// `SizeOfStackCommit`.
    pub size_of_stack_commit: u64,
    /// `SizeOfHeapReserve`.
    pub size_of_heap_reserve: u64,
    /// `SizeOfHeapCommit`.
    pub size_of_heap_commit: u64,
    /// `LoaderFlags`: reserved.
    pub loader_flags: u32,
    /// `NumberOfRvaAndSizes`: the declared number of data directories.
    pub number_of_rva_and_sizes: u32,
}

impl OptionalHeader {
    /// Parses the optional header at `offset`.
    ///
    /// # Errors
    ///
    /// Returns `InvalidValue` for a magic other than `0x10B` or `0x20B`, and an
    /// error if the fixed part of the header is not fully present.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, ParseError> {
        let mut probe = Reader::new(data).sub_reader(offset, 2)?;
        let magic = probe.read_u16()?;
        match magic {
            PE32_MAGIC => Self::parse_pe32(data, offset),
            PE32PLUS_MAGIC => Self::parse_pe32_plus(data, offset),
            _ => Err(ParseError::invalid_value(offset, "optional header magic")
                .with_values(u64::from(PE32_MAGIC), u64::from(magic))),
        }
    }

    fn parse_pe32(data: &[u8], offset: usize) -> Result<Self, ParseError> {
        let mut reader = Reader::new(data).sub_reader(offset, PE32_FIXED_SIZE)?;
        Ok(Self {
            offset,
            magic: reader.read_u16()?,
            major_linker_version: reader.read_u8()?,
            minor_linker_version: reader.read_u8()?,
            size_of_code: reader.read_u32()?,
            size_of_initialized_data: reader.read_u32()?,
            size_of_uninitialized_data: reader.read_u32()?,
            address_of_entry_point: reader.read_u32()?,
            base_of_code: reader.read_u32()?,
            base_of_data: Some(reader.read_u32()?),
            image_base: u64::from(reader.read_u32()?),
            section_alignment: reader.read_u32()?,
            file_alignment: reader.read_u32()?,
            major_os_version: reader.read_u16()?,
            minor_os_version: reader.read_u16()?,
            major_image_version: reader.read_u16()?,
            minor_image_version: reader.read_u16()?,
            major_subsystem_version: reader.read_u16()?,
            minor_subsystem_version: reader.read_u16()?,
            win32_version_value: reader.read_u32()?,
            size_of_image: reader.read_u32()?,
            size_of_headers: reader.read_u32()?,
            checksum: reader.read_u32()?,
            subsystem: reader.read_u16()?,
            dll_characteristics: reader.read_u16()?,
            size_of_stack_reserve: u64::from(reader.read_u32()?),
            size_of_stack_commit: u64::from(reader.read_u32()?),
            size_of_heap_reserve: u64::from(reader.read_u32()?),
            size_of_heap_commit: u64::from(reader.read_u32()?),
            loader_flags: reader.read_u32()?,
            number_of_rva_and_sizes: reader.read_u32()?,
        })
    }

    fn parse_pe32_plus(data: &[u8], offset: usize) -> Result<Self, ParseError> {
        let mut reader = Reader::new(data).sub_reader(offset, PE32PLUS_FIXED_SIZE)?;
        Ok(Self {
            offset,
            magic: reader.read_u16()?,
            major_linker_version: reader.read_u8()?,
            minor_linker_version: reader.read_u8()?,
            size_of_code: reader.read_u32()?,
            size_of_initialized_data: reader.read_u32()?,
            size_of_uninitialized_data: reader.read_u32()?,
            address_of_entry_point: reader.read_u32()?,
            base_of_code: reader.read_u32()?,
            base_of_data: None,
            image_base: reader.read_u64()?,
            section_alignment: reader.read_u32()?,
            file_alignment: reader.read_u32()?,
            major_os_version: reader.read_u16()?,
            minor_os_version: reader.read_u16()?,
            major_image_version: reader.read_u16()?,
            minor_image_version: reader.read_u16()?,
            major_subsystem_version: reader.read_u16()?,
            minor_subsystem_version: reader.read_u16()?,
            win32_version_value: reader.read_u32()?,
            size_of_image: reader.read_u32()?,
            size_of_headers: reader.read_u32()?,
            checksum: reader.read_u32()?,
            subsystem: reader.read_u16()?,
            dll_characteristics: reader.read_u16()?,
            size_of_stack_reserve: reader.read_u64()?,
            size_of_stack_commit: reader.read_u64()?,
            size_of_heap_reserve: reader.read_u64()?,
            size_of_heap_commit: reader.read_u64()?,
            loader_flags: reader.read_u32()?,
            number_of_rva_and_sizes: reader.read_u32()?,
        })
    }

    /// Returns `true` for a `PE32+` header.
    #[must_use]
    pub const fn is_pe32_plus(&self) -> bool {
        self.magic == PE32PLUS_MAGIC
    }

    /// Returns the size of the fixed part of this header, without directories.
    #[must_use]
    pub const fn fixed_size(&self) -> usize {
        if self.is_pe32_plus() {
            PE32PLUS_FIXED_SIZE
        } else {
            PE32_FIXED_SIZE
        }
    }

    /// Returns `true` if [`DLL_DYNAMIC_BASE`] is set.
    #[must_use]
    pub const fn has_aslr(&self) -> bool {
        self.dll_characteristics & DLL_DYNAMIC_BASE != 0
    }

    /// Returns `true` if [`DLL_NX_COMPAT`] is set.
    #[must_use]
    pub const fn has_dep(&self) -> bool {
        self.dll_characteristics & DLL_NX_COMPAT != 0
    }

    /// Returns `true` if [`DLL_GUARD_CF`] is set.
    #[must_use]
    pub const fn has_cfg(&self) -> bool {
        self.dll_characteristics & DLL_GUARD_CF != 0
    }

    /// Returns `true` if [`DLL_HIGH_ENTROPY_VA`] is set.
    #[must_use]
    pub const fn has_high_entropy_va(&self) -> bool {
        self.dll_characteristics & DLL_HIGH_ENTROPY_VA != 0
    }

    /// Returns a short human-readable name of the subsystem.
    #[must_use]
    pub const fn subsystem_name(&self) -> Option<&'static str> {
        match self.subsystem {
            SUBSYSTEM_NATIVE => Some("native"),
            SUBSYSTEM_WINDOWS_GUI => Some("windows-gui"),
            SUBSYSTEM_WINDOWS_CUI => Some("windows-cui"),
            SUBSYSTEM_EFI_APPLICATION => Some("efi-application"),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DIRECTORY_SIZE, DLL_DYNAMIC_BASE, DLL_GUARD_CF, DLL_NX_COMPAT, DataDirectory,
        OptionalHeader, PE32_FIXED_SIZE, PE32_MAGIC, PE32PLUS_FIXED_SIZE, PE32PLUS_MAGIC,
        SUBSYSTEM_WINDOWS_GUI,
    };
    use crate::ErrorKind;

    fn pe32_bytes() -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PE32_FIXED_SIZE);
        bytes.extend_from_slice(&PE32_MAGIC.to_le_bytes());
        bytes.extend_from_slice(&[14, 0]);
        bytes.extend_from_slice(&0x200u32.to_le_bytes()); // SizeOfCode
        bytes.extend_from_slice(&0x200u32.to_le_bytes()); // SizeOfInitializedData
        bytes.extend_from_slice(&0u32.to_le_bytes()); // SizeOfUninitializedData
        bytes.extend_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
        bytes.extend_from_slice(&0x1000u32.to_le_bytes()); // BaseOfCode
        bytes.extend_from_slice(&0x2000u32.to_le_bytes()); // BaseOfData
        bytes.extend_from_slice(&0x0040_0000u32.to_le_bytes()); // ImageBase
        bytes.extend_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        bytes.extend_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
        for _ in 0..6 {
            bytes.extend_from_slice(&6u16.to_le_bytes()); // versions
        }
        bytes.extend_from_slice(&0u32.to_le_bytes()); // Win32VersionValue
        bytes.extend_from_slice(&0x2000u32.to_le_bytes()); // SizeOfImage
        bytes.extend_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
        bytes.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
        bytes.extend_from_slice(&SUBSYSTEM_WINDOWS_GUI.to_le_bytes());
        bytes.extend_from_slice(&(DLL_DYNAMIC_BASE | DLL_NX_COMPAT | DLL_GUARD_CF).to_le_bytes());
        for _ in 0..4 {
            bytes.extend_from_slice(&0x10_0000u32.to_le_bytes()); // stack/heap
        }
        bytes.extend_from_slice(&0u32.to_le_bytes()); // LoaderFlags
        bytes.extend_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        bytes
    }

    fn pe32plus_bytes() -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PE32PLUS_FIXED_SIZE);
        bytes.extend_from_slice(&PE32PLUS_MAGIC.to_le_bytes());
        bytes.extend_from_slice(&[14, 0]);
        bytes.extend_from_slice(&0x200u32.to_le_bytes());
        bytes.extend_from_slice(&0x200u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0x1000u32.to_le_bytes());
        bytes.extend_from_slice(&0x1000u32.to_le_bytes());
        bytes.extend_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes()); // ImageBase
        bytes.extend_from_slice(&0x1000u32.to_le_bytes());
        bytes.extend_from_slice(&0x200u32.to_le_bytes());
        for _ in 0..6 {
            bytes.extend_from_slice(&6u16.to_le_bytes());
        }
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0x2000u32.to_le_bytes());
        bytes.extend_from_slice(&0x200u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&SUBSYSTEM_WINDOWS_GUI.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        for _ in 0..4 {
            bytes.extend_from_slice(&0x10_0000u64.to_le_bytes());
        }
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&16u32.to_le_bytes());
        bytes
    }

    #[test]
    fn pe32_fixed_size_matches_the_layout() {
        assert_eq!(pe32_bytes().len(), PE32_FIXED_SIZE);
        assert_eq!(pe32plus_bytes().len(), PE32PLUS_FIXED_SIZE);
    }

    #[test]
    fn parses_pe32_fields() {
        let header = OptionalHeader::parse(&pe32_bytes(), 0).unwrap();
        assert_eq!(header.magic, PE32_MAGIC);
        assert!(!header.is_pe32_plus());
        assert_eq!(header.fixed_size(), PE32_FIXED_SIZE);
        assert_eq!(header.base_of_data, Some(0x2000));
        assert_eq!(header.image_base, 0x0040_0000);
        assert_eq!(header.address_of_entry_point, 0x1000);
        assert_eq!(header.section_alignment, 0x1000);
        assert_eq!(header.file_alignment, 0x200);
        assert_eq!(header.size_of_image, 0x2000);
        assert_eq!(header.size_of_headers, 0x200);
        assert_eq!(header.subsystem, SUBSYSTEM_WINDOWS_GUI);
        assert_eq!(header.subsystem_name(), Some("windows-gui"));
        assert_eq!(header.number_of_rva_and_sizes, 16);
        assert!(header.has_aslr());
        assert!(header.has_dep());
        assert!(header.has_cfg());
        assert!(!header.has_high_entropy_va());
    }

    #[test]
    fn parses_pe32plus_fields() {
        let header = OptionalHeader::parse(&pe32plus_bytes(), 0).unwrap();
        assert_eq!(header.magic, PE32PLUS_MAGIC);
        assert!(header.is_pe32_plus());
        assert_eq!(header.fixed_size(), PE32PLUS_FIXED_SIZE);
        assert_eq!(header.base_of_data, None);
        assert_eq!(header.image_base, 0x0000_0001_4000_0000);
        assert_eq!(header.size_of_stack_reserve, 0x10_0000);
        assert!(!header.has_aslr());
    }

    #[test]
    fn rejects_unknown_magic_with_evidence() {
        let mut bytes = pe32_bytes();
        if let Some(slot) = bytes.get_mut(..2) {
            slot.copy_from_slice(&0x999u16.to_le_bytes());
        }
        let error = OptionalHeader::parse(&bytes, 0).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidValue);
        assert_eq!(error.expected(), Some(u64::from(PE32_MAGIC)));
        assert_eq!(error.actual(), Some(0x999));
    }

    #[test]
    fn truncated_header_is_rejected() {
        let mut bytes = pe32_bytes();
        bytes.truncate(60);
        let error = OptionalHeader::parse(&bytes, 0).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::OutOfBounds);
    }

    #[test]
    fn offset_past_end_is_out_of_bounds() {
        let bytes = pe32_bytes();
        let error = OptionalHeader::parse(&bytes, 1000).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::OutOfBounds);
    }

    #[test]
    fn parses_at_an_offset() {
        let mut bytes = vec![0u8; 16];
        bytes.extend_from_slice(&pe32_bytes());
        let header = OptionalHeader::parse(&bytes, 16).unwrap();
        assert_eq!(header.offset, 16);
        assert_eq!(header.magic, PE32_MAGIC);
    }

    #[test]
    fn directory_entry_round_trip() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x1000u32.to_le_bytes());
        bytes.extend_from_slice(&0x200u32.to_le_bytes());
        let directory = DataDirectory::parse(&bytes, 0, 1).unwrap();
        assert_eq!(directory.index, 1);
        assert_eq!(directory.virtual_address, 0x1000);
        assert_eq!(directory.size, 0x200);
        assert!(!directory.is_empty());
        assert_eq!(bytes.len(), DIRECTORY_SIZE);
    }

    #[test]
    fn empty_directory_is_detected() {
        let bytes = [0u8; 8];
        let directory = DataDirectory::parse(&bytes, 0, 0).unwrap();
        assert!(directory.is_empty());
    }
}
