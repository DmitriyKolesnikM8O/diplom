//! DOS header.
//!
//! Every PE image starts with a 64-byte DOS header. Only two fields matter for
//! analysis: the `MZ` magic and `e_lfanew`, the file offset of the PE
//! signature. The rest is legacy stub data, but the bytes are still preserved
//! by the parser because hostile files hide payloads there.

use crate::bytes::Reader;
use crate::error::ParseError;

/// Size of the DOS header defined by the specification.
pub const DOS_HEADER_SIZE: usize = 0x40;

/// Offset of the `e_lfanew` field inside the DOS header.
pub const E_LFANEW_OFFSET: usize = 0x3C;

/// `MZ`: the first two bytes of every DOS and PE image.
pub const DOS_MAGIC: u16 = 0x5A4D;

/// The parsed DOS header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DosHeader {
    /// File offset of the header, always zero.
    pub offset: usize,
    /// `e_lfanew`: file offset of the PE signature.
    pub pe_offset: u32,
}

impl DosHeader {
    /// Parses the DOS header at the start of `data`.
    ///
    /// # Errors
    ///
    /// Returns `UnexpectedEof` if the file is shorter than 64 bytes, and
    /// `InvalidValue` (with expected and actual magic) if the file does not
    /// start with `MZ`.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < DOS_HEADER_SIZE {
            return Err(ParseError::unexpected_eof(data.len(), "DOS header"));
        }
        let mut reader = Reader::new(data);
        let magic = reader.read_u16()?;
        if magic != DOS_MAGIC {
            return Err(ParseError::invalid_value(0, "MZ signature")
                .with_values(u64::from(DOS_MAGIC), u64::from(magic)));
        }
        reader.seek(E_LFANEW_OFFSET)?;
        let pe_offset = reader.read_u32()?;
        Ok(Self {
            offset: 0,
            pe_offset,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{DOS_MAGIC, DosHeader, E_LFANEW_OFFSET};
    use crate::ErrorKind;

    fn dos_header(pe_offset: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x40];
        if let Some(slot) = bytes.get_mut(..2) {
            slot.copy_from_slice(b"MZ");
        }
        if let Some(slot) = bytes.get_mut(E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4) {
            slot.copy_from_slice(&pe_offset.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn parses_magic_and_pe_offset() {
        let header = DosHeader::parse(&dos_header(0x80)).unwrap();
        assert_eq!(header.offset, 0);
        assert_eq!(header.pe_offset, 0x80);
    }

    #[test]
    fn magic_constant_is_mz() {
        assert_eq!(DOS_MAGIC.to_le_bytes(), *b"MZ");
    }

    #[test]
    fn missing_magic_reports_expected_and_actual() {
        let mut bytes = dos_header(0x40);
        if let Some(slot) = bytes.get_mut(..2) {
            slot.copy_from_slice(b"XX");
        }
        let error = DosHeader::parse(&bytes).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidValue);
        assert_eq!(error.expected(), Some(u64::from(DOS_MAGIC)));
        assert_eq!(error.actual(), Some(u64::from(u16::from_le_bytes(*b"XX"))));
    }

    #[test]
    fn truncated_header_is_reported_as_eof() {
        let error = DosHeader::parse(&[0x4D, 0x5A]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
    }

    #[test]
    fn empty_input_is_eof() {
        assert_eq!(
            DosHeader::parse(&[]).unwrap_err().kind(),
            ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn truncated_e_lfanew_is_eof() {
        let mut bytes = dos_header(0x40);
        bytes.truncate(E_LFANEW_OFFSET + 2);
        assert_eq!(
            DosHeader::parse(&bytes).unwrap_err().kind(),
            ErrorKind::UnexpectedEof
        );
    }
}
