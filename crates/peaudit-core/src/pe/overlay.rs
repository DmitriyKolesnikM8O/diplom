//! Data that is stored in the file but is not part of the image.
//!
//! An overlay is the classic place to hide a second executable, an archive or a
//! payload: the loader never maps those bytes, so they cannot break the image,
//! and a parser that only walks the headers never sees them. The module finds
//! the region, it does not judge what is in it — content rules come later.
//!
//! Two details make the naive "everything after the last section" wrong:
//!
//! - The **attribute certificate table** is appended after the sections and is
//!   not an overlay. Its directory entry points at a file offset, not an RVA.
//! - Data can also be appended **after** the certificate table (T44, `PE-OVL-004`
//!   / `PE-CERT-002`), so one `(offset, size)` pair cannot describe every file.
//!
//! The result is therefore a partition of the file after the headers into up to
//! three regions: before the certificate table, the table itself, and after it.
//! All regions are clipped to the file: a declared range that runs past the end
//! is reported by the certificate rules, not silently included here.
//!
//! The overlay never starts inside the headers. Bytes of the header region are
//! mapped as headers even when `SizeOfHeaders` is larger than the structures
//! actually present, so the start is the maximum of three ends: the section
//! data, the declared section table and `SizeOfHeaders`.

use crate::pe::{PeFile, optional};

/// A contiguous range of bytes in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DataRegion {
    /// Start of the range, in bytes from the beginning of the file.
    pub offset: u64,
    /// Length of the range in bytes.
    pub size: u64,
}

impl DataRegion {
    /// Returns the first offset after the range.
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.offset.saturating_add(self.size)
    }

    /// Returns `true` if the range contains no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.size == 0
    }
}

/// How the bytes after the headers are partitioned.
///
/// All fields are [`None`] for an image that ends with its last section, which
/// is the common case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OverlayInfo {
    /// Data after the last section and before the attribute certificate table.
    ///
    /// When no certificate table follows the sections, this is the whole
    /// overlay.
    pub leading: Option<DataRegion>,
    /// The attribute certificate table, present only when it starts at or after
    /// the last section.
    ///
    /// A table that starts earlier overlaps the image; that is a finding of its
    /// own, and it cannot be subtracted from the overlay without inventing a
    /// partition.
    pub certificate: Option<DataRegion>,
    /// Data after the attribute certificate table.
    pub trailing: Option<DataRegion>,
}

impl OverlayInfo {
    /// Computes the partition of `data` after the headers.
    #[must_use]
    pub fn compute(data: &[u8], file: &PeFile) -> Self {
        let len = data.len() as u64;
        let start = start_offset(file).min(len);
        if start >= len {
            return Self::default();
        }

        let rest = DataRegion {
            offset: start,
            size: len - start,
        };
        let Some(certificate) = certificate_region(file, len) else {
            return Self {
                leading: Some(rest),
                ..Self::default()
            };
        };
        if certificate.offset < start {
            return Self {
                leading: Some(rest),
                ..Self::default()
            };
        }

        let leading = (certificate.offset > start).then(|| DataRegion {
            offset: start,
            size: certificate.offset - start,
        });
        let certificate_end = certificate.end();
        let trailing = (certificate_end < len).then(|| DataRegion {
            offset: certificate_end,
            size: len - certificate_end,
        });
        Self {
            leading,
            certificate: Some(certificate),
            trailing,
        }
    }

    /// Returns `true` if the file holds data outside the image.
    ///
    /// The certificate table alone does not count: it is a legitimate append.
    #[must_use]
    pub fn is_present(&self) -> bool {
        self.leading.is_some() || self.trailing.is_some()
    }

    /// Returns the total number of overlay bytes, excluding the certificate
    /// table.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.leading.map_or(0, |region| region.size) + self.trailing.map_or(0, |region| region.size)
    }
}

/// Returns the first byte after the headers: the later of the section data, the
/// declared section table and `SizeOfHeaders`.
fn start_offset(file: &PeFile) -> u64 {
    let section_end = file
        .sections
        .iter()
        .filter(|section| section.size_of_raw_data != 0)
        .map(|section| {
            u64::from(section.pointer_to_raw_data)
                .saturating_add(u64::from(section.size_of_raw_data))
        })
        .max()
        .unwrap_or(0);
    let declared_headers = file
        .optional
        .map_or(0, |header| u64::from(header.size_of_headers));
    let table_end = file.section_table_end().unwrap_or(0);
    section_end.max(declared_headers).max(table_end)
}

/// Returns the certificate table clipped to the file, or [`None`] when it is
/// absent, empty or entirely past the end.
fn certificate_region(file: &PeFile, len: u64) -> Option<DataRegion> {
    let directory = file
        .directories
        .iter()
        .find(|directory| directory.index == optional::DIRECTORY_SECURITY)?;
    if directory.virtual_address == 0 || directory.size == 0 {
        return None;
    }
    let offset = u64::from(directory.virtual_address);
    if offset >= len {
        return None;
    }
    Some(DataRegion {
        offset,
        size: u64::from(directory.size).min(len - offset),
    })
}

#[cfg(test)]
mod tests {
    use super::{DataRegion, OverlayInfo};
    use crate::limits::Limits;
    use crate::pe::{PeFile, coff, optional, section};
    use crate::testutil::PeBuilder;

    /// Parses `bytes` and computes the overlay.
    fn overlay(bytes: &[u8]) -> OverlayInfo {
        let file = PeFile::parse(bytes, &Limits::default());
        OverlayInfo::compute(bytes, &file)
    }

    /// Builds the default image with `tail` bytes appended.
    fn image_with_tail(tail: usize) -> Vec<u8> {
        let mut bytes = PeBuilder::pe32().into_bytes();
        bytes.resize(bytes.len() + tail, 0xCC);
        bytes
    }

    /// Writes the certificate directory entry.
    fn set_certificate(builder: &mut PeBuilder, offset: u32, size: u32) {
        let entry = builder.directories_offset()
            + optional::DIRECTORY_SECURITY as usize * optional::DIRECTORY_SIZE;
        assert!(builder.patch_u32(entry, offset));
        assert!(builder.patch_u32(entry + 4, size));
    }

    /// Writes raw location fields of an existing section entry.
    fn set_raw(builder: &mut PeBuilder, index: usize, pointer: u32, size: u32) {
        let entry = builder.sections_offset() + index * section::SECTION_HEADER_SIZE;
        assert!(builder.patch_u32(entry + 16, size));
        assert!(builder.patch_u32(entry + 20, pointer));
    }

    fn region(offset: u64, size: u64) -> Option<DataRegion> {
        Some(DataRegion { offset, size })
    }

    #[test]
    fn an_image_ending_with_its_last_section_has_no_overlay() {
        let builder = PeBuilder::pe32();
        let info = overlay(builder.bytes());

        assert_eq!(info, OverlayInfo::default());
        assert!(!info.is_present());
        assert_eq!(info.total_size(), 0);
    }

    #[test]
    fn data_after_the_last_section_is_overlay() {
        let bytes = image_with_tail(0x100);
        let info = overlay(&bytes);

        assert_eq!(info.leading, region(0x400, 0x100));
        assert_eq!(info.certificate, None);
        assert_eq!(info.trailing, None);
        assert!(info.is_present());
        assert_eq!(info.total_size(), 0x100);
    }

    #[test]
    fn the_highest_raw_end_wins_over_table_order() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(builder.coff_offset() + coff::NUMBER_OF_SECTIONS_OFFSET, 2));
        set_raw(&mut builder, 0, 0x300, 0x200);
        set_raw(&mut builder, 1, 0x200, 0x200);
        let mut bytes = builder.into_bytes();
        bytes.resize(0x600, 0xCC);

        // Ends are 0x500 and 0x400, so the overlay starts at 0x500.
        assert_eq!(overlay(&bytes).leading, region(0x500, 0x100));
    }

    #[test]
    fn a_section_past_the_end_of_file_leaves_no_overlay() {
        let mut builder = PeBuilder::pe32();
        set_raw(&mut builder, 0, 0x200, 0x1000);
        let mut bytes = builder.into_bytes();
        bytes.resize(0x500, 0xCC);

        assert_eq!(overlay(&bytes), OverlayInfo::default());
    }

    #[test]
    fn a_certificate_table_at_the_end_is_not_overlay() {
        let mut builder = PeBuilder::pe32();
        set_certificate(&mut builder, 0x400, 0x100);
        let mut bytes = builder.into_bytes();
        bytes.resize(0x500, 0xCC);

        let info = overlay(&bytes);
        assert_eq!(info.leading, None);
        assert_eq!(info.certificate, region(0x400, 0x100));
        assert_eq!(info.trailing, None);
        assert!(!info.is_present());
        assert_eq!(info.total_size(), 0);
    }

    #[test]
    fn data_before_and_after_the_certificate_is_overlay() {
        // T44: something appended after the signature.
        let mut builder = PeBuilder::pe32();
        set_certificate(&mut builder, 0x480, 0x80);
        let mut bytes = builder.into_bytes();
        bytes.resize(0x680, 0xCC);

        let info = overlay(&bytes);
        assert_eq!(info.leading, region(0x400, 0x80));
        assert_eq!(info.certificate, region(0x480, 0x80));
        assert_eq!(info.trailing, region(0x500, 0x180));
        assert!(info.is_present());
        assert_eq!(info.total_size(), 0x200);
    }

    #[test]
    fn a_certificate_table_past_the_end_of_file_is_ignored() {
        let mut builder = PeBuilder::pe32();
        set_certificate(&mut builder, 0x900, 0x10);
        let mut bytes = builder.into_bytes();
        bytes.resize(0x500, 0xCC);

        let info = overlay(&bytes);
        assert_eq!(info.leading, region(0x400, 0x100));
        assert_eq!(info.certificate, None);
    }

    #[test]
    fn a_certificate_table_inside_the_image_does_not_split_the_overlay() {
        let mut builder = PeBuilder::pe32();
        set_certificate(&mut builder, 0x100, 0x10);
        let mut bytes = builder.into_bytes();
        bytes.resize(0x500, 0xCC);

        let info = overlay(&bytes);
        assert_eq!(info.leading, region(0x400, 0x100));
        assert_eq!(info.certificate, None);
        assert_eq!(info.trailing, None);
    }

    #[test]
    fn an_empty_certificate_directory_is_ignored() {
        let mut builder = PeBuilder::pe32();
        set_certificate(&mut builder, 0x400, 0);
        let mut bytes = builder.into_bytes();
        bytes.resize(0x500, 0xCC);

        assert_eq!(overlay(&bytes).leading, region(0x400, 0x100));
    }

    #[test]
    fn a_certificate_size_is_clipped_to_the_end_of_file() {
        let mut builder = PeBuilder::pe32();
        set_certificate(&mut builder, 0x400, 0x1000);
        let mut bytes = builder.into_bytes();
        bytes.resize(0x500, 0xCC);

        let info = overlay(&bytes);
        assert_eq!(info.certificate, region(0x400, 0x100));
        assert_eq!(info.leading, None);
        assert_eq!(info.trailing, None);
    }

    #[test]
    fn without_sections_overlay_starts_after_the_headers() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(builder.coff_offset() + coff::NUMBER_OF_SECTIONS_OFFSET, 0));
        let mut bytes = builder.into_bytes();
        bytes.resize(0x500, 0xCC);

        // Section table ends at 0x160, SizeOfHeaders is 0x200.
        assert_eq!(overlay(&bytes).leading, region(0x200, 0x300));
    }

    #[test]
    fn a_region_end_saturates_instead_of_overflowing() {
        let region = DataRegion {
            offset: u64::MAX - 1,
            size: 10,
        };
        assert_eq!(region.end(), u64::MAX);
        assert!(!region.is_empty());
    }

    #[test]
    fn an_empty_region_is_reported_as_empty() {
        let region = DataRegion {
            offset: 0x400,
            size: 0,
        };
        assert!(region.is_empty());
        assert_eq!(region.end(), 0x400);
    }
}
