//! The PE checksum, computed the way Windows computes it.
//!
//! The value is a 16-bit ones'-complement sum of the file treated as
//! little-endian 16-bit words, plus the file length, with one subtraction: the
//! four bytes of the `CheckSum` field itself are treated as zero, otherwise the
//! value would depend on itself.
//!
//! The algorithm is specified but easy to get subtly wrong, so the rules of this
//! implementation are stated explicitly:
//!
//! - words are read little-endian, and an odd trailing byte is added as a word
//!   with a zero high byte;
//! - the `CheckSum` field is **masked to zero**, not skipped by word index, so a
//!   field that is not four-byte aligned still behaves as the specification
//!   says;
//! - carries are folded as they accumulate, which is required only to keep the
//!   intermediate value small; the result is the same as folding once at the
//!   end;
//! - the file length is added **after** the final fold and is not folded again.
//!
//! Only the comparison matters to the analyzer: Windows verifies the checksum
//! for drivers and a few other images, never for ordinary user-mode executables,
//! so a mismatch is a finding whose severity depends on the image kind.

use crate::pe::{PeFile, optional};

/// Number of bytes in the `CheckSum` field.
const CHECKSUM_FIELD_SIZE: usize = 4;

/// Computes the PE checksum of `data`.
///
/// `checksum_field` is the offset of the four-byte `CheckSum` field; pass
/// [`None`] to sum every byte (useful for pinning the algorithm itself). Bytes
/// outside `data` are not read, so a field that lies past the end is simply not
/// masked.
#[must_use]
pub fn compute_checksum(data: &[u8], checksum_field: Option<usize>) -> u32 {
    // The field is masked, not skipped: a field that is not four-byte aligned
    // covers one byte of each neighbouring word.
    let field = checksum_field.map(|start| start..start.saturating_add(CHECKSUM_FIELD_SIZE));

    let mut sum: u64 = 0;
    let mut base = 0usize;
    for chunk in data.chunks_exact(2) {
        // `chunks_exact(2)` yields exactly two bytes, so the pattern cannot fail.
        let &[lo, hi] = chunk else { break };
        let mut bytes = [lo, hi];
        if let Some(range) = &field {
            if range.contains(&base) {
                bytes[0] = 0;
            }
            if range.contains(&(base + 1)) {
                bytes[1] = 0;
            }
        }
        sum += u64::from(u16::from_le_bytes(bytes));
        // Bounded by the buffer length, so the addition cannot overflow.
        base += 2;
    }
    // An odd trailing byte is summed as a word with a zero high byte.
    let tail = data.len() & !1;
    if let Some(&byte) = data.get(tail) {
        if !field.as_ref().is_some_and(|range| range.contains(&tail)) {
            sum += u64::from(byte);
        }
    }

    // Fold the carries until the value fits in 16 bits. The loop runs at most a
    // few times even for a 512 MiB input.
    while sum > u64::from(u16::MAX) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let length = u32::try_from(data.len()).unwrap_or(u32::MAX);
    (sum as u32).saturating_add(length)
}

/// The stored and computed checksum of an image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChecksumInfo {
    /// `CheckSum` as stored in the optional header.
    pub stored: Option<u32>,
    /// Checksum computed over the file with the field masked.
    ///
    /// [`None`] when the optional header is missing: without it there is no
    /// field to mask and no stored value to compare against.
    pub computed: Option<u32>,
}

impl ChecksumInfo {
    /// Computes both values for `data`.
    #[must_use]
    pub fn compute(data: &[u8], file: &PeFile) -> Self {
        let field = file
            .offsets
            .optional
            .and_then(|offset| offset.checked_add(optional::CHECKSUM_OFFSET));
        Self {
            stored: file.optional.map(|header| header.checksum),
            computed: field.map(|field| compute_checksum(data, Some(field))),
        }
    }

    /// Returns `true` if the stored value equals the computed one.
    ///
    /// [`None`] when there is nothing to compare.
    #[must_use]
    pub fn is_consistent(&self) -> Option<bool> {
        match (self.stored, self.computed) {
            (Some(stored), Some(computed)) => Some(stored == computed),
            _ => None,
        }
    }

    /// Returns `true` if a non-zero checksum is stored.
    ///
    /// Zero means "not set": linkers leave it alone unless the image is meant to
    /// be verified, so it must not be reported as a mismatch.
    #[must_use]
    pub fn is_set(&self) -> bool {
        self.stored.is_some_and(|stored| stored != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::{ChecksumInfo, compute_checksum};
    use crate::limits::Limits;
    use crate::pe::{PeFile, coff, optional};
    use crate::testutil::PeBuilder;

    #[test]
    fn an_empty_input_has_a_zero_checksum() {
        assert_eq!(compute_checksum(&[], None), 0);
        assert_eq!(compute_checksum(&[], Some(0)), 0);
    }

    #[test]
    fn words_are_summed_with_the_file_length() {
        // 0x3231 + 0x3433 = 0x6664, plus the four bytes of input.
        assert_eq!(compute_checksum(b"1234", None), 0x6668);
        // The odd trailing byte is added as a word.
        assert_eq!(compute_checksum(b"12345", None), 0x669E);
        assert_eq!(compute_checksum(b"123456789", None), 0xD512);
    }

    #[test]
    fn the_checksum_field_is_masked_not_skipped() {
        // Both words collapse to zero, so only the length remains.
        assert_eq!(compute_checksum(&[0xFF; 4], Some(0)), 4);

        // An unaligned field at offset 1 covers bytes 1..5, so only the first
        // byte of the first word survives: 0x00FF plus the length.
        assert_eq!(compute_checksum(&[0xFF; 4], Some(1)), 0x103);
    }

    #[test]
    fn a_field_past_the_end_masks_nothing() {
        assert_eq!(
            compute_checksum(b"1234", Some(4)),
            compute_checksum(b"1234", None)
        );
    }

    #[test]
    fn the_field_value_does_not_change_the_result() {
        let mut builder = PeBuilder::pe32();
        let field = builder.optional_offset() + optional::CHECKSUM_OFFSET;
        let before = compute_checksum(builder.bytes(), Some(field));
        assert!(builder.patch_u32(field, 0xDEAD_BEEF));
        assert_eq!(compute_checksum(builder.bytes(), Some(field)), before);
    }

    /// Vectors produced by `MapFileAndCheckSumW` from `imagehlp.dll` for the
    /// bytes of the fixtures below, so the implementation is pinned to Windows
    /// and not to itself.
    #[test]
    fn windows_vectors_match() {
        let pe32 = PeBuilder::pe32();
        let field = pe32.optional_offset() + optional::CHECKSUM_OFFSET;
        assert_eq!(compute_checksum(pe32.bytes(), Some(field)), 0x0000_9205);

        let pe32plus = PeBuilder::pe32plus();
        let field = pe32plus.optional_offset() + optional::CHECKSUM_OFFSET;
        assert_eq!(compute_checksum(pe32plus.bytes(), Some(field)), 0x0000_36EF);
    }

    #[test]
    fn writing_the_computed_value_makes_the_image_consistent() {
        let mut builder = PeBuilder::pe32();
        let field = builder.optional_offset() + optional::CHECKSUM_OFFSET;
        let computed = compute_checksum(builder.bytes(), Some(field));
        assert!(builder.patch_u32(field, computed));

        let file = PeFile::parse(builder.bytes(), &Limits::default());
        let info = ChecksumInfo::compute(builder.bytes(), &file);
        assert_eq!(info.stored, Some(computed));
        assert_eq!(info.is_consistent(), Some(true));
        assert!(info.is_set());
    }

    #[test]
    fn a_zero_stored_checksum_is_not_set() {
        let builder = PeBuilder::pe32();
        let file = PeFile::parse(builder.bytes(), &Limits::default());
        let info = ChecksumInfo::compute(builder.bytes(), &file);

        assert_eq!(info.stored, Some(0));
        assert!(!info.is_set());
        assert_eq!(info.is_consistent(), Some(false));
    }

    #[test]
    fn without_an_optional_header_there_is_nothing_to_compare() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(
            builder.coff_offset() + coff::SIZE_OF_OPTIONAL_HEADER_OFFSET,
            0
        ));
        let file = PeFile::parse(builder.bytes(), &Limits::default());
        let info = ChecksumInfo::compute(builder.bytes(), &file);

        assert_eq!(info.stored, None);
        assert_eq!(info.computed, None);
        assert_eq!(info.is_consistent(), None);
        assert!(!info.is_set());
    }
}
