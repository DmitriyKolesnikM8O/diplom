//! Values computed from the parsed headers.
//!
//! Parsing answers "what does the file declare"; derivation answers "what
//! follows from it". The two stages are kept apart on purpose: a rule compares
//! the declaration with the derived value, so a mismatch becomes a finding with
//! both numbers in the evidence instead of a judgement hidden in the parser.
//!
//! Derivation never fails. A value that cannot be computed — no optional header,
//! no sections, zero alignment — is [`None`], not a diagnostic: the file is
//! simply not in a state where the question makes sense.
//!
//! The values here come in two kinds: some need only the parsed model
//! ([`HeadersSize`], [`ImageSize`]), others need the bytes as well
//! ([`OverlayInfo`], [`ChecksumInfo`], [`SectionEntropy`]). Derivation takes both,
//! so a caller cannot accidentally compute a checksum over a buffer different
//! from the one that was parsed.
//!
//! Entropy is measured here, once, and reused by every rule: a rule that needs
//! "is this section packed" must not rescan the file, and two rules must not
//! disagree because they scanned different ranges.

use crate::entropy::{HIGH_ENTROPY_THRESHOLD, shannon_entropy};
use crate::pe::{ChecksumInfo, DataRegion, OverlayInfo, PeFile, SectionHeader};

/// The already parsed model, plus the values computed from it.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Derived {
    /// Layout of the header region, present when the optional header was read.
    pub headers_size: Option<HeadersSize>,
    /// Declared and computed `SizeOfImage`, present when the optional header was
    /// read.
    pub image_size: Option<ImageSize>,
    /// Data after the headers that is not part of the image.
    pub overlay: OverlayInfo,
    /// Stored and computed PE checksum.
    pub checksum: ChecksumInfo,
    /// Entropy of every parsed section, in table order.
    pub section_entropy: Vec<SectionEntropy>,
}

impl Derived {
    /// Computes every derived value for `data`.
    #[must_use]
    pub fn compute(data: &[u8], file: &PeFile) -> Self {
        Self {
            headers_size: HeadersSize::compute(file),
            image_size: ImageSize::compute(file),
            overlay: OverlayInfo::compute(data, file),
            checksum: ChecksumInfo::compute(data, file),
            section_entropy: file
                .sections
                .iter()
                .enumerate()
                .map(|(index, section)| measure_section(data, index, section))
                .collect(),
        }
    }

    /// Returns the entry for the section at `index` in the table.
    #[must_use]
    pub fn section(&self, index: usize) -> Option<&SectionEntropy> {
        self.section_entropy.get(index)
    }
}

/// Entropy of one section's file bytes.
///
/// Entropy is measured over the bytes that are actually present, not over
/// `VirtualSize`: zero-filled tails are created by the loader, and a section
/// whose raw data is cut short would otherwise look far less random than it is.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SectionEntropy {
    /// Index of the section in the table.
    pub index: usize,
    /// File range the measurement covers, already clipped to the file.
    ///
    /// `offset` is the declared `PointerToRawData`, `size` is the part that
    /// exists; for a section fully inside the file this is exactly the raw
    /// range.
    pub data: DataRegion,
    /// Shannon entropy of [`SectionEntropy::data`], in bits per byte.
    pub entropy: f64,
    /// `true` when the section declares more raw data than the file holds.
    ///
    /// The measurement is then taken over fewer bytes than declared, so a rule
    /// must report the truncation (`PE-SEC-001`) rather than trust the number.
    pub truncated: bool,
}

impl SectionEntropy {
    /// Returns `true` if the entropy is at or above
    /// [`HIGH_ENTROPY_THRESHOLD`].
    #[must_use]
    pub fn is_high_entropy(&self) -> bool {
        self.entropy >= HIGH_ENTROPY_THRESHOLD
    }
}

/// Measures one section, clipping its raw range to the file.
fn measure_section(data: &[u8], index: usize, section: &SectionHeader) -> SectionEntropy {
    let offset = u64::from(section.pointer_to_raw_data);
    let declared = u64::from(section.size_of_raw_data);
    let available = (data.len() as u64).saturating_sub(offset).min(declared);

    // `usize::try_from` keeps a 32-bit target honest: a range that cannot even
    // be addressed is treated as absent rather than wrapped.
    let bytes = usize::try_from(offset)
        .ok()
        .zip(usize::try_from(available).ok())
        .and_then(|(start, size)| data.get(start..start.saturating_add(size)));
    let (size, entropy) = match bytes {
        Some(bytes) => (bytes.len() as u64, shannon_entropy(bytes)),
        None => (0, 0.0),
    };

    SectionEntropy {
        index,
        data: DataRegion { offset, size },
        entropy,
        truncated: size < declared,
    }
}

/// Layout of the header region: what the file declares and what it requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadersSize {
    /// `SizeOfHeaders` as declared in the optional header.
    pub declared: u32,
    /// End of the section table as the file declares it, in bytes from the
    /// start of the file.
    ///
    /// Computed from the **declared** section count, not from the entries the
    /// parser managed to read: the loader needs room for every declared entry,
    /// and a truncated table is reported separately by `sections.truncated`.
    pub required: u64,
    /// `FileAlignment`; `0` when the image declares none.
    pub file_alignment: u32,
}

impl HeadersSize {
    /// Derives the layout, or returns [`None`] without an optional header.
    #[must_use]
    pub fn compute(file: &PeFile) -> Option<Self> {
        let optional = file.optional?;
        Some(Self {
            declared: optional.size_of_headers,
            required: file.section_table_end()?,
            file_alignment: optional.file_alignment,
        })
    }

    /// Returns `true` if `SizeOfHeaders` covers every header structure.
    #[must_use]
    pub fn covers_headers(&self) -> bool {
        u64::from(self.declared) >= self.required
    }

    /// Returns how many bytes `SizeOfHeaders` is short by; `0` when it covers
    /// the headers.
    #[must_use]
    pub fn shortfall(&self) -> u64 {
        self.required.saturating_sub(u64::from(self.declared))
    }

    /// Returns `SizeOfHeaders` rounded up to `FileAlignment`.
    ///
    /// [`None`] when `FileAlignment` is zero, because no rounding rule exists.
    #[must_use]
    pub fn aligned_declared(&self) -> Option<u64> {
        align_up(u64::from(self.declared), self.file_alignment)
    }

    /// Returns the required header end rounded up to `FileAlignment`.
    ///
    /// [`None`] when `FileAlignment` is zero.
    #[must_use]
    pub fn aligned_required(&self) -> Option<u64> {
        align_up(self.required, self.file_alignment)
    }

    /// Returns `true` if `SizeOfHeaders` is a multiple of `FileAlignment`.
    ///
    /// [`None`] when `FileAlignment` is zero.
    #[must_use]
    pub fn declared_is_aligned(&self) -> Option<bool> {
        if self.file_alignment == 0 {
            return None;
        }
        Some(u64::from(self.declared) % u64::from(self.file_alignment) == 0)
    }
}

/// `SizeOfImage`, as declared and as computed from the sections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageSize {
    /// `SizeOfImage` as declared in the optional header.
    pub declared: u32,
    /// `align_up(max(VirtualAddress + VirtualSize), SectionAlignment)`.
    ///
    /// The maximum is taken over the whole table rather than the last entry: a
    /// reordered table must not change the answer, and the reordering itself is
    /// a finding.
    ///
    /// [`None`] when the image has no sections or `SectionAlignment` is zero.
    pub computed: Option<u64>,
    /// `SectionAlignment`.
    pub section_alignment: u32,
}

impl ImageSize {
    /// Derives the value, or returns [`None`] without an optional header.
    #[must_use]
    pub fn compute(file: &PeFile) -> Option<Self> {
        let optional = file.optional?;
        let end = file
            .sections
            .iter()
            .map(|section| {
                u64::from(section.virtual_address).saturating_add(u64::from(section.virtual_size))
            })
            .max();

        Some(Self {
            declared: optional.size_of_image,
            computed: end.and_then(|end| align_up(end, optional.section_alignment)),
            section_alignment: optional.section_alignment,
        })
    }

    /// Returns `true` if the declared value equals the computed one.
    ///
    /// [`None`] when the value could not be computed.
    #[must_use]
    pub fn is_consistent(&self) -> Option<bool> {
        self.computed
            .map(|computed| computed == u64::from(self.declared))
    }
}

/// Rounds `value` up to a multiple of `alignment`.
///
/// Returns [`None`] for a zero alignment: the specification allows it only for
/// files smaller than the page size, which the analyzer does not special-case.
fn align_up(value: u64, alignment: u32) -> Option<u64> {
    if alignment == 0 {
        return None;
    }
    let alignment = u64::from(alignment);
    Some(value.div_ceil(alignment).saturating_mul(alignment))
}

#[cfg(test)]
mod tests {
    use super::Derived;
    use crate::limits::Limits;
    use crate::pe::{PeFile, coff, optional, section};
    use crate::testutil::PeBuilder;
    /// Parses the builder and returns the derived values with the model.
    fn derive(builder: &PeBuilder) -> (PeFile, Derived) {
        let file = PeFile::parse(builder.bytes(), &Limits::default());
        let derived = Derived::compute(builder.bytes(), &file);
        (file, derived)
    }

    /// Writes `virtual_address` and `virtual_size` into an existing entry.
    fn write_section(
        builder: &mut PeBuilder,
        index: usize,
        virtual_address: u32,
        virtual_size: u32,
    ) {
        let entry = builder.sections_offset() + index * section::SECTION_HEADER_SIZE;
        assert!(builder.patch_u32(entry + 8, virtual_size));
        assert!(builder.patch_u32(entry + 12, virtual_address));
    }

    #[test]
    fn headers_size_covers_the_section_table() {
        let builder = PeBuilder::pe32();
        let required = u64::try_from(builder.sections_offset() + section::SECTION_HEADER_SIZE)
            .expect("offset fits in u64");
        let (_, derived) = derive(&builder);
        let headers = derived.headers_size.expect("headers size");

        assert_eq!(headers.declared, 0x200);
        assert_eq!(headers.required, required);
        assert_eq!(headers.file_alignment, 0x200);
        assert!(headers.covers_headers());
        assert_eq!(headers.shortfall(), 0);
        assert_eq!(headers.declared_is_aligned(), Some(true));
        assert_eq!(headers.aligned_declared(), Some(0x200));
        assert_eq!(headers.aligned_required(), Some(0x200));
    }

    #[test]
    fn a_short_size_of_headers_is_visible() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u32(
            builder.optional_offset() + optional::SIZE_OF_HEADERS_OFFSET,
            0x100
        ));
        let (_, derived) = derive(&builder);
        let headers = derived.headers_size.expect("headers size");
        let required = u64::try_from(builder.sections_offset() + section::SECTION_HEADER_SIZE)
            .expect("offset fits in u64");

        assert!(!headers.covers_headers());
        assert_eq!(headers.shortfall(), required - 0x100);
    }

    #[test]
    fn a_misaligned_size_of_headers_is_visible() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u32(
            builder.optional_offset() + optional::SIZE_OF_HEADERS_OFFSET,
            0x201
        ));
        let (_, derived) = derive(&builder);
        let headers = derived.headers_size.expect("headers size");

        assert_eq!(headers.declared_is_aligned(), Some(false));
        assert_eq!(headers.aligned_declared(), Some(0x400));
    }

    #[test]
    fn missing_file_alignment_disables_alignment_checks() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u32(
            builder.optional_offset() + optional::FILE_ALIGNMENT_OFFSET,
            0
        ));
        let (_, derived) = derive(&builder);
        let headers = derived.headers_size.expect("headers size");

        assert_eq!(headers.declared_is_aligned(), None);
        assert_eq!(headers.aligned_declared(), None);
        assert_eq!(headers.aligned_required(), None);
    }

    #[test]
    fn without_an_optional_header_there_is_no_derived_layout() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(
            builder.coff_offset() + coff::SIZE_OF_OPTIONAL_HEADER_OFFSET,
            0
        ));
        let (file, derived) = derive(&builder);

        assert!(file.optional.is_none());
        assert!(derived.headers_size.is_none());
        assert!(derived.image_size.is_none());
        // Without an optional header the section table is read straight after
        // COFF, so the "sections" are garbage — but they are still measured.
        assert!(derived.checksum.computed.is_none());
    }

    #[test]
    fn required_counts_declared_sections_even_when_parsing_stops() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(
            builder.coff_offset() + coff::NUMBER_OF_SECTIONS_OFFSET,
            u16::MAX
        ));
        let (file, derived) = derive(&builder);
        let headers = derived.headers_size.expect("headers size");
        let expected = u64::try_from(builder.sections_offset()).expect("offset fits in u64")
            + u64::from(u16::MAX) * section::SECTION_HEADER_SIZE as u64;

        assert!(file.sections.len() < usize::from(u16::MAX));
        assert_eq!(headers.required, expected);
        assert!(!headers.covers_headers());
    }

    #[test]
    fn image_size_matches_the_computed_extent() {
        let builder = PeBuilder::pe32();
        let (_, derived) = derive(&builder);
        let image = derived.image_size.expect("image size");

        assert_eq!(image.declared, 0x2000);
        assert_eq!(image.section_alignment, 0x1000);
        assert_eq!(image.computed, Some(0x2000));
        assert_eq!(image.is_consistent(), Some(true));
    }

    #[test]
    fn image_size_is_computed_from_the_highest_section_end() {
        let mut builder = PeBuilder::pe32();
        write_section(&mut builder, 0, 0x2800, 0x900);
        let (_, derived) = derive(&builder);
        let image = derived.image_size.expect("image size");

        // 0x2800 + 0x900 = 0x3100, rounded up to 0x4000.
        assert_eq!(image.computed, Some(0x4000));
        assert_eq!(image.is_consistent(), Some(false));
    }

    #[test]
    fn image_size_uses_the_maximum_not_the_last_entry() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(builder.coff_offset() + coff::NUMBER_OF_SECTIONS_OFFSET, 2));
        write_section(&mut builder, 0, 0x3000, 0x1000);
        write_section(&mut builder, 1, 0x1000, 0x1000);
        let (file, derived) = derive(&builder);
        let image = derived.image_size.expect("image size");

        assert_eq!(file.sections.len(), 2);
        assert_eq!(image.computed, Some(0x4000));
    }

    #[test]
    fn zero_section_alignment_makes_the_image_size_uncomputable() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u32(
            builder.optional_offset() + optional::SECTION_ALIGNMENT_OFFSET,
            0
        ));
        let (_, derived) = derive(&builder);
        let image = derived.image_size.expect("image size");

        assert_eq!(image.section_alignment, 0);
        assert_eq!(image.computed, None);
        assert_eq!(image.is_consistent(), None);
    }

    #[test]
    fn zero_sections_have_no_computed_image_size() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(builder.coff_offset() + coff::NUMBER_OF_SECTIONS_OFFSET, 0));
        let (file, derived) = derive(&builder);
        let headers = derived.headers_size.expect("headers size");
        let image = derived.image_size.expect("image size");

        assert!(file.sections.is_empty());
        assert_eq!(image.computed, None);
        // The table position is recorded even for an empty table.
        assert_eq!(
            headers.required,
            u64::try_from(builder.sections_offset()).expect("offset fits in u64")
        );
        assert!(headers.covers_headers());
    }

    #[test]
    fn derived_includes_overlay_and_checksum() {
        let mut bytes = PeBuilder::pe32().into_bytes();
        bytes.resize(bytes.len() + 0x10, 0xCC);
        let file = PeFile::parse(&bytes, &Limits::default());
        let derived = Derived::compute(&bytes, &file);

        assert!(derived.overlay.is_present());
        assert_eq!(derived.overlay.total_size(), 0x10);
        assert_eq!(derived.checksum.stored, Some(0));
        assert!(derived.checksum.computed.is_some());
        assert_eq!(derived.checksum.is_consistent(), Some(false));
    }

    /// Writes raw location fields of an existing section entry.
    fn write_raw(builder: &mut PeBuilder, index: usize, pointer: u32, size: u32) {
        let entry = builder.sections_offset() + index * section::SECTION_HEADER_SIZE;
        assert!(builder.patch_u32(entry + 16, size));
        assert!(builder.patch_u32(entry + 20, pointer));
    }

    #[test]
    fn every_section_gets_an_entropy_entry() {
        let builder = PeBuilder::pe32();
        let (_, derived) = derive(&builder);
        let entry = derived.section(0).expect("one section");

        assert_eq!(derived.section_entropy.len(), 1);
        assert_eq!(entry.index, 0);
        assert_eq!(
            entry.data,
            crate::pe::DataRegion {
                offset: 0x200,
                size: 0x200
            }
        );
        // The fixture's section is zero-filled.
        assert_eq!(entry.entropy, 0.0);
        assert!(!entry.truncated);
        assert!(!entry.is_high_entropy());
        assert!(derived.section(1).is_none());
    }

    #[test]
    fn entropy_measures_the_section_bytes() {
        let mut bytes = PeBuilder::pe32().into_bytes();
        let Some(raw) = bytes.get_mut(0x200..0x400) else {
            panic!("fixture has a raw section");
        };
        for (index, byte) in raw.iter_mut().enumerate() {
            *byte = (index % 256) as u8;
        }

        let file = PeFile::parse(&bytes, &Limits::default());
        let derived = Derived::compute(&bytes, &file);
        let entry = derived.section(0).expect("one section");

        assert_eq!(entry.entropy, 8.0);
        assert!(entry.is_high_entropy());
        assert!(!entry.truncated);
    }

    #[test]
    fn a_truncated_section_is_marked_and_measured_over_what_exists() {
        let mut builder = PeBuilder::pe32();
        write_raw(&mut builder, 0, 0x200, 0x1000);
        let (_, derived) = derive(&builder);
        let entry = derived.section(0).expect("one section");

        // The file is 0x400 bytes, so only 0x200 of the declared 0x1000 exist.
        assert_eq!(
            entry.data,
            crate::pe::DataRegion {
                offset: 0x200,
                size: 0x200
            }
        );
        assert!(entry.truncated);
        assert_eq!(entry.entropy, 0.0);
    }

    #[test]
    fn a_section_past_the_end_of_file_has_no_bytes() {
        let mut builder = PeBuilder::pe32();
        write_raw(&mut builder, 0, 0x1000, 0x200);
        let (_, derived) = derive(&builder);
        let entry = derived.section(0).expect("one section");

        assert_eq!(entry.data.size, 0);
        assert_eq!(entry.data.offset, 0x1000);
        assert!(entry.truncated);
        assert_eq!(entry.entropy, 0.0);
    }

    #[test]
    fn a_section_without_raw_data_is_not_truncated() {
        let mut builder = PeBuilder::pe32();
        write_raw(&mut builder, 0, 0x200, 0);
        let (_, derived) = derive(&builder);
        let entry = derived.section(0).expect("one section");

        assert_eq!(entry.data.size, 0);
        assert!(!entry.truncated);
        assert_eq!(entry.entropy, 0.0);
    }

    #[test]
    fn zero_sections_have_no_entropy_entries() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(builder.coff_offset() + coff::NUMBER_OF_SECTIONS_OFFSET, 0));
        let (file, derived) = derive(&builder);

        assert!(file.sections.is_empty());
        assert!(derived.section_entropy.is_empty());
    }
}
