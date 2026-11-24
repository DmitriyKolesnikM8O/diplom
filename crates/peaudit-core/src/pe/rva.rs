//! Translating an RVA into a file offset under three competing models.
//!
//! An RVA is an address inside the loaded image, not a position in the file.
//! Turning one into the other needs a model of how the image is laid out, and
//! there is no single model: the PE/COFF specification, the Windows loader and
//! third-party parsers disagree on the edges. A malformed image can exploit
//! that disagreement, so the module exposes each model separately and never
//! silently picks one — see [`RvaResolution`].
//!
//! Everything here is pure header arithmetic: the functions never look at the
//! file length. Whether a claimed offset actually exists is a finding for a
//! rule (`PE-SEC-001`), not a reason to change the mapping. Without that
//! separation a rule could not tell "the parser stopped at the end of the file"
//! from "the file really maps an RVA this far out".
//!
//! Sections are searched in table order, so the first match wins. Overlapping
//! sections are a finding (`PE-SEC-005`), and which one you get is exactly the
//! kind of order dependence the report is meant to expose. Headers are checked
//! before sections, matching both the specification and the loader.

use crate::pe::{PeFile, SectionHeader};

/// A model used to translate an RVA into a file offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RvaStrategy {
    /// Follows the PE/COFF specification.
    ///
    /// A section spans `VirtualSize`. Inside the span, the first `SizeOfRawData`
    /// bytes are backed by the file and the rest is zero-filled. An RVA at or
    /// beyond `VirtualSize` is not part of the section, even when
    /// `SizeOfRawData` is larger.
    Spec,
    /// Models what the Windows loader does with the same headers.
    ///
    /// A section spans `max(VirtualSize, SizeOfRawData)`: raw bytes are never
    /// trimmed when they extend past `VirtualSize`, and a large `VirtualSize` is
    /// zero-filled (S8, T24 of `materials/evasion-taxonomy.md`). File-backed
    /// bytes still end at `SizeOfRawData`.
    Loader,
    /// Models parsers that take `max(VirtualSize, SizeOfRawData)` as the amount
    /// of data present in the file.
    ///
    /// Unlike [`RvaStrategy::Loader`] the whole span is treated as file-backed:
    /// such a parser reads `max(VirtualSize, SizeOfRawData)` bytes at
    /// `PointerToRawData` without checking `SizeOfRawData`. This is a common
    /// source of parser differential (T24); the strategy exists to name it, not
    /// because it is correct.
    MaxVirtualRaw,
}

impl RvaStrategy {
    /// Returns the stable machine-readable name of this strategy.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Spec => "spec",
            Self::Loader => "loader",
            Self::MaxVirtualRaw => "max-virtual-raw",
        }
    }
}

impl core::fmt::Display for RvaStrategy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The result of translating one RVA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RvaMapping {
    /// The RVA is backed by these bytes of the file.
    ///
    /// The offset is relative to the start of the file. It may be past the end
    /// of the file: checking that is a rule's job, not the mapping's.
    FileOffset(u64),
    /// The RVA belongs to the image, but the file holds no bytes for it.
    ///
    /// This is the tail of a section whose `VirtualSize` exceeds its
    /// `SizeOfRawData`: the loader supplies zeros there.
    ZeroFill,
    /// The RVA does not belong to the image under this strategy.
    Unmapped,
}

impl RvaMapping {
    /// Returns `true` if the RVA belongs to the image.
    #[must_use]
    pub const fn is_mapped(self) -> bool {
        matches!(self, Self::FileOffset(_) | Self::ZeroFill)
    }

    /// Returns the file offset, or [`None`] for a zero-filled or unmapped RVA.
    #[must_use]
    pub const fn file_offset(self) -> Option<u64> {
        match self {
            Self::FileOffset(offset) => Some(offset),
            Self::ZeroFill | Self::Unmapped => None,
        }
    }

    /// Returns the stable machine-readable name of this mapping.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileOffset(_) => "file-offset",
            Self::ZeroFill => "zero-fill",
            Self::Unmapped => "unmapped",
        }
    }
}

impl core::fmt::Display for RvaMapping {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FileOffset(offset) => write!(f, "file-offset:{offset:#x}"),
            Self::ZeroFill => f.write_str(self.as_str()),
            Self::Unmapped => f.write_str(self.as_str()),
        }
    }
}

/// The same RVA translated by every strategy.
///
/// Returned by [`PeFile::resolve_rva`] so a rule can report a disagreement
/// instead of hiding it behind one default choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RvaResolution {
    /// Mapping under [`RvaStrategy::Spec`].
    pub spec: RvaMapping,
    /// Mapping under [`RvaStrategy::Loader`].
    pub loader: RvaMapping,
    /// Mapping under [`RvaStrategy::MaxVirtualRaw`].
    pub max_virtual_raw: RvaMapping,
}

impl RvaResolution {
    /// Returns `true` if all three strategies produced the same answer.
    #[must_use]
    pub fn is_consistent(self) -> bool {
        self.spec == self.loader && self.loader == self.max_virtual_raw
    }
}

/// Translates `rva` under `strategy`, or returns [`None`] if no section admits
/// the RVA.
fn map_in_section(section: &SectionHeader, rva: u32, strategy: RvaStrategy) -> Option<RvaMapping> {
    let delta = u64::from(rva).checked_sub(u64::from(section.virtual_address))?;
    let virtual_size = u64::from(section.virtual_size);
    let raw_size = u64::from(section.size_of_raw_data);

    let span = match strategy {
        RvaStrategy::Spec => virtual_size,
        RvaStrategy::Loader | RvaStrategy::MaxVirtualRaw => virtual_size.max(raw_size),
    };
    if delta >= span {
        return None;
    }

    let file_backed = match strategy {
        RvaStrategy::Spec | RvaStrategy::Loader => delta < raw_size,
        RvaStrategy::MaxVirtualRaw => true,
    };
    if !file_backed {
        return Some(RvaMapping::ZeroFill);
    }

    // `pointer_to_raw_data` and `delta` are both below 2^32, so the sum fits in
    // a `u64`; the fallback only keeps the function free of unchecked
    // arithmetic.
    Some(
        u64::from(section.pointer_to_raw_data)
            .checked_add(delta)
            .map_or(RvaMapping::Unmapped, RvaMapping::FileOffset),
    )
}

impl PeFile {
    /// Translates `rva` into a file offset under `strategy`.
    ///
    /// RVAs below `SizeOfHeaders` are file offsets in every strategy: the
    /// headers are mapped as they are stored. When the optional header is
    /// missing, `SizeOfHeaders` is unknown and no header region exists.
    ///
    /// The result never depends on the file length; see the module docs.
    #[must_use]
    pub fn map_rva(&self, rva: u32, strategy: RvaStrategy) -> RvaMapping {
        if let Some(optional) = self.optional {
            if u64::from(rva) < u64::from(optional.size_of_headers) {
                return RvaMapping::FileOffset(u64::from(rva));
            }
        }

        for section in &self.sections {
            if let Some(mapping) = map_in_section(section, rva, strategy) {
                return mapping;
            }
        }
        RvaMapping::Unmapped
    }

    /// Translates `rva` under every strategy at once.
    #[must_use]
    pub fn resolve_rva(&self, rva: u32) -> RvaResolution {
        RvaResolution {
            spec: self.map_rva(rva, RvaStrategy::Spec),
            loader: self.map_rva(rva, RvaStrategy::Loader),
            max_virtual_raw: self.map_rva(rva, RvaStrategy::MaxVirtualRaw),
        }
    }

    /// Translates a file offset back into an RVA.
    ///
    /// Offsets below `SizeOfHeaders` map to the same value. Otherwise the first
    /// section in table order whose raw range contains `offset` wins; when raw
    /// ranges overlap, the answer therefore depends on table order, which is
    /// itself worth reporting (`PE-SEC-005`).
    ///
    /// Returns [`None`] if no structure covers the offset.
    #[must_use]
    pub fn offset_to_rva(&self, offset: u64) -> Option<u32> {
        if let Some(optional) = self.optional {
            if offset < u64::from(optional.size_of_headers) {
                return u32::try_from(offset).ok();
            }
        }

        for section in &self.sections {
            let raw_size = u64::from(section.size_of_raw_data);
            if raw_size == 0 {
                continue;
            }
            let Some(delta) = offset.checked_sub(u64::from(section.pointer_to_raw_data)) else {
                continue;
            };
            if delta >= raw_size {
                continue;
            }
            let rva = u64::from(section.virtual_address).checked_add(delta)?;
            return u32::try_from(rva).ok();
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{RvaMapping, RvaStrategy};
    use crate::limits::Limits;
    use crate::pe::{PeFile, coff, section};
    use crate::testutil::PeBuilder;

    /// One section as the tests want it, before it is written to an image.
    struct RawSection {
        virtual_address: u32,
        virtual_size: u32,
        size_of_raw_data: u32,
        pointer_to_raw_data: u32,
    }

    const fn raw(
        virtual_address: u32,
        virtual_size: u32,
        size_of_raw_data: u32,
        pointer_to_raw_data: u32,
    ) -> RawSection {
        RawSection {
            virtual_address,
            virtual_size,
            size_of_raw_data,
            pointer_to_raw_data,
        }
    }

    /// Builds a parsed image with the given sections and returns it.
    ///
    /// The section table has room for five entries before the header area ends,
    /// so tests do not have to move any offsets.
    fn image(sections: &[RawSection]) -> PeFile {
        let mut builder = PeBuilder::pe32();
        assert!(sections.len() <= 5, "the fixture has room for five entries");
        let count = u16::try_from(sections.len()).expect("section count fits in u16");
        assert!(builder.patch_u16(
            builder.coff_offset() + coff::NUMBER_OF_SECTIONS_OFFSET,
            count
        ));

        for (index, spec) in sections.iter().enumerate() {
            let mut entry = [0u8; section::SECTION_HEADER_SIZE];
            entry[..7].copy_from_slice(b".sect\0\0");
            entry[8..12].copy_from_slice(&spec.virtual_size.to_le_bytes());
            entry[12..16].copy_from_slice(&spec.virtual_address.to_le_bytes());
            entry[16..20].copy_from_slice(&spec.size_of_raw_data.to_le_bytes());
            entry[20..24].copy_from_slice(&spec.pointer_to_raw_data.to_le_bytes());
            let offset = builder.sections_offset() + index * section::SECTION_HEADER_SIZE;
            assert!(builder.patch_bytes(offset, &entry));
        }

        let file = PeFile::parse(builder.bytes(), &Limits::default());
        assert_eq!(file.sections.len(), sections.len());
        assert!(!file.has_errors(), "{:?}", file.diagnostics);
        file
    }

    const ALL: [RvaStrategy; 3] = [
        RvaStrategy::Spec,
        RvaStrategy::Loader,
        RvaStrategy::MaxVirtualRaw,
    ];

    #[test]
    fn headers_map_to_themselves_in_every_strategy() {
        let file = image(&[raw(0x1000, 0x1000, 0x200, 0x200)]);
        for strategy in ALL {
            assert_eq!(file.map_rva(0x100, strategy), RvaMapping::FileOffset(0x100));
            assert_eq!(file.map_rva(0x1FF, strategy), RvaMapping::FileOffset(0x1FF));
        }
    }

    #[test]
    fn headers_win_over_an_overlapping_section() {
        let file = image(&[raw(0x100, 0x1000, 0x200, 0x200)]);
        for strategy in ALL {
            assert_eq!(file.map_rva(0x100, strategy), RvaMapping::FileOffset(0x100));
        }
    }

    #[test]
    fn a_section_start_maps_to_its_raw_pointer() {
        let file = image(&[raw(0x1000, 0x1000, 0x200, 0x200)]);
        for strategy in ALL {
            assert_eq!(
                file.map_rva(0x1000, strategy),
                RvaMapping::FileOffset(0x200)
            );
        }
    }

    #[test]
    fn offsets_inside_raw_data_follow_the_delta() {
        let file = image(&[raw(0x1000, 0x1000, 0x200, 0x200)]);
        for strategy in ALL {
            assert_eq!(
                file.map_rva(0x1100, strategy),
                RvaMapping::FileOffset(0x300)
            );
            assert_eq!(
                file.map_rva(0x11FF, strategy),
                RvaMapping::FileOffset(0x3FF)
            );
        }
    }

    #[test]
    fn a_virtual_tail_is_zero_filled_for_spec_and_loader() {
        let file = image(&[raw(0x1000, 0x1000, 0x200, 0x200)]);
        assert_eq!(
            file.map_rva(0x1200, RvaStrategy::Spec),
            RvaMapping::ZeroFill
        );
        assert_eq!(
            file.map_rva(0x1FFF, RvaStrategy::Spec),
            RvaMapping::ZeroFill
        );
        assert_eq!(
            file.map_rva(0x1200, RvaStrategy::Loader),
            RvaMapping::ZeroFill
        );
        // The naive parser reads the same bytes as raw data.
        assert_eq!(
            file.map_rva(0x1200, RvaStrategy::MaxVirtualRaw),
            RvaMapping::FileOffset(0x400)
        );
    }

    #[test]
    fn an_rva_past_virtual_size_is_unmapped_for_spec() {
        let file = image(&[raw(0x1000, 0x1000, 0x200, 0x200)]);
        assert_eq!(
            file.map_rva(0x2000, RvaStrategy::Spec),
            RvaMapping::Unmapped
        );
        assert_eq!(
            file.map_rva(0x2000, RvaStrategy::Loader),
            RvaMapping::Unmapped
        );
    }

    #[test]
    fn raw_data_past_virtual_size_is_trimmed_only_by_spec() {
        // T24: VirtualSize < SizeOfRawData.
        let file = image(&[raw(0x1000, 0x100, 0x200, 0x200)]);
        assert_eq!(
            file.map_rva(0x1100, RvaStrategy::Spec),
            RvaMapping::Unmapped
        );
        assert_eq!(
            file.map_rva(0x1100, RvaStrategy::Loader),
            RvaMapping::FileOffset(0x300)
        );
        assert_eq!(
            file.map_rva(0x1100, RvaStrategy::MaxVirtualRaw),
            RvaMapping::FileOffset(0x300)
        );
        // Below VirtualSize all strategies agree.
        assert_eq!(
            file.map_rva(0x10FF, RvaStrategy::Spec),
            RvaMapping::FileOffset(0x2FF)
        );
    }

    #[test]
    fn zero_virtual_size_is_empty_only_for_spec() {
        // T25: VirtualSize == 0, SizeOfRawData > 0.
        let file = image(&[raw(0x1000, 0, 0x200, 0x200)]);
        assert_eq!(
            file.map_rva(0x1000, RvaStrategy::Spec),
            RvaMapping::Unmapped
        );
        assert_eq!(
            file.map_rva(0x1000, RvaStrategy::Loader),
            RvaMapping::FileOffset(0x200)
        );
        assert_eq!(
            file.map_rva(0x1000, RvaStrategy::MaxVirtualRaw),
            RvaMapping::FileOffset(0x200)
        );
    }

    #[test]
    fn a_section_without_raw_data_is_zero_filled_except_for_naive_parsers() {
        // T26: raw = 0, VirtualSize > 0.
        let file = image(&[raw(0x1000, 0x200, 0, 0)]);
        assert_eq!(
            file.map_rva(0x1000, RvaStrategy::Spec),
            RvaMapping::ZeroFill
        );
        assert_eq!(
            file.map_rva(0x1000, RvaStrategy::Loader),
            RvaMapping::ZeroFill
        );
        // The naive parser assumes raw data exists and lands in the headers.
        assert_eq!(
            file.map_rva(0x1000, RvaStrategy::MaxVirtualRaw),
            RvaMapping::FileOffset(0)
        );
    }

    #[test]
    fn an_rva_outside_the_image_is_unmapped() {
        let file = image(&[raw(0x1000, 0x1000, 0x200, 0x200)]);
        for strategy in ALL {
            assert_eq!(file.map_rva(0x9000, strategy), RvaMapping::Unmapped);
        }
    }

    #[test]
    fn the_gap_between_sections_is_unmapped() {
        let file = image(&[
            raw(0x1000, 0x1000, 0x200, 0x200),
            raw(0x3000, 0x1000, 0x200, 0x400),
        ]);
        for strategy in ALL {
            assert_eq!(file.map_rva(0x2000, strategy), RvaMapping::Unmapped);
            assert_eq!(
                file.map_rva(0x3000, strategy),
                RvaMapping::FileOffset(0x400)
            );
        }
    }

    #[test]
    fn without_an_optional_header_there_is_no_header_region() {
        let mut builder = PeBuilder::pe32();
        assert!(builder.patch_u16(
            builder.coff_offset() + coff::SIZE_OF_OPTIONAL_HEADER_OFFSET,
            0
        ));
        assert!(builder.patch_u16(builder.coff_offset() + coff::NUMBER_OF_SECTIONS_OFFSET, 0));
        let file = PeFile::parse(builder.bytes(), &Limits::default());
        assert!(file.optional.is_none());
        assert!(file.sections.is_empty());

        for strategy in ALL {
            assert_eq!(file.map_rva(0x100, strategy), RvaMapping::Unmapped);
            assert_eq!(file.map_rva(0x1000, strategy), RvaMapping::Unmapped);
        }
        assert_eq!(file.offset_to_rva(0x100), None);
        assert_eq!(file.offset_to_rva(0x200), None);
    }

    #[test]
    fn resolution_reports_disagreement_instead_of_hiding_it() {
        let file = image(&[raw(0x1000, 0x1000, 0x200, 0x200)]);
        let agreement = file.resolve_rva(0x1100);
        assert!(agreement.is_consistent());
        assert_eq!(agreement.spec, RvaMapping::FileOffset(0x300));

        let disagreement = file.resolve_rva(0x1200);
        assert!(!disagreement.is_consistent());
        assert_eq!(disagreement.spec, RvaMapping::ZeroFill);
        assert_eq!(disagreement.loader, RvaMapping::ZeroFill);
        assert_eq!(disagreement.max_virtual_raw, RvaMapping::FileOffset(0x400));
    }

    #[test]
    fn mapping_names_are_stable() {
        assert_eq!(RvaStrategy::Spec.as_str(), "spec");
        assert_eq!(RvaStrategy::Loader.as_str(), "loader");
        assert_eq!(RvaStrategy::MaxVirtualRaw.as_str(), "max-virtual-raw");
        assert_eq!(RvaMapping::FileOffset(0x10).as_str(), "file-offset");
        assert_eq!(RvaMapping::ZeroFill.as_str(), "zero-fill");
        assert_eq!(RvaMapping::Unmapped.as_str(), "unmapped");
        assert_eq!(RvaMapping::FileOffset(0x10).to_string(), "file-offset:0x10");
        assert_eq!(RvaMapping::Unmapped.to_string(), "unmapped");
    }

    #[test]
    fn mapping_helpers_agree_with_the_variant() {
        assert!(RvaMapping::FileOffset(0x10).is_mapped());
        assert!(RvaMapping::ZeroFill.is_mapped());
        assert!(!RvaMapping::Unmapped.is_mapped());
        assert_eq!(RvaMapping::FileOffset(0x10).file_offset(), Some(0x10));
        assert_eq!(RvaMapping::ZeroFill.file_offset(), None);
    }

    #[test]
    fn offset_to_rva_reverses_the_headers_and_the_section() {
        let file = image(&[raw(0x1000, 0x1000, 0x200, 0x200)]);
        assert_eq!(file.offset_to_rva(0x100), Some(0x100));
        assert_eq!(file.offset_to_rva(0x200), Some(0x1000));
        assert_eq!(file.offset_to_rva(0x3FF), Some(0x11FF));
        assert_eq!(file.offset_to_rva(0x400), None);
    }

    #[test]
    fn offset_to_rva_skips_sections_without_raw_data() {
        let file = image(&[raw(0x1000, 0x200, 0, 0), raw(0x2000, 0x1000, 0x200, 0x200)]);
        assert_eq!(file.offset_to_rva(0x200), Some(0x2000));
    }

    #[test]
    fn offset_to_rva_returns_the_first_overlapping_section() {
        let file = image(&[
            raw(0x1000, 0x1000, 0x200, 0x200),
            raw(0x5000, 0x1000, 0x200, 0x200),
        ]);
        assert_eq!(file.offset_to_rva(0x300), Some(0x1100));
    }

    #[test]
    fn offset_to_rva_refuses_an_rva_that_does_not_fit_in_u32() {
        let file = image(&[raw(0xFFFF_FF00, 0x1000, 0x200, 0x200)]);
        assert_eq!(file.offset_to_rva(0x100), Some(0x100));
        assert_eq!(file.offset_to_rva(0x300), None);
    }

    #[test]
    fn every_section_start_round_trips_through_the_spec_mapping() {
        let file = image(&[
            raw(0x1000, 0x1000, 0x200, 0x200),
            raw(0x3000, 0x800, 0x200, 0x400),
            raw(0x5000, 0x40, 0x200, 0x600),
        ]);
        for section in &file.sections {
            let expected = RvaMapping::FileOffset(u64::from(section.pointer_to_raw_data));
            assert_eq!(
                file.map_rva(section.virtual_address, RvaStrategy::Spec),
                expected
            );
            assert_eq!(
                file.map_rva(section.virtual_address, RvaStrategy::Loader),
                expected
            );
            assert_eq!(
                file.map_rva(section.virtual_address, RvaStrategy::MaxVirtualRaw),
                expected
            );
            assert_eq!(
                file.offset_to_rva(u64::from(section.pointer_to_raw_data)),
                Some(section.virtual_address)
            );
        }
    }
}
