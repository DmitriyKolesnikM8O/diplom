//! Integration tests for the header parser, driven through the public API.
//!
//! Unit tests live next to the code and may reach into private helpers. These
//! tests only use what a downstream crate sees: `PeFile`, `ParseState`,
//! `testutil::PeBuilder` and the diagnostic codes. They exist to catch two
//! classes of regression that unit tests cannot:
//!
//! - a public item that becomes unreachable or loses its documentation contract;
//! - a silent change in the parsed model, caught by the golden dumps below.

// Test code may unwrap: a failed assertion is the intended outcome there.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fmt::Write as _;

use peaudit_core::pe::{coff, dos, optional, section};
use peaudit_core::testutil::PeBuilder;
use peaudit_core::{Limits, ParseState, PeFile, codes};

/// Renders a deterministic one-line-per-structure description of the model.
///
/// The format is deliberately explicit: every field printed here is part of the
/// contract that rules and reports rely on.
fn dump(file: &PeFile) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "state={}", file.state());
    let _ = writeln!(
        out,
        "offsets dos={:#x} pe={:#x} coff={:#x} optional={:#x} directories={:#x} sections={:#x}",
        file.offsets.dos.unwrap_or(usize::MAX),
        file.offsets.pe_signature.unwrap_or(usize::MAX),
        file.offsets.coff.unwrap_or(usize::MAX),
        file.offsets.optional.unwrap_or(usize::MAX),
        file.offsets.directories.unwrap_or(usize::MAX),
        file.offsets.sections.unwrap_or(usize::MAX),
    );
    let coff = file.coff;
    let _ = writeln!(
        out,
        "coff machine={} sections={} optional-size={} dll={} exe={}",
        coff.and_then(|header| header.machine_name())
            .unwrap_or("none"),
        coff.map_or(0, |header| header.number_of_sections),
        coff.map_or(0, |header| header.size_of_optional_header),
        coff.is_some_and(|header| header.is_dll()),
        coff.is_some_and(|header| header.is_executable_image()),
    );
    let _ = writeln!(
        out,
        "optional magic={:#x} image-base={:#x} entry={:#x} align={:#x}/{:#x} image-size={:#x} headers-size={:#x} subsystem={} dirs={}",
        file.optional.map_or(0, |header| header.magic),
        file.optional.map_or(0, |header| header.image_base),
        file.optional
            .map_or(0, |header| header.address_of_entry_point),
        file.optional.map_or(0, |header| header.section_alignment),
        file.optional.map_or(0, |header| header.file_alignment),
        file.optional.map_or(0, |header| header.size_of_image),
        file.optional.map_or(0, |header| header.size_of_headers),
        file.optional
            .and_then(|header| header.subsystem_name())
            .unwrap_or("none"),
        file.optional
            .map_or(0, |header| header.number_of_rva_and_sizes),
    );
    let _ = writeln!(out, "directories={}", file.directories.len());
    for (index, entry) in file.sections.iter().enumerate() {
        let _ = writeln!(
            out,
            "section[{index}] name={:?} va={:#x} vsize={:#x} raw={:#x} ptr={:#x} flags={:#010x}",
            entry.name_str().unwrap_or("<non-utf8>"),
            entry.virtual_address,
            entry.virtual_size,
            entry.size_of_raw_data,
            entry.pointer_to_raw_data,
            entry.characteristics,
        );
    }
    let _ = writeln!(out, "diagnostics={}", file.diagnostics.len());
    for diagnostic in &file.diagnostics {
        let _ = writeln!(out, "  {} {}", diagnostic.severity(), diagnostic.code());
    }
    out
}

#[test]
fn pe32_model_matches_the_golden_dump() {
    let builder = PeBuilder::pe32();
    let file = PeFile::parse(builder.bytes(), &Limits::default());

    assert_eq!(file.state(), ParseState::Complete);
    assert_eq!(
        dump(&file),
        "\
state=complete
offsets dos=0x0 pe=0x40 coff=0x44 optional=0x58 directories=0xb8 sections=0x138
coff machine=i386 sections=1 optional-size=224 dll=false exe=true
optional magic=0x10b image-base=0x400000 entry=0x1000 align=0x1000/0x200 image-size=0x2000 headers-size=0x200 subsystem=windows-cui dirs=16
directories=16
section[0] name=\".text\" va=0x1000 vsize=0x1000 raw=0x200 ptr=0x200 flags=0x60000020
diagnostics=0
"
    );
}

#[test]
fn pe32plus_model_matches_the_golden_dump() {
    let builder = PeBuilder::pe32plus();
    let file = PeFile::parse(builder.bytes(), &Limits::default());

    assert_eq!(file.state(), ParseState::Complete);
    assert_eq!(
        dump(&file),
        "\
state=complete
offsets dos=0x0 pe=0x40 coff=0x44 optional=0x58 directories=0xc8 sections=0x148
coff machine=amd64 sections=1 optional-size=240 dll=false exe=true
optional magic=0x20b image-base=0x140000000 entry=0x1000 align=0x1000/0x200 image-size=0x2000 headers-size=0x200 subsystem=windows-cui dirs=16
directories=16
section[0] name=\".text\" va=0x1000 vsize=0x1000 raw=0x200 ptr=0x200 flags=0x60000020
diagnostics=0
"
    );
}

#[test]
fn layout_constants_agree_with_the_generated_image() {
    let builder = PeBuilder::pe32();
    assert_eq!(builder.pe_offset(), dos::DOS_HEADER_SIZE);
    assert_eq!(
        builder.coff_offset(),
        builder.pe_offset() + peaudit_core::pe::PE_SIGNATURE.len()
    );
    assert_eq!(
        builder.optional_offset(),
        builder.coff_offset() + coff::COFF_HEADER_SIZE
    );
    assert_eq!(
        builder.directories_offset(),
        builder.optional_offset() + optional::PE32_FIXED_SIZE
    );
    assert_eq!(
        builder.sections_offset(),
        builder.directories_offset() + 16 * optional::DIRECTORY_SIZE
    );
    assert_eq!(section::SECTION_HEADER_SIZE, 40);
}

#[test]
fn a_broken_dos_header_is_reported_through_the_public_api() {
    let mut builder = PeBuilder::pe32();
    assert!(builder.patch_bytes(0, b"XX"));
    let file = PeFile::parse(builder.bytes(), &Limits::default());

    assert_eq!(file.state(), ParseState::Failed);
    assert!(file.has_diagnostic(codes::DOS_MZ_MISSING));
    assert!(file.has_errors());
    assert!(file.dos.is_none() && file.coff.is_none() && file.optional.is_none());
}

#[test]
fn a_short_file_is_reported_as_truncated_not_as_a_missing_signature() {
    let file = PeFile::parse(b"MZ", &Limits::default());

    assert_eq!(file.state(), ParseState::Failed);
    assert!(file.has_diagnostic(codes::DOS_TRUNCATED));
    assert!(!file.has_diagnostic(codes::DOS_MZ_MISSING));
}

#[test]
fn section_flags_drive_the_write_execute_predicate() {
    let mut builder = PeBuilder::pe32();
    let characteristics_offset = builder.sections_offset() + 36;
    let writable = section::SCN_CNT_CODE
        | section::SCN_MEM_EXECUTE
        | section::SCN_MEM_READ
        | section::SCN_MEM_WRITE;
    assert!(builder.patch_u32(characteristics_offset, writable));

    let file = PeFile::parse(builder.bytes(), &Limits::default());
    let text = file.find_section(".text").expect("section .text");
    assert!(text.is_writable_and_executable());
    // The flag combination is a finding for a rule, not a parse error.
    assert_eq!(file.state(), ParseState::Complete);
    assert!(file.diagnostics.is_empty());
}
