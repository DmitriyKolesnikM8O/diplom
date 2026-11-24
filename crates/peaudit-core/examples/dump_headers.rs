//! Prints the parsed header model of a file.
//!
//! This is a debugging aid, not part of the analyzer: it exists so that the
//! model can be compared by hand against another parser or against a hex dump.
//!
//! ```powershell
//! cargo run -p peaudit-core --example dump_headers -- C:\Windows\System32\notepad.exe
//! ```

use std::process::ExitCode;

use peaudit_core::{Derived, Limits, PeFile};

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: dump_headers <file>");
        return ExitCode::FAILURE;
    };
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("cannot read {path}: {error}");
            return ExitCode::FAILURE;
        }
    };

    let file = PeFile::parse(&bytes, &Limits::default());
    println!("file: {path} ({} bytes)", bytes.len());
    println!("state: {}", file.state());

    let derived = Derived::compute(&bytes, &file);

    if let Some(dos) = file.dos {
        println!("dos: e_lfanew = {:#x}", dos.pe_offset);
    }
    if let Some(coff) = file.coff {
        println!(
            "coff: machine = {:#06x} ({}) sections = {} optional-size = {} characteristics = {:#06x}",
            coff.machine,
            coff.machine_name().unwrap_or("unknown"),
            coff.number_of_sections,
            coff.size_of_optional_header,
            coff.characteristics,
        );
    }
    if let Some(optional) = file.optional {
        println!(
            "optional: magic = {:#x} image-base = {:#x} entry = {:#x} subsystem = {}",
            optional.magic,
            optional.image_base,
            optional.address_of_entry_point,
            optional.subsystem_name().unwrap_or("unknown"),
        );
        println!(
            "          image-size = {:#x} headers-size = {:#x} align = {:#x}/{:#x} dirs = {}",
            optional.size_of_image,
            optional.size_of_headers,
            optional.section_alignment,
            optional.file_alignment,
            optional.number_of_rva_and_sizes,
        );
    }

    println!("directories: {}", file.directories.len());
    for directory in &file.directories {
        if !directory.is_empty() {
            println!(
                "  [{:2}] rva = {:#010x} size = {:#x}",
                directory.index, directory.virtual_address, directory.size
            );
        }
    }

    println!("sections: {}", file.sections.len());
    for (index, section) in file.sections.iter().enumerate() {
        println!(
            "  [{index}] {:?} va = {:#x} vsize = {:#x} raw = {:#x} ptr = {:#x} flags = {:#010x} entropy = {:.2?}",
            section.name_str().unwrap_or("<non-utf8>"),
            section.virtual_address,
            section.virtual_size,
            section.size_of_raw_data,
            section.pointer_to_raw_data,
            section.characteristics,
            derived.section(index).map(|entry| entry.entropy),
        );
    }

    if let Some(headers) = derived.headers_size {
        println!(
            "headers: declared = {:#x} required = {:#x} covers = {} shortfall = {:#x} aligned = {:?}",
            headers.declared,
            headers.required,
            headers.covers_headers(),
            headers.shortfall(),
            headers.declared_is_aligned(),
        );
    }
    if let Some(image) = derived.image_size {
        println!(
            "image: declared = {:#x} computed = {:x?} consistent = {:?}",
            image.declared,
            image.computed,
            image.is_consistent(),
        );
    }
    let overlay = derived.overlay;
    if overlay.is_present() || overlay.certificate.is_some() {
        println!(
            "overlay: leading = {:?} certificate = {:?} trailing = {:?} total = {:#x}",
            overlay.leading,
            overlay.certificate,
            overlay.trailing,
            overlay.total_size(),
        );
    }
    let checksum = derived.checksum;
    println!(
        "checksum: stored = {:x?} computed = {:x?} set = {} consistent = {:?}",
        checksum.stored,
        checksum.computed,
        checksum.is_set(),
        checksum.is_consistent(),
    );

    if !file.diagnostics.is_empty() {
        println!("diagnostics:");
        for diagnostic in &file.diagnostics {
            println!("  {diagnostic}");
        }
    }
    ExitCode::SUCCESS
}
