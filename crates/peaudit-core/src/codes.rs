//! Registry of stable diagnostic codes.
//!
//! A code is a dot-separated lowercase identifier such as `"dos.mz-missing"`.
//! Once released, a code is never renamed or reused: consumers may match on it
//! in JSON reports. Parsers must use these constants instead of constructing
//! strings at the call site, so a typo becomes a missing constant.
//!
//! New codes are added here together with an entry in [`ALL`]; the test in this
//! module enforces the naming convention and rejects duplicates. A code in
//! [`ALL`] must also be produced by some input — a registered code that no
//! parser path can emit is a registry bug, not a spare slot (see the
//! reachability test in [`crate::pe`]).
//!
//! The registry describes **parse-level** problems only. Non-conformance that
//! requires no parsing decision — zero sections, a value outside the
//! specification — is a finding for a rule, not a diagnostic (ADR-0005).

use crate::error::DiagCode;

/// A configured safety limit was exceeded and the affected substructure was
/// skipped.
pub const LIMIT_EXCEEDED: DiagCode = DiagCode::new("limit.exceeded");

/// The file is smaller than the 64-byte DOS header.
pub const DOS_TRUNCATED: DiagCode = DiagCode::new("dos.truncated");

/// The file does not start with `MZ`.
pub const DOS_MZ_MISSING: DiagCode = DiagCode::new("dos.mz-missing");

/// `e_lfanew` points inside the DOS header instead of past it.
pub const DOS_PE_OFFSET_TOO_SMALL: DiagCode = DiagCode::new("dos.pe-offset-too-small");

/// `e_lfanew` points outside the file.
pub const DOS_PE_OFFSET_OUT_OF_RANGE: DiagCode = DiagCode::new("dos.pe-offset-out-of-range");

/// `e_lfanew` is not 4-byte aligned. Informational: some parsers accept it.
pub const DOS_PE_OFFSET_UNALIGNED: DiagCode = DiagCode::new("dos.pe-offset-unaligned");

/// The PE signature `PE\0\0` was not found at `e_lfanew`.
pub const PE_SIGNATURE_MISSING: DiagCode = DiagCode::new("pe.signature-missing");

/// The file ends inside the 4-byte PE signature.
pub const PE_SIGNATURE_TRUNCATED: DiagCode = DiagCode::new("pe.signature-truncated");

/// The 20-byte COFF header is not fully present.
pub const COFF_TRUNCATED: DiagCode = DiagCode::new("coff.truncated");

/// `SizeOfOptionalHeader` is zero, so the optional header is absent.
pub const COFF_MISSING_OPTIONAL_HEADER: DiagCode = DiagCode::new("coff.missing-optional-header");

/// The optional header is not fully present.
pub const OPTIONAL_TRUNCATED: DiagCode = DiagCode::new("optional.truncated");

/// The optional header magic is neither `0x10B` nor `0x20B` nor `0x107`.
pub const OPTIONAL_BAD_MAGIC: DiagCode = DiagCode::new("optional.bad-magic");

/// The optional header magic is `0x107` (ROM image), which is not modeled.
pub const OPTIONAL_ROM_UNSUPPORTED: DiagCode = DiagCode::new("optional.rom-unsupported");

/// `SizeOfOptionalHeader` is smaller than the fixed part of the header.
pub const OPTIONAL_SIZE_MISMATCH: DiagCode = DiagCode::new("optional.size-mismatch");

/// `NumberOfRvaAndSizes` exceeds the 16 directories defined by the specification.
pub const OPTIONAL_TOO_MANY_DIRECTORIES: DiagCode = DiagCode::new("optional.too-many-directories");

/// The data directory array ends before all declared entries were read.
pub const DIRECTORIES_TRUNCATED: DiagCode = DiagCode::new("directories.truncated");

/// The section table ends before all declared entries were read.
pub const SECTIONS_TRUNCATED: DiagCode = DiagCode::new("sections.truncated");

/// Every registered code, in sorted order.
///
/// Used by tests and by documentation generation; parsers refer to the
/// individual constants above.
pub const ALL: &[DiagCode] = &[
    COFF_MISSING_OPTIONAL_HEADER,
    COFF_TRUNCATED,
    DIRECTORIES_TRUNCATED,
    DOS_MZ_MISSING,
    DOS_PE_OFFSET_OUT_OF_RANGE,
    DOS_PE_OFFSET_TOO_SMALL,
    DOS_PE_OFFSET_UNALIGNED,
    DOS_TRUNCATED,
    LIMIT_EXCEEDED,
    OPTIONAL_BAD_MAGIC,
    OPTIONAL_ROM_UNSUPPORTED,
    OPTIONAL_SIZE_MISMATCH,
    OPTIONAL_TOO_MANY_DIRECTORIES,
    OPTIONAL_TRUNCATED,
    PE_SIGNATURE_MISSING,
    PE_SIGNATURE_TRUNCATED,
    SECTIONS_TRUNCATED,
];

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::ALL;

    /// Accepts `segment(.segment)*` where each segment is lowercase ASCII,
    /// digits and interior hyphens, and starts/ends with an alphanumeric.
    fn is_valid_code(code: &str) -> bool {
        if code.is_empty() {
            return false;
        }
        code.split('.').all(|segment| {
            let bytes = segment.as_bytes();
            let alphanumeric = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
            !bytes.is_empty()
                && bytes.first().is_some_and(alphanumeric)
                && bytes.last().is_some_and(alphanumeric)
                && bytes.iter().all(|byte| alphanumeric(byte) || *byte == b'-')
        })
    }

    #[test]
    fn every_code_matches_the_naming_convention() {
        for code in ALL {
            assert!(
                is_valid_code(code.as_str()),
                "invalid diagnostic code: {code}"
            );
        }
    }

    #[test]
    fn validator_rejects_bad_codes() {
        assert!(is_valid_code("dos.mz-missing"));
        assert!(is_valid_code("limit.exceeded"));
        assert!(!is_valid_code(""));
        assert!(!is_valid_code(".dos"));
        assert!(!is_valid_code("dos."));
        assert!(!is_valid_code("dos..mz"));
        assert!(!is_valid_code("Dos.MZ"));
        assert!(!is_valid_code("dos.-mz"));
        assert!(!is_valid_code("dos.mz-"));
    }

    #[test]
    fn all_is_sorted_and_unique() {
        let mut sorted = ALL.to_vec();
        sorted.sort();
        assert_eq!(sorted, ALL, "ALL must stay sorted");

        let unique: HashSet<_> = ALL.iter().collect();
        assert_eq!(unique.len(), ALL.len(), "duplicate diagnostic code");
    }
}
