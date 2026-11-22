//! Registry of stable diagnostic codes.
//!
//! A code is a dot-separated lowercase identifier such as `"dos.mz-missing"`.
//! Once released, a code is never renamed or reused: consumers may match on it
//! in JSON reports. Parsers must use these constants instead of constructing
//! strings at the call site, so a typo becomes a missing constant.
//!
//! New codes are added here together with an entry in [`ALL`]; the test in this
//! module enforces the naming convention and rejects duplicates.

use crate::error::DiagCode;

/// A configured safety limit was exceeded and the affected substructure was
/// skipped.
pub const LIMIT_EXCEEDED: DiagCode = DiagCode::new("limit.exceeded");

/// A signature does not match the expected bytes.
pub const INVALID_SIGNATURE: DiagCode = DiagCode::new("parse.invalid-signature");

/// A field holds a value outside its allowed range.
pub const INVALID_VALUE: DiagCode = DiagCode::new("parse.invalid-value");

/// A structure ended before all of its bytes were available.
pub const TRUNCATED: DiagCode = DiagCode::new("parse.truncated");

/// A structure is well-formed but not supported by this version.
pub const UNSUPPORTED: DiagCode = DiagCode::new("parse.unsupported");

/// Every registered code, in sorted order.
///
/// Used by tests and by documentation generation; parsers refer to the
/// individual constants above.
pub const ALL: &[DiagCode] = &[
    LIMIT_EXCEEDED,
    INVALID_SIGNATURE,
    INVALID_VALUE,
    TRUNCATED,
    UNSUPPORTED,
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
