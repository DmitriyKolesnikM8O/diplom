//! C ABI for `peaudit`.
//!
//! This is the only crate where `unsafe` is allowed: it is the boundary between
//! Rust and C. The boundary is kept as small as possible; all analysis logic
//! lives in `peaudit-core`.

#![allow(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::ffi::c_char;

/// Returns the library version as a NUL-terminated C string.
///
/// The returned pointer is valid for the whole process lifetime and must not be
/// freed by the caller.
#[unsafe(no_mangle)]
pub extern "C" fn peaudit_version() -> *const c_char {
    const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr().cast()
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use super::peaudit_version;

    #[test]
    fn version_is_a_valid_c_string() {
        let ptr = peaudit_version();
        assert!(!ptr.is_null());

        // SAFETY: `peaudit_version` returns a pointer to a static,
        // NUL-terminated string that lives for the whole process.
        let value = unsafe { CStr::from_ptr(ptr) };
        assert_eq!(
            value.to_str().unwrap_or_default(),
            env!("CARGO_PKG_VERSION")
        );
    }
}
