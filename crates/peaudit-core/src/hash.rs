//! File hashes for triage and correlation.
//!
//! Hashes are not used for any security decision inside the analyzer: they let
//! a report be matched against external databases (VirusTotal, malware
//! corpora) and deduplicated. SHA-256 is the primary identifier; MD5 and SHA-1
//! are kept only for compatibility with existing feeds.
//!
//! Because every digest is a full pass over the input, the analyzer computes
//! SHA-256 by default and the legacy digests only on request. See
//! [`HashSelection`].
//!
//! The functions are thin wrappers over the RustCrypto implementations, so a
//! single call site cannot accidentally hash a different slice.

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// Which digests to compute for one input.
///
/// A full pass over the file is required for each digest, so the default is
/// [`HashSelection::SHA256_ONLY`]. Legacy digests are computed only when a
/// caller explicitly asks for them, for example for a feed that publishes MD5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashSelection {
    /// Compute the SHA-256 digest.
    pub sha256: bool,
    /// Compute the SHA-1 digest.
    pub sha1: bool,
    /// Compute the MD5 digest.
    pub md5: bool,
}

impl HashSelection {
    /// SHA-256 only, the default policy.
    pub const SHA256_ONLY: Self = Self {
        sha256: true,
        sha1: false,
        md5: false,
    };

    /// All three digests, for compatibility with external feeds.
    pub const ALL: Self = Self {
        sha256: true,
        sha1: true,
        md5: true,
    };

    /// No digest at all.
    ///
    /// Used by callers that only need the structural analysis, such as
    /// `peaudit scan --no-hashes`: skipping the passes keeps a batch scan fast
    /// when the file identity is not needed.
    pub const NONE: Self = Self {
        sha256: false,
        sha1: false,
        md5: false,
    };

    /// Returns `true` if no digest is selected.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        !self.sha256 && !self.sha1 && !self.md5
    }

    /// Returns the number of passes over the input this selection requires.
    #[must_use]
    pub const fn passes(self) -> usize {
        self.sha256 as usize + self.sha1 as usize + self.md5 as usize
    }
}

impl Default for HashSelection {
    fn default() -> Self {
        Self::SHA256_ONLY
    }
}

/// Hashes of one input buffer.
///
/// A field is [`None`] when the corresponding digest was not selected: an
/// absent hash is different from a zeroed one, and a report must not present
/// a digest that was never computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileHashes {
    /// SHA-256 digest, the primary file identifier.
    pub sha256: Option<[u8; 32]>,
    /// SHA-1 digest, kept for compatibility with existing feeds.
    pub sha1: Option<[u8; 20]>,
    /// MD5 digest, kept for compatibility with existing feeds.
    pub md5: Option<[u8; 16]>,
}

impl FileHashes {
    /// Returns `true` if no digest was computed.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.sha256.is_none() && self.sha1.is_none() && self.md5.is_none()
    }
}

/// Formats a byte string as lowercase hexadecimal.
///
/// Used for digests in reports: the JSON form of a hash is a single string, not
/// an array of decimal bytes.
#[must_use]
pub fn hex_digest(bytes: &[u8]) -> String {
    use core::fmt::Write as _;

    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        // Writing into a `String` cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Computes the SHA-256 digest of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Computes the SHA-1 digest of `data`.
///
/// SHA-1 is cryptographically broken; it is provided only for matching against
/// external datasets that still publish it.
#[must_use]
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let digest = Sha1::digest(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest);
    out
}

/// Computes the MD5 digest of `data`.
///
/// MD5 is cryptographically broken; it is provided only for matching against
/// external datasets that still publish it.
#[must_use]
pub fn md5(data: &[u8]) -> [u8; 16] {
    let digest = Md5::digest(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

/// Computes the digests selected by `selection` in one call.
///
/// Unselected digests stay [`None`]; no pass over the input is made for them.
#[must_use]
pub fn hash_file(data: &[u8], selection: HashSelection) -> FileHashes {
    FileHashes {
        sha256: selection.sha256.then(|| sha256(data)),
        sha1: selection.sha1.then(|| sha1(data)),
        md5: selection.md5.then(|| md5(data)),
    }
}

/// Computes all three digests in one call.
///
/// Equivalent to [`hash_file`] with [`HashSelection::ALL`]. Prefer
/// [`hash_file`] with [`HashSelection::SHA256_ONLY`] unless legacy digests are
/// actually needed.
#[must_use]
pub fn hash_all(data: &[u8]) -> FileHashes {
    hash_file(data, HashSelection::ALL)
}

#[cfg(test)]
mod tests {
    use super::{HashSelection, hash_all, hash_file, hex_digest, md5, sha1, sha256};

    #[test]
    fn hex_digest_is_lowercase_and_zero_padded() {
        assert_eq!(hex_digest(&[]), "");
        assert_eq!(hex_digest(&[0x00, 0x0f, 0xff]), "000fff");
    }

    fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(
            hex_digest(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_digest(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha1_matches_known_vectors() {
        assert_eq!(
            hex_digest(&sha1(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            hex_digest(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn md5_matches_known_vectors() {
        assert_eq!(hex_digest(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex_digest(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn hash_all_agrees_with_individual_functions() {
        let data = b"MZ\x90\x00this is not a real PE";
        let hashes = hash_all(data);
        assert_eq!(hashes.sha256, Some(sha256(data)));
        assert_eq!(hashes.sha1, Some(sha1(data)));
        assert_eq!(hashes.md5, Some(md5(data)));
    }

    #[test]
    fn hashes_are_stable_across_calls() {
        let data = [0xA5u8; 1000];
        assert_eq!(sha256(&data), sha256(&data));
        assert_eq!(sha1(&data), sha1(&data));
        assert_eq!(md5(&data), md5(&data));
    }

    #[test]
    fn default_selection_is_sha256_only() {
        let selection = HashSelection::default();
        assert_eq!(selection, HashSelection::SHA256_ONLY);
        assert_eq!(selection.passes(), 1);

        let data = b"abc";
        let hashes = hash_file(data, selection);
        assert_eq!(hashes.sha256, Some(sha256(data)));
        assert_eq!(hashes.sha1, None);
        assert_eq!(hashes.md5, None);
        assert!(!hashes.is_empty());
    }

    #[test]
    fn selection_controls_which_digests_are_computed() {
        let data = b"abc";

        let sha1_only = HashSelection {
            sha256: false,
            sha1: true,
            md5: false,
        };
        let hashes = hash_file(data, sha1_only);
        assert_eq!(hashes.sha256, None);
        assert_eq!(hashes.sha1, Some(sha1(data)));
        assert_eq!(hashes.md5, None);

        let none = HashSelection {
            sha256: false,
            sha1: false,
            md5: false,
        };
        assert!(none.is_empty());
        assert_eq!(none.passes(), 0);
        assert!(hash_file(data, none).is_empty());
    }

    #[test]
    fn all_selection_requires_three_passes() {
        assert_eq!(HashSelection::ALL.passes(), 3);
        assert!(!HashSelection::ALL.is_empty());
    }

    #[test]
    #[ignore = "manual benchmark: cargo test -p peaudit-core --release bench_hashes_10mb -- --ignored --nocapture"]
    fn bench_hashes_10mb() {
        const SIZE: usize = 10 * 1024 * 1024;
        let mut state = 0x0BAD_C0DE_DEAD_BEEF_u64;
        let mut data = vec![0u8; SIZE];
        for byte in &mut data {
            *byte = (xorshift(&mut state) & 0xFF) as u8;
        }

        let mib = SIZE as f64 / (1024.0 * 1024.0);
        let measure = |name: &str, run: &dyn Fn() -> usize| {
            let started = std::time::Instant::now();
            let passes = run();
            let elapsed = started.elapsed().as_secs_f64();
            println!(
                "{name}: {:.1} ms, {:.1} MiB/s ({passes} pass(es))",
                elapsed * 1000.0,
                mib * passes as f64 / elapsed
            );
        };

        measure("sha256", &|| {
            std::hint::black_box(super::sha256(&data));
            1
        });
        measure("sha1", &|| {
            std::hint::black_box(super::sha1(&data));
            1
        });
        measure("md5", &|| {
            std::hint::black_box(super::md5(&data));
            1
        });
        measure("sha256-only policy", &|| {
            std::hint::black_box(hash_file(&data, HashSelection::SHA256_ONLY));
            1
        });
        measure("all-three policy", &|| {
            std::hint::black_box(hash_file(&data, HashSelection::ALL));
            3
        });
    }
}
