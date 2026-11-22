//! File hashes for triage and correlation.
//!
//! Hashes are not used for any security decision inside the analyzer: they let
//! a report be matched against external databases (VirusTotal, malware
//! corpora) and deduplicated. MD5 and SHA-1 are kept for compatibility with
//! existing feeds; SHA-256 is the primary identifier.
//!
//! The functions are thin wrappers over the RustCrypto implementations, so a
//! single call site cannot accidentally hash a different slice.

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// Hashes of one input buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileHashes {
    /// SHA-256 digest, the primary file identifier.
    pub sha256: [u8; 32],
    /// SHA-1 digest, kept for compatibility with existing feeds.
    pub sha1: [u8; 20],
    /// MD5 digest, kept for compatibility with existing feeds.
    pub md5: [u8; 16],
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

/// Computes all three hashes in one call.
#[must_use]
pub fn hash_all(data: &[u8]) -> FileHashes {
    FileHashes {
        sha256: sha256(data),
        sha1: sha1(data),
        md5: md5(data),
    }
}

#[cfg(test)]
mod tests {
    use super::{hash_all, md5, sha1, sha256};

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;

        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            // Writing into a String cannot fail.
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha1_matches_known_vectors() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn md5_matches_known_vectors() {
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn hash_all_agrees_with_individual_functions() {
        let data = b"MZ\x90\x00this is not a real PE";
        let hashes = hash_all(data);
        assert_eq!(hashes.sha256, sha256(data));
        assert_eq!(hashes.sha1, sha1(data));
        assert_eq!(hashes.md5, md5(data));
    }

    #[test]
    fn hashes_are_stable_across_calls() {
        let data = [0xA5u8; 1000];
        assert_eq!(sha256(&data), sha256(&data));
        assert_eq!(sha1(&data), sha1(&data));
        assert_eq!(md5(&data), md5(&data));
    }
}
