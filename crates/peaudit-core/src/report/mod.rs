//! The report model.
//!
//! A report is the product of one analysis: the parsed model, the findings, the
//! three verdicts and the measurements behind them. It is the only structure
//! that has a stable JSON contract, documented in `docs/report-schema.md` and
//! validated by `docs/report.schema.json`.
//!
//! Determinism is a contract, not a wish: the same bytes and the same options
//! produce a byte-identical JSON document. There is therefore no timestamp, no
//! duration and no hash-map ordering here.

use serde::Serialize;

use crate::analysis::finding::Finding;
use crate::analysis::scoring::Verdicts;
use crate::derived::Derived;
use crate::entropy::shannon_entropy;
use crate::hash::{HashSelection, hash_file, hex_digest};
use crate::limits::Limits;
use crate::pe::PeFile;

/// Version of the JSON report contract.
///
/// A breaking change bumps the major part; a new optional field bumps the minor
/// part. The value is part of the JSON document, so a consumer can refuse a
/// report it does not understand.
pub const SCHEMA_VERSION: &str = "1.0";

/// A complete analysis of one file.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// Version of the JSON contract.
    pub schema_version: &'static str,
    /// Name and version of the tool that produced the report.
    pub tool: ToolInfo,
    /// Identity of the analyzed file.
    pub file: FileInfo,
    /// What the parser managed to read.
    pub parse: ParseInfo,
    /// Three independent verdicts.
    ///
    /// `null` when the file is not a PE image at all: there is nothing to judge,
    /// and reporting three zero scores would be a false statement of "clean".
    pub verdicts: Option<Verdicts>,
    /// Findings, sorted by severity descending, then by rule id.
    pub findings: Vec<Finding>,
    /// Measurements behind the findings.
    pub metrics: Metrics,
    /// Safety caps that were applied.
    pub limits: LimitsInfo,
}

impl Report {
    /// Builds a report from an analysis.
    ///
    /// `findings` must already be sorted (`Findings::into_sorted`): the
    /// constructor does not reorder them, so the caller's ordering is the
    /// contract.
    #[must_use]
    pub fn build(
        data: &[u8],
        file: &PeFile,
        derived: &Derived,
        limits: &Limits,
        hashes: HashSelection,
        findings: Vec<Finding>,
        verdicts: Option<Verdicts>,
    ) -> Self {
        let digests = hash_file(data, hashes);

        Self {
            schema_version: SCHEMA_VERSION,
            tool: ToolInfo {
                name: "peaudit",
                version: env!("CARGO_PKG_VERSION"),
            },
            file: FileInfo {
                path: None,
                size: data.len() as u64,
                sha256: digests.sha256.map(|digest| hex_digest(&digest)),
                sha1: digests.sha1.map(|digest| hex_digest(&digest)),
                md5: digests.md5.map(|digest| hex_digest(&digest)),
            },
            parse: ParseInfo::build(file),
            verdicts,
            findings,
            metrics: Metrics::build(data, file, derived),
            limits: LimitsInfo::from_limits(limits),
        }
    }
}

/// Tool identity.
#[derive(Debug, Clone, Serialize)]
pub struct ToolInfo {
    /// Binary name, stable across versions.
    pub name: &'static str,
    /// Version from `Cargo.toml`.
    pub version: &'static str,
}

/// Identity of the analyzed file.
#[derive(Debug, Clone, Serialize)]
pub struct FileInfo {
    /// Path as given by the caller; absent in library mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Size in bytes.
    pub size: u64,
    /// SHA-256 digest, lowercase hexadecimal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// SHA-1 digest, computed only on request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    /// MD5 digest, computed only on request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,
}

/// How far the parser got and what it reported.
#[derive(Debug, Clone, Serialize)]
pub struct ParseInfo {
    /// `failed`, `partial` or `complete`.
    pub status: &'static str,
    /// `pe32` or `pe32+`, absent without an optional header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<&'static str>,
    /// Machine name such as `amd64`, absent when the COFF header was not read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine: Option<&'static str>,
    /// Parse-level decisions, in the order the parser made them.
    pub diagnostics: Vec<DiagnosticInfo>,
}

impl ParseInfo {
    fn build(file: &PeFile) -> Self {
        Self {
            status: file.state().as_str(),
            format: file.optional.map(|header| {
                if header.is_pe32_plus() {
                    "pe32+"
                } else {
                    "pe32"
                }
            }),
            machine: file.coff.and_then(|coff| coff.machine_name()),
            diagnostics: file
                .diagnostics
                .iter()
                .map(|diagnostic| {
                    let error = diagnostic.parse_error();
                    DiagnosticInfo {
                        code: diagnostic.code().as_str(),
                        severity: diagnostic.severity().as_str(),
                        offset: diagnostic.offset().map(|offset| offset as u64),
                        context: error.map(|error| error.context()),
                    }
                })
                .collect(),
        }
    }
}

/// One parser diagnostic, reduced to the fields a report needs.
#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticInfo {
    /// Stable diagnostic code such as `dos.mz-missing`.
    pub code: &'static str,
    /// `info`, `warning` or `error`.
    pub severity: &'static str,
    /// File offset the diagnostic points at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// Name of the structure that failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<&'static str>,
}

/// Measurements the rules rely on.
#[derive(Debug, Clone, Serialize)]
pub struct Metrics {
    /// Header layout, declared and required.
    pub headers: HeadersMetrics,
    /// Image extent, declared and computed.
    pub image: ImageMetrics,
    /// Overlay partition.
    pub overlay: OverlayMetrics,
    /// Checksum, stored and computed.
    pub checksum: ChecksumMetrics,
    /// Shannon entropy of the file and of every section.
    pub entropy: EntropyMetrics,
}

impl Metrics {
    fn build(data: &[u8], file: &PeFile, derived: &Derived) -> Self {
        let headers = derived.headers_size;
        let image = derived.image_size;
        let checksum = &derived.checksum;

        Self {
            headers: HeadersMetrics {
                declared: headers.map(|headers| headers.declared),
                required: headers.map(|headers| headers.required),
            },
            image: ImageMetrics {
                declared: image.map(|image| image.declared),
                computed: image.and_then(|image| image.computed),
            },
            overlay: OverlayMetrics {
                leading: RegionMetrics::from_region(derived.overlay.leading),
                certificate: RegionMetrics::from_region(derived.overlay.certificate),
                trailing: RegionMetrics::from_region(derived.overlay.trailing),
            },
            checksum: ChecksumMetrics {
                stored: checksum.stored,
                computed: checksum.computed,
                consistent: checksum.is_consistent(),
            },
            entropy: EntropyMetrics {
                file: round4(shannon_entropy(data)),
                sections: derived
                    .section_entropy
                    .iter()
                    .map(|entry| SectionEntropyMetrics {
                        index: entry.index,
                        name: file
                            .sections
                            .get(entry.index)
                            .and_then(|section| section.name_str())
                            .map(str::to_owned),
                        offset: entry.data.offset,
                        size: entry.data.size,
                        entropy: round4(entry.entropy),
                        truncated: entry.truncated,
                        high: entry.is_high_entropy(),
                    })
                    .collect(),
            },
        }
    }
}

/// `SizeOfHeaders` against the actual end of the section table.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct HeadersMetrics {
    /// Declared value, absent without an optional header.
    pub declared: Option<u32>,
    /// End of the declared section table, absent without an optional header.
    pub required: Option<u64>,
}

/// `SizeOfImage` against the aligned end of the last section.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ImageMetrics {
    /// Declared value, absent without an optional header.
    pub declared: Option<u32>,
    /// Computed value, absent when it cannot be computed.
    pub computed: Option<u64>,
}

/// Overlay, split around the certificate table.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct OverlayMetrics {
    /// Data between the last section and the certificate table.
    pub leading: RegionMetrics,
    /// Embedded attribute certificate table.
    pub certificate: RegionMetrics,
    /// Data after the certificate table.
    pub trailing: RegionMetrics,
}

/// One file region.
///
/// `offset` is `null` when the region is absent; `size` is then `0`. Keeping
/// the object shape stable means a consumer does not need to special-case
/// missing regions.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct RegionMetrics {
    /// Start offset, absent when the region does not exist.
    pub offset: Option<u64>,
    /// Size in bytes, `0` when the region does not exist.
    pub size: u64,
}

impl RegionMetrics {
    fn from_region(region: Option<crate::pe::DataRegion>) -> Self {
        match region {
            Some(region) => Self {
                offset: Some(region.offset),
                size: region.size,
            },
            None => Self {
                offset: None,
                size: 0,
            },
        }
    }
}

/// Checksum values.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ChecksumMetrics {
    /// Declared value, absent without an optional header.
    pub stored: Option<u32>,
    /// Computed value, absent without an optional header.
    pub computed: Option<u32>,
    /// Whether the two agree, absent when they cannot be compared.
    pub consistent: Option<bool>,
}

/// Entropy of the file and of every parsed section.
#[derive(Debug, Clone, Serialize)]
pub struct EntropyMetrics {
    /// Shannon entropy of the whole file, in bits per byte.
    pub file: f64,
    /// One entry per parsed section, in table order.
    pub sections: Vec<SectionEntropyMetrics>,
}

/// Entropy of one section.
#[derive(Debug, Clone, Serialize)]
pub struct SectionEntropyMetrics {
    /// Index in the section table.
    pub index: usize,
    /// Section name, absent when it is not valid UTF-8.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// File offset of the measured bytes.
    pub offset: u64,
    /// Number of bytes actually measured.
    pub size: u64,
    /// Shannon entropy, rounded to four decimals.
    pub entropy: f64,
    /// `true` when the declared raw data is larger than the file.
    pub truncated: bool,
    /// `true` when the entropy is at or above the high-entropy threshold.
    pub high: bool,
}

/// Safety caps that were applied while parsing.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct LimitsInfo {
    /// Maximum accepted input size.
    pub max_file_size: u64,
    /// Maximum number of section table entries.
    pub max_sections: usize,
    /// Maximum number of import descriptors.
    pub max_imports: usize,
    /// Maximum number of export entries.
    pub max_exports: usize,
    /// Maximum number of resource directory nodes.
    pub max_resource_nodes: usize,
    /// Maximum resource tree depth.
    pub max_resource_depth: u8,
    /// Maximum length of a single string.
    pub max_string_len: usize,
    /// Maximum number of thunks per import descriptor.
    pub max_thunks_per_import: usize,
    /// Maximum sliding window for entropy analysis.
    pub max_entropy_window: usize,
}

impl LimitsInfo {
    fn from_limits(limits: &Limits) -> Self {
        Self {
            max_file_size: limits.max_file_size,
            max_sections: limits.max_sections,
            max_imports: limits.max_imports,
            max_exports: limits.max_exports,
            max_resource_nodes: limits.max_resource_nodes,
            max_resource_depth: limits.max_resource_depth,
            max_string_len: limits.max_string_len,
            max_thunks_per_import: limits.max_thunks_per_import,
            max_entropy_window: limits.max_entropy_window,
        }
    }
}

/// Rounds a measurement to four decimals.
///
/// Entropy is a floating-point number; four decimals are enough to compare a
/// report with an external tool and keep the JSON readable.
fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}
