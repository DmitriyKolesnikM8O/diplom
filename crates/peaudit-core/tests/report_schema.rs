//! Report contract tests.
//!
//! Two things are checked here and nowhere else:
//!
//! - a real report validates against `docs/report.schema.json`, so the schema
//!   cannot drift from the Rust structures;
//! - the validator itself rejects broken documents, so the first check is not
//!   vacuous.
//!
//! The JSON schema is deliberately small (draft-07 with `type`, `required`,
//! `properties`, `items`, `enum`, `anyOf`, `$ref` and numeric bounds), so the
//! validator below stays a hundred lines instead of pulling a dependency into
//! the core crate.

// Test code may unwrap: a failed assertion is the intended outcome there.
// JSON navigation by index is also fine here: a missing key must fail the test.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use peaudit_core::analysis::{AnalysisOptions, analyze};
use peaudit_core::pe::{optional, section};
use peaudit_core::report::Report;
use peaudit_core::testutil::PeBuilder;
use serde_json::Value;

/// Loads the schema from the repository root.
fn schema() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/report.schema.json");
    let text = std::fs::read_to_string(path).expect("schema file");
    serde_json::from_str(&text).expect("schema is valid JSON")
}

/// Builds a fixture with several independent defects.
fn dirty_builder() -> PeBuilder {
    let mut builder = PeBuilder::pe32();
    let optional_offset = builder.optional_offset();

    assert!(builder.patch_u32(optional_offset + optional::SIZE_OF_IMAGE_OFFSET, 0x1000));
    assert!(builder.patch_u32(optional_offset + optional::SIZE_OF_HEADERS_OFFSET, 0x100));
    assert!(builder.patch_u32(optional_offset + optional::CHECKSUM_OFFSET, 0x1234));

    let entry = builder.sections_offset();
    assert!(builder.patch_u32(entry + section::POINTER_TO_RAW_DATA_OFFSET, 0x80));
    assert!(builder.patch_u32(
        entry + section::CHARACTERISTICS_OFFSET,
        section::SCN_MEM_EXECUTE | section::SCN_MEM_WRITE
    ));

    builder
}

fn clean_report() -> Report {
    analyze(PeBuilder::pe32().bytes(), &AnalysisOptions::default())
}

fn report_json(report: &Report) -> Value {
    serde_json::to_value(report).expect("report serializes")
}

fn assert_valid(value: &Value) {
    let schema = schema();
    if let Err(error) = validate(value, &schema, &schema, "$") {
        panic!("report does not match the schema: {error}");
    }
}

#[test]
fn a_clean_report_matches_the_schema() {
    let report = clean_report();
    assert_valid(&report_json(&report));
}

#[test]
fn a_dirty_report_matches_the_schema() {
    let report = analyze(dirty_builder().bytes(), &AnalysisOptions::default());
    assert!(!report.findings.is_empty());
    assert_valid(&report_json(&report));
}

#[test]
fn a_non_pe_report_matches_the_schema() {
    let report = analyze(b"MZ", &AnalysisOptions::default());
    let value = report_json(&report);

    assert_eq!(value["parse"]["status"], "failed");
    assert!(value["verdicts"].is_null());
    assert_valid(&value);
}

#[test]
fn a_clean_file_produces_no_findings_and_three_clean_verdicts() {
    let report = clean_report();

    assert!(report.findings.is_empty());
    let verdicts = report.verdicts.expect("a parsed file has verdicts");
    for verdict in [verdicts.spec, verdicts.loader, verdicts.security] {
        assert_eq!(verdict.score, 0);
        assert_eq!(verdict.level.as_str(), "clean");
    }
}

#[test]
fn findings_are_sorted_by_severity_then_id() {
    let report = analyze(dirty_builder().bytes(), &AnalysisOptions::default());
    let ids: Vec<_> = report.findings.iter().map(|finding| finding.id).collect();

    assert_eq!(
        ids,
        [
            "PE-OPT-003",
            "PE-SEC-007",
            "PE-SEC-012",
            "PE-OPT-002",
            "PE-OPT-008",
        ]
    );
}

#[test]
fn the_three_verdicts_answer_different_questions() {
    let report = analyze(dirty_builder().bytes(), &AnalysisOptions::default());
    let verdicts = report.verdicts.expect("verdicts");

    // PE-SEC-007 counts only in `security`, while PE-OPT-002 counts only in
    // `spec` and `loader`, so the two scores must not coincide.
    assert!(
        verdicts.security.score != verdicts.loader.score,
        "security {} / loader {}",
        verdicts.security.score,
        verdicts.loader.score
    );
}

#[test]
fn the_report_is_deterministic() {
    let bytes = dirty_builder().into_bytes();
    let first = serde_json::to_string(&analyze(&bytes, &AnalysisOptions::default())).unwrap();
    let second = serde_json::to_string(&analyze(&bytes, &AnalysisOptions::default())).unwrap();

    assert_eq!(first, second);
}

#[test]
fn a_missing_required_field_is_rejected() {
    let mut value = report_json(&clean_report());
    value
        .as_object_mut()
        .expect("object")
        .remove("schema_version");

    let schema = schema();
    assert!(validate(&value, &schema, &schema, "$").is_err());
}

#[test]
fn an_unknown_severity_is_rejected() {
    let mut value = report_json(&clean_report());
    value["findings"] = serde_json::json!([{
        "id": "PE-XXX-001",
        "title": "test",
        "severity": "bogus",
        "confidence": "high",
        "category": "section",
        "profiles": ["security"],
        "message": "test",
        "evidence": [],
        "references": []
    }]);

    let schema = schema();
    assert!(validate(&value, &schema, &schema, "$").is_err());
}

#[test]
fn a_score_above_one_hundred_is_rejected() {
    let mut value = report_json(&clean_report());
    value["verdicts"]["security"]["score"] = serde_json::json!(101);

    let schema = schema();
    assert!(validate(&value, &schema, &schema, "$").is_err());
}

#[test]
fn an_unexpected_field_is_rejected() {
    let mut value = report_json(&clean_report());
    value["surprise"] = serde_json::json!(true);

    let schema = schema();
    assert!(validate(&value, &schema, &schema, "$").is_err());
}

/// Validates `value` against `schema`; `root` is the document `$ref`s resolve in.
fn validate(value: &Value, schema: &Value, root: &Value, path: &str) -> Result<(), String> {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let name = reference
            .strip_prefix("#/definitions/")
            .ok_or_else(|| format!("{path}: unsupported $ref `{reference}`"))?;
        let target = root
            .get("definitions")
            .and_then(|definitions| definitions.get(name))
            .ok_or_else(|| format!("{path}: unknown definition `{name}`"))?;
        return validate(value, target, root, path);
    }

    if let Some(branches) = schema.get("anyOf").and_then(Value::as_array) {
        let matched = branches
            .iter()
            .any(|branch| validate(value, branch, root, path).is_ok());
        if !matched {
            return Err(format!("{path}: matches no anyOf branch"));
        }
    }

    if let Some(kind) = schema.get("type") {
        let accepted = match kind {
            Value::String(kind) => type_matches(value, kind),
            Value::Array(kinds) => kinds
                .iter()
                .filter_map(Value::as_str)
                .any(|kind| type_matches(value, kind)),
            _ => return Err(format!("{path}: malformed type")),
        };
        if !accepted {
            return Err(format!("{path}: expected type {kind}, got {value}"));
        }
    }

    if let Some(allowed) = schema.get("enum").and_then(Value::as_array) {
        if !allowed.iter().any(|allowed| allowed == value) {
            return Err(format!("{path}: {value} is not one of {allowed:?}"));
        }
    }

    if let Some(number) = value.as_f64() {
        if let Some(minimum) = schema.get("minimum").and_then(Value::as_f64) {
            if number < minimum {
                return Err(format!("{path}: {number} is below {minimum}"));
            }
        }
        if let Some(maximum) = schema.get("maximum").and_then(Value::as_f64) {
            if number > maximum {
                return Err(format!("{path}: {number} is above {maximum}"));
            }
        }
    }

    match value {
        Value::Object(map) => {
            if let Some(required) = schema.get("required").and_then(Value::as_array) {
                for key in required.iter().filter_map(Value::as_str) {
                    if !map.contains_key(key) {
                        return Err(format!("{path}: missing `{key}`"));
                    }
                }
            }
            if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
                for (key, subschema) in properties {
                    if let Some(child) = map.get(key) {
                        validate(child, subschema, root, &format!("{path}.{key}"))?;
                    }
                }
                if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                    for key in map.keys() {
                        if !properties.contains_key(key) {
                            return Err(format!("{path}: unexpected field `{key}`"));
                        }
                    }
                }
            }
        }
        Value::Array(items) => {
            if let Some(minimum) = schema.get("minItems").and_then(Value::as_u64) {
                if (items.len() as u64) < minimum {
                    return Err(format!("{path}: fewer than {minimum} items"));
                }
            }
            if let Some(item_schema) = schema.get("items") {
                for (index, item) in items.iter().enumerate() {
                    validate(item, item_schema, root, &format!("{path}[{index}]"))?;
                }
            }
        }
        _ => {}
    }

    Ok(())
}

/// Returns `true` when `value` is of the JSON Schema `kind`.
fn type_matches(value: &Value, kind: &str) -> bool {
    match kind {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.is_i64() || value.is_u64(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => false,
    }
}
