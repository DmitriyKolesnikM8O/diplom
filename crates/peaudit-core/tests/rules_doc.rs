//! `docs/rules.md` is generated from the rule registry.
//!
//! The file is committed so that the documentation is readable without running
//! the generator. This test keeps the two in sync: editing a `RuleMeta` without
//! regenerating the file fails CI.

// Test code may panic: a failed assertion is the intended outcome there.
#![allow(clippy::panic)]

#[test]
fn rules_doc_is_up_to_date() {
    let committed = include_str!("../../../docs/rules.md").replace("\r\n", "\n");
    let generated = peaudit_core::analysis::rules::markdown();

    assert_eq!(
        committed, generated,
        "docs/rules.md is stale: run `cargo xtask rules-doc`"
    );
}
