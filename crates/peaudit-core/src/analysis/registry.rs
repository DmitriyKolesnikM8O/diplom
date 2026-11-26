//! The rule registry.
//!
//! The registry is the single list of rules that run. It is built once, in a
//! stable order (COFF, optional header, sections), and never mutated: a report
//! must not depend on hash iteration order or on link order.
//!
//! Adding a rule means adding it to the `RULES` list of its module. The test
//! below rejects duplicate identifiers and empty metadata, and
//! `docs/rules.md` is generated from this list, so a rule cannot be shipped
//! without documentation.

use std::sync::LazyLock;

use super::rule::Rule;
use super::rules;

static RULES: LazyLock<Vec<&'static dyn Rule>> = LazyLock::new(|| {
    let mut all: Vec<&'static dyn Rule> = Vec::new();
    all.extend_from_slice(rules::coff::RULES);
    all.extend_from_slice(rules::optional::RULES);
    all.extend_from_slice(rules::section::RULES);
    all
});

/// Returns every registered rule, in stable order.
#[must_use]
pub fn rules() -> &'static [&'static dyn Rule] {
    RULES.as_slice()
}

/// Looks up a rule by its stable identifier.
#[must_use]
pub fn rule(id: &str) -> Option<&'static dyn Rule> {
    RULES.iter().copied().find(|rule| rule.meta().id == id)
}

#[cfg(test)]
mod tests {
    use super::rules;

    #[test]
    fn identifiers_are_unique() {
        let mut ids: Vec<_> = rules().iter().map(|rule| rule.meta().id).collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();

        assert_eq!(ids.len(), total, "duplicate rule id");
    }

    #[test]
    fn every_rule_has_metadata() {
        for rule in rules() {
            let meta = rule.meta();
            assert!(!meta.id.is_empty());
            assert!(meta.id.starts_with("PE-"), "{}", meta.id);
            assert!(!meta.title.is_empty(), "{}", meta.id);
            assert!(!meta.description.is_empty(), "{}", meta.id);
            assert!(!meta.profiles.is_empty(), "{}", meta.id);
            assert!(!meta.references.is_empty(), "{}", meta.id);
            assert!(!meta.family.is_empty(), "{}", meta.id);
            assert!(!meta.since.is_empty(), "{}", meta.id);
        }
    }

    #[test]
    fn the_order_is_stable() {
        let ids: Vec<_> = rules().iter().map(|rule| rule.meta().id).collect();
        let first = ids.first().copied();
        let last = ids.last().copied();

        assert_eq!(first, Some("PE-COFF-001"));
        assert_eq!(last, Some("PE-SEC-013"));
    }

    #[test]
    fn lookup_by_id_finds_the_rule() {
        let rule = super::rule("PE-SEC-007").expect("registered");
        assert_eq!(
            rule.meta().title,
            "Секция одновременно записываемая и исполняемая"
        );
        assert!(super::rule("PE-XXX-999").is_none());
    }
}
