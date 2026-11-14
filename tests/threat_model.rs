//! The threat model must state its limits explicitly (IDN-19).
//!
//! The document is part of the security contract: these tests pin the
//! statements IDN-19's done-when requires, so silently weakening the
//! document fails CI instead of going unnoticed.

const THREAT_MODEL: &str = include_str!("../docs/threat-model.md");

const README: &str = include_str!("../README.md");

/// Every attacker class the backlog names must have its own section.
#[test]
fn every_attacker_class_has_a_section() {
    for class in [
        "### Passive eavesdropper",
        "### Malicious relay",
        "### Impersonator",
        "### Spammer or Sybil",
        "### Device thief",
    ] {
        assert!(
            THREAT_MODEL.contains(class),
            "threat model must cover the attacker class headed {class:?}"
        );
    }
}

/// The done-when: relay-visible origin and destination must be stated
/// plainly as a non-protection, not implied.
#[test]
fn mvp_states_relay_visible_origin_and_destination() {
    assert!(
        THREAT_MODEL.contains("Origin and destination are visible to relays."),
        "the MVP non-protection list must say plainly that relays see origin and destination"
    );
}

/// The done-when: no forward secrecy against recipient key compromise
/// must be stated plainly, with the key it is compromised through.
#[test]
fn mvp_states_no_forward_secrecy_against_recipient_key_compromise() {
    assert!(
        THREAT_MODEL.contains("No forward secrecy against recipient key compromise."),
        "the MVP non-protection list must say plainly that there is no forward secrecy \
         against recipient key compromise"
    );
    assert!(
        THREAT_MODEL.contains("recipient's long-term agreement key"),
        "the forward-secrecy limit must name the key whose compromise breaks it"
    );
}

/// Forward secrecy status is tracked per milestone, not as one vague line.
#[test]
fn forward_secrecy_status_is_given_per_milestone() {
    for row in ["| M0 to M3 (MVP) |", "| M4 (IDN-06) |", "| M6 (IDN-15) |"] {
        assert!(
            THREAT_MODEL.contains(row),
            "forward-secrecy table must contain the row {row:?}"
        );
    }
}

/// The scope requires metadata, contact graph and location to be covered.
#[test]
fn metadata_contact_graph_and_location_are_covered() {
    for topic in [
        "traffic patterns",
        "Contact graph and traffic patterns are exposed",
        "Location is protected in transit",
    ] {
        assert!(
            THREAT_MODEL.contains(topic),
            "threat model must cover the topic {topic:?}"
        );
    }
}

/// The README summary must link to the full document rather than
/// duplicating it, so the two can never drift apart silently.
#[test]
fn readme_links_to_the_threat_model() {
    assert!(
        README.contains("(docs/threat-model.md)"),
        "README must link to docs/threat-model.md"
    );
}
