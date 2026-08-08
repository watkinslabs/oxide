// The flow-label policy, driven as a decision.
//
// The contract these pin is that the read and the transmit answer come from
// ONE rule: what a socket reads back is what its packets do, except where the
// namespace deliberately overrides both.

use super::*;

#[test]
fn a_socket_that_named_no_policy_inherits_the_namespaces() {
    // The compiled default opts sockets in, so an untouched socket reads back
    // enabled rather than disabled.
    assert!(namespace_default(DEFAULT_POLICY));
    assert!(socket_policy(false, false, DEFAULT_POLICY));
    assert!(!socket_policy(false, false, OFF));
    assert!(!socket_policy(false, false, OPTIN));
    assert!(socket_policy(false, false, FORCED));
    // Having named one, the socket's own answer is the one that stands.
    assert!(!socket_policy(true, false, DEFAULT_POLICY));
    assert!(socket_policy(true, true, OPTIN));
}

#[test]
fn the_namespace_has_the_last_word_in_both_directions() {
    // OFF suppresses generation even for a socket that asked for it.
    assert!(!generates(true, true, OFF));
    assert!(!generates(false, false, OFF));
    // FORCED generates one even for a socket that opted out.
    assert!(generates(true, false, FORCED));
    // Between the two extremes the socket's own policy decides.
    assert!(generates(true, true, OPTIN));
    assert!(!generates(true, false, OPTIN));
    assert!(generates(false, false, OPTOUT));
    assert!(!generates(false, false, OPTIN));
}

#[test]
fn the_read_and_the_transmit_answer_agree_wherever_the_namespace_does_not_override() {
    for policy in [OPTOUT, OPTIN] {
        for named in [false, true] {
            for bit in [false, true] {
                assert_eq!(socket_policy(named, bit, policy), generates(named, bit, policy),
                    "policy {policy} named {named} bit {bit}");
            }
        }
    }
}
