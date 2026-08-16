// The TCP transition table itself. These pin every documented cell rather
// than a sample: a single wrong entry is a state machine that accepts a
// segment it must refuse, and nothing else in the tree would notice.

use crate::proto::tcp_state::*;

fn next(dir: usize, index: usize, state: u8) -> u8 {
    TCP_CONNTRACKS[dir][index][state as usize]
}

#[test]
fn flag_classification_precedence() {
    assert_eq!(conntrack_index(TCPHDR_SYN), TCP_SYN_SET);
    assert_eq!(conntrack_index(TCPHDR_SYN | TCPHDR_ACK), TCP_SYNACK_SET);
    assert_eq!(conntrack_index(TCPHDR_FIN | TCPHDR_ACK), TCP_FIN_SET);
    assert_eq!(conntrack_index(TCPHDR_ACK), TCP_ACK_SET);
    assert_eq!(conntrack_index(0), TCP_NONE_SET);
    // A RST wins over every other bit, including SYN — otherwise a
    // SYN|RST would be classified as an opening segment.
    assert_eq!(conntrack_index(TCPHDR_RST | TCPHDR_ACK), TCP_RST_SET);
    assert_eq!(conntrack_index(TCPHDR_RST | TCPHDR_SYN), TCP_RST_SET);
    assert_eq!(conntrack_index(TCPHDR_FIN | TCPHDR_SYN), TCP_SYN_SET);
}

#[test]
fn valid_flag_combinations() {
    for f in [TCPHDR_SYN, TCPHDR_SYN | TCPHDR_URG, TCPHDR_SYN | TCPHDR_ACK,
              TCPHDR_RST, TCPHDR_RST | TCPHDR_ACK, TCPHDR_FIN | TCPHDR_ACK,
              TCPHDR_FIN | TCPHDR_ACK | TCPHDR_URG, TCPHDR_ACK, TCPHDR_ACK | TCPHDR_URG]
    { assert!(valid_flags(f), "{f:#x} is a legal combination"); }
    // PSH, ECE and CWR are always permitted on top of a legal combination.
    assert!(valid_flags(TCPHDR_ACK | TCPHDR_PSH | TCPHDR_ECE | TCPHDR_CWR));
    for f in [0u8, TCPHDR_FIN, TCPHDR_URG, TCPHDR_SYN | TCPHDR_FIN,
              TCPHDR_SYN | TCPHDR_RST, TCPHDR_FIN | TCPHDR_RST]
    { assert!(!valid_flags(f), "{f:#x} must be refused"); }
}

#[test]
fn original_direction_table_is_exact() {
    const NONE: u8 = TCP_CONNTRACK_NONE;
    let rows: [(usize, [u8; 10]); 6] = [
        (TCP_SYN_SET,    [TCP_CONNTRACK_SYN_SENT, TCP_CONNTRACK_SYN_SENT,
                          TCP_CONNTRACK_IGNORE, TCP_CONNTRACK_IGNORE,
                          TCP_CONNTRACK_IGNORE, TCP_CONNTRACK_IGNORE,
                          TCP_CONNTRACK_IGNORE, TCP_CONNTRACK_SYN_SENT,
                          TCP_CONNTRACK_SYN_SENT, TCP_CONNTRACK_SYN_SENT2]),
        (TCP_SYNACK_SET, [TCP_CONNTRACK_MAX, TCP_CONNTRACK_MAX, TCP_CONNTRACK_SYN_RECV,
                          TCP_CONNTRACK_MAX, TCP_CONNTRACK_MAX, TCP_CONNTRACK_MAX,
                          TCP_CONNTRACK_MAX, TCP_CONNTRACK_MAX, TCP_CONNTRACK_MAX,
                          TCP_CONNTRACK_SYN_RECV]),
        (TCP_FIN_SET,    [TCP_CONNTRACK_MAX, TCP_CONNTRACK_MAX, TCP_CONNTRACK_FIN_WAIT,
                          TCP_CONNTRACK_FIN_WAIT, TCP_CONNTRACK_LAST_ACK,
                          TCP_CONNTRACK_LAST_ACK, TCP_CONNTRACK_LAST_ACK,
                          TCP_CONNTRACK_TIME_WAIT, TCP_CONNTRACK_CLOSE,
                          TCP_CONNTRACK_MAX]),
        (TCP_ACK_SET,    [TCP_CONNTRACK_ESTABLISHED, TCP_CONNTRACK_MAX,
                          TCP_CONNTRACK_ESTABLISHED, TCP_CONNTRACK_ESTABLISHED,
                          TCP_CONNTRACK_CLOSE_WAIT, TCP_CONNTRACK_CLOSE_WAIT,
                          TCP_CONNTRACK_TIME_WAIT, TCP_CONNTRACK_TIME_WAIT,
                          TCP_CONNTRACK_CLOSE, TCP_CONNTRACK_MAX]),
        (TCP_RST_SET,    [TCP_CONNTRACK_MAX, TCP_CONNTRACK_CLOSE, TCP_CONNTRACK_CLOSE,
                          TCP_CONNTRACK_CLOSE, TCP_CONNTRACK_CLOSE, TCP_CONNTRACK_CLOSE,
                          TCP_CONNTRACK_CLOSE, TCP_CONNTRACK_CLOSE, TCP_CONNTRACK_CLOSE,
                          TCP_CONNTRACK_CLOSE]),
        (TCP_NONE_SET,   [TCP_CONNTRACK_MAX; 10]),
    ];
    for (index, expected) in rows {
        for state in 0..10u8 {
            assert_eq!(next(0, index, state), expected[state as usize],
                "ORIGINAL row {index} state {state}");
        }
    }
    assert_eq!(next(0, TCP_SYN_SET, NONE), TCP_CONNTRACK_SYN_SENT);
}

#[test]
fn reply_direction_table_is_exact() {
    let rows: [(usize, [u8; 10]); 6] = [
        (TCP_SYN_SET,    [TCP_CONNTRACK_MAX, TCP_CONNTRACK_SYN_SENT2, TCP_CONNTRACK_MAX,
                          TCP_CONNTRACK_MAX, TCP_CONNTRACK_MAX, TCP_CONNTRACK_MAX,
                          TCP_CONNTRACK_MAX, TCP_CONNTRACK_SYN_SENT, TCP_CONNTRACK_MAX,
                          TCP_CONNTRACK_SYN_SENT2]),
        (TCP_SYNACK_SET, [TCP_CONNTRACK_MAX, TCP_CONNTRACK_SYN_RECV, TCP_CONNTRACK_IGNORE,
                          TCP_CONNTRACK_IGNORE, TCP_CONNTRACK_IGNORE, TCP_CONNTRACK_IGNORE,
                          TCP_CONNTRACK_IGNORE, TCP_CONNTRACK_IGNORE, TCP_CONNTRACK_IGNORE,
                          TCP_CONNTRACK_SYN_RECV]),
        (TCP_FIN_SET,    [TCP_CONNTRACK_MAX, TCP_CONNTRACK_MAX, TCP_CONNTRACK_FIN_WAIT,
                          TCP_CONNTRACK_FIN_WAIT, TCP_CONNTRACK_LAST_ACK,
                          TCP_CONNTRACK_LAST_ACK, TCP_CONNTRACK_LAST_ACK,
                          TCP_CONNTRACK_TIME_WAIT, TCP_CONNTRACK_CLOSE,
                          TCP_CONNTRACK_MAX]),
        (TCP_ACK_SET,    [TCP_CONNTRACK_MAX, TCP_CONNTRACK_IGNORE, TCP_CONNTRACK_SYN_RECV,
                          TCP_CONNTRACK_ESTABLISHED, TCP_CONNTRACK_CLOSE_WAIT,
                          TCP_CONNTRACK_CLOSE_WAIT, TCP_CONNTRACK_TIME_WAIT,
                          TCP_CONNTRACK_TIME_WAIT, TCP_CONNTRACK_CLOSE,
                          TCP_CONNTRACK_IGNORE]),
        (TCP_RST_SET,    [TCP_CONNTRACK_MAX, TCP_CONNTRACK_CLOSE, TCP_CONNTRACK_CLOSE,
                          TCP_CONNTRACK_CLOSE, TCP_CONNTRACK_CLOSE, TCP_CONNTRACK_CLOSE,
                          TCP_CONNTRACK_CLOSE, TCP_CONNTRACK_CLOSE, TCP_CONNTRACK_CLOSE,
                          TCP_CONNTRACK_CLOSE]),
        (TCP_NONE_SET,   [TCP_CONNTRACK_MAX; 10]),
    ];
    for (index, expected) in rows {
        for state in 0..10u8 {
            assert_eq!(next(1, index, state), expected[state as usize],
                "REPLY row {index} state {state}");
        }
    }
}

#[test]
fn a_bare_reply_syn_from_nothing_is_invalid() {
    // The asymmetry matters: an ORIGINAL SYN opens a flow, a REPLY SYN from
    // NONE must not — otherwise a spoofed reply-side SYN creates state.
    assert_eq!(next(0, TCP_SYN_SET, TCP_CONNTRACK_NONE), TCP_CONNTRACK_SYN_SENT);
    assert_eq!(next(1, TCP_SYN_SET, TCP_CONNTRACK_NONE), TCP_CONNTRACK_MAX);
}

#[test]
fn default_timeouts() {
    assert_eq!(TCP_TIMEOUTS[TCP_CONNTRACK_SYN_SENT as usize], 120);
    assert_eq!(TCP_TIMEOUTS[TCP_CONNTRACK_SYN_RECV as usize], 60);
    assert_eq!(TCP_TIMEOUTS[TCP_CONNTRACK_ESTABLISHED as usize], 432_000);
    assert_eq!(TCP_TIMEOUTS[TCP_CONNTRACK_FIN_WAIT as usize], 120);
    assert_eq!(TCP_TIMEOUTS[TCP_CONNTRACK_CLOSE_WAIT as usize], 60);
    assert_eq!(TCP_TIMEOUTS[TCP_CONNTRACK_LAST_ACK as usize], 30);
    assert_eq!(TCP_TIMEOUTS[TCP_CONNTRACK_TIME_WAIT as usize], 120);
    assert_eq!(TCP_TIMEOUTS[TCP_CONNTRACK_CLOSE as usize], 10);
    assert_eq!(TCP_TIMEOUTS[TCP_CONNTRACK_SYN_SENT2 as usize], 120);
    assert_eq!(TCP_TIMEOUTS[TCP_CONNTRACK_RETRANS as usize], 300);
    assert_eq!(TCP_TIMEOUTS[TCP_CONNTRACK_UNACK as usize], 300);
}

#[test]
fn early_drop_only_from_closing_states() {
    for s in [TCP_CONNTRACK_FIN_WAIT, TCP_CONNTRACK_LAST_ACK, TCP_CONNTRACK_TIME_WAIT,
              TCP_CONNTRACK_CLOSE, TCP_CONNTRACK_CLOSE_WAIT]
    { assert!(can_early_drop(s)); }
    for s in [TCP_CONNTRACK_NONE, TCP_CONNTRACK_SYN_SENT, TCP_CONNTRACK_SYN_RECV,
              TCP_CONNTRACK_ESTABLISHED, TCP_CONNTRACK_SYN_SENT2]
    { assert!(!can_early_drop(s), "an open connection must not be evicted"); }
}
