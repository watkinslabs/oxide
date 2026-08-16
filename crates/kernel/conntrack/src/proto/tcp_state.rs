//! TCP conntrack state constants and the transition table. The table is the
//! whole policy: a packet's flag class plus the direction it arrived from
//! selects the next state, and two of the entries are not states at all —
//! `IGNORE` means "let it pass without changing anything" and `INVALID`
//! means "conntrack refuses it".

/// Conntrack's TCP states. Distinct from the endpoint's own TCP state: this
/// is what a middlebox can infer from the segments it has seen.
pub const TCP_CONNTRACK_NONE:        u8 = 0;
pub const TCP_CONNTRACK_SYN_SENT:    u8 = 1;
pub const TCP_CONNTRACK_SYN_RECV:    u8 = 2;
pub const TCP_CONNTRACK_ESTABLISHED: u8 = 3;
pub const TCP_CONNTRACK_FIN_WAIT:    u8 = 4;
pub const TCP_CONNTRACK_CLOSE_WAIT:  u8 = 5;
pub const TCP_CONNTRACK_LAST_ACK:    u8 = 6;
pub const TCP_CONNTRACK_TIME_WAIT:   u8 = 7;
pub const TCP_CONNTRACK_CLOSE:       u8 = 8;
pub const TCP_CONNTRACK_SYN_SENT2:   u8 = 9;
/// One past the last real state; the table uses it as "invalid".
pub const TCP_CONNTRACK_MAX:         u8 = 10;
/// Table sentinel meaning "ignore this packet, keep the current state".
pub const TCP_CONNTRACK_IGNORE:      u8 = 11;
/// Pseudo-state slots that exist only to carry a timeout.
pub const TCP_CONNTRACK_RETRANS:     u8 = 12;
pub const TCP_CONNTRACK_UNACK:       u8 = 13;
pub const TCP_CONNTRACK_TIMEOUT_MAX: usize = 14;

/// Human names, in state order — the strings `/proc/net/nf_conntrack` prints.
pub const TCP_STATE_NAMES: [&str; 10] = [
    "NONE", "SYN_SENT", "SYN_RECV", "ESTABLISHED", "FIN_WAIT",
    "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE", "SYN_SENT2",
];

/// Flag-combination classes the transition table is indexed by.
pub const TCP_SYN_SET:    usize = 0;
pub const TCP_SYNACK_SET: usize = 1;
pub const TCP_FIN_SET:    usize = 2;
pub const TCP_ACK_SET:    usize = 3;
pub const TCP_RST_SET:    usize = 4;
pub const TCP_NONE_SET:   usize = 5;
pub const TCP_BIT_SET_MAX: usize = 6;

// TCP header flag bits.
pub const TCPHDR_FIN: u8 = 0x01;
pub const TCPHDR_SYN: u8 = 0x02;
pub const TCPHDR_RST: u8 = 0x04;
pub const TCPHDR_PSH: u8 = 0x08;
pub const TCPHDR_ACK: u8 = 0x10;
pub const TCPHDR_URG: u8 = 0x20;
pub const TCPHDR_ECE: u8 = 0x40;
pub const TCPHDR_CWR: u8 = 0x80;

// Per-direction tracking flags.
pub const IP_CT_TCP_FLAG_WINDOW_SCALE:          u8 = 0x01;
pub const IP_CT_TCP_FLAG_SACK_PERM:             u8 = 0x02;
pub const IP_CT_TCP_FLAG_CLOSE_INIT:            u8 = 0x04;
pub const IP_CT_TCP_FLAG_BE_LIBERAL:            u8 = 0x08;
pub const IP_CT_TCP_FLAG_DATA_UNACKNOWLEDGED:   u8 = 0x10;
pub const IP_CT_TCP_FLAG_MAXACK_SET:            u8 = 0x20;
pub const IP_CT_EXP_CHALLENGE_ACK:              u8 = 0x40;
pub const IP_CT_TCP_SIMULTANEOUS_OPEN:          u8 = 0x80;

/// Largest window scale a peer may advertise.
pub const TCP_MAX_WSCALE: u8 = 14;

// TCP option kinds the tracker reads.
pub const TCPOPT_EOL:       u8 = 0;
pub const TCPOPT_NOP:       u8 = 1;
pub const TCPOPT_WINDOW:    u8 = 3;
pub const TCPOPT_SACK_PERM: u8 = 4;
pub const TCPOPT_SACK:      u8 = 5;
pub const TCPOLEN_WINDOW:    u8 = 3;
pub const TCPOLEN_SACK_PERM: u8 = 2;

/// Floor for the ACK-window lower bound, so a tiny advertised window does not
/// make every delayed ACK look out of range.
pub const MAXACKWINCONST: u32 = 66000;

/// Default per-state timeouts, seconds.
pub const TCP_TIMEOUTS: [u32; TCP_CONNTRACK_TIMEOUT_MAX] = [
    0,        // NONE — never used as a live state
    120,      // SYN_SENT
    60,       // SYN_RECV
    432_000,  // ESTABLISHED (5 days)
    120,      // FIN_WAIT
    60,       // CLOSE_WAIT
    30,       // LAST_ACK
    120,      // TIME_WAIT
    10,       // CLOSE
    120,      // SYN_SENT2
    0,        // MAX sentinel slot, never armed
    0,        // IGNORE sentinel slot, never armed
    300,      // RETRANS
    300,      // UNACK
];

/// Retransmissions in one direction after which the entry drops to the
/// RETRANS timeout.
pub const TCP_MAX_RETRANS: u8 = 3;

const S: u8 = TCP_CONNTRACK_SYN_SENT;
const R: u8 = TCP_CONNTRACK_SYN_RECV;
const E: u8 = TCP_CONNTRACK_ESTABLISHED;
const F: u8 = TCP_CONNTRACK_FIN_WAIT;
const W: u8 = TCP_CONNTRACK_CLOSE_WAIT;
const L: u8 = TCP_CONNTRACK_LAST_ACK;
const T: u8 = TCP_CONNTRACK_TIME_WAIT;
const C: u8 = TCP_CONNTRACK_CLOSE;
const D: u8 = TCP_CONNTRACK_SYN_SENT2;
const V: u8 = TCP_CONNTRACK_MAX;      // invalid
const G: u8 = TCP_CONNTRACK_IGNORE;   // ignore

/// `[direction][flag class][current state] -> next state`. Direction 0 is the
/// original direction, 1 the reply. Column order is the state constants above.
pub const TCP_CONNTRACKS: [[[u8; 10]; TCP_BIT_SET_MAX]; 2] = [
    [ // ORIGINAL
        //  NONE SS   SR   ES   FW   CW   LA   TW   CL   S2
        [    S,   S,   G,   G,   G,   G,   G,   S,   S,   D ], // syn
        [    V,   V,   R,   V,   V,   V,   V,   V,   V,   R ], // syn|ack
        [    V,   V,   F,   F,   L,   L,   L,   T,   C,   V ], // fin
        [    E,   V,   E,   E,   W,   W,   T,   T,   C,   V ], // ack
        [    V,   C,   C,   C,   C,   C,   C,   C,   C,   C ], // rst
        [    V,   V,   V,   V,   V,   V,   V,   V,   V,   V ], // none
    ],
    [ // REPLY
        //  NONE SS   SR   ES   FW   CW   LA   TW   CL   S2
        [    V,   D,   V,   V,   V,   V,   V,   S,   V,   D ], // syn
        [    V,   R,   G,   G,   G,   G,   G,   G,   G,   R ], // syn|ack
        [    V,   V,   F,   F,   L,   L,   L,   T,   C,   V ], // fin
        [    V,   G,   R,   E,   W,   W,   T,   T,   C,   G ], // ack
        [    V,   C,   C,   C,   C,   C,   C,   C,   C,   C ], // rst
        [    V,   V,   V,   V,   V,   V,   V,   V,   V,   V ], // none
    ],
];

/// Flag class of one segment. Precedence is RST, then SYN (with or without
/// ACK), then FIN, then bare ACK — a RST carrying an ACK is a RST.
/// # C: O(1)
pub const fn conntrack_index(flags: u8) -> usize {
    if flags & TCPHDR_RST != 0 { return TCP_RST_SET; }
    if flags & TCPHDR_SYN != 0 {
        return if flags & TCPHDR_ACK != 0 { TCP_SYNACK_SET } else { TCP_SYN_SET };
    }
    if flags & TCPHDR_FIN != 0 { return TCP_FIN_SET; }
    if flags & TCPHDR_ACK != 0 { return TCP_ACK_SET; }
    TCP_NONE_SET
}

/// Flag combinations conntrack considers structurally legal, after masking
/// off ECE/CWR/PSH which are always allowed. Anything else is a malformed
/// segment and never reaches the state machine. # C: O(1)
pub fn valid_flags(flags: u8) -> bool {
    let f = flags & !(TCPHDR_ECE | TCPHDR_CWR | TCPHDR_PSH);
    matches!(f,
        TCPHDR_SYN
        | 0x22 // SYN|URG
        | 0x12 // SYN|ACK
        | TCPHDR_RST
        | 0x14 // RST|ACK
        | 0x11 // FIN|ACK
        | 0x31 // FIN|ACK|URG
        | TCPHDR_ACK
        | 0x30 // ACK|URG
    )
}

/// States from which an entry may be evicted early under table pressure.
/// # C: O(1)
pub fn can_early_drop(state: u8) -> bool {
    matches!(state, TCP_CONNTRACK_FIN_WAIT | TCP_CONNTRACK_LAST_ACK
        | TCP_CONNTRACK_TIME_WAIT | TCP_CONNTRACK_CLOSE | TCP_CONNTRACK_CLOSE_WAIT)
}
