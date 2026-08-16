//! Parsed expression forms. One variant per nftables expression; the fields
//! are exactly what the reference keeps in the expression's private area, so
//! evaluation never re-reads the wire blob.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

/// One compiled expression.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Expr {
    Payload {
        dreg: u32, base: u32, offset: u32, len: u32,
        /// Present on the set direction; the register supplying the bytes.
        sreg: Option<u32>,
        csum_type: u32, csum_offset: u32, csum_flags: u32,
    },
    Cmp { sreg: u32, op: u32, data: Vec<u8> },
    Immediate { dreg: u32, verdict: Option<i32>, chain: Option<String>, value: Vec<u8> },
    Meta { dreg: Option<u32>, sreg: Option<u32>, key: u32 },
    Lookup { sreg: u32, dreg: Option<u32>, set: String, set_id: Option<usize>, invert: bool },
    Counter,
    Bitwise { sreg: u32, dreg: u32, mask: Vec<u8>, xor: Vec<u8> },
    Byteorder { sreg: u32, dreg: u32, op: u32, len: u32, size: u32 },

    Ct { dreg: Option<u32>, sreg: Option<u32>, key: u32, dir: Option<u8>, len: u32 },
    Nat {
        nat_type: u32, family: u8, flags: u32,
        sreg_addr_min: Option<u32>, sreg_addr_max: Option<u32>,
        sreg_proto_min: Option<u32>, sreg_proto_max: Option<u32>,
    },
    Masq { flags: u32, sreg_proto_min: Option<u32>, sreg_proto_max: Option<u32> },
    Redir { flags: u32, sreg_proto_min: Option<u32>, sreg_proto_max: Option<u32> },
    Dup { sreg_addr: Option<u32>, sreg_dev: Option<u32> },
    Fwd { sreg_dev: u32, sreg_addr: Option<u32>, nfproto: Option<u8> },

    Limit { index: usize, limit_type: u32, rate: u64, nsecs: u64, burst: u32,
            tokens_max: u64, invert: bool },
    Log { group: Option<u16>, prefix: String, snaplen: u32, qthreshold: u16,
          level: u32, flags: u32 },
    Queue { num: u16, total: u16, flags: u32, sreg_qnum: Option<u32> },
    Quota { index: usize, quota: u64, consumed: u64, invert: bool },
    Reject { reject_type: u32, icmp_code: u8 },

    Hash { sreg: u32, dreg: u32, len: u32, modulus: u32, seed: u32, offset: u32,
           hash_type: u32 },
    Numgen { index: usize, dreg: u32, modulus: u32, offset: u32, ng_type: u32 },
    Range { sreg: u32, op: u32, from: Vec<u8>, to: Vec<u8> },
    Objref { obj_type: Option<u32>, name: Option<String>, sreg: Option<u32>,
             set: Option<String>, set_id: Option<usize> },

    Exthdr { dreg: Option<u32>, sreg: Option<u32>, op: u32, htype: u8, offset: u32,
             len: u32, flags: u32 },
    Rt { dreg: u32, key: u32 },
    Fib { dreg: u32, result: u32, flags: u32 },
    Socket { dreg: u32, key: u32, level: u32 },
    Osf { dreg: u32, ttl: u8, flags: u32 },

    Tproxy { family: u8, sreg_addr: Option<u32>, sreg_port: Option<u32> },
    Synproxy { mss: u16, wscale: u8, flags: u32 },
    Connlimit { index: usize, count: u32, invert: bool },
    FlowOffload { table: String },
    Xfrm { dreg: u32, key: u32, dir: u32, spnum: u32 },
    Last { index: usize, set: bool, msecs: u64 },
    Tunnel { dreg: u32, key: u32, mode: u32 },
}

/// Why a rule's expression list was refused. Each maps onto the errno the
/// reference reports for the same input.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// The blob does not decode, a required attribute is absent, or a value
    /// is out of the range its attribute permits.
    Malformed,
    /// The expression, or a flag inside it, is not one this kernel serves.
    Unsupported,
    /// A referenced set does not exist in the rule's table.
    MissingSet,
    /// A computed bound would wrap.
    Overflow,
    /// A modulus or index falls outside its permitted span.
    OutOfRange,
    /// The rule sits on a hook or family where the expression can never fire.
    WrongHook,
}

impl Expr {
    /// Index into the per-rule stateful-expression array, for the expressions
    /// that carry counters between packets. # C: O(1)
    pub fn state_index(&self) -> Option<usize> {
        match self {
            Expr::Limit { index, .. } | Expr::Quota { index, .. }
            | Expr::Numgen { index, .. } | Expr::Connlimit { index, .. }
            | Expr::Last { index, .. } => Some(*index),
            _ => None,
        }
    }
}
