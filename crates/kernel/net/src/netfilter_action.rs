//! Effects carried from nftables into the packet owner.

extern crate alloc;
use alloc::{string::String, vec::Vec};

use conntrack::tuple::InetAddr;
use nat::NatRange;

/// One effect recorded by a netfilter rule and applied by the packet owner.
/// The action list is ordered: Linux evaluates expressions and consumes each
/// effect at the hook that owns the relevant packet state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    Nat { manip: u8, range: NatRange },
    Masquerade { range: NatRange },
    Redirect { range: NatRange },
    Dup { gateway: Option<InetAddr>, oif: Option<u32> },
    Fwd { oif: u32, nfproto: Option<u8> },
    Log { group: Option<u16>, level: u32, prefix: String, snaplen: u32,
          qthreshold: u16, flags: u32 },
    Reject { reject_type: u32, icmp_code: u8, family: u8 },
    TproxyAssign { addr: InetAddr, port: u16 },
    Synproxy { mss: u16, wscale: u8, flags: u32 },
    FlowOffload { table: String },
    PayloadSet { base: u32, offset: u32, data: Vec<u8>, csum_type: u32,
                 csum_offset: u32, csum_flags: u32 },
    ExthdrSet { op: u32, htype: u8, offset: u32, data: Vec<u8> },
    ExthdrStrip { op: u32, htype: u8 },
}
