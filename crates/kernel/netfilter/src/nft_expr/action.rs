//! Effects an expression asks for on the packet. The interpreter records
//! them; applying one needs a packet buffer, a route or a device, none of
//! which belong inside a rule walk.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use conntrack::tuple::InetAddr;
use nat::NatRange;

/// One recorded effect, in the order the rule asked for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    /// Establish a binding rewriting one end of the flow.
    Nat { manip: u8, range: NatRange },
    /// Source translation onto the egress interface's address.
    Masquerade { range: NatRange },
    /// Destination translation onto the local host.
    Redirect { range: NatRange },
    /// Copy the packet to another interface, optionally via a gateway.
    Dup { gateway: Option<InetAddr>, oif: Option<u32> },
    /// Send the packet out an interface. `nfproto` selects the neighbour
    /// form, which resolves the next hop instead of transmitting verbatim.
    Fwd { oif: u32, nfproto: Option<u8> },
    /// Emit a log record.
    Log { group: Option<u16>, level: u32, prefix: String, snaplen: u32,
          qthreshold: u16, flags: u32 },
    /// Answer the sender before dropping.
    Reject { reject_type: u32, icmp_code: u8, family: u8 },
    /// Hand the packet to a local transparent socket.
    TproxyAssign { addr: InetAddr, port: u16 },
    /// Complete the handshake on the sender's behalf.
    Synproxy { mss: u16, wscale: u8, flags: u32 },
    /// Move the flow to a software flow table.
    FlowOffload { table: String },
    /// Write register bytes into the packet and fix the checksum.
    PayloadSet { base: u32, offset: u32, data: Vec<u8>, csum_type: u32,
                 csum_offset: u32, csum_flags: u32 },
    /// Overwrite one header option.
    ExthdrSet { op: u32, htype: u8, offset: u32, data: Vec<u8> },
    /// Remove one header option.
    ExthdrStrip { op: u32, htype: u8 },
}
