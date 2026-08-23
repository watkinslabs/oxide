//! Effects carried from nftables into the packet owner.

extern crate alloc;
use alloc::{string::String, vec::Vec};

use conntrack::tuple::InetAddr;
use alloc::sync::Arc;
use nat::NatRange;

pub const PAYLOAD_LL_HEADER: u32 = 0;
pub const PAYLOAD_NETWORK_HEADER: u32 = 1;
pub const PAYLOAD_TRANSPORT_HEADER: u32 = 2;
pub const PAYLOAD_INNER_HEADER: u32 = 3;
pub const PAYLOAD_CSUM_NONE: u32 = 0;
pub const PAYLOAD_CSUM_INET: u32 = 1;
pub const PAYLOAD_CSUM_SCTP: u32 = 2;
pub const PAYLOAD_L4CSUM_PSEUDOHDR: u32 = 1 << 0;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ApplyError {
    Unsupported,
    Invalid,
}

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

impl Action {
    /// Apply an action to the packet buffer which owns the hook walk.
    /// Actions that require route, conntrack, or device ownership stay
    /// explicit failures until that owner supplies the corresponding state;
    /// silently accepting and dropping them would split nftables' truth.
    pub fn apply(&self, p: &mut crate::pkt::Pkt, family: u8) -> Result<(), ApplyError> {
        self.apply_at(p, family, 0)
    }

    /// Apply an action at its owning netfilter hook. Stateful actions are
    /// committed to the packet's namespace-owned conntrack entry before the
    /// packet bytes are manipulated, matching Linux's nft NAT path.
    pub fn apply_at(&self, p: &mut crate::pkt::Pkt, family: u8, _hook: u32)
        -> Result<(), ApplyError> {
        match self {
            Self::Nat { manip, range } => apply_nat_setup(p, *manip, range),
            Self::PayloadSet { base, offset, data, csum_type, csum_offset, csum_flags } => {
                if *csum_type != PAYLOAD_CSUM_NONE || *csum_offset != 0 || *csum_flags != 0 {
                    return Err(ApplyError::Unsupported);
                }
                let start = match *base {
                    PAYLOAD_NETWORK_HEADER => *offset as usize,
                    PAYLOAD_TRANSPORT_HEADER => transport_offset(p.data(), family)
                        .ok_or(ApplyError::Invalid)? + *offset as usize,
                    _ => return Err(ApplyError::Unsupported),
                };
                let end = start.checked_add(data.len()).ok_or(ApplyError::Invalid)?;
                let dst = p.data_mut().get_mut(start..end).ok_or(ApplyError::Invalid)?;
                dst.copy_from_slice(data);
                Ok(())
            }
            _ => Err(ApplyError::Unsupported),
        }
    }
}

fn apply_nat_setup(p: &mut crate::pkt::Pkt, manip: u8, range: &NatRange)
    -> Result<(), ApplyError> {
    let Some((table, Some(conn), _info, _dir)) = p.conntrack_state_owned() else {
        return Err(ApplyError::Invalid);
    };
    if nat::setup::initialized(conn.status(), manip) { return Ok(()); }
    let now = p.timestamp_ns / 1_000_000_000;
    struct Env<'a> { table: &'a conntrack::CtTable, conn: &'a Arc<conntrack::Conn>, now: u64 }
    impl nat::NatEnv for Env<'_> {
        fn tuple_taken(&self, tuple: &conntrack::tuple::Tuple) -> bool {
            self.table.tuple_taken(tuple, Some(self.conn), self.now)
        }
        fn random_u16(&self) -> u16 { self.table.random_u16() }
        fn try_evict(&self, _tuple: &conntrack::tuple::Tuple) -> bool {
            self.table.early_drop(self.now)
        }
    }
    let env = Env { table: &table.table, conn: &conn, now };
    if nat::setup_info(&conn, range, manip, &env) == nat::SetupResult::Drop {
        return Err(ApplyError::Invalid);
    }
    Ok(())
}

pub(crate) fn apply_conntrack_packet(p: &mut crate::pkt::Pkt, conn: Arc<conntrack::Conn>,
                                     dir: u8, family: u8, hook: u32)
                                     -> Result<(), ApplyError> {
    if !nat::packet_needs_manip(conn.status(), hook as u8, dir) { return Ok(()); }
    let target = nat::target_tuple(&conn, dir).ok_or(ApplyError::Invalid)?;
    let l4 = transport_offset(p.data(), family).ok_or(ApplyError::Invalid)?;
    nat::manip::manip_packet(p.data_mut(), l4, &target,
                             nat::uapi::hook_to_manip(hook as u8))
        .map_err(|_| ApplyError::Invalid)
}

fn transport_offset(pkt: &[u8], family: u8) -> Option<usize> {
    if family == 10 {
        if pkt.len() < 40 { return None; }
        return Some(40);
    }
    if family != 2 || pkt.len() < 20 || pkt[0] >> 4 != 4 { return None; }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || ihl > pkt.len() { return None; }
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1fff;
    if frag != 0 { return None; }
    Some(ihl)
}

#[cfg(test)]
mod tests {
    use alloc::{string::String, sync::Arc, vec};
    use conntrack::entry::Conn;
    use conntrack::tuple::{InetAddr, ProtoPart, Tuple, TupleEnd};
    use conntrack::uapi::{IP_CT_NEW, IPPROTO_TCP, NFPROTO_IPV4};
    use super::{apply_conntrack_packet, Action, ApplyError, PAYLOAD_NETWORK_HEADER,
                PAYLOAD_TRANSPORT_HEADER};
    use crate::pkt::Pkt;

    #[test]
    fn payload_set_mutates_packet_owner_buffer() {
        let mut pkt = Pkt::from_owned(vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17,
                                            0, 0, 10, 0, 0, 1, 10, 0, 0, 2]);
        let action = Action::PayloadSet { base: PAYLOAD_NETWORK_HEADER, offset: 1,
            data: vec![0x2e], csum_type: 0, csum_offset: 0, csum_flags: 0 };
        action.apply(&mut pkt, 2).unwrap();
        assert_eq!(pkt.data()[1], 0x2e);
    }

    #[test]
    fn payload_set_resolves_transport_header_and_rejects_bounds() {
        let mut pkt = Pkt::from_owned(vec![0x45, 0, 0, 24, 0, 0, 0, 0, 64, 17,
                                            0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
                                            0, 53, 0, 54]);
        let action = Action::PayloadSet { base: PAYLOAD_TRANSPORT_HEADER, offset: 1,
            data: vec![0xab], csum_type: 0, csum_offset: 0, csum_flags: 0 };
        action.apply(&mut pkt, 2).unwrap();
        assert_eq!(pkt.data()[21], 0xab);
        let invalid = Action::PayloadSet { base: PAYLOAD_NETWORK_HEADER, offset: 24,
            data: vec![1], csum_type: 0, csum_offset: 0, csum_flags: 0 };
        assert_eq!(invalid.apply(&mut pkt, 2), Err(ApplyError::Invalid));
    }

    #[test]
    fn stateful_actions_are_not_silently_discarded() {
        let mut pkt = Pkt::from_owned(vec![0; 20]);
        let action = Action::FlowOffload { table: String::new() };
        assert_eq!(action.apply(&mut pkt, 2), Err(ApplyError::Unsupported));
    }

    #[test]
    fn nat_action_binds_the_pending_flow_and_rewrites_the_owner() {
        let orig = Tuple { src: TupleEnd { addr: InetAddr::v4([10, 0, 0, 1]),
                proto: ProtoPart::port(40000) },
            dst: TupleEnd { addr: InetAddr::v4([198, 51, 100, 2]),
                proto: ProtoPart::port(443) }, l3num: NFPROTO_IPV4, protonum: IPPROTO_TCP, zone: 0 };
        let conn = Arc::new(Conn::new(1, orig, orig.invert().unwrap(), 7));
        let table = Arc::new(conntrack::CtNet::new(7, 1));
        table.table.add_pending(conn.clone());
        let mut pkt = Pkt::from_owned(vec![
            0x45, 0, 0, 40, 0, 0, 0, 0, 64, IPPROTO_TCP, 0, 0,
            10, 0, 0, 1, 198, 51, 100, 2, 0x9c, 0x40, 1, 0xbb,
            0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0x20, 0, 0, 0, 0, 0,
        ]);
        pkt.set_conntrack_state(table, Some(conn.clone()), IP_CT_NEW, 0);
        let action = Action::Nat { manip: nat::uapi::NF_NAT_MANIP_SRC,
            range: nat::NatRange::single_addr(InetAddr::v4([203, 0, 113, 9]), 0) };
        action.apply_at(&mut pkt, NFPROTO_IPV4, 4).unwrap();
        apply_conntrack_packet(&mut pkt, conn.clone(), 0, NFPROTO_IPV4, 4).unwrap();
        assert_eq!(&pkt.data()[12..16], &[203, 0, 113, 9]);
        assert_eq!(conn.reply_tuple().dst.addr, InetAddr::v4([203, 0, 113, 9]));
        assert!(action.apply_at(&mut pkt, NFPROTO_IPV4, 4).is_ok());
    }
}
