//! Live netfilter hook state translated into nftables expression inputs.

use crate::nft_expr::{EvalCtx, IfInfo};

pub(crate) struct Input<'a> {
    pub namespace: u64,
    pub hook_id: u32,
    pub pkt: &'a [u8],
    pub ll: &'a [u8],
    pub family: u8,
    pub link_protocol: Option<u16>,
    pub mark: u32,
    pub priority: u32,
    pub ingress: Option<net::NetIfaceId>,
    pub egress: Option<net::NetIfaceId>,
    pub timestamp_ns: u64,
    pub ct: Option<&'a conntrack::Conn>,
    pub ct_available: bool,
    pub ctinfo: u8,
    pub ct_dir: u8,
    pub socket: Option<net::SocketLookup>,
    pub live: bool,
    pub chain_min_priority: Option<i32>,
    pub chain_max_priority: Option<i32>,
}

impl<'a> Input<'a> {
    pub(crate) const fn bare(namespace: u64, hook_id: u32, pkt: &'a [u8], family: u8,
                             mark: u32) -> Self {
        Self { namespace, hook_id, pkt, ll: &[], family, link_protocol: None, mark, priority: 0,
            ingress: None, egress: None, timestamp_ns: 0,
            ct: None, ct_available: false, ctinfo: conntrack::uapi::IP_CT_UNTRACKED, ct_dir: 0,
            socket: None,
            live: false, chain_min_priority: None, chain_max_priority: None }
    }

    pub(crate) fn from_hook(hook: &'a net::stack::NfHookCtx<'a>) -> Self {
        let socket = net::global_stack().socket_lookup_in(
            hook.namespace, hook.family, hook.pkt, hook.ingress);
        Self { namespace: hook.namespace, hook_id: hook.hook_id, pkt: hook.pkt, ll: hook.ll,
            family: hook.family, link_protocol: hook.link_protocol, mark: hook.mark, priority: hook.priority,
            ingress: hook.ingress, egress: hook.egress, timestamp_ns: hook.timestamp_ns,
            ct: hook.ct, ct_available: hook.ct_available,
            ctinfo: hook.ctinfo, ct_dir: hook.ct_dir, socket, live: true,
            chain_min_priority: hook.chain_min_priority, chain_max_priority: hook.chain_max_priority }
    }

    pub(crate) fn populate(&self, ctx: &mut EvalCtx<'a>, mark: u32) {
        ctx.hook = self.hook_id as u8;
        ctx.mark = mark;
        ctx.ll = self.ll;
        ctx.meta.protocol = self.link_protocol.or_else(|| match self.family {
            crate::nft_expr::uapi::NFPROTO_IPV4 => Some(net::addr::eth_p::IPV4),
            crate::nft_expr::uapi::NFPROTO_IPV6 => Some(net::addr::eth_p::IPV6),
            _ => None,
        });
        ctx.meta.priority = self.priority;
        ctx.meta.iif = self.ingress.and_then(|id| iface(self.namespace, id));
        ctx.meta.oif = self.egress.and_then(|id| iface(self.namespace, id));
        if self.timestamp_ns != 0 { ctx.meta.time_ns = Some(self.timestamp_ns); }
        ctx.meta.l4proto = l4proto(self.family, self.pkt);
        ctx.meta.fragoff = fragoff(self.family, self.pkt);
        if let Some(socket) = self.socket {
            ctx.meta.skuid = socket.uid;
            ctx.meta.skgid = socket.gid;
        }
    }
}

fn iface(namespace: u64, id: net::NetIfaceId) -> Option<IfInfo> {
    let stack = net::global_stack();
    let index = stack.ifaces.ifindex_in_ns(id, namespace)?;
    let dev = stack.ifaces.lookup_in_ns(id, namespace)?;
    let mut name = [0; crate::nft_expr::limits::IFNAMSIZ];
    let bytes = dev.name().as_bytes();
    let n = bytes.len().min(name.len().saturating_sub(1));
    name[..n].copy_from_slice(&bytes[..n]);
    Some(IfInfo { index, name, kind: [0; crate::nft_expr::limits::IFNAMSIZ],
        iftype: dev.hardware_type(), group: 0 })
}

fn fragoff(family: u8, pkt: &[u8]) -> u16 {
    match family {
        crate::nft_expr::uapi::NFPROTO_IPV4 if pkt.len() >= 8 =>
            u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1fff,
        _ => 0,
    }
}

fn l4proto(family: u8, pkt: &[u8]) -> Option<u8> {
    match family {
        crate::nft_expr::uapi::NFPROTO_IPV4 => {
            if pkt.first().map(|b| b >> 4) != Some(4) { return None; }
            let ihl = pkt.first().map(|b| (b & 0x0f) as usize * 4)?;
            (ihl >= 20 && pkt.len() >= ihl).then(|| pkt.get(9).copied()).flatten()
        }
        crate::nft_expr::uapi::NFPROTO_IPV6 => ipv6_l4proto(pkt),
        _ => None,
    }
}

fn ipv6_l4proto(pkt: &[u8]) -> Option<u8> {
    if pkt.len() < 40 || pkt[0] >> 4 != 6 { return None; }
    let mut next = pkt[6];
    let mut off = 40usize;
    loop {
        match next {
            0 | 43 | 60 => {
                let len = ((*pkt.get(off + 1)? as usize) + 1) * 8;
                next = *pkt.get(off)?;
                off = off.checked_add(len)?;
                if off > pkt.len() { return None; }
            }
            44 => {
                let fragment = u16::from_be_bytes([*pkt.get(off + 2)?, *pkt.get(off + 3)?]);
                if fragment & 0xfff8 != 0 { return None; }
                next = *pkt.get(off)?;
                off = off.checked_add(8)?;
                if off > pkt.len() { return None; }
            }
            51 => {
                let len = ((*pkt.get(off + 1)? as usize) + 2) * 4;
                next = *pkt.get(off)?;
                off = off.checked_add(len)?;
                if off > pkt.len() { return None; }
            }
            _ => return Some(next),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::l4proto;
    use crate::nft_expr::{EvalCtx, ExprStates};
    use crate::nft_expr::uapi::{NFPROTO_IPV4, NFPROTO_IPV6};

    #[test]
    fn packet_context_publishes_ipv4_transport_protocol() {
        let mut pkt = [0u8; 20];
        pkt[0] = 0x45;
        pkt[9] = 6;
        assert_eq!(l4proto(NFPROTO_IPV4, &pkt), Some(6));
    }

    #[test]
    fn packet_context_publishes_ipv6_next_header() {
        let mut pkt = [0u8; 40];
        pkt[0] = 0x60;
        pkt[6] = 17;
        assert_eq!(l4proto(NFPROTO_IPV6, &pkt), Some(17));
    }

    #[test]
    fn packet_context_walks_ipv6_extension_headers() {
        let mut pkt = [0u8; 56];
        pkt[0] = 0x60;
        pkt[6] = 0;
        pkt[40] = 17;
        pkt[41] = 0;
        assert_eq!(l4proto(NFPROTO_IPV6, &pkt), Some(17));
    }

    #[test]
    fn packet_context_hides_ipv6_transport_on_noninitial_fragment() {
        let mut pkt = [0u8; 48];
        pkt[0] = 0x60;
        pkt[6] = 44;
        pkt[40] = 17;
        pkt[42] = 0;
        pkt[43] = 8;
        assert_eq!(l4proto(NFPROTO_IPV6, &pkt), None);
    }

    #[test]
    fn packet_context_does_not_publish_protocol_for_truncated_ipv4() {
        assert_eq!(l4proto(NFPROTO_IPV4, &[0x45, 0, 0, 0]), None);
    }

    #[test]
    fn populate_writes_the_derived_protocol_into_the_rule_context() {
        let mut pkt = [0u8; 20];
        pkt[0] = 0x45;
        pkt[9] = 17;
        let input = super::Input::bare(0, 0, &pkt, NFPROTO_IPV4, 0);
        let states = ExprStates::default();
        let mut ctx = EvalCtx::new(&pkt, NFPROTO_IPV4, &states);
        input.populate(&mut ctx, 0);
        assert_eq!(ctx.meta.l4proto, Some(17));
    }
}
