//! Live netfilter hook state translated into nftables expression inputs.

use crate::nft_expr::{EvalCtx, IfInfo};

pub(crate) struct Input<'a> {
    pub namespace: u64,
    pub hook_id: u32,
    pub pkt: &'a [u8],
    pub ll: &'a [u8],
    pub family: u8,
    pub mark: u32,
    pub priority: u32,
    pub ingress: Option<net::NetIfaceId>,
    pub egress: Option<net::NetIfaceId>,
    pub timestamp_ns: u64,
}

impl<'a> Input<'a> {
    pub(crate) const fn bare(namespace: u64, hook_id: u32, pkt: &'a [u8], family: u8,
                             mark: u32) -> Self {
        Self { namespace, hook_id, pkt, ll: &[], family, mark, priority: 0,
            ingress: None, egress: None, timestamp_ns: 0 }
    }

    pub(crate) fn from_hook(hook: &'a net::stack::NfHookCtx<'a>) -> Self {
        Self { namespace: hook.namespace, hook_id: hook.hook_id, pkt: hook.pkt, ll: hook.ll,
            family: hook.family, mark: hook.mark, priority: hook.priority,
            ingress: hook.ingress, egress: hook.egress, timestamp_ns: hook.timestamp_ns }
    }

    pub(crate) fn populate(&self, ctx: &mut EvalCtx<'a>, mark: u32) {
        ctx.hook = self.hook_id as u8;
        ctx.mark = mark;
        ctx.ll = self.ll;
        ctx.meta.protocol = match self.family {
            crate::nft_expr::uapi::NFPROTO_IPV4 => Some(net::addr::eth_p::IPV4),
            crate::nft_expr::uapi::NFPROTO_IPV6 => Some(net::addr::eth_p::IPV6),
            _ => None,
        };
        ctx.meta.priority = self.priority;
        ctx.meta.iif = self.ingress.and_then(|id| iface(self.namespace, id));
        ctx.meta.oif = self.egress.and_then(|id| iface(self.namespace, id));
        if self.timestamp_ns != 0 { ctx.meta.time_ns = Some(self.timestamp_ns); }
        ctx.meta.fragoff = fragoff(self.family, self.pkt);
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
