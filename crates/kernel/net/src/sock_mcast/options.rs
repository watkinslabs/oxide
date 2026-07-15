use super::*;
use crate::sock::{SockKind, AF_INET, AF_INET6};

/// Parsed multicast scalar option owned by the network work-function layer.
pub enum McastScalar {
    V4Iface { addr: Ipv4Addr, ifindex: i32 },
    V4Ttl(i32),
    V4Loop(i32),
    V6Iface(i32),
    V6Hops(i32),
    V6Loop(i32),
}

/// Multicast setsockopt policy class checked before UAPI parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McastSetOp {
    V4Iface,
    V4Ttl,
    V4Other,
    V4Membership,
    V6IfaceOrHops,
    V6Other,
    V6Membership,
}

/// Multicast getsockopt family class checked before UAPI parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McastGetOp { V4, V6 }

/// Typed multicast scalar returned to getsockopt encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McastScalarGet { V4Ttl, V4Loop, V6Iface, V6Hops, V6Loop }

pub(super) fn supports_v4(sock: &InetSocket) -> bool {
    matches!(sock.family.load(core::sync::atomic::Ordering::Acquire), AF_INET | AF_INET6)
}

pub(super) fn supports_v6(sock: &InetSocket) -> bool {
    sock.family.load(core::sync::atomic::Ordering::Acquire) == AF_INET6
}

fn is_tcp(sock: &InetSocket) -> bool {
    matches!(*sock.kind.lock(), SockKind::TcpInit | SockKind::TcpListener(_) | SockKind::TcpConn(_))
}

impl InetSocket {
    /// Check multicast socket, family, and protocol policy before UAPI access. # C: O(1)
    pub fn preflight_mcast_set(&self, op: McastSetOp) -> NetResult<()> {
        let family = self.family.load(core::sync::atomic::Ordering::Acquire);
        if family != AF_INET && family != AF_INET6 { return Err(NetError::Eopnotsupp); }
        match op {
            McastSetOp::V4Iface | McastSetOp::V4Ttl => {
                if !supports_v4(self) { return Err(NetError::Enoprotoopt); }
                if is_tcp(self) { return Err(NetError::Einval); }
            }
            McastSetOp::V4Other => if !supports_v4(self) { return Err(NetError::Enoprotoopt); },
            McastSetOp::V4Membership => {
                if !supports_v4(self) { return Err(NetError::Enoprotoopt); }
                if is_tcp(self) { return Err(NetError::Eproto); }
            }
            McastSetOp::V6IfaceOrHops => {
                if !supports_v6(self) || is_tcp(self) { return Err(NetError::Enoprotoopt); }
            }
            McastSetOp::V6Other => if !supports_v6(self) { return Err(NetError::Enoprotoopt); },
            McastSetOp::V6Membership => {
                if !supports_v6(self) { return Err(NetError::Enoprotoopt); }
                if is_tcp(self) { return Err(NetError::Eproto); }
            }
        }
        Ok(())
    }

    /// Check multicast getsockopt family policy before UAPI access. # C: O(1)
    pub fn preflight_mcast_get(&self, op: McastGetOp) -> NetResult<()> {
        let supported = match op { McastGetOp::V4 => supports_v4(self), McastGetOp::V6 => supports_v6(self) };
        if supported { Ok(()) } else { Err(NetError::Eopnotsupp) }
    }

    /// Snapshot one multicast scalar under socket close exclusion. # C: O(1)
    pub fn get_mcast_scalar(&self, option: McastScalarGet) -> NetResult<i32> {
        use core::sync::atomic::Ordering;
        self.preflight_mcast_get(match option {
            McastScalarGet::V4Ttl | McastScalarGet::V4Loop => McastGetOp::V4,
            McastScalarGet::V6Iface | McastScalarGet::V6Hops | McastScalarGet::V6Loop => McastGetOp::V6,
        })?;
        let _guard = self.mcast_guard()?;
        Ok(match option {
            McastScalarGet::V4Ttl => self.opts.ip_mcast_ttl.load(Ordering::Acquire),
            McastScalarGet::V4Loop => self.opts.ip_mcast_loop.load(Ordering::Acquire),
            McastScalarGet::V6Iface => self.opts.ipv6_mcast_ifindex.load(Ordering::Acquire) as i32,
            McastScalarGet::V6Hops => self.opts.ipv6_mcast_hops.load(Ordering::Acquire),
            McastScalarGet::V6Loop => self.opts.ipv6_mcast_loop.load(Ordering::Acquire),
        })
    }

    /// Validate and apply one parsed multicast scalar option. # C: O(N)
    pub fn set_mcast_scalar(&self, option: McastScalar) -> NetResult<()> {
        use core::sync::atomic::Ordering;
        match option {
            McastScalar::V4Iface { addr, ifindex } => {
                self.preflight_mcast_set(McastSetOp::V4Iface)?;
                if ifindex < 0 { return Err(NetError::Eaddrnotavail); }
                self.set_v4_mcast_iface(addr, ifindex as u32).map_err(|error| {
                    if error == NetError::Enodev { NetError::Eaddrnotavail } else { error }
                })
            }
            McastScalar::V4Ttl(value) => {
                self.preflight_mcast_set(McastSetOp::V4Ttl)?;
                if !(-1..=255).contains(&value) { return Err(NetError::Einval); }
                let _guard = self.mcast_guard()?;
                self.opts.ip_mcast_ttl.store(if value == -1 { 1 } else { value }, Ordering::Release);
                Ok(())
            }
            McastScalar::V4Loop(value) => {
                self.preflight_mcast_set(McastSetOp::V4Other)?;
                let _guard = self.mcast_guard()?;
                self.opts.ip_mcast_loop.store(if value != 0 { 1 } else { 0 }, Ordering::Release);
                Ok(())
            }
            McastScalar::V6Iface(ifindex) => {
                self.preflight_mcast_set(McastSetOp::V6IfaceOrHops)?;
                self.set_v6_mcast_iface(ifindex as u32)
            }
            McastScalar::V6Hops(value) => {
                self.preflight_mcast_set(McastSetOp::V6IfaceOrHops)?;
                if !(-1..=255).contains(&value) { return Err(NetError::Einval); }
                let _guard = self.mcast_guard()?;
                self.opts.ipv6_mcast_hops.store(if value == -1 { 1 } else { value }, Ordering::Release);
                Ok(())
            }
            McastScalar::V6Loop(value) => {
                self.preflight_mcast_set(McastSetOp::V6Other)?;
                if !(0..=1).contains(&value) { return Err(NetError::Einval); }
                let _guard = self.mcast_guard()?;
                self.opts.ipv6_mcast_loop.store(value, Ordering::Release);
                Ok(())
            }
        }
    }
}
