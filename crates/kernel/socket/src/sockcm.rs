// SOL_SOCKET send-ancillary admission — Linux `__sock_cmsg_send`.
//
// Every family except AF_UNIX and NETLINK reaches its SOL_SOCKET control
// messages through this rule; the two SCM families answer them from
// `control::parse` instead, because `SCM_RIGHTS` there carries descriptors
// rather than being ignored. Keeping the generic rule in one place is what
// makes "which control message does a UDP socket accept" a single answer
// rather than one per protocol.
//
// The socket-option NUMBERS are the option table's; only the two control types
// that have no option counterpart are declared here.

use crate::cmsg_walk::Cmsg;
use crate::{Error, KResult};

use net::sock_opts::sol_socket::{SO_MARK, SO_PRIORITY, SO_TIMESTAMPING_NEW, SO_TIMESTAMPING_OLD,
    SO_TXTIME, TC_PRIO_BESTEFFORT, TC_PRIO_INTERACTIVE};

/// `SCM_TXTIME` shares `SO_TXTIME`'s number.
const SCM_TXTIME: i32 = SO_TXTIME as i32;
/// `SCM_TS_OPT_ID` — a control type with no socket-option counterpart.
const SCM_TS_OPT_ID: i32 = 81;
/// `SCM_DEVMEM_DMABUF` shares `SO_DEVMEM_DMABUF`'s number.
const SCM_DEVMEM_DMABUF: i32 = 79;
/// `SCM_RIGHTS`/`SCM_CREDENTIALS` are semantically AF_UNIX's, and every other
/// family steps over them without objecting.
const SCM_RIGHTS: i32 = 1;
const SCM_CREDENTIALS: i32 = 2;

use net::send_control::SockCm;
use net::uapi::{SOF_TIMESTAMPING_OPT_ID, SOF_TIMESTAMPING_TX_RECORD_MASK};

/// The socket state the generic rule branches on, snapshotted once per message.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SockCmEnv {
    pub net_raw: bool,
    pub net_admin: bool,
    /// `sock_flag(sk, SOCK_TXTIME)`.
    pub txtime: bool,
    /// `sk_is_tcp`.
    pub tcp: bool,
    /// `sk_tsflags & SOF_TIMESTAMPING_OPT_ID`.
    pub tstamp_opt_id: bool,
}

impl SockCmEnv {
    /// `sk_set_prio_allowed`: the interactive band is unprivileged, everything
    /// above it needs a network capability. # C: O(1)
    fn prio_allowed(&self, value: i32) -> bool {
        (TC_PRIO_BESTEFFORT..=TC_PRIO_INTERACTIVE).contains(&value)
            || self.net_raw || self.net_admin
    }
}

fn u32_exact(data: &[u8]) -> KResult<u32> {
    if data.len() != 4 { return Err(Error::Einval); }
    Ok(u32::from_ne_bytes(data[..4].try_into().unwrap()))
}

/// Admit one SOL_SOCKET control message on a send and RECORD what it settles.
///
/// An unrecognised type is EINVAL; a recognised one is screened for its exact
/// length and, where Linux gates it, for the caller's capability. An admitted
/// value is written into `out`, which is the message's one copy of it — the
/// transmit path resolves it against the socket's own choice rather than
/// finding it mirrored anywhere. # C: O(1)
pub(crate) fn admit(env: &SockCmEnv, cmsg: &Cmsg<'_>, out: &mut SockCm) -> KResult<()> {
    match cmsg.kind {
        kind if kind == SO_MARK as i32 => {
            if !env.net_raw && !env.net_admin { return Err(Error::Eperm); }
            out.mark = Some(u32_exact(cmsg.data)?);
            Ok(())
        }
        kind if kind == SO_TIMESTAMPING_OLD as i32 || kind == SO_TIMESTAMPING_NEW as i32 => {
            let flags = u32_exact(cmsg.data)?;
            if flags & !SOF_TIMESTAMPING_TX_RECORD_MASK != 0 { return Err(Error::Einval); }
            out.tsflags = Some(flags);
            Ok(())
        }
        SCM_TXTIME => {
            if !env.txtime { return Err(Error::Einval); }
            if cmsg.data.len() != 8 { return Err(Error::Einval); }
            out.transmit_time = Some(u64::from_ne_bytes(cmsg.data[..8].try_into().unwrap()));
            Ok(())
        }
        SCM_TS_OPT_ID => {
            // The transmit-identifier override is a datagram facility; a TCP
            // sender is refused before its socket's own flags are consulted.
            if env.tcp { return Err(Error::Einval); }
            if !env.tstamp_opt_id { return Err(Error::Einval); }
            out.ts_opt_id = Some(u32_exact(cmsg.data)?);
            Ok(())
        }
        SCM_RIGHTS | SCM_CREDENTIALS => Ok(()),
        kind if kind == SO_PRIORITY as i32 => {
            let value = u32_exact(cmsg.data)?;
            if !env.prio_allowed(value as i32) { return Err(Error::Eperm); }
            out.priority = Some(value);
            Ok(())
        }
        SCM_DEVMEM_DMABUF => u32_exact(cmsg.data).map(|_| ()),
        _ => Err(Error::Einval),
    }
}

/// Snapshot the socket state the generic rule branches on, once per message.
/// `#[inline(never)]`: the capability lookups walk a namespace chain and are
/// only reached by a message that carries ancillary data.
/// # C: O(1)
#[inline(never)]
pub(crate) fn env_for(ctx: &crate::SendContext<'_>, socket: &alloc::sync::Arc<net::sock::InetSocket>)
    -> SockCmEnv
{
    use core::sync::atomic::Ordering;
    SockCmEnv {
        net_raw: nscg::proc_ns::has_net_raw_for(ctx.task(), &socket.net_namespace),
        net_admin: nscg::proc_ns::has_net_admin_for(ctx.task(), &socket.net_namespace),
        txtime: socket.opts.generic.flag(net::sock_opts::sol_socket::flag::TXTIME),
        tcp: matches!(*socket.kind.lock(), net::sock::SockKind::TcpConn(_)
            | net::sock::SockKind::TcpInit | net::sock::SockKind::TcpListener(_)),
        tstamp_opt_id: socket.opts.timestamping.load(Ordering::Acquire) as u32
            & SOF_TIMESTAMPING_OPT_ID != 0,
    }
}

/// The whole send-ancillary admission for a socket whose transport owns no
/// control messages of its own — a stream, or AF_PACKET. Levels other than
/// SOL_SOCKET are stepped over exactly as the transports that DO own a level
/// step over the levels they do not. # C: O(control)
pub(crate) fn admit_socket_level_only(control: &[u8], env: &SockCmEnv) -> KResult<SockCm> {
    let mut out = SockCm::default();
    for item in crate::cmsg_walk::CmsgWalk::new(control) {
        let item = item?;
        if item.level != crate::cmsg_walk::SOL_SOCKET { continue; }
        admit(env, &item, &mut out)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn msg(kind: i32, data: &[u8]) -> (Vec<u8>, i32) { (data.to_vec(), kind) }

    fn admit_bytes(env: &SockCmEnv, kind: i32, data: &[u8]) -> KResult<()> {
        settle(env, kind, data).map(|_| ())
    }

    fn settle(env: &SockCmEnv, kind: i32, data: &[u8]) -> KResult<SockCm> {
        let (data, kind) = msg(kind, data);
        let mut out = SockCm::default();
        admit(env, &Cmsg { level: crate::cmsg_walk::SOL_SOCKET, kind, data: &data }, &mut out)?;
        Ok(out)
    }

    fn caps() -> SockCmEnv { SockCmEnv { net_raw: true, ..SockCmEnv::default() } }

    #[test]
    fn scm_rights_and_credentials_are_stepped_over_rather_than_refused() {
        let env = SockCmEnv::default();
        assert_eq!(admit_bytes(&env, SCM_RIGHTS, &[0; 4]), Ok(()));
        assert_eq!(admit_bytes(&env, SCM_CREDENTIALS, &[0; 12]), Ok(()));
    }

    #[test]
    fn an_unknown_socket_level_type_is_einval() {
        assert_eq!(admit_bytes(&SockCmEnv::default(), 1234, &[0; 4]), Err(Error::Einval));
    }

    #[test]
    fn so_mark_needs_a_network_capability_before_its_length_is_screened() {
        let none = SockCmEnv::default();
        assert_eq!(admit_bytes(&none, SO_MARK as i32, &[0; 7]), Err(Error::Eperm));
        assert_eq!(admit_bytes(&caps(), SO_MARK as i32, &[0; 7]), Err(Error::Einval));
        assert_eq!(admit_bytes(&caps(), SO_MARK as i32, &[0; 4]), Ok(()));
        let admin = SockCmEnv { net_admin: true, ..SockCmEnv::default() };
        assert_eq!(admit_bytes(&admin, SO_MARK as i32, &[0; 4]), Ok(()));
    }

    #[test]
    fn timestamping_rejects_bits_outside_the_transmit_record_mask() {
        let env = SockCmEnv::default();
        assert_eq!(admit_bytes(&env, SO_TIMESTAMPING_OLD as i32, &0x303u32.to_ne_bytes()), Ok(()));
        assert_eq!(admit_bytes(&env, SO_TIMESTAMPING_NEW as i32, &0x303u32.to_ne_bytes()), Ok(()));
        assert_eq!(admit_bytes(&env, SO_TIMESTAMPING_OLD as i32, &0x310u32.to_ne_bytes()),
            Err(Error::Einval));
        assert_eq!(admit_bytes(&env, SO_TIMESTAMPING_OLD as i32, &[0; 8]), Err(Error::Einval));
    }

    #[test]
    fn txtime_needs_the_socket_option_enabled_and_an_exact_width() {
        let off = SockCmEnv::default();
        assert_eq!(admit_bytes(&off, SCM_TXTIME, &[0; 8]), Err(Error::Einval));
        let on = SockCmEnv { txtime: true, ..SockCmEnv::default() };
        assert_eq!(admit_bytes(&on, SCM_TXTIME, &[0; 8]), Ok(()));
        assert_eq!(admit_bytes(&on, SCM_TXTIME, &[0; 4]), Err(Error::Einval));
    }

    #[test]
    fn the_transmit_identifier_is_refused_on_a_stream_and_without_the_socket_flag() {
        let tcp = SockCmEnv { tcp: true, tstamp_opt_id: true, ..SockCmEnv::default() };
        assert_eq!(admit_bytes(&tcp, SCM_TS_OPT_ID, &[0; 4]), Err(Error::Einval));
        let bare = SockCmEnv::default();
        assert_eq!(admit_bytes(&bare, SCM_TS_OPT_ID, &[0; 4]), Err(Error::Einval));
        let ready = SockCmEnv { tstamp_opt_id: true, ..SockCmEnv::default() };
        assert_eq!(admit_bytes(&ready, SCM_TS_OPT_ID, &[0; 4]), Ok(()));
    }

    #[test]
    fn priority_above_the_interactive_band_needs_a_capability() {
        let none = SockCmEnv::default();
        assert_eq!(admit_bytes(&none, SO_PRIORITY as i32, &0u32.to_ne_bytes()), Ok(()));
        assert_eq!(admit_bytes(&none, SO_PRIORITY as i32, &6u32.to_ne_bytes()), Ok(()));
        assert_eq!(admit_bytes(&none, SO_PRIORITY as i32, &7u32.to_ne_bytes()), Err(Error::Eperm));
        assert_eq!(admit_bytes(&caps(), SO_PRIORITY as i32, &7u32.to_ne_bytes()), Ok(()));
    }
}
