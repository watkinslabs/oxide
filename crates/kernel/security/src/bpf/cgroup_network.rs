//! Cgroup skb and socket-address contexts and verdict runners.

use cgroup::{CgroupBpfAttachType, CgroupBpfRuntime};
use syscall::errno::Errno;
use vfs::InodeRef;

use super::{BpfProgInode, uapi};
use crate::bpf_interp::{Helper, HelperState};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CgroupSkbAttach {
    Ingress,
    Egress,
}

pub struct CgroupSkbContext<'a> {
    pub packet: &'a [u8],
    /// Linux `__sk_buff.protocol`: a network-order EtherType in a `u32`.
    pub protocol: u32,
    pub ifindex: u32,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CgroupSkbVerdict {
    pub allow: bool,
    pub congestion_notification: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CgroupSockAddrAttach {
    Inet4Bind,
    Inet6Bind,
    Inet4Connect,
    Inet6Connect,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CgroupSockAddrContext {
    pub user_family: u32,
    /// Raw network-order IPv4 value.
    pub user_ip4: u32,
    /// Four raw network-order IPv6 words.
    pub user_ip6: [u32; 4],
    /// Raw network-order port in the low 16 bits.
    pub user_port: u32,
    pub family: u32,
    pub socket_type: u32,
    pub protocol: u32,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CgroupSockAddrVerdict {
    pub bind_no_cap_net_bind_service: bool,
}

/// Positive Linux errno selected by a cgroup sockaddr program.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CgroupSockAddrError(i32);

impl CgroupSockAddrError {
    fn from_errno(errno: Errno) -> Self { Self(errno.as_i32()) }

    fn from_retval(retval: i32) -> Option<Self> {
        let raw = retval.checked_neg()?;
        (1..=4095).contains(&raw).then_some(Self(raw))
    }

    /// Return the exact positive Linux errno number.
    /// # C: O(1)
    pub const fn as_i32(self) -> i32 { self.0 }
}

impl From<Errno> for CgroupSockAddrError {
    fn from(errno: Errno) -> Self { Self::from_errno(errno) }
}

fn skb_attach(attach: CgroupSkbAttach) -> (CgroupBpfAttachType, u32) {
    match attach {
        CgroupSkbAttach::Ingress => (
            CgroupBpfAttachType::InetIngress,
            uapi::attach_type::CGROUP_INET_INGRESS,
        ),
        CgroupSkbAttach::Egress => (
            CgroupBpfAttachType::InetEgress,
            uapi::attach_type::CGROUP_INET_EGRESS,
        ),
    }
}

/// Run one pinned cgroup's effective skb chain. Every program must return
/// bit 0 set; egress additionally ORs bit 1 as congestion notification.
/// # C: O(effective programs * program instructions)
pub fn run_cgroup_skb(
    runtime: &CgroupBpfRuntime,
    attach: CgroupSkbAttach,
    context: CgroupSkbContext<'_>,
) -> Result<CgroupSkbVerdict, Errno> {
    let (attach_type, expected) = skb_attach(attach);
    let programs = runtime.effective(attach_type);
    let mut ctx = [0u8; 44];
    ctx[0..4].copy_from_slice(&(context.packet.len() as u32).to_ne_bytes());
    ctx[16..20].copy_from_slice(&context.protocol.to_ne_bytes());
    ctx[40..44].copy_from_slice(&context.ifindex.to_ne_bytes());
    run_skb_programs(&programs, attach, expected, &ctx, context.packet)
}

fn run_skb_programs(
    programs: &[InodeRef],
    attach: CgroupSkbAttach,
    expected: u32,
    ctx: &[u8; 44],
    packet: &[u8],
) -> Result<CgroupSkbVerdict, Errno> {
    let mut allow = true;
    let mut congestion = false;
    let mut state = HelperState::default();
    for inode in programs.iter() {
        let prog = inode.private::<BpfProgInode>().ok_or(Errno::Einval)?;
        if prog.prog_type != uapi::prog_type::CGROUP_SKB
            || prog.enforce_expected_attach_type && prog.expected_attach_type != expected {
            return Err(Errno::Einval);
        }
        let raw = crate::bpf_interp::run_program_with_state(
            prog, ctx, packet, &[], &mut state,
        ).ok_or(Errno::Einval)? as u32;
        let max = if attach == CgroupSkbAttach::Egress { 3 } else { 1 };
        if raw > max { return Err(Errno::Einval); }
        allow &= raw & 1 != 0;
        if attach == CgroupSkbAttach::Egress { congestion |= raw & 2 != 0; }
    }
    Ok(CgroupSkbVerdict { allow, congestion_notification: congestion })
}

fn sockaddr_attach(attach: CgroupSockAddrAttach) -> (CgroupBpfAttachType, u32) {
    match attach {
        CgroupSockAddrAttach::Inet4Bind => (
            CgroupBpfAttachType::Inet4Bind, uapi::attach_type::CGROUP_INET4_BIND,
        ),
        CgroupSockAddrAttach::Inet6Bind => (
            CgroupBpfAttachType::Inet6Bind, uapi::attach_type::CGROUP_INET6_BIND,
        ),
        CgroupSockAddrAttach::Inet4Connect => (
            CgroupBpfAttachType::Inet4Connect, uapi::attach_type::CGROUP_INET4_CONNECT,
        ),
        CgroupSockAddrAttach::Inet6Connect => (
            CgroupBpfAttachType::Inet6Connect, uapi::attach_type::CGROUP_INET6_CONNECT,
        ),
    }
}

fn helper_get_retval(
    state: &mut HelperState,
    _a: i64,
    _b: i64,
    _c: i64,
    _d: i64,
    _e: i64,
) -> i64 {
    state.retval as i64
}

fn helper_set_retval(
    state: &mut HelperState,
    value: i64,
    _b: i64,
    _c: i64,
    _d: i64,
    _e: i64,
) -> i64 {
    state.retval = value as i32;
    0
}

static SOCKADDR_HELPERS: [Helper; 2] = [
    Helper { id: uapi::func_id::GET_RETVAL, f: helper_get_retval },
    Helper { id: uapi::func_id::SET_RETVAL, f: helper_set_retval },
];

fn serialize_sockaddr(context: &CgroupSockAddrContext) -> [u8; 40] {
    let mut bytes = [0u8; 40];
    bytes[0..4].copy_from_slice(&context.user_family.to_ne_bytes());
    bytes[4..8].copy_from_slice(&context.user_ip4.to_ne_bytes());
    for (index, word) in context.user_ip6.iter().enumerate() {
        let start = 8 + index * 4;
        bytes[start..start + 4].copy_from_slice(&word.to_ne_bytes());
    }
    bytes[24..28].copy_from_slice(&context.user_port.to_ne_bytes());
    bytes[28..32].copy_from_slice(&context.family.to_ne_bytes());
    bytes[32..36].copy_from_slice(&context.socket_type.to_ne_bytes());
    bytes[36..40].copy_from_slice(&context.protocol.to_ne_bytes());
    bytes
}

fn copy_sockaddr_writes(bytes: &[u8; 40], context: &mut CgroupSockAddrContext) {
    context.user_ip4 = u32::from_ne_bytes(bytes[4..8].try_into().unwrap());
    for index in 0..4 {
        let start = 8 + index * 4;
        context.user_ip6[index] =
            u32::from_ne_bytes(bytes[start..start + 4].try_into().unwrap());
    }
    context.user_port = u32::from_ne_bytes(bytes[24..28].try_into().unwrap());
}

/// Run one pinned cgroup's effective sockaddr chain. Successful user-address
/// rewrites are copied back; a denied chain leaves the caller's context
/// untouched. Upper return bits are ORed and bit 1 bypasses the privileged
/// bind-port capability check.
/// # C: O(effective programs * program instructions)
pub fn run_cgroup_sock_addr(
    runtime: &CgroupBpfRuntime,
    attach: CgroupSockAddrAttach,
    context: &mut CgroupSockAddrContext,
) -> Result<CgroupSockAddrVerdict, CgroupSockAddrError> {
    let (attach_type, expected) = sockaddr_attach(attach);
    let programs = runtime.effective(attach_type);
    let mut bytes = serialize_sockaddr(context);
    let verdict = run_sockaddr_programs(&programs, expected, &mut bytes)?;
    copy_sockaddr_writes(&bytes, context);
    Ok(verdict)
}

fn run_sockaddr_programs(
    programs: &[InodeRef],
    expected: u32,
    bytes: &mut [u8; 40],
) -> Result<CgroupSockAddrVerdict, CgroupSockAddrError> {
    let mut flags = 0u32;
    let mut state = HelperState::default();
    for inode in programs.iter() {
        let prog = inode.private::<BpfProgInode>().ok_or(Errno::Einval)?;
        if prog.prog_type != uapi::prog_type::CGROUP_SOCK_ADDR
            || prog.enforce_expected_attach_type && prog.expected_attach_type != expected {
            return Err(Errno::Einval.into());
        }
        let raw = crate::bpf_interp::run_program_mut_with_state(
            prog, bytes, &SOCKADDR_HELPERS, &mut state,
        ).ok_or(Errno::Einval)? as u32;
        let max = if matches!(expected,
            uapi::attach_type::CGROUP_INET4_BIND | uapi::attach_type::CGROUP_INET6_BIND) {
            3
        } else {
            1
        };
        if raw > max || state.retval < -4095 || state.retval > 0 {
            return Err(Errno::Einval.into());
        }
        flags |= raw >> 1;
        if raw & 1 == 0 && state.retval >= 0 {
            state.retval = -(Errno::Eperm.as_i32());
        }
    }
    if state.retval < 0 {
        return Err(CgroupSockAddrError::from_retval(state.retval)
            .unwrap_or_else(|| CgroupSockAddrError::from_errno(Errno::Einval)));
    }
    Ok(CgroupSockAddrVerdict {
        bind_no_cap_net_bind_service: flags & 1 != 0,
    })
}

#[cfg(test)]
#[path = "cgroup_network_tests.rs"]
mod tests;
