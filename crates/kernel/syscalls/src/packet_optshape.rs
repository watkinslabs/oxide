// The AF_PACKET setsockopt ABI SHAPE: how many bytes each option's write must
// supply, which requests are refused before any user memory is touched, and the
// one value coercion `PACKET_VNET_HDR` applies. No user memory, no cfg gating —
// `054_setsockopt/packet.rs` imports exactly this many bytes and applies exactly
// this coercion, while hosted `cargo test` drives the rules directly.
//
// The variable-length options (`PACKET_RX_RING`/`PACKET_TX_RING`, whose need
// depends on the socket's TPACKET version, and the fanout/membership requests)
// carry their own length rule in their own helper and are absent here.

use syscall::errno::Errno;

/// The `optlen` contract one AF_PACKET write carries.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum SetLen {
    /// Rejected unless `optlen` is exactly this — the scalar options.
    Exact(u32),
    /// Rejected only when `optlen` is short; extra bytes are ignored.
    AtLeast(u32),
}

const I32_LEN: u32 = core::mem::size_of::<i32>() as u32;
const U32_LEN: u32 = core::mem::size_of::<u32>() as u32;

/// The fixed-shape AF_PACKET writes and the width each demands. # C: O(1)
pub(crate) fn set_len(optname: u64) -> Option<SetLen> {
    Some(match optname {
        net::uapi::PACKET_COPY_THRESH => SetLen::Exact(I32_LEN),
        net::uapi::PACKET_TIMESTAMP => SetLen::Exact(I32_LEN),
        net::uapi::PACKET_LOSS => SetLen::Exact(I32_LEN),
        net::uapi::PACKET_QDISC_BYPASS => SetLen::Exact(I32_LEN),
        net::uapi::PACKET_TX_HAS_OFF => SetLen::Exact(U32_LEN),
        net::uapi::PACKET_RESERVE => SetLen::Exact(U32_LEN),
        // `PACKET_VNET_HDR` and its explicit-size twin take the leading `int`
        // and ignore any tail, so a caller passing a wider word still lands.
        net::uapi::PACKET_VNET_HDR | net::uapi::PACKET_VNET_HDR_SZ => SetLen::AtLeast(U32_LEN),
        _ => return None,
    })
}

/// Screen one fixed-shape write's `optlen`, yielding the byte count to import.
/// # C: O(1)
pub(crate) fn check_set_len(optname: u64, optlen: u32) -> Result<u32, Errno> {
    match set_len(optname) {
        Some(SetLen::Exact(need)) if optlen == need => Ok(need),
        Some(SetLen::AtLeast(need)) if optlen >= need => Ok(need),
        Some(_) => Err(Errno::Einval),
        None => Err(Errno::Enoprotoopt),
    }
}

/// `PACKET_VNET_HDR` is a SOCK_RAW-only knob: `packet_setsockopt` refuses a
/// cooked (SOCK_DGRAM) socket before it looks at the length, and refuses a
/// short write before it reads the buffer. So an unprivileged shape error
/// always reports EINVAL — a caller passing an unreadable pointer on a cooked
/// socket never sees EFAULT. # C: O(1)
pub(crate) fn vnet_hdr_admit(raw: bool, optlen: u32) -> Result<u32, Errno> {
    if !raw { return Err(Errno::Einval); }
    check_set_len(net::uapi::PACKET_VNET_HDR, optlen)
}

/// The one value coercion the vnet-header pair applies. `PACKET_VNET_HDR` is a
/// boolean spelled as an int — any non-zero request selects the standard
/// `virtio_net_hdr`, never the caller's number — while `PACKET_VNET_HDR_SZ`
/// takes the size verbatim. # C: O(1)
pub(crate) fn vnet_hdr_size(value: u32, explicit_size: bool) -> u32 {
    if explicit_size { value }
    else if value == 0 { 0 }
    else { net::uapi::VIRTIO_NET_HDR_LEN }
}

/// The readback twin of `vnet_hdr_size`: `PACKET_VNET_HDR` reports the boolean
/// "is a header attached", NOT the stored length, while `PACKET_VNET_HDR_SZ`
/// reports the length itself. Reading either through the other's rule turns a
/// 12-byte header into `12` or a `true` into `1` byte. # C: O(1)
pub(crate) fn vnet_hdr_get(size: u32, explicit_size: bool) -> i32 {
    if explicit_size { size as i32 } else { i32::from(size != 0) }
}

/// Which import a `PACKET_FANOUT_DATA` write performs, or the error it takes.
///
/// The group answers first: a socket that joined no fanout group, or joined one
/// whose selector is neither classic nor extended, is refused for that reason
/// alone — a locked filter does not turn that refusal into a permission error.
/// The lock is the accepting modes' own refusal, and it precedes the import, so
/// a locked socket never reads the caller's program. # C: O(1)
pub(crate) fn fanout_data_mode(mode: Option<u8>, filter_locked: bool) -> Result<u8, Errno> {
    let mode = mode.ok_or(Errno::Einval)?;
    if mode != net::uapi::PACKET_FANOUT_CBPF && mode != net::uapi::PACKET_FANOUT_EBPF {
        return Err(Errno::Einval);
    }
    if filter_locked { return Err(Errno::Eperm); }
    Ok(mode)
}

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod tests;
