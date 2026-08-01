// SOL_SOCKET reads whose value is not one fixed-width scalar: the memory
// report, the peer group list, the peer address, and the attached classic
// filter. Each has its own length ladder, so they never reach the scalar table.
//
// No target gate: the decision logic must run under hosted `cargo test`.

use syscall::errno::Errno;
use super::{SK_MEMINFO_VARS, SO_ATTACH_FILTER, SO_GET_FILTER};

/// `sk_get_meminfo` slots, in wire order. # C: O(1)
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct MemInfo {
    pub rmem_alloc: u32,
    pub rcvbuf: u32,
    pub wmem_alloc: u32,
    pub sndbuf: u32,
    pub fwd_alloc: u32,
    pub wmem_queued: u32,
    pub optmem: u32,
    pub backlog: u32,
    pub drops: u32,
}

impl MemInfo {
    /// # C: O(1)
    pub fn words(&self) -> [u32; SK_MEMINFO_VARS] {
        [self.rmem_alloc, self.rcvbuf, self.wmem_alloc, self.sndbuf, self.fwd_alloc,
         self.wmem_queued, self.optmem, self.backlog, self.drops]
    }

    /// Native encoding of the whole report. # C: O(1)
    pub fn bytes(&self) -> [u8; SK_MEMINFO_VARS * core::mem::size_of::<u32>()] {
        let mut out = [0u8; SK_MEMINFO_VARS * core::mem::size_of::<u32>()];
        for (slot, word) in self.words().iter().enumerate() {
            let at = slot * core::mem::size_of::<u32>();
            out[at..at + core::mem::size_of::<u32>()].copy_from_slice(&word.to_ne_bytes());
        }
        out
    }
}

/// `SO_MEMINFO` truncates to the caller's buffer and never fails on a short
/// one; the published length is what was actually written. # C: O(1)
pub fn meminfo_len(requested: i32) -> usize {
    core::cmp::min(requested as usize, SK_MEMINFO_VARS * core::mem::size_of::<u32>())
}

/// `SO_PEERGROUPS`: no peer credential is `ENODATA`, and a buffer too small for
/// the whole list is `ERANGE` **after** the needed length is published — the
/// caller retries with the length it was told. # C: O(1)
pub fn peergroups_len(groups: Option<usize>, requested: i32) -> Result<usize, (usize, Errno)> {
    let Some(count) = groups else { return Err((0, Errno::Enodata)); };
    let needed = count * core::mem::size_of::<u32>();
    if (requested as usize) < needed { return Err((needed, Errno::Erange)); }
    Ok(needed)
}

/// `SO_PEERNAME`: an unconnected socket is `ENOTCONN`, and asking for more than
/// the peer address occupies is `EINVAL` — the option never zero-pads. The
/// caller receives exactly the length it asked for. # C: O(1)
pub fn peername_len(address_len: Option<usize>, requested: i32) -> Result<usize, Errno> {
    let Some(address_len) = address_len else { return Err(Errno::Enotconn); };
    if address_len < requested as usize { return Err(Errno::Einval); }
    Ok(requested as usize)
}

/// One accepted `SO_GET_FILTER` read: the byte count to copy out, and the
/// published length — which counts filter BLOCKS, not bytes. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FilterRead { pub copy_bytes: usize, pub published_len: usize }

/// `sock_filter` is four fields packed into eight bytes.
pub const SOCK_FILTER_SIZE: usize = 8;

/// `sk_get_filter`: nothing attached publishes a zero length; a program with no
/// retained classic source cannot be dumped (`EACCES`); a zero-length request
/// is the block-count enquiry; and a request smaller than the block count is
/// `EINVAL`. `classic_bytes` is `None` when the attached program is not classic.
/// # C: O(1)
pub fn get_filter(classic_bytes: Option<usize>, attached: bool, requested: i32)
    -> Result<FilterRead, Errno>
{
    if !attached { return Ok(FilterRead { copy_bytes: 0, published_len: 0 }); }
    let Some(bytes) = classic_bytes else { return Err(Errno::Eacces); };
    let blocks = bytes / SOCK_FILTER_SIZE;
    if requested == 0 { return Ok(FilterRead { copy_bytes: 0, published_len: blocks }); }
    if (requested as usize) < blocks { return Err(Errno::Einval); }
    Ok(FilterRead { copy_bytes: blocks * SOCK_FILTER_SIZE, published_len: blocks })
}

/// The read direction of `SO_ATTACH_FILTER`'s number. # C: O(1)
pub fn is_get_filter(optname: u64) -> bool { optname == SO_GET_FILTER }

/// Both names denote one option number. # C: O(1)
pub fn get_filter_shares_attach_number() -> bool { SO_GET_FILTER == SO_ATTACH_FILTER }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meminfo_encodes_nine_native_words_in_wire_order() {
        let info = MemInfo { rmem_alloc: 1, rcvbuf: 2, wmem_alloc: 3, sndbuf: 4,
            fwd_alloc: 5, wmem_queued: 6, optmem: 7, backlog: 8, drops: 9 };
        assert_eq!(info.words(), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let bytes = info.bytes();
        assert_eq!(bytes.len(), 36);
        assert_eq!(u32::from_ne_bytes(bytes[32..].try_into().unwrap()), 9);
    }

    #[test]
    fn meminfo_truncates_a_short_request_instead_of_failing() {
        assert_eq!(meminfo_len(4), 4);
        assert_eq!(meminfo_len(0), 0);
        assert_eq!(meminfo_len(36), 36);
        assert_eq!(meminfo_len(i32::MAX), 36);
    }

    #[test]
    fn peergroups_publishes_the_needed_length_before_erange() {
        assert_eq!(peergroups_len(None, 64), Err((0, Errno::Enodata)));
        assert_eq!(peergroups_len(Some(3), 8), Err((12, Errno::Erange)));
        assert_eq!(peergroups_len(Some(3), 12), Ok(12));
        assert_eq!(peergroups_len(Some(0), 0), Ok(0));
    }

    #[test]
    fn peername_rejects_a_request_wider_than_the_address() {
        assert_eq!(peername_len(None, 16), Err(Errno::Enotconn));
        assert_eq!(peername_len(Some(16), 17), Err(Errno::Einval));
        assert_eq!(peername_len(Some(16), 16), Ok(16));
        assert_eq!(peername_len(Some(16), 4), Ok(4));
    }

    #[test]
    fn get_filter_publishes_block_counts_not_byte_counts() {
        assert_eq!(get_filter(None, false, 64), Ok(FilterRead { copy_bytes: 0, published_len: 0 }));
        assert_eq!(get_filter(None, true, 64), Err(Errno::Eacces));
        assert_eq!(get_filter(Some(24), true, 0),
            Ok(FilterRead { copy_bytes: 0, published_len: 3 }));
        assert_eq!(get_filter(Some(24), true, 2), Err(Errno::Einval));
        assert_eq!(get_filter(Some(24), true, 3),
            Ok(FilterRead { copy_bytes: 24, published_len: 3 }));
        assert_eq!(get_filter(Some(24), true, 4096),
            Ok(FilterRead { copy_bytes: 24, published_len: 3 }));
    }

    #[test]
    fn get_filter_reuses_the_attach_option_number() {
        assert!(get_filter_shares_attach_number());
        assert!(is_get_filter(SO_ATTACH_FILTER));
    }
}
