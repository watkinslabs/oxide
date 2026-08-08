// Socket-filter program context: the `struct __sk_buff` a
// `BPF_PROG_TYPE_SOCKET_FILTER` program receives in R1, and the entry point
// that runs one against a received frame.
//
// The verifier admits only the fields this module fills, so a program can
// never observe a byte of the context that has no source.

use crate::bpf_verify::context::sk_buff;
use crate::bpf_verify::SK_FILTER_CONTEXT_BYTES;

/// Frame metadata a socket filter is entitled to see. `protocol` is the
/// host-order EtherType and `ifindex` is 0 when the frame arrived on no
/// device, which is what a filter on a socket with no netdevice observes.
pub struct SkFilterContext<'a> {
    pub packet: &'a [u8],
    pub protocol: u16,
    pub ifindex: u32,
}

impl<'a> SkFilterContext<'a> {
    /// Context for a frame carrying no link-layer identity. # C: O(1)
    pub fn bare(packet: &'a [u8]) -> Self {
        Self { packet, protocol: 0, ifindex: 0 }
    }
}

fn put_word(bytes: &mut [u8; SK_FILTER_CONTEXT_BYTES], at: usize, value: u32) {
    bytes[at..at + sk_buff::WORD].copy_from_slice(&value.to_ne_bytes());
}

/// Materialise the `__sk_buff` a socket filter reads. `protocol` is stored
/// in network order, matching the on-wire width the field carries.
/// # C: O(1)
pub fn build(ctx: &SkFilterContext<'_>) -> [u8; SK_FILTER_CONTEXT_BYTES] {
    let mut bytes = [0u8; SK_FILTER_CONTEXT_BYTES];
    let len = u32::try_from(ctx.packet.len()).unwrap_or(u32::MAX);
    put_word(&mut bytes, sk_buff::LEN, len);
    put_word(&mut bytes, sk_buff::PROTOCOL, u32::from(ctx.protocol.to_be()));
    put_word(&mut bytes, sk_buff::IFINDEX, ctx.ifindex);
    bytes
}

/// Run one verified socket filter and return its Linux `u32` verdict: the
/// number of leading bytes to keep, 0 to drop. A program the runner cannot
/// complete drops the frame rather than admitting it.
/// # C: O(instructions)
pub fn run(insns: &[u8], ctx: SkFilterContext<'_>) -> u32 {
    let context = build(&ctx);
    crate::bpf_interp::run_socket_filter(insns, &context, ctx.packet)
        .map_or(0, |verdict| verdict as u32)
}

#[cfg(test)]
#[path = "sk_filter_tests.rs"]
mod tests;
