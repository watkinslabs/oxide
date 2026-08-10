// Reuseport selection program context: the `struct sk_reuseport_md` a
// `BPF_PROG_TYPE_SK_REUSEPORT` program receives in R1, and the entry point
// that runs one when a bind key with several members has to decide which of
// them takes an arriving packet.
//
// The verifier admits only the members this module fills, so a program can
// never observe a byte of the context that has no source.

use crate::bpf_verify::SK_REUSEPORT_CONTEXT_BYTES;
use crate::bpf_verify::context::sk_reuseport_md as md;

/// What a selection program is entitled to know about the packet and about
/// the group it is choosing within.
///
/// `packet` starts at the transport header, which is where the reference
/// leaves the data pointer for this program type — unlike the classic
/// filter flavour, whose data pointer is advanced past that header first.
pub struct SkReuseportContext<'a> {
    pub packet: &'a [u8],
    /// Link-layer protocol in host order; stored network-order, the width it
    /// carries on the wire.
    pub eth_protocol: u16,
    /// Transport protocol, e.g. `IPPROTO_TCP`.
    pub ip_protocol: u8,
    /// The group was created for a socket bound to a wildcard address.
    pub bind_inany: bool,
    /// Flow hash over the packet's four tuple: the value the group's own
    /// distribution would have used had no program been attached.
    pub hash: u32,
}

fn put_word(bytes: &mut [u8; SK_REUSEPORT_CONTEXT_BYTES], at: usize, value: u32) {
    bytes[at..at + md::WORD].copy_from_slice(&value.to_ne_bytes());
}

/// Materialise the `sk_reuseport_md` a selection program reads. The two
/// packet bounds and the two socket handles stay zero and are unreachable:
/// the verifier refuses every access to them. # C: O(1)
pub fn build(ctx: &SkReuseportContext<'_>) -> [u8; SK_REUSEPORT_CONTEXT_BYTES] {
    let mut bytes = [0u8; SK_REUSEPORT_CONTEXT_BYTES];
    let len = u32::try_from(ctx.packet.len()).unwrap_or(u32::MAX);
    put_word(&mut bytes, md::LEN, len);
    put_word(&mut bytes, md::ETH_PROTOCOL, u32::from(ctx.eth_protocol.to_be()));
    put_word(&mut bytes, md::IP_PROTOCOL, u32::from(ctx.ip_protocol));
    put_word(&mut bytes, md::BIND_INANY, u32::from(ctx.bind_inany));
    put_word(&mut bytes, md::HASH, ctx.hash);
    bytes
}

/// `SK_DROP`: refuse the packet outright rather than choosing a member.
pub const SK_DROP: u32 = 0;
/// `SK_PASS`: the program is content; whichever member it selected takes the
/// packet, and a program that selected none leaves the group on its own
/// distribution.
pub const SK_PASS: u32 = 1;

/// What one selection run produced.
pub struct Verdict {
    /// `SK_PASS` or `SK_DROP`.
    pub action: u32,
    /// The member the program named, if it named one. A program that names
    /// none leaves its group on the group's own distribution.
    pub selected: Option<crate::bpf::map::sockarray::SockHandle>,
}

/// The group a selection program runs for, and the map set its relocated
/// instructions index into.
pub struct Run<'a> {
    pub insns: &'a [u8],
    pub maps: &'a [vfs::InodeRef],
    pub runner: crate::bpf::map::sockarray::RunnerState,
}

/// Run one verified selection program. A program the runner cannot complete
/// drops the packet rather than letting an unfinished run choose, and names
/// nothing. # C: O(instructions)
pub fn run(program: Run<'_>, ctx: SkReuseportContext<'_>) -> Verdict {
    let context = build(&ctx);
    let mut state = crate::bpf_interp::HelperState {
        reuseport_runner: Some(program.runner), ..Default::default()
    };
    let action = crate::bpf_interp::run_reuseport(
        program.insns, &context, ctx.packet, program.maps, &mut state);
    match action {
        Some(action) => Verdict { action: action as u32, selected: state.selected_sock },
        None => Verdict { action: SK_DROP, selected: None },
    }
}

#[cfg(test)]
#[path = "sk_reuseport_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "sk_reuseport_select_tests.rs"]
mod select_tests;
