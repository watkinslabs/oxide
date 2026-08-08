//! Socket-filter context and verdict contract.

use super::*;
use crate::bpf_verify::verify_program;
use crate::bpf::uapi;

fn raw(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let off = off.to_le_bytes();
    let imm = imm.to_le_bytes();
    [opcode, src << 4 | dst, off[0], off[1], imm[0], imm[1], imm[2], imm[3]]
}

fn cat(parts: &[[u8; 8]]) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::new();
    for part in parts { out.extend_from_slice(part); }
    out
}

/// Every program below must pass the same verifier the load path uses, so
/// no test can assert a runtime result for a program that would be refused.
fn verified(insns: &[u8]) -> &[u8] {
    assert_eq!(
        verify_program(uapi::prog_type::SOCKET_FILTER, 0, insns, &[]),
        Ok(false),
    );
    insns
}

#[test]
fn the_length_field_is_the_frame_length_not_its_first_bytes() {
    // `r0 = skb->len; exit` — the field is at context offset 0, which is
    // exactly where a program that mistook the packet for the context
    // would read packet bytes instead.
    let p = cat(&[raw(0x61, 0, 1, sk_buff::LEN as i16, 0), raw(0x95, 0, 0, 0, 0)]);
    let packet = [0xffu8, 0xff, 0xff, 0xff, 0, 0, 0];
    assert_eq!(run(verified(&p), SkFilterContext::bare(&packet)), packet.len() as u32);
}

#[test]
fn protocol_is_published_in_network_order() {
    const IPV4: u16 = 0x0800;
    let p = cat(&[raw(0x61, 0, 1, sk_buff::PROTOCOL as i16, 0), raw(0x95, 0, 0, 0, 0)]);
    let packet = [0u8; 4];
    let verdict = run(verified(&p), SkFilterContext {
        packet: &packet, protocol: IPV4, ifindex: 0,
    });
    assert_eq!(verdict, u32::from(IPV4.to_be()));
}

#[test]
fn ifindex_reaches_the_program() {
    let p = cat(&[raw(0x61, 0, 1, sk_buff::IFINDEX as i16, 0), raw(0x95, 0, 0, 0, 0)]);
    let packet = [0u8; 1];
    assert_eq!(
        run(verified(&p), SkFilterContext { packet: &packet, protocol: 0, ifindex: 9 }),
        9,
    );
}

#[test]
fn frame_bytes_are_reachable_only_through_the_load_helper() {
    // Copy the first 4 bytes of the frame onto the stack and return them.
    let p = cat(&[
        raw(0xbf, 3, 10, 0, 0),
        raw(0x07, 3, 0, 0, -8),
        raw(0xb7, 2, 0, 0, 0),
        raw(0xb7, 4, 0, 0, 4),
        raw(0x85, 0, 0, 0, uapi::func_id::SKB_LOAD_BYTES as i32),
        raw(0x61, 0, 10, -8, 0),
        raw(0x95, 0, 0, 0, 0),
    ]);
    let packet = [0x11u8, 0x22, 0x33, 0x44, 0x55];
    assert_eq!(
        run(verified(&p), SkFilterContext::bare(&packet)),
        u32::from_le_bytes([0x11, 0x22, 0x33, 0x44]),
    );
}

#[test]
fn an_unmodelled_field_reads_as_nothing_because_it_never_verifies() {
    // The context buffer carries a zero at `mark`; the verifier is what
    // keeps that zero from ever being observed.
    let p = cat(&[raw(0x61, 0, 1, sk_buff::MARK as i16, 0), raw(0x95, 0, 0, 0, 0)]);
    assert!(verify_program(uapi::prog_type::SOCKET_FILTER, 0, &p, &[]).is_err());
}

#[test]
fn the_context_buffer_covers_the_whole_uapi_structure() {
    assert_eq!(SK_FILTER_CONTEXT_BYTES, sk_buff::SIZE);
    let packet = [0u8; 2];
    let bytes = build(&SkFilterContext::bare(&packet));
    assert_eq!(bytes.len(), sk_buff::SIZE);
    assert_eq!(u32::from_ne_bytes(bytes[sk_buff::LEN..sk_buff::LEN + 4].try_into().unwrap()), 2);
}

#[test]
fn a_program_the_runner_cannot_finish_drops_the_frame() {
    // A bare EXIT never verifies, but the runner must still refuse rather
    // than admit a frame if one is ever handed to it.
    let packet = [0u8; 1];
    assert_eq!(run(&[], SkFilterContext::bare(&packet)), 0);
}
