//! `sk_reuseport_md` context and action contract.

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

/// Every program run below must pass the verifier the load path uses, so no
/// test can assert a runtime result for a program that would be refused.
fn verified(insns: &[u8]) -> &[u8] {
    assert_eq!(verify_program(uapi::prog_type::SK_REUSEPORT, 0, insns, &[]), Ok(false));
    insns
}

fn refused(insns: &[u8]) {
    assert!(verify_program(uapi::prog_type::SK_REUSEPORT, 0, insns, &[]).is_err());
}

/// A run with no maps, for the programs that only ever answer with an action.
fn bare(insns: &[u8]) -> Run<'_> {
    Run { insns, maps: &[], runner: crate::bpf::map::sockarray::RunnerState {
        group_id: 1, protocol: 6, family: 2,
    } }
}

/// The action a program answered with, for the tests that assert nothing
/// about which member it named.
fn action(insns: &[u8], ctx: SkReuseportContext<'_>) -> u32 { run(bare(insns), ctx).action }

fn ctx<'a>(packet: &'a [u8]) -> SkReuseportContext<'a> {
    SkReuseportContext { packet, eth_protocol: 0, ip_protocol: 0, bind_inany: false, hash: 0 }
}

/// A program that passes when the named context member holds `value` and
/// drops otherwise. The action is what the program returns, so the member's
/// own value never has to be a legal return.
fn field_equals(offset: usize, value: u32) -> alloc::vec::Vec<u8> {
    cat(&[
        raw(0x61, 0, 1, offset as i16, 0),
        raw(0x15, 0, 0, 2, value as i32),
        raw(0xb7, 0, 0, 0, SK_DROP as i32),
        raw(0x95, 0, 0, 0, 0),
        raw(0xb7, 0, 0, 0, SK_PASS as i32),
        raw(0x95, 0, 0, 0, 0),
    ])
}

/// A program whose only point is the one context access it makes: the value
/// goes to a scratch register, so admission is the only thing under test.
fn reads_field(opcode: u8, offset: usize) -> alloc::vec::Vec<u8> {
    cat(&[
        raw(opcode, 2, 1, offset as i16, 0),
        raw(0xb7, 0, 0, 0, SK_PASS as i32),
        raw(0x95, 0, 0, 0, 0),
    ])
}

#[test]
fn the_length_field_measures_from_the_transport_header() {
    let packet = [0xffu8; 9];
    let p = field_equals(md::LEN, packet.len() as u32);
    assert_eq!(action(verified(&p), ctx(&packet)), SK_PASS);
    let shorter = [0xffu8; 8];
    assert_eq!(action(&p, ctx(&shorter)), SK_DROP);
}

#[test]
fn eth_protocol_is_published_in_network_order() {
    const IPV6: u16 = 0x86dd;
    let packet = [0u8; 4];
    let network_order = field_equals(md::ETH_PROTOCOL, u32::from(IPV6.to_be()));
    let host_order = field_equals(md::ETH_PROTOCOL, u32::from(IPV6));
    let with = |p: &[u8]| action(verified(p), SkReuseportContext {
        packet: &packet, eth_protocol: IPV6, ip_protocol: 0, bind_inany: false, hash: 0,
    });
    assert_eq!(with(&network_order), SK_PASS);
    assert_eq!(with(&host_order), SK_DROP);
}

#[test]
fn ip_protocol_and_bind_inany_and_hash_all_reach_the_program() {
    const TCP: u8 = 6;
    const HASH: u32 = 0x0ead_beef;
    let packet = [0u8; 1];
    let with = |p: &[u8], inany: bool| action(verified(p), SkReuseportContext {
        packet: &packet, eth_protocol: 0, ip_protocol: TCP, bind_inany: inany, hash: HASH,
    });
    assert_eq!(with(&field_equals(md::IP_PROTOCOL, u32::from(TCP)), false), SK_PASS);
    assert_eq!(with(&field_equals(md::IP_PROTOCOL, 17), false), SK_DROP);
    assert_eq!(with(&field_equals(md::BIND_INANY, 0), false), SK_PASS);
    assert_eq!(with(&field_equals(md::BIND_INANY, 1), false), SK_DROP);
    assert_eq!(with(&field_equals(md::BIND_INANY, 1), true), SK_PASS);
    assert_eq!(with(&field_equals(md::HASH, HASH), false), SK_PASS);
    assert_eq!(with(&field_equals(md::HASH, HASH ^ 1), false), SK_DROP);
}

#[test]
fn packet_bytes_are_reachable_only_through_the_load_helper() {
    // Copy the first 4 bytes of the packet onto the stack and pass when they
    // are what the caller put there.
    let p = cat(&[
        raw(0xbf, 3, 10, 0, 0),
        raw(0x07, 3, 0, 0, -8),
        raw(0xb7, 2, 0, 0, 0),
        raw(0xb7, 4, 0, 0, 4),
        raw(0x85, 0, 0, 0, uapi::func_id::SKB_LOAD_BYTES as i32),
        raw(0x61, 0, 10, -8, 0),
        raw(0x15, 0, 0, 2, 0x0403_0201),
        raw(0xb7, 0, 0, 0, SK_DROP as i32),
        raw(0x95, 0, 0, 0, 0),
        raw(0xb7, 0, 0, 0, SK_PASS as i32),
        raw(0x95, 0, 0, 0, 0),
    ]);
    assert_eq!(action(verified(&p), ctx(&[1, 2, 3, 4, 5])), SK_PASS);
    assert_eq!(action(&p, ctx(&[9, 2, 3, 4, 5])), SK_DROP);
}

#[test]
fn the_pointer_members_are_refused_rather_than_served_as_zero() {
    for offset in [md::DATA, md::DATA_END, md::SK, md::MIGRATING_SK] {
        refused(&reads_field(0x79, offset));
        refused(&reads_field(0x61, offset));
    }
    refused(&reads_field(0x61, md::PADDING));
}

#[test]
fn every_published_member_admits_a_whole_word_read() {
    for offset in [md::LEN, md::ETH_PROTOCOL, md::IP_PROTOCOL, md::BIND_INANY, md::HASH] {
        verified(&reads_field(0x61, offset));
    }
}

#[test]
fn a_narrow_read_stays_inside_one_member() {
    // Halves and bytes of a published member are readable at their own
    // alignment, which is what keeps a narrow read from ever spanning two
    // members: the members are word-aligned and contiguous.
    verified(&reads_field(0x69, md::HASH + 2));
    verified(&reads_field(0x71, md::BIND_INANY + 3));
    // Unaligned, and wider than a member, are both refused.
    refused(&reads_field(0x61, md::LEN + 2));
    refused(&reads_field(0x69, md::LEN + 1));
    refused(&reads_field(0x79, md::HASH));
}

#[test]
fn nothing_in_the_context_is_writable() {
    let p = cat(&[
        raw(0xb7, 2, 0, 0, 0),
        raw(0x63, 1, 2, md::HASH as i16, 0),
        raw(0xb7, 0, 0, 0, SK_PASS as i32),
        raw(0x95, 0, 0, 0, 0),
    ]);
    refused(&p);
}

#[test]
fn only_the_two_actions_verify() {
    for action in [SK_DROP, SK_PASS] {
        let p = cat(&[raw(0xb7, 0, 0, 0, action as i32), raw(0x95, 0, 0, 0, 0)]);
        assert_eq!(verify_program(uapi::prog_type::SK_REUSEPORT, 0, &p, &[]), Ok(false));
    }
    refused(&cat(&[raw(0xb7, 0, 0, 0, 2), raw(0x95, 0, 0, 0, 0)]));
}

#[test]
fn the_context_buffer_covers_the_whole_uapi_structure() {
    assert_eq!(SK_REUSEPORT_CONTEXT_BYTES, md::SIZE);
    let packet = [0u8; 3];
    let bytes = build(&ctx(&packet));
    assert_eq!(bytes.len(), md::SIZE);
    assert_eq!(u32::from_ne_bytes(bytes[md::LEN..md::LEN + 4].try_into().unwrap()), 3);
    // The members this kernel cannot source stay zero and unreachable.
    assert_eq!(&bytes[md::DATA..md::LEN], &[0u8; 16]);
    assert_eq!(&bytes[md::SK..md::SIZE], &[0u8; 16]);
}

#[test]
fn a_program_the_runner_cannot_finish_drops_the_packet() {
    let packet = [0u8; 1];
    assert_eq!(action(&[], ctx(&packet)), SK_DROP);
}
