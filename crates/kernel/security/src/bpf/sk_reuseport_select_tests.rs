//! Naming a member through a socket map, end to end: a loaded program that
//! calls the selection helper, a real map holding a real weak handle, and the
//! selection the run leaves behind.
//!
//! Before this a selection program could only drop a packet or defer to its
//! group's own distribution — there was no map that could hold a socket and no
//! helper that could name one — so nothing here could be asserted at all.

use super::*;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use crate::bpf::map::sockarray::{
    HashedSock, RunnerState, SockArray, SockHandle, SockState, install_sock_resolvers,
};
use crate::bpf::uapi;
use crate::bpf_verify::verify_program;

struct Hashed(u32);

/// Cookie is the whole identity a test resolver needs: `1` is a member of the
/// running group, `2` is a socket bound elsewhere, anything else belongs to no
/// group at all.
fn test_state(handle: &SockHandle) -> Option<SockState> {
    handle.upgrade()?;
    match handle.cookie {
        1 => Some(SockState { group_id: GROUP, protocol: 6, family: 2 }),
        2 => Some(SockState { group_id: GROUP + 1, protocol: 6, family: 2 }),
        _ => None,
    }
}

fn test_from_fd(_fd: i32) -> Result<SockHandle, syscall::errno::Errno> {
    Err(syscall::errno::Errno::Einval)
}

const GROUP: u64 = 7;

fn raw(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let off = off.to_le_bytes();
    let imm = imm.to_le_bytes();
    [opcode, src << 4 | dst, off[0], off[1], imm[0], imm[1], imm[2], imm[3]]
}

/// A program that reads slot 0 of its one map through the selection helper and
/// answers `SK_PASS` only when the helper reported `expected`. The action
/// therefore says what the program SAW, and the selection the run recorded says
/// what the kernel DID — two independent observations of one call.
fn selecting_program(expected: i32) -> Vec<u8> {
    [
        raw(0x62, 10, 0, -4, 0),
        raw(0x18, 2, uapi::pseudo::MAP_FD, 0, 0),
        raw(0, 0, 0, 0, 0),
        raw(0xbf, 3, 10, 0, 0),
        raw(0x07, 3, 0, 0, -4),
        raw(0xb7, 4, 0, 0, 0),
        raw(0x85, 0, 0, 0, uapi::func_id::SK_SELECT_REUSEPORT as i32),
        raw(0x15, 0, 0, 2, expected),
        raw(0xb7, 0, 0, 0, SK_DROP as i32),
        raw(0x95, 0, 0, 0, 0),
        raw(0xb7, 0, 0, 0, SK_PASS as i32),
        raw(0x95, 0, 0, 0, 0),
    ].into_iter().flatten().collect()
}

fn sock_map(entries: u32) -> vfs::InodeRef {
    crate::bpf::map::allocate(uapi::map_type::REUSEPORT_SOCKARRAY, 4, 8, entries, 0)
        .expect("a socket map")
}

fn array_of(inode: &vfs::InodeRef) -> &SockArray {
    inode.private::<crate::bpf::BpfMapInode>().expect("a map")
        .storage.sock_array().expect("holding sockets")
}

fn store(inode: &vfs::InodeRef, object: &Arc<Hashed>, cookie: u64) {
    let handle = SockHandle { hashed: Arc::downgrade(object) as HashedSock, cookie };
    array_of(inode).update(&0u32.to_ne_bytes(), 1, handle, 0).expect("stored");
}

fn ctx<'a>(packet: &'a [u8]) -> SkReuseportContext<'a> {
    SkReuseportContext { packet, eth_protocol: 0, ip_protocol: 6, bind_inany: false, hash: 0 }
}

fn run_with(insns: &[u8], maps: &[vfs::InodeRef]) -> Verdict {
    assert_eq!(verify_program(uapi::prog_type::SK_REUSEPORT, 0, insns, maps), Ok(false),
        "a program the load path would refuse cannot be asserted about");
    run(Run { insns, maps, runner: RunnerState { group_id: GROUP, protocol: 6, family: 2 } },
        ctx(&[0; 20]))
}

fn errno(e: syscall::errno::Errno) -> i32 { -(e.as_i32()) }

#[test]
fn a_program_names_a_member_of_its_own_group_and_the_run_records_it() {
    install_sock_resolvers(test_from_fd, test_state);
    let map = sock_map(1);
    let member = Arc::new(Hashed(1));
    store(&map, &member, 1);

    let verdict = run_with(&selecting_program(0), core::slice::from_ref(&map));
    assert_eq!(verdict.action, SK_PASS, "the helper reported success to the program");
    let selected = verdict.selected.expect("the run recorded a selection");
    assert_eq!(selected.cookie, 1);
    let named: Arc<dyn Any + Send + Sync> = selected.upgrade().expect("still live");
    assert!(Arc::ptr_eq(&named, &(member.clone() as Arc<dyn Any + Send + Sync>)),
        "and it names the very object that was stored");
}

#[test]
fn naming_a_socket_bound_elsewhere_selects_nothing() {
    install_sock_resolvers(test_from_fd, test_state);
    let map = sock_map(1);
    let elsewhere = Arc::new(Hashed(2));
    store(&map, &elsewhere, 2);

    let verdict = run_with(&selecting_program(errno(syscall::errno::Errno::Ebadfd)),
        core::slice::from_ref(&map));
    assert_eq!(verdict.action, SK_PASS, "the program saw the refusal it expected");
    assert!(verdict.selected.is_none(), "and nothing was selected");
}

#[test]
fn naming_a_socket_that_has_closed_selects_nothing() {
    install_sock_resolvers(test_from_fd, test_state);
    let map = sock_map(1);
    let member = Arc::new(Hashed(1));
    store(&map, &member, 1);
    drop(member);

    let verdict = run_with(&selecting_program(errno(syscall::errno::Errno::Enoent)),
        core::slice::from_ref(&map));
    assert_eq!(verdict.action, SK_PASS, "the closed socket reported an absent slot");
    assert!(verdict.selected.is_none());
}

#[test]
fn naming_an_empty_slot_selects_nothing() {
    install_sock_resolvers(test_from_fd, test_state);
    let map = sock_map(1);
    let verdict = run_with(&selecting_program(errno(syscall::errno::Errno::Enoent)),
        core::slice::from_ref(&map));
    assert_eq!(verdict.action, SK_PASS);
    assert!(verdict.selected.is_none());
}

#[test]
fn a_program_that_names_a_member_and_then_refuses_the_packet_still_refuses_it() {
    install_sock_resolvers(test_from_fd, test_state);
    let map = sock_map(1);
    let member = Arc::new(Hashed(1));
    store(&map, &member, 1);
    // The same call, but the program answers SK_DROP on success: the action is
    // the program's own return value and outranks any selection it made.
    let verdict = run_with(&selecting_program(1), core::slice::from_ref(&map));
    assert_eq!(verdict.action, SK_DROP);
    assert!(verdict.selected.is_some(), "the selection was still recorded");
}

#[test]
fn the_helper_belongs_to_this_program_type_and_to_a_socket_holding_map_only() {
    let map = sock_map(1);
    let insns = selecting_program(0);
    assert_eq!(verify_program(uapi::prog_type::SK_REUSEPORT, 0, &insns,
        core::slice::from_ref(&map)), Ok(false));
    assert!(verify_program(uapi::prog_type::SOCKET_FILTER, 0, &insns,
        core::slice::from_ref(&map)).is_err(), "no other program type may name a member");

    let bytes = crate::bpf::map::allocate(uapi::map_type::ARRAY, 4, 8, 1, 0).expect("a byte map");
    assert!(verify_program(uapi::prog_type::SK_REUSEPORT, 0, &insns,
        core::slice::from_ref(&bytes)).is_err(), "a map that holds bytes holds no member");
}

#[test]
fn an_undefined_flag_is_refused_at_load_rather_than_at_run_time() {
    let map = sock_map(1);
    let mut insns = selecting_program(0);
    // R4 carries the flags word; no flag is defined for this call.
    insns[5 * 8..6 * 8].copy_from_slice(&raw(0xb7, 4, 0, 0, 1));
    assert!(verify_program(uapi::prog_type::SK_REUSEPORT, 0, &insns,
        core::slice::from_ref(&map)).is_err());
}
