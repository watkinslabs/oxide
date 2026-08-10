//! The socket map's create, store, lookup and selection contracts.
//!
//! Two things are pinned here that nothing else can pin: that a slot stops
//! answering the moment the object it names is dropped — which is what makes a
//! map safe to hold sockets in at all — and the order the selection refusals
//! are decided in, which is observable to a program as four distinct errnos.

use super::*;
use crate::bpf::uapi;
use crate::bpf::map as bpfmap;
use alloc::sync::Arc;
use alloc::vec::Vec;

/// A stand-in for a hashed transport object: the map is type-erased, so any
/// `Any + Send + Sync` allocation exercises the same lifetime contract the
/// real listen entries and receive queues do.
struct Hashed(u32);

fn handle(object: &Arc<Hashed>, cookie: u64) -> SockHandle {
    SockHandle {
        hashed: Arc::downgrade(object) as HashedSock,
        cell: Arc::downgrade(object) as HashedSock,
        cookie, protocol: 6, family: 2,
    }
}

fn key(index: u32) -> Vec<u8> { index.to_ne_bytes().to_vec() }

fn runner() -> RunnerState { RunnerState { group_id: 7, protocol: 6, family: 2 } }

#[test]
fn a_slot_stops_answering_once_its_socket_is_gone() {
    let array = SockArray::allocate(4).expect("four slots");
    let object = Arc::new(Hashed(1));
    array.update(&key(2), 4, handle(&object, 99), 0).expect("stored");
    let found = array.lookup(&key(2), 4).expect("in range").expect("stored socket");
    assert_eq!(found.cookie, 99);
    assert!(found.is_live());

    drop(object);
    assert!(array.lookup(&key(2), 4).expect("in range").is_none(),
        "a closed socket's slot reads empty");
    assert_eq!(array.delete(&key(2), 4), Err(Errno::Enoent),
        "and deleting it reports the slot was already empty");
}

#[test]
fn a_dead_slot_counts_as_empty_for_the_store_flags() {
    let array = SockArray::allocate(2).expect("two slots");
    let first = Arc::new(Hashed(1));
    array.update(&key(0), 2, handle(&first, 1), 0).expect("stored");
    let second = Arc::new(Hashed(2));
    assert_eq!(array.update(&key(0), 2, handle(&second, 2), uapi::elem_flags::NOEXIST).err(),
        Some(Errno::Eexist), "the slot is occupied by a live socket");
    drop(first);
    array.update(&key(0), 2, handle(&second, 2), uapi::elem_flags::NOEXIST)
        .expect("a slot whose socket closed is available again");
    assert_eq!(array.lookup(&key(0), 2).unwrap().unwrap().cookie, 2);
}

#[test]
fn an_index_past_the_end_is_distinct_from_an_empty_slot() {
    let array = SockArray::allocate(2).expect("two slots");
    assert_eq!(array.lookup(&key(2), 2).err(), Some(Errno::E2big));
    assert_eq!(array.delete(&key(9), 2), Err(Errno::E2big));
    assert!(array.lookup(&key(1), 2).expect("in range").is_none());
    assert_eq!(array.delete(&key(1), 2), Err(Errno::Enoent));
}

#[test]
fn store_flags_arbitrate_against_live_occupancy() {
    assert_eq!(update_flags_check(false, uapi::elem_flags::ANY), Ok(()));
    assert_eq!(update_flags_check(false, uapi::elem_flags::NOEXIST), Ok(()));
    assert_eq!(update_flags_check(false, uapi::elem_flags::EXIST), Err(Errno::Enoent));
    assert_eq!(update_flags_check(true, uapi::elem_flags::NOEXIST), Err(Errno::Eexist));
    assert_eq!(update_flags_check(true, uapi::elem_flags::EXIST), Ok(()));
    assert_eq!(update_flags_check(false, uapi::elem_flags::F_LOCK), Err(Errno::Einval));
}

#[test]
fn keys_enumerate_the_arrays_shape_not_its_contents() {
    let array = SockArray::allocate(3).expect("three slots");
    assert_eq!(array.next_key(None, 3), Ok(Some(key(0))));
    assert_eq!(array.next_key(Some(&key(0)), 3), Ok(Some(key(1))));
    assert_eq!(array.next_key(Some(&key(2)), 3), Ok(None));
    assert_eq!(array.next_key(Some(&key(3)), 3), Err(Errno::E2big));
}

#[test]
fn only_a_descriptor_shaped_value_and_an_index_shaped_key_create_the_map() {
    assert_eq!(alloc_check(4, 4, 8, 0), Ok(()));
    assert_eq!(alloc_check(4, 8, 8, 0), Ok(()));
    assert_eq!(alloc_check(4, 2, 8, 0), Err(Errno::Einval), "a value that is no descriptor");
    assert_eq!(alloc_check(8, 8, 8, 0), Err(Errno::Einval), "a key that is no index");
    assert_eq!(alloc_check(4, 8, 0, 0), Err(Errno::Einval), "an array of nothing");
    assert_eq!(alloc_check(4, 8, 8, u32::MAX), Err(Errno::Einval), "flags this map has no use for");
}

#[test]
fn a_socket_that_could_never_be_reached_is_not_storable() {
    let ok = StoredShape {
        tcp_or_udp: true, inet: true, stream_or_dgram: true, hashed: true, in_group: true,
    };
    assert_eq!(stored_shape_check(ok), Ok(()));
    assert_eq!(stored_shape_check(StoredShape { tcp_or_udp: false, ..ok }), Err(Errno::Enotsupp));
    assert_eq!(stored_shape_check(StoredShape { inet: false, ..ok }), Err(Errno::Enotsupp));
    assert_eq!(stored_shape_check(StoredShape { stream_or_dgram: false, ..ok }),
        Err(Errno::Enotsupp));
    // Shape is decided before liveness, so a socket that is wrong in both
    // ways reports the shape.
    assert_eq!(stored_shape_check(StoredShape { tcp_or_udp: false, hashed: false, ..ok }),
        Err(Errno::Enotsupp));
    assert_eq!(stored_shape_check(StoredShape { hashed: false, ..ok }), Err(Errno::Einval));
    assert_eq!(stored_shape_check(StoredShape { in_group: false, ..ok }), Err(Errno::Einval));
}

#[test]
fn a_program_may_only_name_a_member_of_its_own_group() {
    let same = SockState { group_id: 7, protocol: 6, family: 2 };
    assert_eq!(select_check(runner(), Some(same)), Ok(()));
    // Absent state covers both a closed socket and one in no group at all.
    assert_eq!(select_check(runner(), None), Err(Errno::Enoent));
}

#[test]
fn naming_a_socket_outside_the_group_reports_what_differs_first() {
    let elsewhere = |protocol, family| SockState { group_id: 99, protocol, family };
    assert_eq!(select_check(runner(), Some(elsewhere(17, 2))), Err(Errno::Eprototype));
    // A different family is only reported once the protocol matches.
    assert_eq!(select_check(runner(), Some(elsewhere(17, 10))), Err(Errno::Eprototype));
    assert_eq!(select_check(runner(), Some(elsewhere(6, 10))), Err(Errno::Eafnosupport));
    // Same protocol, same family, different group: bound somewhere else.
    assert_eq!(select_check(runner(), Some(elsewhere(6, 2))), Err(Errno::Ebadfd));
}

#[test]
fn a_descriptor_value_is_read_in_either_width_and_never_out_of_range() {
    use bpfmap::sock_elem::{fd_from_value, lookup_width_ok};
    assert_eq!(fd_from_value(&3i32.to_ne_bytes()), Ok(3));
    assert_eq!(fd_from_value(&3u64.to_ne_bytes()), Ok(3));
    assert_eq!(fd_from_value(&(i32::MAX as u64 + 1).to_ne_bytes()), Err(Errno::Einval));
    assert_eq!(fd_from_value(&[0, 0]), Err(Errno::Einval));
    // A cookie needs the wide value; a narrow map has nowhere to report one.
    assert_eq!(lookup_width_ok(8), Ok(()));
    assert_eq!(lookup_width_ok(4), Err(Errno::Enospc));
}

#[test]
fn the_map_type_creates_a_socket_holding_backing_and_no_byte_backing() {
    let inode = bpfmap::allocate(
        uapi::map_type::REUSEPORT_SOCKARRAY, 4, 8, 4, 0,
    ).expect("the map type is one this kernel creates");
    let map = inode.private::<crate::bpf::BpfMapInode>().expect("a map object");
    assert!(map.storage.sock_array().is_some(), "it holds sockets");
    assert!(map.lookup_value(&key(0)).is_none(), "and no bytes any byte path could return");
}
