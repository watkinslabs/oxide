use alloc::sync::Arc;

use super::*;

#[test]
fn array_is_preallocated_and_obeys_array_update_flags() {
    let inode = allocate(uapi::map_type::ARRAY, 4, 8, 2, 0).unwrap();
    let map = inode.private::<BpfMapInode>().unwrap();
    let key = 1u32.to_ne_bytes().to_vec();
    assert_eq!(map.lookup_value(&key).unwrap().copy_out().unwrap(), &[0; 8]);
    assert_eq!(
        update_entry(map, key.clone(), 7u64.to_ne_bytes().to_vec(), uapi::elem_flags::NOEXIST),
        Err(Errno::Eexist),
    );
    assert_eq!(
        update_entry(map, key.clone(), 7u64.to_ne_bytes().to_vec(), uapi::elem_flags::EXIST),
        Ok(0),
    );
    assert_eq!(
        u64::from_ne_bytes(map.lookup_value(&key).unwrap().copy_out().unwrap().try_into().unwrap()),
        7,
    );
}

#[test]
fn live_map_ids_resolve_and_enumerate_through_inode_ownership() {
    let first = allocate(uapi::map_type::ARRAY, 4, 8, 1, 0).unwrap();
    let first_id = first.private::<BpfMapInode>().unwrap().id;
    let second = allocate(uapi::map_type::ARRAY, 4, 8, 1, 0).unwrap();
    let second_id = second.private::<BpfMapInode>().unwrap().id;
    assert_eq!(map_by_id(first_id).map(|inode| inode.ino()), Some(first.ino()));
    assert_eq!(next_live_map_id(first_id), Some(second_id));
}

#[test]
fn lpm_lookup_selects_the_longest_matching_prefix() {
    let inode = allocate(
        uapi::map_type::LPM_TRIE, 8, 8, 4, uapi::map_flags::NO_PREALLOC,
    ).unwrap();
    let map = inode.private::<BpfMapInode>().unwrap();
    let key = |prefix: u32, address: [u8; 4]| {
        let mut bytes = prefix.to_ne_bytes().to_vec();
        bytes.extend_from_slice(&address);
        bytes
    };
    update_entry(map, key(16, [10, 1, 0, 0]), 16u64.to_ne_bytes().to_vec(), 0).unwrap();
    update_entry(map, key(24, [10, 1, 2, 0]), 24u64.to_ne_bytes().to_vec(), 0).unwrap();
    let value = map.lookup_value(&key(32, [10, 1, 2, 99])).unwrap();
    assert_eq!(
        u64::from_ne_bytes(value.copy_out().unwrap().try_into().unwrap()),
        24,
    );
}

#[test]
fn lpm_identity_ignores_bits_beyond_the_prefix() {
    let inode = allocate(
        uapi::map_type::LPM_TRIE, 8, 8, 2, uapi::map_flags::NO_PREALLOC,
    ).unwrap();
    let map = inode.private::<BpfMapInode>().unwrap();
    let key = |address: [u8; 4]| {
        let mut bytes = 20u32.to_ne_bytes().to_vec();
        bytes.extend_from_slice(&address);
        bytes
    };
    update_entry(map, key([10, 1, 0x2f, 0xaa]), 1u64.to_ne_bytes().to_vec(), 0).unwrap();
    assert_eq!(
        update_entry(
            map,
            key([10, 1, 0x28, 0x55]),
            2u64.to_ne_bytes().to_vec(),
            uapi::elem_flags::NOEXIST,
        ),
        Err(Errno::Eexist),
    );
    assert!(map.lookup_value(&key([10, 1, 0x2a, 0xff])).is_some());
    assert!(remove_entry(map, &key([10, 1, 0x20, 0x01]), false).unwrap().is_some());
    assert!(map.lookup_value(&key([10, 1, 0x2a, 0xff])).is_none());
}

#[test]
fn lpm_iteration_canonicalizes_input_but_returns_the_last_raw_key() {
    let inode = allocate(
        uapi::map_type::LPM_TRIE, 8, 8, 3, uapi::map_flags::NO_PREALLOC,
    ).unwrap();
    let map = inode.private::<BpfMapInode>().unwrap();
    let key = |prefix: u32, address: [u8; 4]| {
        let mut bytes = prefix.to_ne_bytes().to_vec();
        bytes.extend_from_slice(&address);
        bytes
    };
    let original = key(20, [10, 1, 0x2f, 0xaa]);
    let replacement = key(20, [10, 1, 0x28, 0x55]);
    let alias = key(20, [10, 1, 0x20, 0xff]);
    let successor = key(24, [10, 1, 3, 0x77]);
    update_entry(map, original, 1u64.to_ne_bytes().to_vec(), 0).unwrap();
    update_entry(map, successor.clone(), 2u64.to_ne_bytes().to_vec(), 0).unwrap();
    update_entry(map, replacement.clone(), 3u64.to_ne_bytes().to_vec(), 0).unwrap();
    assert_eq!(map.storage.next_key(None, map.max_entries).unwrap(), Some(replacement));
    assert_eq!(
        map.storage.next_key(Some(&alias), map.max_entries).unwrap(),
        Some(successor),
    );
}

#[test]
fn oversized_hash_capacity_is_e2big_before_allocation() {
    assert!(matches!(
        storage::MapStorage::allocate(
            uapi::map_type::HASH, 4, 8, (1u32 << 31) + 1, 0,
        ),
        Err(Errno::E2big),
    ));
}

#[test]
fn freeze_and_writer_admission_are_one_atomic_decision() {
    let storage = storage::MapStorage::allocate(
        uapi::map_type::HASH, 4, 8, 1, uapi::map_flags::NO_PREALLOC,
    ).unwrap();
    let guard = storage.begin_write().unwrap();
    assert_eq!(storage.freeze(), Err(Errno::Ebusy));
    drop(guard);
    assert_eq!(storage.freeze(), Ok(()));
    assert!(matches!(storage.begin_write(), Err(Errno::Eperm)));
    assert_eq!(storage.freeze(), Err(Errno::Ebusy));
}

#[test]
fn lookup_errno_ordering_matches_linux() {
    use uapi::off::map_elem as o;

    let mut attr = Attr::zeroed();
    attr.bytes[o::FLAGS..o::FLAGS + 8]
        .copy_from_slice(&uapi::elem_flags::NOEXIST.to_ne_bytes());
    assert_eq!(elem(&attr, MapOp::LookupAndDelete), Err(Errno::Einval));

    let inode = allocate(
        uapi::map_type::HASH, 4, 8, 1, uapi::map_flags::NO_PREALLOC,
    ).unwrap();
    let map = inode.private::<BpfMapInode>().unwrap();
    let key = 9u32.to_ne_bytes().to_vec();
    assert_eq!(lookup_to_user(map, &key, 0), Err(Errno::Enoent));
    assert_eq!(lookup_delete_to_user(map, &key, 0), Err(Errno::Enoent));
    update_entry(map, key.clone(), 7u64.to_ne_bytes().to_vec(), 0).unwrap();
    assert_eq!(lookup_delete_to_user(map, &key, 0), Err(Errno::Efault));
    assert!(map.lookup_value(&key).is_none());
}

#[test]
fn interpreter_map_lookup_and_xadd_share_the_map_value() {
    let map = allocate(uapi::map_type::ARRAY, 4, 8, 1, 0).unwrap();
    let bytes = [
        raw(0x62, 10, 0, -4, 0),
        raw(0x18, 1, uapi::pseudo::MAP_FD, 0, 0),
        raw(0, 0, 0, 0, 0),
        raw(0xbf, 2, 10, 0, 0),
        raw(0x07, 2, 0, 0, -4),
        raw(0x85, 0, 0, 0, uapi::func_id::MAP_LOOKUP_ELEM as i32),
        raw(0xb7, 1, 0, 0, 5),
        raw(0xdb, 0, 1, 0, 0),
        raw(0x79, 0, 0, 0, 0),
        raw(0x95, 0, 0, 0, 0),
    ].into_iter().flatten().collect();
    let prog_inode = super::super::make_bpf_prog_inode_with_meta(
        uapi::prog_type::CGROUP_SKB,
        uapi::attach_type::CGROUP_INET_INGRESS,
        bytes,
        alloc::vec![Arc::clone(&map)],
    );
    let prog = prog_inode.private::<super::super::BpfProgInode>().unwrap();
    assert_eq!(
        crate::bpf_interp::run_program_with_state(
            prog, &[0; 44], &[], &[], &mut crate::bpf_interp::HelperState::default(),
        ),
        Some(5),
    );
}

#[test]
fn interpreter_enforces_program_map_permissions_independently() {
    let run = |flags, instructions: &[[u8; 8]]| {
        let map = allocate(uapi::map_type::ARRAY, 4, 8, 1, flags).unwrap();
        let prog_inode = super::super::make_bpf_prog_inode_with_meta(
            uapi::prog_type::CGROUP_SKB,
            uapi::attach_type::CGROUP_INET_INGRESS,
            instructions.iter().flatten().copied().collect(),
            alloc::vec![map],
        );
        let prog = prog_inode.private::<super::super::BpfProgInode>().unwrap();
        crate::bpf_interp::run_program_with_state(
            prog, &[0; 44], &[], &[], &mut crate::bpf_interp::HelperState::default(),
        )
    };
    let read = [
        raw(0x18, 1, uapi::pseudo::MAP_VALUE, 0, 0),
        raw(0, 0, 0, 0, 0),
        raw(0x79, 0, 1, 0, 0),
        raw(0x95, 0, 0, 0, 0),
    ];
    assert_eq!(run(uapi::map_flags::WRONLY_PROG, &read), None);
    let write = [
        raw(0x18, 1, uapi::pseudo::MAP_VALUE, 0, 0),
        raw(0, 0, 0, 0, 0),
        raw(0x7a, 1, 0, 0, 7),
        raw(0xb7, 0, 0, 0, 1),
        raw(0x95, 0, 0, 0, 0),
    ];
    assert_eq!(run(uapi::map_flags::RDONLY_PROG, &write), None);
    let atomic = [
        raw(0x18, 1, uapi::pseudo::MAP_VALUE, 0, 0),
        raw(0, 0, 0, 0, 0),
        raw(0xb7, 2, 0, 0, 1),
        raw(0xdb, 1, 2, 0, 0),
        raw(0xb7, 0, 0, 0, 1),
        raw(0x95, 0, 0, 0, 0),
    ];
    assert_eq!(run(uapi::map_flags::RDONLY_PROG, &atomic), None);
    assert_eq!(run(uapi::map_flags::WRONLY_PROG, &atomic), None);
}

fn raw(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let off = off.to_le_bytes();
    let imm = imm.to_le_bytes();
    [opcode, src << 4 | dst, off[0], off[1], imm[0], imm[1], imm[2], imm[3]]
}
