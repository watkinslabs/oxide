//! Map command admission: creation parameters and element operations.

use super::*;

// ------------------------------------------------------------ MAP_CREATE

fn good_map_create() -> Attr {
    use uapi::off::map_create as o;
    attr_with(&[(o::MAP_TYPE, uapi::map_type::HASH), (o::KEY_SIZE, 4),
                (o::VALUE_SIZE, 8), (o::MAX_ENTRIES, 16)])
}

#[test]
fn map_create_bad_map_type_is_einval_even_without_cap_bpf() {
    // map_create_alloc(): the map-type lookup returns -EINVAL long
    // before the `sysctl_unprivileged_bpf_disabled` EPERM gate.
    let mut a = good_map_create();
    a.bytes[uapi::off::map_create::MAP_TYPE..uapi::off::map_create::MAP_TYPE + 4]
        .copy_from_slice(&999u32.to_ne_bytes());
    assert_eq!(map_create_check(&a, caps_none(), true), Err(Errno::Einval));
}

#[test]
fn map_create_without_cap_bpf_is_eperm_when_unpriv_is_disabled() {
    assert_eq!(map_create_check(&good_map_create(), caps_none(), true), Err(Errno::Eperm));
    assert!(map_create_check(&good_map_create(), caps_bpf(), true).is_ok());
}

#[test]
fn map_create_is_allowed_unprivileged_when_the_sysctl_is_off() {
    // "Intent here is for unprivileged_bpf_disabled to block BPF map
    // creation for unprivileged users" — map_create_alloc().
    assert!(map_create_check(&good_map_create(), caps_none(), false).is_ok());
}

#[test]
fn map_create_cap_sys_admin_alone_satisfies_bpf_capable() {
    let caps = Caps { sys_admin: true, ..Caps::default() };
    assert!(map_create_check(&good_map_create(), caps, true).is_ok());
}

#[test]
fn map_create_zero_sizes_are_einval() {
    use uapi::off::map_create as o;
    for off in [o::KEY_SIZE, o::VALUE_SIZE, o::MAX_ENTRIES] {
        let mut a = good_map_create();
        a.bytes[off..off + 4].copy_from_slice(&0u32.to_ne_bytes());
        assert_eq!(map_create_check(&a, caps_bpf(), true), Err(Errno::Einval));
    }
}

#[test]
fn map_create_rdonly_and_wronly_together_is_einval() {
    // bpf_get_file_flag().
    use uapi::map_flags as f;
    let mut a = good_map_create();
    let off = uapi::off::map_create::MAP_FLAGS;
    a.bytes[off..off + 4].copy_from_slice(&(f::RDONLY | f::WRONLY).to_ne_bytes());
    assert_eq!(map_create_check(&a, caps_bpf(), true), Err(Errno::Einval));
}

#[test]
fn map_create_unknown_flag_bit_is_einval() {
    // htab_map_alloc_check(): attr->map_flags & ~HTAB_CREATE_FLAG_MASK.
    let mut a = good_map_create();
    let off = uapi::off::map_create::MAP_FLAGS;
    a.bytes[off..off + 4].copy_from_slice(&(1u32 << 20).to_ne_bytes());
    assert_eq!(map_create_check(&a, caps_bpf(), true), Err(Errno::Einval));
}

#[test]
fn map_create_zero_seed_needs_cap_sys_admin() {
    // htab_map_alloc_check(): zero_seed && !capable(CAP_SYS_ADMIN) -> -EPERM.
    let mut a = good_map_create();
    let off = uapi::off::map_create::MAP_FLAGS;
    a.bytes[off..off + 4].copy_from_slice(&uapi::map_flags::ZERO_SEED.to_ne_bytes());
    assert_eq!(map_create_check(&a, caps_bpf(), true), Err(Errno::Eperm));
    let admin = Caps { sys_admin: true, ..Caps::default() };
    assert!(map_create_check(&a, admin, true).is_ok());
}

#[test]
fn map_create_nonzero_map_extra_is_einval_for_hash() {
    let mut a = good_map_create();
    attr_u64(&mut a, uapi::off::map_create::MAP_EXTRA, 1);
    assert_eq!(map_create_check(&a, caps_bpf(), true), Err(Errno::Einval));
}

#[test]
fn map_create_short_attr_reads_as_zeros_and_fails_validation_not_the_size_check() {
    // A 4-byte attr leaves key_size/value_size/max_entries zero-filled;
    // Linux reaches htab_map_alloc_check() and returns -EINVAL, never
    // "attr too short".
    let (copy, tail) = size_protocol(4).unwrap();
    assert_eq!((copy, tail), (4, 0));
    let a = attr_with(&[(uapi::off::map_create::MAP_TYPE, uapi::map_type::HASH)]);
    assert_eq!(map_create_check(&a, caps_bpf(), true), Err(Errno::Einval));
}

// ------------------------------------------------------- map element ops

#[test]
fn element_ops_need_no_capability_at_all() {
    // map_lookup_elem()/map_update_elem() gate on the fd's FMODE only.
    assert_eq!(map_access_ok(0, false, Access::Read), Ok(()));
    assert_eq!(map_access_ok(0, false, Access::Write), Ok(()));
}

#[test]
fn frozen_map_loses_write_but_keeps_read() {
    // map_get_sys_perms(): frozen clears FMODE_CAN_WRITE.
    assert_eq!(map_access_ok(0, true, Access::Write), Err(Errno::Eperm));
    assert_eq!(map_access_ok(0, true, Access::Read), Ok(()));
}

#[test]
fn rdonly_and_wronly_map_flags_gate_the_matching_direction() {
    use uapi::map_flags as f;
    assert_eq!(map_access_ok(f::RDONLY, false, Access::Write), Err(Errno::Eperm));
    assert_eq!(map_access_ok(f::RDONLY, false, Access::Read), Ok(()));
    assert_eq!(map_access_ok(f::WRONLY, false, Access::Read), Err(Errno::Eperm));
    assert_eq!(map_access_ok(f::WRONLY, false, Access::Write), Ok(()));
}

#[test]
fn hash_map_rejects_lock_cpu_and_high_half_flags() {
    use uapi::elem_flags as e;
    let all = !0u64;
    assert_eq!(check_op_flags(e::F_LOCK, e::F_LOCK | e::F_CPU), Err(Errno::Einval));
    assert_eq!(check_op_flags(e::F_CPU, e::F_LOCK | e::F_CPU), Err(Errno::Einval));
    assert_eq!(check_op_flags(1u64 << 32, all), Err(Errno::Einval));
    assert_eq!(check_op_flags(e::ANY, all), Ok(()));
}

#[test]
fn lookup_rejects_any_update_flag_because_its_allowed_mask_is_narrow() {
    use uapi::elem_flags as e;
    let lookup_mask = e::F_LOCK | e::F_CPU;
    assert_eq!(check_op_flags(e::NOEXIST, lookup_mask), Err(Errno::Einval));
    assert_eq!(check_op_flags(e::EXIST, lookup_mask), Err(Errno::Einval));
}

#[test]
fn update_flags_above_bpf_exist_are_einval() {
    // htab_map_update_elem(): (map_flags & ~BPF_F_LOCK) > BPF_EXIST.
    use uapi::elem_flags as e;
    assert_eq!(check_update_flags(e::ANY), Ok(()));
    assert_eq!(check_update_flags(e::NOEXIST), Ok(()));
    assert_eq!(check_update_flags(e::EXIST), Ok(()));
    assert_eq!(check_update_flags(3), Err(Errno::Einval));
}

#[test]
fn noexist_on_a_present_key_is_eexist_and_exist_on_absent_is_enoent() {
    use uapi::elem_flags as e;
    assert_eq!(update_presence_verdict(e::NOEXIST, true), Err(Errno::Eexist));
    assert_eq!(update_presence_verdict(e::NOEXIST, false), Ok(()));
    assert_eq!(update_presence_verdict(e::EXIST, false), Err(Errno::Enoent));
    assert_eq!(update_presence_verdict(e::EXIST, true), Ok(()));
    assert_eq!(update_presence_verdict(e::ANY, true), Ok(()));
    assert_eq!(update_presence_verdict(e::ANY, false), Ok(()));
}

