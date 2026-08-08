// Hosted tests for the `bpf(2)` attr protocol + validation ladders.
// Every assertion names the Linux function it pins.

use super::*;

fn attr_with(pairs: &[(usize, u32)]) -> Attr {
    let mut a = Attr::zeroed();
    for (off, v) in pairs { a.bytes[*off..*off + 4].copy_from_slice(&v.to_ne_bytes()); }
    a
}

fn attr_u64(a: &mut Attr, off: usize, v: u64) { a.bytes[off..off + 8].copy_from_slice(&v.to_ne_bytes()); }

fn caps_none() -> Caps { Caps::default() }
fn caps_bpf() -> Caps { Caps { bpf: true, ..Caps::default() } }

// ------------------------------------------------------- size protocol

#[test]
fn size_larger_than_a_page_is_e2big_before_anything_else() {
    // bpf_check_uarg_tail_zero(): actual_size > PAGE_SIZE -> -E2BIG.
    assert_eq!(size_protocol(uapi::ATTR_MAX_USER_SIZE as u32 + 1), Err(Errno::E2big));
    assert!(size_protocol(uapi::ATTR_MAX_USER_SIZE as u32).is_ok());
}

#[test]
fn short_size_copies_short_and_zero_fills_the_rest() {
    // __sys_bpf(): memset(&attr,0,...) then copy_from_bpfptr(size).
    assert_eq!(size_protocol(4), Ok((4, 0)));
    assert_eq!(size_protocol(0), Ok((0, 0)));
}

#[test]
fn size_between_attr_size_and_page_needs_a_tail_zero_check() {
    let (copy, tail) = size_protocol(uapi::ATTR_SIZE as u32 + 8).unwrap();
    assert_eq!((copy, tail), (uapi::ATTR_SIZE, 8));
    assert_eq!(tail_verdict(false), Err(Errno::E2big));
    assert_eq!(tail_verdict(true), Ok(()));
}

#[test]
fn unknown_command_is_einval_but_only_after_the_size_check() {
    // __sys_bpf(): `default: err = -EINVAL` sits after the tail-zero call.
    assert!(!cmd_is_known(uapi::cmd::MAX));
    assert!(!cmd_is_known(0xdead_beef));
    assert!(cmd_is_known(uapi::cmd::PROG_ASSOC_STRUCT_OPS));
    assert_eq!(size_protocol(0x1_0000), Err(Errno::E2big));
}

// ----------------------------------------------------------- CHECK_ATTR

#[test]
fn check_attr_rejects_a_nonzero_byte_past_the_last_field() {
    let mut a = Attr::zeroed();
    assert_eq!(check_attr(&a, uapi::off::map_elem::FLAGS_LAST_END), Ok(()));
    a.bytes[uapi::off::map_elem::FLAGS_LAST_END] = 1;
    assert_eq!(check_attr(&a, uapi::off::map_elem::FLAGS_LAST_END), Err(Errno::Einval));
}

#[test]
fn map_delete_elem_last_field_is_key_so_value_and_flags_must_be_zero() {
    // BPF_MAP_DELETE_ELEM_LAST_FIELD key -> zero region starts at 16.
    let mut a = Attr::zeroed();
    attr_u64(&mut a, uapi::off::map_elem::VALUE, 1);
    assert_eq!(check_attr(&a, uapi::off::map_elem::KEY_LAST_END), Err(Errno::Einval));
    assert_eq!(check_attr(&a, uapi::off::map_elem::FLAGS_LAST_END), Ok(()));
}

#[test]
fn prog_load_last_field_ends_the_union_so_check_attr_always_passes() {
    let mut a = Attr::zeroed();
    a.bytes[uapi::ATTR_SIZE - 1] = 0xff;
    assert_eq!(check_attr(&a, uapi::off::prog_load::LAST_END), Ok(()));
}

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

// -------------------------------------------------------------- PROG_LOAD

fn good_prog_load(prog_type: u32, insn_cnt: u32) -> Attr {
    use uapi::off::prog_load as o;
    attr_with(&[(o::PROG_TYPE, prog_type), (o::INSN_CNT, insn_cnt)])
}

#[test]
fn prog_load_insn_count_zero_or_over_the_ceiling_is_e2big_not_einval() {
    // bpf_prog_load(): `err = -E2BIG` on the insn_cnt bound.
    let t = uapi::prog_type::SOCKET_FILTER;
    assert_eq!(prog_load_check(&good_prog_load(t, 0), caps_bpf(), true), Err(Errno::E2big));
    let over = uapi::COMPLEXITY_LIMIT_INSNS + 1;
    assert_eq!(prog_load_check(&good_prog_load(t, over), caps_bpf(), true), Err(Errno::E2big));
}

#[test]
fn unprivileged_insn_ceiling_is_bpf_maxinsns() {
    // insn_cnt > (bpf_cap ? BPF_COMPLEXITY_LIMIT_INSNS : BPF_MAXINSNS).
    let t = uapi::prog_type::SOCKET_FILTER;
    let a = good_prog_load(t, uapi::MAXINSNS + 1);
    assert_eq!(prog_load_check(&a, caps_none(), false), Err(Errno::E2big));
    assert!(prog_load_check(&a, caps_bpf(), false).is_ok());
}

#[test]
fn prog_load_without_cap_bpf_is_eperm_when_unpriv_is_disabled() {
    let a = good_prog_load(uapi::prog_type::SOCKET_FILTER, 1);
    assert_eq!(prog_load_check(&a, caps_none(), true), Err(Errno::Eperm));
}

#[test]
fn only_socket_filter_and_cgroup_skb_load_without_cap_bpf() {
    for t in [uapi::prog_type::SOCKET_FILTER, uapi::prog_type::CGROUP_SKB] {
        assert!(prog_load_check(&good_prog_load(t, 1), caps_none(), false).is_ok(), "type {t}");
    }
    let a = good_prog_load(uapi::prog_type::SYSCALL, 1);
    assert_eq!(prog_load_check(&a, caps_none(), false), Err(Errno::Eperm));
}

#[test]
fn net_admin_prog_types_demand_cap_net_admin() {
    let a = good_prog_load(uapi::prog_type::XDP, 1);
    assert_eq!(prog_load_check(&a, caps_bpf(), false), Err(Errno::Eperm));
    let caps = Caps { bpf: true, net_admin: true, ..Caps::default() };
    assert!(prog_load_check(&a, caps, false).is_ok());
    assert!(is_net_admin_prog_type(uapi::prog_type::CGROUP_DEVICE));
    assert!(!is_net_admin_prog_type(uapi::prog_type::CGROUP_SKB));
}

#[test]
fn perfmon_prog_types_demand_cap_perfmon() {
    let a = good_prog_load(uapi::prog_type::KPROBE, 1);
    assert_eq!(prog_load_check(&a, caps_bpf(), false), Err(Errno::Eperm));
    let caps = Caps { bpf: true, perfmon: true, ..Caps::default() };
    assert!(prog_load_check(&a, caps, false).is_ok());
    assert!(is_perfmon_prog_type(uapi::prog_type::LSM));
}

#[test]
fn prog_load_unknown_prog_flag_bit_is_einval_before_any_eperm() {
    let mut a = good_prog_load(uapi::prog_type::SOCKET_FILTER, 1);
    let off = uapi::off::prog_load::PROG_FLAGS;
    a.bytes[off..off + 4].copy_from_slice(&(1u32 << 20).to_ne_bytes());
    assert_eq!(prog_load_check(&a, caps_none(), true), Err(Errno::Einval));
}

#[test]
fn prog_types_without_a_runner_are_not_loadable() {
    // find_prog_type(): bpf_prog_types[type] == NULL -> -EINVAL, which is
    // what Linux returns for any type whose CONFIG is not built in.
    assert!(prog_type_supported(uapi::prog_type::SOCKET_FILTER));
    assert!(prog_type_supported(uapi::prog_type::CGROUP_DEVICE));
    assert!(prog_type_supported(uapi::prog_type::CGROUP_SKB));
    assert!(prog_type_supported(uapi::prog_type::CGROUP_SOCK_ADDR));
    for t in [uapi::prog_type::UNSPEC, uapi::prog_type::XDP, uapi::prog_type::KPROBE,
              uapi::prog_type::SCHED_CLS, uapi::prog_type::TRACING,
              uapi::prog_type::SYSCALL] {
        assert!(!prog_type_supported(t), "type {t} must not be loadable");
    }
}

#[test]
fn expected_attach_contract_accepts_arbitrary_device_and_socket_values() {
    assert_eq!(
        expected_attach_type_check(uapi::prog_type::CGROUP_DEVICE, 0xfeed),
        Ok(()),
    );
    assert_eq!(
        expected_attach_type_check(uapi::prog_type::SOCKET_FILTER, 0xbeef),
        Ok(()),
    );
    assert_eq!(
        expected_attach_type_check(uapi::prog_type::CGROUP_SKB, uapi::attach_type::MAX),
        Err(Errno::Einval),
    );
}

#[test]
fn lsm_programs_are_loadable_and_need_both_bpf_and_perfmon() {
    assert!(prog_type_supported(uapi::prog_type::LSM));
    // LSM is a perfmon prog type, so CAP_BPF alone does not carry a load;
    // it is not a net-admin type, so CAP_NET_ADMIN does not substitute.
    let a = good_prog_load(uapi::prog_type::LSM, 1);
    assert_eq!(prog_load_check(&a, caps_bpf(), false), Err(Errno::Eperm));
    let net = Caps { bpf: true, net_admin: true, ..Caps::default() };
    assert_eq!(prog_load_check(&a, net, false), Err(Errno::Eperm));
    let perfmon = Caps { perfmon: true, ..Caps::default() };
    assert_eq!(prog_load_check(&a, perfmon, false), Err(Errno::Eperm));
    let caps = Caps { bpf: true, perfmon: true, ..Caps::default() };
    assert!(prog_load_check(&a, caps, false).is_ok());
}

#[test]
fn only_a_program_type_that_attaches_to_a_target_may_name_one() {
    use uapi::prog_type as p;
    for prog_type in [p::TRACING, p::LSM, p::STRUCT_OPS, p::EXT] {
        assert_eq!(prog_load_check_attach(prog_type, uapi::attach_type::LSM_MAC, 1), Ok(()));
    }
    for prog_type in [p::SOCKET_FILTER, p::CGROUP_DEVICE, p::KPROBE] {
        assert_eq!(prog_load_check_attach(prog_type, 0, 1), Err(Errno::Einval));
        // Naming no target at all leaves those types unaffected.
        assert_eq!(prog_load_check_attach(prog_type, 0, 0), Ok(()));
    }
}

#[test]
fn an_attach_target_above_the_type_id_ceiling_is_refused() {
    const MAX_TYPE_ID: u32 = 0x000f_ffff;
    assert_eq!(
        prog_load_check_attach(uapi::prog_type::LSM, uapi::attach_type::LSM_MAC, MAX_TYPE_ID),
        Ok(()),
    );
    for attach_btf_id in [MAX_TYPE_ID + 1, u32::MAX] {
        assert_eq!(
            prog_load_check_attach(
                uapi::prog_type::LSM, uapi::attach_type::LSM_MAC, attach_btf_id,
            ),
            Err(Errno::Einval),
        );
    }
}

// ------------------------------------------------------------ PROG_ATTACH

#[test]
fn prog_attach_routes_implemented_cgroup_types() {
    let a = attr_with(&[(uapi::off::prog_attach::ATTACH_TYPE, uapi::attach_type::CGROUP_DEVICE)]);
    let ptype = prog_attach_check(&a).expect("attach type resolves");
    assert_eq!(ptype, uapi::prog_type::CGROUP_DEVICE);
    let skb = attr_with(&[(
        uapi::off::prog_attach::ATTACH_TYPE,
        uapi::attach_type::CGROUP_INET_EGRESS,
    )]);
    assert_eq!(prog_attach_check(&skb), Ok(uapi::prog_type::CGROUP_SKB));
}

#[test]
fn prog_attach_unknown_attach_type_is_einval() {
    let a = attr_with(&[(uapi::off::prog_attach::ATTACH_TYPE, uapi::attach_type::MAX)]);
    assert_eq!(prog_attach_check(&a), Err(Errno::Einval));
}

#[test]
fn prog_attach_rejects_trailing_garbage_and_unknown_attach_flags() {
    let mut a = attr_with(&[(uapi::off::prog_attach::ATTACH_TYPE, uapi::attach_type::CGROUP_DEVICE)]);
    a.bytes[uapi::off::prog_attach::LAST_END] = 1;
    assert_eq!(prog_attach_check(&a), Err(Errno::Einval));

    let a = attr_with(&[(uapi::off::prog_attach::ATTACH_TYPE, uapi::attach_type::CGROUP_DEVICE),
                        (uapi::off::prog_attach::ATTACH_FLAGS, 1 << 20)]);
    assert_eq!(prog_attach_check(&a), Err(Errno::Einval));
}

#[test]
fn prog_attach_accepts_cgroup_revision_ordering_flag_surface() {
    use uapi::attach_flags as f;
    use uapi::off::prog_attach as o;
    let flags = f::ALLOW_MULTI | f::BEFORE | f::ID | f::PREORDER;
    let a = attr_with(&[
        (o::ATTACH_TYPE, uapi::attach_type::CGROUP_INET_EGRESS),
        (o::ATTACH_FLAGS, flags), (o::RELATIVE_FD, 17),
    ]);
    assert_eq!(prog_attach_check(&a), Ok(uapi::prog_type::CGROUP_SKB));
}

// ------------------------------------------------------------- PROG_QUERY

#[test]
fn prog_query_needs_net_admin_before_attr_validation() {
    use uapi::off::prog_query as o;
    let mut a = attr_with(&[(o::ATTACH_TYPE, uapi::attach_type::CGROUP_DEVICE)]);
    a.bytes[o::LAST_END] = 1;
    assert_eq!(prog_query_check(&a, caps_bpf()), Err(Errno::Eperm));
    let caps = Caps { bpf: true, net_admin: true, ..Caps::default() };
    assert_eq!(prog_query_check(&a, caps), Err(Errno::Einval));
}

#[test]
fn prog_query_accepts_implemented_cgroup_attach_views() {
    use uapi::off::prog_query as o;
    let caps = Caps { net_admin: true, ..Caps::default() };
    let direct = attr_with(&[(o::TARGET_FD, 7),
        (o::ATTACH_TYPE, uapi::attach_type::CGROUP_DEVICE), (o::PROG_CNT, 4)]);
    assert_eq!(prog_query_check(&direct, caps).unwrap().prog_cnt, 4);

    let mut effective = attr_with(&[(o::ATTACH_TYPE, uapi::attach_type::CGROUP_DEVICE),
        (o::QUERY_FLAGS, uapi::query_flags::EFFECTIVE)]);
    attr_u64(&mut effective, o::PROG_ATTACH_FLAGS, 0x1000);
    assert!(prog_query_check(&effective, caps).is_ok(),
        "target fd resolution precedes the effective pointer constraint");
    let wrong = attr_with(&[(o::ATTACH_TYPE, uapi::attach_type::CGROUP_INET_EGRESS)]);
    assert_eq!(
        prog_query_check(&wrong, caps).unwrap().attach_type,
        uapi::attach_type::CGROUP_INET_EGRESS,
    );
}

#[test]
fn prog_get_fd_by_id_checks_tail_before_sys_admin() {
    use uapi::off::prog_get_fd_by_id as o;
    let mut bad = attr_with(&[(o::PROG_ID, 7)]);
    bad.bytes[o::LAST_END] = 1;
    assert_eq!(prog_get_fd_by_id_check(&bad, caps_none()), Err(Errno::Einval));
    let good = attr_with(&[(o::PROG_ID, 7)]);
    assert_eq!(prog_get_fd_by_id_check(&good, caps_none()), Err(Errno::Eperm));
    assert_eq!(
        prog_get_fd_by_id_check(&good, Caps { sys_admin: true, ..Caps::default() }),
        Ok(7),
    );
}

// ------------------------------------------------------------ LINK_CREATE

#[test]
fn link_create_decodes_cgroup_ordering_and_revision_union() {
    use uapi::off::link_create as o;
    let flags = uapi::attach_flags::BEFORE | uapi::attach_flags::ID
        | uapi::attach_flags::PREORDER | uapi::attach_flags::LINK;
    let mut a = attr_with(&[
        (o::PROG_FD, 3), (o::TARGET_FD, 4),
        (o::ATTACH_TYPE, uapi::attach_type::CGROUP_DEVICE),
        (o::FLAGS, flags), (o::CGROUP_RELATIVE_FD, 9),
    ]);
    attr_u64(&mut a, o::CGROUP_EXPECTED_REVISION, 27);
    assert_eq!(link_create_check(&a), Ok(LinkCreate {
        prog_fd: 3, target_fd: 4, attach_type: uapi::attach_type::CGROUP_DEVICE,
        flags, target_btf_id: 9, relative_fd: 9, expected_revision: 27,
    }));
    assert_eq!(cgroup_link_flags_check(flags), Ok(()));

    assert_eq!(
        cgroup_link_flags_check(flags | uapi::attach_flags::ALLOW_MULTI),
        Err(Errno::Einval),
    );
}

#[test]
fn link_create_check_attr_region_starts_at_sixty_four() {
    // BPF_LINK_CREATE_LAST_FIELD link_create.uprobe_multi.path_fd.
    use uapi::off::link_create as o;
    let mut a = attr_with(&[(o::ATTACH_TYPE, uapi::attach_type::LSM_MAC)]);
    a.bytes[o::LAST_END - 1] = 0xff;
    assert!(link_create_check(&a).is_ok());
    a.bytes[o::LAST_END] = 1;
    assert_eq!(link_create_check(&a), Err(Errno::Einval));
}

// `kernel.unprivileged_bpf_disabled`. The latch is the whole point of the
// knob: an attacker who reaches code that can write it must not be able to
// re-open the interface it closed.
#[test]
fn unprivileged_bpf_may_be_switched_off_for_good_but_only_by_an_administrator() {
    // Only the administrative capability writes it at all, and the refusal is
    // EPERM rather than a value complaint.
    assert_eq!(unpriv_write_verdict(0, 1, false), Err(Errno::Eperm));
    assert_eq!(unpriv_write_verdict(0, 1, true), Ok(1));
    // 1 is a one-way latch: nothing re-opens it, not even the same value's
    // weaker neighbour.
    assert_eq!(unpriv_write_verdict(1, 0, true), Err(Errno::Eperm));
    assert_eq!(unpriv_write_verdict(1, 2, true), Err(Errno::Eperm));
    assert_eq!(unpriv_write_verdict(1, 1, true), Ok(1));
    // The build-time default carries no latch, so an administrator can still
    // choose the weaker setting on a kernel that shipped with the stronger.
    assert_eq!(unpriv_write_verdict(2, 0, true), Ok(0));
    assert_eq!(unpriv_write_verdict(2, 1, true), Ok(1));
    // Out-of-window values are a value complaint, checked after the capability.
    assert_eq!(unpriv_write_verdict(0, 3, true), Err(Errno::Einval));
    assert_eq!(unpriv_write_verdict(0, -1, true), Err(Errno::Einval));
    assert_eq!(unpriv_write_verdict(0, 3, false), Err(Errno::Eperm));
}
