use alloc::vec::Vec;
use core::cell::RefCell;

use syscall::errno::Errno;

use super::attach::{
    OrderRequest, attach_cap_check, classic_order_needs_resolution, decode_order,
    ensure_attach_compatible, resolve_classic_attach, resolve_query_target,
};
use super::super::attr::{Caps, ProgQuery};
use super::super::uapi;
use super::super::make_bpf_prog_inode_with_contract;

#[test]
fn classic_attach_resolves_linux_fd_order_before_semantic_flags() {
    let events = RefCell::new(Vec::new());
    let flags = uapi::attach_flags::ALLOW_OVERRIDE
        | uapi::attach_flags::ALLOW_MULTI | uapi::attach_flags::REPLACE;
    let result = resolve_classic_attach(
        flags, 11, 12, 13,
        |fd| {
            events.borrow_mut().push(fd);
            if fd == 13 { Err(Errno::Ebadf) } else { Ok(fd) }
        },
        |fd| {
            events.borrow_mut().push(fd);
            Ok(fd)
        },
    );
    assert!(matches!(result, Err(Errno::Ebadf)));
    assert_eq!(*events.borrow(), alloc::vec![11, 12, 13]);
}

#[test]
fn classic_attach_bad_program_and_target_precede_invalid_mode() {
    let flags = uapi::attach_flags::ALLOW_OVERRIDE | uapi::attach_flags::ALLOW_MULTI;
    let bad_prog = resolve_classic_attach(
        flags, 11, 12, 0,
        |_| Err::<i32, _>(Errno::Ebadf), |_| Ok::<i32, _>(12),
    );
    assert!(matches!(bad_prog, Err(Errno::Ebadf)));
    let bad_target = resolve_classic_attach(
        flags, 11, 12, 0,
        |_| Ok::<i32, _>(11), |_| Err::<i32, _>(Errno::Enoent),
    );
    assert!(matches!(bad_target, Err(Errno::Enoent)));
    let invalid = resolve_classic_attach(
        flags, 11, 12, 0,
        |_| Ok::<i32, _>(11), |_| Ok::<i32, _>(12),
    );
    assert!(matches!(invalid, Err(Errno::Einval)));
}

#[test]
fn ordering_decodes_program_and_link_fd_or_id_anchors() {
    use uapi::attach_flags as f;
    assert_eq!(
        decode_order(f::ALLOW_MULTI | f::BEFORE, 7, false),
        Ok(OrderRequest::BeforeProg { id: false, value: 7 }),
    );
    assert_eq!(
        decode_order(f::ALLOW_MULTI | f::AFTER | f::ID, 8, false),
        Ok(OrderRequest::AfterProg { id: true, value: 8 }),
    );
    assert_eq!(
        decode_order(f::BEFORE | f::LINK, 9, true),
        Ok(OrderRequest::BeforeLink { id: false, value: 9 }),
    );
    assert_eq!(
        decode_order(f::AFTER | f::LINK | f::ID, 10, true),
        Ok(OrderRequest::AfterLink { id: true, value: 10 }),
    );
}

#[test]
fn ordering_rejects_owner_selector_mismatch_and_invalid_pairs() {
    use uapi::attach_flags as f;
    assert_eq!(decode_order(f::BEFORE | f::LINK, 7, false), Err(Errno::Einval));
    assert_eq!(decode_order(f::BEFORE, 7, true), Err(Errno::Einval));
    assert_eq!(decode_order(f::BEFORE | f::AFTER, 7, false), Err(Errno::Einval));
    assert_eq!(decode_order(f::BEFORE | f::AFTER, 0, false), Ok(OrderRequest::Empty));
    assert_eq!(decode_order(f::BEFORE, 0, false), Ok(OrderRequest::First));
    assert_eq!(decode_order(f::AFTER, 0, false), Ok(OrderRequest::Last));
}

#[test]
fn existing_non_multi_entry_ignores_an_unused_relative_fd() {
    use cgroup::BpfAttachMode as M;
    use uapi::attach_flags as f;
    assert!(!classic_order_needs_resolution(f::BEFORE, M::Single, false));
    assert!(!classic_order_needs_resolution(
        f::ALLOW_OVERRIDE | f::AFTER, M::Override, false,
    ));
    assert!(classic_order_needs_resolution(f::BEFORE, M::Single, true));
    assert!(classic_order_needs_resolution(f::ALLOW_MULTI | f::BEFORE, M::Multi, false));
}

#[test]
fn cgroup_skb_attach_needs_net_admin_or_sys_admin() {
    let none = Caps::default();
    assert_eq!(
        attach_cap_check(uapi::prog_type::CGROUP_SKB, none, false),
        Err(Errno::Einval),
    );
    assert_eq!(
        attach_cap_check(uapi::prog_type::CGROUP_SKB, none, true),
        Err(Errno::Eperm),
    );
    let net = Caps { net_admin: true, ..Caps::default() };
    let admin = Caps { sys_admin: true, ..Caps::default() };
    assert_eq!(attach_cap_check(uapi::prog_type::CGROUP_SKB, net, true), Ok(()));
    assert_eq!(attach_cap_check(uapi::prog_type::CGROUP_SKB, admin, true), Ok(()));
    assert_eq!(attach_cap_check(uapi::prog_type::CGROUP_DEVICE, none, true), Ok(()));
}

#[test]
fn cgroup_skb_direction_mismatch_only_applies_to_enforced_contracts() {
    let caps = Caps { net_admin: true, ..Caps::default() };
    let unenforced = make_bpf_prog_inode_with_contract(
        uapi::prog_type::CGROUP_SKB,
        uapi::attach_type::CGROUP_INET_INGRESS,
        false,
        Vec::new(),
        Vec::new(),
    );
    assert_eq!(
        ensure_attach_compatible(
            &unenforced, uapi::attach_type::CGROUP_INET_EGRESS, caps, false,
        ),
        Ok(()),
    );
    let enforced = make_bpf_prog_inode_with_contract(
        uapi::prog_type::CGROUP_SKB,
        uapi::attach_type::CGROUP_INET_INGRESS,
        true,
        Vec::new(),
        Vec::new(),
    );
    assert_eq!(
        ensure_attach_compatible(
            &enforced, uapi::attach_type::CGROUP_INET_EGRESS, caps, false,
        ),
        Err(Errno::Einval),
    );
}

#[test]
fn query_resolves_online_target_before_effective_pointer_constraint() {
    let query = ProgQuery {
        target_fd: 12,
        attach_type: uapi::attach_type::CGROUP_DEVICE,
        query_flags: uapi::query_flags::EFFECTIVE,
        prog_ids: 0,
        prog_cnt: 0,
        prog_attach_flags: 0x1000,
    };
    let stale = resolve_query_target(&query, |_| Err::<i32, _>(Errno::Enoent));
    assert!(matches!(stale, Err(Errno::Enoent)));
    let live = resolve_query_target(&query, |_| Ok::<i32, _>(12));
    assert!(matches!(live, Err(Errno::Einval)));
}
