use alloc::vec::Vec;
use core::cell::Cell;

use syscall::errno::Errno;

use super::{expected_attach_then, verify};
use super::super::uapi;

#[test]
fn invalid_expected_attach_type_precedes_bad_user_pointer() {
    let copied = Cell::new(false);
    let result = expected_attach_then(
        uapi::prog_type::CGROUP_SKB,
        uapi::attach_type::MAX,
        || {
            copied.set(true);
            Err::<(), _>(Errno::Efault)
        },
    );
    assert_eq!(result, Err(Errno::Einval));
    assert!(!copied.get(), "instruction and license copies must not run");
}

fn returns(value: i32) -> Vec<u8> {
    let mut insns = Vec::new();
    insns.extend_from_slice(&[0xb7, 0, 0, 0]);
    insns.extend_from_slice(&value.to_le_bytes());
    insns.extend_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
    insns
}

#[test]
fn load_carries_verifier_egress_attach_contract() {
    assert_eq!(verify(
        uapi::prog_type::CGROUP_SKB,
        uapi::attach_type::CGROUP_INET_EGRESS,
        &returns(2),
        &[],
    ), Ok(true));
    assert_eq!(verify(
        uapi::prog_type::CGROUP_SKB,
        uapi::attach_type::CGROUP_INET_EGRESS,
        &returns(1),
        &[],
    ), Ok(false));
    assert_eq!(verify(
        uapi::prog_type::CGROUP_SKB,
        uapi::attach_type::CGROUP_INET_INGRESS,
        &returns(1),
        &[],
    ), Ok(false));
}
