use alloc::sync::Arc;

use super::*;

fn raw(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let off = off.to_le_bytes();
    let imm = imm.to_le_bytes();
    [opcode, src << 4 | dst, off[0], off[1], imm[0], imm[1], imm[2], imm[3]]
}

fn program(prog_type: u32, attach_type: u32, insns: &[[u8; 8]]) -> InodeRef {
    super::super::make_bpf_prog_inode_with_meta(
        prog_type,
        attach_type,
        insns.iter().flatten().copied().collect(),
        alloc::vec![],
    )
}

#[test]
fn skb_runner_serialized_fields_drive_the_verdict() {
    let prog = program(
        uapi::prog_type::CGROUP_SKB,
        uapi::attach_type::CGROUP_INET_INGRESS,
        &[
            raw(0x61, 2, 1, 40, 0),
            raw(0xb7, 0, 0, 0, 0),
            raw(0x15, 2, 0, 1, 0),
            raw(0xb7, 0, 0, 0, 1),
            raw(0x95, 0, 0, 0, 0),
        ],
    );
    let programs = [prog];
    let mut ctx = [0u8; 44];
    ctx[40..44].copy_from_slice(&7u32.to_ne_bytes());
    assert_eq!(
        run_skb_programs(
            &programs, CgroupSkbAttach::Ingress,
            uapi::attach_type::CGROUP_INET_INGRESS, &ctx, &[],
        ).unwrap(),
        CgroupSkbVerdict { allow: true, congestion_notification: false },
    );
    ctx[40..44].copy_from_slice(&0u32.to_ne_bytes());
    assert!(!run_skb_programs(
        &programs, CgroupSkbAttach::Ingress,
        uapi::attach_type::CGROUP_INET_INGRESS, &ctx, &[],
    ).unwrap().allow);
}

#[test]
fn sockaddr_runner_applies_successful_writes_and_bind_flag() {
    let network_port = u16::to_be(8080) as u32;
    let prog = program(
        uapi::prog_type::CGROUP_SOCK_ADDR,
        uapi::attach_type::CGROUP_INET4_BIND,
        &[
            raw(0x62, 1, 0, 24, network_port as i32),
            raw(0xb7, 0, 0, 0, 3),
            raw(0x95, 0, 0, 0, 0),
        ],
    );
    let mut bytes = [0u8; 40];
    let verdict = run_sockaddr_programs(
        &[Arc::clone(&prog)], uapi::attach_type::CGROUP_INET4_BIND, &mut bytes,
    ).unwrap();
    assert!(verdict.bind_no_cap_net_bind_service);
    assert_eq!(u32::from_ne_bytes(bytes[24..28].try_into().unwrap()), network_port);
}

#[test]
fn sockaddr_denial_is_eperm() {
    let deny = program(
        uapi::prog_type::CGROUP_SOCK_ADDR,
        uapi::attach_type::CGROUP_INET4_CONNECT,
        &[raw(0xb7, 0, 0, 0, 0), raw(0x95, 0, 0, 0, 0)],
    );
    let error = run_sockaddr_programs(
        &[deny], uapi::attach_type::CGROUP_INET4_CONNECT, &mut [0; 40],
    ).unwrap_err();
    assert_eq!(error.as_i32(), Errno::Eperm.as_i32());
}

#[test]
fn sockaddr_set_retval_preserves_exact_errno() {
    let deny = program(
        uapi::prog_type::CGROUP_SOCK_ADDR,
        uapi::attach_type::CGROUP_INET4_CONNECT,
        &[
            raw(0xb7, 1, 0, 0, -(Errno::Eagain.as_i32())),
            raw(0x85, 0, 0, 0, uapi::func_id::SET_RETVAL as i32),
            raw(0xb7, 0, 0, 0, 0),
            raw(0x95, 0, 0, 0, 0),
        ],
    );
    let error = run_sockaddr_programs(
        &[deny], uapi::attach_type::CGROUP_INET4_CONNECT, &mut [0; 40],
    ).unwrap_err();
    assert_eq!(error.as_i32(), Errno::Eagain.as_i32());
}

#[test]
fn sockaddr_set_retval_preserves_the_entire_linux_raw_error_range() {
    for raw_errno in [134, 4095] {
        let deny = program(
            uapi::prog_type::CGROUP_SOCK_ADDR,
            uapi::attach_type::CGROUP_INET4_CONNECT,
            &[
                raw(0xb7, 1, 0, 0, -raw_errno),
                raw(0x85, 0, 0, 0, uapi::func_id::SET_RETVAL as i32),
                raw(0xb7, 0, 0, 0, 0),
                raw(0x95, 0, 0, 0, 0),
            ],
        );
        let error = run_sockaddr_programs(
            &[deny], uapi::attach_type::CGROUP_INET4_CONNECT, &mut [0; 40],
        ).unwrap_err();
        assert_eq!(error.as_i32(), raw_errno);
    }
}

#[test]
fn runners_defensively_reject_out_of_range_return_values() {
    let bad_skb = program(
        uapi::prog_type::CGROUP_SKB,
        uapi::attach_type::CGROUP_INET_INGRESS,
        &[raw(0xb7, 0, 0, 0, 2), raw(0x95, 0, 0, 0, 0)],
    );
    assert_eq!(
        run_skb_programs(
            &[bad_skb], CgroupSkbAttach::Ingress,
            uapi::attach_type::CGROUP_INET_INGRESS, &[0; 44], &[],
        ),
        Err(Errno::Einval),
    );
    let bad_bind = program(
        uapi::prog_type::CGROUP_SOCK_ADDR,
        uapi::attach_type::CGROUP_INET4_BIND,
        &[raw(0xb7, 0, 0, 0, 4), raw(0x95, 0, 0, 0, 0)],
    );
    let error = run_sockaddr_programs(
        &[bad_bind], uapi::attach_type::CGROUP_INET4_BIND, &mut [0; 40],
    ).unwrap_err();
    assert_eq!(error.as_i32(), Errno::Einval.as_i32());
}

#[test]
fn runtime_expected_attach_checks_follow_the_verifier_contract_bit() {
    let insns = [
        raw(0xb7, 0, 0, 0, 1),
        raw(0x95, 0, 0, 0, 0),
    ].into_iter().flatten().collect();
    let strict_skb = super::super::make_bpf_prog_inode_with_contract(
        uapi::prog_type::CGROUP_SKB,
        uapi::attach_type::CGROUP_INET_INGRESS,
        true,
        insns,
        alloc::vec![],
    );
    assert_eq!(
        run_skb_programs(
            &[strict_skb], CgroupSkbAttach::Egress,
            uapi::attach_type::CGROUP_INET_EGRESS, &[0; 44], &[],
        ),
        Err(Errno::Einval),
    );

    let loose_addr = program(
        uapi::prog_type::CGROUP_SOCK_ADDR,
        uapi::attach_type::CGROUP_INET4_CONNECT,
        &[raw(0xb7, 0, 0, 0, 1), raw(0x95, 0, 0, 0, 0)],
    );
    assert!(run_sockaddr_programs(
        &[loose_addr], uapi::attach_type::CGROUP_INET6_CONNECT, &mut [0; 40],
    ).is_ok());
    let strict_addr = super::super::make_bpf_prog_inode_with_contract(
        uapi::prog_type::CGROUP_SOCK_ADDR,
        uapi::attach_type::CGROUP_INET4_CONNECT,
        true,
        [
            raw(0xb7, 0, 0, 0, 1),
            raw(0x95, 0, 0, 0, 0),
        ].into_iter().flatten().collect(),
        alloc::vec![],
    );
    let error = run_sockaddr_programs(
        &[strict_addr], uapi::attach_type::CGROUP_INET6_CONNECT, &mut [0; 40],
    ).unwrap_err();
    assert_eq!(error.as_i32(), Errno::Einval.as_i32());
}
