use super::*;

fn hex(source: &str) -> Vec<u8> {
    let compact: Vec<u8> = source.bytes().filter(|byte| !byte.is_ascii_whitespace()).collect();
    compact.chunks_exact(2).map(|pair| {
        let digit = |value: u8| match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("bad hex"),
        };
        digit(pair[0]) << 4 | digit(pair[1])
    }).collect()
}

fn array(value_size: u32, max_entries: u32, flags: u32) -> InodeRef {
    crate::bpf::map::allocate(
        uapi::map_type::ARRAY, 4, value_size, max_entries, flags,
    ).unwrap()
}

fn raw(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let off = off.to_le_bytes();
    let imm = imm.to_le_bytes();
    [opcode, src << 4 | dst, off[0], off[1], imm[0], imm[1], imm[2], imm[3]]
}

#[test]
fn accepts_systemd_257_socket_bind_object_program() {
    let mut insns = hex(
        "bf16000000000000b40000000100000061610000000000005601410002000000
         61611c000000000056013f00020000006161180000000000631afcff00000000
         b40700000000000061a8fcff00000000dc08000010000000637af8ff00000000
         bfa200000000000007020000f8ffffff18010000000000000000000000000000
         85000000010000001500130000000000610200000000000016020e00ffffffff
         61612400000000001602030000000000616300000000000054030000ff000000
         5e32090000000000610204000000000016020100000000005e12060000000000
         6901080000000000160126000000000069020a0000000000ae28020000000000
         0c120000000000002e8222000000000004070000010000001607010080000000
         0500e6ff000000006161180000000000631afcff00000000b407000000000000
         61a8fcff00000000dc08000010000000637af8ff00000000bfa2000000000000
         07020000f8ffffff180100000000000000000000000000008500000001000000
         1500130000000000610200000000000016020e00ffffffff6161240000000000
         1602030000000000616300000000000054030000ff0000005e32090000000000
         610204000000000016020100000000005e120600000000006901080000000000
         160109000000000069020a0000000000ae280200000000000c12000000000000
         2e82050000000000040700000100000016070100800000000500e6ff00000000
         b4000000010000009500000000000000b4000000000000000500fdff00000000",
    );
    insns[14 * 8 + 1] = 0x11;
    insns[45 * 8 + 1] = 0x11;
    insns[45 * 8 + 4..45 * 8 + 8].copy_from_slice(&1i32.to_le_bytes());
    let maps = [array(12, 128, 0), array(12, 128, 0)];
    assert_eq!(verify_cgroup_network(
        uapi::prog_type::CGROUP_SOCK_ADDR,
        uapi::attach_type::CGROUP_INET4_BIND,
        &insns,
        &maps,
    ), Ok(false));
}

#[test]
fn accepts_systemd_257_restrict_ifaces_object_program() {
    let mut insns = hex(
        "6111280000000000631afcff00000000bfa200000000000007020000fcffffff
         1801000000000000000000000000000085000000010000001801000000000000
         000000000000000071110000000000001601030000000000b401000001000000
         15000300000000000500030000000000b4010000010000001500010000000000
         b401000000000000bc100000000000009500000000000000",
    );
    insns[4 * 8 + 1] = 0x11;
    insns[7 * 8 + 1] = 0x21;
    insns[7 * 8 + 4..7 * 8 + 8].copy_from_slice(&1i32.to_le_bytes());
    let hash = crate::bpf::map::allocate(uapi::map_type::HASH, 4, 1, 8, 0).unwrap();
    let rodata = array(1, 1, uapi::map_flags::RDONLY_PROG);
    assert_eq!(verify_cgroup_network(
        uapi::prog_type::CGROUP_SKB,
        uapi::attach_type::CGROUP_INET_EGRESS,
        &insns,
        &[hash, rodata],
    ), Ok(false));
}

#[test]
fn map_value_must_be_checked_for_null_before_dereference() {
    let insns: Vec<u8> = [
        raw(0x62, 10, 0, -4, 0),
        raw(0x18, 1, uapi::pseudo::MAP_FD, 0, 0),
        raw(0, 0, 0, 0, 0),
        raw(0xbf, 2, 10, 0, 0),
        raw(0x07, 2, 0, 0, -4),
        raw(0x85, 0, 0, 0, uapi::func_id::MAP_LOOKUP_ELEM as i32),
        raw(0x61, 0, 0, 0, 0),
        raw(0x95, 0, 0, 0, 0),
    ].into_iter().flatten().collect();
    let map = array(4, 1, 0);
    assert_eq!(
        verify_cgroup_network(
            uapi::prog_type::CGROUP_SKB,
            uapi::attach_type::CGROUP_INET_INGRESS,
            &insns,
            &[map],
        ),
        Err(VerifyError::UnsafeContextAccess),
    );
}

#[test]
fn rejects_unproved_infinite_jump_and_accepts_canonical_counter_loop() {
    let infinite: Vec<u8> = [
        raw(0x05, 0, 0, -1, 0),
        raw(0x95, 0, 0, 0, 0),
    ].into_iter().flatten().collect();
    assert_eq!(
        verify_cgroup_network(
            uapi::prog_type::CGROUP_SKB,
            uapi::attach_type::CGROUP_INET_INGRESS,
            &infinite,
            &[],
        ),
        Err(VerifyError::UnsupportedOpcode),
    );
    let bounded: Vec<u8> = [
        raw(0xb7, 2, 0, 0, 0),
        raw(0x07, 2, 0, 0, 1),
        raw(0xa5, 2, 0, -2, 4),
        raw(0xb7, 0, 0, 0, 1),
        raw(0x95, 0, 0, 0, 0),
    ].into_iter().flatten().collect();
    assert_eq!(
        verify_cgroup_network(
            uapi::prog_type::CGROUP_SKB,
            uapi::attach_type::CGROUP_INET_INGRESS,
            &bounded,
            &[],
        ),
        Ok(false),
    );
}

#[test]
fn rejects_a_loop_whose_nearest_initializer_can_be_bypassed() {
    let bypassed: Vec<u8> = [
        raw(0xb7, 2, 0, 0, 5),
        raw(0x05, 0, 0, 1, 0),
        raw(0xb7, 2, 0, 0, 0),
        raw(0xb7, 3, 0, 0, 0),
        raw(0x07, 2, 0, 0, 1),
        raw(0x55, 2, 0, -2, 4),
        raw(0xb7, 0, 0, 0, 1),
        raw(0x95, 0, 0, 0, 0),
    ].into_iter().flatten().collect();
    assert_eq!(
        verify_cgroup_network(
            uapi::prog_type::CGROUP_SKB,
            uapi::attach_type::CGROUP_INET_INGRESS,
            &bypassed,
            &[],
        ),
        Err(VerifyError::UnsupportedOpcode),
    );
}

#[test]
fn rejects_unreachable_network_instructions() {
    let unreachable: Vec<u8> = [
        raw(0x05, 0, 0, 1, 0),
        raw(0xb7, 0, 0, 0, 0),
        raw(0xb7, 0, 0, 0, 1),
        raw(0x95, 0, 0, 0, 0),
    ].into_iter().flatten().collect();
    assert_eq!(
        verify_cgroup_network(
            uapi::prog_type::CGROUP_SKB,
            uapi::attach_type::CGROUP_INET_INGRESS,
            &unreachable,
            &[],
        ),
        Err(VerifyError::UnreachableInsn),
    );
}

#[test]
fn infeasible_state_path_remains_structurally_reachable() {
    let program: Vec<u8> = [
        raw(0xb7, 0, 0, 0, 0),
        raw(0x15, 0, 0, 1, 0),
        raw(0xb7, 0, 0, 0, 1),
        raw(0x95, 0, 0, 0, 0),
    ].into_iter().flatten().collect();
    assert_eq!(verify_cgroup_network(
        uapi::prog_type::CGROUP_SKB,
        uapi::attach_type::CGROUP_INET_INGRESS,
        &program,
        &[],
    ), Ok(false));
}

#[test]
fn attach_types_enforce_linux_return_ranges() {
    let returns = |value| {
        [raw(0xb7, 0, 0, 0, value), raw(0x95, 0, 0, 0, 0)]
            .into_iter().flatten().collect::<Vec<u8>>()
    };
    assert_eq!(verify_cgroup_network(
        uapi::prog_type::CGROUP_SKB,
        uapi::attach_type::CGROUP_INET_INGRESS,
        &returns(2),
        &[],
    ), Err(VerifyError::UnsupportedOpcode));
    assert_eq!(verify_cgroup_network(
        uapi::prog_type::CGROUP_SKB,
        uapi::attach_type::CGROUP_INET_EGRESS,
        &returns(3),
        &[],
    ), Ok(true));
    assert_eq!(verify_cgroup_network(
        uapi::prog_type::CGROUP_SOCK_ADDR,
        uapi::attach_type::CGROUP_INET4_CONNECT,
        &returns(2),
        &[],
    ), Err(VerifyError::UnsupportedOpcode));
    assert_eq!(verify_cgroup_network(
        uapi::prog_type::CGROUP_SOCK_ADDR,
        uapi::attach_type::CGROUP_INET4_BIND,
        &returns(3),
        &[],
    ), Ok(false));
}

#[test]
fn egress_contract_survives_converging_return_states() {
    let program: Vec<u8> = [
        raw(0x61, 2, 1, 0, 0),
        raw(0x15, 2, 0, 2, 0),
        raw(0xb7, 0, 0, 0, 1),
        raw(0x05, 0, 0, 1, 0),
        raw(0xb7, 0, 0, 0, 2),
        raw(0xbf, 0, 0, 0, 0),
        raw(0x95, 0, 0, 0, 0),
    ].into_iter().flatten().collect();
    assert_eq!(verify_cgroup_network(
        uapi::prog_type::CGROUP_SKB,
        uapi::attach_type::CGROUP_INET_EGRESS,
        &program,
        &[],
    ), Ok(true));
}

#[test]
fn egress_contract_keeps_branch_correlation_until_exit() {
    let program: Vec<u8> = [
        raw(0x61, 2, 1, 0, 0),
        raw(0x15, 2, 0, 3, 0),
        raw(0xb7, 0, 0, 0, 1),
        raw(0xb7, 3, 0, 0, 1),
        raw(0x05, 0, 0, 2, 0),
        raw(0xb7, 0, 0, 0, 2),
        raw(0xb7, 3, 0, 0, 0),
        raw(0x15, 3, 0, 2, 1),
        raw(0xb7, 0, 0, 0, 1),
        raw(0x95, 0, 0, 0, 0),
        raw(0x95, 0, 0, 0, 0),
    ].into_iter().flatten().collect();
    assert_eq!(verify_cgroup_network(
        uapi::prog_type::CGROUP_SKB,
        uapi::attach_type::CGROUP_INET_EGRESS,
        &program,
        &[],
    ), Ok(false));
}

#[test]
fn set_retval_requires_the_linux_negative_errno_range() {
    let program = |value| {
        [
            raw(0xb7, 1, 0, 0, value),
            raw(0x85, 0, 0, 0, uapi::func_id::SET_RETVAL as i32),
            raw(0xb7, 0, 0, 0, 1),
            raw(0x95, 0, 0, 0, 0),
        ].into_iter().flatten().collect::<Vec<u8>>()
    };
    for value in [-4095, -1, 0] {
        assert_eq!(verify_cgroup_network(
            uapi::prog_type::CGROUP_SOCK_ADDR,
            uapi::attach_type::CGROUP_INET4_CONNECT,
            &program(value),
            &[],
        ), Ok(false));
    }
    for value in [-4096, 1] {
        assert_eq!(verify_cgroup_network(
            uapi::prog_type::CGROUP_SOCK_ADDR,
            uapi::attach_type::CGROUP_INET4_CONNECT,
            &program(value),
            &[],
        ), Err(VerifyError::UnsupportedOpcode));
    }
}

#[test]
fn program_map_permissions_deny_reads_and_writes_independently() {
    let read: Vec<u8> = [
        raw(0x18, 1, uapi::pseudo::MAP_VALUE, 0, 0),
        raw(0, 0, 0, 0, 0),
        raw(0x61, 0, 1, 0, 0),
        raw(0x95, 0, 0, 0, 0),
    ].into_iter().flatten().collect();
    let write: Vec<u8> = [
        raw(0x18, 1, uapi::pseudo::MAP_VALUE, 0, 0),
        raw(0, 0, 0, 0, 0),
        raw(0x62, 1, 0, 0, 7),
        raw(0xb7, 0, 0, 0, 1),
        raw(0x95, 0, 0, 0, 0),
    ].into_iter().flatten().collect();
    let atomic: Vec<u8> = [
        raw(0x18, 1, uapi::pseudo::MAP_VALUE, 0, 0),
        raw(0, 0, 0, 0, 0),
        raw(0xb7, 2, 0, 0, 1),
        raw(0xdb, 1, 2, 0, 0),
        raw(0xb7, 0, 0, 0, 1),
        raw(0x95, 0, 0, 0, 0),
    ].into_iter().flatten().collect();
    assert_eq!(verify_cgroup_network(
        uapi::prog_type::CGROUP_SKB,
        uapi::attach_type::CGROUP_INET_INGRESS,
        &read,
        &[array(4, 1, uapi::map_flags::WRONLY_PROG)],
    ), Err(VerifyError::UnsafeContextAccess));
    assert_eq!(verify_cgroup_network(
        uapi::prog_type::CGROUP_SKB,
        uapi::attach_type::CGROUP_INET_INGRESS,
        &write,
        &[array(4, 1, uapi::map_flags::RDONLY_PROG)],
    ), Err(VerifyError::UnsafeContextAccess));
    for flags in [uapi::map_flags::RDONLY_PROG, uapi::map_flags::WRONLY_PROG] {
        assert_eq!(verify_cgroup_network(
            uapi::prog_type::CGROUP_SKB,
            uapi::attach_type::CGROUP_INET_INGRESS,
            &atomic,
            &[array(8, 1, flags)],
        ), Err(VerifyError::UnsafeContextAccess));
    }
}

#[test]
fn sockaddr_context_access_is_aligned_and_field_contained() {
    let verify = |attach, insns: &[[u8; 8]]| verify_cgroup_network(
        uapi::prog_type::CGROUP_SOCK_ADDR,
        attach,
        &insns.iter().flatten().copied().collect::<Vec<u8>>(),
        &[],
    );
    let invalid_read = [
        raw(0x79, 2, 1, 20, 0),
        raw(0xb7, 0, 0, 0, 1),
        raw(0x95, 0, 0, 0, 0),
    ];
    assert_eq!(
        verify(uapi::attach_type::CGROUP_INET6_CONNECT, &invalid_read),
        Err(VerifyError::UnsafeContextAccess),
    );
    let invalid_write = [
        raw(0x7a, 1, 0, 20, 0),
        raw(0xb7, 0, 0, 0, 1),
        raw(0x95, 0, 0, 0, 0),
    ];
    assert_eq!(
        verify(uapi::attach_type::CGROUP_INET6_CONNECT, &invalid_write),
        Err(VerifyError::UnsafeContextAccess),
    );
    let misaligned = [
        raw(0x69, 2, 1, 5, 0),
        raw(0xb7, 0, 0, 0, 1),
        raw(0x95, 0, 0, 0, 0),
    ];
    assert_eq!(
        verify(uapi::attach_type::CGROUP_INET4_CONNECT, &misaligned),
        Err(VerifyError::UnsafeContextAccess),
    );
    let valid = [
        raw(0x79, 2, 1, 16, 0),
        raw(0x7a, 1, 0, 16, 0),
        raw(0xb7, 0, 0, 0, 1),
        raw(0x95, 0, 0, 0, 0),
    ];
    assert_eq!(verify(uapi::attach_type::CGROUP_INET6_CONNECT, &valid), Ok(false));
}

#[test]
fn large_straight_line_program_uses_bounded_fallible_state() {
    let mut insns = Vec::new();
    for _ in 0..32_768 {
        insns.extend_from_slice(&raw(0xb7, 0, 0, 0, 1));
    }
    insns.extend_from_slice(&raw(0x95, 0, 0, 0, 0));
    assert_eq!(verify_cgroup_network(
        uapi::prog_type::CGROUP_SKB,
        uapi::attach_type::CGROUP_INET_INGRESS,
        &insns,
        &[],
    ), Ok(false));
}
