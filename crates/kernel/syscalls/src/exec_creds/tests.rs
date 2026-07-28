// Every branch of the execve credential transition. Ungated so these actually
// run — `cargo test -p syscalls exec_creds` must report a NON-ZERO pass count.

use super::*;

const CAP_SETUID: u64 = 1 << 7;
const CAP_NET_BIND: u64 = 1 << 10;
const CAP_SYS_ADMIN: u64 = 1 << 21;
const CAP_ALL: u64 = sched::Creds::CAP_FULL;

/// A plain unprivileged caller: uid 1000, full bounding set, nothing else.
fn user_creds() -> TaskCreds {
    TaskCreds {
        ruid: 1000, euid: 1000, suid: 1000, fsuid: 1000,
        rgid: 1000, egid: 1000, sgid: 1000, fsgid: 1000,
        cap_permitted: 0, cap_effective: 0, cap_inheritable: 0,
        cap_ambient: 0, cap_bounding: CAP_ALL, securebits: 0,
    }
}

fn root_creds() -> TaskCreds {
    TaskCreds {
        ruid: 0, euid: 0, suid: 0, fsuid: 0,
        rgid: 0, egid: 0, sgid: 0, fsgid: 0,
        cap_permitted: CAP_ALL, cap_effective: CAP_ALL, cap_inheritable: 0,
        cap_ambient: 0, cap_bounding: CAP_ALL, securebits: 0,
    }
}

/// Mode 0755, root-owned, on a normal mount, readable and executable.
fn ctx(old: TaskCreds) -> ExecContext<'static> {
    ExecContext {
        old,
        file_mode: 0o755, file_uid: 0, file_gid: 0,
        mnt_may_suid: true, file_uid_mapped: true, file_gid_mapped: true,
        may_exec: true,
        file_caps: FileCaps::default(), file_caps_rootid_is_root: true,
        no_new_privs: false, fs_shared: false, ptracer_capable: true,
        can_setuid: false, root_uid: 0, groups: &[],
        not_readable: false, suid_dumpable: sched::SUID_DUMP_DISABLE,
    }
}

fn setuid_root(old: TaskCreds) -> ExecContext<'static> {
    ExecContext { file_mode: 0o4755, file_uid: 0, ..ctx(old) }
}

// --------------------------------------------------------------- plain exec

#[test]
fn plain_exec_by_an_unprivileged_user_changes_no_id_and_is_not_secure() {
    let t = transition(&ctx(user_creds())).unwrap();
    assert_eq!(t.new.euid, 1000);
    assert_eq!(t.new.egid, 1000);
    assert_eq!(t.new.suid, 1000);
    assert_eq!(t.new.fsuid, 1000);
    assert_eq!(t.new.cap_permitted, 0);
    assert_eq!(t.new.cap_effective, 0);
    assert!(!t.secure_exec, "AT_SECURE must be 0 for an ordinary exec");
    assert_eq!(t.per_clear, 0);
    assert_eq!(t.dumpable, sched::SUID_DUMP_USER);
}

#[test]
fn plain_exec_by_root_regains_the_bounding_set_as_permitted_and_effective() {
    // systemd's executor lowers its effective set before execve and relies on
    // the kernel restoring it (`handle_privileged_root`).
    let mut old = root_creds();
    old.cap_effective = 0;
    old.cap_permitted = CAP_ALL;
    let t = transition(&ctx(old)).unwrap();
    assert_eq!(t.new.cap_permitted, CAP_ALL);
    assert_eq!(t.new.cap_effective, CAP_ALL);
    assert!(!t.secure_exec, "root exec'ing a plain binary is not a secure exec");
    assert_eq!(t.dumpable, sched::SUID_DUMP_USER);
}

#[test]
fn secure_noroot_denies_root_the_privileged_root_path() {
    let mut old = root_creds();
    old.securebits = sched::securebits::SECBIT_NOROOT;
    old.cap_permitted = CAP_ALL;
    let t = transition(&ctx(old)).unwrap();
    assert_eq!(t.new.cap_permitted, 0, "SECBIT_NOROOT: uid 0 is not special");
    assert_eq!(t.new.cap_effective, 0);
}

// ------------------------------------------------------------------- setuid

#[test]
fn setuid_root_binary_raises_euid_and_grants_full_caps() {
    let t = transition(&setuid_root(user_creds())).unwrap();
    assert_eq!(t.new.euid, 0, "S_ISUID must raise euid to the file owner");
    assert_eq!(t.new.ruid, 1000, "real uid is untouched by setuid exec");
    assert_eq!(t.new.suid, 0, "saved uid follows the effective uid");
    assert_eq!(t.new.fsuid, 0);
    assert_eq!(t.new.cap_permitted, CAP_ALL);
    assert_eq!(t.new.cap_effective, CAP_ALL);
    assert!(t.secure_exec, "AT_SECURE must be 1 for a setuid exec");
    assert_ne!(t.per_clear & sched::personality::PER_CLEAR_ON_SETID, 0);
    assert_eq!(t.dumpable, sched::SUID_DUMP_DISABLE,
        "a setuid process is not dumpable by its unprivileged owner");
}

#[test]
fn setuid_is_suppressed_on_a_nosuid_mount() {
    let cx = ExecContext { mnt_may_suid: false, ..setuid_root(user_creds()) };
    let t = transition(&cx).unwrap();
    assert_eq!(t.new.euid, 1000, "mount -o nosuid must not be decorative");
    assert_eq!(t.new.cap_permitted, 0);
    assert_eq!(t.new.cap_effective, 0);
    assert!(!t.secure_exec);
    assert_eq!(t.per_clear, 0);
}

#[test]
fn setuid_is_suppressed_under_no_new_privs() {
    let cx = ExecContext { no_new_privs: true, ..setuid_root(user_creds()) };
    let t = transition(&cx).unwrap();
    assert_eq!(t.new.euid, 1000, "PR_SET_NO_NEW_PRIVS must block the setuid bit");
    assert_eq!(t.new.cap_permitted, 0);
    assert!(!t.secure_exec);
}

#[test]
fn setuid_is_suppressed_when_the_file_owner_has_no_mapping_in_the_user_ns() {
    let cx = ExecContext { file_uid_mapped: false, ..setuid_root(user_creds()) };
    assert_eq!(transition(&cx).unwrap().new.euid, 1000);
    let cx = ExecContext { file_gid_mapped: false, ..setuid_root(user_creds()) };
    assert_eq!(transition(&cx).unwrap().new.euid, 1000);
}

#[test]
fn setuid_is_suppressed_when_the_exec_bit_vanished_under_the_lock() {
    let cx = ExecContext { may_exec: false, ..setuid_root(user_creds()) };
    assert_eq!(transition(&cx).unwrap().new.euid, 1000);
}

#[test]
fn setuid_to_a_non_root_owner_grants_no_capabilities() {
    let cx = ExecContext { file_mode: 0o4755, file_uid: 42, ..ctx(user_creds()) };
    let t = transition(&cx).unwrap();
    assert_eq!(t.new.euid, 42);
    assert_eq!(t.new.cap_permitted, 0, "only uid 0 takes the privileged-root path");
    assert!(t.secure_exec);
}

#[test]
fn setuid_exec_under_a_shared_fs_struct_is_downgraded_to_the_real_uid() {
    // LSM_UNSAFE_SHARE: a sibling thread could rewrite cwd/root under the
    // setuid image, so the id transition is refused.
    let cx = ExecContext { fs_shared: true, ..setuid_root(user_creds()) };
    let t = transition(&cx).unwrap();
    assert_eq!(t.new.euid, 1000);
    assert_eq!(t.new.cap_permitted, 0, "permitted is intersected with the old set");
}

#[test]
fn setuid_exec_traced_by_an_incapable_tracer_is_downgraded() {
    let cx = ExecContext { ptracer_capable: false, ..setuid_root(user_creds()) };
    assert_eq!(transition(&cx).unwrap().new.euid, 1000);
}

#[test]
fn setuid_exec_traced_by_a_capable_tracer_still_transitions() {
    // `bprm->unsafe & ~LSM_UNSAFE_PTRACE` is zero and ptracer_capable is true.
    let t = transition(&setuid_root(user_creds())).unwrap();
    assert_eq!(t.new.euid, 0);
}

#[test]
fn a_caller_with_cap_setuid_keeps_the_transition_when_only_ptrace_is_unsafe() {
    let mut old = user_creds();
    old.cap_effective = CAP_SETUID;
    old.cap_permitted = CAP_SETUID;
    let cx = ExecContext { ptracer_capable: false, can_setuid: true, ..setuid_root(old) };
    let t = transition(&cx).unwrap();
    assert_eq!(t.new.euid, 0, "CAP_SETUID keeps the id change, caps are still clamped");
    assert_eq!(t.new.cap_permitted, CAP_SETUID, "permitted &= old permitted");
}

// ------------------------------------------------------------------- setgid

#[test]
fn setgid_binary_with_the_group_exec_bit_raises_egid() {
    let cx = ExecContext { file_mode: 0o2755, file_gid: 50, ..ctx(user_creds()) };
    let t = transition(&cx).unwrap();
    assert_eq!(t.new.egid, 50);
    assert_eq!(t.new.sgid, 50, "saved gid follows the effective gid");
    assert_eq!(t.new.fsgid, 50);
    assert_eq!(t.new.euid, 1000, "S_ISGID alone leaves the uid alone");
    assert!(t.secure_exec);
    assert_ne!(t.per_clear & sched::personality::PER_CLEAR_ON_SETID, 0);
}

#[test]
fn s_isgid_without_the_group_exec_bit_is_mandatory_locking_not_setgid() {
    // mode 2745: S_ISGID set, S_IXGRP clear.
    let cx = ExecContext { file_mode: 0o2745, file_gid: 50, ..ctx(user_creds()) };
    let t = transition(&cx).unwrap();
    assert_eq!(t.new.egid, 1000);
    assert!(!t.secure_exec);
    assert_eq!(t.per_clear, 0);
}

#[test]
fn setgid_is_suppressed_on_a_nosuid_mount_and_under_no_new_privs() {
    let base = ExecContext { file_mode: 0o2755, file_gid: 50, ..ctx(user_creds()) };
    let nosuid = ExecContext { mnt_may_suid: false, ..ExecContext { file_mode: 0o2755, file_gid: 50, ..ctx(user_creds()) } };
    assert_eq!(transition(&nosuid).unwrap().new.egid, 1000);
    let nnp = ExecContext { no_new_privs: true, ..base };
    assert_eq!(transition(&nnp).unwrap().new.egid, 1000);
}

#[test]
fn setgid_to_a_group_the_caller_already_holds_is_not_an_id_change() {
    // `id_changed = euid != old euid || !in_group_p(new egid)`, and
    // in_group_p searches the caller's supplementary list — so acquiring a
    // group it already holds is NOT an id change and does not cancel ambient.
    // AT_SECURE is still 1, because that clause tests `egid != old->gid`
    // independently of `id_changed`.
    static GROUPS: [u32; 2] = [50, 60];
    let mut old = user_creds();
    old.cap_ambient = CAP_NET_BIND;
    old.cap_permitted = CAP_NET_BIND;
    old.cap_inheritable = CAP_NET_BIND;
    let cx = ExecContext { file_mode: 0o2755, file_gid: 50, groups: &GROUPS, ..ctx(old) };
    let t = transition(&cx).unwrap();
    assert_eq!(t.new.egid, 50);
    assert_eq!(t.new.cap_ambient, CAP_NET_BIND, "no id change, so ambient survives");
    assert!(t.secure_exec, "egid still differs from the real gid");
}

// ---------------------------------------------------------------- file caps

fn fcaps(permitted: u64, effective: bool) -> FileCaps {
    FileCaps { present: true, permitted, inheritable: 0, effective, rootid: 0 }
}

#[test]
fn file_caps_grant_permitted_and_effective_when_the_effective_bit_is_set() {
    let cx = ExecContext { file_caps: fcaps(CAP_NET_BIND, true), ..ctx(user_creds()) };
    let t = transition(&cx).unwrap();
    assert_eq!(t.new.cap_permitted, CAP_NET_BIND);
    assert_eq!(t.new.cap_effective, CAP_NET_BIND);
    assert!(t.secure_exec, "a non-root process that gained caps is a secure exec");
    assert_ne!(t.per_clear & sched::personality::PER_CLEAR_ON_SETID, 0);
}

#[test]
fn file_caps_without_the_effective_bit_leave_the_effective_set_empty() {
    let cx = ExecContext { file_caps: fcaps(CAP_NET_BIND, false), ..ctx(user_creds()) };
    let t = transition(&cx).unwrap();
    assert_eq!(t.new.cap_permitted, CAP_NET_BIND);
    assert_eq!(t.new.cap_effective, 0, "pE' = pA' when fE is clear");
    assert!(t.secure_exec);
}

#[test]
fn file_caps_are_dropped_on_a_nosuid_mount() {
    let cx = ExecContext { mnt_may_suid: false, file_caps: fcaps(CAP_NET_BIND, true), ..ctx(user_creds()) };
    let t = transition(&cx).unwrap();
    assert_eq!(t.new.cap_permitted, 0);
    assert_eq!(t.new.cap_effective, 0);
}

#[test]
fn file_caps_are_dropped_when_the_rev3_rootid_is_not_ns_root() {
    let cx = ExecContext {
        file_caps: fcaps(CAP_NET_BIND, true), file_caps_rootid_is_root: false,
        ..ctx(user_creds())
    };
    assert_eq!(transition(&cx).unwrap().new.cap_permitted, 0);
}

#[test]
fn file_caps_are_clamped_by_the_bounding_set() {
    let mut old = user_creds();
    old.cap_bounding = CAP_NET_BIND;
    let cx = ExecContext { file_caps: fcaps(CAP_NET_BIND | CAP_SYS_ADMIN, false), ..ctx(old) };
    let t = transition(&cx).unwrap();
    assert_eq!(t.new.cap_permitted, CAP_NET_BIND, "pP' = (X & fP) | (pI & fI)");
}

#[test]
fn an_effective_file_cap_that_the_bounding_set_forbids_fails_the_exec() {
    let mut old = user_creds();
    old.cap_bounding = CAP_NET_BIND;
    let cx = ExecContext { file_caps: fcaps(CAP_NET_BIND | CAP_SYS_ADMIN, true), ..ctx(old) };
    assert_eq!(transition(&cx), Err(Errno::Eperm),
        "a legacy binary that cannot notice missing caps must not run");
}

#[test]
fn inheritable_file_caps_intersect_the_task_inheritable_set() {
    let mut old = user_creds();
    old.cap_inheritable = CAP_NET_BIND | CAP_SYS_ADMIN;
    let cx = ExecContext {
        file_caps: FileCaps { present: true, permitted: 0, inheritable: CAP_NET_BIND, effective: true, rootid: 0 },
        ..ctx(old)
    };
    assert_eq!(transition(&cx).unwrap().new.cap_permitted, CAP_NET_BIND);
}

#[test]
fn file_caps_on_a_setuid_root_binary_are_honoured_and_root_gets_no_extra() {
    // `handle_privileged_root` bails on the has_fcap + suid-root combination.
    let cx = ExecContext { file_caps: fcaps(CAP_NET_BIND, true), ..setuid_root(user_creds()) };
    let t = transition(&cx).unwrap();
    assert_eq!(t.new.euid, 0);
    assert_eq!(t.new.cap_permitted, CAP_NET_BIND,
        "setuid-root + file caps grants only the file caps, not the whole set");
    assert!(t.secure_exec);
}

#[test]
fn no_new_privs_clamps_file_caps_to_what_the_caller_already_had() {
    let mut old = user_creds();
    old.cap_permitted = CAP_NET_BIND;
    let cx = ExecContext {
        no_new_privs: true,
        file_caps: fcaps(CAP_NET_BIND | CAP_SYS_ADMIN, true),
        ..ctx(old)
    };
    let t = transition(&cx).unwrap();
    assert_eq!(t.new.cap_permitted, CAP_NET_BIND,
        "no_new_privs: exec may never yield MORE permitted caps than it went in with");
    assert_eq!(t.new.cap_effective, CAP_NET_BIND);
}

// ------------------------------------------------------------------ ambient

#[test]
fn ambient_caps_survive_a_plain_unprivileged_exec() {
    let mut old = user_creds();
    old.cap_ambient = CAP_NET_BIND;
    old.cap_permitted = CAP_NET_BIND;
    old.cap_inheritable = CAP_NET_BIND;
    let t = transition(&ctx(old)).unwrap();
    assert_eq!(t.new.cap_ambient, CAP_NET_BIND, "ambient exists to cross plain execs");
    assert_eq!(t.new.cap_permitted, CAP_NET_BIND, "pP' |= pA'");
    assert_eq!(t.new.cap_effective, CAP_NET_BIND, "pE' = pA' when fE is clear");
    // NOT a secure exec: `__cap_grew(permitted, ambient, new)` is
    // `permitted & ~ambient`, which is empty when the only permitted caps came
    // from the ambient set. Ambient exists precisely so privilege can cross an
    // ordinary exec without tripping AT_SECURE and losing LD_LIBRARY_PATH.
    assert!(!t.secure_exec);
}

#[test]
fn ambient_caps_are_cleared_on_a_setuid_exec() {
    let mut old = user_creds();
    old.cap_ambient = CAP_NET_BIND;
    old.cap_permitted = CAP_NET_BIND;
    old.cap_inheritable = CAP_NET_BIND;
    let t = transition(&setuid_root(old)).unwrap();
    assert_eq!(t.new.cap_ambient, 0, "a setid transition cancels the ambient set");
    assert_eq!(t.new.euid, 0);
}

#[test]
fn ambient_caps_are_cleared_when_the_file_carries_capabilities() {
    let mut old = user_creds();
    old.cap_ambient = CAP_NET_BIND;
    old.cap_permitted = CAP_NET_BIND;
    old.cap_inheritable = CAP_NET_BIND;
    let cx = ExecContext { file_caps: fcaps(CAP_SYS_ADMIN, false), ..ctx(old) };
    let t = transition(&cx).unwrap();
    assert_eq!(t.new.cap_ambient, 0, "file caps cancel the ambient set");
    assert_eq!(t.new.cap_permitted, CAP_SYS_ADMIN);
}

#[test]
fn ambient_caps_are_cleared_on_a_setgid_exec_to_a_foreign_group() {
    let mut old = user_creds();
    old.cap_ambient = CAP_NET_BIND;
    old.cap_permitted = CAP_NET_BIND;
    old.cap_inheritable = CAP_NET_BIND;
    let cx = ExecContext { file_mode: 0o2755, file_gid: 50, ..ctx(old) };
    assert_eq!(transition(&cx).unwrap().new.cap_ambient, 0);
}

// --------------------------------------------------------------- securebits

#[test]
fn keep_caps_is_cleared_by_exec_but_its_lock_survives() {
    let mut old = user_creds();
    old.securebits = sched::securebits::SECBIT_KEEP_CAPS
        | sched::securebits::SECBIT_KEEP_CAPS_LOCKED;
    let t = transition(&ctx(old)).unwrap();
    assert_eq!(t.new.securebits & sched::securebits::SECBIT_KEEP_CAPS, 0);
    assert_ne!(t.new.securebits & sched::securebits::SECBIT_KEEP_CAPS_LOCKED, 0);
}

// -------------------------------------------------------------- dumpability

#[test]
fn an_unreadable_binary_forces_the_suid_dumpable_policy() {
    let cx = ExecContext { not_readable: true, suid_dumpable: sched::SUID_DUMP_DISABLE, ..ctx(user_creds()) };
    assert_eq!(transition(&cx).unwrap().dumpable, sched::SUID_DUMP_DISABLE);
    let cx = ExecContext { not_readable: true, suid_dumpable: sched::SUID_DUMP_ROOT, ..ctx(user_creds()) };
    assert_eq!(transition(&cx).unwrap().dumpable, sched::SUID_DUMP_ROOT);
}

#[test]
fn a_suppressed_setuid_exec_stays_owner_dumpable() {
    let cx = ExecContext { mnt_may_suid: false, ..setuid_root(user_creds()) };
    assert_eq!(transition(&cx).unwrap().dumpable, sched::SUID_DUMP_USER);
}

// -------------------------------------------------------------- AT_SECURE

#[test]
fn at_secure_is_set_exactly_when_an_id_or_capability_actually_changed() {
    // The table glibc's __libc_enable_secure depends on.
    let cases: [(&str, ExecContext<'static>, bool); 6] = [
        ("plain user exec",        ctx(user_creds()),                                   false),
        ("plain root exec",        ctx(root_creds()),                                   false),
        ("setuid root",            setuid_root(user_creds()),                           true),
        ("setuid suppressed",      ExecContext { mnt_may_suid: false, ..setuid_root(user_creds()) }, false),
        ("file caps",              ExecContext { file_caps: fcaps(CAP_NET_BIND, true), ..ctx(user_creds()) }, true),
        ("setgid foreign group",   ExecContext { file_mode: 0o2755, file_gid: 50, ..ctx(user_creds()) }, true),
    ];
    for (name, cx, want) in cases {
        assert_eq!(transition(&cx).unwrap().secure_exec, want, "AT_SECURE for {}", name);
    }
}

#[test]
fn root_exec_after_dropping_to_a_user_shell_is_secure() {
    // euid 0, ruid 1000 (a setuid-root process re-exec'ing): new euid (0)
    // differs from old ruid (1000), so AT_SECURE stays 1.
    let mut old = user_creds();
    old.euid = 0; old.suid = 0; old.fsuid = 0;
    old.cap_permitted = CAP_ALL; old.cap_effective = CAP_ALL;
    let t = transition(&ctx(old)).unwrap();
    assert!(t.secure_exec);
}

// ------------------------------------------------------ xattr decode

#[test]
fn decode_reads_the_interleaved_vfs_cap_data_layout() {
    // struct vfs_cap_data { __le32 magic_etc; struct { __le32 permitted,
    // inheritable; } data[2]; } — the two halves of `permitted` are NOT
    // adjacent. Reading them as adjacent words mixes inheritable into
    // permitted's high half and silently mis-grants every cap above bit 31.
    let mut buf = [0u8; 20];
    buf[0..4].copy_from_slice(&(0x0200_0000u32 | VFS_CAP_FLAGS_EFFECTIVE).to_le_bytes());
    buf[4..8].copy_from_slice(&0x0000_0080u32.to_le_bytes());   // data[0].permitted   -> CAP_SETUID
    buf[8..12].copy_from_slice(&0x0000_0400u32.to_le_bytes());  // data[0].inheritable -> CAP_NET_BIND
    buf[12..16].copy_from_slice(&0x0000_0100u32.to_le_bytes()); // data[1].permitted   -> bit 40
    buf[16..20].copy_from_slice(&0u32.to_le_bytes());           // data[1].inheritable
    let fc = decode_file_caps(&buf).expect("valid revision 2 xattr");
    assert!(fc.present);
    assert!(fc.effective);
    assert_eq!(fc.permitted, CAP_SETUID | (1u64 << 40));
    assert_eq!(fc.inheritable, CAP_NET_BIND);
}

#[test]
fn decode_keeps_the_revision_3_rootid_and_rejects_wrong_lengths() {
    let mut buf = [0u8; 24];
    buf[0..4].copy_from_slice(&0x0300_0000u32.to_le_bytes());
    buf[20..24].copy_from_slice(&1000u32.to_le_bytes());
    assert_eq!(decode_file_caps(&buf).expect("valid revision 3").rootid, 1000);
    // Revision 3 magic with a revision-2 length is malformed.
    assert_eq!(decode_file_caps(&buf[..20]), None);
    assert_eq!(decode_file_caps(&[]), None);
    // Unknown revision.
    let mut bad = [0u8; 20];
    bad[0..4].copy_from_slice(&0x0900_0000u32.to_le_bytes());
    assert_eq!(decode_file_caps(&bad), None);
}

#[test]
fn decode_masks_bits_above_the_last_defined_capability() {
    let mut buf = [0u8; 20];
    buf[0..4].copy_from_slice(&0x0200_0000u32.to_le_bytes());
    buf[12..16].copy_from_slice(&u32::MAX.to_le_bytes());  // data[1].permitted
    let fc = decode_file_caps(&buf).unwrap();
    assert_eq!(fc.permitted & !CAP_ALL, 0, "undefined capability bits must not leak in");
}
