use super::*;
use alloc::string::String;

/// A deliberately NON-root, NON-privileged task: every field that the old
/// renderer hardcoded (uid/gid quads, the capability bitmaps, NoNewPrivs) is
/// set to something a fabricated constant could not produce.
fn unprivileged() -> Status<'static> {
    Status {
        name: "gdbus", umask: 0o22, state: "S (sleeping)",
        tgid: 812, ngid: 0, pid: 815, ppid: 1, tracer_pid: 0,
        uid: [1000, 1000, 1000, 1000],
        gid: [1000, 1000, 1000, 1000],
        fd_size: 64,
        groups: &[10, 1000],
        ns_tgid: 812, ns_pid: 815, ns_pgid: 812, ns_sid: 812,
        kthread: false, threads: 3,
        sig_queued: 0, sig_limit: 63_000,
        sig_pnd: 0, shd_pnd: 0, sig_blk: 0x1000, sig_ign: 0x1000, sig_cgt: 0x0000_0001_0000_4002,
        cap_inh: 0, cap_prm: 0, cap_eff: 0, cap_bnd: 0x0000_01ff_ffff_ffff, cap_amb: 0,
        no_new_privs: true, seccomp: 2, seccomp_filters: 1,
        cpus_allowed: 0xf, nr_cpus: 4,
        mems_allowed: 1, nr_nodes: 1,
        nvcsw: 41, nivcsw: 7,
        mem_rows: b"",
    }
}

fn field<'a>(body: &'a str, key: &str) -> &'a str {
    body.lines()
        .find(|l| l.starts_with(key) && l.as_bytes().get(key.len()) == Some(&b':'))
        .map(|l| &l[key.len() + 2..])
        .unwrap_or_else(|| panic!("no {key} line in:\n{body}"))
}

fn body_of(s: &Status) -> String {
    String::from_utf8(render(s)).expect("status body is ASCII")
}

#[test]
fn an_unprivileged_task_is_not_reported_as_root_with_full_capabilities() {
    // The pre-fix renderer emitted `Uid:\t0\t0\t0\t0`, `Gid:` the same, and
    // CapPrm/CapEff/CapBnd = 000001ffffffffff for EVERY task. polkit, systemd
    // and dbus-daemon decide what a peer may do from exactly these lines.
    let b = body_of(&unprivileged());
    assert_eq!(field(&b, "Uid"), "1000\t1000\t1000\t1000");
    assert_eq!(field(&b, "Gid"), "1000\t1000\t1000\t1000");
    assert_eq!(field(&b, "CapPrm"), "0000000000000000");
    assert_eq!(field(&b, "CapEff"), "0000000000000000");
    assert_eq!(field(&b, "CapInh"), "0000000000000000");
    assert_eq!(field(&b, "CapAmb"), "0000000000000000");
    assert_eq!(field(&b, "CapBnd"), "000001ffffffffff", "bounding set is the one still full");
    assert_eq!(field(&b, "NoNewPrivs"), "1");
}

#[test]
fn a_privileged_task_still_renders_its_real_root_credentials() {
    let mut s = unprivileged();
    s.uid = [0, 0, 0, 0];
    s.gid = [0, 0, 0, 0];
    s.cap_prm = 0x0000_01ff_ffff_ffff;
    s.cap_eff = 0x0000_01ff_ffff_ffff;
    s.no_new_privs = false;
    let b = body_of(&s);
    assert_eq!(field(&b, "Uid"), "0\t0\t0\t0");
    assert_eq!(field(&b, "CapEff"), "000001ffffffffff");
    assert_eq!(field(&b, "NoNewPrivs"), "0");
}

#[test]
fn a_setuid_task_reports_all_four_distinct_ids() {
    // real 1000, effective 0, saved 0, fs 0 — the shape a setuid-root binary
    // has. A single-id renderer cannot express it.
    let mut s = unprivileged();
    s.uid = [1000, 0, 0, 0];
    s.gid = [1000, 100, 100, 100];
    let b = body_of(&s);
    assert_eq!(field(&b, "Uid"), "1000\t0\t0\t0");
    assert_eq!(field(&b, "Gid"), "1000\t100\t100\t100");
}

#[test]
fn supplementary_groups_are_space_separated_with_linuxs_trailing_space() {
    let b = body_of(&unprivileged());
    assert_eq!(field(&b, "Groups"), "10 1000 ", "Linux appends one trailing space");
    let mut s = unprivileged();
    s.groups = &[];
    assert_eq!(field(&body_of(&s), "Groups"), " ", "no groups: still the trailing space");
}

#[test]
fn signal_sets_are_sixteen_hex_digits() {
    let b = body_of(&unprivileged());
    assert_eq!(field(&b, "SigBlk"), "0000000000001000");
    assert_eq!(field(&b, "SigIgn"), "0000000000001000");
    assert_eq!(field(&b, "SigCgt"), "0000000100004002");
    assert_eq!(field(&b, "SigPnd"), "0000000000000000");
    assert_eq!(field(&b, "SigQ"), "0/63000");
}

#[test]
fn seccomp_and_thread_count_are_the_tasks_own() {
    let b = body_of(&unprivileged());
    assert_eq!(field(&b, "Seccomp"), "2");
    assert_eq!(field(&b, "Seccomp_filters"), "1");
    assert_eq!(field(&b, "Threads"), "3");
    assert_eq!(field(&b, "FDSize"), "64");
    assert_eq!(field(&b, "TracerPid"), "0");
    assert_eq!(field(&b, "Kthread"), "0");
    assert_eq!(field(&b, "voluntary_ctxt_switches"), "41");
    assert_eq!(field(&b, "nonvoluntary_ctxt_switches"), "7");
}

#[test]
fn a_traced_kernel_thread_reports_its_tracer_and_kthread_flag() {
    let mut s = unprivileged();
    s.kthread = true;
    s.tracer_pid = 900;
    let b = body_of(&s);
    assert_eq!(field(&b, "Kthread"), "1");
    assert_eq!(field(&b, "TracerPid"), "900");
}

// Linux `%*pb`: 32-bit chunks, most-significant first, comma-separated; only
// the top chunk is narrowed to the bit count. Verified against a live
// `/proc/self/status` on a 48-CPU host: `Cpus_allowed: ffff,ffffffff`.
#[test]
fn cpu_mask_matches_linuxs_bitmap_chunking() {
    let mut s = unprivileged();
    s.cpus_allowed = 0x0000_ffff_ffff_ffff; s.nr_cpus = 48;
    let b = body_of(&s);
    assert_eq!(field(&b, "Cpus_allowed"), "ffff,ffffffff");
    assert_eq!(field(&b, "Cpus_allowed_list"), "0-47");

    s.cpus_allowed = 1; s.nr_cpus = 1;
    assert_eq!(field(&body_of(&s), "Cpus_allowed"), "1", "a 1-CPU mask is one digit, not 8");

    s.cpus_allowed = 0b1101; s.nr_cpus = 4;
    let b = body_of(&s);
    assert_eq!(field(&b, "Cpus_allowed"), "d");
    assert_eq!(field(&b, "Cpus_allowed_list"), "0,2-3");

    s.cpus_allowed = 0; s.nr_cpus = 4;
    assert_eq!(field(&body_of(&s), "Cpus_allowed_list"), "", "empty mask lists nothing");
}

#[test]
fn field_order_matches_linux_proc_pid_status() {
    let b = body_of(&unprivileged());
    let keys: alloc::vec::Vec<&str> = b.lines().filter_map(|l| l.split(':').next()).collect();
    assert_eq!(keys, [
        "Name", "Umask", "State", "Tgid", "Ngid", "Pid", "PPid", "TracerPid",
        "Uid", "Gid", "FDSize", "Groups", "NStgid", "NSpid", "NSpgid", "NSsid",
        "Kthread", "Threads", "SigQ", "SigPnd", "ShdPnd", "SigBlk", "SigIgn",
        "SigCgt", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb",
        "NoNewPrivs", "Seccomp", "Seccomp_filters",
        "Speculation_Store_Bypass", "SpeculationIndirectBranch",
        "Cpus_allowed", "Cpus_allowed_list", "Mems_allowed", "Mems_allowed_list",
        "voluntary_ctxt_switches", "nonvoluntary_ctxt_switches",
    ]);
    assert_eq!(field(&b, "Umask"), "0022", "4-digit octal, as Linux %#04o renders it");
}
