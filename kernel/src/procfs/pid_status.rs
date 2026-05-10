// F158: /proc/<pid>/status body builder. Extracted from procfs.rs to
// keep that file under the 1000-line cap. Linux-conformant field
// set: identity (Name/Umask/State/Tgid/Pid/PPid/etc.), capability
// bitmaps, signal masks, namespaces (NStgid/NSpid/NSpgid/NSsid),
// CPU/memory affinity, ctxt-switch counts, speculation status.


use alloc::vec::Vec;

/// # C: O(1) — fixed field set.
pub fn body(tid: u32) -> Vec<u8> {
    use core::sync::atomic::Ordering;
    let mut out = Vec::with_capacity(1024);
    let task = match sched::live::registry::lookup(tid) { Some(t) => t, None => return out };
    let ppid = task.parent_tid.load(Ordering::Acquire) as u64;
    let umask = task.umask.load(Ordering::Acquire) as u64;
    let pgid = task.pgid.load(Ordering::Acquire) as u64;
    let sid  = task.sid.load(Ordering::Acquire) as u64;
    push(&mut out, b"Name:\t"); push(&mut out, task.name.as_bytes()); push(&mut out, b"\n");
    push(&mut out, b"Umask:\t"); push_octal(&mut out, umask, 4); push(&mut out, b"\n");
    push(&mut out, b"State:\t"); push(&mut out, task.state().linux_status_label().as_bytes()); push(&mut out, b"\n");
    push(&mut out, b"Tgid:\t"); push_u64(&mut out, tid as u64);
    push(&mut out, b"\nNgid:\t0\nPid:\t"); push_u64(&mut out, tid as u64);
    push(&mut out, b"\nPPid:\t"); push_u64(&mut out, ppid);
    push(&mut out, b"\nTracerPid:\t0\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nFDSize:\t256\nGroups:\t\n");
    push(&mut out, b"NStgid:\t"); push_u64(&mut out, tid as u64);
    push(&mut out, b"\nNSpid:\t"); push_u64(&mut out, tid as u64);
    push(&mut out, b"\nNSpgid:\t"); push_u64(&mut out, pgid);
    push(&mut out, b"\nNSsid:\t"); push_u64(&mut out, sid);
    push(&mut out, b"\nThreads:\t1\nSigQ:\t0/0\n\
SigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\n\
SigBlk:\t0000000000000000\nSigIgn:\t0000000000000000\nSigCgt:\t0000000000000000\n\
CapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\nCapEff:\t000001ffffffffff\n\
CapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n\
NoNewPrivs:\t0\nSeccomp:\t0\nSeccomp_filters:\t0\n\
Speculation_Store_Bypass:\tthread vulnerable\nSpeculationIndirectBranch:\tunknown\n\
Cpus_allowed:\t1\nCpus_allowed_list:\t0\nMems_allowed:\t1\nMems_allowed_list:\t0\n\
voluntary_ctxt_switches:\t0\nnonvoluntary_ctxt_switches:\t0\n");
    out
}

fn push(v: &mut Vec<u8>, b: &[u8]) { v.extend_from_slice(b); }

fn push_u64(v: &mut Vec<u8>, mut n: u64) {
    if n == 0 { v.push(b'0'); return; }
    let mut buf = [0u8; 20]; let mut i = 0;
    while n > 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    while i > 0 { i -= 1; v.push(buf[i]); }
}

fn push_octal(v: &mut Vec<u8>, mut n: u64, min_width: usize) {
    let mut buf = [0u8; 24]; let mut i = 0;
    if n == 0 { buf[0] = b'0'; i = 1; }
    while n > 0 { buf[i] = b'0' + (n & 7) as u8; n >>= 3; i += 1; }
    while i < min_width { buf[i] = b'0'; i += 1; }
    while i > 0 { i -= 1; v.push(buf[i]); }
}
