// Unhandled-fatal-signal reporting: the kernel-log line a task's death by an
// unhandled synchronous fault owes the operator.
//
// `debug/exception-trace` -> `show_unhandled_signals`, printed by the ARCH
// fault path just before the signal is forced. Default 1 on x86_64, 0 on
// aarch64, per the reference's per-arch initialiser.
//
// Decision logic lives here, ungated, so it is reachable from `cargo test`;
// the emit half is a thin klog writer and the ARCH fault path is its one
// caller.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// Reference `DEFAULT_RATELIMIT_INTERVAL` (5 s) in nanoseconds.
pub const RATELIMIT_INTERVAL_NS: u64 = 5_000_000_000;
/// Reference `DEFAULT_RATELIMIT_BURST`.
pub const RATELIMIT_BURST: u32 = 10;

/// `sa_handler == SIG_DFL`.
pub const SIG_DFL: u64 = 0;
/// `sa_handler == SIG_IGN`.
pub const SIG_IGN: u64 = 1;

/// `show_unhandled_signals`. The reference initialises this per arch: 1 on
/// x86_64, 0 on aarch64. Keeping the arch split means a report that appears on
/// one arch and not the other is the documented default, not a porting bug.
static SHOW_UNHANDLED: AtomicBool = AtomicBool::new(cfg!(target_arch = "x86_64"));

/// Read `debug/exception-trace`. # C: O(1)
pub fn show_unhandled_signals() -> bool { SHOW_UNHANDLED.load(Ordering::Relaxed) }
/// Write `debug/exception-trace`. # C: O(1)
pub fn set_show_unhandled_signals(on: bool) { SHOW_UNHANDLED.store(on, Ordering::Relaxed) }

/// Reference `unhandled_signal(tsk, sig)`: would this signal reach its default
/// action without any userspace or tracer say in the matter?
///
/// Order is load-bearing. PID 1 reports unconditionally — its death is the
/// operator's problem whatever it had installed. A real handler means the
/// program asked to see the fault (JIT guard pages, GC write barriers), so
/// nothing is printed. A task already carrying a pending SIGKILL is on its way
/// out and its new signals are dropped, so there is nothing to report. A
/// traced task's signal belongs to its tracer, which may well suppress it.
/// # C: O(1)
pub fn unhandled_signal(handler: u64, is_global_init: bool, fatal_pending: bool, ptraced: bool) -> bool {
    if is_global_init { return true; }
    if handler != SIG_IGN && handler != SIG_DFL { return false; }
    if fatal_pending { return false; }
    !ptraced
}

/// Reference `struct ratelimit_state` over a fixed interval and burst: allow
/// up to `RATELIMIT_BURST` messages per `RATELIMIT_INTERVAL_NS`, then go quiet
/// until the interval rolls over.
pub struct RateLimit {
    begin: AtomicU64,
    printed: AtomicU32,
}

impl RateLimit {
    /// A limiter that has not yet opened an interval. # C: O(1)
    pub const fn new() -> Self { Self { begin: AtomicU64::new(0), printed: AtomicU32::new(0) } }

    /// Charge one message against the limiter at `now_ns`; `true` means print.
    ///
    /// The first call opens the interval. A call past `begin + interval` opens
    /// a fresh one, which is what keeps a slow drip of faults visible forever
    /// rather than silencing the log after the first ten.
    /// # C: O(1)
    pub fn allow(&self, now_ns: u64) -> bool {
        let begin = self.begin.load(Ordering::Relaxed);
        if begin == 0 || now_ns.wrapping_sub(begin) >= RATELIMIT_INTERVAL_NS {
            self.begin.store(now_ns, Ordering::Relaxed);
            self.printed.store(1, Ordering::Relaxed);
            return true;
        }
        let n = self.printed.fetch_add(1, Ordering::Relaxed);
        n < RATELIMIT_BURST
    }
}

impl Default for RateLimit {
    fn default() -> Self { Self::new() }
}

/// The one limiter the fault report is charged against.
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
static FAULT_RS: RateLimit = RateLimit::new();

/// Reference `show_signal_msg()`: one line naming the task that a synchronous
/// user-mode fault is about to kill, and where it died.
///
/// Called by the ARCH fault path BEFORE the signal is queued, because the
/// screen it applies (`unhandled_signal`) reads the disposition that forcing
/// the signal is about to overwrite with `SIG_DFL`. Reading it afterwards
/// would report every fault, including the ones a JIT or GC installed a
/// handler for and resolves in userspace.
/// # C: O(1)
/// # Ctx: fault, task context
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub fn report_user_fault(sig: u32, addr: u64, ip: u64, sp: u64, err: u64, vma: Option<VmaAddr>) {
    if !show_unhandled_signals() { return; }
    let Some(cur) = crate::live::current() else { return };
    let handler = cur.sigactions_ref().get(sig).handler;
    let is_init = cur.vtgid.load(Ordering::Relaxed) == 1;
    let fatal_pending = cur.sigpending.load(Ordering::Acquire) & crate::Signum::Sigkill.bit() != 0;
    let ptraced = cur.traced_by.load(Ordering::Acquire) != 0;
    if !unhandled_signal(handler, is_init, fatal_pending, ptraced) { return; }
    if !FAULT_RS.allow(crate::deadline::clock::now_ns()) { return; }

    let comm = cur.comm_bytes();
    klog::write_raw(crate::Task::comm_trim(&comm).as_bytes());
    klog::write_raw(b"[");
    klog::write_dec_u64(cur.vtgid.load(Ordering::Relaxed) as u64);
    klog::write_raw(b"]: ");
    klog::write_raw(fault_kind(sig));
    klog::write_raw(b" at ");   klog::write_hex_u64(addr);
    klog::write_raw(b" ip ");   klog::write_hex_u64(ip);
    klog::write_raw(b" sp ");   klog::write_hex_u64(sp);
    klog::write_raw(b" error "); klog::write_hex_u64(err);
    klog::write_raw(b" tid ");  klog::write_dec_u64(cur.tid as u64);
    // The reference's `print_vma_addr` tail: the file of the MAPPING the
    // faulting instruction sits in, the instruction's offset within that file,
    // and the mapping's range. Naming the process's own executable here is
    // actively misleading — a fault inside a shared library reads as a fault in
    // the program — and the file-relative offset is what turns the line into a
    // symbol without the dead process's `/proc/<pid>/maps`. A mapping with no
    // file prints no tail at all, exactly as the reference's `vma->vm_file`
    // test does.
    if let Some(v) = vma {
        let mut tail = [0u8; VMA_TAIL_MAX];
        let n = write_vma_tail(&mut tail, &v);
        klog::write_raw(&tail[..n]);
    }
    klog::write_raw(b"\n");
}

/// Bytes of a mapped file's name the report carries. The reference prints the
/// name at dentry depth 1 — the basename alone — and every mapped object whose
/// name matters to a crash report (`libc.so.6`, a program image, a `.so` under
/// a versioned directory) fits well inside this.
pub const VMA_NAME_MAX: usize = 64;

/// The mapped file's basename, copied by value.
///
/// A borrow cannot be used: the name lives under the mm's lock in another
/// crate, while `VmaAddr` is `Copy` and outlives the lookup that produced it.
/// Empty means the mapping has no file, which the reference reports by printing
/// no tail rather than by printing an anonymous placeholder.
#[derive(Clone, Copy)]
pub struct VmaName {
    buf: [u8; VMA_NAME_MAX],
    len: u8,
}

impl VmaName {
    /// A mapping with no file behind it. # C: O(1)
    pub const fn none() -> Self { Self { buf: [0; VMA_NAME_MAX], len: 0 } }

    /// Final component of `path`, truncated to [`VMA_NAME_MAX`].
    ///
    /// Truncation is silent by design: a name long enough to be cut is still
    /// enough to identify the object, and the alternative — dropping the tail
    /// entirely — loses the only clue the line carries. A path whose last
    /// component is empty (a trailing slash) yields no name, since there is no
    /// dentry the reference could have printed.
    /// # C: O(len(path))
    pub fn from_path(path: &[u8]) -> Self {
        let base = match path.iter().rposition(|&c| c == b'/') {
            Some(i) => &path[i + 1..],
            None    => path,
        };
        let n = if base.len() > VMA_NAME_MAX { VMA_NAME_MAX } else { base.len() };
        let mut out = Self::none();
        out.buf[..n].copy_from_slice(&base[..n]);
        out.len = n as u8;
        out
    }

    /// The name, or `None` when the mapping has no file. # C: O(1)
    pub fn as_bytes(&self) -> Option<&[u8]> {
        if self.len == 0 { None } else { Some(&self.buf[..self.len as usize]) }
    }
}

impl Default for VmaName {
    fn default() -> Self { Self::none() }
}

/// Where the faulting instruction sits: the mapping that covers it, the name of
/// the file that mapping is of, and the instruction's offset within that file.
/// Assembled by the ARCH fault path, which is the layer holding the mm.
#[derive(Clone, Copy)]
pub struct VmaAddr {
    /// First address of the mapping covering the faulting instruction.
    pub start: u64,
    /// Length of that mapping in bytes.
    pub len: u64,
    /// Basename of the mapped file; empty for an anonymous mapping.
    pub name: VmaName,
    /// Offset of the faulting instruction within the backing file.
    pub file_off: u64,
}

/// Assemble the report's mapping record for a faulting `ip` covered by the
/// mapping `[start, end)`. `file` is the mapping's own backing — the path it was
/// established from and the file offset the mapping begins at — or `None` for an
/// anonymous mapping.
///
/// Ungated because the choice this makes is the whole defect it exists to fix:
/// the name must come from the MAPPING's file, never from the faulting process's
/// executable, or a fault in a shared library is reported against the program.
/// The offset is the reference's `ip - vm_start + (vm_pgoff << PAGE_SHIFT)`.
/// # C: O(len(path))
pub fn vma_addr_from(start: u64, end: u64, ip: u64, file: Option<(&[u8], u64)>) -> VmaAddr {
    let (name, file_off) = match file {
        Some((path, vm_off)) => (VmaName::from_path(path), vm_off + ip.saturating_sub(start)),
        None => (VmaName::none(), 0),
    };
    VmaAddr { start, len: end.saturating_sub(start), name, file_off }
}

/// Longest tail [`write_vma_tail`] can produce: ` in ` + a full-length name +
/// `[` + three 16-digit hex fields + two separators + `]`.
pub const VMA_TAIL_MAX: usize = 4 + VMA_NAME_MAX + 1 + 16 * 3 + 2 + 1;

/// Render the reference's `print_vma_addr` tail — ` in <name>[<file offset>,<vma
/// start>+<vma length>]` — into `out`, returning the bytes written.
///
/// Ungated and buffer-based so the FORM is testable without a kernel: the field
/// order and the bracketing are what let a reader hand the offset straight to a
/// symbolizer, and a silent change to either makes every past crash line
/// unreadable. Nothing is written for a mapping with no file.
/// # C: O(1)
pub fn write_vma_tail(out: &mut [u8], v: &VmaAddr) -> usize {
    let Some(name) = v.name.as_bytes() else { return 0 };
    let mut n = 0;
    let mut put = |src: &[u8], n: &mut usize| {
        let room = out.len() - *n;
        let take = if src.len() > room { room } else { src.len() };
        out[*n..*n + take].copy_from_slice(&src[..take]);
        *n += take;
    };
    put(b" in ", &mut n);
    put(name, &mut n);
    put(b"[", &mut n);
    put(&hex16(v.file_off), &mut n);
    put(b",", &mut n);
    put(&hex16(v.start), &mut n);
    put(b"+", &mut n);
    put(&hex16(v.len), &mut n);
    put(b"]", &mut n);
    n
}

/// One 64-bit value as 16 zero-padded lowercase hex digits, matching the
/// addresses printed earlier on the same line. # C: O(1)
fn hex16(v: u64) -> [u8; 16] {
    let mut b = [0u8; 16];
    for i in 0..16 {
        let nib = ((v >> ((15 - i) * 4)) & 0xf) as u8;
        b[i] = if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) };
    }
    b
}

/// The reference names the SIGSEGV case `segfault`; every other fault signal
/// is reported by the generic `unhandled exception` wording rather than being
/// dropped, so a SIGBUS or SIGILL death is not silent.
/// # C: O(1)
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
fn fault_kind(sig: u32) -> &'static [u8] {
    match sig {
        s if s == crate::Signum::Sigsegv.as_u8() as u32 => b"segfault",
        s if s == crate::Signum::Sigbus.as_u8()   as u32 => b"bus error",
        s if s == crate::Signum::Sigill.as_u8()   as u32 => b"illegal instruction",
        s if s == crate::Signum::Sigfpe.as_u8()   as u32 => b"fp exception",
        s if s == crate::Signum::Sigtrap.as_u8()  as u32 => b"trap",
        _ => b"unhandled exception",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_caught_signal_is_never_reported() {
        assert!(!unhandled_signal(0x4001_0000, false, false, false));
    }

    #[test]
    fn default_and_ignored_dispositions_are_both_reported() {
        assert!(unhandled_signal(SIG_DFL, false, false, false));
        assert!(unhandled_signal(SIG_IGN, false, false, false));
    }

    #[test]
    fn pid_one_is_reported_even_with_a_handler_installed() {
        assert!(unhandled_signal(0x4001_0000, true, false, false));
    }

    #[test]
    fn a_task_already_carrying_sigkill_is_not_reported() {
        assert!(!unhandled_signal(SIG_DFL, false, true, false));
    }

    #[test]
    fn a_traced_task_leaves_the_decision_to_its_tracer() {
        assert!(!unhandled_signal(SIG_DFL, false, false, true));
    }

    #[test]
    fn pid_one_outranks_both_the_dying_and_the_traced_screen() {
        assert!(unhandled_signal(SIG_DFL, true, true, true));
    }

    #[test]
    fn the_burst_is_ten_messages_then_silence_within_one_interval() {
        let rl = RateLimit::new();
        // Interval opens at t=1 and that first message counts against the burst.
        assert!(rl.allow(1));
        for i in 1..RATELIMIT_BURST as u64 { assert!(rl.allow(1 + i), "message {i} inside burst"); }
        assert!(!rl.allow(1 + RATELIMIT_BURST as u64));
        assert!(!rl.allow(RATELIMIT_INTERVAL_NS - 1));
    }

    #[test]
    fn the_interval_rolling_over_re_opens_the_burst() {
        let rl = RateLimit::new();
        for _ in 0..RATELIMIT_BURST + 5 { rl.allow(1); }
        assert!(!rl.allow(1));
        assert!(rl.allow(1 + RATELIMIT_INTERVAL_NS));
    }

    #[test]
    fn a_zero_timestamp_still_opens_an_interval() {
        let rl = RateLimit::new();
        assert!(rl.allow(0));
    }

    // The knob is process-global, so a test that WRITES it races every other
    // test in the binary. Its default is asserted read-only here; the write
    // path is covered where it is reachable from userspace, by the procfs
    // sysctl tests.

    #[test]
    fn exception_trace_defaults_on_for_x86_64_and_off_for_aarch64() {
        assert_eq!(show_unhandled_signals(), cfg!(target_arch = "x86_64"));
    }

    fn tail(v: &VmaAddr) -> alloc::string::String {
        let mut buf = [0u8; VMA_TAIL_MAX];
        let n = write_vma_tail(&mut buf, v);
        alloc::string::String::from_utf8(buf[..n].to_vec()).unwrap()
    }

    #[test]
    fn a_mapped_file_is_named_by_its_basename_not_by_its_path() {
        let n = VmaName::from_path(b"/usr/lib64/libc.so.6");
        assert_eq!(n.as_bytes(), Some(&b"libc.so.6"[..]));
    }

    #[test]
    fn a_bare_name_with_no_directory_is_kept_whole() {
        assert_eq!(VmaName::from_path(b"busybox").as_bytes(), Some(&b"busybox"[..]));
    }

    #[test]
    fn a_path_ending_in_a_separator_names_nothing() {
        assert!(VmaName::from_path(b"/usr/lib64/").as_bytes().is_none());
        assert!(VmaName::from_path(b"").as_bytes().is_none());
    }

    #[test]
    fn an_over_long_basename_is_truncated_rather_than_dropped() {
        let long = [b'x'; VMA_NAME_MAX + 20];
        let n = VmaName::from_path(&long);
        assert_eq!(n.as_bytes().unwrap().len(), VMA_NAME_MAX);
    }

    // The exact line a reader hands to a symbolizer. Field ORDER is the
    // contract: the file-relative offset comes first, then the mapping's start
    // and length, all inside one bracket after the file's name.
    #[test]
    fn the_tail_is_the_file_then_offset_then_mapping_range() {
        let v = VmaAddr {
            start: 0x7f2a_c997_4000, len: 0x16_e000,
            name: VmaName::from_path(b"/usr/lib64/libc.so.6"), file_off: 0x14_8e9d,
        };
        assert_eq!(tail(&v),
            " in libc.so.6[0000000000148e9d,00007f2ac9974000+000000000016e000]");
    }

    // The reference tests `vma->vm_file` and prints the whole tail or none of
    // it; an anonymous mapping must not produce a stray ` in `.
    #[test]
    fn an_anonymous_mapping_prints_no_tail_at_all() {
        let v = VmaAddr { start: 0x1000, len: 0x1000, name: VmaName::none(), file_off: 0 };
        assert_eq!(tail(&v), "");
    }

    // The line this whole change exists for. A `gdm-session-worker` fault at
    // ip 0x7f2ac9abce9d sits inside the mapping of the guest's `libc.so.6`
    // (start 0x7f2ac9974000, one executable segment page-rounded to 0x16e000);
    // the report previously named `/usr/libexec/gdm-session-worker`, the
    // process's own executable, which is a different binary entirely. The
    // offset 0x148e9d is what a symbolizer turns into `__strlen_avx2+0x1d`.
    #[test]
    fn a_fault_in_a_mapped_library_names_the_library_not_the_program() {
        let v = vma_addr_from(0x7f2a_c997_4000, 0x7f2a_c9ae_2000, 0x7f2a_c9ab_ce9d,
                              Some((b"/usr/lib64/libc.so.6", 0)));
        assert_eq!(v.name.as_bytes(), Some(&b"libc.so.6"[..]));
        assert_eq!(v.file_off, 0x14_8e9d);
        assert_eq!(tail(&v),
            " in libc.so.6[0000000000148e9d,00007f2ac9974000+000000000016e000]");
    }

    // Reference `ip -= vma->vm_start; ip += vma->vm_pgoff << PAGE_SHIFT`.
    #[test]
    fn the_offset_is_measured_from_the_mappings_own_file_offset() {
        let v = vma_addr_from(0x1000, 0x3000, 0x1abc, Some((b"/lib/ld.so", 0x20_0000)));
        assert_eq!(v.file_off, 0x20_0abc);
    }

    #[test]
    fn an_anonymous_mapping_carries_no_name_and_no_offset() {
        let v = vma_addr_from(0x1000, 0x2000, 0x1abc, None);
        assert!(v.name.as_bytes().is_none());
        assert_eq!(v.file_off, 0);
        assert_eq!(v.len, 0x1000);
    }

    #[test]
    fn the_longest_possible_tail_fits_the_declared_buffer() {
        let v = VmaAddr {
            start: u64::MAX, len: u64::MAX,
            name: VmaName::from_path(&[b'z'; VMA_NAME_MAX]), file_off: u64::MAX,
        };
        assert_eq!(tail(&v).len(), VMA_TAIL_MAX);
    }
}
