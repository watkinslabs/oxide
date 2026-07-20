use super::*;

const PAGE_MASK: u64 = hal::PAGE_SIZE_BYTES - 1;

/// Retained ARM fault provenance: enumerate the owning mm's VMA tree when a
/// user translation fault cannot find its expected mapping.  A missing loader
/// VMA and a corrupted tree have identical fault codes; ranges plus canonical
/// Arc ownership pointers distinguish them without changing fault handling.
/// # C: O(number of VMAs)
#[cfg(feature = "debug-displaystack")]
pub(super) fn dump_arm_vmas(mm: &vmm::AddressSpace) {
    let vmas = mm.snapshot_vmas();
    klog::write_raw(b"[FAULT-ARM-VMAS] root=");
    klog::write_hex_u64(mm.root_pa());
    klog::write_raw(b" count=");
    klog::write_dec_u64(vmas.len() as u64);
    klog::write_raw(b"\n");
    for vma in vmas {
        klog::write_raw(b"[FAULT-ARM-VMA-RANGE] start=");
        klog::write_hex_u64(vma.start.as_u64());
        klog::write_raw(b" end=");
        klog::write_hex_u64(vma.end.as_u64());
        klog::write_raw(b" anon=");
        klog::write_hex_u64(vma.anon_vma.as_ref().map_or(0, |owner| alloc::sync::Arc::as_ptr(owner) as u64));
        klog::write_raw(b" file=");
        klog::write_hex_u64(vma.file_rmap.as_ref().map_or(0, |owner| alloc::sync::Arc::as_ptr(owner) as u64));
        klog::write_raw(b"\n");
    }
}

#[cfg(all(feature = "debug-mount", target_arch = "x86_64"))]
pub(super) static STEP_VA:   AtomicU64 = AtomicU64::new(0);
#[cfg(all(feature = "debug-mount", target_arch = "x86_64"))]
pub(super) static STEP_RIP:  AtomicU64 = AtomicU64::new(0);
#[cfg(all(feature = "debug-mount", target_arch = "x86_64"))]
pub(super) static STEP_ROOT: AtomicU64 = AtomicU64::new(0);
#[cfg(all(feature = "debug-mount", target_arch = "x86_64"))]
static PREV_TRAP_HOOK: AtomicU64 = AtomicU64::new(0);

/// Linear address of glibc's `initial` atexit list (next page after the
/// __exit_funcs_lock page) — deterministic (no ASLR). The boot wedge
/// overwrites this region with a library-path string.
#[cfg(all(feature = "debug-mount", target_arch = "x86_64"))]
const WATCH_VA: u64 = 0x0000_7fff_fe88_e000;

/// #DB hook: a DR0 hardware write-watchpoint on WATCH_VA fires here (no
/// page-protection slowdown). Reads the 8 bytes just written; if they're a
/// stray ASCII path ("/lib…") logs the writing RIP — the corruptor. Chains
/// the previous (ptrace) hook for non-DR #DBs.
#[cfg(all(feature = "debug-mount", target_arch = "x86_64"))]
pub fn lock_step_hook(frame: &mut hal_x86_64::FaultFrame) -> bool {
    // SAFETY: privileged DR6 read+clear at CPL=0.
    let dr6 = unsafe { hal_x86_64::read_clear_dr6() };
    if dr6 & 0x1 == 0 {
        // Not our DR0 hit — delegate to the chained (ptrace) hook.
        let p = PREV_TRAP_HOOK.load(Ordering::Acquire);
        if p != 0 {
            // SAFETY: PREV_TRAP_HOOK holds a valid UserTrapHook fn pointer captured at install.
            let prev: hal_x86_64::UserTrapHook = unsafe { core::mem::transmute(p as *const ()) };
            return prev(frame);
        }
        return false;
    }
    // Read what was just written via the current task's AS.
    let mut buf = [0u8; 16];
    if let Some(cur) = sched::live::current() {
        // SAFETY: single-mutator mm slot per 13§5.
        if let Some(mm) = unsafe { cur.mm_ref() } {
            let root = mm.root_pa();
            let hhdm = hhdm_offset();
            // SAFETY: root is the live AS; HHDM read of the just-written bytes.
            if let Some(pa) = unsafe { read_foreign_leaf_pa(root, WATCH_VA & !0xFFF, hhdm) } {
                let src = (hhdm + (pa & !0xFFF) + (WATCH_VA & 0xFFF)) as *const u8;
                for i in 0..16 { buf[i] = unsafe { core::ptr::read_volatile(src.add(i)) }; }
            }
        }
    }
    if buf[0] == b'/' || (buf[0] >= 0x20 && buf[0] < 0x7f && buf[1] >= 0x20 && buf[1] < 0x7f) {
        klog::write_raw(b"[mnt] WATCHHIT rip=");
        klog::write_hex_u64(frame.rip);            // trap-type #DB: RIP is just past the store
        klog::write_raw(b" data=");
        for i in 0..16 { klog::write_hex_u64(buf[i] as u64); klog::write_raw(b","); }
        klog::write_raw(b"\n");
    }
    true        // consumed; iretq back to user (DR6 already cleared)
}

/// Install the DR0 write-watchpoint #DB hook (chaining the previous) + arm
/// the watchpoint on the atexit list.
#[cfg(all(feature = "debug-mount", target_arch = "x86_64"))]
pub fn install_lock_step_hook() {
    // SAFETY: boot-time install; hook lives for the kernel lifetime.
    let prev = unsafe { hal_x86_64::install_user_trap_hook(lock_step_hook) };
    PREV_TRAP_HOOK.store(prev as *const () as u64, Ordering::Release);
    // DR0 disabled: the #DB on the first atexit-list write deterministically
    // wedges the process (both DR7 encodings) — the #DB delivery path is unsafe
    // for data breakpoints here / the atexit section can't tolerate the trap.
    let _ = WATCH_VA;
    // unsafe { hal_x86_64::set_data_watchpoint(WATCH_VA); }
}

/// debug-cow probe 2 (SEGV-FAULT DUMP): emitted the instant a user fault
/// becomes fatal (no VMA / protection violation / not-present that can't be
/// filled → SIGSEGV). Pins the failing VA + the covering VMA [lo,hi,prot] +
/// whether a live PTE/frame exists there. `rip`/`cr2`/`err` are the arch
/// fault triple (x86: RIP / CR2 / PFEC; aarch64: ELR / FAR / ESR). The `err`
/// bits distinguish a CODE fault (bad text page — instruction-fetch) from a
/// DATA / stack fault, which tells whether the wrong-frame / double-alloc
/// victim was an executable page or a data page. No-op when the feature is
/// off (returns before any work).
/// # C: O(log N_vmas) + O(walk depth)
#[cfg(feature = "debug-cow")]
pub(super) fn segv_dump(rip: u64, cr2: u64, err: u64) {
    fn dump_vma(label: &[u8], v: Option<vmm::Vma>) {
        klog::write_raw(label);
        match v {
            Some(v) => {
                klog::write_raw(b"=[");
                klog::write_hex_u64(v.start.as_u64());
                klog::write_raw(b",");
                klog::write_hex_u64(v.end.as_u64());
                klog::write_raw(b",prot=");
                klog::write_hex_u64(v.prot.bits() as u64);
                match &v.backing {
                    VmaBacking::File { backing, off } => {
                        klog::write_raw(b",file_ino=");
                        klog::write_hex_u64(backing.ino());
                        klog::write_raw(b",file_off=");
                        klog::write_hex_u64(*off);
                    }
                    VmaBacking::KernelBytes { off, .. } => {
                        klog::write_raw(b",kb_off=");
                        klog::write_hex_u64(*off as u64);
                    }
                    VmaBacking::Anonymous => klog::write_raw(b",anon"),
                    VmaBacking::KernelFrame { pa } => {
                        klog::write_raw(b",kframe=");
                        klog::write_hex_u64(*pa);
                    }
                    VmaBacking::PhysRange { base_pa } => {
                        klog::write_raw(b",phys=");
                        klog::write_hex_u64(*base_pa);
                    }
                    VmaBacking::Special => klog::write_raw(b",special"),
                }
                klog::write_raw(b"]");
            }
            None => klog::write_raw(b"=none"),
        }
    }

    fn dump_u64_at(root: u64, label: &[u8], addr: u64) {
        klog::write_raw(label);
        klog::write_hex_u64(addr);
        if root == 0 || addr >= USER_VA_END {
            klog::write_raw(b":unreadable");
            return;
        }
        let hhdm = hhdm_offset();
        match unsafe { read_foreign_leaf(root, addr & !PAGE_MASK, hhdm) } {
            Some((pa, raw)) => {
            let src = (hhdm + (pa & !PAGE_MASK) + (addr & PAGE_MASK)) as *const u64;
                let val = unsafe { core::ptr::read_volatile(src) };
                klog::write_raw(b":pte=");
                klog::write_hex_u64(raw);
                klog::write_raw(b":val=");
                klog::write_hex_u64(val);
            }
            None => klog::write_raw(b":pte=none"),
        }
    }

    let tid = sched::live::current().map(|c| c.tid).unwrap_or(0);
    klog::write_raw(b"[SEGV] rip="); klog::write_hex_u64(rip);
    klog::write_raw(b" cr2=");       klog::write_hex_u64(cr2);
    klog::write_raw(b" err=");       klog::write_hex_u64(err);
    klog::write_raw(b" pid=");       klog::write_dec_u64(tid as u64);
    let mut root = 0u64;
    if let Some(cur) = sched::live::current() {
        // SAFETY: single-mutator mm slot per 13§5; fault ctx with IRQs off; read-only VMA query.
        if let Some(mm) = unsafe { cur.mm_ref() } {
            root = mm.root_pa();
            dump_vma(b" cr2_vma", UserVirtAddr::new(cr2 & !PAGE_MASK).and_then(|u| mm.find_vma(u)));
            let rip_vma = UserVirtAddr::new(rip & !PAGE_MASK).and_then(|u| mm.find_vma(u));
            dump_vma(b" rip_vma", rip_vma.clone());
            if let Some(v) = rip_vma {
                if let VmaBacking::File { off, .. } = &v.backing {
                    let load_base = v.start.as_u64().saturating_sub(*off);
                    let got_addr = load_base.saturating_add(0x1e6eb0);
                    dump_vma(b" got_vma", UserVirtAddr::new(got_addr).and_then(|u| mm.find_vma(u)));
                    dump_u64_at(root, b" got_rtld_global_ro@", got_addr);
                }
            }
        }
    }
    // Live PTE + frame at the faulting page, walked from this AS's root. A
    // present PTE on a fatal fault = protection/wrong-frame; absent = a
    // not-present nobody could fill (no backing).
    if root != 0 {
        let hhdm = hhdm_offset();
        // SAFETY: read-only foreign-leaf PT walk of the current AS root; HHDM covers PT memory; single-CPU fault ctx.
        match unsafe { read_foreign_leaf(root, cr2 & !PAGE_MASK, hhdm) } {
            Some((pa, raw)) => {
                klog::write_raw(b" pte=");   klog::write_hex_u64(raw);
            klog::write_raw(b" frame="); klog::write_hex_u64(pa & !PAGE_MASK);
            }
            None => klog::write_raw(b" pte=none frame=none"),
        }
    }
    // DISAMBIGUATION (bootA4): the residual fault is a near-NULL DATA read at a
    // deterministic libc site. Two surviving hypotheses produce a tiny cr2:
    //   (3a) `%fs:offset` with FS_BASE==0  → TLS/context-switch hole, OR
    //   (2)  a register holds a wrong/zero base read out of a mis-installed
    //        frame → plain near-null deref.
    // The TLS-base value + the faulting instruction bytes + the GP register
    // file pin which one: a `64`(fs-prefix) opcode with fsbase==0 ⇒ (3a); a
    // plain `mov` whose base register is ~0 ⇒ (2). Decoded offline from this
    // line. x86: TLS base = IA32_FS_BASE; arm: TLS base = TPIDR_EL0.
    {
        // TLS base register (the `%fs`/TPIDR pointer userspace TLS rides).
        #[cfg(target_arch = "x86_64")]
        // SAFETY: rdmsr IA32_FS_BASE at CPL=0 is unconditionally legal; pure read of the live per-CPU FS base.
        let tls_base = unsafe { hal_x86_64::get_user_fs_base() };
        #[cfg(target_arch = "aarch64")]
        let tls_base = {
            let v: u64;
            // SAFETY: mrs tpidr_el0 at EL1 reads the live user TLS base; pure read, no side effects.
            unsafe { core::arch::asm!("mrs {v}, tpidr_el0", v = out(reg) v, options(nomem, nostack, preserves_flags)); }
            v
        };
        klog::write_raw(b" fsbase="); klog::write_hex_u64(tls_base);
        // GP register file at fault — the base register holding ~0 names the
        // wrong-frame victim; for a `%fs:` access the GPRs are irrelevant and
        // fsbase==0 is the tell.
        #[cfg(target_arch = "x86_64")]
        {
            let g = hal_x86_64::current_fault_gprs();
            if !g.is_null() {
                // SAFETY: current_fault_gprs() returns the live FaultGprs the per-vector stub pushed on the kernel stack; we only read.
                let g = unsafe { &*g };
                klog::write_raw(b" rax="); klog::write_hex_u64(g.rax);
                klog::write_raw(b" rbx="); klog::write_hex_u64(g.rbx);
                klog::write_raw(b" rcx="); klog::write_hex_u64(g.rcx);
                klog::write_raw(b" rdx="); klog::write_hex_u64(g.rdx);
                klog::write_raw(b" rsi="); klog::write_hex_u64(g.rsi);
                klog::write_raw(b" rdi="); klog::write_hex_u64(g.rdi);
                klog::write_raw(b" rbp="); klog::write_hex_u64(g.rbp);
                klog::write_raw(b" r8=");  klog::write_hex_u64(g.r8);
                klog::write_raw(b" r12="); klog::write_hex_u64(g.r12);
            }
        }
    }
    klog::write_raw(b"\n");
}
