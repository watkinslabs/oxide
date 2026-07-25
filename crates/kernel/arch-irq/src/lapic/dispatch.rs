use core::sync::atomic::{AtomicU64, Ordering};

use super::regs::{eoi, local_apic_id};

/// Per-CPU tick counter incremented by the timer-IRQ dispatcher.
#[cfg(target_arch = "x86_64")]
pub static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Cross-CPU resched IPI receive counter. Incremented by the
/// `VEC_RESCHED` arm of `oxide_irq_dispatch`. v1 smoke uses this
/// to validate the IPI path end-to-end (BSP -> AP -> handler).
#[cfg(target_arch = "x86_64")]
pub static RESCHED_IPI_COUNT: AtomicU64 = AtomicU64::new(0);

/// B1347 corruption hunt: monotonically bumped at the TOP of every
/// `oxide_irq_dispatch` (all vectors), with the vector stashed in `IRQ_LAST_VEC`.
/// kalloc's corruption detector reads these (via a hook) to tell whether an IRQ
/// fired between the last clean free-list validate and the detection — i.e.
/// whether the stray offset-0/8 Arc-refcount write happened in a HARD-IRQ
/// handler (which does NOT set preempt_count's hardirq bits, so `ctx.in_irq`
/// alone can't see it). # C: O(1)
#[cfg(target_arch = "x86_64")]
pub static IRQ_SEQ: AtomicU64 = AtomicU64::new(0);
/// Vector of the most recent `oxide_irq_dispatch`. # C: O(1)
#[cfg(target_arch = "x86_64")]
pub static IRQ_LAST_VEC: AtomicU64 = AtomicU64::new(0);

/// Rust IRQ dispatcher invoked from the per-vector asm stub. Bumps
/// the tick counter, EOIs, sets NEED_RESCHED, then asks the
/// scheduler for the next task and stages it in
/// `oxide_preempt_next_ctx` so the asm tail switches on IRQ exit
/// (per `14§R07`).
///
/// # SAFETY: invoked only from the IRQ entry asm with IRQs masked
/// (interrupt-gate clears IF on entry).
/// # C: O(1)
/// # Ctx: IRQ
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
#[no_mangle]
unsafe extern "C" fn oxide_irq_dispatch(frame: *const u8) {
    // Linux `irq_enter`: hardirq-account the whole dispatcher. While the
    // HARDIRQ field is set, no `preempt_enable` pair inside any handler can
    // fire `schedule()` — a context switch can never happen on the per-CPU
    // hardirq stack this dispatcher runs on. Dropped (`irq_exit`) before the
    // tail softirq drain, exactly as Linux `irq_exit`→`invoke_softirq`.
    sched::preempt::irq_enter();
    // Frame layout (push order in oxide_irq_vec_NN):
    //   err(0) vec(8) r11..rax -- `mov rdi,rsp` happens AFTER the
    //   9 reg pushes, so frame[0..8] = r11 ... frame[72..80] = vec.
    // SAFETY: caller is the per-vector IRQ asm stub which always pushes the same scaffold; offset 72 lies within.
    let vec_tag = unsafe {
        core::ptr::read_volatile(frame.add(72) as *const u64)
    } as u8;

    // B1347: stamp the IRQ arrival BEFORE any handler runs, so kalloc can tell an
    // IRQ fired in the corruption window and name its vector.
    IRQ_LAST_VEC.store(vec_tag as u64, Ordering::Release);
    IRQ_SEQ.fetch_add(1, Ordering::AcqRel);

    // EOI on every IRQ vector -- both timer and IPIs need it.
    // SAFETY: dispatcher is the in-progress IRQ; LAPIC was mapped+enabled before STI.
    unsafe { eoi(); }

    match vec_tag {
        hal_x86_64::VEC_TIMER => {
            TICK_COUNT.fetch_add(1, Ordering::Relaxed);
            crate::irqstat::hit_timer();
            // debug-wakelat: measure the real LAPIC periodic-tick period +
            // flag any stalled inter-tick gap (H3).
            #[cfg(feature = "debug-wakelat")]
            {
                use hal::TimerOps;
                sched::live::wakelat::note_tick(hal_x86_64::X86TimerOps::monotonic_ns().0);
            }
            // Per-CPU heartbeat + cross-CPU hard-lockup scan (runs on every
            // CPU that ticks, so a frozen CPU is observed by another).
            sched::diag::percpu::tick();
            sched::live::preempt::set_need_resched();
            // /proc/stat per-CPU cputime accounting runs on EVERY CPU — each
            // charges its OWN tick to its own `cpuN` bucket (Linux per-CPU
            // kcpustat). Was the timer taken in user mode? Saved CS sits at
            // frame+96 (r11@0..vec@72, err@80, rip@88, cs@96); ring 3
            // (CS&3==3) = user code was running.
            // SAFETY: `frame` is the per-vector IRQ scaffold pushed by the stub; +96 is the CPU-pushed CS slot, within the saved frame.
            let from_user = unsafe { (core::ptr::read_volatile(frame.add(96) as *const u64) & 3) == 3 };
            sched::cpustat::account(
                if from_user { sched::cpustat::TickKind::User } else { sched::cpustat::TickKind::Idle });
            // G3: per-task utime/stime — charge the real inter-tick delta to
            // the interrupted task's user/kernel CPU-time bucket (getrusage/
            // times). IRQ-context: atomics only.
            sched::cpustat::charge_current_tick(from_user);
            // DIAG (debug-wakelat): `[USERIP]` — sample the interrupted USER rip
            // so a pure-userspace busy-spin (a task stuck in a userspace loop with
            // stime=0, invisible to /proc/<pid>/syscall which is stubbed) reveals
            // its loop PC + owning task. A fixed rip repeating across samples = the
            // spin site; feed (rip - lib_base from /proc/<pid>/maps) to objdump.
            // Rate-limited to ~1/128 user ticks to avoid flooding.
            #[cfg(feature = "debug-wakelat")]
            if from_user {
                static URIP_SAMP: AtomicU64 = AtomicU64::new(0);
                if URIP_SAMP.fetch_add(1, Ordering::Relaxed) % 128 == 0 {
                    // SAFETY: frame+88 is the CPU-pushed user RIP slot (layout above).
                    let rip = unsafe { core::ptr::read_volatile(frame.add(88) as *const u64) };
                    klog::write_raw(b"[USERIP rip=");
                    klog::write_hex_u64(rip);
                    if let Some(c) = sched::live::current() {
                        klog::write_raw(b" tid=");
                        klog::write_dec_u64(c.tid as u64);
                        klog::write_raw(b" lastsc=");
                        klog::write_dec_u64(c.last_syscall_nr.load(Ordering::Relaxed) as u64);
                        klog::write_raw(b" ");
                        klog::write_raw(c.name.as_bytes());
                    }
                    klog::write_raw(b"]\n");
                }
            }
            // DIAG (debug-wakelat): `[KERNIP]` — a tick that interrupted KERNEL
            // mode on a REAL user task (not idle) samples the kernel RIP. A fixed
            // RIP repeating = a kernel-mode busy-spin (spinlock livelock / a kernel
            // loop) that `[USERIP]` (from_user only) can't see. Feed the RIP to
            // addr2line on the kernel ELF. Excludes the idle/kthread sink (tgid==0).
            // Rate-limited 1/128 to match USERIP.
            #[cfg(feature = "debug-wakelat")]
            if !from_user {
                if let Some(c) = sched::live::current() {
                    if c.tgid.load(Ordering::Relaxed) != 0 {
                        static KRIP_SAMP: AtomicU64 = AtomicU64::new(0);
                        if KRIP_SAMP.fetch_add(1, Ordering::Relaxed) % 128 == 0 {
                            // SAFETY: frame+88 is the CPU-pushed RIP slot; same offset
                            // for kernel-mode ticks (no SS/RSP pushed, but RIP is top).
                            let rip = unsafe { core::ptr::read_volatile(frame.add(88) as *const u64) };
                            klog::write_raw(b"[KERNIP rip=");
                            klog::write_hex_u64(rip);
                            klog::write_raw(b" tid=");
                            klog::write_dec_u64(c.tid as u64);
                            klog::write_raw(b" lastsc=");
                            klog::write_dec_u64(c.last_syscall_nr.load(Ordering::Relaxed) as u64);
                            klog::write_raw(b" ");
                            klog::write_raw(c.name.as_bytes());
                            klog::write_raw(b"]\n");
                        }
                    }
                }
            }
            // BSP timer hook runs only on the boot CPU. The softirq drain is
            // PER-CPU (Linux: every CPU runs its own
            // __do_softirq from irq_exit) — each CPU drains its OWN pending
            // mask below. APs that arm their own periodic timer reach here too.
            let is_bsp = local_apic_id() == ::cpu::smp::boot_cpu_id();
            if is_bsp {
                // SAFETY: timer ISR ctx with IRQs masked; BSP-owned timer hook.
                unsafe { crate::tick_poll(from_user); }
            }
            // Softirq drain moved to the fn tail (after `irq_exit`) — Linux
            // order: the hardirq field must drop before `invoke_softirq`.
            crate::deadline::rearm();
            // The actual switch happens at IRQ exit via
            // `oxide_irq_resched_on_exit` → `schedule()` (one engine); the
            // tick only requested it by setting need_resched above.
        }
        hal_x86_64::VEC_RESCHED => {
            RESCHED_IPI_COUNT.fetch_add(1, Ordering::Relaxed);
            crate::irqstat::hit_resched();
            // Cross-CPU resched IPI: another CPU asked us to pick a new
            // task. Set need_resched; the IRQ-exit slow path
            // (`oxide_irq_resched_on_exit` → `schedule()`) does the switch.
            sched::live::preempt::set_need_resched();
        }
        hal_x86_64::VEC_TLB_SHOOTDOWN => {
            // Cross-CPU TLB shootdown: another CPU downgraded/removed a
            // user PTE in an mm we may have cached. Invalidate the
            // requested VA (or full-flush) locally and ACK. EOI already
            // issued above. No resched implied.
            crate::tlb::service();
        }
        v if v >= hal_x86_64::VEC_MSI_POOL_FIRST
          && v <= hal_x86_64::VEC_MSI_POOL_LAST => {
            // F58: per-vector MSI delivery. EOI already issued above.
            // Bump the diagnostic counter, then route only to the owning
            // per-vector handler if installed.
            crate::MSI_FIRES.fetch_add(1, Ordering::Relaxed);
            let idx = (v - hal_x86_64::VEC_MSI_POOL_FIRST) as usize;
            crate::irqstat::hit_line(idx);
            let raw = crate::MSI_HANDLERS[idx].load(Ordering::Acquire);
            if !raw.is_null() {
                // SAFETY: raw was installed via `register_msi_handler` with the documented `fn()` signature; reverse cast restores the ABI-compatible fn pointer.
                let f: fn() = unsafe { core::mem::transmute(raw) };
                f();
            }
            let _ = crate::invoke_x86_line_handler(v);
        }
        _ => { /* unknown vector -- EOI'd, fall through */ }
    }
    // Linux `irq_exit`: drop the hardirq field FIRST, then drain softirqs
    // (Linux `invoke_softirq`) — `do_softirq`'s `in_interrupt` guard must see
    // only the softirq field, so a nested IRQ inside an in-progress drain
    // still refuses to re-enter. Unconditional, so the count never leaks.
    sched::preempt::irq_exit();
    if softirq::pending() {
        // SAFETY: EOI issued above; LAPIC accepts the next IRQ; do_softirq's in_interrupt guard blocks re-entry; cli restores ISR masking before the vector epilogue.
        unsafe {
            core::arch::asm!("sti", options(nomem, nostack, preserves_flags));
            sched::bh::do_softirq();
            core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
        }
    }
}

/// IRQ-exit return-to-user reschedule slow path (`14§R07` / `smp-arch.md`
/// Phase A). Every IRQ stub calls this after the dispatcher returns,
/// passing the interrupted frame's saved CS. VOLUNTARY preempt: switch
/// only when returning to user mode (`CS&3==3`) AND a resched was
/// requested at a safe point (`preempt_count==0`, via
/// `should_resched_to_user`). The one `schedule()` performs the switch —
/// there is no IRQ-tail staging engine. `schedule()` preserves the IRQ
/// state of its caller (here the IRQ-exit context's IF=0), so on return
/// IRQs are still masked and the stub's pop+`iretq` tail is atomic (the
/// `iretq` restores the user IF from the frame).
///
/// # SAFETY: invoked only from the IRQ-exit asm with IRQs masked; the
/// interrupted scratch + iretq image live on the current kernel stack and
/// are restored by `oxide_irq_resume_user` after this returns (across the
/// `schedule()` switch, the stack is preserved by the saved Context).
/// # C: O(log N) when it schedules; O(1) otherwise
/// # Ctx: IRQ-exit
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
#[no_mangle]
unsafe extern "C" fn oxide_irq_resched_on_exit(saved_cs: u64) {
    let from_user = (saved_cs & 3) == 3;
    if sched::preempt::should_resched_to_user(from_user) {
        sched::preempt::take_need_resched();
        // SAFETY: IRQ-exit safe point — should_resched_to_user confirmed
        // preempt_count==0 and user-return; the interrupted frame is on the
        // stack and restored after schedule() returns. schedule() preserves
        // this context's IF=0, so IRQs stay masked through the iretq tail.
        unsafe { sched::live::schedule(); }
    }
}
