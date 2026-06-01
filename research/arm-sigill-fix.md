# Implementation recipe: catchable synchronous-fault SIGILL (aarch64 + x86)

Unblocks openssl/libcrypto on arm (→ systemd-on-arm). Root cause: openssl 3.0
`OPENSSL_cpuid_setup` (.init_array) SIGILL-probes armv8.2 crypto insns cortex-a72
lacks → EL0 ESR.EC=0 undefined-instruction → kernel halts (no EC=0 handling) → hang.
Fix = deliver a CATCHABLE SIGILL (invoke the task's sa_handler) so the probe's
handler siglongjmps and continues. Mirror existing softstep (EC=0x32) plumbing.

## aarch64

1. `crates/arch/hal-aarch64/src/vbar.rs` `oxide_lower_el_sync_handler`: after the
   `cmp x9, #0x32 / b.eq oxide_softstep_save_block`, add:
   `cmp x9, #0` / `b.eq oxide_undef_save_block`.
   Add `oxide_undef_save_block` = byte-for-byte copy of `oxide_softstep_save_block`
   (pop 16B preamble→restore x9; sub sp #288; save x0..x28 + elr/spsr/sp_el0;
   `adrp/str oxide_svc_frame_base`) but `bl oxide_arm_undef_handler` instead of
   the softstep hook; then `str x0,[sp,#0xc8]` / `b oxide_lower_sync_restore`.
   (lower_sync_restore msr's elr_el1/sp_el0 from frame + `ldr x0,[sp,#0xc8]` → x0.)

2. New hook in `crates/kernel/fs/src/ptrace.rs` (sibling of
   `oxide_arm_software_step_handler`, fs crate has sched + sig_dispatch):
   ```
   #[no_mangle] pub unsafe extern "C" fn oxide_arm_undef_handler(frame_ptr:*mut u8)->u64 {
     hal_aarch64::set_current_svc_frame(frame_ptr as u64);
     let cur = sched::live::current()...;
     let h = (&*cur.sigactions.get())[3];  // SIGILL=4 → index 3
     let saved_x0 = (&*(frame_ptr as *const hal_aarch64::SvcFrame)).gp[0];
     if h.handler != SIG_DFL && h.handler != SIG_IGN {
        sig_dispatch::deliver(h.handler, h.restorer, 4 /*SIGILL*/, saved_x0); // rewrites elr_el1→handler
        return 4;  // → retval slot → x0=SIGILL at handler entry
     }
     // default: SIGILL = core+terminate. Mirror sigsegv_terminate_arm but exit_status=4
     // (coredump(4); mark Zombie ws=4; schedule away — diverges).
   }
   ```
   Declare `extern "C" { fn oxide_arm_undef_handler... }` near the softstep decl.

3. x86 mirror (`crates/arch/hal-x86_64/src/fault.rs` `oxide_fault_print_rust`):
   for `vec==6` (#UD) from CPL=3 (user), if SIGILL handler registered →
   `deliver_x86(handler, restorer, 4, saved_rax)` + arrange x86 retval=4; else
   terminate (sigsegv_terminate-style, signal 4). Don't disturb the elf-smoke ud2
   landmark handler (it checks specific RIPs first).

## Verify
- Un-gate openssl_probe on arm in `tools/xtask/src/assets/oxide-smokes.sh` (rebuild
  xtask), boot arm → expect `openssl_probe: ... rv=0` (cpuid_setup probes caught).
- Then REMOVE the arm gate (run on both arches); update TASKS.md (blocker RESOLVED).
- Both-arch boot gate; spec-lint; read docs/54 before touching the asm.
- Hosted test if feasible: synthetic EC=0 frame → oxide_arm_undef_handler delivers.

## Gotchas
- **CRITICAL — stale svc_frame slot:** `deliver_arm` (sig_dispatch.rs:285) reads the
  per-task `c.svc_frame` slot (F206), falling back to the global. On an EC=0 FAULT
  that slot still holds the *last syscall's* SVC frame → deliver_arm would rewrite the
  WRONG frame. So `oxide_arm_undef_handler` MUST, before calling `sig_dispatch::deliver`:
  `cur.svc_frame.store(frame_ptr, Release)` AND `hal_aarch64::set_current_svc_frame(frame_ptr)`.
  Then deliver_arm rewrites the EC=0 frame; the lower_sync_restore epilogue eret's to
  the handler. (The EC=0 frame is byte-identical to the SVC frame because the save
  block is copied from softstep, so `SvcFrame` accessors are valid on it.)
- REJECTED shortcut: rebuilding arm openssl `no-asm` (skips cpuid SIGILL-probe) — that
  masks a real kernel gap (Linux delivers catchable SIGILL on undefined instructions;
  userspace relies on it). Do the kernel fix.
- musl sets sa_restorer (`__restore_rt`); PendingSignal.restorer = h.restorer.
- openssl's SIGILL handler siglongjmps (doesn't return) → won't re-hit the undef insn;
  but a clean impl still supports rt_sigreturn (rt_sigreturn_arm already works).
- SIGILL default = core (not ignore) — terminate path must kill, not resume.
