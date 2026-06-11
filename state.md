# state — session hand-off

Branch: B93-ap-syscall-msrs (PR pending). **x86 SMP=2 now boots to login.**
Roadmap: vty-plan.md.

## Landed this session
- **B92 (#1746, merged):** unified wait4 child-selection predicate
  (`registry::wait_pid_matches`, -1/0/+tid/-pgid) for reap_one/peek_one +
  take_child_stop_event; closed pid==0/pid<-1 reap gap (waitid(P_PGID)) and the
  take_child_stop_event vpid-vs-tid bug. 5 host tests. The "console zombie"
  bug was a MIS-DIAGNOSIS — reaping is proven correct (see
  [[project_console_zombie_resolved]]).
- **B93 (this branch): x86 AP CPU-state parity — the real SMP bug.** The AP
  (`ap_main_x86`) brought up GDT/IDT/LAPIC/runqueue/TSS but NEVER enabled two
  per-CPU CPU features the BSP enables at `_start_rust`:
  1. **syscall MSRs** (`install_syscall_msrs`: EFER.SCE/STAR/LSTAR/SFMASK) →
     a task doing `syscall` on the AP, or migrating + `sysretq`-ing there, #UD'd.
  2. **SSE/FPU** (`enable_sse`: CR0.MP, CR4.OSFXSR|OSXMMEXCPT) → the first SSE
     insn a user task ran on the AP (`pxor`/`movups` — musl uses them
     everywhere) #UD'd → unrecoverable → AP halted in `oxide_fault_common` →
     boot wedged after "Started Console Getty".
  Both now called in `ap_main_x86` after the GDT load. **Verified SMP=2:
  `online=2`, login reached, #UD=0, no CPU-STALL, console-getty alive.**
  Likely also fixes the documented "systemd exits ~25% right after keymap"
  flaky race (that was a process hitting the SSE #UD on the AP).
- Added `OXIDE_QEMU_GDB=1` (image_qemu.rs) → gdb stub on :1234 for per-CPU
  inspection (this is how the SSE gap was pinned: gdb showed AP CR4=0x10020 vs
  BSP 0x10620). `=wait` also passes -S.

## Diagnosis method that worked (use it for SMP)
The in-kernel serial-sysrq task dump (`<NUL>t`) is unreliable when a CPU is
halted (UART not polled). **GDB is the tool:** `OXIDE_QEMU_GDB=1 make qemu-x86
SMP=2 ...`, boot to the wedge, then `gdb -batch` → `target remote :1234` →
`info threads` + per-vCPU `bt`/`p $cr0`/`p $cr4`. ELF =
target/x86_64-unknown-oxide-kernel/release/oxide-x86_64. Scripts:
/tmp/smp_gdb.sh, /tmp/smp_verify.sh (one-shot boot + login/UD/stall check).

## FIRST THING NEXT SESSION
1. Land B93: spec-lint clean; commit + push (pre-push hook runs SMP=2 smoke
   both arches). If hook passes, PR + merge.
2. Re-confirm SMP=2 reliability over a few boots (the ~25% systemd-exit race
   may or may not be fully gone). If a residual flake remains, gdb the wedge.
3. Then revisit: 100% CPU with ≥2 htops (poll-spin, present on UP too —
   007_poll.rs RESCAN fallback; wire vt_tty/poll wakeups so poll sleeps full
   timeout). This is the next SMP/poll item.

## Harness hygiene (cost me time this session)
- ALWAYS `pkill -9 -x qemu-system-x86_64` + confirm `fuser
  kernel/blobs/root-x86_64.img` is free before booting — overlapping qemus
  fight the root-img write lock ("Failed to get write lock"). Orphaned qemus
  reparent to the agent process; kill by exact name.
- Dev shell is `set -e`: guard kill/fuser chains with `|| true` or they abort.
- x86 serial = stdio; hold the FIFO writer open (fd or `sleep infinity`) or
  qemu sees EOF and stops reading input.

## Discipline
- THE LINUX WAY; no blind sched/MM patches. spec-lint clean + both arches every
  PR. Memories: project_console_zombie_resolved, feedback_verify_left_no_bolton.
