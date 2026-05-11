# State 2026-05-11

## Branch
`F04-serial-getty` — PR #1010 open. HEAD `32d9a59`.

## What shipped this run

1. **`bf8e5a5`** `fix(irq): ungate LAPIC/GIC bring-up (was hidden by debug-acpi)`.
2. **`94ced16`** `fix(irq): drop schedule_from_irq from timer ISR (cooperative-only)`.
3. **`6ac5a90`** `refactor(console): batch ONLCR writes — one console_emit per NL-free run`.
4. **`32d9a59`** `fix(uart): bounded spin in Uart16550::write_byte (drop byte on cap)` — guards against QEMU host pty back-pressure that would deadlock the boot CPU under lock_irqsave.

## CAT smoke wedge — decisive bisect this session

Inserted an `int3` (0xCC) in the user-mode CAT_BLOB at the mov-$3
position right after the write syscall. A successful sysret would
land user RIP on that int3 → #BP from CPL=3 → fault handler emits
`[FAULT] vec=3` via debug_irq. **No `[FAULT]` line appeared.**

So sysret after CAT's sys_write **does not return to user mode**.
The wedge is in kernel mode somewhere between the sys_write body
completing and the user-mode RIP being resumed.

Also added a heartbeat probe (`klog::write_raw(b".")` every 500
timer ticks) in `oxide_irq_dispatch`'s VEC_TIMER arm. **No dots
appeared post-wedge.** So the timer IRQ never fires either — the
CPU is either spinning with IRQs masked (lock_irqsave) or in some
state preventing the timer from delivering.

Combined with the dispatch-entry [Dnr] probe (which showed `[D3]`
never fires for close), the picture is:
- CAT's sys_write body emits all but the last byte of `/proc/version`
- Something between that and the sysret stalls the kernel
- Timer IRQs masked (lock_irqsave or IF=0 deadlock)
- No fault visible

### Hypotheses tried + rejected this session

| Theory | Test | Result |
|---|---|---|
| %rbx clobber across syscall | Patched CAT to use %rbp | Same hang byte-exact |
| Per-byte UART lock contention | Batched ONLCR (`6ac5a90`) | Same hang |
| Timer-IRQ→schedule corruption | Neutered (`94ced16`) | Same hang |
| Smoke iter reorder | Removed iter 4 from build_elf | Wedged EARLIER on HI |
| 16550 FIFO back-pressure | FCR=0 | Same hang |
| UART back-pressure deadlock | Bounded spin (`32d9a59`) | Same hang, no fault |
| User-mode RIP wrong after sysret | int3 in CAT post-write | int3 didn't fire (sysret didn't deliver) |

### Strongest remaining suspicion

The dispatch disasm shows `oxide_syscall_dispatch` builds the
`SeccompData` struct on a 0xe8-byte stack frame regardless of
seccomp state. With four nested fork/execve frames + the smoke
ELF run_as_task frame + the syscall asm save block + the dispatch
frame + ConsoleInode::write's batched ONLCR locals + klog +
boot_emit + write_bytes loop + write_byte, we may be overflowing
the per-task kernel stack — probably 4 KiB if it's a single page.

Stack overflow during sys_write would page-fault on a guard page
or unmapped address. The fault handler would try to klog — which
takes BOOT_UART under lock_irqsave that the outer boot_emit may
already hold → deadlock with no log emitted.

### First task next session

1. **Check per-task kernel stack size.** Grep `KSTACK` / `kernel_stack`
   in `crates/kernel/sched/src/task.rs` + spawn paths. If it's one
   page (4 KiB), bump to 16 KiB and re-test.
2. **If kstack is already big, check whether sys_write's call chain
   has a recursion or large stack-array.** ConsoleInode::write batched
   variant is small. klog::__klog_emit constructs an InternedFormat
   header — small. boot_emit is small. The seccomp prologue's
   `SeccompData` on stack is ~0xe8 bytes per dispatch.
3. **If neither helps, add a probe at the kernel-stack guard.** Page-
   fault from kernel mode on a guard address should fire `[FAULT]
   vec=14 ... U/K=K`. Currently the fault handler's `[FAULT]` print
   path itself recurses into klog → boot_emit, which would deadlock
   if the outer holder is still there. Need a panic-emit that
   bypasses klog (write straight to UART without taking the lock).

## Open work (carried)

- **Init silent post-CAT** — surfaces only after CAT unwedge.
- **Display + input on GTK** — `OXIDE_QEMU_HEADLESS=1` skips GTK.
- **Real PTRACE_SINGLESTEP** — F49-F51 framework; SIGSTOP/SIGTRAP race.

## Useful pointers

- UART bounded spin: `crates/arch/boot-x86_64/src/uart.rs:124-140`.
- Syscall asm save/restore (rbx confirmed): `crates/arch/hal-x86_64/src/syscall.rs:123,169`.
- Syscall dispatch (seccomp prologue 0xe8 stack): `kernel/src/syscalls/mod.rs:522`.
- ConsoleInode batched write: `kernel/src/dev/console.rs:84`.
- klog write_raw → boot_emit: `crates/shared/klog/src/lib.rs:289` → `crates/arch/boot-x86_64/src/lib.rs:72`.
- Fault handler print path (may deadlock if BOOT_UART held): `crates/arch/hal-x86_64/src/fault.rs:327`.
- CAT smoke at `kernel/src/smoke/elf.rs:254` (build_cat_blob); fd→`%rbx` at offset 16.
- Headless boot: `OXIDE_QEMU_HEADLESS=1 make qemu-x86`.
