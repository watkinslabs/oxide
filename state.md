# State 2026-05-11

## Branch
`F04-serial-getty` — PR #1010 open. HEAD `6e57cba`.

## What shipped this run

1. **`bf8e5a5`** `fix(irq): ungate LAPIC/GIC bring-up (was hidden by debug-acpi)`.
2. **`94ced16`** `fix(irq): drop schedule_from_irq from timer ISR (cooperative-only)`.
3. **`6ac5a90`** `refactor(console): batch ONLCR writes — one console_emit per NL-free run`.

## CAT smoke wedge — investigation deepened, root cause still open

### New evidence (this session)

A dispatch-entry probe `klog::write_raw(b"[Dnr]")` at the head of
`oxide_syscall_dispatch` revealed the full syscall sequence per
iteration:

```
[D57][D61][D59][D1] yo\r\n          [D60]   (YO)
[D57][D61][D59][D1] hi\r\n          [D60]   (HI)
[D57][D61][D59][D0][D1] A           [D60]   (ECHO)
[D57][D61][D59][D2][D0][D1] Linux version...PREEMPT\r   ← STOPS HERE (CAT)
```

(57=fork, 61=wait4, 59=execve, 60=exit, 0=read, 1=write, 2=open.)

**After CAT's `sys_write` returns, NO further `[Dnr]` fires.**
sys_close-entry (`[D3]`) never enters dispatch. So sys_write returns
cleanly, but the *next* user-mode syscall instruction either never
fires or fails to reach `oxide_syscall_entry`.

### What's different about CAT vs ECHO

| | ECHO post-write | CAT post-write |
|---|---|---|
| Next syscall | `exit(0)` (nr=60) | `close(fd)` (nr=3) |
| Args setup | `xor %edi,%edi` | `mov %ebx,%edi` ← uses rbx |

### Hypothesis tested + rejected this session

- **rbx clobbered across syscall return**: patched `build_cat_blob`
  to use `%rbp` instead of `%rbx`. **Same hang byte-exact.** Not a
  rbx-specific clobber.
- Also disassembled `oxide_x86_arm_singlestep` — it correctly does
  `push %rbx` / `pop %rbx` on entry/exit. Rbx is preserved by that
  call.

### Other hypotheses still on the table

- **User code 3 instructions** between sys_write return and close
  syscall: `mov $3,%eax; mov %ebx,%edi; syscall`. If any of these
  faults silently (page-fault that's not classified as user-fault
  and gets eaten), we'd see exactly this signature.
- **Stack/SP corruption**: sysretq pops user RSP from saved frame.
  If RSP is wrong, the next `syscall` instruction would still fire
  (it doesn't depend on RSP) — so this can't be RSP alone. But the
  user `mov` instructions do read code from RIP — if RIP-relative
  fetch faults, page-fault not classified, we'd wedge.
- **Syscall-entry asm wedge specifically when prior syscall was
  ConsoleInode::write of a long buffer**: maybe `OXIDE_SYSCALL_KSTACK`
  or `OXIDE_SYSCALL_USER_RSP_SAVE` got corrupted by sys_write's body
  (e.g. stack overflow from the 56-byte ONLCR loop's nested calls).

### Probes that DO unwedge

`klog::write_raw(b"[CLOSE]\\n")` at sys_close head AND
`b"[EXIT]\\n"` at sys_exit head together let boot proceed past CAT.
Adding the [Dnr] probe alone does NOT unwedge. Adding [W_OUT] at
sys_write exit alone does NOT unwedge.

So the unwedge happens specifically when sys_close *body* emits
bytes. Implication: sys_close entry IS reached, but only completes
when its body emits. That's contradictory unless the wedge is
*after* sys_close runs and the [CLOSE] probe acts as a yield point
that lets a subsequent path drain.

This contradicts the [Dnr] finding (no [D3] without close probe).
Reconciling: maybe Rust's link-time optimization inlines sys_close
into dispatch differently across builds, changing where the actual
syscall body executes. Need to disassemble `oxide_syscall_dispatch`
in both probe-on and probe-off builds to compare.

## First task next session

Two cheap probes that should bisect the remaining ambiguity:

1. **Probe in sys_close head, NO probe in dispatch.** Confirm
   whether sys_close head is reached without the dispatch probe.
   If yes → [Dnr] trace was misleading (maybe inlined elsewhere).
   If no → dispatch isn't reaching the match arm for nr=3.

2. **Disassemble built kernel both ways** (`objdump -d` filtered to
   `oxide_syscall_dispatch`) and diff. Look for whether the nr=3
   arm exists, and whether sys_close is inlined.

```sh
# Build current state (no probes)
cargo run -p xtask -- image --arch x86_64 --features debug-boot
objdump -d target/x86_64-unknown-oxide-kernel/release/oxide-x86_64 \
  | sed -n '/oxide_syscall_dispatch>:/,/^$/p' > /tmp/dispatch-noprobe.s
# Add probe to sys_close head, rebuild, dump again, diff.
```

## Open work (carried)

- **Init silent post-CAT** — addressed after CAT wedge.
- **Display + input on GTK** — `OXIDE_QEMU_HEADLESS=1` skips GTK;
  block-glyphs + dead virtio-input are separate.
- **Real PTRACE_SINGLESTEP** — F49-F51 framework; SIGSTOP/SIGTRAP race.

## Useful pointers

- Dispatch + sys_close + sys_exit: `kernel/src/syscalls/mod.rs:522,133,350`.
- Syscall asm save/restore (rbx confirmed): `crates/arch/hal-x86_64/src/syscall.rs:123,169`.
- ConsoleInode batched write: `kernel/src/dev/console.rs:84`.
- CAT smoke at `kernel/src/smoke/elf.rs:254` (build_cat_blob); fd→`%rbx` at offset 16.
- VERSION_BODY (56 bytes): `kernel/src/procfs/mod.rs:269`.
- Headless boot: `OXIDE_QEMU_HEADLESS=1 make qemu-x86`.
