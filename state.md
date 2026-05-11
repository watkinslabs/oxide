# State 2026-05-11

## Branch
`F04-serial-getty` — PR #1010 open. HEAD `02936ea`.

## What shipped this run

1. **`bf8e5a5`** `fix(irq): ungate LAPIC/GIC bring-up (was hidden by debug-acpi)`.
2. **`94ced16`** `fix(irq): drop schedule_from_irq from timer ISR (cooperative-only)` — closes the iretq-frame-gap exposure introduced by (1).
3. **`02936ea`** `doc(state)` handoff.

## Critical finding — syscall-return register clobber suspected (NEXT)

Probing `sys_close` + `sys_exit_group` head with a one-line
`klog::write_raw(b"[CLOSE]\\n")` / `b"[EXIT]\\n"` **unwedges the CAT
smoke**:

Without probes — trace stops at:
```
yo\r\nhi\r\nALinux version 5.15.0-oxide (oxide@build) #1 SMP PREEMPT\r
```

With probes — full pipeline runs:
```
yo\r\n[EXIT]\nhi\r\n[EXIT]\nA[EXIT]\nLinux version 5.15.0-oxide ...PREEMPT\r\n[CLOSE]\n[EXIT]\n[EXIT]
```

Note: the final `\r\n` of VERSION_BODY now comes out cleanly, then
[CLOSE] (CAT's close fd), then two [EXIT]s (CAT child, smoke parent
final exit). After that — silence for 60s. Init likely never runs
or never makes a syscall.

**Diagnosis:** Any syscall-head klog probe acts as a yield/serial-
flush point that lets the next instruction land cleanly. Most likely
root cause is a register-preservation bug in the syscall return path
— similar to PR #460 / #1009 (`r12`, `rdi..r9`). With probes off,
the syscall return path corrupts a user reg the CAT child needs (e.g.
`%rbx` carries the open() fd from line 16-17 in build_cat_blob and
must survive write+close).

**Probes reverted** — they're band-aids and would violate the
`klog-must-be-cfg-gated` rule (CLAUDE.md/R06). Re-apply locally if
needed for next-session debugging.

## First task next session

Audit syscall save/restore for `%rbx` (and other SysV callee-saved):

```sh
grep -n 'rbx\|rbp\|r12\|r13\|r14\|r15' crates/arch/hal-x86_64/src/syscall.rs
```

The CAT smoke does:
```
mov %eax, %ebx       ; save fd from open into rbx
... read ... write ...
mov %ebx, %edi       ; reload fd for close
mov $3, %eax
syscall              ; close
```

If sys_write's return path clobbers `%rbx` (or the singlestep C-call
fix from #1009 misses rbx), close gets a garbage fd → maybe parks
the task on a fd lookup that sleeps. Verify by:
1. Reading syscall entry asm — confirm rbx is in the
   saved-frame block.
2. Re-adding the probes briefly and tracing close's actual fd arg.

If that's not the cause, fall back to the close/exit probe approach:
add `klog::write_raw` (or `debug_syscall!`) head probes, gate them
under `debug-syscall`, repeat to narrow.

## Open work (carried)

- **Init silent after CAT smoke** — even with probes, no `[EXIT]` from
  init/rcS within 60s. Maybe spawn failed silently, maybe rcS-side
  syscalls also wedge.
- **Display + input on GTK** — `OXIDE_QEMU_HEADLESS=1` skips GTK;
  block-glyphs (fbcon font) + dead virtio-input are separate.
- **Real PTRACE_SINGLESTEP** — F49-F51 framework; SIGSTOP/SIGTRAP race.

## Useful pointers

- Syscall asm save/restore: `crates/arch/hal-x86_64/src/syscall.rs:~175-205`.
- CAT smoke at `kernel/src/smoke/elf.rs:254` (build_cat_blob); the
  `mov %eax, %ebx` is at code offset 16-17.
- VERSION_BODY (56 bytes): `kernel/src/procfs/mod.rs:269`.
- ConsoleInode::write ONLCR loop: `kernel/src/dev/console.rs:84`.
- Headless boot: set `OXIDE_QEMU_HEADLESS=1`.
