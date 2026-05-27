# 54 — Assembly + low-level ABI correctness checklist

DRAFT 2026-05-26. Dep: 20, 21, 13, 15, 27.

Covers BOTH x86_64 and aarch64. Per-arch rows are marked in the
**Arch** column (`x86`, `arm`, `both`). Every kernel-side asm-sub
patch must satisfy this checklist before merge. Each row links to
the upstream patch that surfaced the class so future-you can read
the actual mistake instead of repeating it.

## 1 Register clobbering before save

| ID | Arch | Pattern | Patch |
|---|---|---|---|
| 1.1 | arm | Reading a system register (e.g. `mrs x9, esr_el1`) into a user-owned reg BEFORE the save block copies that reg to the frame. Result: user reg permanently clobbered across resolved-and-retried faults. | F204 / `#1286` — `oxide_lower_el_sync_handler` overwrote x9 with ESR.EC; broke dropbear-aarch64's `sha256_compress` retry-after-demand-page. |
| 1.2 | arm | Using x9 / x10 / x16-x17 as scratch in an EL1 stub WITHOUT saving them to a stack preamble first. Same class as 1.1. | F204. |
| 1.3 | arm | TPIDR_EL1 reserved for the per-CPU base pointer (`21§7`); never use it as a scratch sysreg. Use a 16-byte stack preamble instead. | F204 comment. |
| 1.4 | x86 | `r12`–`r15` and `rbx`/`rbp` are user callee-saved; an asm stub that clobbers them across `bl`/`call` must push first. | P5-10 / B04. |
| 1.5 | x86 | `mov r12, rsp` to stash user RSP corrupts user r12. Use a per-CPU mem slot (see `oxide_syscall_entry`'s `OXIDE_SYSCALL_USER_RSP_SAVE`). | P5-10. |
| 1.6 | both | Any recoverable-resume asm stub MUST save+restore the FULL caller-saved set BEFORE calling Rust. Memorize: skipping one of {rax,rcx,rdx,rsi,rdi,r8-r11} on x86 or {x0..x18} on arm silently breaks any retry path. | `feedback_register_safety.md` user-memory; #172 era. |

## 2 Syscall ABI plumbing

| ID | Arch | Pattern | Patch |
|---|---|---|---|
| 2.1 | both | Standard SysV-ABI `extern "C"` dispatch fn fits only nr + 5 args in regs. Linux syscalls take up to 6 user args (a0..a5). Always read a5 from the arch save block via `crate::syscalls::syscall_a5::read()`. | F205 — `sys_pselect6`'s sigmask_pair was silently dropped on both arches. |
| 2.2 | arm | ARM SVC entry shuffles args into the Linux SVC ABI convention (`x0=nr, x1..x5=a0..a4`). Verify the ORIGINAL `x0..x5` are saved BEFORE the shuffle. | F204 + F205 — same save block. |
| 2.3 | arm | SVC restore on ARM finishes with `ldr x0, [sp, #0xc8]`, clobbering whatever `frame.gp[0]` held. For signal-handler invocation you must return `sig` from `oxide_syscall_dispatch` so the retval slot seeds user x0 = handler's first AAPCS64 arg. | F205 — dropbear-aarch64 handler saw x0 = stale syscall retval, fell into the wrong cmp branch. |
| 2.4 | x86 | x86_64 syscall ABI: user a3 in r10 (NOT rcx — rcx holds the user RIP post-syscall-insn). The entry stub must move r10→a3 BEFORE calling Rust. Check the saved-arg block at `[rsp+0x20]` is r10's value. | Pre-F205 baseline; documented at `oxide_syscall_entry`. |
| 2.5 | x86 | x86_64 syscall ABI preserves user `rcx` (= user RIP) and `r11` (= user RFLAGS) semantics. Both must be restored across the syscall. | Pre-F205 baseline; documented at restore epilogue. |

## 3 Signal frame layout

| ID | Arch | Pattern | Patch |
|---|---|---|---|
| 3.1 | both | The saved rt_sigframe MUST live AT OR ABOVE the handler's entry SP. Handler's own stack grows below new_sp; placing the frame below it lets the handler trample magic / saved_rip / saved_rsp / saved_rflags. | F203 / `#1285`. |
| 3.2 | x86 | x86_64 ABI: also skip the 128-byte red zone below the interrupted SP before allocating the frame. | F203. |
| 3.3 | x86 | After `call`, `(rsp+8) % 16 == 0`. The restorer slot at `[new_rsp+0]` plays the role of the pushed return address — `new_rsp` must satisfy `new_rsp % 16 == 8` at handler entry. | F203 `deliver_x86`. |
| 3.4 | arm | ARM `ret` is `br lr` — no stack pop. The handler returns via x30 = restorer (no on-stack return slot needed). AAPCS64 requires `sp % 16 == 0` at every public function entry. | F203 `deliver_arm`. |
| 3.5 | both | `deliver_<arch>` ORs the delivered sig bit into `sigmask`. `rt_sigreturn_<arch>` MUST restore mask from the saved sigmask slot, or the bit stays set forever and every subsequent sigprocmask cycle propagates it via musl's `__block_all_sigs` / `__restore_sigs`. | F205. |

## 4 Per-fd state lifecycle

| ID | Pattern | Patch |
|---|---|---|
| 4.1 | Pipe writer/reader counts must track LIVE File objects, NOT live Arc<File> refs. `fork_clone` bumping Arc refcount without bumping pipe writers is fine; the count only decrements on File::drop (close hook). NEVER add a clone-side hook to "balance" — that creates an asymmetric over-count. | F205 — early debug attempt; reverted. |
| 4.2 | Exactly ONE close hook may decrement pipe writers/readers. If two subsystems each call `pipe.writers.fetch_sub(1)` on every File::drop you get a double-decrement → underflow on first close. | F205 — inotify's `vfs_close_notify` was duplicating pipe.rs's `pipe_close_hook` decrement. |
| 4.3 | `sys_exit` MUST drop the exiting task's fd_table Arc before mark_done. Linux closes a process's files in `do_exit → exit_files`; without it the pipe write-end File doesn't drop until wait4-reap, and pipe POLL_HUP never propagates. | F205. |

## 5 Magic numbers (CLAUDE.md `07§5`)

| ID | Pattern | Patch |
|---|---|---|
| 5.1 | Signal numbers: NEVER use bare `17`, `23`, `28`, `11`, `7`, etc. in match-arms or comparisons. Use `sched::live::sigpend::Signum::SigXyz` — see `01§4`. Linux uapi assignments differ per arch on some signals; the enum is the single source of truth. | F205 — magic literals in `signal_dispatch::dispatch_pending` got caught at review. |
| 5.2 | SIG_DFL / SIG_IGN sa_handler values are `0` / `1` per Linux uapi. Use named consts at the call site, not bare literals. | F205. |
| 5.3 | Errno values: `Errno::Echild.as_i32() as i64` not `-10`. Syscall slots: `syscall::nrs::NR_FOO` not bare integers. Open flags: `OpenFlags::FOO`. All per `01§4` + CLAUDE.md `07§5`. | Pre-F205 baseline. |

## 6 Tooling

| ID | Lesson | Workflow |
|---|---|---|
| 6.1 | PL011 UART chardev on ARM saturates faster than QEMU drains it. `debug-sched` floods the boot log AND post-boot activity; per-subsystem `debug-XXX` features stay log-coherent. | F205 introduced `debug-ssh`. |
| 6.2 | `grep -a` on `/tmp/qa.log` — UEFI boot lines contain bytes that make grep mis-detect binary. | F205. |
| 6.3 | Use the qemu MCP (`mcp__qemu__qemu_start` etc.) for guided single-step debugging — don't punt to "human-in-the-loop". | CLAUDE.md§autonomous-run-discipline. |

## 7 Procedure for new asm patches (both arches)

1. Read **this file** end to end.
2. Write the asm change.
3. Audit it against §1 (reg clobber-before-save) — pick the row for
   the arch you're touching.
4. If the change touches the syscall path, audit against §2.
5. If the change touches signal delivery, audit against §3.
6. Add a `# C:` doc-comment per `09§6`.
7. Build with `--features debug-ssh` and verify the targeted trace
   shows the path you intended.
8. Run `make smoke` BOTH arches.
9. Run the SSH end-to-end repro from `state.md` — `echo HELLO; id`
   must complete in `<10 s` exit 0 on BOTH arches.
