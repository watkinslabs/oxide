# State 2026-05-11

## Branch
`B13-execve-trace` — PR pending. Fixes the long-running rcS wedge (B12).

## What shipped this run

**Syscall asm bug fix.** `oxide_syscall_entry` restored user-ABI arg
regs (rdi/rsi/rdx/r10/r8/r9) from the saved frame, then immediately
called `oxide_x86_arm_singlestep` as a SysV C function. AMD64 SysV
allows the callee to clobber those registers — so after sysretq,
userspace saw garbage `rdi` (and friends) on every syscall.

Most code didn't notice because the user side rarely uses `rdi` as
state after a syscall. But musl's `open()` wrapper sign-extends the
returned fd into `rdi`, optionally syscalls `fcntl(F_SETFD,
CLOEXEC)`, then calls `__syscall_ret(rdi)`. After the F_SETFD path,
`rdi` returned as a kernel-pointer-like value > -4096, so
`__syscall_ret` interpreted it as a negative errno, returned -1, and
set errno to garbage. The busybox `xopen` wrapper then printed
`"can't open '%s': %m"` — exactly the rcS error.

Fix (`crates/arch/hal-x86_64/src/syscall.rs`): save the 6 user-arg
regs across the singlestep C call by pushing them onto the kernel
stack before, popping after. Layout for the rflags pointer adjusted
accordingly (`+0x40` instead of `+0x10`).

After the fix the trace shows hush successfully opening rcS,
F_DUPFD_CLOEXEC dup'ing fd=3→10, reading the 308-byte script, and
fork+exec'ing the mount/hostname/ifconfig commands inside rcS.

## Verified at boot

- `cargo run -p xtask -- spec-lint` clean.
- x86_64 build green.
- aarch64 build green.
- x86 qemu boot reaches rcS execution past the prior `"can't open"`
  hang; hush runs the script line-by-line.

## Open work

### Login prompt visibility
After rcS, getty should print `oxide login:`. Wall-clock to that
point under qemu-mcp can exceed 90s — not investigated yet whether
that's slow boot or a downstream stall. Try a longer pattern wait or
add a kernel breadcrumb after rcS completes.

### Display visibility on GTK (parked)
B07/B08 path proven; rendered output through interactive QEMU still
requires GTK driver which qemu-mcp can't drive.

### Serial input doesn't echo (parked)
Likely getty-side; revisit after the login-prompt check.

## Followups ready to stack

- Same asm-clobber audit on aarch64 SVC entry (`crates/arch/hal-aarch64/src/svc.rs`):
  the SVC dispatch pattern may have the same issue if any C call
  happens between arg-reg restore and `eret`. Read the entry asm and
  add the same save/restore if needed.
- F03+ keymap follow-ups (mouse drain, `loadkeys` helper).

## First task next session

```sh
# Push B13 to origin and open PR.
git push -u origin B13-execve-trace
gh pr create --title "fix(syscall-x86): preserve user-ABI args across singlestep C call" \
  --body "..."

# After merge: audit aarch64 SVC entry for the same clobber pattern.
```

## Useful pointers

- Bug: `crates/arch/hal-x86_64/src/syscall.rs:175-205` (the
  `add rsp, 0x38` → `push rax` → singlestep call block).
- musl open() reproducer: any `open(path, O_RDONLY|O_CLOEXEC)`.
- busybox source path: `vendor/busybox/busybox` (statically linked).
