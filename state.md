# state — hand-off

Branch: B24-makefile-comma-order (PR pending)
Previous: B22-sig-deliver-mask-and-arm-offset → PR #1018 merged

## Closed in this stretch

- B21 (PR #1017) — `Ext4FileInode` lazy reads + real `sys_newfstatat`.
- B22 (PR #1018) — ARM signal-dispatch: mask delivered signal on
  handler entry, fix `rt_sigreturn_arm` SP offset (40→32) since
  AArch64 `ret` doesn't pop, grow `SIG_FRAME_BYTES` 40→48 to keep
  handler entry SP 16-aligned.

## B24 contents

1. `Makefile`: `comma := ,` was declared *after* `QEMU_FEATURES_*`
   so `:=` expansion produced literal `debug-bootdebug-irq` when
   `FEATURES=debug-irq` was passed. Move `comma :=` above the
   feature vars.
2. Strike the "stray SIGSEGV at tid≈4112, far≈0x7ffffffbf000"
   open item from the previous hand-off — it's `mprotect_smoke`
   deliberately writing to a `PROT_READ` page, and the test
   reports PASS on the next line. Not a bug.

## First task next session

Pick up the next phase per `docs/00§3` master plan. ARM and x86
both reach `oxide login:` and run `uname`/`ls`/`ps` post-login.
