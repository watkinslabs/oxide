# Session hand-off

## Headline
**L2 systemd shared-lib tree COMPLETE (17 deps).** Starting **Track D6 — systemd**.
Branch: `main` clean @ #1455. Next branch: D6 work.

## Done this session (merged)
- B51 #1447 — bounded-retry boot gate (`tools/boot-smoke.sh`, OXIDE_SMOKE_ATTEMPTS=3) for the ~25% SMP getty/login flake; trimmed redundant CAT boot-smoke iter.
- L2 deps (C40 `tools/xtask/src/l2_deps.rs` data-driven table — adding a dep = 1 row in L2_LIBS + 1 in L2_PROBES + build.sh/fetch/probe/rcS/gitignore):
  expat #1448, dbus #1449, libgpg-error #1450, libgcrypt #1451, attr+acl #1452, kmod #1453, openssl #1454, libunistring+libidn2 #1455.
  Earlier-merged: libcap, libxcrypt, util-linux libs, libseccomp, zstd, lz4, pcre2.
- F345 also bumped rootfs 32→128 MiB (`main.rs` count=128) + disk/ESP 64→512 MiB (`image_qemu.rs` count=512): the L2 libs overflowed the embedded-rootfs kernel/ESP (rootfs is `include_bytes!`'d into the kernel → bigger rootfs = bigger kernel = bigger ESP need).
- `dyn_probe` adds `-rpath-link` for every L2 vendor libdir (cross-vendor transitive DT_NEEDED on strict arm ld).

## Open work — D6 systemd (do in order)
1. **DONE (F347): aarch64 catchable synchronous-fault SIGILL** — arm EL0 EC=0 undefined-instruction → `oxide_undef_save_block`→`oxide_arm_undef_handler`→`sig_dispatch::deliver` catchable SIGILL. openssl loads on arm (`openssl_probe rv=0` + login, boot-verified); openssl_probe un-gated both arches. Follow-up: x86 #UD parity mirror (x86 openssl already worked). REMAINING old context below:
   **(superseded)** fix aarch64 synchronous-fault catchable signals (TASKS.md BLOCKER row — ROOT-CAUSED this session). The arm "libcrypto load hang" = openssl `OPENSSL_cpuid_setup` (.init_array) SIGILL-probes armv8.2 crypto insns cortex-a72 lacks → EL0 ESR.EC=0 undefined-instruction → `user_as.rs:526 user_fault_handler` doesn't handle EC=0 → vbar HALTS → hang. Fix: (1) handle EL0 EC=0 undefined insn; (2) deliver it as a CATCHABLE SIGILL (invoke registered handler + sigreturn), NOT terminate — wire synchronous faults through the existing `sys_kill` handler-dispatch path (P3-66) instead of `sigsegv_terminate_arm`. Mirror x86. This unblocks openssl (→ systemd) on arm. (qemu-mcp can't repro interactively — arm TCG+gdb boot >120s tool timeout, only reaches UEFI; use kernel klog / a targeted EC=0 trace instead.)
2. Vendor systemd 259: `tools/fetch-systemd.sh` + `vendor/systemd/build.sh` meson cross `-Dlibc=musl`, cross file for aarch64, disable optional dlopen feats (tpm2/libfido2/pwquality/p11kit/libcryptsetup/bpf-framework/microhttpd/qrencode/gnutls=false), enable kmod/seccomp/openssl/gcrypt/blkid/acl, pkg-config → `vendor/*/install-<arch>`, `-idirafter /usr/include` (x86 UAPI). Land incrementally (libsystemd-shared → pid1 → units).
3. systemd is BIG → rootfs WILL exceed 128 MiB → bump rootfs(`main.rs`)+ESP(`image_qemu.rs`) together. Embedded-rootfs grows the kernel + slows arm TCG boot → if arm boot exceeds the 300s smoke timeout, bump the arm timeout (`.githooks/pre-push`) OR move rootfs off `include_bytes!` onto the attached virtio-blk disk (the proper scaling fix).

## First command (next session)
Read TASKS.md BLOCKER row, then qemu-mcp arm libcrypto-load-hang diagnosis (step 1 above).

## CRITICAL harness rules
- Both-arch boot gate via **backgrounded PLAIN `git push`** (run_in_background + dangerouslyDisableSandbox; `git push 2>FILE; echo PUSH_DONE rc=$?>>FILE`). PUSH_DONE rc=0 = passed.
- rc=141 / "Connection closed" but gate PASSED both arches → re-push `SKIP_SMOKE=1` (verified commit).
- "Could not set up host forwarding tcp::2222" → a stale qemu squats 2222 → false-fail. ALWAYS kill local verify-boot qemu after each test by **ss port (2222/1234) + pgrep `system-aarch64`/`system-x86_64` pid** — NEVER `pkill -f qemu...` (self-kills the shell).
- Watch rootfs free with `dumpe2fs` as deps grow (silent file-drop on overflow → arm pre-init wedge).
- spec-lint clean (`cargo run -p xtask -- spec-lint | tail -1` = "clean") before every commit/PR. `main.rs` is AT the 1000-line cap — refactor/extract before any edit.
- Branch per change F/B/D/C-<NN>; revert dirtied `kernel/blobs/rootfs-*.img` before commit; explicit `git add <paths>`.
