# state.md — session handoff

## Headline
Driving **glibc full-surface completion** toward G19d (musl→glibc vendor
migration). Branch series `F4xx`. The libc is on `main`, both arches build +
boot. Conformance harness at **138/138** (`cargo run -q -p xtask -- glibc-test`).

## What the audit established (docs/59 §9)
`nm -D` host glibc (4214 public) vs ours (now ~1660). Reconciled: ~1034
glibc-internal, ~706 hard-blocked (f80 long double + _Float128 — not Rust-
expressible, see glibc_unsupported.md), leaving the real buildable surface.
The **vendor-needed** gap (what the 95 real binaries reference) is the G19d
blocker and is nearly closed.

## Landed this session (merged to main)
- pthread FULL surface (5 PRs #2037–2042): control/sched, barriers+spinlocks,
  attr extensions, mutexattr/condattr/rwlockattr + timed/clock locks,
  cancel/timedjoin/getattr_np/atfork. pthread gap = 0.
- C11 <threads.h> (#2043): thrd/mtx/cnd/tss/call_once over pthread.
- modern syscalls (#2044): close_range/getdents64/renameat2/getcpu/mount API/
  fanotify/pidfd/process_vm/epoll_pwait2/ptrace/arch_prctl.
- locale _l (#2045): newlocale/uselocale/freelocale + ctype/numeric/string _l +
  __isoc23_strto*_l. KEY: <ctype.h> inlines is*_l through locale_t, so newlocale
  returns a real __locale_struct (ctype tables at offsets 104/112/120).
- eaccess/sigisemptyset/__fpclassify/gets (#2046).
- doc(59 §9) full audit (#2036).

## Remaining VENDOR-needed gap (19) — next, priority order
1. **account-db**: putgrent, putspent, lckpwdf, ulckpwdf — file/lock ops over
   /etc/group|shadow. (clean batch)
2. **data-symbol exports** (the export-mechanism issue): __environ, _environ,
   __progname, __progname_full, __daylight, __timezone, __tzname, __signgam,
   in6addr_any, in6addr_loopback. These are GLOBAL DATA, not fns. global_asm
   `.set` aliases do NOT reach the cdylib dynamic export set (rustc cdylib
   export logic ignores asm `.globl`); need a real exported `static` or a
   version-script entry. Investigate crates/user/glibc/version/{x86_64,aarch64}.map
   (global: is currently comment-only; local: *). THIS unlocks _FloatN too.
3. **clone** — the C clone(2) wrapper (fn ptr + child stack trampoline; per-arch
   asm like __oxide_clone in pthread/mod.rs, but the public glibc signature).
4. **dl_iterate_phdr** — rtld support (crates/user/ldso); walk the link map.
5. **wide**: wcwidth/wcswidth (Unicode width tables — must match host byte-exact),
   mbrtoc32 (UTF-8→UTF-32). Dedicated wide batch.

## Full-surface (non-vendor, lower priority, docs/59 §9.1)
- _FloatN f32/f64 math aliases (208 map to existing libm; BLOCKED on the same
  data/asm export mechanism as #2 above — `.set` aliases don't export).
- C23 new math (~90: sinpi/fmaximum/fminimum/narrowing fNadd), wide _l, Sun RPC
  (135, deprecated — only if a vendor pkg links it), fts/fts64 (coreutils -R;
  exact FTSENT ABI — substantial).

## How to work (the rhythm that's working)
- One cluster = one `F4xx` branch. Read counter in metadata/index.md, bump it.
- Add fns (per-arch nr in internal/nr.rs if syscall-backed), wire module,
  build BOTH arches (`cargo build -q -p glibc --features freestanding --target
  {x86_64,aarch64}-unknown-linux-gnu`), add `userspace/glibc_conformance/t_*.c`
  (compares our libc.so.6 vs host glibc byte-exact), `xtask glibc-test`,
  spec-lint clean, commit/PR/merge.
- spec-lint gotchas: `// SAFETY:` ≥30 chars, immediately before `unsafe {`;
  `pub(crate) fn` needs a `/// # C:` doc marker (is_pub_fn matches pub(crate) fn
  but NOT `pub unsafe extern "C"` nor `pub(crate) unsafe fn`).
- Author Chris Watkins; NO Co-Authored-By.

## Verify gates / boot
- x86: `OXIDE_QEMU_KVM=1 timeout 240 cargo run -q -p xtask -- grub --arch x86_64
  --smp 1 > /tmp/b.log 2>&1` (KVM ~20s to login; rc=124 = booted+timed-out = ok).
- arm boot infra: standard repo path on user's infra; locally use Fedora EDK2
  pflash. Do NOT touch image_qemu.rs/firmware. `pkill -x qemu-system-<arch>`.
- conformance: `cargo run -q -p xtask -- glibc-test` (138/138).

## First task next session
account-db batch: putgrent/putspent (write a group/shadow record to a FILE*),
lckpwdf/ulckpwdf (create+flock /etc/.pwd.lock). New posix file or extend
nss/. t_acctdb.c conformance. Then the data-symbol export batch (#2 above).
