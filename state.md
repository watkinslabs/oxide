# state.md — session handoff

## Headline
**glibc full-surface completion** toward G19d (musl→glibc vendor migration).
The entire libc-FUNCTION surface the 95 vendor binaries reference is now done.
Conformance **144/144** (`cargo run -q -p xtask -- glibc-test`). Both arches
build + boot to `oxide login:` (x86 KVM, arm `make smoke-arm` ~58s).

## Landed this session (merged to main, F473–F487 + D100)
- pthread FULL surface (#2037–2042): control/sched, barriers+spinlocks, attr
  extensions, mutexattr/condattr/rwlockattr + timed/clock locks,
  cancel/timedjoin/getattr_np/atfork. pthread gap = 0.
- C11 <threads.h> (#2043). modern syscalls (#2044: close_range/getdents64/
  renameat2/getcpu/mount-API/fanotify/pidfd/process_vm/epoll_pwait2/ptrace/
  arch_prctl). locale `_l` (#2045, incl. __isoc23_strto*_l; newlocale returns a
  real __locale_struct — <ctype.h> inlines is*_l through it). eaccess/
  sigisemptyset/__fpclassify/gets (#2046). putgrent/putspent/lckpwdf/ulckpwdf
  (#2047). in6addr_any/loopback (#2048). mbrtoc32/c32rtomb (#2049).
  wcwidth/wcswidth (#2050). clone(2) (#2051, naked fn). dl_iterate_phdr (#2052,
  ldso _dl_iterate_phdr + glibc wrapper). Full audit doc (#2036, docs/59 §9).

## Remaining vendor gap = 8 symbols, ONE blocker (docs/59 §9.4)
`__environ`/`_environ`/`__signgam`/`__tzname`/`__timezone`/`__daylight`/
`__progname`/`__progname_full` — global_asm `.set` aliases of canonical Rust
statics. EXPORT is solved (supplementary `--version-script` in build_sharedlib
re-promotes them; verified all land at the canonical address). BLOCKER: our
**ld.so does not do R_*_COPY copy-reloc redirection** for data symbols —
empirically, a single-reference usability test leaves __environ/__progname/
__tzname at their initial value while host populates them. Fix is a
`crates/user/ldso` feature (handle R_X86_64_COPY / R_AARCH64_COPY: memcpy initial
bytes + bind the symbol to the executable's copy for all objects). This also
affects copy-relocated libc data in executables generally. Focused ldso task.
NOT a libc change — don't re-attempt the version-script alias export until the
loader does copy-reloc redirection (it's reverted; the export alone is useless
without redirection).

## Lower-priority full-surface (docs/59 §9.1, non-vendor)
- `_FloatN` f32/f64 math aliases (208 map to existing libm). Export via
  naked-fn `jmp`/`b` thunks (like clone) — bare asm `.set` is localized by
  rustc's cdylib filter. Mechanical.
- C23 new math (~90: sinpi/fmaximum/fminimum/narrowing fNadd) — need real impls.
- wide `_l`, Sun RPC (135, deprecated — only if a vendor pkg links it),
  fts/fts64 (coreutils -R; exact FTSENT ABI — substantial), crypt_* (libxcrypt).
- Hard-blocked (NOT counted): long-double f80 + _Float128 (~560) —
  glibc_unsupported.md. printf %Lf shim is the only worthwhile long-double piece.

## The rhythm (keep using it)
One cluster = one `F4xx` branch (read+bump counter in metadata/index.md). Add
fns (per-arch nr in internal/nr.rs for syscalls), wire module, build BOTH arches
(`cargo build -q -p glibc --features freestanding --target {x86_64,aarch64}-unknown-linux-gnu`),
add `userspace/glibc_conformance/t_*.c` (diffs our libc.so.6 vs host byte-exact),
`cargo run -q -p xtask -- glibc-test`, spec-lint clean, commit/PR/merge.
- KEY export fact: rustc cdylib exports ONLY its `#[no_mangle]` Rust items.
  Bare `global_asm` `.globl`/`.set` symbols are LOCALIZED out of .dynsym. To
  export an asm symbol: a `#[unsafe(naked)] #[no_mangle]` fn (functions), or a
  supplementary `--version-script` (data — but see §9.4 loader caveat).
- spec-lint: `// SAFETY:` ≥30 chars immediately before `unsafe {`; `pub(crate) fn`
  needs `/// # C:` (is_pub_fn matches `pub(crate) fn`, NOT `pub unsafe extern "C"`
  nor `pub(crate) unsafe fn`).
- Author Chris Watkins; NO Co-Authored-By.

## Verify gates / boot
- x86: `OXIDE_QEMU_KVM=1 timeout 240 cargo run -q -p xtask -- grub --arch x86_64
  --smp 1 > /tmp/b.log 2>&1` (KVM ~20s; rc=124 = booted+timed-out = ok).
- arm: `timeout 540 make smoke-arm` (TCG ~58s to `oxide login:` — WORKS locally).
  `pkill -x qemu-system-<arch>` (NOT -f). Don't touch image_qemu.rs/firmware.
- conformance: `cargo run -q -p xtask -- glibc-test` (144/144). x86-only harness.
- ldso changes are boot-critical → boot BOTH arches before push (done for #2052).

## First task next session
Either: (a) the ldso R_*_COPY data-symbol redirection feature (unblocks §9.4 +
copy-relocated data generally — highest-value remaining), or (b) start G19d:
rebuild the vendor packages against the glibc sysroot, retire musl. The libc
function surface is complete enough to attempt G19d; the §9.4 data aliases may
or may not bite depending on how vendor binaries reference them (real GNU ld
collapses aliases at their link time, so many may already work).
