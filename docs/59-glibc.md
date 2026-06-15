# 59 glibc-in-Rust (oxide-libc)

DRAFT 2026-06-14. Dep:`01`,`02`,`03`,`07`,`08`,`09`,`15`,`29`,`29a`,`31`,`53`.

Our own C standard library, written in Rust, ABI-compatible with GNU glibc. Replaces the vendored musl fork (`29a§3`). Emits `libc.so.6` + `ld-linux-x86-64.so.2` / `ld-linux-aarch64.so.1`. Goal: unmodified Fedora `-gnu` binaries (GNOME, systemd, dnf, the RPM world) link + run.

Supersedes musl decision in `29a§2-4`, `07§3`, `29§4`, `03§1` — see R-revisions landing with this spec.

## 1 Why glibc-ABI (not musl, not own-ABI)

- Endgame = Fedora RPM userspace + from-source GNOME desktop (packaging memo). Fedora **is** glibc.
- Real RPM binaries reference glibc-versioned symbols (`memcpy@GLIBC_2.14`), `ld-linux-x86-64.so.2`, IFUNC/IRELATIVE, locale-archive, NSS `.so` modules, `__libc_*`. musl cannot satisfy these unmodified.
- "100% compatible Linux" (`03`) at the userspace ABI ⇒ glibc ABI is the contract.
- Written in Rust (not vendored C) per project charter: `#![no_std]`, small files, owned + testable, no LGPL C tree.

## 2 ABI contract (the hard part — get this exact)

| Item | x86_64 | aarch64 |
|---|---|---|
| libc soname | `libc.so.6` | `libc.so.6` |
| loader soname | `ld-linux-x86-64.so.2` | `ld-linux-aarch64.so.1` |
| baseline version node | `GLIBC_2.2.5` | `GLIBC_2.17` |
| later version nodes | `GLIBC_2.3` … `GLIBC_2.38` as needed | `GLIBC_2.17` … `GLIBC_2.38` |
| userspace target triple | `x86_64-unknown-linux-gnu` | `aarch64-unknown-linux-gnu` |
| TLS model | initial-exec + GD via `__tls_get_addr` | same |
| errno | TLS, via `__errno_location` | same |
| entry | `_start`→`__libc_start_main` | same |
| stack protector | `__stack_chk_fail` + `__stack_chk_guard` | same |

Non-negotiable ABI facts:
- **Symbol versioning** — every public symbol carries a `@GLIBC_x.y` version via linker version-script + `.symver`. Without it, dynamic linker rejects real binaries. `R02`.
- **IFUNC / IRELATIVE** — glibc resolves `memcpy`/`strlen`/etc. through IFUNC resolvers at load. We must emit `STT_GNU_IFUNC` resolvers + handle `R_*_IRELATIVE` in our rtld. `R12`.
- **struct layout** — `FILE`, `pthread_t`(opaque ulong), `pthread_mutex_t`(40B x86_64 / 48B aarch64), `jmp_buf`, `DIR`, `glob_t`, `stat`(glibc layout, NOT kernel `struct stat` — libc translates), `dirent` must match glibc byte-for-byte. Sourced from glibc `sysdeps` headers, recorded in `abi/` golden tables (`§7`).
- **Versioned struct sizes are frozen** — once a binary is built against `sizeof(pthread_mutex_t)=40`, we can never change it. Lock in `abi/` goldens day one.

UAPI / syscall numbers come from `userspace/uapi/` (`29a§3`, `15§6.7`) — unchanged by libc choice; libc binds the same kernel ABI.

## 3 Crate home + layout (`docs/52`)

`crates/user/glibc/` — Rust crate, `crate-type = ["staticlib","cdylib"]`, `#![no_std]`, `#![no_main]`, `panic="abort"`. One public C function (or tight group) **per file**, mirroring glibc's one-function-per-file convention. Hard cap 1000 / soft 500 (`08§7`) — trivially met at one-fn granularity.

Module tree (glibc dir → our module):

| glibc dir | module | scope |
|---|---|---|
| `string/` | `string/` | mem*/str*/strn* — one fn/file |
| `ctype/` | `ctype/` | is*/to* + table |
| `stdlib/` | `stdlib/` | malloc-free wrappers, str→num, qsort, env, exit |
| `malloc/` | `malloc/` | allocator (ptmalloc-compatible behavior, not bytes) |
| `stdio-common/` + `libio/` | `stdio/` | FILE, fopen/printf/scanf family, buffering |
| `time/` | `time/` | clock/gmtime/strftime/tz |
| `signal/` | `signal/` | sigaction/sigprocmask/raise/kill, restorer |
| `posix/` + `io/` | `posix/` | fork/exec/wait/getpid/glob/fnmatch/regex |
| `socket/` + `inet/` + `resolv/` | `net/` | socket calls, inet_*, getaddrinfo, resolver |
| `pwd/`+`grp/`+`nss/` | `nss/` | passwd/group/shadow, nsswitch dispatch (links `crates/user/nss`) |
| `nptl/` | `pthread/` | threads, mutex/cond/rwlock/once/TLS keys, clone3 |
| `dlfcn/` | `dlfcn/` | dlopen/dlsym/dlclose/dladdr → rtld |
| `math/` + `sysdeps/ieee754` | `math/` | libm (folded into libc.so.6 + libm.so.6 alias) |
| `setjmp/` | `setjmp/` | setjmp/longjmp (asm per arch) |
| `wcsmbs/`+`iconv/`+`gconv/` | `locale/` | wide/multibyte, locale, iconv, C.UTF-8/en_US.UTF-8 |
| `crypt/` | `crypt/` | crypt_r (yescrypt/sha512crypt/Argon2id) |
| `rt/` | `rt/` | aio, mq_*, timer_*, shm_* |
| `termios/` | `termios/` | tc*/cf* |
| `sysdeps/<arch>/` | `arch/x86_64/`, `arch/aarch64/` | syscall asm, `_start`, TLS setup, IFUNC variants, `setjmp` asm, `clone` asm |
| `elf/` (rtld) | separate crate `crates/user/ldso/` | `ld-linux-*.so` — see `§5` |
| `csu/` | `start/` | crt1/Scrt1/crti/crtn objects, `__libc_start_main` |

Internal-only shared bits (no C ABI): `crates/user/glibc/src/internal/` — errno TLS slot, lock primitive, syscall raw wrappers, version-map macro.

## 4 Syscall layer (libc side)

libc never inlines raw `syscall` opcodes in portable `.rs`. One arch shim `arch/<arch>/syscall.rs` exposes `sys0..sys6(nr, …) -> isize`; everything else calls those. Mirrors kernel hollow-shell discipline (`53`) on the userspace side: thin syscall wrappers, real C-library logic above them.

Numbers live in `internal/nr.rs` as **per-arch named constants** (`nr::FOO`, never bare slot literals — `07§5`), sourced from the canonical Linux uapi: x86_64 from `syscall_64.tbl`, aarch64 from `asm-generic/unistd.h` — the same per-sysdeps split glibc keeps. Not consumed from the kernel `syscall` crate (x86_64-only dispatch keys + kernel `hal`/`klog` deps = wrong arch + wrong layer for userspace) nor from a generated `userspace/uapi` (export is x86_64-only and unbuilt). aarch64 is asm-generic: no `open`/`stat`/`access`/`pipe`/`dup2`/`fork`/`rename` — libc composes those from `openat`/`newfstatat`/`faccessat`/… (the arch dispatch lives in the wrapper, e.g. `posix/io.rs` `open`→`openat`).

## 5 Dynamic linker (ld-linux)

glibc rtld (`elf/rtld.c`) → `crates/user/ldso/`, emits `ld-linux-x86-64.so.2` / `ld-linux-aarch64.so.1`. Reuses + extends existing `userspace/dynlink/` + `crates/user/dl`. Must do: PT_INTERP self-relocate, DT_NEEDED graph, GOT/PLT lazy + BIND_NOW, `RELA`/`JMPREL`/`RELATIVE`/`IRELATIVE`/`COPY`/`TLS` relocs, symbol-version matching (`GLIBC_2.x`), `ld.so.cache`, `LD_LIBRARY_PATH`/`LD_PRELOAD`, TLS block setup (static + dynamic, `__tls_get_addr`), `dlopen`/`dlsym`/`dlclose`/`dladdr`/`dlinfo`. Path map (replaces `29a§4`):

| Path | Use |
|---|---|
| `/lib64/ld-linux-x86-64.so.2` | x86_64 loader (PT_INTERP) |
| `/lib/ld-linux-aarch64.so.1` | aarch64 loader |
| `/lib64/libc.so.6`, `/lib64/libm.so.6` | runtime |
| `/lib64/libpthread.so.0` → `libc.so.6` | glibc 2.34+ folded into libc; ship stub for old NEEDED |
| `/lib64/libdl.so.2`,`librt.so.1`,`libresolv.so.2` | folded stubs (2.34+) |

glibc 2.34+ folded libpthread/libdl/librt/libanl/libutil into libc.so.6 — we match that: real code in `libc.so.6`, empty versioned stub `.so`s for binaries with stale `DT_NEEDED`.

## 6 Sub-phase ladder (loop grinds top→bottom; each row = ≥1 PR)

Each sub-phase: small files, hosted oracle test vs host glibc, then boot-smoke at the marked milestones. Both arches lockstep (`CLAUDE.md` rule 7).

| G | Title | Gate / milestone |
|---|---|---|
| G0 | Spec R-revisions (`29a`,`07`,`29`,`03`,`00§3`,MANIFEST) + this spec | spec-lint clean |
| G1 | Crate skeleton, target `-gnu`, version-script infra, `abi/` goldens, build via `xtask glibc` | `cargo build` cdylib+staticlib both arches; soname+version nodes present (readelf) |
| G2 | `start/` csu + `__libc_start_main` + `_start` asm + crt objects + `__errno_location` + stack guard | static `hello` links our libc, runs, exits 0 on QEMU |
| G3 | `arch/<arch>/syscall.rs` + `internal/` + raw unistd (read/write/open/close/brk/mmap/exit_group) | static `hello` via real syscalls both arches |
| G4 | `string/` + `ctype/` (one fn/file) + IFUNC variants | oracle proptest vs host glibc 10M ops |
| G5 | `malloc/` allocator | malloc oracle + stress (mtmalloc/mmchurn ports) |
| G6 | `stdio/` FILE + printf/scanf/buffering. G6a=printf format engine (int/str/char/ptr exact, float via core::fmt) + snprintf family + write-side (printf/fprintf/puts/fputs/putchar/fwrite) unbuffered + FILE ABI layout + std streams. G6b=scanf engine + sscanf/vsscanf. G6c=read-side (fopen/fdopen/freopen/fclose/fread/fgetc/getc/getchar/ungetc/fgets/getline/getdelim/fseek/ftell/rewind) + scanf/fscanf/vfscanf over a FILE source. Follow-ups: stdio buffering + putc/getc-macro (__overflow/__uflow), exact float dtoa. | printf/snprintf/sscanf oracle vs host; `hello` printf + file round-trip + fscanf runs |
| G7 | `stdlib/` env/exit/str→num/qsort/bsearch | oracle |
| G8 | `posix/` fork/exec/wait/glob/fnmatch/regex/getopt | busybox-class static bin runs |
| G9 | `signal/` sigaction/restorer/mask/raise/abort | signal smokes (existing ports) |
| G10 | `time/` clock/gmtime/localtime/strftime/tz | oracle + tz |
| G11 | `pthread/` threads/mutex/cond/rwlock/once/TLS-keys/atfork. G11a=create/join (clone trampoline + CHILD_CLEARTID futex + per-arch TCB/CLONE_SETTLS) + self/exit/detach/equal. G11b=`pthread/mutex.rs` (40B `pthread_mutex_t`, 3-state futex lock, NORMAL/RECURSIVE/ERRORCHECK + mutexattr). G11c=`cond.rs` (48B, seq-futex condvar + condattr clock), `rwlock.rs` (56B, state-word futex rwlock), `once.rs` (4B, 3-state futex once), `key.rs` (TLS keys: global slot table + per-thread values in the TCB) + minimal main-thread TCB (`init_main_tcb`, arch_prctl/tpidr) so self/keys work pre-create. | loom + pthread smokes |
| G12 | `ldso/` rtld + IRELATIVE + sym-versioning + dlopen. Ladder: G12a=crate skeleton + self-relocation bootstrap (`dynamic.rs` _DYNAMIC parse, `reloc.rs` R_*_RELATIVE apply over the rtld's own image, standalone `syscall.rs`); G12b=DT_NEEDED graph + lib search (LD_LIBRARY_PATH/ld.so.cache) + mmap PT_LOAD mapping; G12c=symbol resolution + full reloc set (reuse `crate::dl`); G12d=sym-versioning (VERSYM/VERNEED, GLIBC_2.x); G12e=TLS (static+dynamic block, DTV, __tls_get_addr, per-thread errno); G12f=lazy PLT (_dl_runtime_resolve) + .init_array + handoff; G12g=dlopen/dlsym/dlclose/dladdr/dlinfo. | dynamic `hello` runs; `dlopen` smoke |
| G13 | `net/` sockets + inet + getaddrinfo + stub resolver | tcp/inet6 smokes |
| G14 | `nss/` passwd/group/shadow + nsswitch | login_sim + pamtest |
| G15 | `math/` libm | ieee754 oracle vs host libm |
| G16 | `locale/` wide/mb + iconv + C.UTF-8/en_US.UTF-8 | iconv oracle |
| G17 | `crypt/`,`rt/`,`termios/`,`setjmp/` remainder | per-area smokes |
| G18 | Folded-lib stubs (`libpthread/dl/rt/...so`) + ld.so.cache + sysroot publish | unmodified Fedora `-gnu` static+dynamic bin runs (acceptance) |
| G19 | Migrate existing userspace (init, busybox, probes) musl→glibc; retire musl fork + ld-oxide | `make smoke` both arches green on glibc |

Musl stays buildable through G0–G18 (parallel path); retired in G19. No hard cut mid-flight.

## 7 Test contract

- **Hosted oracle (primary loop):** every fn group has a `tests/<area>.rs` that runs our impl against the host system glibc for the same inputs (differential), per `42`/`CLAUDE.md` "verify-left". Milliseconds, no boot. 10M-op proptests where `00§3` mandates.
- **ABI goldens:** `crates/user/glibc/abi/<arch>.toml` records `sizeof`/`offsetof`/version-node for every ABI struct + symbol; CI diffs against `readelf`/`pahole` of reference glibc. Drift = fail.
- **Symbol-set check:** CI asserts our `libc.so.6` exports ⊇ the symbol-version set referenced by the `43§2` acceptance binaries.
- **Boot-smoke:** at G2/G6/G8/G12/G18/G19 milestones, both arches via qemu MCP (`CLAUDE.md`). Boot is the final gate, not the dev loop.
- **No soak** (`02`). Differential proptests + loom (pthread) + miri (internal unsafe) + QEMU = the bug finders.

## 8 Open questions

- OQ1: fold libm into `libc.so.6` or keep distinct `libm.so.6` real code? (lean: distinct, glibc does.)
- OQ2: malloc — reimplement ptmalloc internals or behavior-compatible arena allocator? (ABI only requires behavior + symbol set; lean behavior-compatible.)
- OQ3: resolver — full bind9-style stub vs minimal `files dns`? (G13 minimal, full in later PR; never "deferred" — tracked here.)
- OQ4: keep `crates/user/dl`,`nss`,`pam` as today and have glibc call into them, or absorb? (lean: glibc `nss/` dispatches to `crates/user/nss` modules; pam stays separate lib.)
