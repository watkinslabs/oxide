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
| G12 | `ldso/` rtld + IRELATIVE + sym-versioning + dlopen. Ladder: G12a=crate skeleton + self-relocation bootstrap (`dynamic.rs` _DYNAMIC parse, `reloc.rs` R_*_RELATIVE apply over the rtld's own image, standalone `syscall.rs`); G12b=library lookup (`search.rs` LD_LIBRARY_PATH+default-dirs candidate build, `cache.rs` ld.so.cache new/old-format parse) + the rtld's fs syscalls (openat/read/pread/mmap/mprotect/munmap/faccessat); G12c=rtld core data structures: `bump.rs` minimal mmap-bump allocator (also the freestanding `#[global_allocator]`) + `symbol.rs` symbol resolution (SymView over DT_SYMTAB/STRTAB + GNU_HASH/sysv lookup via `elf::hash`); G12d=DONE — runnable rtld. link map (`linkmap.rs` DT_NEEDED BFS + global lookup) + `loader.rs` (mmap PT_LOAD at bias, W^X) + `relocate.rs` (in-place RELATIVE/Sym/IRELATIVE/COPY via `linkmap::lookup_global`) + `auxv.rs`/`phdr.rs` (initial-stack + phdr parse) + `entry.rs` (`_start`/`_dl_start` self-reloc via AT_BASE + `.hidden _dl_start` to dodge the unrelocated PLT/`_dl_main` app-RELATIVE + handoff). HARNESS `xtask ldso --check` builds `ld-linux-{x86-64.so.2,aarch64.so.1}` cdylibs (rust-lld, both arches) + runs a no-libc PIE through our ld on the host → exit 42/"ld-ok" (x86; aarch64 run = QEMU later). G12e=DONE (parsing) sym-versioning `version.rs` — DT_VERSYM (index+hidden), DT_VERNEED→Vernaux (ref requires name), DT_VERDEF→Verdaux (def provides name), `def_satisfies` (versioned ref matches by version name; unversioned takes the non-hidden default); pure+hosted-tested, resolver wiring folds into G12g; G12f=DONE — per-thread errno (glibc: errno now in `pthread::Tcb`, `__errno_location` reads the thread pointer; 2-thread isolation smoke) + TLS layout (ldso `tls.rs`: variant I/II static-block tp-offset math, `tpoff`/`dtpoff`, `__tls_get_addr` skeleton; pure layout hosted-tested). DTV allocation + relocate.rs Kind::Tls wiring (DTPMOD/DTPOFF/TPOFF) fold into G12g with the link-map TLS image; G12g=DONE — DT_NEEDED libc.so.6 linking: G12g.1 crt-split (libc.so.6 cdylib), G12g.2a version-aware lookup_global, G12g.2b full `_dl_main` (→`link.rs`): build link map from app + DT_NEEDED graph (search+mmap each lib via `objview::build_objview`), apply every object's RELA+JMPREL via `linkmap::lookup_global`, run DT_INIT/.init_array dep-first, handoff. rtld self-links with `-Bsymbolic` (internal refs→RELATIVE, dodging the unrelocated GOT); rtld provides its own `mem.rs` (memcpy/memset/memcmp/strlen/getauxval). HARNESS: `xtask ldso --check` runs a real libc.so.6-linked PIE (`dyn_libc.c`, strlen via JUMP_SLOT) → exit 13. TLS (initial-exec/static): `link.rs` setup_static_tls reads the exe PT_TLS (`phdr::find_tls`), mmaps the TLS block via `tls::layout`, copies the init image, sets the thread pointer (`syscall::set_thread_pointer` arch_prctl/tpidr); relocate.rs Kind::Tls applies TPOFF/DTPMOD/DTPOFF (RelocCtx carries tls_offset+modid). HARNESS `tls_pie.c` (`__thread`) → exit 7. Remaining: lazy PLT (_dl_runtime_resolve), general-dynamic DTV / __tls_get_addr across libs. G12h=DONE — dlopen/dlsym/dlclose/dladdr: rtld exports `_dl_open`/`_dl_sym`/`_dl_close`/`_dl_addr` over a process-global link map (`link.rs` LINK), and adds ITSELF to the resolution scope (`rtld_objview` from AT_BASE) so libc.so.6's `_dl_*` refs bind; glibc `dlfcn` thin-wraps them. HARNESS `dlopen_pie.c` dlopen("libfoo.so")+dlsym("foo") → exit 99. **G12 (the dynamic linker) COMPLETE** — `xtask ldso --check` runs 4 smokes (42 self-reloc, 13 DT_NEEDED libc.so.6, 7 TLS, 99 dlopen). | dynamic `hello` runs; `dlopen` smoke |
| G13 DONE | `net/` — inet.rs (htons/htonl/inet_pton/inet_ntop, oracle vs host), socket.rs (sockaddr_in/in6/storage/msghdr/iovec size-matched + socket/bind/connect/sendto/recvfrom/… wrappers, per-arch nrs; socketpair round-trip smoke), addrinfo.rs (getaddrinfo/getnameinfo/gai_strerror numeric+localhost). FOLLOW-UP: /etc/hosts parse + stub UDP DNS resolver (resolv.conf) for non-numeric names. | tcp/inet6 smokes |
| G14 DONE (files backend) | `nss/` — struct passwd(48)/group(32)/spwd(72) size-matched; getpwnam/getpwuid/getgrnam/getgrgid over /etc/passwd|group via the `crate nss` parsers + static-buffer packing (pure pack_passwd/pack_group hosted-tested). glibc adds `bcmp`. Smoke: getpwuid(0)→"root". FOLLOW-UP: _r reentrant variants, set/get/endpwent iteration, getspnam, nsswitch.conf dispatch beyond `files`. | login_sim + pamtest |
| G15 DONE | `math/` libm — basic (round/sign/fmod/frexp), sqrt (Newton), exp/exp2/expm1, log/log2/log10/log1p, pow (fdlibm e_pow), sin/cos/tan/sincos, asin/acos/atan/atan2, sinh/cosh/tanh, cbrt, hypot, asinh/acosh/atanh (+f32). All differential-oracle vs host libm (≤1–4 ULP). FOLLOW-UPS: bit-exact correctly-rounded sqrt, huge-arg trig (Payne–Hanek), dedicated f32 cores, long double. | ieee754 oracle vs host libm |
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

## 9 Remaining surface (full host-glibc audit, 2026-06-16)

Method: `nm -D --defined-only` host Fedora glibc (libc/m/pthread/rt/dl/resolv/util/crypt/anl) → 4214 public syms; minus our `libc.so.6` exports (1486) minus `glibc_unsupported.md` (long-double f80 + `_Float128`/`_Float32x`/`_Float64x` — not expressible in Rust extern-C). Earlier "achievable surface COMPLETE" was scoped to what the 95 vendor binaries reference (~35 left); THIS is the complete glibc public API, incl. symbols no current vendor binary happens to call yet. Per Discipline rule 3 (no subset) these are in scope.

### 9.1 Status by cluster

| Cluster | Missing | Priority | Notes |
|---|---|---|---|
| pthread full surface | 80 | **HIGH** | have 49 (create/join/mutex/cond/rwlock/once/key). Missing: barriers, spinlocks, cancel, affinity, sched, setname, kill, sigqueue, timed/tryjoin, mutexattr prio/protocol/robust/pshared, rwlockattr. Folded into libc.so.6 — real MT programs need these. |
| fts/fts64 | 10 | **HIGH** | coreutils `rm -r`/`du`/`chmod -R`, `find`. fs-tree traversal over our VFS. |
| net resolver / NSS `_r` | 48 | **HIGH** | getifaddrs/freeifaddrs, dn_comp/expand/skipname, res_* (query/search/send/mkquery/nquery), getaddrinfo_a/gai_*, reentrant get*by*_r, recvmmsg/sendmmsg, get/setsourcefilter. |
| modern syscall wrappers | 39 | MED | close_range/closefrom, getdents64, getdirentries, renameat2, getcpu, fsopen/fsmount/fsconfig/fspick (new mount API), fanotify_init/mark, process_vm_readv/writev, process_madvise/mrelease, arch_prctl, ptrace, readahead, remap_file_pages, epoll_pwait2, acct, fallocate64, preadv64/pwritev64(v2). Obsolete (skip-ok): bdflush, create_module/get_kernel_syms/query_module, STREAMS getmsg/putmsg/getpmsg/putpmsg, profil. |
| locale `_l` variants | 16 | MED | newlocale/freelocale/uselocale/duplocale, nl_langinfo_l, str{coll,xfrm}_l, strto{d,f,ld,l,ul}_l, to{lower,upper}_l. Needs the `__locale_t` object (G16). |
| C11 threads | 25 | MED | thrd_*/cnd_*/mtx_*/tss_*/call_once — thin shims over the pthread surface above. |
| wide/multibyte | 28 | MED | wc*/c8rtomb/c16rtomb/c32rtomb/mbr* remainder (G16). |
| `_FloatN` math (f32/f64) | 259 | LOW | `*f32`==float, `*f64`==double on both arches — ABI-identical aliases of existing libm; mechanical. |
| C23 math (`*pi`, exp/log m1/p1, fmaximum/fminimum, narrowing fadd/fsub/…) | ~90 | LOW | new ISO C23 surface; niche. |
| Sun RPC (clnt_/svc/auth/xdr/pmap/callrpc) | 138 | LOW | historically libtirpc; glibc-deprecated. Implement only if a vendor pkg links it. |
| crypt_* (libxcrypt) | 8 | LOW | separate lib (G17). |
| arc4random/ether_/argp/misc | ~20 | LOW | arc4random{,_buf,_uniform}, ether_*, misc BSD-isms. |

### 9.2 Hard-blocked (NOT counted above — see `glibc_unsupported.md`)

long-double (`*l`, x86 f80) + `_Float128`/`_Float32x`/`_Float64x` extended-precision: ~560 syms. Rust has no `f80`/`_Float128` extern-C type, so the ABI cannot be expressed. Permanent, not deferred.

### 9.3 Closed since the vendor-scoped audit (F-series PRs)

poll/ppoll, epoll, eventfd/signalfd/timerfd/inotify, statx, xattr×12, file/proc wrappers, sig wait family, posix_spawn family, chroot/fexecve/shm, mkostemp/mkstemps/futimesat/waitid, admin syscalls, statfs/statvfs, pthread FULL surface (#2037–2042), C11 threads (#2043), modern syscalls (#2044), locale `_l` (#2045), eaccess/sigisemptyset/__fpclassify/gets (#2046), putgrent/putspent/lckpwdf/ulckpwdf (#2047), in6addr_any/in6addr_loopback.

### 9.4 KNOWN ISSUE — `__`-aliased data symbols + copy relocations

The data symbols `__environ`/`_environ` (==environ), `__signgam`, `__tzname`/`__timezone`/`__daylight`, `__progname`/`__progname_full` are global_asm `.set` aliases of canonical Rust `#[no_mangle]` statics. Two problems:
1. **Export**: rustc's cdylib export filter keeps only its own `#[no_mangle]` items, so the asm aliases are localized out of `.dynsym`. A supplementary anonymous `--version-script` (listing them in `global:`) on the `build_sharedlib` link DOES promote them (verified: all land at the canonical symbol's address).
2. **Copy-reloc INTERPOSITION (the real blocker — a PIC-codegen matter, not the ld.so COPY itself).** ldso ALREADY handles R_*_COPY (`relocate.rs` Kind::Copy: memcpy the lib's bytes into the exe's reserved slot). Empirically, a single-reference usability test (`extern char **__environ; __environ[0]…`, `__progname`, `__tzname`, `__signgam` after lgamma — each referenced ALONE) leaves them at their INITIAL value (environ=0, progname empty, signgam stuck at 1) while the host populates them. Root cause: a COPY reloc only works if BOTH the executable AND libc reach the symbol through the exe's interposing copy. The exe does (its COPY-reloc'd slot IS the definition). But OUR libc accesses its own `environ`/`signgam`/`tzname` **directly** (RELATIVE/PC-relative, since they're defined #[no_mangle] statics in the same cdylib), NOT via the GOT — so libc's startup writes land in libc's private storage; the COPY reloc captured the pre-startup null, and the exe never sees the update. glibc avoids this by routing data-symbol access through the GOT (interposable) for symbols that may be copy-relocated. **Fix = force GOT-indirect access to these exported data symbols inside libc** (visibility/codegen: e.g. don't let LLVM bind them locally — `-Z` direct-access-external-data off, or an explicit GOT-load shim), so the exe's interposing copy is the single storage. Focused PIC-codegen task, NOT a libc-wrapper or ld.so-COPY change. The `__` aliases just exposed it; it equally affects copy-relocated *canonical* libc data in executables. (Shared-lib refs and PIE GOT access are unaffected; the dominant `environ` path works via libc internals.)

### 9.5 Work order (next PRs)

resolver/NSS_r → fts → GOT-indirect codegen for copy-relocatable libc data (§9.4 #2 — unblocks the `__` aliases AND copy-relocated canonical libc data in executables) → `_FloatN` aliases (export via naked-fn jmp thunks, like clone — asm-`.set` is localized) → C23 math → (RPC/crypt only if vendor-linked). DONE this pass: pthread surface, C11 threads, modern syscalls, locale `_l`, account-db, eaccess/sigisemptyset/__fpclassify/gets, in6addr, mbrtoc32, wcwidth/wcswidth, clone(2), dl_iterate_phdr — the entire libc-function surface the vendor binaries reference. Conformance 144/144.
