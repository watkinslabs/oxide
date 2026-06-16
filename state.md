# state.md — session handoff

## Headline
**glibc full-compliance build-out** (docs/59 §9) toward G19d. Directive: implement
EVERYTHING achievable, value-agnostic; only the hard-blocked f80/`_Float128` are
impossible. Conformance **163/163** (`cargo run -q -p xtask -- glibc-test`),
~2100 symbols exported (from ~1486 at run start). **Both arches boot to
`oxide login:`** (x86 KVM; arm `make smoke-arm` ~60s) — verified after all the
libc additions below. Clean tree on `main`. `glibc.md` is the live per-cluster TODO.

## Done this run (merged to main; F473–F509 + D/B fixups, ~53 PRs)
Each landed with a byte-exact-vs-host `userspace/glibc_conformance/t_*.c`, EXCEPT
the RPC/XDR which glibc keeps compat-only (not host-linkable) — those were
RFC-verified by direct round-trip against our libc.so.6.
- pthread FULL surface (80), C11 `<threads.h>` (25)
- modern syscalls (close_range/getdents64/renameat2/mount-API/fanotify/pidfd/
  process_vm/ptrace/arch_prctl/…), clone(2), acct/clock_getcpuclockid/execvpe,
  sendmmsg/recvmmsg
- locale `_l` narrow + wide (isw*/tow*/wcs*/wcsto*_l + __isoc23_*), mbrtoc32/
  c32rtomb, wcwidth/wcswidth
- math: `_FloatN` aliases (246), C23 fmaximum/fminimum, `*pi`/`*m1`/`*p1`,
  `<stdbit.h>` (42), __fpclassify
- account-db (putgrent/putspent/lckpwdf/ulckpwdf), /etc/{ethers,ttys,aliases,
  gshadow,rpc} databases (+ _r), netdb `_r` (serv/proto/net)
- dl_iterate_phdr, dlvsym/dladdr1/dlmopen/dlinfo
- in6addr_any/loopback, ether_aton/ntoa, arc4random family, eaccess/euidaccess,
  sigisemptyset/sigorset/sigandset, gets, gnu_dev_*/swab/ftok/timespec_get(res)/
  group_member/ualarm, LFS *64 aliases (mkstemp64.. + preadv64/pwritev64 +
  strtof64/wcstof64), dn_comp/dn_expand/dn_skipname, SysV signal (sighold/
  sigrelse/sigignore/sigset)
- **XDR layer COMPLETE** (rpc/xdr.rs): xdrmem_create + 10-op vtable + all
  scalar/fixed-width/hyper/float/double primitives + opaque/bytes/string/
  wrapstring/netobj + vector/array/reference/pointer + xdr_sizeof + getpos/setpos.

## DECISION PENDING (asked the user; answer on restart)
(1) keep completing the compat surface (next: getifaddrs + resolver), OR
(2) pivot to **G19d** — rebuild the 95 vendor packages against the glibc sysroot,
retire musl — and let the real migration surface what actually blocks it. The
libc surface is deep enough to attempt G19d now; the §9.4 data-alias blocker may
not bite real GNU-ld vendor binaries.

## Remaining achievable clusters (DO ALL — full compliance; glibc.md §2)
- **Sun RPC client/server (~120)** — clnt_*/svc_*/auth_* (authnone/authunix/
  authdes)/pmap_* + the rpc_msg XDR filters (xdr_callmsg/replymsg/opaque_auth/
  callhdr/accepted_reply/rejected_reply/authunix_parms/des_block). XDR base is
  DONE; the message filters are pure XDR (self-verifiable, RFC5531 struct
  layouts); clnt/svc/pmap need sockets. NOT host-diffable (compat-only) → verify
  by round-trip vs our libc.so.6 (recipe below).
- **resolver (~50)** — res_query/search/send/mkquery/nquery/nsearch/nsend/ninit;
  __res_state; ns_get16/put16/name/parse; getifaddrs/freeifaddrs (netlink
  RTM_GETADDR/GETLINK — HOST-DIFFABLE: same machine→same iface list, check "lo"
  + 127.0.0.1); getaddrinfo_a/gai_* (async, needs a worker thread); get/
  setsourcefilter; inet6_opt_*/inet6_rth_* (~22, pure RFC3542 buffer ops);
  inet_net_pton/ntop/neta/nsap (fiddly classful+CIDR parse).
- **fts/fts64 (10)** — fs-tree traversal (coreutils -R/du/find). Exact FTSENT
  ABI (large struct). HOST-DIFFABLE on a temp dir tree (fts IS still in glibc).
- **BSD net-auth** — rcmd/rexec/ruserok/iruserok/rresvport(_af)/bindresvport.
- **re_* BSD regex (~12)** — re_comp/re_exec/re_compile_pattern/re_search/
  re_match/re_set_syntax over our regcomp/regexec engine.
- **libxcrypt** — crypt_gensalt(+_r/_ra/_rn)/crypt_ra/crypt_rn/crypt_checksalt/
  crypt_preferred_method/fcrypt/xcrypt/xencrypt/xdecrypt.
- **misc stragglers** — strerrorname_np/strerrordesc_np/sigabbrev_np/sigdescr_np
  (need errno-name + signal-abbrev tables — match glibc exactly), sched_getattr/
  setattr/getcpu, mlock2/sync_file_range/vmsplice/tee/pivot_root/mount_setattr/
  move_mount/open_tree, pidfd_getpid/spawn, scandirat/lockf, twalk_r,
  open_wmemstream, wcslcat/wcslcpy, mbrtoc16/c16rtomb, posix_spawn_file_actions_
  add{chdir,fchdir,closefrom,tcsetpgrp}_np + spawnattr sched/sig/pgroup/cgroup.
  Re-audit (recipe below) after each batch.

## The ONE migration blocker (docs/59 §9.4 — reverted, deferred)
8 `__`-aliased DATA symbols (__environ/_environ/__signgam/__tzname/__timezone/
__daylight/__progname/__progname_full). They EXPORT fine (version-script), but
our libc reaches its own exported data DIRECTLY (PC-relative, same cdylib) not
via the GOT, so an executable's copy-reloc interposition desyncs. Fix = force
GOT-indirect codegen for copy-relocatable libc data (no rustc semantic-
interposition flag → GOT-load shim or structural split). LIKELY MOOT for real
GNU-ld vendor binaries — CONFIRM during G19d before investing. Do NOT re-add the
version-script alias export without the codegen fix (useless alone; verified).

## Hard-blocked (NOT achievable — glibc_unsupported.md)
long double `*l` (x86 f80) + `_Float128`/`_Float32x`/`_Float64x` (~700). No Rust
extern-C type. Only worthwhile bit: a `%Lf`/`%Lg` printf/scanf asm shim.

## The rhythm (proven, ~53 PRs)
One cluster = one `F<NN>` branch (read+bump the F counter in metadata/index.md).
Per-arch nr in internal/nr.rs for syscalls; wire the module; build BOTH arches
(`cargo build -q -p glibc --features freestanding --target {x86_64,aarch64}-unknown-linux-gnu`);
add a t_*.c conformance test; `xtask glibc-test`; spec-lint clean; commit/PR/merge
(`gh pr create … ; gh pr merge --merge --delete-branch=true`); bump glibc.md.
- EXPORT facts: rustc cdylib exports ONLY its `#[no_mangle]` Rust items. Bare
  `global_asm` `.set`/`.globl` are LOCALIZED → export via `#[unsafe(naked)]` fns
  (functions, e.g. clone) or a supplementary `--version-script` (functions only;
  DATA also needs the §9.4 codegen). version/floatn.map is wired into
  tools/xtask/src/glibc.rs build_sharedlib.
- spec-lint (DON'T accumulate fixups): `// SAFETY:` body ≥30 chars, on the line
  IMMEDIATELY before `unsafe {`; every `pub fn`/`pub(crate) fn` needs `# C:` (use
  `/// # C:` for pub(crate); is_pub_fn matches `pub fn`/`pub(crate) fn`/`pub
  unsafe fn`, NOT `pub unsafe extern "C"` nor `pub(crate) unsafe fn`). Macro
  export fns must not collide with the private core → name cores `k_*`.
- Math test: SELECT-style (min/max) `==`; computed (trig/exp) tolerance + exact
  special points. exec'ing a host bin in a test → CLEAN envp (no LD_LIBRARY_PATH).
- Compat-only symbols (xdr_*/clnt_*/svc_*): host won't link them in new code, so
  no diff-harness — verify by linking the test against ONLY our sysroot and
  checking output (recipe below). Don't add them to glibc_conformance/.
- Author Chris Watkins; NO Co-Authored-By.

## Verify-against-our-libc recipe (for compat-only symbols)
LIB=target/sysroot/x86_64-unknown-linux-gnu/lib ; rm -f $LIB/libc.so.6 ;
cargo run -q -p xtask -- glibc-test >/dev/null ; # rebuilds the sysroot libc.so.6
cc -fPIE -pie -nostdlib -Wl,--allow-shlib-undefined \
  -Wl,--dynamic-linker=$LIB/ld-linux-x86-64.so.2 -Wl,-rpath,$LIB \
  /tmp/t.c $LIB/Scrt1.o -L$LIB -l:libc.so.6 -o /tmp/t && LD_LIBRARY_PATH=$LIB /tmp/t

## Re-audit (find what's left)
nm -D /lib64/lib{c,m,pthread,rt,dl,resolv,util,crypt,anl}.so* → /tmp/hostglibc.txt
(public set); nm -D our sysroot libc.so.6 → /tmp/ours.txt; `comm -23`. Filter
`^_`/`^GLIBC_`/internal; drop f80/_Float128 (hard-blocked). The non-`l$`/non-
`f128`/non-RPC remainder is the actionable list.

## Boot / verify gates
- x86: `OXIDE_QEMU_KVM=1 timeout 240 cargo run -q -p xtask -- grub --arch x86_64
  --smp 1 > /tmp/b.log 2>&1` (KVM ~20s; grep `oxide login:`).
- arm: `timeout 540 make smoke-arm` (~60s to login, WORKS locally; don't touch
  image_qemu.rs/firmware). `pkill -x qemu-system-<arch>` (NOT -f).
- conformance harness is x86-only. ldso changes → boot BOTH before push.

## First task on restart
Answer the DECISION above. If (1): getifaddrs (netlink, host-diffable) then the
resolver. If (2): start G19d — point the vendor build.sh/rootfs at the glibc
sysroot, rebuild a first package (e.g. coreutils) against our libc.so.6, boot,
fix what actually fails. Either way: re-audit first, then one cluster per F-branch.
