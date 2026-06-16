# state.md — session handoff

## Headline
**glibc full-compliance build-out** (docs/59 §9) toward G19d. Directive: implement
EVERYTHING achievable, value-agnostic. Conformance **163/163**
(`cargo run -q -p xtask -- glibc-test`); both arches build + boot (`oxide login:`).
~2100 symbols exported (from ~1486 at run start). glibc.md is the live TODO.

## Done this run (merged, F473–F497 + D/B fixes)
pthread FULL surface (80), C11 threads (25), modern syscalls (~34), locale `_l`
(~28 + __isoc23_strto*_l), account-db (putgrent/putspent/lckpwdf/ulckpwdf),
eaccess/euidaccess/sigisemptyset/sigorset/sigandset/__fpclassify/gets, in6addr,
mbrtoc32/c32rtomb, wcwidth/wcswidth, clone(2), dl_iterate_phdr, _FloatN math
aliases (246), ether_aton/ntoa + arc4random, acct/clock_getcpuclockid/execvpe,
C23 fmaximum/fminimum (16), netdb _r (serv/proto/net), dlvsym/dladdr1/dlmopen/
dlinfo, C23 *pi trig + *m1/*p1 (math/cpi.rs), /etc/ethers DB (ether_line/hostton/
ntohost), /etc/ttys DB (getttyent family).

## Remaining achievable clusters (DO ALL — full compliance, glibc.md §2)
1. **Sun RPC (149)** — clnt_*/svc_*/auth_*/xdr_*/pmap_*/key_*/callrpc/registerrpc/
   netname/ruserpass + getrpcent/byname/bynumber(+_r)/set/end. Needs XDR + RPC
   client/server + /etc/rpc parser. Largest block; do in sub-batches (xdr first).
2. **resolver (32)** — res_query/search/send/mkquery/nquery/nsearch/nsend/
   gethostby*; dn_comp/dn_expand/dn_skipname; getifaddrs/freeifaddrs (netlink
   RTM_GETADDR); getaddrinfo_a/gai_*; recvmmsg/sendmmsg; get/setsourcefilter.
3. **gshadow (16)** — struct sgrp + getsgnam/getsgent/fgetsgent/sgetsgent/putsgent
   (+_r)/set/end. /etc/gshadow parser (needs a libnss-crate parse_gshadow + glibc
   side; sg_adm + sg_mem are two char** arrays — pack via a 2-list packer).
4. **aliases (14)** — struct aliasent + getaliasbyname/getaliasent(+_r)/set/end.
   /etc/aliases (mail) parser; self-contained in glibc.
5. **fts/fts64 (10)** — fs-tree traversal (coreutils -R/du/find). Exact FTSENT ABI.
6. Any stragglers: re-run the audit (below) to find remaining f32/f64 + misc.

## The ONE migration blocker (docs/59 §9.4, reverted/deferred)
8 `__`-aliased DATA symbols (__environ/_environ/__signgam/__tzname/__timezone/
__daylight/__progname/__progname_full). Export works (version-script); but libc
reaches its own exported data DIRECTLY not via GOT, so copy-reloc interposition
in an executable desyncs. Fix = GOT-indirect codegen for copy-relocatable libc
data (no rustc semantic-interposition flag → GOT shim/structural split). Likely
moot for real GNU-ld vendor binaries — confirm in G19d. DON'T re-add the alias
export without the codegen fix (it's useless alone; empirically verified).

## Hard-blocked (NOT achievable — glibc_unsupported.md)
long double `*l` (x86 f80) + `_Float128`/`_Float32x`/`_Float64x` (~700). No Rust
extern-C type. Only worthwhile bit: a `%Lf`/`%Lg` printf/scanf asm shim.

## The rhythm (proven this run)
One cluster = one `F4xx` branch (read+bump counter in metadata/index.md). nr in
internal/nr.rs (per-arch) for syscalls; wire the module; build BOTH arches
(`cargo build -q -p glibc --features freestanding --target {x86_64,aarch64}-unknown-linux-gnu`);
add `userspace/glibc_conformance/t_*.c` (diffs our libc.so.6 vs host byte-exact);
`xtask glibc-test`; spec-lint clean; commit/PR/merge; bump glibc.md periodically.
- Export facts: rustc cdylib exports ONLY its `#[no_mangle]` Rust items. Bare
  `global_asm` `.set`/`.globl` are LOCALIZED → export via `#[unsafe(naked)]`
  fns (functions) or `crates/user/glibc/version/floatn.map` (+--version-script in
  xtask glibc build_sharedlib). Data aliases also need the §9.4 codegen.
- spec-lint: `// SAFETY:` ≥30 chars, immediately before `unsafe {`; `pub(crate) fn`
  needs `/// # C:` (is_pub_fn matches `pub(crate) fn`, NOT `pub unsafe extern "C"`/
  `pub(crate) unsafe fn`). Macro-generated export fns must NOT collide with the
  private core (name cores `k_*`).
- Math conformance: SELECT-style (min/max) test with `==`; computed (trig/exp)
  test with a tolerance `NEAR()` + exact-at-special-point `==`.
- exec'ing a host binary in a test → pass a CLEAN envp (no LD_LIBRARY_PATH leak).
- Author Chris Watkins; NO Co-Authored-By.

## Re-audit (find what's left)
nm -D host glibc (libc/m/pthread/rt/dl/resolv/util/crypt/anl in /lib64) → public
set; nm -D our target/sysroot/x86_64-unknown-linux-gnu/lib/libc.so.6; comm -23.
Filter `^_`/`GLIBC_`/internal; drop f80/_Float128 (hard-blocked).

## Verify / boot
- x86: `OXIDE_QEMU_KVM=1 timeout 240 cargo run -q -p xtask -- grub --arch x86_64
  --smp 1 > /tmp/b.log 2>&1` (rc=124=ok). arm: `timeout 540 make smoke-arm`
  (~58s to login, WORKS locally). `pkill -x qemu-system-<arch>`. ldso changes →
  boot BOTH before push. conformance harness is x86-only.

## First task next session
aliases DB (self-contained, §2.4) or gshadow (§2.3), then the big ones (resolver,
Sun RPC). Or pivot to G19d (vendor rebuild on glibc) — the function surface is
deep enough to attempt it; the §9.4 data aliases may not bite real binaries.
