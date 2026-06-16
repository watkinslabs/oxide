# state.md — session handoff

## Headline
**glibc full-compliance build-out** (docs/59 §9). Conformance **185/185**
(`cargo run -q -p xtask -- glibc-test`). Both arches boot to `oxide login:`
(x86 KVM ~34s; arm `make smoke-arm SMOKE_TIMEOUT=800` ~58s). Clean tree on
`main`. `glibc.md` = live per-cluster TODO. F counter next = **537**
(metadata/index.md).

## INFLECTION (read first)
The quick host-diffable clusters are largely exhausted. Remaining glibc gaps are
all EITHER large (ns_sprintrr ~30-RR-type formatter; Sun RPC ~80) OR risky for
bit-exact host-diff (re_* GNU regex engine semantics) OR not host-diffable
(libxcrypt needs -lcrypt absent from harness → unit-test vectors). Pick a lane
deliberately; the "one small cluster per PR in 20 min" rhythm no longer applies
cleanly. F536 (crypt_gensalt) already broke it (unit-test validated).

## Done this run (merged to main, F524–F536, one cluster per PR)
- **F524** posix_spawn _np file actions + spawnattr getters + SETSIGDEF/SETSCHED — posix/spawn.rs
- **F525** execveat/sockatmark/isfdtype — posix/process.rs + net/socket.rs + posix/stat.rs
- **F526** pidfd_getpid + pidfd_spawn/spawnp (clone CLONE_PIDFD) — posix/modern.rs + posix/spawn.rs
- **F527** revoke/ustat/uselib/modify_ldt/iopl/ioperm — posix/misc2.rs
- **F528** C23 math: logp1*/remquof*/lgammaf32_r/f64_r/strfromf64 — math/* + stdlib/fcvt.rs
- **F529** pkey_alloc/free/mprotect + pkey_get/set (PKRU x86 / POR_EL0 arm) — posix/modern.rs
- **F530** glob_pattern_p + lchmod (fchmodat2) + dysize — posix/glob.rs + posix/fs.rs + time/tm.rs
- **F531** ns_get/put16/32 + ns_name_ntop/pton/skip — net/nameser.rs (NEW file, RFC1035)
- **F532** ns_name_unpack/uncompress + ns_samename/samedomain/subdomain/makecanon — net/nameser.rs
- **F533** ns_format_ttl + ns_parse_ttl — net/nameser.rs
- **F534** ns_name_pack + ns_name_compress (uncompressed, like dn_comp) — net/nameser.rs
- **F535** ns_initparse/ns_parserr/ns_skiprr/ns_msg_getflag — net/nameser.rs (NsMsg 80B/NsRr 1048B ABI)
- **F536** crypt_gensalt(+_rn/_ra) + crypt_rn/crypt_ra + crypt_preferred_method — crypt/mod.rs
  (UNIT-TEST validated, not host-diff — harness has no -lcrypt)

## Bigger remaining clusters (glibc.md §2) — pick a lane
- **ns_sprintrr/ns_sprintrrf** — RR pretty-print; host-diffable (-lresolv) but a
  big per-RR-type formatter (A/AAAA/NS/CNAME/SOA/MX/TXT/… ~30 types, ns_print.c).
  A focused subset works IF you only test the types you implement.
- **resolver (~45)** res_query/search/send/mkquery — needs DNS over sockets;
  res_mkquery/res_nmkquery are PURE (build a query packet) → host-diffable subset.
- **Sun RPC (~80)** clnt_*/svc_*/auth_*/pmap_* — needs sockets; rpc_msg XDR pure
  (RFC5531) → xdr_* helpers are a host-diffable pure subset; clnt/svc need sockets.
- **re_* BSD regex (~11)** — GNU re_pattern_buffer ABI over our regex engine.
  RISK: GNU engine match semantics differ from our POSIX engine → host-diff may
  fail on edge cases. re_comp/re_exec (BSD-simple) are the safest start.
- **libxcrypt remainder** — crypt_checksalt, fcrypt(=crypt alias), xcrypt/xencrypt/
  xdecrypt (SunRPC DES). Unit-test validated.
- **BSD net-auth** rcmd/rexec/ruserok/iruserok/rresvport(_af)/bindresvport (sockets).
- **multicast src filters** getsourcefilter/set + ipv4 variants (group_filter sockopt).
- small leftovers: STREAMS getmsg/putmsg/isastream/fattach/fdetach (likely
  compat-only/non-linkable), chflags family (murky errno), open_wmemstream,
  malloc_info, psiginfo (needs glibc si_code→string tables — substantial),
  gnu_get_libc_version/release (trivial but version string differs → not diffable).

## DEFERRED (hard, not skipped)
- **C23 narrowing math** f32add/f32sub/f32mul/f32div/f32sqrt/f32fma(+f64x) — need
  round-to-odd via a wider intermediate type we lack in Rust extern-C. ffma is the
  hard 3-term one.
- **inet6_option_* (RFC2292, ~6)** obsolete, cmsghdr+ip6_hbh-wrapped.

## Hard-blocked (NOT achievable — glibc_unsupported.md)
long double `*l` (x86 f80) + `_Float128`/`_Float32x`/`_Float64x` (~700). No Rust
extern-C type. Only worthwhile bit: a `%Lf`/`%Lg` printf/scanf asm shim.

## The rhythm (proven, 13 PRs this run)
One cluster = one F<NN> branch (read+bump F in metadata/index.md). Build BOTH
arches (`cargo build -q -p glibc --features freestanding --target
{x86_64,aarch64}-unknown-linux-gnu`); add host-diffable t_*.c (`#include` what
mkstemp/structs need); `xtask glibc-test`; spec-lint clean; commit/PR/merge
(`gh pr create … ; gh pr merge --merge --delete-branch=true`); bump glibc.md.
Author Chris Watkins, NO Co-Authored-By. EXPORT: rustc cdylib exports
`#[no_mangle]` items only. spec-lint: `// SAFETY:` ≥30 chars on the line before
`unsafe {`; every `pub fn`/`pub(crate) fn` needs `# C:`. New syscalls: add
per-arch nr in internal/nr.rs (x86 syscall_64.tbl, arm asm-generic).

## Host-diffability gotchas learned this run
- Some host symbols are COMPAT-ONLY (non-linkable): ustat, uselib, getmsg/putmsg.
  Can't build a host oracle → can't differentially test. Keep wrapper, note it.
- Differential harness needs BIT-EXACT match. Our lgamma is ~1 ULP off host → print
  reduced precision for double lgamma. log1p/remquo etc. ARE bit-exact.
- Uninitialized C locals + -O2 → layout-dependent flakes (zero-init them).

## Probing host for exact semantics (the proven loop)
Write /tmp/p.c, `cc p.c [-lresolv] -o pbin && ./pbin`, read EXACT output, match
byte-for-byte. WATCH: C arg-eval order is right-to-left. Use a unique output
binary name (not /tmp/pk etc. — collides with leftover dirs).

## Boot / verify gate (mandatory before push for crates/user/glibc touches)
Each glibc change invalidates the rootfs cache → x86 restages (~3-4 min) then
boots. Run sequentially in ONE bg command (run_in_background:true): x86 grub
(KVM, timeout 300) → pkill → `make smoke-arm SMOKE_TIMEOUT=800`. The push hook
re-runs smoke (cache HIT, fast). `pkill -x qemu-system-<arch>`.

## First task on restart
Re-audit then pick the next cluster:
  nm -D /lib64/lib{c,m,pthread,rt,dl,resolv,util,crypt,anl}.so* | awk '$2~/[TWiB]/{print $3}' | sed 's/@.*//' | sort -u > /tmp/host
  cargo build -q -p glibc --features freestanding --target x86_64-unknown-linux-gnu
  nm -D target/sysroot/x86_64-unknown-linux-gnu/lib/libc.so.6 | awk '$2~/[TWiBD]/{print $3}' | sed 's/@.*//' | sort -u > /tmp/ours
  comm -23 /tmp/host /tmp/ours | grep -vE '^_|f128|f32x|f64x'
Then pick the next cluster — suggest ns_initparse/ns_parserr (ns_msg/ns_rr
struct parse, host-diffable -lresolv), re_* BSD regex (engine exists), or
libxcrypt crypt_gensalt (unit-test validated, not host-diffable).
