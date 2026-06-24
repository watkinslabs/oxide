# state.md — session handoff

## Headline
**glibc full-compliance build-out** (docs/59 §9). Conformance **189/189**
(`cargo run -q -p xtask -- glibc-test`). Both arches boot to `oxide login:`
(x86 KVM ~34s; arm `make smoke-arm SMOKE_TIMEOUT=800` ~58s). Active branch:
`F540-ftime`. `glibc.md` = live per-cluster TODO. F counter next = **541**, D = **112**
(metadata/index.md).

## Done this run (merged to main, F524–F536, 13 PRs)
- **F524** posix_spawn _np file actions + spawnattr getters + SETSIGDEF/SETSCHED — posix/spawn.rs
- **F525** execveat/sockatmark/isfdtype — posix/process.rs + net/socket.rs + posix/stat.rs
- **F526** pidfd_getpid + pidfd_spawn/spawnp (clone CLONE_PIDFD) — posix/modern.rs + posix/spawn.rs
- **F527** revoke/ustat/uselib/modify_ldt/iopl/ioperm — posix/misc2.rs
- **F528** C23 math: logp1*/remquof*/lgammaf32_r/f64_r/strfromf64 — math/* + stdlib/fcvt.rs
- **F529** pkey_alloc/free/mprotect + pkey_get/set (PKRU x86 / POR_EL0 arm) — posix/modern.rs
- **F530** glob_pattern_p + lchmod (fchmodat2) + dysize — posix/glob.rs + posix/fs.rs + time/tm.rs
- **F531–F535** entire `ns_*` resolver family — net/nameser.rs (NEW): wire get/put, name
  ntop/pton/skip/unpack/uncompress/pack/compress, domain relations, format/parse_ttl,
  full DNS message parser (ns_initparse/parserr/skiprr/msg_getflag, NsMsg 80B/NsRr 1048B)
- **F536** crypt_gensalt(+_rn/_ra) + crypt_rn/crypt_ra + crypt_preferred_method — crypt/mod.rs
  (UNIT-TEST validated — harness has no -lcrypt)

## CRITICAL FINDING — the verifiable surface is largely DONE (read before continuing)
The ~431 still-missing symbols are MOSTLY not achievable-and-verifiable here:
- **~190 hard-blocked** long double `*l` + `_Float128/_Float32x/_Float64x`. No Rust
  extern-C type. Impossible. (glibc_unsupported.md)
- **~106 Sun RPC** (clnt_*/svc_*/auth_*/pmap_*/xdr_callmsg/...). NOT VERIFIABLE here:
  (a) host glibc keeps them COMPAT-ONLY — NOT linkable without libtirpc (absent), so
  no host-diff oracle, and rpc/*.h headers are GONE (can't even declare the structs);
  (b) our rpc/{xdr,...}.rs are `#![cfg(feature="freestanding")]` and their deps
  (malloc/strlen) too, so `cargo test` on host can't reach them (and `--features
  freestanding` host test = duplicate panic_impl). The XDR core already shipped this way
  UNTESTED. Adding more RPC = unverifiable bolt-on → I declined (discipline). Doing RPC
  properly first needs a test path: gate xdr+deps on `any(freestanding,test)`.
- **socket/infra-dependent** clnt/svc, res_query/res_send, BSD net-auth (rcmd/rexec/
  ruserok/rresvport/bindresvport), getsourcefilter/setsourcefilter, getrpcport — can't
  verify without a live peer/server in the harness.
- **res_mkquery/res_nmkquery** — pure + host-diffable IF the random 2-byte ID is masked,
  BUT need the ~500-byte `__res_state` struct ABI + res_ninit, which we DON'T have.

## Still tractable AND verifiable (the real remaining work — small)
- **F537 DONE locally and committed:** inet6_option_space/init/append/alloc/next/find
  + isctype; host-diffable coverage in t_inet6_option.c + t_ctype2.c.
- **F538 DONE locally:** ns_sprintrr/ns_sprintrrf for A/AAAA/NS/CNAME/PTR/MX/TXT
  and RFC3597 unknown-RR fallback; canonical absolute names, origin-relative
  owner/RDATA names, TTL/class/type tab-column layout; host-diffable t_nssprint.c.
- **F539 DONE locally:** getusershell/setusershell/endusershell over /etc/shells
  with glibc default fallback; host-diffable t_usershell.c. Conformance now 188/188.
- **F540 DONE locally:** ftime over CLOCK_REALTIME into the LP64 timeb layout;
  host-diffable t_ftime.c. Conformance now 189/189.
- small maybes: llseek (=lseek on 64-bit; check it's linkable not compat-only),
  gnu_get_libc_version/release (trivial but version string ≠ host → not diffable).

## DEFERRED (hard, not skipped)
- **C23 narrowing math** f32add/f32sub/f32mul/f32div/f32sqrt/f32fma(+f64x) — need
  round-to-odd via a wider intermediate type we lack in Rust extern-C. ffma hardest.
- **psiginfo** — needs glibc's full si_code→string tables (substantial).
- **open_wmemstream** — wide-stream orientation plumbing. **malloc_info** — XML stats dump.

## The proven loop (for the tractable host-diffable ones)
One cluster = one F<NN> branch (read+bump F in metadata/index.md). Build BOTH arches
(`cargo build -q -p glibc --features freestanding --target {x86_64,aarch64}-unknown-linux-gnu`);
write host-diffable t_*.c; `xtask glibc-test`; spec-lint; commit/PR/merge
(`gh pr create…; gh pr merge --merge --delete-branch=true`); bump glibc.md.
Author Chris Watkins, NO Co-Authored-By. spec-lint: `// SAFETY:` ≥30 chars on the line
before `unsafe {`; every pub fn needs `# C:`. New syscalls: per-arch nr in internal/nr.rs.

## Host-diffability gotchas learned
- COMPAT-ONLY host symbols (non-linkable, no oracle): ustat, uselib, getmsg/putmsg,
  ALL crypt/xdr/rpc. Headers may also be absent (rpc/*.h gone → can't even declare structs).
- Differential harness needs BIT-EXACT match. Our lgamma ~1 ULP off host → print reduced
  precision. Uninitialized C locals + -O2 → layout flakes (zero-init).
- Probe loop: write /tmp/p.c, `cc p.c [-lresolv] -o pbin && ./pbin`, match byte-for-byte.
  Unique output binary name (not /tmp/pk — collides with leftover dirs).

## Boot / verify gate (mandatory before push for crates/user/glibc touches)
glibc change invalidates rootfs cache → x86 restages (~3-4 min). Run sequentially in ONE
bg command: x86 grub (KVM, timeout 300) → pkill → `make smoke-arm SMOKE_TIMEOUT=800`.
`pkill -x qemu-system-<arch>`. Push hook re-runs smoke (cache HIT, fast).

## First task on restart
Re-audit the remaining missing symbol set after F538, then decide the next
verifiable glibc increment:
  nm -D /lib64/lib{c,m,pthread,rt,dl,resolv,util,crypt,anl}.so* | awk '$2~/[TWiB]/{print $3}' | sed 's/@.*//' | sort -u > /tmp/host
  cargo build -q -p glibc --features freestanding --target x86_64-unknown-linux-gnu
  nm -D target/sysroot/x86_64-unknown-linux-gnu/lib/libc.so.6 | awk '$2~/[TWiBD]/{print $3}' | sed 's/@.*//' | sort -u > /tmp/ours
  comm -23 /tmp/host /tmp/ours | grep -vE '^_|f128|f32x|f64x'
DECISION NEEDED: invest in (a) the RPC test-path refactor to unlock ~106 unverified→
verified RPC symbols, or (b) accept RPC stays out and call the glibc surface "complete
modulo impossible/infra-bound" once ns_sprintrr lands.
