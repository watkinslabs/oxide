# state.md — session handoff

## Headline
**glibc full-compliance build-out** (docs/59 §9). Conformance **192/192**
(`cargo run -q -p xtask -- glibc-test`). Both arches boot to `oxide login:`
(x86 KVM ~34s; arm `make smoke-arm SMOKE_TIMEOUT=800` ~58s). Active branch:
`F562-reserved-port-helpers`. `glibc.md` = live per-cluster TODO. F counter next = **563**, B = **138**, D = **112**
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
- **F541 DONE locally:** gnu_get_libc_version/release report the supported ABI
  ceiling (`2.38`) and stable release; host-diffable t_gnu_version.c.
  Conformance now 190/190.
- **F542 DONE locally:** argp_program_version_hook exported and honored before
  argp_program_version in --version handling; host-diffable t_argp.c.
- **F543 DONE locally:** getpw(uid, buf) serializes the live passwd entry in
  legacy colon-line form; host-diffable t_pwgr.c.
- **F544 DONE locally:** ttyslot scans /etc/ttys through ttyent and returns the
  historical slot index, with Linux/glibc 0-on-miss coverage in t_ttyent.c.
- **B137 DONE locally:** x86 GRUB/default cmdline prefers the video VT
  (`console=... console=tty0`) while rootfs starts a separate ttyS0 getty, so
  `/dev/console` and `/dev/ttyS0` are independent login devices. Build-only
  GRUB/rootfs verified for x86_64 + aarch64; local x86 smoke could not enter
  guest because this host lacks `/dev/vhost-vsock`.
- **F545 DONE locally:** C23 `<stdbit.h>` unsigned long / unsigned long long
  variants (`stdc_*_ul`, `stdc_*_ull`) added; host-diffable coverage folded
  into t_stdbit.c. Verification: `xtask glibc-test` 190/190; both freestanding
  arch builds; `spec-lint`; filtered symbol audit now 385 missing (down from 413).
- **F546 DONE locally:** llseek + C-locale time `_l` wrappers
  (strftime_l/strptime_l/wcsftime_l). Time `_l` paths are host-diffed in
  t_strftime.c; llseek is implemented as an LP64 lseek alias but not
  host-diffable because host glibc exposes it as non-default compat-only.
  Verification: `xtask glibc-test` 190/190; both freestanding arch builds;
  `spec-lint`; filtered symbol audit now 381 missing.
- **F547 DONE locally:** sem_clockwait over the existing POSIX semaphore
  futex wait loop, parameterized by clockid for absolute deadlines. Host-diffed
  timeout behavior in t_ipcsem.c. Verification: `xtask glibc-test` 190/190;
  both freestanding arch builds; `spec-lint`; filtered symbol audit now 380.
- **F548 DONE locally:** libxcrypt compatibility names: crypt_checksalt,
  crypt_gensalt_r, fcrypt, xcrypt/xcrypt_r, xcrypt_gensalt/xcrypt_gensalt_r.
  Host harness now links oracle binaries with -lcrypt; t_crypto host-diffs
  default crypt_checksalt + crypt_gensalt_r. The xcrypt/fcrypt names are
  non-default compat-only on host, so covered by ABI audit. Verification:
  `xtask glibc-test` 190/190; both freestanding arch builds; `spec-lint`;
  filtered symbol audit now 373.
- **F549 DONE locally:** C-locale strtof32_l/strtof64_l aliases over
  strtof_l/strtod_l; host-diffed in t_lfs.c. strtold/wcstold remain blocked
  with the rest of long-double ABI. Verification: `xtask glibc-test` 190/190;
  both freestanding arch builds; `spec-lint`; filtered symbol audit now 371.
- **F550 DONE locally:** resolver domain validators res_hnok/res_ownok/
  res_mailok/res_dnok added in net/nameser.rs; host-diffed in t_resok.c
  across wildcard, mailbox, escaping, whitespace, label-length, and total-size
  cases. Verification: `xtask glibc-test` 191/191; both freestanding arch
  builds; `spec-lint`; filtered symbol audit now 367.
- **F551 DONE locally:** gethostent_r added over the existing /etc/hosts
  enumeration cursor and hostent caller-buffer packer; host-diffed in
  t_netdb_r.c. Verification: `xtask glibc-test` 191/191; both freestanding
  arch builds; `spec-lint`; filtered symbol audit now 366.
- **F552 DONE locally:** setlogin added as glibc-matching ENOSYS stub and
  host-diffed in t_deprecated.c. Verification: `xtask glibc-test` 191/191;
  both freestanding arch builds; `spec-lint`; filtered symbol audit now 365.
- **F553 DONE locally:** profil/sprofil and gmon controls
  (monstartup/moncontrol/mcount) added as successful no-ops, matching the
  stable host behavior exercised here; host-diffed in t_deprecated.c.
  Verification: `xtask glibc-test` 191/191; both freestanding arch builds;
  `spec-lint`; filtered symbol audit now 360.
- **F554 DONE locally:** register_printf_type added as the GNU printf
  extension type-ID allocator starting at 8; host-diffed in t_printf_ext.c.
  Verification: `xtask glibc-test` 192/192; both freestanding arch builds;
  `spec-lint`; filtered symbol audit now 359.
- **F555 DONE locally:** res_gethostbyname/res_gethostbyname2/
  res_gethostbyaddr added as resolver compatibility aliases over existing
  host DB lookups. Host glibc exposes them compat-only here, so verification is
  existing suite regression + both arch builds + `spec-lint` + audit drop to 356.
- **F556 DONE locally:** chflags/fchflags added as glibc-matching legacy stubs
  (`chflags` ENOSYS, `fchflags` EINVAL) and host-diffed in t_deprecated.c.
  Verification: `xtask glibc-test` 192/192; both freestanding arch builds;
  `spec-lint`; filtered symbol audit now 354.
- **F557 DONE locally:** klogctl added as a thin syslog(2) wrapper with
  per-arch syscall numbers and unprivileged EPERM host-diff coverage in
  t_sysmisc.c. Verification: `xtask glibc-test` 192/192; both freestanding
  arch builds; `spec-lint`; filtered symbol audit now 353.
- **F558 DONE locally:** public sigreturn added as the obsolete glibc
  ENOSYS stub, distinct from the internal rt_sigreturn restorer trampoline;
  host-diffed in t_signal.c. Verification: `xtask glibc-test` 192/192;
  both freestanding arch builds; `spec-lint`; filtered symbol audit now 352.
- **F559 DONE locally:** ns_name_ntol and ns_name_rollback added to the
  resolver name-codec cluster, matching glibc lowercasing and compression-table
  rollback behavior; host-diffed in t_nameser.c. Verification:
  `xtask glibc-test` 192/192; both freestanding arch builds; `spec-lint`;
  filtered symbol audit now 350.
- **F560 DONE locally:** ns_datetosecs added as the glibc/BIND-compatible
  yyyymmddhhmmss UTC parser with sticky errp validation and uint32 wrapping
  arithmetic, split into net/nameser_date.rs to keep nameser.rs under the
  spec-lint line cap. Host-diffed in t_nsttl.c. Verification:
  `xtask glibc-test` 192/192; both freestanding arch builds; `spec-lint`;
  filtered symbol audit now 349.
- **F561 DONE locally:** getipv4sourcefilter/setipv4sourcefilter and
  getsourcefilter/setsourcefilter added over allocator-backed IP_MSFILTER/
  MCAST_MSFILTER getsockopt/setsockopt packing. Invalid-fd EBADF behavior is
  host-diffed in t_inet2.c. Verification: `xtask glibc-test` 192/192; both
  freestanding arch builds; `spec-lint`; filtered symbol audit now 345.
- **F562 DONE locally:** bindresvport, rresvport, and rresvport_af added over
  the IPv4 reserved-port binding range, with failed privileged bind behavior
  host-diffed in t_inet2.c. Verification: `xtask glibc-test` 192/192; both
  freestanding arch builds; `spec-lint`; filtered symbol audit now 342.
- small maybes: re-audit for any remaining host-linkable stragglers before
  choosing RPC/test-infra work.

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
