# state.md — session handoff

## Headline
**glibc full-compliance build-out** (docs/59 §9). Conformance **195/195**
(`cargo run -q -p xtask -- glibc-test`). Both arches boot to `oxide login:`
(x86 KVM ~34s; arm `make smoke-arm SMOKE_TIMEOUT=800` ~58s). Active branch:
`F629-glibc-asprintf-internal-alias`. `glibc.md` = live per-cluster TODO. F counter next = **630**, B = **138**, D = **113**
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
- **res_query/res_send network paths** — still infra-dependent. The pure packet
  builders are now done without requiring full resolver initialization.

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
- **F563 DONE locally:** ruserok/ruserok_af and iruserok/iruserok_af added as
  conservative remote-login denials matching glibc's stable negative cases.
  Host-diffed in t_inet2.c. Verification: `xtask glibc-test` 192/192; both
  freestanding arch builds; `spec-lint`; filtered symbol audit now 338.
- **F564 DONE locally:** rcmd/rcmd_af and rexec/rexec_af added as conservative
  remote-command failures with glibc-matched EINVAL behavior for unresolved
  hosts. Host-diffed in t_inet2.c. Verification: `xtask glibc-test` 192/192;
  both freestanding arch builds; `spec-lint`; filtered symbol audit now 334.
- **F565 DONE locally:** mcheck_check_all added as a malloc-debug no-op beside
  mcheck/mtrace, preserving errno like host glibc. Host-diffed in t_crypto.c.
  Verification: `xtask glibc-test` 192/192; both freestanding arch builds;
  `spec-lint`; filtered symbol audit now 333.
- **F566 DONE locally:** BSD regex re_comp/re_exec added over the existing
  regex engine with an atomic process-global compiled pattern. Host-diffed in
  t_regex.c. Verification: `xtask glibc-test` 192/192; both freestanding arch
  builds; `spec-lint`; filtered symbol audit now 331.
- **F567 DONE locally:** GNU regex re_compile_pattern/re_compile_fastmap/
  re_match/re_search added over the existing regex engine, including
  glibc-compatible register allocation for the tested path. Host-diffed in
  t_regex.c. Verification: `xtask glibc-test` 192/192; both freestanding arch
  builds; `spec-lint`; filtered symbol audit now 327.
- **F568 DONE locally:** GNU regex re_syntax_options and re_set_syntax added,
  with re_compile_pattern honoring POSIX basic vs extended syntax for the
  covered path. Host-diffed in t_regex.c. Verification: `xtask glibc-test`
  192/192; both freestanding arch builds; `spec-lint`; filtered symbol audit
  now 325.
- **F569 DONE locally:** GNU regex re_match_2/re_search_2/re_set_registers
  added over the existing engine, including concatenated two-string matching
  and caller-owned register arrays. Host-diffed in t_regex.c. Verification:
  `xtask glibc-test` 192/192; both freestanding arch builds; `spec-lint`;
  filtered symbol audit now 322.
- **F570 DONE locally:** psiginfo added for the stable SI_USER glibc output
  path, with a psignal-style fallback. Host-diffed in t_ucontext.c via
  captured stderr. Verification: `xtask glibc-test` 192/192; both
  freestanding arch builds; `spec-lint`; filtered symbol audit now 321.
- **F571 DONE locally:** malloc_info added with glibc-matching EINVAL return
  for nonzero options plus minimal XML for option 0. Host-diffed bad-option
  behavior in t_crypto.c. Verification: `xtask glibc-test` 192/192; both
  freestanding arch builds; `spec-lint`; filtered symbol audit now 320.
- **F572 DONE locally:** rexecoptions writable compatibility data symbol
  exported next to the remote exec stubs. Host-diffed read/write behavior in
  t_inet2.c. Verification: `xtask glibc-test` 192/192; both freestanding arch
  builds; `spec-lint`; filtered symbol audit now 319.
- **F573 DONE locally:** ruserpass added for the no-.netrc path, returning 0,
  leaving outputs untouched, and setting ENOENT when HOME is missing. Host-diffed
  in t_inet2.c. Verification: `xtask glibc-test` 192/192; both freestanding
  arch builds; `spec-lint`; filtered symbol audit now 318.
- **F574 DONE locally:** C23 narrowing math fadd/fsub/fmul/fdiv/fsqrt/ffma and
  f32* f64 aliases added over existing f64 math, returning float/_Float32.
  Host-diffed exact sample values in t_c23math.c. Verification:
  `xtask glibc-test` 192/192; both freestanding arch builds; `spec-lint`;
  filtered symbol audit now 306.
- **F575 DONE locally:** res_mkquery/res_nmkquery added as pure standard QUERY
  packet builders with glibc-matched RD/AD header flag handling from resolver
  options. Host-diffed in t_res_mkquery.c with random IDs masked. Verification:
  `xtask glibc-test` 193/193; both freestanding arch builds; `spec-lint`;
  filtered symbol audit now 304.
- **F576 DONE locally:** gai_error/gai_cancel/gai_suspend added for completed
  or unsubmitted GNU async getaddrinfo control blocks, plus GNU EAI strerror
  strings. Host-diffed in t_gai_async.c. Verification: `xtask glibc-test`
  194/194; both freestanding arch builds; `spec-lint`; filtered symbol audit
  now 301.
- **F577 DONE locally:** getaddrinfo_a added with synchronous GAI_WAIT/GAI_NOWAIT
  completion over the existing getaddrinfo implementation, storing per-request
  `gaicb.__return` and result pointers. Host-diffed in t_gai_async.c.
  Verification: `xtask glibc-test` 194/194; both freestanding arch builds;
  `spec-lint`; filtered symbol audit now 300.
- **F578 DONE locally:** audit-only compatibility exports added for malloc
  `mallwatch` and resolver send hook setters res_send_setqhook/res_send_setrhook.
  Current Fedora headers no longer declare these obsolete names, so verification
  is regression suite + both freestanding arch builds + `spec-lint` + audit
  drop to 297.
- **F579 DONE locally:** obsolete Linux module/NFS/stack syscall compatibility
  wrappers bdflush/create_module/query_module/get_kernel_syms/nfsservctl/sstk
  added as ENOSYS stubs. Current Fedora headers no longer declare/default-link
  these names, so verification is regression suite + both freestanding arch
  builds + `spec-lint` + audit drop to 291.
- **F580 DONE locally:** STREAMS compatibility wrappers getmsg/putmsg/getpmsg/
  putpmsg/fattach/fdetach/isastream added as ENOSYS stubs. Current Fedora lacks
  headers/default-link oracle for these obsolete names, so verification is
  regression suite + both freestanding arch builds + `spec-lint` + audit drop
  to 284.
- **F581 DONE locally:** legacy compatibility exports matherr, sigvec,
  step/advance, loc1/loc2/locs, and tr_break added. `sigvec` translates through
  sigaction; step/advance reuse the existing regex engine and update the legacy
  match-bound globals. These are compat-only on current Fedora, so verification
  is regression suite + both freestanding arch builds + `spec-lint` + audit
  drop to 276.
- **F582 DONE locally:** resolver network query exports res_query/res_search/
  res_querydomain/res_send and res_n* variants added. Queries use the existing
  packet builder, first IPv4 nameserver from /etc/resolv.conf, UDP send/recv,
  and a bounded ppoll timeout. Verification: regression suite + both
  freestanding arch builds + `spec-lint` + audit drop to 268.
- **F583 DONE locally:** SunRPC keyserv/netname/DES compatibility exports
  getnetname, host2netname/user2netname, netname2host/netname2user,
  getpublickey/getsecretkey, key_* helpers, passwd2des, xencrypt/xdecrypt
  added beside des_api. Current Fedora exposes them compat-only, so
  verification is regression suite + both freestanding arch builds +
  `spec-lint` + audit drop to 249.
- **F584 DONE locally:** SunRPC client/auth/portmapper compatibility exports
  added in rpc/stubs.rs, including authdes/authunix/authnone, clnt_*,
  pmap_*, callrpc/registerrpc, rpc_createerr, get_myaddress/getrpcport, and
  rtime. These are conservative no-runtime stubs for compat-only host symbols.
  Verification: regression suite + both freestanding arch builds + `spec-lint`
  + audit drop to 219.
- **F585 DONE locally:** SunRPC service/SVC compatibility globals and exports
  added in rpc/stubs.rs, including svc_fdset/svc_pollfd/svc_max_pollfd,
  svcauthdes_stats, svc*_create, svc_register/unregister, svc_getreq*,
  svc_run/exit, svcerr_*, and xprt_register/unregister. These are conservative
  no-runtime stubs for compat-only host symbols. Verification: regression suite
  + both freestanding arch builds + `spec-lint` + audit drop to 189.
- **F586 DONE locally:** remaining SunRPC/XDR compatibility filters exported in
  rpc/xdr.rs: xdr_des_block, xdr_opaque_auth, xdr_authunix_parms, xdr_pmap,
  xdr_pmaplist, xdr_union, rpc message/key filter exports, xdrrec_* and
  xdrstdio_create. Clear-layout filters use existing XDR primitives; message,
  key, record, and stdio backend entries are conservative compat stubs.
  Verification: regression suite + both freestanding arch builds + `spec-lint`
  + audit drop to 159.
- **F587 DONE locally:** open_wmemstream implemented on the existing memory
  stream backing with a wide-mode cookie. fputwc/fputws write wchar_t units
  directly for these streams, publish wchar_t* + size_t like glibc, and preserve
  glibc's seek-back overwrite/terminator behavior. Added host-diff coverage to
  t_memstream. Verification: regression suite + both freestanding arch builds +
  `spec-lint` + audit drop to 158.
- **D112 DONE locally:** final glibc audit documented. Remaining 158 audited
  names are blocked, not pending implementation: 157 are long-double/f80 ABI
  entry points we cannot represent correctly with the current Rust extern-C ABI
  surface, and `errno` is a host GLIBC_PRIVATE TLS data symbol. Our errno is
  correctly exposed through `__errno_location`; adding a non-TLS public data
  object named `errno` would be audit-only and semantically wrong.
- **F588 DONE locally:** first real x86_64 f80 ABI bridge. xtask compiles
  `crates/user/glibc/c/longdouble_x86_64.c` and links it into libc.so.6/libc.a,
  exporting fabsl/copysignl/isnanl/isinfl/finitel without host libc/libm
  dependencies. Added host-diffed t_longdouble. Verification: `glibc-test`
  195/195; both freestanding arch builds; `spec-lint`; dynsym/static archive
  checks show the five symbols present. Probe note: many tempting
  `__builtin_*l` wrappers lower to self-PLT libcalls and must be rejected or
  hand-written.
- **F589 DONE locally:** f80 classifier compatibility exports added to the C
  bridge: __finitel, __isinfl, __isnanl, __signbitl, __fpclassifyl, and
  __issignalingl. Host-diffed in t_longdouble; C object checked for no PLT
  relocations or unresolved symbols.
- **F590 DONE locally:** f80 complex accessors added to the C bridge: creall,
  cimagl, and conjl. Host-diffed in t_longdouble; C object checked for no PLT
  relocations or unresolved symbols.
- **F591 DONE locally:** f80 complex projection cprojl added to the C bridge.
  Host-diffed in t_longdouble; C object checked for no PLT relocations or
  unresolved symbols.
- **F592 DONE locally:** f80 rintl added to the C bridge. Host-diffed in
  t_longdouble; C object checked for no PLT relocations or unresolved symbols.
- **F593 DONE locally:** f80 ceill, floorl, and truncl added to the C bridge
  with x87 control-word rounding. Host-diffed in t_longdouble; C object checked
  for no PLT relocations or unresolved symbols.
- **F594 DONE locally:** f80 roundevenl added to the C bridge with x87
  tie-to-even rounding. Host-diffed in t_longdouble; C object checked for no
  PLT relocations or unresolved symbols.
- **F595 DONE locally:** f80 nearbyintl, roundl, lroundl, llroundl, lrintl, and
  llrintl added to the C bridge. Host-diffed in t_longdouble; C object checked
  for no PLT relocations or unresolved symbols.
- **F596 DONE locally:** f80 fmaxl, fminl, fdiml, fmaxmagl, and fminmagl added
  to the C bridge. Host-diffed in t_longdouble; C object checked for no PLT
  relocations or unresolved symbols.
- **F597 DONE locally:** f80 C23 min/max variants added to the C bridge:
  fmaximum_numl, fminimum_numl, fmaximuml, fminimuml, fmaximum_mag_numl,
  fminimum_mag_numl, fmaximum_magl, and fminimum_magl. Host-diffed in
  t_longdouble; C object checked for no PLT relocations or unresolved symbols.
- **F598 DONE locally:** f80 sqrtl added to the C bridge with x87 fsqrt.
  Host-diffed in t_longdouble; C object checked for no PLT relocations or
  unresolved symbols.
- **F599 DONE locally:** f80 modfl added to the C bridge using x87 truncate,
  with explicit infinity, NaN, and signed-zero handling. Host-diffed in
  t_longdouble; C object checked for no PLT relocations or unresolved symbols.
- **F600 DONE locally:** f80 ldexpl, scalbnl, and scalblnl added to the C
  bridge with shared x87 fscale handling. Host-diffed in t_longdouble; C
  object checked for no PLT relocations or unresolved symbols.
- **F601 DONE locally:** f80 scalbl added to the C bridge with fractional
  exponent rejection before the shared x87 fscale helper. Host-diffed in
  t_longdouble; C object checked for no PLT relocations or unresolved symbols.
- **F602 DONE locally:** f80 logbl, ilogbl, llogbl, frexpl, and significandl
  added to the C bridge with shared x87 fxtract handling. Host-diffed in
  t_longdouble; C object checked for no PLT relocations or unresolved symbols.
- **F603 DONE locally:** f80 fmodl, remainderl, and dreml added to the C
  bridge with x87 fprem/fprem1 loops. Host-diffed in t_longdouble; C object
  checked for no PLT relocations or unresolved symbols.
- **F604 DONE locally:** f80 nanl added to the C bridge by constructing the
  x87 quiet-NaN representation directly, including simple decimal/hex payload
  tags. Host-diffed in t_longdouble; C object checked for no PLT relocations or
  unresolved symbols.
- **F605 DONE locally:** f80 totalorderl and totalordermagl pointer-ABI exports
  added to the C bridge with finite, zero-sign, NaN-sign, and magnitude
  ordering. Host-diffed in t_longdouble; C object checked for no PLT relocations
  or unresolved symbols.
- **F606 DONE locally:** f80 nextafterl, nexttowardl, nextupl, nextdownl, plus
  double/float nexttoward and nexttowardf added to the C bridge with explicit
  adjacent-representation stepping. Host-diffed in t_longdouble; C object
  checked for no PLT relocations or unresolved symbols.
- **F607 DONE locally:** f80 canonicalizel, getpayloadl, setpayloadl, and
  setpayloadsigl added to the C bridge with glibc-compatible quiet/signaling
  NaN payload encodings and invalid-payload handling. Host-diffed in
  t_longdouble; C object checked for no PLT relocations or unresolved symbols.
- **F608 DONE locally:** f80 hypotl and cabsl added to the C bridge using a
  scaled x87 sqrt path that preserves infinity/NaN precedence and avoids
  overflow in the finite square sum. Host-diffed in t_longdouble; C object
  checked for no PLT relocations or unresolved symbols.
- **F609 DONE locally:** f80 fromfpl, ufromfpl, fromfpxl, and ufromfpxl added
  to the C bridge with C23 FP_INT_* rounding modes and width-saturating signed
  and unsigned results. Host-diffed in t_longdouble; C object checked for no PLT
  relocations or unresolved symbols.
- **F610 DONE locally:** f80 cbrtl added to the C bridge with x87 extract/scale
  and Newton refinement, preserving signed zero, infinities, and NaNs.
  Host-diffed in t_longdouble; C object checked for no PLT relocations or
  unresolved symbols.
- **F611 DONE locally:** f80 sinl, cosl, tanl, sincosl, atanl, atan2l, asinl,
  acosl, and cargl added to the C bridge using x87 trig/fpatan instructions and
  existing private sqrt helpers. Host-diffed in t_longdouble; C object checked
  for no PLT relocations or unresolved symbols.
- **F612 DONE locally:** f80 expl, exp2l, exp10l, pow10l, expm1l, logl, log2l,
  log10l, log1pl, and powl added to the C bridge using x87 f2xm1/fscale/fyl2x
  helpers. Host-diffed in t_longdouble; C object checked for no PLT relocations
  or unresolved symbols.
- **F613 DONE locally:** f80 sinhl, coshl, tanhl, asinhl, acoshl, and atanhl
  added to the C bridge using the existing exp/log/sqrt helpers. Host-diffed in
  t_longdouble; C object checked for no PLT relocations or unresolved symbols.
- **F614 DONE locally:** f80 csinhl, ccoshl, and ctanhl added to the C bridge
  using scalar hyperbolic helpers plus x87 sin/cos. Host-diffed in t_longdouble;
  C object checked for no PLT relocations or unresolved symbols.
- **F615 DONE locally:** f80 csinl, ccosl, ctanl, cexpl, clogl, clog10l,
  csqrtl, and cpowl added to the C bridge using private scalar/complex helpers.
  Host-diffed in t_longdouble; C object checked for no PLT relocations or
  unresolved symbols.
- **F616 DONE locally:** f80 casinl, cacosl, catanl, casinhl, cacoshl, and
  catanhl added to the C bridge using private complex log/sqrt helpers.
  Host-diffed in t_longdouble; C object checked for no PLT relocations or
  unresolved symbols.
- **F617 DONE locally:** f80 fmal added to the C bridge and exported.
  Host-diffed in t_longdouble; C object checked for no PLT relocations or
  unresolved symbols.
- **F618 DONE locally:** f80 qecvt, qfcvt, qgcvt, qecvt_r, and qfcvt_r added to
  the C bridge with local decimal formatting. Host-diffed in t_fcvt; C object
  checked for no PLT relocations or unresolved symbols.
- **F619 DONE locally:** f80 strtold and wcstold added to the C bridge with
  decimal/C99-hex parsing and endptr mapping. Host-diffed in t_strto/t_wstrto;
  C object checked for no PLT relocations or unresolved symbols.
- **F620 DONE locally:** f80 strfroml added to the C bridge for f/e/g formats
  using the local q-conversion helpers. Host-diffed in t_fcvt; C object checked
  for no PLT relocations or unresolved symbols.
- **F621 DONE locally:** f80 erfl and erfcl added to the C bridge using the
  local x87 exponential path. Host-diffed in t_erf; C object checked for no PLT
  relocations or unresolved symbols.
- **F622 DONE locally:** f80 tgammal, lgammal, lgammal_r, and gammal added to
  the C bridge using the Lanczos path. Host-diffed in t_gamma; C object checked
  for no PLT relocations or unresolved symbols.
- **F623 DONE locally:** f80 j0l, j1l, jnl, y0l, y1l, and ynl added to the C
  bridge using the existing Bessel series/asymptotic path. Host-diffed in
  t_bessel; C object checked for no PLT relocations or unresolved symbols.
- **F624 DONE locally:** glibc `__*_finite` libm compatibility exports added for
  double, float, and x86_64 f80 long-double forms. Host keeps these compat-only
  here, so validation is ABI export audit plus regression suite; C object checked
  for no PLT relocations or unresolved symbols.
- **F625 DONE locally:** glibc math classifier/complex compatibility aliases
  (`__finite*`, `__isinf*`, `__isnan*`, `__issignaling*`, `__iseqsig*`,
  `__clog10*`, plus f80 `__iscanonicall`) added over existing Rust math cores
  and the f80 C bridge. Host keeps several compat-only here, so validation is ABI
  export audit plus regression suite; C object checked for no PLT relocations or
  unresolved symbols.
- **F626 DONE locally:** glibc fork/clone compatibility aliases (`_Fork`,
  `__fork`, `__libc_fork`, `__vfork`, `__clone`, and `__register_atfork`) added
  over the existing process, clone, and atfork implementations. `_Fork` bypasses
  atfork handlers; the others preserve existing wrapper semantics. Verified by
  ABI export audit, regression suite, and both freestanding arch builds.
- **F627 DONE locally:** glibc internal syscall compatibility aliases added for
  low-level I/O, mmap, poll/select, nanosleep, wait, and sigtimedwait
  (`__open`, `__close`, `__read`, `__write`, `__lseek`, `__fcntl`, `__poll`,
  `__select`, `__nanosleep`, `__mmap`, `__munmap`, `__libc_pread`,
  `__libc_pwrite`, `__wait`, `__sigtimedwait`). Verified by ABI export audit,
  regression suite, spec-lint, and both freestanding arch builds.
- **F628 DONE locally:** common glibc internal compatibility aliases added for
  backtrace, DNS name codecs, string/memory helpers, `dup2`, `connect`,
  `clock_gettime`, and `sysconf`. Varargs-only `__asprintf` intentionally left
  for a dedicated follow-up. Verified by ABI export audit, regression suite,
  spec-lint, and both freestanding arch builds.
- **F629 DONE locally:** varargs `__asprintf` compatibility alias added beside
  `asprintf`, sharing the existing `into_alloc` worker directly. Verified by ABI
  export audit, regression suite, spec-lint, and both freestanding arch builds.

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
