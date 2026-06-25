# glibc — remaining TODO

> Live audit (docs/59 §9): `nm -D` host Fedora glibc (4214 public) vs our
> `libc.so.6` (**~2295 exported**). Directive: implement EVERYTHING achievable
> (full compliance), value-agnostic. Achievable audited surface now includes an
> x86_64 C ABI bridge for real f80 long-double entry points. Remaining audit
> names are mostly broader long-double/quad families plus host
> `errno@@GLIBC_PRIVATE`, which is an ELF TLS data symbol. Conformance
> **195/195**; both arches build.

## 1. The one migration blocker (docs/59 §9.4)
8 `__`-aliased DATA symbols (__environ/_environ/__signgam/__tzname/__timezone/
__daylight/__progname/__progname_full). Export works; libc reaches its own data
DIRECTLY not via GOT, so copy-reloc interposition in an executable desyncs. Fix =
GOT-indirect codegen for copy-relocatable libc data. Likely moot for real GNU-ld
vendor binaries (confirm in G19d). Reverted; don't re-add without the codegen fix.

## NOTE (latest++): XDR layer DONE — rpc/xdr.rs: xdrmem_create + 10-op vtable +
all scalar/fixed-width/hyper/float/double primitives + opaque/bytes/string/
wrapstring/netobj + vector/array/reference/pointer + xdr_sizeof + getpos/setpos.
RFC4506-verified vs our libc (glibc keeps xdr_* COMPAT-ONLY → not host-diffable).
Also DONE: SysV signal (sighold/sigrelse/sigignore/sigset), the missing
C23 `<stdbit.h>` unsigned long / unsigned long long variants (F545), and
llseek + C-locale time `_l` wrappers (F546), and sem_clockwait (F547).
Also DONE: libxcrypt compatibility aliases + crypt_checksalt (F548).
Also DONE: C-locale strtof32_l/strtof64_l (F549); strtold/wcstold remain
hard-blocked with the other long-double ABI functions.
Also DONE: resolver validators res_hnok/res_ownok/res_mailok/res_dnok (F550)
gethostent_r (F551), setlogin ENOSYS stub (F552), and profil/sprofil +
gmon no-ops (F553).
Also DONE: register_printf_type (F554).
Also DONE: res_gethostbyname/res_gethostbyname2/res_gethostbyaddr aliases (F555).
Also DONE: chflags/fchflags legacy stubs (F556).
Also DONE: klogctl syslog(2) wrapper (F557).
Also DONE: public sigreturn ENOSYS stub (F558).
Also DONE: ns_name_ntol/ns_name_rollback (F559).
Also DONE: ns_datetosecs (F560).
Also DONE: source-filter socket APIs (F561).
Also DONE: reserved-port helpers bindresvport/rresvport(_af) (F562).
Also DONE: ruserok/iruserok remote-login denials (F563).
Also DONE: rcmd/rexec remote-command failure stubs (F564).
Also DONE: mcheck_check_all malloc-debug no-op (F565).
Also DONE: BSD regex re_comp/re_exec (F566).
Also DONE: GNU regex re_compile_pattern/re_compile_fastmap/re_match/re_search (F567).
Also DONE: GNU regex re_syntax_options/re_set_syntax (F568).
Also DONE: GNU regex re_match_2/re_search_2/re_set_registers (F569).
Also DONE: psiginfo SI_USER output path (F570).
Also DONE: malloc_info minimal XML + bad-option EINVAL return (F571).
Also DONE: rexecoptions remote-exec compatibility data symbol (F572).
Also DONE: ruserpass no-.netrc compatibility path (F573).
Also DONE: C23 narrowing math fadd/fsub/fmul/fdiv/fsqrt/ffma + f32* f64 aliases (F574).
Also DONE: res_mkquery/res_nmkquery standard QUERY packet builders (F575).
Also DONE: gai_error/gai_cancel/gai_suspend async getaddrinfo status helpers (F576).
Also DONE: getaddrinfo_a synchronous GAI_WAIT/GAI_NOWAIT compatibility path (F577).
Also DONE: mallwatch + res_send_setqhook/res_send_setrhook compat exports (F578).
Also DONE: obsolete Linux ENOSYS stubs bdflush/create_module/query_module/
get_kernel_syms/nfsservctl/sstk (F579).
Also DONE: STREAMS ENOSYS stubs getmsg/putmsg/getpmsg/putpmsg/fattach/
fdetach/isastream (F580).
Also DONE: legacy compat exports matherr, sigvec, step/advance, loc1/loc2/locs,
and tr_break (F581).
Also DONE: resolver UDP query/send/search exports res_query/res_search/
res_querydomain/res_send and res_n* variants (F582).
Also DONE: SunRPC keyserv/netname/DES compat exports getnetname,
host2netname/user2netname, netname2host/netname2user,
getpublickey/getsecretkey, key_* helpers, passwd2des, xencrypt/xdecrypt (F583).
Also DONE: SunRPC client/auth/portmapper compat stubs authdes/authunix/authnone,
clnt_*, pmap_*, callrpc/registerrpc, rpc_createerr, get_myaddress/getrpcport,
and rtime (F584).
Also DONE: SunRPC service/SVC compat globals and stubs svc_fdset/svc_pollfd/
svc_max_pollfd/svcauthdes_stats, svc*_create, svc_register/unregister,
svc_getreq*, svc_run/exit, svcerr_*, and xprt_register/unregister (F585).
Also DONE: remaining SunRPC/XDR compatibility filter exports xdr_des_block,
xdr_opaque_auth, xdr_authunix_parms, xdr_pmap/pmaplist, xdr_union, rpc message
and key filters, xdrrec_*, and xdrstdio_create (F586). Remaining audit surface
was long-double-family ABI, open_wmemstream, and public errno.
Also DONE: open_wmemstream wide memory stream, including host-diffed fputws/
fseek/fputwc/fflush coverage (F587). Remaining audit surface is long-double-
family ABI plus public errno. Final audit note: host errno is a GLIBC_PRIVATE
TLS data symbol; our per-thread errno is available through __errno_location,
and exporting a plain `errno` object would be semantically wrong (D112).
Also DONE: first real x86_64 f80 long-double ABI bridge (F588): xtask compiles
and links `crates/user/glibc/c/longdouble_x86_64.c` into libc.so.6/libc.a,
exporting fabsl/copysignl/isnanl/isinfl/finitel without host libc/libm
dependencies. Host-diffed in t_longdouble.
Also DONE: f80 classifier compatibility bridge (F589): __finitel,
__isinfl, __isnanl, __signbitl, __fpclassifyl, and __issignalingl exported from
the same freestanding C object and host-diffed in t_longdouble.
Also DONE: f80 complex accessors (F590): creall, cimagl, and conjl exported from
the same freestanding C object and host-diffed in t_longdouble.
Also DONE: f80 complex projection (F591): cprojl exported from the same
freestanding C object and host-diffed in t_longdouble.
Also DONE: f80 rounding-to-integral (F592): rintl exported from the same
freestanding C object and host-diffed in t_longdouble.
Also DONE: f80 x87 directed rounding (F593): ceill, floorl, and truncl exported
from the same freestanding C object and host-diffed in t_longdouble.
Also DONE: f80 tie-to-even rounding (F594): roundevenl exported from the same
freestanding C object and host-diffed in t_longdouble.
Also DONE: f80 rounding batch (F595): nearbyintl, roundl, lroundl, llroundl,
lrintl, and llrintl exported from the same freestanding C object and
host-diffed in t_longdouble.
Also DONE: f80 min/max batch (F596): fmaxl, fminl, fdiml, fmaxmagl, and
fminmagl exported from the same freestanding C object and host-diffed in
t_longdouble.
Also DONE: f80 C23 min/max batch (F597): fmaximum_numl, fminimum_numl,
fmaximuml, fminimuml, fmaximum_mag_numl, fminimum_mag_numl, fmaximum_magl, and
fminimum_magl exported from the same freestanding C object and host-diffed in
t_longdouble.
Also DONE: glibc `__*_finite` libm compatibility aliases (F624): double/float
wrappers over the existing Rust libm cores plus x86_64 f80 wrappers in the C
bridge. Host keeps these symbols compat-only here, so verified by ABI export
audit, regression suite, both freestanding arch builds, and C-object no-PLT
audit.
Also DONE: glibc math classifier/complex compatibility aliases (F625):
`__finite*`, `__isinf*`, `__isnan*`, `__issignaling*`, `__iseqsig*`,
`__clog10*`, plus f80 `__iscanonicall`, over existing Rust math cores and the
x86_64 f80 C bridge. Verified by ABI export audit, regression suite, both
freestanding arch builds, and C-object no-PLT audit.
Also DONE: glibc fork/clone compatibility aliases (F626): `_Fork`, `__fork`,
`__libc_fork`, `__vfork`, `__clone`, and `__register_atfork` exported over the
existing process, clone, and atfork implementations. Verified by ABI export
audit, regression suite, and both freestanding arch builds.
Also DONE: glibc internal syscall compatibility aliases (F627): low-level I/O,
mmap/munmap, poll/select, nanosleep, wait, sigtimedwait, and libc pread/pwrite
aliases exported over existing syscall wrappers. Verified by ABI export audit,
regression suite, spec-lint, and both freestanding arch builds.

## NOTE (latest): also DONE since the §-headers below were written —
wide `_l` (isw*/tow*/wcs*/wcsto*_l + __isoc23_wcsto*_l), LFS *64 aliases
(mkstemp64 family + preadv64/pwritev64(v2) + strtof64/wcstof64) + mkostemps,
C23 `<stdbit.h>` (70), gnu_dev_*/swab/ftok/timespec_get(res)/group_member/ualarm,
/etc/rpc DB, dn_comp/expand/skipname, sendmmsg/recvmmsg, /etc/{ethers,ttys,
aliases,gshadow} DBs, C23 *pi/*m1/*p1 + fmaximum/fminimum, netdb _r, dl extras.
Conformance 162/162. So §2.4 (wide _l) and the LFS/stdbit/misc parts are CLOSED.

## 2. Remaining achievable clusters (DO ALL)
- **Sun RPC (~140)** — clnt_*/svc_*/auth_*/xdr_*/pmap_*/key_*/callrpc/registerrpc/
  xprt/svcerr/svctcp/svcudp/getrpcport/netname/passwd2des/des_setparity/ruserpass.
  A whole subsystem (XDR serialization + RPC client/server). Biggest block.
  (getrpcent/byname/bynumber + _r already done — net/rpcent.rs.)
- **resolver (~48)** — res_query/search/send/nquery/nsearch/nsend/ninit/
  res_gethostby*; __res_state; ns_* (ns_get16/put/name/parse); getaddrinfo_a/gai_*
  (async, needs threads); (getipv4sourcefilter/setipv4sourcefilter +
  getsourcefilter/setsourcefilter DONE — F561, net/socket.rs, IP_MSFILTER/
  MCAST_MSFILTER packing over getsockopt/setsockopt; invalid-fd EBADF
  host-diffed in t_inet2.c); (getifaddrs/freeifaddrs DONE — net/ifaddrs.rs, F510,
  netlink RTM_GETLINK+GETADDR, host-diffable t_getifaddrs.c);
  (inet6_option_* DONE — F537, net/inet6_option.rs, RFC2292 obsolete
  cmsghdr-wrapped builder/parser with glibc-matched padding, host-diffable
  t_inet6_option.c; isctype DONE — ctype/table.rs, host-diffable t_ctype2.c.)
  (inet6_opt_* DONE — F518, net/inet6_opt.rs, host-diffable t_inet6_opt.c).
  (inet6_rth_* DONE — F517, net/inet6_rth.rs, host-diffable t_inet6_rth.c).
  (inet_net_pton/ntop/neta/nsap_addr/nsap_ntoa DONE — F516, net/inet.rs,
  AF_INET classful-default-bits + class-D=4, host-diffable t_inet_net.c via
  -lresolv oracle; dn_comp/dn_expand/dn_skipname + recvmmsg/sendmmsg done.)
  (ns_get16/get32/put16/put32 + ns_name_ntop/ntol/pton/skip +
  ns_name_rollback DONE — F531/F559,
  net/nameser.rs RFC1035 codec w/ glibc escaping (special \, \DDD nonprint,
  root "."), lowercasing, and compression-table rollback; host-diffable
  t_nameser.c.
  (ns_name_unpack/uncompress + ns_samename/samedomain/subdomain/makecanon DONE
  — F532, net/nameser.rs, host-diffable t_nameser2.c.)
  (ns_format_ttl/ns_parse_ttl DONE — F533, net/nameser.rs, host-diffable
  t_nsttl.c. ns_datetosecs DONE — F560, net/nameser_date.rs, yyyymmddhhmmss
  UTC parser with glibc/BIND sticky errp validation and uint32 wrapping
  arithmetic; host-diffable t_nsttl.c.)
  (ns_name_pack/ns_name_compress DONE — F534, net/nameser.rs, uncompressed
  emit like dn_comp (matches glibc when dnptrs==NULL; full labels are
  wire-legal), host-diffable t_nameser2.c. STILL TODO: compression-pointer
  emit when dnptrs given.)
  (ns_initparse/ns_parserr/ns_skiprr/ns_msg_getflag DONE — F535, net/nameser.rs,
  NsMsg(80B)/NsRr(1048B) ABI structs + header/section walk + per-RR name
  expansion; host-diffable t_nsmsg.c (flags, question, multi-RR, OOB).)
  (ns_sprintrr/ns_sprintrrf DONE — F538, net/nameser.rs, zone-style RR
  formatting for A/AAAA/NS/CNAME/PTR/MX/TXT plus RFC3597 unknown-RR fallback,
  canonical absolute names, origin-relative owner/RDATA names, TTL/class/type
  tab-column layout; host-diffable t_nssprint.c via -lresolv oracle.)
  (res_hnok/res_ownok/res_mailok/res_dnok DONE — F550, net/nameser.rs,
  host/mailbox/owner/general DNS domain validators with glibc-matched
  wildcard, escaping, whitespace, label-length, and total-size behavior;
  host-diffable t_resok.c via -lresolv oracle.)
  (gethostent_r DONE — F551, net/netdb_host.rs, reentrant /etc/hosts
  enumeration over the existing cursor + caller-buffer hostent packer;
  host-diffable t_netdb_r.c.)
  (res_gethostbyname/res_gethostbyname2/res_gethostbyaddr DONE — F555,
  net/netdb_host.rs, compatibility aliases over gethostby*; host glibc keeps
  these compat-only here, so ABI-audit verified.)
  (res_mkquery/res_nmkquery DONE — F575, net/resolv_query.rs, pure standard
  QUERY packet builders using ns_name_compress and resolver options for RD/AD
  flags; host-diffable t_res_mkquery.c masks random IDs.)
  (res_query/res_search/res_querydomain/res_send and res_n* variants DONE —
  F582, net/resolv_query.rs, UDP to first IPv4 /etc/resolv.conf nameserver with
  bounded ppoll timeout.)
  (gai_error/gai_cancel/gai_suspend DONE — F576, net/addrinfo.rs, completed/
  unsubmitted async status helpers plus GNU EAI strerror strings; host-diffable
  t_gai_async.c. getaddrinfo_a DONE — F577, synchronous GAI_WAIT/GAI_NOWAIT
  completion over getaddrinfo with per-request status/result storage.)
- ~~**fts/fts64 (10)**~~ DONE — posix/fts.rs (F511). BSD pre/post-order iterator,
  cycle detect (FTS_DC), FTS_LOGICAL/PHYSICAL/SEEDOT/XDEV/COMFOLLOW + fts_set
  SKIP/FOLLOW. Exact FTSENT ABI (112B). Host-diffable t_fts.c over a temp tree.
- **wide `_l` (~25)** — isw*_l, tow{lower,upper,ctrans}_l, wctype_l/wctrans_l/
  iswctype_l, wcs{coll,xfrm,casecmp,ncasecmp}_l, wcsto{d,f,l,ul,ll,ull,f32,f64}_l,
  wcsftime_l. Delegate to the C-locale base (like the narrow _l already done).
- **C23 narrowing math** — f64x/long-double variants remain blocked/deferred
  with the rest of long-double ABI. exp10m1/exp2m1/log10p1/log2p1 done.
  fadd/fsub/fmul/fdiv/fsqrt/ffma + f32addf64/f32subf64/f32mulf64/
  f32divf64/f32sqrtf64/f32fmaf64 DONE — F574, math/narrow.rs, float result
  from existing f64 operations; exact host-diffed sample values in t_c23math.c.
  (logp1/logp1f/logp1f32/f64 + remquof/remquof32 + lgammaf32_r/f64_r +
  strfromf64 DONE — F528, _Float32==float/_Float64==double aliases of existing
  fns; bit-exact host-diffable t_c23math.c).
- **LFS aliases** — mkstemp64/mkostemp64/mkstemps64/mkostemps(64)/preadv64(v2)/
  pwritev64(v2)/lockf64/scandirat64/strtof64/wcstof64. Mostly thin == aliases.
- **SysV signal compat** — sigset/sighold/sigrelse/sigignore; sigvec; sigreturn.
- **misc syscalls** —
  (tee/vmsplice/sync_file_range DONE — F521, posix/morecalls.rs, t_splicefam.c;
  splice/getcpu also done).
  (sched_getattr/setattr/getcpu DONE — F522, posix/sched.rs, t_schedattr.c),
  (mlock2/pivot_root/open_tree/move_mount/mount_setattr DONE — F523,
  posix/morecalls.rs, t_mountmem.c).
  (execveat/sockatmark/isfdtype DONE — F525, posix/process.rs +
  net/socket.rs + posix/stat.rs; host-diffable t_morecalls.c).
  (pidfd_getpid/pidfd_spawn/pidfd_spawnp DONE — F526, posix/modern.rs
  (fdinfo "Pid:" parse) + posix/spawn.rs (clone CLONE_PIDFD reusing
  child_apply); host-diffable t_spawn.c via pidfd_open + waitid(P_PIDFD)).
  (glob_pattern_p + lchmod (fchmodat2) + dysize DONE — F530, posix/glob.rs +
  posix/fs.rs + time/tm.rs; host-diffable t_miscsmall.c).
  (getusershell/setusershell/endusershell DONE — F539, posix/usershell.rs,
  /etc/shells parser with glibc default fallback; host-diffable t_usershell.c).
  (ftime DONE — F540, time/clock.rs, CLOCK_REALTIME-backed legacy timeb fill;
  host-diffable property test t_ftime.c.)
  (gnu_get_libc_version/release DONE — F541, misc/gnu_version.rs, reports
  version-script ABI ceiling 2.38 + stable release; host-diffable property test
  t_gnu_version.c.)
  (argp_program_version_hook DONE — F542, posix/argp.rs + help.rs, exported
  hook pointer and --version dispatch precedence; host-diffable t_argp.c.)
  (getpw DONE — F543, nss/mod.rs, legacy uid→passwd-line renderer over
  /etc/passwd; host-diffable t_pwgr.c.)
  (ttyslot DONE — F544, posix/tty.rs, scans /etc/ttys via ttyent and returns
  the historical 1-based slot or Linux/glibc 0-on-miss; host-diffable
  t_ttyent.c.)
  (pkey_alloc/free/mprotect + pkey_get/set DONE — F529, posix/modern.rs;
  alloc/free/mprotect syscall passthrough both arches, get/set via PKRU
  (x86) / POR_EL0 (arm) register ops; host-diffable t_pkey.c).
  (revoke/ustat/uselib/modify_ldt/iopl/ioperm DONE — F527, posix/misc2.rs;
  revoke=ENOSYS stub, ustat/uselib x86 passthrough else ENOSYS, modify_ldt/
  iopl/ioperm x86-only; t_deprecated.c diffs revoke + x86 trio — ustat/uselib
  host-compat-only so not diff-linkable).
  (llseek + strftime_l/strptime_l/wcsftime_l DONE — F546, posix/io.rs +
  time/{strftime,strptime}.rs; time `_l` host-diffable in t_strftime.c, llseek
  implemented as LP64 lseek alias but host keeps it non-default compat-only),
  (sem_clockwait DONE — F547, rt/sem.rs; clockid-param absolute timeout shares
  the futex wait loop, host-diffable timeout coverage in t_ipcsem.c),
  (setlogin DONE — F552, glibc-matching ENOSYS stub host-diffed in
  t_deprecated.c),
  (profil/sprofil + monstartup/moncontrol/mcount DONE — F553, successful
  no-op compatibility hooks host-diffed in t_deprecated.c),
  (register_printf_type DONE — F554, GNU printf extension type-ID allocator
  host-diffed in t_printf_ext.c),
  (chflags/fchflags DONE — F556, posix/misc2.rs, glibc-compatible legacy
  stubs: chflags returns ENOSYS and fchflags returns EINVAL; host-diffed in
  t_deprecated.c),
  (klogctl DONE — F557, posix/morecalls.rs + internal/nr.rs, thin syslog(2)
  wrapper with x86_64/aarch64 syscall numbers; host-diffed EPERM in
  t_sysmisc.c),
  (sigreturn DONE — F558, signal/sigaction.rs, public obsolete ENOSYS stub
  host-diffed in t_signal.c; internal rt_sigreturn restorer remains separate),
  (psiginfo DONE — F570, signal/legacy.rs, glibc SI_USER output path with
  psignal-style fallback; host-diffed via captured stderr in t_ucontext.c),
  (malloc_info DONE — F571, malloc/introspect.rs, bad-option EINVAL return
  host-diffed in t_crypto.c; option 0 emits minimal XML),
  lockf, scandirat, timespec_get/getres, ftok, ftime, ualarm,
  group_member, gnu_dev_major/minor/makedev, glob_pattern_p, ttyslot, scandirat/scandirat64 (DONE F519), lockf/lockf64 (DONE F520, posix/lockf.rs, t_lockf.c),
  (sigabbrev_np/sigdescr_np/strerrorname_np/strerrordesc_np DONE — F512,
  string/errname.rs complete 133-errno name+desc table, signal/desc.rs abbrev;
  host-diffable t_errname_np.c exhaustive), twalk_r,
  open_wmemstream,
  (wcslcat/wcslcpy DONE — F514, string/wstr.rs BSD bounded copy/concat; host-diffable t_wcslcpy.c), (twalk_r DONE — F515, search/tree.rs; host-diffable t_twalk_r.c),
  (mbrtoc8/mbrtoc16/c8rtomb/c16rtomb DONE — F513, locale/wchar.rs surrogate +
  code-unit state machines over mbstate_t; host-diffable t_uchar_c816.c),
  (posix_spawn_file_actions_add{chdir,fchdir,closefrom,tcsetpgrp}_np +
  posix_spawnattr_get/set{sched*,sig*,pgroup,cgroup_np} DONE — F524,
  posix/spawn.rs: new file-action kinds replayed in child_apply,
  SpawnAttr stores sched policy/prio + cgroup, SETSIGDEF resets to SIG_DFL,
  SETSCHED{ULER,PARAM} replayed via sched_set{scheduler,param}; host-diffable
  t_spawn.c chdir_np + attr getter round-trip).
- **BSD net auth** — remote-login helpers mostly closed; remaining netname/DES
  compatibility stays in Sun RPC/DES scope.
  (bindresvport/rresvport/rresvport_af DONE — F562, net/socket.rs, reserved
  port range bind with host-diffed unprivileged failure behavior in t_inet2.c.)
  (ruserok/ruserok_af/iruserok/iruserok_af DONE — F563, net/socket.rs,
  conservative remote-login denial behavior host-diffed in t_inet2.c.)
  (rcmd/rcmd_af/rexec/rexec_af DONE — F564, net/socket.rs, conservative
  EINVAL failure behavior for unresolved hosts host-diffed in t_inet2.c.
  rexecoptions data symbol DONE — F572, read/write host-diffed in t_inet2.c.)
  (ruserpass DONE — F573, net/socket.rs, no-.netrc path returns 0 with ENOENT
  and untouched outputs when HOME is missing; host-diffed in t_inet2.c.)
- **old regexp.h regex (~6)** — advance/step/loc1/loc2/locs/tr_break legacy
  interfaces/globals.
  (re_comp/re_exec DONE — F566, regex/mod.rs, process-global compiled pattern
  over the existing engine; host-diffed in t_regex.c.)
  (re_compile_pattern/re_compile_fastmap/re_match/re_search DONE — F567,
  regex/mod.rs, lower-level GNU buffer API over the existing engine with
  glibc-style register allocation for the tested path; host-diffed in
  t_regex.c.)
  (re_syntax_options/re_set_syntax DONE — F568, regex/mod.rs, global GNU
  syntax setting honored by re_compile_pattern for POSIX basic vs extended;
  host-diffed in t_regex.c.)
  (re_match_2/re_search_2/re_set_registers DONE — F569, regex/mod.rs,
  two-string GNU regex helpers and caller-owned register arrays over the
  existing engine; host-diffed in t_regex.c.)
- **libxcrypt** — (crypt_gensalt/_rn/_ra + crypt_rn/crypt_ra + crypt_preferred_method
  DONE — F536, crypt/mod.rs; $5$/$6$ salt = crypt-itoa64 of rbytes (NULL⇒getrandom),
  rounds= iff ≠ default; host harness now links -lcrypt for default libxcrypt
  symbols; Rust vectors from libxcrypt. preferred_method="$6$" — yescrypt not
  impl.) (crypt_checksalt, crypt_gensalt_r, fcrypt, xcrypt/xcrypt_r,
  xcrypt_gensalt/xcrypt_gensalt_r DONE — F548, crypt/mod.rs; xcrypt/fcrypt
  are non-default compat-only on host so ABI-audited, while crypt_checksalt and
  crypt_gensalt_r are host-diffed in t_crypto.c.) STILL TODO:
  xencrypt/xdecrypt (SunRPC DES).
- **malloc debug** — mcheck/mcheck_pedantic/mprobe/mtrace/muntrace already
  done; mcheck_check_all DONE — F565, malloc/introspect.rs, errno-preserving
  no-op host-diffed in t_crypto.c. STILL TODO: malloc_info; mallwatch is
  compat-only/non-linkable on this host.
- Re-audit (docs/59 §9 / state.md recipe) for stragglers after each batch.

## 3. DEFERRED ABI WORK: long double `*l` + `_Float128`/`_Float32x`/`_Float64x`
Rust still has no stable extern-C type for x86_64 f80 or IEEE quad returns, so
functions that directly pass/return those types need ABI-side bridge code.
F588 proves the x86_64 path by linking a freestanding C object for
fabsl/copysignl/isnanl/isinfl/finitel, and F589 extends it to f80 classifier
compatibility aliases. Remaining work is to grow that bridge carefully, reject
compiler builtins that lower to self-PLT libcalls, keep objects dependency-free,
and design the separate aarch64 quad-long-double surface.

## Done (this run, ~41 PRs, 160/160)
pthread FULL surface, C11 threads, modern syscalls, locale `_l` (narrow),
account-db, eaccess/sigisemptyset/__fpclassify/gets, in6addr, mbrtoc32/c32rtomb,
wcwidth/wcswidth, clone(2), dl_iterate_phdr, _FloatN math aliases (246),
ether_aton/ntoa + arc4random, acct/clock_getcpuclockid/execvpe, C23
fmaximum/fminimum, netdb _r (serv/proto/net), dlvsym/dladdr1/dlmopen/dlinfo,
C23 *pi/*m1/*p1, /etc/ethers DB, /etc/ttys DB, /etc/aliases DB, /etc/gshadow,
/etc/rpc DB, dn_comp/expand/skipname, sendmmsg/recvmmsg, C23 <stdbit.h> (42).
