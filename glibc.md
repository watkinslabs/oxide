# glibc — remaining TODO

> Live audit (docs/59 §9): `nm -D` host Fedora glibc (4214 public) vs our
> `libc.so.6` (**~2092 exported**). Directive: implement EVERYTHING achievable
> (full compliance), value-agnostic. Only the hard-blocked f80/`_Float128` (§3)
> are truly impossible. Conformance **191/191**; both arches boot.

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
Remaining RPC =
clnt_*/svc_*/auth_*/pmap_* (sockets) + the rpc_msg XDR filters (xdr_callmsg/
replymsg/opaque_auth/...). Conformance 163/163.

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
- **resolver (~48)** — res_query/search/send/mkquery/nquery/nsearch/nsend/ninit/
  res_gethostby*; __res_state; ns_* (ns_get16/put/name/parse); getaddrinfo_a/gai_*
  (async, needs threads); (getifaddrs/freeifaddrs DONE — net/ifaddrs.rs, F510,
  netlink RTM_GETLINK+GETADDR, host-diffable t_getifaddrs.c);
  (inet6_option_* DONE — F537, net/inet6_option.rs, RFC2292 obsolete
  cmsghdr-wrapped builder/parser with glibc-matched padding, host-diffable
  t_inet6_option.c; isctype DONE — ctype/table.rs, host-diffable t_ctype2.c.)
  (inet6_opt_* DONE — F518, net/inet6_opt.rs, host-diffable t_inet6_opt.c).
  (inet6_rth_* DONE — F517, net/inet6_rth.rs, host-diffable t_inet6_rth.c).
  (inet_net_pton/ntop/neta/nsap_addr/nsap_ntoa DONE — F516, net/inet.rs,
  AF_INET classful-default-bits + class-D=4, host-diffable t_inet_net.c via
  -lresolv oracle; dn_comp/dn_expand/dn_skipname + recvmmsg/sendmmsg done.)
  (ns_get16/get32/put16/put32 + ns_name_ntop/pton/skip DONE — F531,
  net/nameser.rs RFC1035 codec w/ glibc escaping (special \, \DDD nonprint,
  root "."), host-diffable t_nameser.c.
  (ns_name_unpack/uncompress + ns_samename/samedomain/subdomain/makecanon DONE
  — F532, net/nameser.rs, host-diffable t_nameser2.c.)
  (ns_format_ttl/ns_parse_ttl DONE — F533, net/nameser.rs, host-diffable
  t_nsttl.c. ns_datetosecs DEFERRED — host glibc's range validation rejects
  dates past a version/time-dependent recent-past cutoff (1980 fails, 2024
  passes), so not safely bit-diffable.)
  (ns_name_pack/ns_name_compress DONE — F534, net/nameser.rs, uncompressed
  emit like dn_comp (matches glibc when dnptrs==NULL; full labels are
  wire-legal), host-diffable t_nameser2.c. STILL TODO: compression-pointer
  emit when dnptrs given; ns_datetosecs.)
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
- ~~**fts/fts64 (10)**~~ DONE — posix/fts.rs (F511). BSD pre/post-order iterator,
  cycle detect (FTS_DC), FTS_LOGICAL/PHYSICAL/SEEDOT/XDEV/COMFOLLOW + fts_set
  SKIP/FOLLOW. Exact FTSENT ABI (112B). Host-diffable t_fts.c over a temp tree.
- **wide `_l` (~25)** — isw*_l, tow{lower,upper,ctrans}_l, wctype_l/wctrans_l/
  iswctype_l, wcs{coll,xfrm,casecmp,ncasecmp}_l, wcsto{d,f,l,ul,ll,ull,f32,f64}_l,
  wcsftime_l. Delegate to the C-locale base (like the narrow _l already done).
- **C23 narrowing math** — f32add/f32div/f32mul/f32sub/f32sqrt/f32fma(+f64x...)
  STILL DEFERRED (round-to-odd). exp10m1/exp2m1/log10p1/log2p1 done.
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
- **BSD net auth** — rcmd/rexec/ruserok/iruserok/rresvport(_af), bindresvport.
- **re_* BSD regex (~12)** — re_comp/re_exec/re_compile_pattern/re_search/re_match.
- **libxcrypt** — (crypt_gensalt/_rn/_ra + crypt_rn/crypt_ra + crypt_preferred_method
  DONE — F536, crypt/mod.rs; $5$/$6$ salt = crypt-itoa64 of rbytes (NULL⇒getrandom),
  rounds= iff ≠ default; host harness now links -lcrypt for default libxcrypt
  symbols; Rust vectors from libxcrypt. preferred_method="$6$" — yescrypt not
  impl.) (crypt_checksalt, crypt_gensalt_r, fcrypt, xcrypt/xcrypt_r,
  xcrypt_gensalt/xcrypt_gensalt_r DONE — F548, crypt/mod.rs; xcrypt/fcrypt
  are non-default compat-only on host so ABI-audited, while crypt_checksalt and
  crypt_gensalt_r are host-diffed in t_crypto.c.) STILL TODO:
  xencrypt/xdecrypt (SunRPC DES).
- Re-audit (docs/59 §9 / state.md recipe) for stragglers after each batch.

## 3. HARD-BLOCKED (glibc_unsupported.md): long double `*l` + `_Float128`/
`_Float32x`/`_Float64x` (~700). No Rust extern-C type. Only the `%Lf` printf shim.

## Done (this run, ~41 PRs, 160/160)
pthread FULL surface, C11 threads, modern syscalls, locale `_l` (narrow),
account-db, eaccess/sigisemptyset/__fpclassify/gets, in6addr, mbrtoc32/c32rtomb,
wcwidth/wcswidth, clone(2), dl_iterate_phdr, _FloatN math aliases (246),
ether_aton/ntoa + arc4random, acct/clock_getcpuclockid/execvpe, C23
fmaximum/fminimum, netdb _r (serv/proto/net), dlvsym/dladdr1/dlmopen/dlinfo,
C23 *pi/*m1/*p1, /etc/ethers DB, /etc/ttys DB, /etc/aliases DB, /etc/gshadow,
/etc/rpc DB, dn_comp/expand/skipname, sendmmsg/recvmmsg, C23 <stdbit.h> (42).
