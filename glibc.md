# glibc — remaining TODO

> Live audit (docs/59 §9): `nm -D` host Fedora glibc (4214 public) vs our
> `libc.so.6` (**~2060 exported**). Directive: implement EVERYTHING achievable
> (full compliance), value-agnostic. Only the hard-blocked f80/`_Float128` (§3)
> are truly impossible. Conformance **160/160**; both arches boot.

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
Also DONE: SysV signal (sighold/sigrelse/sigignore/sigset). Remaining RPC =
clnt_*/svc_*/auth_*/pmap_* (sockets) + the rpc_msg XDR filters (xdr_callmsg/
replymsg/opaque_auth/...). Conformance 163/163.

## NOTE (latest): also DONE since the §-headers below were written —
wide `_l` (isw*/tow*/wcs*/wcsto*_l + __isoc23_wcsto*_l), LFS *64 aliases
(mkstemp64 family + preadv64/pwritev64(v2) + strtof64/wcstof64) + mkostemps,
C23 `<stdbit.h>` (42), gnu_dev_*/swab/ftok/timespec_get(res)/group_member/ualarm,
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
  inet6_option_* (RFC2292 DEPRECATED, ~6) — DEFERRED: cmsghdr+ip6_hbh-wrapped,
  obsolete (host warns); intricate cmsg/alignment layout, low value.
  (inet6_opt_* DONE — F518, net/inet6_opt.rs, host-diffable t_inet6_opt.c).
  (inet6_rth_* DONE — F517, net/inet6_rth.rs, host-diffable t_inet6_rth.c).
  (inet_net_pton/ntop/neta/nsap_addr/nsap_ntoa DONE — F516, net/inet.rs,
  AF_INET classful-default-bits + class-D=4, host-diffable t_inet_net.c via
  -lresolv oracle; dn_comp/dn_expand/dn_skipname + recvmmsg/sendmmsg done.)
  (ns_get16/get32/put16/put32 + ns_name_ntop/pton/skip DONE — F531,
  net/nameser.rs RFC1035 codec w/ glibc escaping (special \, \DDD nonprint,
  root "."), host-diffable t_nameser.c.
  (ns_name_unpack/uncompress + ns_samename/samedomain/subdomain/makecanon DONE
  — F532, net/nameser.rs, host-diffable t_nameser2.c. STILL TODO: ns_name_pack/
  compress (compression-pointer emit must match glibc), ns_initparse/ns_parserr/
  ns_skiprr/ns_sprintrr (ns_msg/ns_rr parse), ns_datetosecs, ns_format_ttl/parse_ttl.)
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
  (pkey_alloc/free/mprotect + pkey_get/set DONE — F529, posix/modern.rs;
  alloc/free/mprotect syscall passthrough both arches, get/set via PKRU
  (x86) / POR_EL0 (arm) register ops; host-diffable t_pkey.c).
  (revoke/ustat/uselib/modify_ldt/iopl/ioperm DONE — F527, posix/misc2.rs;
  revoke=ENOSYS stub, ustat/uselib x86 passthrough else ENOSYS, modify_ldt/
  iopl/ioperm x86-only; t_deprecated.c diffs revoke + x86 trio — ustat/uselib
  host-compat-only so not diff-linkable).
  setlogin, lockf, scandirat, timespec_get/getres, ftok, ftime, ualarm,
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
- **libxcrypt** — crypt_gensalt(+_r/_ra/_rn)/crypt_ra/crypt_rn/crypt_preferred_method/
  crypt_checksalt/fcrypt/xcrypt/xencrypt/xdecrypt.
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
