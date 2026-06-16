# glibc — remaining TODO

> Live audit (docs/59 §9): `nm -D` host Fedora glibc (4214 public) vs our
> `libc.so.6` (1672 exported). The libc **function** surface the 95 vendor
> binaries reference is COMPLETE — conformance 144/144, both arches boot.
> What's left below is the FULL upstream surface (most non-vendor) + the one
> real migration blocker. Counts current as of the pthread/C11/syscalls/locale/
> account-db/wide/clone/dl_iterate_phdr pass.

## 1. VENDOR-NEEDED gap — 8 symbols, ONE blocker (the only thing G19d truly needs)

`__environ` `_environ` `__signgam` `__tzname` `__timezone` `__daylight` `__progname` `__progname_full`

These are `.set` aliases of canonical Rust statics (environ/signgam/tzname/…).
- **Export**: solved — a supplementary `--version-script` in `xtask glibc`
  build_sharedlib re-promotes them (rustc localizes bare asm symbols otherwise).
- **Blocker (docs/59 §9.4)**: our libc reaches its own exported data DIRECTLY
  (PC-relative, same cdylib), not via the GOT, so an executable's copy-reloc
  interposition desyncs (libc writes its private storage; the exe reads its
  un-updated copy). ldso already does R_*_COPY. Fix = force GOT-indirect access
  to copy-relocatable exported data inside libc (PIC visibility/codegen; rustc
  exposes no semantic-interposition flag → needs a GOT-load shim or a structural
  split). LIKELY MOOT for real vendor binaries (GNU ld collapses aliases + gcc
  -fPIE GOT-accesses data) — confirm during G19d before investing.

## 2. Full-surface, not vendor-referenced (lower priority)

### net resolver (32) — DNS + iface
dn_comp dn_expand dn_skipname getifaddrs freeifaddrs gai_error gai_suspend getaddrinfo_a getipv4sourcefilter getsourcefilter setsourcefilter recvmmsg sendmmsg res_query res_querydomain res_search res_send res_mkquery res_nmkquery res_nquery res_nquerydomain res_nsearch res_nsend res_gethostbyname res_gethostbyname2 res_gethostbyaddr res_hnok res_dnok res_mailok res_ownok res_send_setqhook res_send_setrhook

### NSS reentrant `_r` + enumerators (~40) — nss db iteration
get{host,net,proto,rpc,serv,sg,alias}ent_r, get{net,proto,rpc,serv,sg}by*_r, getaliasbyname_r, fgetsgent_r, sgetsgent_r, twalk_r, ether_aton_r, ether_ntoa_r; set/get/end{alias,rpc,sg,tty}ent, getsgent, getttyent, putsgent, sgetsgent

### fts/fts64 (10) — coreutils `rm -r`/`du`/`find` (exact FTSENT ABI — substantial)
fts_open fts_read fts_children fts_set fts_close + fts64_*

### dl extras (4)
dladdr1 dlinfo dlmopen dlvsym

### misc syscall wrappers (~15)
acct chflags fchflags clock_getcpuclockid execveat execvpe getcpu quotactl process_madvise process_mrelease pidfd_getpid pidfd_spawn pidfd_spawnp; STREAMS getmsg/putmsg/getpmsg/putpmsg + fattach/fdetach (obsolete); bdflush/create_module (obsolete)

### BSD/misc (~15)
arc4random arc4random_buf arc4random_uniform ether_aton ether_ntoa ether_hostton ether_ntohost ether_line bindresvport argp_program_version_hook crypt_gensalt(+_r/_ra/_rn) crypt_ra crypt_rn crypt_preferred_method crypt_checksalt fcrypt

### `_FloatN` math aliases (265) — MECHANICAL
`*f32`==float, `*f64`==double; alias existing libm via naked-fn jmp/b thunks
(asm `.set` is localized by rustc → use naked fns like `clone`). 208 map to
existing cores; ~57 need a base (the C23 set below).

### C23 new math (~90)
`*pi` trig (sinpi/cospi/atan2pi…), exp10m1/exp2m1/log*p1, fmaximum/fminimum
(+_mag/_num variants), narrowing fadd/fsub/fmul/fdiv/fsqrt/ffma (+f32x/f64x).
Need real implementations, not aliases.

### Sun RPC (138) — DEPRECATED (libtirpc territory)
clnt_*/svc_*/auth*/xdr_*/pmap_*/callrpc/key_*/netname/… — build only if a
specific vendor package links it.

## 3. HARD-BLOCKED — cannot implement (docs/59 §9.2, glibc_unsupported.md)

- **long double `*l` (x86 80-bit f80): ~226** + **`_Float128`/`_Float32x`/`_Float64x`: ~477**.
  Rust has no `f80`/`_Float128` extern-C type → the ABI can't be expressed.
  Only worthwhile piece: a `%Lf`/`%Lg` printf/scanf asm shim.

## Done (this pass)
pthread FULL surface (80), C11 `<threads.h>` (25), modern syscalls (~34), locale
`_l` (~28 + `__isoc23_strto*_l`), account-db (putgrent/putspent/lckpwdf/ulckpwdf),
eaccess/euidaccess/sigisemptyset/sigorset/sigandset/__fpclassify/gets,
in6addr_any/in6addr_loopback, mbrtoc32/c32rtomb, wcwidth/wcswidth, clone(2),
dl_iterate_phdr. Each byte-exact vs host glibc (`xtask glibc-test`, 144/144).
