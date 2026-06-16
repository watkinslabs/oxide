# glibc — remaining TODO

> Live audit (docs/59 §9): `nm -D` host Fedora glibc (4214 public) vs our
> `libc.so.6` (**1919 exported**). Directive: implement EVERYTHING achievable
> (full compliance), value-agnostic. Only the hard-blocked f80/`_Float128`
> (§3) are truly impossible. Conformance 150/150, both arches boot.

## 1. The one migration blocker (docs/59 §9.4)

8 `__`-aliased DATA symbols (`__environ`/`_environ`/`__signgam`/`__tzname`/
`__timezone`/`__daylight`/`__progname`/`__progname_full`). They export fine via
version-script, but our libc reaches its own exported data DIRECTLY (PC-relative,
same cdylib) not via the GOT, so an executable's copy-reloc interposition
desyncs. Fix = GOT-indirect codegen for copy-relocatable exported data inside
libc (rustc has no semantic-interposition flag → GOT-load shim or structural
split). Likely moot for real GNU-ld vendor binaries — confirm in G19d. Reverted
(export alone is useless without the codegen fix).

## 2. Remaining achievable clusters (DO ALL — full compliance)

- **Sun RPC (149)**: clnt_*/svc_*/auth_*/xdr_*/pmap_*/key_*/callrpc/registerrpc/
  netname/get_my_address/ruserpass + getrpcent/byname/bynumber(+_r)/set/end.
  Needs the XDR + RPC client/server machinery + /etc/rpc parser. Largest block.
- **gshadow (16)**: struct sgrp + getsgnam/getsgent/fgetsgent/sgetsgent/putsgent
  (+_r) + set/end. /etc/gshadow parser (libnss crate + glibc). sg_adm + sg_mem
  (two char** arrays).
- **aliases (14)**: struct aliasent + getaliasbyname/getaliasent(+_r)/set/end.
  /etc/aliases (mail) parser.
- **ttyent (7)**: struct ttyent + getttyent/getttynam/setttyent/endttyent +
  fstab-ish /etc/ttys parser (usually empty on Linux → NULL).
- **resolver (32)**: res_query/search/send/mkquery/nquery/nsearch/nsend/
  gethostby*; dn_comp/dn_expand/dn_skipname; getifaddrs/freeifaddrs (netlink
  RTM_GETADDR); getaddrinfo_a/gai_* (async); recvmmsg/sendmmsg; get/setsourcefilter.
- **C23 trig `*pi` (35)**: sinpi/cospi/tanpi/asinpi/acospi/atanpi/atan2pi
  (+f/f32/f64). NEED exact argument reduction (exact at integer/half-integer).
- **C23 `*m1`/`*p1` (16)**: exp10m1/exp2m1/log10p1/log2p1 (+f/f32/f64).
- **fts/fts64 (10)**: fs-tree traversal (coreutils -R/du/find). Exact FTSENT ABI.
- **ether DB (3)**: ether_hostton/ether_ntohost/ether_line (/etc/ethers parser).
- **`_FloatN` f32/f64 (57 remaining)**: alias to the C23 bases above once those
  exist (regen version/floatn.map after C23 trig/m1p1/minmax land).

## 3. HARD-BLOCKED — cannot implement (docs/59 §9.2, glibc_unsupported.md)
long double `*l` (x86 80-bit f80) + `_Float128`/`_Float32x`/`_Float64x` (~700).
No Rust extern-C type. Only worthwhile piece: a `%Lf`/`%Lg` printf/scanf shim.

## Done (this autonomous run, ~30 PRs, conformance 150/150)
pthread FULL surface (80), C11 threads (25), modern syscalls (~34), locale `_l`
(~28 + __isoc23_strto*_l), account-db (putgrent/putspent/lckpwdf/ulckpwdf),
eaccess/euidaccess/sigisemptyset/sigorset/sigandset/__fpclassify/gets, in6addr,
mbrtoc32/c32rtomb, wcwidth/wcswidth, clone(2), dl_iterate_phdr, _FloatN math
aliases (208), ether_aton/ntoa + arc4random family, acct/clock_getcpuclockid/
execvpe, C23 fmaximum/fminimum family (16), netdb _r (serv/proto/net), dlvsym/
dladdr1/dlmopen/dlinfo. Each byte-exact vs host (`xtask glibc-test`).
