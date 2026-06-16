# state.md — session handoff

## Headline
**glibc full-compliance build-out** (docs/59 §9), continuing the compat surface
(user chose option 1 over G19d). Conformance **171/171**
(`cargo run -q -p xtask -- glibc-test`). Both arches boot to `oxide login:`
(x86 KVM ~20s; arm `make smoke-arm` ~58s). Clean tree on `main`. `glibc.md` is
the live per-cluster TODO. F counter next = **518** (metadata/index.md).

## Done this run (merged to main, F510–F517, one cluster per PR)
Each landed with a host-diffable `userspace/glibc_conformance/t_*.c`.
- **F510** getifaddrs/freeifaddrs — net/ifaddrs.rs, netlink RTM_GETLINK+GETADDR
- **F511** fts/fts64 — posix/fts.rs, BSD pre/post-order iterator, full FTSENT ABI
- **F512** strerror{name,desc}_np + sig{abbrev,descr}_np — string/errname.rs
  (complete 0..133 errno name+desc table; strerror::msg delegates), signal/desc.rs
- **F513** mbrtoc8/c8rtomb/mbrtoc16/c16rtomb — locale/wchar.rs (uchar.h)
- **F514** wcslcat/wcslcpy — string/wstr.rs
- **F515** twalk_r — search/tree.rs
- **F516** inet_net_pton/ntop/neta/nsap_addr/nsap_ntoa — net/inet.rs (AF_INET only;
  classful-default bits w/ class-D=4). **glibc-test host oracle now links -lresolv.**
- **F517** inet6_rth_* — net/inet6_rth.rs (RFC3542 routing header type 0)

## Next up (glibc.md §2, all host-diffable unless noted)
- **inet6_opt_* + inet6_option_* (~16)** — RFC3542/RFC2292 HBH/Dest option
  TLV builders/parsers (Pad1/PadN, `align` placement). Intricate — probe host
  byte layout first. In libc directly (no -lresolv).
- **C23 narrowing math (~12)** — fadd/fsub/fmul/fdiv/fsqrt/ffma + f32*f64 aliases.
  DEFERRED: needs round-to-odd numerics (fma residual gives exact tie-break for
  add/sub/mul/div/sqrt; ffma is the hard 3-term one). Bit-exact host diff.
- **open_wmemstream** — needs wide-stream orientation plumbing (heavier).
- **Sun RPC client/server (~120)** clnt_*/svc_*/auth_*/pmap_* — needs sockets;
  rpc_msg XDR filters are pure (RFC5531). XDR base already DONE.
- **resolver (~48)** res_query/search/send/mkquery/ns_*; getaddrinfo_a/gai_*.
- **BSD net-auth** rcmd/rexec/ruserok/rresvport/bindresvport.
- **re_* BSD regex (~12)**, **libxcrypt** crypt_gensalt/crypt_ra/…
- **misc** sched_getattr/setattr/getcpu, mlock2/sync_file_range/vmsplice/tee/
  pivot_root/mount_setattr/move_mount/open_tree, scandirat/lockf,
  posix_spawn_file_actions_add{chdir,fchdir,closefrom,tcsetpgrp}_np + spawnattr.

## Hard-blocked (NOT achievable — glibc_unsupported.md)
long double `*l` (x86 f80) + `_Float128`/`_Float32x`/`_Float64x` (~700). No Rust
extern-C type. Only worthwhile bit: a `%Lf`/`%Lg` printf/scanf asm shim.

## The rhythm (proven, ~8 PRs/run)
One cluster = one `F<NN>` branch (read+bump F in metadata/index.md). Build BOTH
arches (`cargo build -q -p glibc --features freestanding --target
{x86_64,aarch64}-unknown-linux-gnu`); add host-diffable t_*.c; `xtask glibc-test`;
spec-lint clean; commit/PR/merge; bump glibc.md. Author Chris Watkins, NO
Co-Authored-By. EXPORT: rustc cdylib exports `#[no_mangle]` items only.
spec-lint: `// SAFETY:` ≥30 chars on the line before `unsafe {`; every `pub fn`/
`pub(crate) fn` needs `# C:` (`/// # C:` for pub(crate)).

## Probing host glibc for exact semantics (the proven loop)
Write a /tmp/p.c probe, `cc p.c [-lresolv] -o p && ./p`, read EXACT outputs, then
match byte-for-byte. Watch C arg-eval order (printf(f(a),f(b)) is right-to-left!).
Compat-only symbols (inet_net_*, rpc): host oracle needs -lresolv (already wired).

## Boot / verify gates (mandatory before push for crates/user/glibc touches)
Each glibc change invalidates the rootfs cache → x86 restages (~3-4 min) then
boots. Run sequentially in ONE bg command to avoid cross-pkill/contention:
x86 grub (KVM) → pkill → `make smoke-arm SMOKE_TIMEOUT=800`. Default 600s
per-attempt times out on the cold restage — use 800+. `pkill -x qemu-system-<arch>`.

## First task on restart
Continue the compat surface. Re-audit:
  nm -D our libc.so.6 | sed 's/@.*//' | sort -u > ours; comm -23 <host set> ours
  | grep -vE '^_|l$|f128|f32x|f64x'  (NOTE: `l$` filter wrongly drops fmul etc).
Then inet6_opt_*/option_* (F518): probe host TLV/padding layout, implement in a
new net/inet6_opt.rs, t_inet6_opt.c, one F-branch.
