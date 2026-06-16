# state.md — session handoff

## Headline
**glibc full-compliance build-out** (docs/59 §9), completing the compat surface
(user chose option 1 over G19d). Conformance **177/177**
(`cargo run -q -p xtask -- glibc-test`). Both arches boot to `oxide login:`
(x86 KVM ~20s; arm `make smoke-arm SMOKE_TIMEOUT=800` ~55s). Clean tree on
`main`. `glibc.md` = live per-cluster TODO. F counter next = **524**
(metadata/index.md).

## Done this run (merged to main, F510–F523, one cluster per PR, host-diffable t_*.c)
- **F510** getifaddrs/freeifaddrs — net/ifaddrs.rs (netlink RTM_GETLINK+GETADDR)
- **F511** fts/fts64 — posix/fts.rs (BSD iterator, full FTSENT ABI)
- **F512** strerror{name,desc}_np + sig{abbrev,descr}_np — string/errname.rs (full
  0..133 errno name+desc table; strerror::msg delegates), signal/desc.rs
- **F513** mbrtoc8/c8rtomb/mbrtoc16/c16rtomb — locale/wchar.rs
- **F514** wcslcat/wcslcpy — string/wstr.rs
- **F515** twalk_r — search/tree.rs
- **F516** inet_net_pton/ntop/neta/nsap_addr/nsap_ntoa — net/inet.rs (AF_INET;
  glibc-test host oracle now links **-lresolv**)
- **F517** inet6_rth_* — net/inet6_rth.rs (RFC3542 routing header type 0)
- **F518** inet6_opt_* — net/inet6_opt.rs (RFC3542 HBH/Dest TLV options)
- **F519** scandirat/scandirat64 — posix/dirent.rs (shared scandir_dir collector)
- **F520** lockf/lockf64 — posix/lockf.rs (fcntl record locks)
- **F521** tee/vmsplice/sync_file_range — posix/morecalls.rs
- **F522** sched_getattr/setattr/getcpu — posix/sched.rs
- **F523** mlock2/pivot_root/open_tree/move_mount/mount_setattr — posix/morecalls.rs

## Next up (glibc.md §2)
- **posix_spawn_file_actions_add{chdir,fchdir,closefrom,tcsetpgrp}_np** + spawnattr
  get/set{sched*,sig*,pgroup,cgroup_np} — extend existing posix_spawn; host-diffable
  by spawning a child and observing.
- **misc syscall wrappers** still missing: pidfd_getpid/spawn/spawnp, ustat, revoke,
  setlogin, uselib, modify_ldt/ioperm (x86-only), swab. Thin nr passthroughs;
  host-diffable via error returns (run on host kernel in the conformance harness).
- **C23 narrowing math (~12)** fadd/fsub/fmul/fdiv/fsqrt/ffma + f32*f64 aliases.
  DEFERRED — needs round-to-odd numerics (fma residual gives exact tie-break for
  add/sub/mul/div/sqrt; ffma is the hard 3-term one). Bit-exact host diff.
- **inet6_option_* (RFC2292, ~6)** DEFERRED — cmsghdr+ip6_hbh-wrapped, obsolete
  (host warns), intricate. Low value.
- **open_wmemstream** — needs wide-stream orientation plumbing (heavier).
- **Sun RPC client/server (~120)** clnt_*/svc_*/auth_*/pmap_* — needs sockets;
  rpc_msg XDR filters are pure (RFC5531). XDR base already done.
- **resolver (~48)** res_query/search/send/mkquery/ns_*; getaddrinfo_a/gai_*.
- **BSD net-auth** rcmd/rexec/ruserok/rresvport/bindresvport; **re_* BSD regex (~12)**;
  **libxcrypt** crypt_gensalt/crypt_ra/….

## Hard-blocked (NOT achievable — glibc_unsupported.md)
long double `*l` (x86 f80) + `_Float128`/`_Float32x`/`_Float64x` (~700). No Rust
extern-C type. Only worthwhile bit: a `%Lf`/`%Lg` printf/scanf asm shim.

## The rhythm (proven, 14 PRs this run)
One cluster = one F<NN> branch (read+bump F in metadata/index.md). Build BOTH
arches (`cargo build -q -p glibc --features freestanding --target
{x86_64,aarch64}-unknown-linux-gnu`); add host-diffable t_*.c (remember
`#include <stdlib.h>` for mkstemp/mkdtemp); `xtask glibc-test`; spec-lint clean;
commit/PR/merge (`gh pr create … ; gh pr merge --merge --delete-branch=true`);
bump glibc.md. Author Chris Watkins, NO Co-Authored-By. EXPORT: rustc cdylib
exports `#[no_mangle]` items only. spec-lint: `// SAFETY:` ≥30 chars on the line
before `unsafe {`; every `pub fn`/`pub(crate) fn` needs `# C:` (`/// # C:` for
pub(crate)). New syscalls: add per-arch nr in internal/nr.rs (x86 syscall_64.tbl,
arm asm-generic), wrap in posix/morecalls.rs or the relevant module.

## Probing host glibc for exact semantics (the proven loop)
Write /tmp/p.c, `cc p.c [-lresolv] -o p && ./p`, read EXACT output, match
byte-for-byte. WATCH: C arg-eval order is right-to-left (printf(f(a),f(b))).

## Boot / verify gate (mandatory before push for crates/user/glibc touches)
Each glibc change invalidates the rootfs cache → x86 restages (~3-4 min) then
boots. Run sequentially in ONE bg command (run_in_background:true) to avoid
cross-pkill/contention: x86 grub (KVM, timeout 240) → pkill → `make smoke-arm
SMOKE_TIMEOUT=800`. Default 600s per-attempt times out on the cold restage.
`pkill -x qemu-system-<arch>`. The push hook re-runs smoke (cache HIT, fast).

## First task on restart
Re-audit then continue the compat surface:
  nm -D /lib64/lib{c,m,pthread,rt,dl,resolv,util,crypt,anl}.so* | awk '$2~/[TWiB]/{print $3}' | sed 's/@.*//' | sort -u > /tmp/host
  nm -D target/sysroot/x86_64-unknown-linux-gnu/lib/libc.so.6 | awk '$2~/[TWiBD]/{print $3}' | sed 's/@.*//' | sort -u > /tmp/ours
  comm -23 /tmp/host /tmp/ours | grep -vE '^_|f128|f32x|f64x'   (NOTE: a `l$` filter wrongly drops fmul etc.)
Then pick the next cluster (suggest posix_spawn_file_actions_*_np, then the
remaining misc syscall wrappers), one F-branch each.
