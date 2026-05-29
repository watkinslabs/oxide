# Real systemd on musl — build research

Goal: build **real systemd** (PID1 + manager + journald + networkd + resolved + logind + systemctl + udevd) against **musl libc**, cross-compiled for `x86_64` and `aarch64`, to run as PID 1 on a from-scratch Linux-compatible kernel. No stubs, no busybox-init substitution. Drop-in RedHat/systemd replacement.

## Headline (read first)

There are **two viable routes**, and the right answer depends on how greenfield you want to be:

1. **systemd 259 (released; latest point `v259.6`) — native upstream musl support.** As of 259, **systemd builds against musl in-tree with NO external patch series**, enabled with the meson option **`-Dlibc=musl`** (the build needs to be told; it does not silently autodetect). glibc-only features (NSS modules, `DynamicUser=`, homed, userdbd, nsresourced, unprivileged nspawn) are disabled automatically. *Experimental* per upstream — driven by postmarketOS/Alpine; Red Hat maintainer publicly worried the compat layer is "fragile." But it is real, in-tree, and the strategic direction. **For a greenfield distro this is the recommended baseline** — you avoid carrying ~24 out-of-tree patches. systemd is the manager you control, so the "experimental, may be dropped" caveat is acceptable: you can pin a version and carry the shims yourself if upstream ever removes them (they're the OE patches, upstreamed).
2. **systemd 255/257 + the OpenEmbedded/Yocto musl patch series (~22 patches).** Battle-tested, used in production by postmarketOS (which ships systemd 257.x on musl as PID1 on real phones). Pick this if you want an LTS-stable base or if 259's experimental musl support proves flaky for you.

Either way: musl systemd is a real, shipping thing. **Do NOT fork.** Consume upstream 259, or upstream + the OE series.

Verified release tags (live): `v255.21`, `v257.9`, `v258.8`, **`v259`** … **`v259.6`** (latest).

**Kernel floor (from v259 NEWS):** v259 builds against Linux ≥ 4.x today, but **v260 will raise the minimum to Linux ≥ 5.10 (recommended ≥ 5.14)**, glibc ≥ 2.34 (N/A for musl), libxcrypt ≥ 4.4.0, util-linux ≥ 2.37, openssl ≥ 3.0.0, libseccomp ≥ 2.4.0, python ≥ 3.9. **Also: v259 mounts cgroup2 with the `memory_hugetlb_accounting` option, which needs kernel ≥ 6.6** — implement that mount option or systemd's cgroup setup will warn/degrade. Default journal storage is now `persistent`. networkd/nspawn NAT now require **nftables** (libiptc/iptables path removed) — implement the nftables netlink subsystem if you want networkd NAT.

---

## 1. Who ships systemd on musl, and how

| Project | Ships systemd-on-musl? | How / what they use |
|---|---|---|
| **systemd upstream** | **Yes — since v259** | In-tree musl support, selected via meson `-Dlibc=musl`; NSS-coupled features auto-disabled. Experimental, "no promise of future maintenance" (259 NEWS, verbatim below). Driven by postmarketOS + Alpine devs (PR #38825) and awilfox/Adélie. |
| **postmarketOS** | **Yes — in production as PID1** | Alpine-based (musl). Merged systemd into `edge` Jan 2025; shipped in **v25.06**. Tracks systemd-stable — **257.8** as of late 2025. This is the most-exercised *running* musl systemd as PID1 on real hardware. Patches: the OE/Yocto set + pmOS integration, now converging on upstream-native as 259 lands. |
| **OpenEmbedded / Yocto (poky)** | **Yes — reference patch series** | `meta/recipes-core/systemd/`. Real upstream systemd built `libc-musl`, musl patches applied via `SRC_URI_MUSL`. **The canonical, best-maintained out-of-tree musl patch source** for pre-259. Versions: scarthgap=255.21, styhead=256.5, walnascar=257.6. |
| **Adélie Linux** | No (ships s6+OpenRC) | But: Adélie maintainer **A. Wilcox (awilfox)** wrote a *separate, more-upstreamable* musl port targeting recent systemd/musl (the "Cat Fox Life" / catfox.life port). Distinct from the OE patchset; much of that effort fed the eventual upstream 259 support. Adélie itself uses musl + s6 + OpenRC, not systemd. |
| **Alpine (upstream)** | No (policy: OpenRC + busybox-init) | musl origin, but no systemd in main. Alpine devs contributed to the upstream musl effort though. |
| **Void Linux** | No (runit, both variants) | Originally offered systemd, **dropped it because it didn't work on musl**; committed to runit. Void's musl flavor has no systemd. |
| **Chimera Linux** | No (dinit) | musl (patched for mimalloc) + dinit + FreeBSD userland + LLVM. Deliberately no systemd. |
| **Gentoo musl** | No (masked on musl profiles) | musl profiles force OpenRC; systemd masked. The third-party **`12101111` overlay** carries a systemd-on-musl-clang ebuild using the **OpenEmbedded patches** (clang/musl/arm64 profile) — a working community example but maintainer-specific. |
| **Artix / openSUSE / RedHat** | N/A | glibc distros. Not musl. |
| **"msystemd"** | Not a real current project | No such maintained repo exists today (GitHub search: 0 results). Historically people meant either the OE patchset, the Adélie/catfox port, or the old `uselessd` fork (2014, dead). Don't chase it. |

**Bottom line:** the live, maintained sources are **(a) systemd upstream v259** (native), **(b) OpenEmbedded/Yocto poky** (canonical pre-259 patch series), and **(c) postmarketOS** (proof it runs as PID1 on musl). Everything else avoids systemd or isn't musl.

systemd 259 NEWS (verbatim):
> Incomplete support for musl libc is now available by setting the "libc" meson option to "musl". Note that systemd compiled with musl has various limitations: since NSS or equivalent functionality is not available, nss-systemd, nss-resolve, DynamicUser=, systemd-homed, systemd-userdbd, systemd-nsresourced, and so on will not work. Also, the usual memory pressure behaviour of long-running systemd services has no effect on musl. We also implemented a bunch of shims and workarounds to support compiling and running with musl. Caveat emptor. This support for musl is provided without a promise of continued support in future releases. We'll make the decision based on the amount of work required to maintain the compatibility layer in systemd, how many musl-specific bugs are reported, and feedback on the desirability of this effort provided by users and distributions.

---

## 2. Best musl patch source — exact location

### If targeting 259+ (recommended): no patch series needed
Build `v259`/`v259.6` directly with meson `-Dlibc=musl`. The musl shims live in-tree (`src/basic/missing_*.h` + conditional code); they are the OE patch set, upstreamed (systemd PR #38825 "Add experimental musl support" by yuwata, plus awilfox's header/`getgrent`/`strptime %z` fixes via PRs #34064-#34066). With `-Dlibc=musl`, NSS-dependent features (nss-systemd, nss-resolve, DynamicUser=, homed, userdbd, nsresourced, unprivileged nspawn) disable automatically. Mirror only your own distro-integration patches (presets, unit overrides), NOT portability patches.
- Source: `https://github.com/systemd/systemd` tag `v259.6` (or kernel.org mirror `https://mirrors.edge.kernel.org/pub/linux/utilities/systemd/`).
- The PR that landed it: `https://github.com/systemd/systemd/pull/38825`.

### If targeting 255/257 (LTS-stable route): OpenEmbedded/Yocto poky
- Repo: `https://git.yoctoproject.org/poky`
- Patch dir: `meta/recipes-core/systemd/systemd/`
- Recipe + glue: `meta/recipes-core/systemd/systemd_<ver>.bb` + `systemd.inc`
- Browse: `https://git.yoctoproject.org/poky/tree/meta/recipes-core/systemd/systemd?h=<branch>`
- Raw patch fetch: `https://git.yoctoproject.org/poky/plain/meta/recipes-core/systemd/systemd/<patch>?h=<branch>`

**Verified version ↔ branch map:**

| Branch | systemd version |
|---|---|
| `scarthgap` (LTS) | **255.21** |
| `styhead` | 256.5 |
| `walnascar` | **257.6** |

The musl patch list is **applied only for `libc-musl`** via:
```
SRC_URI:append:libc-musl = " ${SRC_URI_MUSL}"
```

**`SRC_URI_MUSL` for walnascar (systemd 257.6) — exact, complete (24 files):**
```
0003-missing_type.h-add-comparison_fn_t.patch
0004-add-fallback-parse_printf_format-implementation.patch
0005-don-t-fail-if-GLOB_BRACE-and-GLOB_ALTDIRFUNC-is-not-.patch
0006-add-missing-FTW_-macros-for-musl.patch
0007-Use-uintmax_t-for-handling-rlim_t.patch
0008-Define-glibc-compatible-basename-for-non-glibc-syste.patch
0009-Do-not-disable-buffering-when-writing-to-oom_score_a.patch
0010-distinguish-XSI-compliant-strerror_r-from-GNU-specif.patch
0011-avoid-redefinition-of-prctl_mm_map-structure.patch
0012-do-not-disable-buffer-in-writing-files.patch
0013-Handle-__cpu_mask-usage.patch
0014-Handle-missing-gshadow.patch
0015-missing_syscall.h-Define-MIPS-ABI-defines-for-musl.patch
0016-pass-correct-parameters-to-getdents64.patch
0017-Adjust-for-musl-headers.patch
0018-test-bus-error-strerror-is-assumed-to-be-GNU-specifi.patch
0019-errno-util-Make-STRERROR-portable-for-musl.patch
0020-sd-event-Make-malloc_trim-conditional-on-glibc.patch
0021-shared-Do-not-use-malloc_info-on-musl.patch
0022-avoid-missing-LOCK_EX-declaration.patch
0023-include-signal.h-to-avoid-the-undeclared-error.patch
0024-undef-stdin-for-references-using-stdin-as-a-struct-m.patch
0025-adjust-header-inclusion-order-to-avoid-redeclaration.patch
0026-build-path.c-avoid-boot-time-segfault-for-musl.patch
```
(scarthgap/255.21 is the same set minus `0023..0026` plus a `0007-don-t-pass-AT_SYMLINK_NOFOLLOW...` — 22 files; numbering shifts by 1 because the OE-only `sysv-install`/`binfmt` patches consume early numbers. The `SRC_URI_BASE` patches `0001-binfmt-...`, `0002-implment-systemd-sysv-install-for-OE`, `0001-Do-not-create-var-log-README` are OE-specific, NOT musl — skip them for your own distro.)

**Note:** systemd 259's in-tree shims are essentially the upstreamed form of this exact list. That's the proof the series is sound.

---

## 3. Build dependencies to cross-build first (musl)

OE's actual unconditional `DEPENDS`: `libcap libgcrypt gperf-native util-linux python3-jinja2-native libxcrypt`. Everything else is `PACKAGECONFIG`-gated. Below, "mandatory" = needed for PID1 + manager + journald + networkd + resolved + logind.

### Mandatory
| Dep | Why |
|---|---|
| **libcap** | per-unit capability drop/bound/ambient. Hard dep. musl-clean. |
| **util-linux** (libmount, libblkid, libuuid; libfdisk for repart) | `.mount` units, device UUIDs, mount handling. libmount effectively mandatory for the manager. Build for musl (Alpine/OE patches; mostly clean now). |
| **libxcrypt** | `crypt()` for logind/PAM password paths. In OE's unconditional DEPENDS. |
| **libgcrypt** (+ libgpg-error) | In OE's unconditional DEPENDS; journald FSS sealing. |
| **gperf** (native) | build-time perfect-hash gen. |
| **python3 + jinja2** (native), **meson**, **ninja** | build-time codegen + build system. |
| **libseccomp** | `SystemCallFilter=` + unit sandboxing. Mandatory for real systemd semantics. musl-clean. |
| **kmod** (libkmod) | module autoload (`systemd-modules-load`, udev modalias). Needed for real udevd. |
| **D-Bus impl** (dbus reference, or dbus-broker) | logind/resolved/networkd/machined IPC; `systemctl`/`busctl`. See note. |

### Strongly recommended (feature-complete daemons)
| Dep | Enables |
|---|---|
| **openssl** | resolved DNS-over-TLS (`PACKAGECONFIG[dns-over-tls]`→openssl), DNSSEC, journal TLS, importd |
| **zstd, lz4, xz** | journal compression (zstd = modern default; at least zstd) |
| **libpcre2** | `journalctl --grep` |
| **acl** | journald per-user journal ACLs |
| **pam** (linux-pam) | logind sessions / login integration. Real logind needs it. |
| **libidn2** | resolved IDNA (note: OE removes the older `idn` for musl; use idn2) |
| **audit** | `systemd-journald` audit integration (optional but common on RH-like) |
| **libqrencode** | `journalctl` FSS QR (cosmetic) |

### Optional / drop for lean musl PID1
- **elfutils (libdw)** — coredump symbolization. *musl-painful* (glibc-isms; Alpine patches it). Drop coredump until you've cross-built elfutils for musl.
- **libmicrohttpd** — journal-remote/gatewayd HTTP. Drop unless remote journals needed.
- **gnu-efi / systemd-boot / ukify** — only if you boot via systemd-boot/UKI. Irrelevant with your own loader (Limine/U-Boot). (In OE this is a *separate* `systemd-boot` recipe, not a build option of the main one.)
- **libbpf + clang/bpftool** — BPF `IPAddressDeny=` etc. Optional.
- **tpm2-tss, libfido2, p11-kit, libpwquality, libcryptsetup** — cryptenroll/measured-boot/homed. Optional.
- **bzip2, libcurl, gnutls** — optional codecs/transport.

### D-Bus choice (important)
systemd needs a bus for logind/resolved/networkd/machined and for `systemctl`/`busctl`.
- **dbus (reference libdbus + dbus-daemon)** — what most builds use; musl-clean; safe default.
- **dbus-broker** — sd-bus-native, faster, drop-in replacement (ships `dbus-broker.service` replacing `dbus.service`); Arch/Fedora default. **It builds on musl** (recent releases added musl-build fixes), though upstream lists glibc as the supported target — test it. Recommended for a systemd-first distro; still ship `dbus` package for policy config + `busctl` tooling.
- **basu** = a standalone *sd-bus library* extraction for apps; **NOT a bus daemon** — not a substitute here.

### Ordered cross-build list (start here)
```
1.  musl sysroot + kernel headers + libgcc/compiler-rt
2.  gperf-native, meson, ninja, python3+jinja2        (native/host)
3.  libcap
4.  libxcrypt
5.  util-linux  (libuuid → libblkid → libmount → libfdisk)
6.  libseccomp
7.  kmod
8.  pcre2
9.  zstd, lz4, xz
10. openssl            (resolved DoT/DNSSEC, journal TLS)
11. libgpg-error → libgcrypt   (journald FSS)
12. acl
13. libidn2
14. linux-pam          (logind)
15. dbus  and/or  dbus-broker
16. (optional) audit, elfutils, libmicrohttpd, libqrencode, tpm2-tss, libfido2
17. systemd v259  (or 257.6 + OE walnascar musl series)
```

---

## 4. meson configure flags (musl, near-static)

### Linking reality — read first
**Full static systemd is NOT feasible.** systemd **requires dynamic linking**:
- It `dlopen()`s many libs at runtime (libidn2, libqrencode, pcre2, tpm2, cryptsetup, libbpf, libarchive, some kmod paths). A static binary cannot `dlopen`.
- musl explicitly does not support `dlopen` from a static binary.
- The NSS architecture assumes a dynamic loader (moot on musl — NSS auto-disabled — but the design is dynamic).

**Build systemd dynamically** against shared musl (`ld-musl-{x86_64,aarch64}.so.1`) + shared `.so` deps. "Near-static" = minimize the dlopen surface (disable optional dlopen features you don't need) and keep `link-*-shared=true` so the big `libsystemd-shared-<ver>.so` is shared by all binaries (much smaller image). Ship the musl loader in initramfs/root. **This is exactly how postmarketOS runs musl systemd.**

### musl-forced disables (hard-require glibc)
For 259+ with `-Dlibc=musl`: **systemd disables the NSS-coupled ones automatically** (nss-systemd, nss-resolve, DynamicUser=, homed, userdbd, nsresourced, unprivileged nspawn). Note one runtime consequence from the 259 NEWS: **the usual memory-pressure behaviour of long-running services has no effect on musl** (glibc malloc trimming hook absent) — accept it. For the OE route, OE forces the glibc-only features off via:
```
PACKAGECONFIG:remove:libc-musl = "gshadow idn nss-myhostname nss-mymachines nss-resolve nss-systemd userdb"
```
(Verified exact against poky `systemd.inc` walnascar & scarthgap. OE does NOT remove `resolved` or `localed` for musl — both build fine.)
Reasons:
- **nss-\*** plugins (`nss-resolve`, `nss-myhostname`, `nss-mymachines`, `nss-systemd`) — **musl has no NSS dlopen plugin mechanism.** Cannot be loaded. Disable all. (resolved as a *daemon* still works; you wire it via `/etc/resolv.conf` → `127.0.0.53` stub listener, and apps use it over D-Bus — NOT via NSS.)
- **gshadow** — musl has no `gshadow.h`; patch `0014` stubs it, feature disabled.
- **userdb** — depends on nss-systemd/varlink-NSS bridge; drop on musl.
- **idn** (libidn1) — removed; use `libidn2` instead.
- **resolved / localed** — NOT removed by OE; both build on musl. **Keep `-Dresolve=enabled` and `-Dlocaled=enabled`.** You only lose the NSS *wiring* for resolved (no `nss-resolve`); wire it via the `127.0.0.53` stub listener in `/etc/resolv.conf` and D-Bus instead.
- **DynamicUser=, systemd-homed, systemd-userdbd, systemd-nsresourced, unprivileged systemd-nspawn** — all depend on the NSS/userdb varlink bridge and are **unavailable on musl** (259 NEWS confirms). Don't rely on `DynamicUser=` in your unit files; use static system users (`sysusers.d`).

### Concrete meson option set (start from this; systemd 259 / 257.x)
```
meson setup build \
  --cross-file cross-x86_64-musl.txt \    # or aarch64
  --prefix=/usr \
  --buildtype=release \
  -Dmode=release \                        # use 'developer' for first bring-up
  -Dlibc=musl \                           # REQUIRED on 259+ to select musl path
  \
  # core init/manager — share the big lib
  -Dlink-udev-shared=true \
  -Dlink-systemctl-shared=true \
  -Dstatic-libsystemd=false \
  -Dstatic-libudev=false \
  \
  # musl-incompatible — OFF (259 auto-disables; set explicitly for older)
  -Dnss-myhostname=false \
  -Dnss-mymachines=disabled \
  -Dnss-resolve=disabled \
  -Dnss-systemd=false \
  -Dgshadow=false \
  -Duserdb=false \
  -Didn=false \
  \
  # daemons you DO want (all musl-buildable)
  -Dlogind=true \
  -Dnetworkd=true \
  -Dresolve=true \           # keep it; wire via 127.0.0.53 stub, not NSS
  -Ddns-over-tls=true \      # needs openssl
  -Dtimesyncd=true \
  -Dtimedated=true \
  -Dhostnamed=true \
  -Dlocaled=true \           # builds on musl; OE drops it by policy only
  -Dmachined=true \
  -Dcoredump=disabled \      # flip to enabled only after elfutils-on-musl built
  \
  # security / sandboxing
  -Dseccomp=enabled \
  -Dselinux=disabled \
  -Dsmack=false \
  -Dapparmor=disabled \
  -Dpam=enabled \
  -Dacl=enabled \
  -Daudit=disabled \         # enable if you cross-built audit
  \
  # journal
  -Dgcrypt=enabled \
  -Dzstd=enabled -Dlz4=enabled -Dxz=enabled \
  -Dpcre2=enabled \
  -Dqrencode=disabled \
  -Dmicrohttpd=disabled \
  -Djournal-upload=disabled \
  \
  # crypto / dns
  -Dopenssl=enabled \
  -Dgnutls=disabled \
  \
  # boot/UKI/EFI — OFF (you have your own loader)
  -Dgnu-efi=false \
  -Dbootloader=false \
  -Dukify=disabled \
  \
  # optional integrations — OFF initially
  -Dbpf-framework=disabled \
  -Dtpm2=disabled \
  -Dfido2=disabled \
  -Dpwquality=disabled \
  -Dp11kit=disabled \
  -Dlibcryptsetup=disabled \
  -Dlibcurl=disabled \
  -Dlibarchive=disabled \
  -Dimportd=disabled \
  -Dfdisk=enabled \          # util-linux libfdisk (repart)
  -Dkmod=enabled \
  -Dbinfmt=true \
  -Dhibernate=true \
  -Dbacklight=true \
  -Drandomseed=true \
  -Dquotacheck=disabled \
  -Ddefault-hierarchy=unified \   # cgroup v2 only — REQUIRED for modern
  \
  -Dtests=false \
  -Dman=disabled -Dhtml=disabled
```
Notes:
- meson option *types* differ: boolean (`true/false`) vs feature (`enabled/disabled/auto`). The list above matches systemd's actual option types (see `meson.options`/`meson_options.txt`).
- musl cross file must set the musl sysroot in `c_args`/`c_link_args` and define `-D_GNU_SOURCE` (systemd assumes it). 259 handles header gaps in-tree; older needs the OE `missing_*` shims.
- `-Ddefault-hierarchy=unified` is essential — see §5.

---

## 5. Kernel must-haves — definitive checklist

systemd refuses to boot, or silently loses features, without these. For a from-scratch kernel this is the contract.

### Cgroups (HARD — PID1 aborts without v2)
- **cgroup v2 unified hierarchy, single `cgroup2` mount at `/sys/fs/cgroup`.** systemd 256+ is unified-only by default; legacy/hybrid v1 deprecated/removed. Build with `-Ddefault-hierarchy=unified`.
- Controllers expected/delegated: **`cpu`, `cpuset`, `io`, `memory`, `pids`** (+ optional `hugetlb`, `rdma`, `misc`). Minimum: `memory` + `pids`; add `cpu`+`io` for resource control.
- Required cgroup-core files/semantics: `cgroup.controllers`, `cgroup.subtree_control`, `cgroup.procs`, `cgroup.threads`, `cgroup.events` (the `populated` notify — systemd watches this), `cgroup.freeze`, **`cgroup.kill`** (modern fast unit-kill), `cgroup.type`, `cgroup.max.depth`/`max.descendants`.
- Delegation: nested cgroup creation by an unprivileged user-session manager.

### Syscalls (must exist + be correct; names → x86_64 NR / aarch64 NR)
| Syscall | x86_64 | aarch64 | Used for |
|---|---|---|---|
| `signalfd4` | 289 | 74 | PID1 signal handling (no async handlers) |
| `timerfd_create` / `timerfd_settime` | 283 / 286 | 85 / 86 | timer units, watchdogs |
| `epoll_create1` / `epoll_ctl` / `epoll_pwait` | 291 / 233 / 281 | 20 / 21 / 22 | sd-event core loop |
| `eventfd2` | 290 | 19 | sd-event wakeups |
| `inotify_init1` / `add_watch` / `rm_watch` | 294 / 254 / 255 | 26 / 27 / 28 | path units, config watch |
| `fanotify_init` / `fanotify_mark` | 300 / 301 | 262 / 263 | optional; some watch paths |
| `memfd_create` | 319 | 279 | sealed memfds (journal/creds/IPC) — REQUIRED |
| `close_range` | 436 | 436 | fd cleanup before exec — modern systemd requires |
| `pidfd_open` | 434 | 434 | race-free process tracking — REQUIRED in modern |
| `pidfd_send_signal` | 424 | 424 | race-free service kill — REQUIRED |
| `pidfd_getfd` | 438 | 438 | optional fd passing |
| `name_to_handle_at` / `open_by_handle_at` | 303 / 304 | 264 / 265 | mount-id tracking, machined |
| `statx` | 332 | 291 | mount-id, btime |
| `clone3` | 435 | 435 | namespace creation (clone fallback exists) |
| `unshare` | 272 | 97 | unit sandboxing namespaces |
| `setns` | 308 | 268 | namespaces / machined |
| `pivot_root` | 155 | 41 | `RootDirectory=`, switch-root |
| `mount` / `umount2` | 165 / 166 | 40 / 39 | mount units |
| `fsopen`/`fsconfig`/`fsmount`/`move_mount`/`open_tree` | 430/431/432/429/428 | same NRs | new mount API — recent systemd uses it; implement or graceful fallback |
| `mount_setattr` | 442 | 442 | ro/idmapped bind mounts (`ProtectSystem=`, `ReadOnlyPaths=`) |
| `prctl` (PDEATHSIG, CHILD_SUBREAPER, NO_NEW_PRIVS, CAP_AMBIENT, SET_NAME) | 157 | 167 | reaping, `NoNewPrivileges=`, ambient caps |
| `seccomp` (SET_MODE_FILTER) | 317 | 277 | `SystemCallFilter=` |
| `keyctl` / `add_key` / `request_key` | 250 / 248 / 249 | 219 / 217 / 218 | encrypted credentials keyring |
| `getrandom` | 318 | 278 | seeding, UUIDs |
| `io_uring_setup`/`enter`/`register` | 425/426/427 | 425/426/427 | optional sd-event backend (not required) |
| `clock_gettime`/`settime`/`adjtimex`/`clock_adjtime` | 228/227/159/305 | 113/112/171/266 | timedated/timesyncd |
| `set_tid_address` / `set_robust_list` / `rseq` | 218 / 273 / 334 | 96 / 99 / 293 | normal pthread/musl startup |

(NRs are mainline Linux; aarch64 uses the generic table — implement those numbers so musl's wrappers match.)

### procfs / sysfs / special filesystems
- **`/proc`** full semantics: `/proc/self`, `/proc/<pid>/{stat,status,cmdline,cgroup,fd,fdinfo,mountinfo,oom_score_adj,attr,limits}`, `/proc/cmdline`, `/proc/1/*`, and **`/proc/<pid>/ns/{mnt,pid,net,uts,ipc,cgroup,user,time}`** symlinks (REQUIRED for namespaces/machined).
- **`/sys`** (sysfs): `/sys/fs/cgroup` (cgroup2), `/sys/class/*`, `/sys/devices/*`, uevent files, `/sys/kernel/*`, `/sys/fs/bpf` (if bpf). udevd needs `/sys` walkability + **`NETLINK_KOBJECT_UEVENT`**.
- **`/dev`** as devtmpfs (or udev-managed): `/dev/null`, `/dev/console`, **`/dev/kmsg`** (journald kernel-log source — readable structured records + writable), `/dev/urandom`, `/dev/ptmx`+devpts, `/dev/shm` tmpfs, `/dev/mqueue`.
- **tmpfs** at `/run`, `/dev/shm` (and usually `/tmp`).
- **autofs** — only for `.automount` units. Implement autofs4 protocol if you want automount; else systemd just won't offer it.

### Namespaces & mount semantics (HARD for sandboxing + nspawn)
- All namespace types: mount, PID, network, UTS, IPC, cgroup, user, time — via `clone3`/`unshare`/`setns` with `CLONE_NEW*`.
- **Mount propagation**: `MS_SHARED`/`MS_PRIVATE`/`MS_SLAVE`/`MS_REC`. systemd marks `/` shared at boot then makes per-unit mounts private. Wrong propagation = sandbox leaks/breaks.
- **`MS_MOVE`** + **`pivot_root`** — initramfs switch-root + `RootDirectory=`.
- **New mount API** (`fsopen`/`fsconfig`/`fsmount`/`move_mount`/`open_tree`) — recent systemd uses it; implement, or ensure clean fallback to classic `mount(2)`.
- **`mount_setattr`** — ro/idmapped binds for `ProtectSystem=`, `ReadOnlyPaths=`.

### Capabilities & security
- Full POSIX caps incl. **ambient caps** (`PR_CAP_AMBIENT`), bounding set, securebits — `AmbientCapabilities=`/`CapabilityBoundingSet=`.
- **`prctl(PR_SET_NO_NEW_PRIVS)`** — pervasive in sandboxed units.
- **seccomp filter mode** (`SECCOMP_SET_MODE_FILTER`, `SECCOMP_FILTER_FLAG_*`).
- **`PR_SET_CHILD_SUBREAPER`** + correct **zombie reaping**/`SIGCHLD` to PID1 — without it PID1 can't adopt orphans; the entire service-tracking model breaks. NON-NEGOTIABLE.

### Netlink / sockets (networkd, udevd, IPC)
- `AF_NETLINK`: **`NETLINK_ROUTE`** (rtnetlink — networkd link/addr/route), **`NETLINK_KOBJECT_UEVENT`** (udev), `NETLINK_GENERIC` (genetlink — wireguard/ethtool/etc.).
- `AF_UNIX` with **`SO_PASSCRED`/`SCM_CREDENTIALS`/`SCM_RIGHTS`** — D-Bus, socket activation, journald all depend on credential + fd passing. HARD requirement.
- `SOCK_CLOEXEC`/`SOCK_NONBLOCK` flags everywhere.

### Misc
- **`fcntl` `F_ADD_SEALS`/`F_GET_SEALS`** on memfds — journald + credential sealing REQUIRE seal support.
- `fcntl(F_SETPIPE_SZ)`, `mmap` `MAP_POPULATE`, `MADV_*` — journal pipes/mmap.
- `copy_file_range` (graceful EOPNOTSUPP fallback exists), `renameat2(RENAME_NOREPLACE)` (atomic config swap), `O_TMPFILE`/`O_PATH`/`AT_*` family.
- `/dev/kmsg` structured records + `syslog(2)`/`klogctl` for kmsg drain.
- **EPOLL + eventfd + signalfd are non-negotiable** — sd-event has no fallback.

### Minimum-to-boot vs feature-complete
- **PID1 boots** with: cgroup-v2 mounted; /proc /sys /dev; signalfd4/timerfd/epoll/eventfd2/inotify; memfd_create + F_ADD_SEALS; AF_UNIX + SCM_RIGHTS/SCM_CREDENTIALS; PR_SET_CHILD_SUBREAPER; basic mount/umount; prctl; getrandom.
- **Add for service mgmt**: pidfd_open/pidfd_send_signal, close_range, seccomp, caps+ambient, namespaces+propagation, name_to_handle_at.
- **Add for daemons**: NETLINK_ROUTE (networkd), NETLINK_KOBJECT_UEVENT (udevd), /dev/kmsg (journald), keyctl (credentials), clock_adjtime (timesyncd).

---

## 6. Known musl source incompatibilities → how each is resolved

Maps to OE patch filenames (walnascar numbering); in 259 the same fixes are in-tree.

| glibc-ism | musl problem | Fix |
|---|---|---|
| `comparison_fn_t` / `__compar_fn_t` | not in musl headers | `0003-missing_type.h-add-comparison_fn_t.patch` (define in `missing_type.h`) |
| `parse_printf_format` (glibc printf introspection, `printf.h`) | absent in musl | `0004-add-fallback-parse_printf_format-implementation.patch` |
| `GLOB_BRACE`/`GLOB_ALTDIRFUNC` | musl lacks these glob flags | `0005-don-t-fail-if-GLOB_BRACE-and-GLOB_ALTDIRFUNC...` |
| `FTW_*` / `nftw` flags | musl missing some | `0006-add-missing-FTW_-macros-for-musl.patch` |
| `rlim_t` printf handling | type-width mismatch | `0007-Use-uintmax_t-for-handling-rlim_t.patch` |
| `basename` GNU vs POSIX | musl differs | `0008-Define-glibc-compatible-basename-for-non-glibc-syste.patch` |
| stdio buffering on oom_score_adj write | musl buffering differs | `0009-Do-not-disable-buffering-when-writing-to-oom_score_a.patch` |
| `strerror_r` GNU (char*) vs XSI/POSIX (int) | musl is POSIX | `0010-distinguish-XSI-compliant-strerror_r-from-GNU-specif.patch` + `0019-errno-util-Make-STRERROR-portable-for-musl.patch` + `0018-test-bus-error-strerror...` |
| `struct prctl_mm_map` redefinition | kernel-header vs systemd clash on musl | `0011-avoid-redefinition-of-prctl_mm_map-structure.patch` |
| file-write buffering | musl differs | `0012-do-not-disable-buffer-in-writing-files.patch` |
| `__cpu_mask` (glibc cpuset internal) | absent | `0013-Handle-__cpu_mask-usage.patch` |
| `gshadow.h` / sgrp | musl has no gshadow | `0014-Handle-missing-gshadow.patch` (+ `-Dgshadow=false`) |
| MIPS syscall ABI defines | musl-MIPS gap | `0015-missing_syscall.h-Define-MIPS-ABI...` (irrelevant x86/arm, harmless) |
| `getdents64` struct/params | mismatch | `0016-pass-correct-parameters-to-getdents64.patch` |
| general musl header gaps | `__WORDSIZE` etc. | `0017-Adjust-for-musl-headers.patch` |
| `qsort_r` GNU arg order | musl differs | (covered by the above header/portability set; systemd also uses its own `typesafe_qsort`) |
| `LOCK_EX`/`<sys/file.h>` | not pulled in | `0022-avoid-missing-LOCK_EX-declaration.patch` |
| missing `<signal.h>` include | undeclared-error on musl | `0023-include-signal.h-to-avoid-the-undeclared-error.patch` |
| `stdin` used as struct member name | musl macroizes `stdin` | `0024-undef-stdin-for-references-using-stdin-as-a-struct-m.patch` |
| header inclusion order redeclaration | musl ordering | `0025-adjust-header-inclusion-order-to-avoid-redeclaration.patch` |
| boot-time segfault in `build-path.c` | musl runtime diff | `0026-build-path.c-avoid-boot-time-segfault-for-musl.patch` |

Handled **internally by systemd already** (no patch needed):
- `secure_getenv` → systemd ships its own fallback.
- `canonicalize_file_name` → systemd uses its own `chase()`/`path_*`, not the glibc fn.
- `gettid` → `missing_syscall.h` raw syscall wrappers.
- `error.h` family → systemd uses `log_*()`, not glibc `error()`.
- `printf("%m")` → **musl supports `%m`**, no issue.
- `crypt_r` → uses libxcrypt.
- `malloc_trim`/`malloc_info` (glibc-only) → made conditional (`0020`, `0021`).

Net: **~22-24 portability patches, all small.** On 259 they're upstream. This is not a fork.

---

## 7. Recommended plan (concrete)

1. **systemd version:** **`v259`** (native musl, no external patch series). Fallback if 259's experimental musl bites: **`v257.6` + OE walnascar musl series** (22-24 patches, postmarketOS-proven).
2. **Patch source:**
   - 259 route: none for portability — only your own distro-integration patches (presets/units). Source: `github.com/systemd/systemd` tag `v259`.
   - 257 route: poky `walnascar` `SRC_URI_MUSL` list (§2), fetch each via `https://git.yoctoproject.org/poky/plain/meta/recipes-core/systemd/systemd/<patch>?h=walnascar`. **Skip** the OE-only non-musl patches (`binfmt`, `sysv-install`, `var-log-README`).
3. **Cross-build deps in order** (§3): musl sysroot → gperf/meson/ninja/jinja2 (native) → libcap → libxcrypt → util-linux → libseccomp → kmod → pcre2 → zstd/lz4/xz → openssl → libgpg-error+libgcrypt → acl → libidn2 → linux-pam → dbus and/or dbus-broker. Optional later: audit, elfutils, microhttpd, qrencode, tpm2, fido2.
4. **Linking:** dynamic against shared musl + shared deps; ship `ld-musl-{x86_64,aarch64}.so.1`; **do NOT attempt full-static**; keep `link-*-shared=true`.
5. **meson flags:** start from §4. First bring-up: `-Dmode=developer`, `-Dtests=false`, coredump/EFI off, NSS/gshadow/userdb/idn off. **Keep resolved + localed ON** (they build on musl; OE only drops them by policy). `-Ddefault-hierarchy=unified`.
6. **Kernel:** implement §5. Gate order: (a) cgroup-v2 + /proc /sys /dev + signalfd/timerfd/epoll/eventfd/inotify + memfd+seals + AF_UNIX/SCM + CHILD_SUBREAPER → PID1 boots; (b) pidfd + close_range + seccomp + caps + namespaces+propagation + name_to_handle_at → service mgmt; (c) NETLINK_ROUTE/UEVENT + /dev/kmsg + keyctl → networkd/udevd/journald.
7. **Cross-check** against postmarketOS pmaports (`gitlab.com/postmarketOS/pmaports`, systemd 257.8 on musl as PID1) when a patch fails to apply or a daemon misbehaves.
8. **D-Bus:** ship **dbus-broker** as the system bus (sd-bus-native, drop-in `dbus-broker.service`) + the **dbus** package for policy config and `busctl`. Test dbus-broker's musl build; fall back to reference dbus if needed.

---

## Sources
- systemd v259 NEWS (verbatim musl paragraph): `https://raw.githubusercontent.com/systemd/systemd/v259/NEWS`
- The Register on 259-rc1 musl: `https://www.theregister.com/2025/11/20/rc_systemd_259/`
- Release tags verified live: `v255.21 v257.9 v258.8 v259 … v259.6`
- poky walnascar systemd_257.6.bb (`SRC_URI_MUSL`): `https://git.yoctoproject.org/poky/plain/meta/recipes-core/systemd/systemd_257.6.bb?h=walnascar`
- poky scarthgap systemd_255.21.bb: `https://git.yoctoproject.org/poky/plain/meta/recipes-core/systemd/systemd_255.21.bb?h=scarthgap`
- poky systemd.inc (DEPENDS, PACKAGECONFIG, `PACKAGECONFIG:remove:libc-musl`): `https://git.yoctoproject.org/poky/plain/meta/recipes-core/systemd/systemd.inc?h=walnascar`
- OE musl removal list (`PACKAGECONFIG:remove:libc-musl`, verified exact, walnascar+scarthgap): `gshadow idn nss-myhostname nss-mymachines nss-resolve nss-systemd userdb` (note: OE does NOT drop resolved or localed — earlier draft was wrong; both build on musl and stay enabled)
- systemd 259 musl PR: `https://github.com/systemd/systemd/pull/38825`
- LWN "What's new in systemd v259": `https://lwn.net/Articles/1051235/`
- postmarketOS systemd-on-musl (257.8, PID1, v25.06): `https://postmarketos.org/blog/2025/06/22/v25.06-release/`, `https://postmarketos.org/edge/2025/01/09/systemd-soon/`
- Adélie/awilfox musl port writeups: `https://catfox.life/2024/09/05/porting-systemd-to-musl-libc-powered-linux/`, `https://catfox.life/2024/01/05/systemd-through-the-eyes-of-a-musl-distribution-maintainer/`
- Gentoo 12101111 overlay (systemd-on-musl using OE patches): `https://github.com/12101111/overlay`
- dbus-broker: `https://github.com/bus1/dbus-broker`
- musl-libc projects list: `https://wiki.musl-libc.org/projects-using-musl.html`
