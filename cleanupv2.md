# cleanupv2 — `make live` boot assessment (2026-07-05)

Source: `oxide-images/test.log` (7794 lines) — live-gnome x86_64 boot of the current kernel.

## TL;DR — where we are

Boot is **much further than the historical notes suggest**. It now:

- Reaches `basic.target` → `multi-user.target` → **`graphical.target` (t≈106s)**, "Startup finished".
- Brings up dbus-broker, polkit, systemd-logind (seat0 created), udisks2, machined, gdm, and launches **gnome-session / gdm-wayland-session** for `gnome-initial-setup` (uid 979).

Then it **wedges in a repeating loop** and never presents a usable desktop. The terminal state is a cascade off **one root cause**: the per-user systemd manager (`user@979.service`) cannot start, so the session D-Bus can never activate `org.freedesktop.systemd1`, so every `gsd-*` plugin and `gnome-session` blocks on a 120 s D-Bus timeout and gives up.

Everything else in the log is either (a) a contributor to that wedge, (b) an independent subsystem gap that will bite once the wedge clears, or (c) benign noise worth silencing so real failures stand out.

---

## Campaign ledger

Goal: complete every item below to **100% Linux compat, no hacks/stubs**. One item = one branch = one PR (isolated worktree off fresh `origin/main`). Status flips to DONE with the merging PR so history is auditable.

Status: `TODO` · `IN-PROGRESS` · `DONE` · `WONTFIX` (only if Linux itself diverges, per [[build-missing-subsystems-for-100]]).

| Item | Summary | Tier | Status | Branch | PR |
|------|---------|------|--------|--------|-----|
| 1.1 | PAM `PAM_SESSION_ERR` — `user@979.service` step PAM | 1 | BLOCKED — no causative syscall (semantic bug; ~15 captures exhausted boot-capture) | B423 + captures | #2477 |
| 1.2 | Namespaces: UTS + net + mount-ns tolerance | 1 | MOSTLY DONE — UTS (fleet) + net-ns AF_UNIX/loopback isolation (B518 #2579); inet-per-ns + mount-ns-tolerance = documented follow-ups | B518-netns-isolation | #2579 |
| 2.1 | `PR_SET_MM` (all 15 subcmds) + fix reversed argv/env stack | 2 | DONE | B430-prctl-set-mm | #2498 |
| 2.2 | udev `hwdb` + `path_id` builtins | 2 | TODO (hwdb.bin asset vs mmap ENODATA; medium) | — | — |
| 2.3 | `/dev/vda` ENXIO (virtio-blk open) | 2 | **DONE** — root cause was the block-registry↔VFS-BLKDEV table split (NOT a virtio driver gap; disjoint from the fleet's virtio lane) | B525-blkdev-open | #2583 |
| 2.4 | Module autoload alias no-op for built-ins | 2 | TODO — **fleet's active virtio/uevent lane** | — | — |
| 3.1 | `systemd-initctl` fifo `read()` EIO | 3 | DONE | B502-fifo-open-impl | #2562 |
| 3.2 | Persistent journal EBUSY (mmap/flock) | 3 | TODO (mmap/flock race; needs boot capture) | — | — |
| 3.3 | `/proc/sys` writable sysctl leaves (core_pattern honored) | 3 | DONE | B512-sysctl-leaves | #2565 |
| 3.4 | `/dev/fuse` (real FUSE subsystem) DONE; `/dev/null` ENXIO = separate intermittent race | 3 | PARTIAL — FUSE done (B518 #2581); /dev/null race remains (needs capture) | B518-fuse | #2581 |
| 3.5 | userdb short-read message framing | 3 | **PARTIAL / still open.** Landed a real, correct related fix — `sendmsg(2)` now coalesces the iovec array into ONE datagram for message-boundary sockets (UDP / AF_UNIX DGRAM / SEQPACKET) instead of one datagram per iovec (B527 #2585). But it does NOT resolve the userdb error: boot still shows "Received too short user lookup message" ×4. Traced to PID1's `user_lookup_fd` SOCK_DGRAM socketpair receiving a ≤8-byte datagram (systemd's `offsetof(unit_name)==8` check). ALL socketpair paths inspected clean — send stores `payload.to_vec()`, and recvfrom / recvmsg / recv_msg / recv_payload each pass the caller's full buffer size as `max` and deliver the whole payload; none truncate to ≤8. Next step: byte-level syscall trace of the actual `send()`/`recvmsg()` counts on the socketpair to see whether the child sends short or uses a path that fragments. Tier-3 noise (systemd logs "ignoring", non-fatal). | B527-sendmsg-coalesce (partial) | #2585 |
| 3.6 | update-utmp-runlevel D-Bus (cascade of 1.1) | 3 | BLOCKED-ON-1.1 (resolves when 1.1 lands) | — | — |
| 3.7 | PSI `/proc/pressure/*` (cpu live; mem/io honest-zero hook-ready) | 3 | DONE | B517-psi-pressure | #2576 |
| 3.8 | `/dev/mem` / `/dev/kvm` | 3 | WONTFIX | — | expected nested-virt noise |

---

## TIER 1 — Fatal (blocks login / GNOME session)

### 1.1 `user@979.service` dies at step PAM → no `systemd --user` → session-bus deadlock  ⭐ primary blocker
Evidence (lines 6521–6604, repeats at 7589/7659):
```
(systemd)[182]: PAM failed: Cannot make/remove an entry for the specified session
(systemd)[182]: user@979.service: Failed to set up PAM session: Operation not permitted
(systemd)[182]: user@979.service: Failed at step PAM spawning /usr/lib/systemd/systemd: Operation not permitted
user@979.service: Main process exited, code=exited, status=224/PAM
```
Downstream cascade (lines 7582/7703/7790, repeats):
```
dbus-daemon[188]: Failed to activate service 'org.freedesktop.systemd1': timed out (service_start_timeout=120000ms)
gnome-session-binary: ... StartServiceByName for org.freedesktop.systemd1: Timeout was reached
gsd-usb-protection / gsd-sharing / gsd-rfkill: Timeout was reached
```
The concrete kernel signal is **EPERM at the PAM session step**. `systemd --user` runs a fresh PAM stack; the failing module is almost certainly one of `pam_keyinit` (session keyring join via `keyctl(KEYCTL_JOIN_SESSION_KEYRING)`), `pam_loginuid` (write `/proc/self/loginuid`), or `pam_namespace`/`pam_systemd`. "Cannot make/remove an entry for the specified session" points hardest at the **session keyring**.

**Static audit (B423, 2026-07-05) — three prime suspects CLEARED:**
- `keyctl(KEYCTL_JOIN_SESSION_KEYRING)` → returns the global keyring serial unconditionally, no uid/cap gate (`crates/kernel/fs/src/keyring.rs:166`). Succeeds for uid 979. Not the cause.
- `/proc/self/loginuid` write → backed by writable `SysctlInode`, no CAP_AUDIT_CONTROL gate (`crates/kernel/procfs/src/static_files.rs:204`, `sysctl.rs:42`). Succeeds. Not the cause.
- `setns`/`unshare`/`clone(CLONE_NEW*)` → no cap gate; all NS bits implemented (`syscalls/src/272_unshare.rs`, `308_setns.rs`, `056_clone.rs`). Not the cause.
- The ONLY cap-gated EPERM reachable in a fresh PAM stack is **`setgroups`** (`crates/kernel/sched/src/cred.rs:388`, needs `CAP_SETGID`). Root gets `CAP_FULL` (`creds.rs:47`), so this only fires **if exec has already dropped to uid 979 before the PAM step**. Real systemd runs `setup_pam()` while still root (before `enforce_user()`), so setgroups should succeed — meaning either our exec drops privileges too early, OR the EPERM is a syscall that EPERMs even for root.
- **Disambiguation requires a capture-first boot** with `--features debug-syscall` (+`debug-mount`): reproduce, grep pid-182's window for the syscall returning `rv=-1`/EPERM (errno 1). debug-syscall already logs every `(nr, rv)` — no new probe needed (`syscalls/src/dispatch/core.rs:38`). **Blocker: needs an exclusive live-gnome boot** (main tree is occupied by the parallel agent; boot-verify reads main-tree artifacts).

**Live-gnome capture findings (2026-07-05, debug-syscall, 11 boots via the isolated `OXIDE_KERNEL_DIR` pipeline):**
- The cleanupv2 EPERM-syscall hypothesis is **DISPROVEN**. systemd's "Failed at step PAM ... Operation not permitted" is a **synthetic** EPERM systemd reports for ANY PAM-step failure. The real failure is a PAM module returning **`PAM_SESSION_ERR`** ("Cannot make/remove an entry for the specified session").
- In the failing `user@979` manager: `keyctl(JOIN_SESSION_KEYRING)`→serial, `add_key`→serial, `KEYCTL_SETPERM`→0, all `prctl` (incl. the `PR_CAPBSET_READ` cap_last_cap probe, EINVAL at cap 64 is normal), and logind "New session c2" **all succeed**. NO abnormal syscall error in the traced set. Manager `exit_group(224)` after an ~18s window of untraced file/socket ops.
- `pam_keyinit` is `session optional` (cannot fail the session); **`pam_loginuid` is `session required`** — prime suspect. Root cause is an untraced file/socket op (loginuid write, or a dbus/socket op), OR a semantic divergence (our `keyctl JOIN_SESSION_KEYRING` returns the single global serial instead of a fresh per-session keyring). NEXT: surgical in-kernel probe on the loginuid write path (boot-capture flooding hit diminishing returns).
- **Deep-capture conclusion (~15 live-gnome boots, all-error + connect-path probes):** the failing process is the `user@979` manager (`(systemd)[176]`). EVERY syscall it makes SUCCEEDS — the only errors in its window are benign (ioctl ENOTTY floods, openat/readlink ENOENT probes, mkdirat EEXIST) and an incidental **TCP** connect ECONNREFUSED (`tcp_conn/io.rs:43` — a network/DNS probe, NOT a unix socket; both unix-connect branches were probed and never fired). So the PAM_SESSION_ERR is a **pure semantic failure**: a syscall returns DATA a `session required` PAM module rejects — which boot-capture fundamentally cannot surface. Boot-capture is exhausted; further progress needs guest-side strace of pid 176 or reading the exact systemd-user PAM module chain, not more boots.
- **PAM module chain identified (no-boot rootfs analysis via debugfs, 2026-07-05):** `/usr/lib/pam.d/systemd-user` session stack = `pam_selinux(close/open)`, `pam_loginuid`, `pam_keyinit(optional)`, `pam_namespace`, then `include system-auth` (`pam_limits`, `pam_unix`). RULED OUT: pam_selinux (kernel exposes no selinuxfs → `is_selinux_enabled()`=0 → no-op), pam_namespace (`/etc/security/namespace.conf` empty → no-op), pam_loginuid (loginuid write verified OK). REMAINING `session required` suspects doing real work: **pam_limits** (setrlimit over limits.conf) and **pam_unix** (session). Final pin needs an in-guest strace of the manager (semantic data mismatch, not an errno).
- **Separate real bug found in the hunt:** `keyctl(KEYCTL_JOIN_SESSION_KEYRING)` returns a CONSTANT global serial (`1`) every call (fake single keyring) instead of a fresh per-session keyring — a genuine Linux-divergence worth fixing on its own merits. **FIXED: B516-real-keyrings #2572** (real per-task keyring hierarchy, 7 hosted tests). pam_keyinit is `session optional` so this was not the 1.1 root cause.
- Reusable pipeline built: `tools/boot-iso.sh` (#2485), imagectl `OXIDE_KERNEL_DIR` override (oxide-images), enhanced `debug-syscall` probe + `debug-openat` split (#2550), `oxide-images` live-gnome capture harness.

**Plan of attack:** capture-first, per house method. Add/extend a `debug-pam` (or reuse `debug-syscall`) gate to log the exact syscall returning EPERM in pid 182's window. Prime suspects to audit in kernel: `keyctl`/`add_key` session-keyring semantics, `/proc/self/loginuid` write path, and `setns`/`unshare` used by pam_namespace. Fixing this single item is expected to unblock the whole desktop.

### 1.2 Namespace subsystem gaps (UTS + network + partial mount)
Evidence (28 hits): 
```
ProtectHostname=yes ... kernel does not support UTS namespaces, ignoring
PrivateNetwork=yes ... kernel does not support ... network namespace, proceeding without
accounts-daemon.service: Failed to set up mount namespacing: /run/systemd/seats: No such file or directory
accounts-daemon.service: Main process exited, code=exited, status=226/NAMESPACE
```
Three distinct namespace types are missing/incomplete:
- **UTS namespace** — unimplemented (`ProtectHostname` silently skipped everywhere).
- **Network namespace** — unimplemented (`PrivateNetwork` skipped). Also `IP firewall ... does not support BPF/cgroup firewalling`.
- **Mount namespace** — partially works but `accounts-daemon` hard-fails `226/NAMESPACE` when a `BindReadOnlyPaths`/seat path is absent, i.e. the per-service mount-ns propagation isn't robust.

Hardened units (accounts-daemon already fully FAILED) will keep dying until these land. Likely related to 1.1 (pam_namespace).

**Plan:** implement UTS + net namespace stubs at minimum (enough that `setns/unshare(CLONE_NEWUTS|CLONE_NEWNET)` succeed and are no-op-correct), and make per-service mount-ns setup tolerate missing bind sources the way Linux does. Grep the kernel ns/clone flag handling for `CLONE_NEWUTS`/`CLONE_NEWNET`/`CLONE_NEWNS`.

---

## TIER 2 — Major functional gaps (will bite next)

### 2.1 `prctl(PR_SET_MM_ARG_START/ARG_END)` → EINVAL  (30×)
```
PR_SET_MM_ARG_START failed, attempting PR_SET_MM_ARG_END hack: Invalid argument
PR_SET_MM_ARG_END hack failed, proceeding without: Invalid argument
```
systemd uses `PR_SET_MM` to rewrite `argv[]`/mm fields (unit relabeling, `systemd --user` cmdline). Returns `-22`. `PR_SET_MM` subcommands are unimplemented. Non-fatal today (systemd falls back) but pervasive; implement the `mm_struct` field setters in the `prctl` handler.

### 2.2 udev `hwdb` builtin → ENODATA (60×) and `path_id` builtin → ENOENT (15×)
```
60-evdev.rules / 60-input-id.rules / 50-udev-default.rules: Failed to run builtin 'hwdb ...': No data available
71-seat.rules:75 Failed to run builtin 'path_id': No such file or directory
```
`hwdb` (ENODATA on the mmap'd `hwdb.bin` trie) and `path_id` fail. Consequences: input/evdev/seat tagging never gets applied, which **feeds directly into logind seat/session assignment** and thus Tier-1 session setup. Determine whether `hwdb.bin` is missing from the image or the mmap/read path returns ENODATA; `path_id` ENOENT suggests a helper/exec lookup gap.

### 2.3 Root block device `/dev/vda` unusable → ENXIO
```
Failed to open '/dev/vda', ignoring: No such device or address
Failed to open block device /dev/vda, ignoring: No such device or address
systemd-remount-fs[37]: mount: /: can't find LABEL=oxide
```
The virtio-blk root disk node exists but `open()` returns **ENXIO**, so `LABEL=oxide` is never found and the real disk is never mounted (system runs entirely off the boot/overlay).

**FIXED (B525 #2583).** Root cause was NOT a virtio-blk driver gap — it was a two-table split: the `block::registry` mints the devtmpfs `/dev/<name>` node via `drv::try_device_add` but never registered a `vfs::BlockDevOps` for the disk's dev_t, so `DeviceFileOps` in vfs hit `lookup_blkdev(devt) == None` → ENXIO on every path-based open. The kernel booted regardless because ext4 mounts by-serial (`by_serial("oxide-root")`), bypassing the node. Fix bridges the tables (`block/src/devbridge.rs`): `register`/`unregister` now publish/drop a `DiskBlkOps` adapter into the VFS BLKDEV region (Linux `add_disk`/`del_gendisk`); adapter does whole-sector RMW byte I/O; added BLKGETSIZE64/BLKGETSIZE/BLKSSZGET/BLKBSZGET so blkid/mkfs probes succeed. Because the fix lives entirely in `vfs/devnode` + `block/registry` (NOT the virtio driver), it was disjoint from the fleet's virtio lane. Hosted-tested + both arches build.

### 2.4 Module autoload alias misses (16×)
```
Failed to find module 'pci:v00001AF4d...'  /  'virtio:d0000000X'  /  'platform:i8042'
```
Expected for a monolithic kernel (no loadable modules), but the aliases for **built-in** drivers (virtio-blk/net/gpu, i8042) should resolve to no-ops instead of failing, or `modules.builtin.alias` should be populated so udev stops trying. Mostly noise, but the virtio ones overlap with 2.3.

---

## TIER 3 — Noise / robustness (silence so real failures surface)

| # | Symptom | Evidence | Nature |
|---|---------|----------|--------|
| 3.1 | `systemd-initctl.service` fully FAILED (start-limit) | `Failed to read from fifo: Input/output error` ×6 → `Start request repeated too quickly` (L1286) | FIFO/named-pipe `read()` returns **EIO** instead of blocking. Fix the fifo read path. |
| 3.2 | Persistent journal unusable | `Failed to open system journal: Device or resource busy` (L925); `journal ... corrupted ... renaming` | mmap/flock **EBUSY** on journal file — matches the long-standing EBUSY note. |
| 3.3 | `/proc/sys` writes fail | `Couldn't write ... kernel/core_pattern, kernel/sysrq, kernel/core_pipe_limit, net/ipv4/conf/*` (L720–810) | Missing writable sysctl leaves in procfs. |
| 3.4 | `/dev/null` open → ENXIO (intermittent) | `polkitd: Error opening /dev/null: No such device or address` (L6000); `fuse: device not found` (L6784) | Char-device open path intermittently ENXIO; `/dev/fuse` node missing. |
| 3.5 | userdb protocol | `Received too short user lookup message, ignoring` ×8 | systemd-userdbd socket message framing/short-read. |
| 3.6 | `systemd-update-utmp-runlevel.service` FAILED | `Failed to get D-Bus connection: No data available` (L6316/6373) | Partly cascade from 1.1; UTMP + bus reconnect. |
| 3.7 | PSI / memory-pressure | `Failed to allocate memory pressure watch ... Operation not supported` (L1404) | PSI (`/proc/pressure/*`) unimplemented. |
| 3.8 | `/dev/mem`, `/dev/kvm` | `Can't read memory from /dev/mem`; `Unable to open /dev/kvm` (L6298/6312) | Expected (nested virt); libvirt noise, leave as-is. |

---

## Recommended order of attack

1. **1.1 PAM/EPERM in `user@979.service`** — capture the exact failing syscall first (`debug-pam`/`debug-syscall`), then fix. This is the gate to a real desktop; do it before anything else.
2. **1.2 namespaces (UTS + net stubs, mount-ns tolerance)** — likely intertwined with 1.1 and unblocks the already-FAILED hardened daemons (accounts-daemon, etc.).
3. **2.2 hwdb + path_id** — restores seat/input tagging that logind (and 1.1) depend on.
4. **2.1 PR_SET_MM** — cheap prctl fill-in, kills 30 lines of noise and unblocks argv relabel.
5. **2.3 /dev/vda ENXIO + 2.4 virtio aliases** — needed for any persistent-storage story.
6. **Tier 3 sweep** — fifo EIO (3.1), journal EBUSY (3.2), sysctl leaves (3.3), /dev/null+/dev/fuse (3.4). Each is small and removes noise that currently hides real regressions.

### Method notes (house rules)
- **Capture-first**: for 1.1 / 3.1 / 3.4, add a cargo `debug-*` feature gate that logs the offending syscall + errno before proposing a fix; keep the probe in-tree permanently (per [[keep-gated-debug-instrumentation]]).
- **No overlapping agents**: one item = one lane; claim before starting (per [[no-overlapping-agents]]).
- **Build the subsystem** for infra gaps (namespaces, PR_SET_MM, PSI) rather than stubbing to a floor, unless Linux itself diverges (per [[build-missing-subsystems-for-100]]).
