# cleanupv2 — `make live` boot assessment (2026-07-05)

Source: `oxide-images/test.log` (7794 lines) — live-gnome x86_64 boot of the current kernel.

## TL;DR — where we are

Boot is **much further than the historical notes suggest**. It now:

- Reaches `basic.target` → `multi-user.target` → **`graphical.target` (t≈106s)**, "Startup finished".
- Brings up dbus-broker, polkit, systemd-logind (seat0 created), udisks2, machined, gdm, and launches **gnome-session / gdm-wayland-session** for `gnome-initial-setup` (uid 979).

Then it **wedges in a repeating loop** and never presents a usable desktop. The terminal state is a cascade off **one root cause**: the per-user systemd manager (`user@979.service`) cannot start, so the session D-Bus can never activate `org.freedesktop.systemd1`, so every `gsd-*` plugin and `gnome-session` blocks on a 120 s D-Bus timeout and gives up.

Everything else in the log is either (a) a contributor to that wedge, (b) an independent subsystem gap that will bite once the wedge clears, or (c) benign noise worth silencing so real failures stand out.

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
The virtio-blk root disk node exists but `open()` returns **ENXIO**, so `LABEL=oxide` is never found and the real disk is never mounted (system runs entirely off the boot/overlay). This is a real virtio-blk / device-open gap and will block any persistent-storage work. Cross-ref the `virtio:d*` module-alias misses (2.4).

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
