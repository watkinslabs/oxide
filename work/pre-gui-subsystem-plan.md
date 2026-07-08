# Pre-GUI Subsystem Plan

## 1 Scope

Goal: close Linux-compatible subsystem contracts that graphical login depends on before GNOME-specific debugging resumes.

Non-goals:

- No ext4/VFS work; another lane owns it.
- No GNOME session, shell, theme, compositor policy, or desktop packaging work.
- No scheduler rewrite unless targeted traces prove a wakeup/latency defect after VT, DRM, and AF_UNIX contracts are verified.

Inputs:

| Source | Contract |
|---|---|
| `README.md` | Current priority order and boot-to-graphical objective |
| `state.md` | Last observed blocker and evidence from prior boots |
| `docs/50-vt.md` | VT/KD ioctl surface and switching invariants |
| `docs/47-drm-kms.md` | DRM card/render node split, master/auth, KMS, render allow list |
| `docs/24-ipc.md` | AF_UNIX `SCM_RIGHTS`/`SCM_CREDENTIALS`, futex, eventfd, timerfd |
| `docs/13-sched.md` | no-lost-wakeup and wakeup preemption invariants |

## 2 Priority Order

| Priority | Lane | Done when |
|---|---|---|
| P0 | Subsystem observability | One probe or smoke can name the failing contract without booting a full desktop. |
| P1 | VT/KD ioctl compliance | Hosted tests and a boot probe cover switching, wait-active, process mode, and text/graphics mode. |
| P2 | DRM master/auth and node split | Card and render nodes behave per Linux for open, ioctl allow/deny, master ownership, and auth. |
| P3 | Seat/device handoff substrate | tty, input, card, and render device metadata plus permissions support logind-style ownership transfer. |
| P4 | AF_UNIX/D-Bus substrate | fd passing, credentials, pidfd/fd lifetime, poll/epoll, close, and hangup semantics survive broker-like traffic. |
| P5 | Wakeup latency fallback | Only begins with traces showing P1-P4 are correct and a runnable task is not scheduled or woken promptly. |

## 3 P0 Observability

Build probes that run against the real kernel interfaces and produce single-line PASS/FAIL plus a structured failure reason.

Required artifacts:

| Artifact | Content |
|---|---|
| VT probe | ioctl name, fd path, active VT before/after, errno, blocked waiter state |
| DRM probe | node path, ioctl, auth/master state, errno, returned ids/caps |
| AF_UNIX probe | socket type, cmsg sent/received, received fd behavior, peer creds |
| Wake trace | futex/epoll waiter, waker tid, timestamp delta, final task state |

Acceptance:

- Probe failure identifies missing Linux semantic, wrong errno, unexpected blocking point, or wrong returned structure.
- Probe can run without a graphical desktop.
- Boot smoke is added only when hosted coverage cannot exercise the kernel/device path.

## 4 P1 VT/KD Ioctls

Implement and prove the complete currently-needed VT/KD surface from `docs/50-vt.md`.

Required ioctl behavior:

| Group | Calls |
|---|---|
| Active state | `VT_GETSTATE`, `VT_ACTIVATE`, `VT_WAITACTIVE` |
| Mode ownership | `VT_GETMODE`, `VT_SETMODE`, `VT_RELDISP` |
| Display mode | `KDGETMODE`, `KDSETMODE` |
| Compatibility | `VT_OPENQRY`, `VT_DISALLOCATE`, `VT_RESIZE`, `VT_RESIZEX` as spec/audit requires |

Implementation expectations:

- `VT_WAITACTIVE` blocks on a wait queue and wakes exactly when the target VT becomes active.
- `VT_ACTIVATE` validates range and switches through the same state path as keyboard-driven switching.
- `VT_PROCESS` mode delivers release/acquire signals and honors `VT_RELDISP`.
- `KDSETMODE(KD_GRAPHICS)` stops fbcon drawing for that VT; `KDSETMODE(KD_TEXT)` resumes it.
- Errnos match Linux for invalid VT ids, bad pointers, unsupported legacy operations, and inactive disallocation.

Tests:

- Hosted ioctl tests over real tty/vt objects.
- A small userspace probe under `userspace/` if hosted tests cannot cover syscall/uapi packing.
- Boot smoke that runs the probe and records active VT before/after.

## 5 P2 DRM Master/Auth And Nodes

Complete the Linux card/render split from `docs/47-drm-kms.md`.

Required behavior:

| Area | Contract |
|---|---|
| Publication | `/dev/dri/card0`, `/dev/dri/renderD128`, matching sysfs/devfs metadata |
| Render node | Allows only render-safe ioctls; rejects master/KMS-only ioctls with Linux-compatible errno |
| Card node | Supports KMS ioctls and enforces one DRM master where required |
| Master | `DRM_IOCTL_SET_MASTER`, `DRM_IOCTL_DROP_MASTER`, open/close master lifetime |
| Auth | `DRM_IOCTL_GET_MAGIC`, `DRM_IOCTL_AUTH_MAGIC`, per-file auth state |
| Future 3D | Keep render-node path generic for GEM/PRIME/syncobj, not virtio-gpu-only shortcuts |

Tests:

- Hosted unit tests for per-file master/auth state.
- Probe opens card and render nodes, compares allowed/denied ioctl matrix, and verifies errno.
- Probe opens two card fds and proves single-master behavior across set/drop/close.

## 6 P3 Seat/Device Handoff Substrate

Do the Linux kernel/device side of seat handoff, independent of a desktop session.

Required behavior:

| Device class | Contract |
|---|---|
| tty/vt | stable device ids, permissions, active VT sysfs state |
| input | event devices enumerable with udev-compatible metadata |
| drm card | KMS-capable card node with master semantics |
| drm render | unprivileged render node when permissions allow |
| lifetime | close/drop revokes file-owned state without leaking master/auth/session data |

Acceptance:

- Device metadata is sufficient for a logind-like userland to identify seat0 devices.
- A synthetic handoff probe can open, pass, revoke, and close device fds without GNOME.
- No path relies on hard-coded process names or graphical desktop behavior.

## 7 P4 AF_UNIX/D-Bus Substrate

Prove the IPC/control plane used by service managers and session brokers.

Required behavior:

| Area | Contract |
|---|---|
| `SCM_RIGHTS` | send duplicates fds into message metadata; receive installs working fds in receiver |
| `SCM_CREDENTIALS` | sender pid/uid/gid snapshot matches Linux expectations |
| pidfd/fd handoff | passed pidfds and ordinary fds retain lifetime and poll behavior |
| readiness | poll/epoll wake on queued data, cmsg availability, close, and peer shutdown |
| socket forms | pathname and abstract sockets behave per AF_UNIX rules |
| pressure | broker-like many-client traffic does not lose wakeups or cmsg metadata |

Tests:

- Extend existing socketpair/fd-passing probes where possible.
- Add broker-style hosted test with many clients sending fds and credentials.
- Boot smoke only if the hosted path cannot exercise VFS pathname sockets or process credentials.

## 8 P5 Wakeup Latency Fallback

Do not start here. Begin only if P1-P4 probes pass and traces still show blocked progress.

Trace requirements:

| Trace | Must show |
|---|---|
| Futex | waiter key, waker, wake count, post-wake runnable state |
| Epoll | watched fd, ready mask, waiter, wake timestamp |
| Scheduler | runnable insertion, selected task, current task, preempt state |
| Timer | expiry, callback, waiter wake |

Acceptance:

- A failing trace proves one of: lost wakeup, runnable task not scheduled, preemption disabled too long, or wrong readiness mask.
- Fix includes a deterministic hosted reproducer before any boot claim.

## 9 Branch Split

Use the next counter in `metadata/index.md` at the time each lane starts; do not reserve numbers from this document.

Suggested lane titles:

| Lane | Title |
|---|---|
| Bug/function | `vt-kd-ioctl-compliance` |
| Bug/function | `drm-master-auth-compliance` |
| Bug/function | `seat-device-handoff-substrate` |
| Bug/function | `afunix-dbus-handoff-substrate` |
| Bug/function | `wakeup-latency-proof` |
| Tooling | `pre-gui-subsystem-probes` |

## 10 Definition Of Done

Each implementation lane is done only when:

- Missing Linux behavior is stated before code changes.
- Hosted/unit proof covers core semantics.
- Probe or boot-facing proof covers syscall/uapi/device plumbing when relevant.
- Errno and blocking behavior are asserted, not eyeballed.
- x86_64 and aarch64 build gates pass for touched kernel/runtime code.
- README/state/handoff docs are updated only for material changes in priority or evidence.
