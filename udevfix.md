# Udev Fix Ledger

Date: 2026-07-06

Rule: each row is one short-lived branch from fresh `origin/main`. Status starts
as `NOT DONE`; update this file when a branch is claimed, verified, merged, or
blocked. Boot smokes are skipped for this campaign per user instruction; use
focused source/unit/build checks only unless a fix cannot be trusted without a
boot.

| Status | Branch | Description |
| --- | --- | --- |
| DONE | B606-udev-canonical-devpath | Make generic `/sys/devices/.../uevent` replay use the same canonical DEVPATH as add/remove events. |
| DONE | B607-net-uevent-env | Make net device `uevent` replay include `INTERFACE` and `IFINDEX` instead of emitting a bare event. |
| DONE | B608-uevent-seqnum-sysfs | Add/readable `/sys/kernel/uevent_seqnum` backed by the netlink uevent sequence counter, or document and prove non-requirement in code tests. |
| DONE | B610-sys-dev-block-index | Ensure `/sys/dev/block/<major>:<minor>` resolves for real registered block disks, including disks sourced from `block::registry`. |
| DONE | B611-tty-subsystem-link | Add `subsystem` symlink to `/sys/devices/virtual/tty/<name>` if code/tests confirm udev/libudev expects the same class-device shape as other classes. |
| DONE | B612-udev-control-proof | Add focused AF_UNIX/systemd-udevd control socket proof for connect, wake, send, and reply behavior without boot smokes. |
| VERIFIED | B613-inotify-udev-dirs | Prove or fix inotify `IN_CREATE`/`IN_DELETE`/move delivery for `/dev` and `/run/udev` directory mutations. |
| NOT DONE | B614-class-env-audit | Audit and fix class-specific uevent env for input, sound, graphics, misc, and mem devices where Linux udev rules need more than DEVNAME/MAJOR/MINOR. |

## Current Priority

1. `B606-udev-canonical-devpath`
2. `B607-net-uevent-env`
3. `B608-uevent-seqnum-sysfs`
4. `B610-sys-dev-block-index`
5. Remaining proof/audit rows after the deterministic replay and sysfs-index fixes.
