# GNOME-boot campaign ledger

Goal: boot live-GNOME, fixing every kernel system on the path 100% Linux-compat,
no hacks/stubs. Every item ships with a hosted smoke test / harness (fast path);
boot only to verify. Source: scratch/kernel-audit2.md.

Rule: fix the first failing boot contract before chasing subsystem completeness.

| # | Item (audit ref) | Status | Branch | Harness |
|---|---|---|---|---|
| 1 | tmpfiles-dev-early 249s stall = missed AF_UNIX targeted wake (§2.5) | IN-PROGRESS | B700? | net af_unix wake harness |
| 2 | udev/devfs/sysfs uevents + /dev nodes (§2.2) | TODO | | |
| 3 | systemd mount contract (§2.3) | TODO | | |
| 4 | cgroup v2 unified (§2.4) | TODO | | |
| 5 | AF_UNIX/netlink/epoll/D-Bus reliability (§2.5) | TODO | | |
| 6 | procfs/sysfs basics (§2.6) | TODO | | |
| 7 | DRM/KMS + fb (§3.1) | TODO | | |
| 8 | input/evdev (§3.2) | TODO | | |
| 9 | TTY/PTY/VT/logind session (§3.3) | TODO | | |
| 10 | swap (swapfile-on-ext4) (§3.4) | TODO | | |
| 11 | basic net (lo + one virtio-net) (§3.5) | TODO | | |

## Done this session
- ext4 100% complete (14 lanes) + B699 op_lock/flush livelock fix (merged, main).
  Boot now clears the ext4 livelock; hwdb finishes ~55s (was hard-hang).

## Current: item 1
Evidence: tmpfiles-setup-dev-early (tid 31) started 11.2s, Finished (success) 266.5s.
Zero ext4/namei traces in the window => BLOCKED, not slow-working. epoll_wait has a
20ms safety-net rescan, so a 249s stall is NOT in epoll_wait — it's a blocking
AF_UNIX primitive parked on a WaitList woken only by a targeted notify, freed late
by an unrelated global wake ~266s. UnixListener::notify_subs() (listener.rs:44) has
NO global fallback, unlike wake_peer_subs (events.rs:23). Socket-activated userdbd
inherits an already-listening fd => never calls listen()/register_subs, so the
listener's single `subs` weak still points at systemd's epoll, not userdbd's.
Next: instrument the AF_UNIX park points to confirm the exact primitive + the 266s
waker, then fix (global fallback + multi-subscriber listener subs), add hosted harness.
