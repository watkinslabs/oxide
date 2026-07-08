# Handoff — glibc quick-boot + 4 kernel/compat fixes; GNOME greeter still not visible

**Branch:** `F693-quickboot-glibc-rootfs` (pushed, PR #2837).
**Goal (NOT yet met):** graphical GNOME booting to a visible greeter, 100% Linux-compat, no stubs.

## DONE + verified
- **musl → glibc quick-boot** (packs `../images/output/live-gnome-x86_64-root.img`; zero ld-musl).
- **KVM + 4G** defaults; **rw root + service masks** → graphical.target 137s→52s.
- **DRM VIRTGPU_GETPARAM/GET_CAPS** (Mesa 2D/llvmpipe fallback) — correct; unverified end-to-end (greeter never reaches mutter reliably).
- **`init=` kernel param honored** (ccf787cf) — was hardcoded /init. VERIFIED `init: selected /usr/bin/bash`.
- **3 kernel reap bugs** (found via `debug-taskdump`, the key tool — dumps every task's state/last-syscall every 20s):
  - c1ceabf5: exited CLONE_THREAD threads auto-release (were wait4-zombies + spurious SIGCHLD). thread-zombies 19→0.
  - a01b0af5 + af881c2a: reparented-zombie → re-notify init + queue child_sigq event (ssi_pid was 0 → systemd reaped nothing). t=20s backlog 15→0.

## STILL BLOCKED — greeter launch loops; gnome-shell never stably execs
From task dumps of a wedged live-gnome KVM boot:
- logind DID create the greeter session **c1 with card0 (226:0)** (saw `session-c1-device-226-0`), so the seat IS graphical.
- gdm is alive (pid ~223) but its main thread sits in **ppoll**; gnome-shell/gdm-session-worker **never exec** (0). The
  session c1 setup **loops** (repeated `FDSTORE=1` for session-c1-device-226-0) → gdm keeps re-creating the greeter.
- ~24 late PROCESS zombies (gdm/sh/bash/session helpers) accumulate — SYMPTOM: they are children of gdm, which is
  blocked in ppoll and not reaping them (init reaps its own children fine early; the leak is gdm-side + a few reparented).
- RULED OUT: the `init=/usr/bin/bash` `#PF` (rip=0xffffffff80257229 = `smoke::elf::user_fault_handler` faulting on a
  not-present user page) is SEPARATE — bash-as-PID1 only; the greeter boots have **zero [FAULT]**. Still a real bug
  (fault handler #PFs for the init= spawn stack) but NOT the greeter blocker. Fix later.
- ROOT-CAUSE CHAIN (found via `systemd.log_level=debug` on the cmdline — that's how to get userspace errors on serial):
  gnome-shell never execs ← `gdm.service: starting held back, waiting for: switcheroo-control.service`
  ← `switcheroo-control.service: start operation timed out. Terminating` — it forks /usr/libexec/switcheroo-control
  (pid 114) but NEVER acquires its D-Bus name `net.hadess.SwitcherooControl` → systemd times it out → cascades to gdm.
- SAME signature on switcheroo-control, accounts-daemon, upowerd, polkitd in the task dumps: **main thread parked in
  `futex`, a worker thread zombied**. These are glib GDBus services hanging at STARTUP while acquiring their bus name.
  => The real bug is kernel-side: a futex/thread-sync wake lost, or D-Bus-over-AF_UNIX message/poll delivery, in the
  glib GDBus name-acquisition path. Fix this and gdm should proceed. NO stub — it's a real kernel bug.
- RULED OUT (this session): raw futex lost-wakeup. The futex WAIT/WAKE/key code is correct (re-checks *uaddr under
  WAITERS.lock; private key = shared mm.root_pa so cross-thread wakes match). Widened debug-futextrace to also trace
  switcheroo-control/accounts-daemon (wait.rs ftx_target_exe) and a boot showed **0 FTX-WAIT/WAKE** for them — they do
  NOT block on the traced futex path. So the hang is in the **D-Bus-over-AF_UNIX delivery** (dbus-broker RequestName
  reply not arriving, or eventfd/epoll wake for the socket), NOT futex.
- ALSO RULED OUT: poll/ppoll lost-wakeup. 007_poll.rs subscribes to each fd's PollSubscribers BEFORE scanning AND
  re-scans every RESCAN_NS=20ms (park_dl = min(deadline, now+20ms)) — self-heals from any lost wake in ≤20ms.
  epoll_wait has the same bounded rescan. So neither futex nor poll can hang PERMANENTLY on a lost wake.
- Therefore switcheroo-control's ppoll re-scans ~4500× over its 90s timeout and NEVER sees readiness => the D-Bus
  RequestName reply genuinely never becomes readable. Two suspects, both concrete + kernel-side:
    (a) dbus-broker never delivers switcheroo's message / reply — AF_UNIX SCM/message delivery drops it; OR
    (b) the AF_UNIX socket poll()/readiness wrongly returns not-readable when data IS queued (so the 20ms rescan
        never observes POLLIN). NOTE: sock/inode.rs poll() delegates to InetSocket::poll() — verify the UNIX-domain
        (unix_sock stream) path has a correct poll/readiness that reflects queued rx bytes; it may be missing/wrong.
- NEXT: trace one D-Bus round-trip: pick switcheroo-control (pid ~114) or accounts-daemon, trace its AF_UNIX
  sendmsg/recvmsg on /run/dbus/system_bus_socket + the peer (dbus-broker) recv + the poll mask each computes. Find
  where the message or the readiness is dropped. That IPC fix is the last mile to a visible GNOME greeter.
- How to get userspace errors on serial: add `systemd.log_level=debug` to the dev cmdline (image_qemu/x86_64.rs).

## Tooling facts
- `debug-taskdump` feature = the diagnostic: `qemu_start arch=x86_64 accel=kvm mem=4G features=debug-boot,debug-taskdump`,
  run ~200s, grep `[TASKDUMP] t=NNNs` for each proc's state/last-syscall; grep `[DRMIOCTL]` for mutter's DRM sequence.
- gdb `qemu_interrupt` does NOT work under KVM. No serial getty (getty on tty0). `init=/bin/bash` needs ext4 read_file to
  follow the usrmerge /bin→/usr/bin symlink (use /usr/bin/bash); and it #PFs (above).
- Boots wedge intermittently (~6/7) during greeter launch. init tid = 3235774466 (vpid 1).

## Pick up here
1. Root-cause the `init=/usr/bin/bash` kernel #PF (addr2line rip=0xffffffff80257229) — likely the exec initial-stack build
   or first user fault not being demand-paged; this is the strongest lead and may be the greeter loop's cause.
2. If separate: get gnome-shell's error — either fix ext4 symlink follow so `init=/bin/bash` works for a rescue shell to
   run journalctl, or add a serial-getty to the image profile.
