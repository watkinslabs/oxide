# Handoff — glibc quick-boot done; boot-to-GNOME: 2 reap bugs fixed, greeter still blocked

**Branch:** `F693-quickboot-glibc-rootfs` (pushed, PR #2837).
**Goal:** graphical GNOME booting to a visible greeter, 100% Linux-compat, no stubs.

## DONE + verified
- **musl → glibc quick-boot** (packs `../images/output/live-gnome-x86_64-root.img`; zero ld-musl).
- **KVM + 4G** defaults; **rw root + service masks** (zram/firewalld/chronyd/modem/plymouth) → graphical.target 137s→52s.
- **DRM VIRTGPU_GETPARAM/GET_CAPS** implemented (Mesa 2D/llvmpipe fallback) — correct, still unverified end-to-end (greeter never reaches mutter reliably).
- Debug traces → opt-in `debug-displaystack`; boot-smoke marker → `Reached target basic.target`.
- **`debug-taskdump` is the key diagnostic**: boot with `features=debug-boot,debug-taskdump`, it dumps
  every task (state/last-syscall/futex/exe) every 20s from the timer tick. That's how the bugs below were found.

## Two kernel reap bugs FIXED this session (committed, verified via task dump)
1. **c1ceabf5 — exited CLONE_THREAD threads must auto-release.** `sys_exit` treated a non-leader
   thread (tid!=tgid) as a process: signal_child_exit (SIGCHLD to parent) + wait4-zombie. Linux
   release_task auto-reaps threads (pthread_join = clear_child_tid FUTEX_WAKE only). polkitd piled up
   19 zombie THREADS + flooded itself with spurious SIGCHLD. Fix: 060_exit skips signal_child_exit for
   tid!=tgid; switch.rs drops (not enqueue_zombie) a non-leader-thread zombie. **thread-zombies 19→0.**
2. **a01b0af5 — notify init when reparenting an already-zombie child** (forget_original_parent→do_notify_parent).

## STILL BLOCKED (pick up here) — greeter never launches gnome-shell
Task dump at t=240s of a wedged live-gnome boot (KVM):
- gdm IS alive (pid 223, 4 threads) but its main thread sits in **ppoll** — waiting on the
  logind seat / `CanGraphical` handshake (a D-Bus reply), NOT reaping. gnome-shell/gdm-session-worker
  never exec (0). So the block is the **gdm↔logind↔seat0/DRM-master handshake**, likely intermittent
  (ONE boot with debug-futextrace DID reach gnome-shell + DRM ioctls).
- **26 PROCESS zombies** (tid==tgid: gdm×3, sh×3, bash, true, nm-dispatcher, plymouth, session helpers)
  parented to init (ptid=3235774466) that **init never reaps** even though it's in epoll_wait on its
  SIGCHLD signalfd and I explicitly post SIGCHLD+wake it. Next suspect: signalfd read siginfo si_pid
  (fs/signalfd.rs + sched push_child_event) — if the siginfo reports a wrong/stale si_pid, systemd
  waitid(si_pid) reaps nothing → leak. Verify the child-exit event queue → signalfd_siginfo si_pid path.
  TRIED: pushing push_child_event(&t, init) inside reparent_children so init's signalfd read gets the
  right si_pid — the boot then wedged at ~18s (suspect: calling child_sigq_push in the preempt-off
  sys_exit→reparent path, or just a flaky early wedge). Reverted (unverified). Retry carefully, or
  push the child event OUTSIDE the preempt-off window.
- Whether the zombie-reap gap and the gdm-seat wait are the same root or two bugs is unresolved.

## Facts / tooling
- init tid = 3235774466 (vpid 1). Zombies keyed by parent_tid; reap_one matches parent_tid==parent.
- gdb `qemu_interrupt` does NOT work under KVM; no serial getty (getty is on tty0); kernel IGNORES
  `init=` cmdline (hardcodes /init at smoke/src/elf.rs:95 — a real compat gap; blocks init=/bin/bash shell).
- Boots wedge intermittently (~6/7) at random points during greeter launch. Use debug-taskdump + grep
  the t=NNNs dumps for state/last-syscall to see what each process is blocked on.
- First command: qemu_start arch=x86_64 accel=kvm mem=4G features=debug-boot,debug-taskdump; run ~200s;
  analyze the last [TASKDUMP] for gdm/gnome-shell/logind states + zombie parents.
