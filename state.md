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
- **NEW concrete lead:** `init=/usr/bin/bash` selected bash then the kernel took a **#PF (NP-W-K) at rip=ffffffff80257229,
  cr2=user-stack** during PID1 stack-build/first-run. If the exec/stack path can #PF the kernel, gnome-shell's exec could
  hit the same → killed → gdm relaunch loop = the greeter loop. INVESTIGATE this #PF first (hal fault handler / user_as
  stack fault at 0x...57229) — it may be THE greeter blocker, not just a bash-as-init quirk.

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
