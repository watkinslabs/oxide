# Linux-class gap list

Rule: implement everything the Linux way. No hacks. No oxide-only mixins. No fake-success paths. No admit-and-no-op where Linux has real behavior. If Linux needs a real subsystem boundary, real userspace contract, real fd/ioctl/namespace/mount/linker behavior, we do that.

## 1. Hard requirements

- Real Linux userspace behavior, not probe-only behavior.
- Real upstream-style boot chain: real PID 1, real getty/login, real shared-lib userspace.
- Real Linux ABI semantics on both `x86_64` and `aarch64`.
- Real Linux-style layering: kernel substrate, real libc/dynamic linker/userspace, no oxide-specific shortcuts in the contract surface.

## 2. Biggest code-derived gaps

### 2.1 PID 1 / login / distro boot flow

- Finish a real boot-to-shell path, not just probes and support crates.
- `crates/user/svc/` is a parser + supervisor substrate, but the repo still reads like integration is incomplete rather than a finished PID 1 path.
- `userspace/login_sim/login_sim.c` and `userspace/pamtest/pamtest.c` show the real login/PAM chain is still being debugged.
- Goal: real `systemd`/`agetty`/`login`/`bash` path, Linux-style, no custom oxide auth flow.

### 2.2 NSS / PAM / account stack

- `crates/user/nss/src/lib.rs` is file parsing only; need full libc-facing NSS behavior.
- `crates/user/pam/src/lib.rs` is PAM-shaped logic, not full Linux PAM module/runtime behavior.
- Replace any oxide-local auth shortcuts with the same service/module behavior real Linux userland expects.

### 2.3 Dynamic linker / shared library runtime

- `userspace/dynlink/dynlink.c` is real but still missing Linux-grade pieces:
  - TLS init image / DTV setup
  - IFUNC
  - GNU symbol versioning
  - `dlopen` / `dlsym`
  - full lazy binding if needed
- `userspace/openssl_probe/openssl_probe.c` documents an aarch64 constructor hang before `main`, which is a hard blocker for serious shared-lib userspace.
- Need full Linux-style loader/runtime behavior on both arches, not “works for small hand-picked binaries”.

### 2.4 Namespaces

- `crates/kernel/syscalls/src/272_unshare.rs` still says only parts are truly isolated; several `CLONE_NEW*` cases mainly allocate ids / membership bits.
- Need real mount/user/pid/net/ipc/cgroup namespace behavior, not namespace markers without full enforcement.
- `setns` exists (`308_setns.rs`), but namespace semantics must match Linux end-to-end.

### 2.5 Mount / rootfs / root transition

- `pivot_root` exists (`155_pivot_root.rs`), modern mount syscalls exist, but the tree still contains comments about follow-up integration and admit/no-op behavior around mounts.
- Need fully Linux-style mount propagation, mount namespace behavior, root switching, and systemd-compatible mount API semantics.
- Eliminate fake-success or softened behavior in mount paths.

### 2.6 Network control plane

- Data-plane code is large and real, but the control-plane still needs hardening for full Linux CLI compatibility.
- Finish full rtnetlink behavior expected by `iproute2`, `systemd-networkd`, DHCP clients, and related tooling.
- Ensure route/address management is real and persistent, not boot-default-ish behavior.
- Keep AF_PACKET / DHCP / IPv6 / routing behavior Linux-correct.

### 2.7 io_uring

- `425_io_uring_setup` and `426_io_uring_enter` are real.
- `427_io_uring_register.rs` still returns `0` unconditionally.
- Need real Linux registration semantics: fixed buffers, fixed files, ring visibility/mmap behavior, and the missing operational pieces.

### 2.8 ext4 correctness / scale

- ext4 is real, but `crates/kernel/ext4/src/mount.rs` and `extent_rw.rs` still cap supported extent depth.
- Large real rootfs trees will keep stressing ext4 edge cases.
- Need Linux-correct behavior for deeper extent trees, large directories, symlink/path behavior, and broader distro filesystem workloads.

### 2.9 Subsystem init / bring-up consistency

- Some crates still expose skeleton `init()` shims returning `NotImplemented`, even where real functionality exists elsewhere:
  - `crates/kernel/iouring/src/lib.rs`
  - `crates/kernel/net/src/lib.rs`
  - `crates/kernel/tty/src/lib.rs`
- Clean this up so subsystem bring-up is real, coherent, and Linux-like rather than split between live code and stale skeleton entrypoints.

### 2.10 netfilter / nftables enforcement

- `crates/kernel/netfilter/src/lib.rs` is still primarily nfnetlink/nftables storage and message handling.
- Real packet-path enforcement is still missing.
- Need real Linux netfilter behavior in the live RX/TX path, not just userspace-visible rule storage.

### 2.11 BPF / eBPF

- `crates/kernel/security/src/bpf.rs` explicitly leaves real eBPF breadth, full verifier behavior, and JIT as follow-up work.
- Need Linux-grade BPF behavior, not a narrow admit path plus partial map/prog substrate.
- This matters for seccomp-adjacent tooling, tracing, tc/XDP-class behavior, and modern system software.

### 2.12 tracing / tracefs / ftrace / perf

- `crates/kernel/tracefs/src/lib.rs` is still a placeholder tree with static files and empty defaults.
- Need real trace buffers, real tracepoints, real event registration, and Linux-style trace plumbing.
- `perf_event_open` exists, but the perf stack is still much thinner than Linux perf/ftrace/tracepoint behavior.

### 2.13 fanotify / audit-grade observability

- fanotify is still effectively a narrowed compatibility layer over inotify-style storage.
- Need real Linux fanotify semantics, not just enough for probes.
- Audit infrastructure is also underbuilt relative to Linux expectations.

## 3. Graphics/X11 path

### 3.1 Kernel-side substrate mostly exists

- DRM/KMS exists: `crates/drivers/drm/`
- virtio-gpu exists: `crates/drivers/drv-virtio-gpu/`
- fbdev exists: `crates/drivers/fbdev/`
- VT exists: `crates/kernel/vt/`
- evdev exists: `crates/drivers/drv-virtio-input/`

### 3.2 What still blocks real X11 bring-up

- No real X11 userspace stack is present in-tree/vendor flow:
  - no `xorg`
  - no `mesa`
  - no `libX11`
  - no `weston`
- No real `libdrm`-based userspace integration path is visible yet.
- Kernel graphics/input substrate must be hardened enough for real userspace, not just probes.
- Shared-library correctness on `aarch64` must be fixed first; otherwise a real graphics stack will collapse under constructor/TLS/runtime issues.
- Bring up the graphics stack the Linux way: real DRM/libdrm/Xorg or Wayland userspace, not oxide-specific display shims.

## 4. Missing subsystem families not called out in the first pass

### 4.1 USB

- No real USB host stack showed up:
  - no xHCI
  - no EHCI/OHCI/UHCI
  - no HID stack
  - no USB mass-storage stack
- Need the Linux USB model, enumeration, hub/device lifecycle, and driver binding behavior.

### 4.2 ACPI runtime / AML

- No real ACPI runtime + AML interpreter stack is present.
- Need Linux-style ACPI table consumption, AML execution, power-button/runtime device description handling, and firmware-driven platform integration.

### 4.3 KVM / virtualization

- No real KVM / VMX / SVM hypervisor backend is present.
- Need Linux-style virtualization support if QEMU/KVM-class userspace is a goal.

### 4.4 Network and user filesystems

- No real FUSE, NFS, CIFS/SMB, 9p, or virtio-fs subsystem family is present.
- For Linux-class userspace, these need real filesystem semantics, not special-case shims.

### 4.5 Wi-Fi / Bluetooth

- No real cfg80211/mac80211/nl80211-class wireless stack showed up.
- No real Bluetooth HCI stack showed up.
- Need Linux-style wireless and Bluetooth subsystems if the goal is broad Linux hardware/software parity.

### 4.6 Audio

- No ALSA/PCM/mixer/virtio-snd class subsystem family showed up.
- Need real Linux audio stack behavior for desktop-class userland.

### 4.7 Storage plumbing above raw disks

- No real loop-device, device-mapper, md/RAID, dm-crypt/LUKS class stack showed up.
- Need Linux-style block-virtualization and storage-composition layers for real distro behavior.

### 4.8 Full LSM family

- No real SELinux, AppArmor, IMA/EVM, Smack, or TOMOYO class implementation is present.
- Current security work is not yet equivalent to Linux’s full security-module ecosystem.

## 5. Things to remove or stop doing

- Stop relying on probe-only evidence as if it equals full subsystem completion.
- Stop keeping fake-success paths where Linux would do real work.
- Stop accepting oxide-local substitutes for Linux user-visible behavior.
- Stop leaving “follow-up” semantics in code for surfaces that distro userspace already depends on.

## 6. Required implementation rule for every open item

For every item above:

- implement the Linux ABI and Linux behavior
- use upstream-compatible userspace expectations
- preserve normal Linux fd / ioctl / mount / namespace / linker / auth semantics
- do not add oxide-only user-visible extensions as a substitute for missing Linux behavior
- do not ship hacks, fake success, partial stubs, or compatibility theater

## 7. Priority order

1. Real shared-lib runtime on both arches, especially aarch64.
2. Real PID 1 / login / PAM / NSS / shell path.
3. Real namespace + mount + rootfs transition semantics.
4. Real network control-plane behavior.
5. Real io_uring completion.
6. ext4 correctness for real distro rootfs scale.
7. Real netfilter/BPF/tracing/perf/fanotify depth.
8. Then package and boot a real Linux graphics stack (X11 and/or Wayland) on top.
9. Then close the major missing subsystem families: USB, ACPI/AML, KVM, network filesystems, wireless/Bluetooth, audio, storage composition, and full LSMs.
