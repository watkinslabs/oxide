# Session hand-off — disk-based rootfs + fast IO; vendoring apps

## Landed on main this session
- **Disk-based rootfs (F405/#1612):** userspace runs from real virtio-blk disks (ext4),
  NOT baked into the kernel. x86+arm boot to `oxide login:` from the `oxide-root` disk.
- **virtio-blk multi-sector perf (B63/#1615):** was ~1 round-trip/sector (~0.1 MB/s,
  boot+big binaries crawled). Now 128 KiB bounce + multi-sector submit (4 KiB read 8→1,
  ~256× fewer round-trips). **Boot→login ~16 s.** Both keystones (driver + ext4
  de-singletonization) were adversarially reviewed + bugs fixed before landing.
- **rootfs is a 1 GiB virtio-blk disk** (rootfs.rs count=1024) — grows freely, zero
  kernel cost (read on demand). home-<arch>.img is a separate /home disk.
- **x86_64-musl-g++ C++ toolchain** (fetch-cross.sh; gitignored) — enables C++ apps.
- **x86 HHDM full direct map (B65/B66, #1620/#1622):** MB2 trampoline mapped only 1 GiB
  into HHDM → x86 hung at -m 2G (PMM derefs hhdm+pfn*4096 per seeded page). Now 512 ×
  1 GiB PDPTE pages = phys 0..512 GiB — any standard RAM size. Verified x86 boots to
  login at -m 8G; both arches at -m 2G. Requires PDPE1GB (universal on x86_64).
- **38 tools staged + boot-verified:** rg fd bat eza jq tldr hyperfine dust sd btm procs
  zoxide ncdu htop tree dos2unix curl wget fzf tmux lazygit yq delta choose hexyl rsync
  nano tokei grex xh yazi(+ya) dialog btop dua gron pv entr.

## KEY OPEN ITEM — TUI startup-hang gap (4 tools built+de-staged)
starship, glow, micro, duf are BUILT (recipes in tools/fetch-*.sh + vendor/*/build.sh,
committed; binaries gitignored/local) but **NOT staged** — they HANG on startup under
oxide. Signature: persists with stdin redirected to /dev/null + stdout to a file (so
NOT a tty-read block). **ncurses TUIs work** (htop/ncdu/nano/dialog), **fzf/yq (Go,
non-TUI) work**, but bubbletea/tcell (Go) + crossterm/starship (Rust) HANG — so it's how
those terminal libs probe the terminal/init, not language/tokio/threads. NEXT: boot a
`--features debug-all` kernel, run `starship --version </dev/null`, capture the LAST
syscalls before silence → the blocking syscall (likely a tty ioctl or a /dev/tty open).
Fix the kernel gap, then re-add the 4 to rootfs.rs staging + allowlist their binaries.

## Other follow-ups (not blocking)
- x86 HHDM caps at 512 GiB (one PDPT). >512 GiB RAM would need more PML4 entries.
- 8 GiB boot is slower (seeds 2M pages + 48 MB PageMeta) — fine, just O(RAM) seed cost.

## Backlog (continue — autonomous; prefer NON-bubbletea/tcell tools until the hang is fixed)
- CLI/ncurses (likely work): gron, jq-clones, pv, mtr, ncdu(done), aerc?, neomutt(big),
  man-db (needs gdbm+libpipeline — vendor first), mc (needs glib — vendor first).
- C++ (toolchain ready): lnav (sqlite/pcre/readline).
- Heavy: neovim (libuv/luajit/msgpack/tree-sitter/unibilium/libtermkey/libvterm).
- Defer bubbletea/tcell/crossterm TUIs (gitui, zellij, helix, lazygit-is-already-in…)
  until the startup-hang is fixed.

## Vendoring pattern (PROVEN, parallel sub-agents)
fetch-<tool>.sh + vendor/<tool>/build.sh (static-musl both arches) + vendor/.gitignore
allowlist + rootfs.rs staging tuple. Rust: cargo +crt-static, onig→regex-fancy if onig C
dep. C: --host=<arch>-linux-musl static, ncurses via vendor/ncurses/install-<arch>
(+ -DNCURSES_ENABLE_STDBOOL_H=1; dialog needs a libtinfo=libncursesw shim). C++:
vendor/cross/{x86_64,aarch64}-linux-musl-cross g++ + STATIC -static-libstdc++. Go:
vendor/go/bin/go CGO_ENABLED=0. Orchestrator wires gitignore+rootfs; boot-test; commit.

## Boot-test recipe (x86)
Build: `cargo run -p xtask -- rootfs --arch x86_64 && ... kernel --arch x86_64 --features
debug-boot && ... grub --arch x86_64 --features debug-boot --build-only`. Boot:
qemu-system-x86_64 q35 -enable-kvm -smp 2 **-m 2G** -cdrom target/oxide-x86_64-grub.iso
-boot d + virtio-blk drives serial=oxide-root/oxide-home + `-serial unix:/tmp/x.sock`.
Login alice/swordfish. BIG binaries (8–16 MB) still take a few s to page in even post-fix
— allow generous settle in capture.

## Gotchas
- **Smoke push SSH idle-timeout:** the pre-push smoke holds the SSH connection ~10 min;
  GitHub idle-closes it so the push dies AFTER the hook passes ("Connection closed by
  remote host"). If the smoke PASSED but the branch isn't on origin, re-push the SAME
  commit with `SKIP_SMOKE=1` (already verified). Seen on B63.
- Branch counters: max F=408, B=66. Author Chris Watkins. CI = compile-check (stub-blobs;
  no rootfs blob needed since the embed is gone).

## Resume
```
cd /home/nd/oxide2 && git checkout main && git pull && gh run list --limit 3
```
