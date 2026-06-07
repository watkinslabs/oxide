# Tasks

Living work list. See state.md for the session hand-off + boot-verify recipes.

## ACTIVE — user-reported blockers (top priority)
- [ ] **BUG A — bash echo on serial** (KERNEL EXONERATED; userspace/readline):
      typed chars don't echo per-keystroke in bash; appear only on redisplay
      (TAB/Enter). Exhaustively isolated this session — the KERNEL is correct:
      • `os.write(1,c)` in raw mode echoes per-char immediately
      • `cat` cooked-mode (kernel line-discipline) echoes per-char
      • single-byte `printf` appears; idle-tty `select()` correctly = not-readable
      • winsize = 80x24; fails identically under TERM=dumb/vt100/xterm/linux and
        under both `sh` and `bash`.
      By transitivity (os.write proves the write→console→serial path), bash is
      NOT issuing per-char echo `write()`s → it's **readline not emitting the
      incremental echo** in our env. NOT a kernel bug. Next: strace/debug-bash
      to confirm no per-char write(), or inspect the vendored bash/readline build
      config (vendor/bash/build.sh) — readline incremental-redisplay path. Also
      noticed: `stty` is missing from the rootfs (coreutils applet not staged).
      LEAD: vendor/bash/build.sh compiles with `-std=gnu89
      -Wno-implicit-function-declaration -Wno-incompatible-pointer-types` —
      suppressing implicit-function-declaration on a 64-bit musl cross-build is a
      correctness hazard (a fn that really returns a pointer gets truncated to
      int). Likely fix: re-vendor bash with -std=gnu11 + proper headers, NO
      suppression, and resolve the real missing declarations. (userspace rebuild.)
- [x] **Console/GPU — RESOLVED** (verified both arches): the entire kernel-side
      graphical console WORKS — virtio-gpu scanout (1280x800), fbcon glyph
      rendering (screendump: 4480 white glyph px on the FB), klog+/dev/console
      aux-sink output, and virtio-input drain→keymap→push_and_wake_fg(VT0)→getty
      (verified: qemu `sendkey "root\n"` → login responded). The user's blank
      screen was a QEMU-LAUNCH bug, not the kernel: q35 adds a default std-VGA
      that becomes the PRIMARY display, so the GTK window showed that blank VGA
      while the virtio-gpu console was a hidden secondary. FIX: `-vga none` in
      image_qemu.rs (x86) so virtio-gpu is THE display. arm `virt` has no
      default VGA (already correct). Earlier "output gap"/"input gap" diagnoses
      were both wrong — the kernel console was complete all along.
- [x] **Login/profile done properly** — RESOLVED (verified live): the console
      login already execs a LOGIN shell (`$0` = `-sh`) and `/etc/profile` +
      `/etc/profile.d/*.sh` ARE sourced (marker `OXIDE_PROFILE_RAN=1` set after
      `alice` login). The earlier "not sourced" reading was a stale-ISO artifact
      (rebuilt rootfs but not the ISO it embeds). Login env is correct end-to-end
      (PATH, LANG, aliases, prompt, profile.d). util-linux login + agetty +
      profile/skel all from vendor sources, no shims.
- [ ] **Syscall audit + complete coverage**: drive off `syscal_anal.md` (the
      existing syscall analysis) + build a coverage checker that enumerates the
      implemented dispatch (`syscall::nrs` + per-arch dispatch) vs the full Linux
      syscall set, flagging every slot that is missing, `ENOSYS`/stub/strawman,
      or semantically wrong. Then per docs/15 implement or fix EVERY flagged
      syscall to full Linux semantics (only the 17 OBSOLETE numbers keep ENOSYS).
- [ ] **One syscall = one file** (docs/53 §0 spec): split the grouped handler
      files (`crates/kernel/syscalls/src/{fs,net,…}.rs`) into per-syscall
      `<NNN>_<name>.rs` files (x86_64 number + Linux name). Move existing; create
      for missing. FILES, not crates. Fold into the syscall audit work.
- [ ] **Drop "Tier 1/2/3" vocabulary** from docs/53 + CLAUDE.md (user: "there are
      no tiers"). Keep the real structure (ABI types crate / subsystem work fns /
      per-syscall handler files), just remove the tier labels/jargon.

## Policy (user, this session)
- Missing SYSTEMS get built **kernel-side, Linux-style** (real subsystem, not a
  shim/façade — per feedback_never_fake_build_real).
- All USERSPACE comes from **real vendor sources** (bash, coreutils, util-linux,
  systemd, …) — never custom/hand-rolled replacements.

## ACTIVE — busybox removal (in progress)
- [x] busybox functionally gone (vendor binary deleted; rootfs uses real
      coreutils/bash/util-linux/systemd; /bin/busybox absent from image).
- [x] rootfs.rs: deleted the dead busybox install block (was skipped anyway).
- [ ] Scrub ALL remaining "busybox" mentions repo-wide (docs/*.md, kernel
      comments, tools/*.sh, research, CHANGELOG; delete tests/acceptance/busybox/).
      Background agent running; verify ZERO mentions remain outside vendor/.git,
      build + spec-lint clean, then commit. CLAUDE.md handled separately.

## Done — this SMP + distro session (merged)
- [x] **arm SMP=2 FIXED** (#1564): root cause was vmm.rs `ATTR1=1<<3` (AttrIdx 2)
      vs `1<<2` (AttrIdx 1). Under self-boot MAIR=0xFF04, Normal-WB is AttrIdx 1,
      so every demand-faulted user page was mapped Device → first unaligned musl
      read took DFSC=0x21 alignment abort → PID1 SIGSEGV. arm -smp 1 AND 2 boot.
      (Supersedes the long "arm SMP=2 wedge" investigation.)
- [x] boot-smoke gate now runs BOTH arches at -smp 2 (#1566).
- [x] **x86 AP INIT/SIPI bring-up** (#1567): real-mode→long-mode trampoline
      (PAE+LME+NXE) + MADT INIT/SIPI; AP reaches long mode + LAPIC + online.
      GATED OFF pending 2 integration fixes (below).
- [x] Distro /etc profiles + skel (#1569) + locale (#1571): shells, hosts,
      environment, motd, bash.bashrc(+LANG), inputrc, profile.d, skel + root/alice.

## Open — SMP / distro follow-ups
- [ ] **x86 SMP integration** (the 2 gated fixes in bring_up_aps_x86): (1)
      PMM-reserve the trampoline low page (TRAMP_PA=0x8000 copy corrupts live
      RAM); (2) AP scheduling participation (per-CPU runqueue + LAPIC-timer
      preempt + sti idle wedges the BSP boot). Flip `if true { return 0; }`.
- [ ] **Login-shell sourcing**: getty/util-linux-login launches the user shell
      as interactive-NON-login → ~/.bashrc runs but /etc/profile + profile.d do
      not. LANG worked around via /etc/bash.bashrc (#1571). Proper fix: make
      login exec a login shell (argv[0]="-bash").
- [ ] python3 in rootfs: "No module named 'encodings'" (stdlib path / zip).
- [ ] Phase 15 acceptance: loopback nc/ping clean (net bins + 171 oracle tests
      pass, lo in /proc/net/dev) → close Phase 15.
- [ ] Phase 16 real namespace isolation — unshare/setns are id-tracking substrate
      (F100-F107), NOT real isolation. (P16-01 UTS attempt abandoned; do not merge.)
- [ ] More distro standard items / cross-built programs toward the GNOME endgame
      (vendor real musl + distro programs; see project_distro_goal memory).

## Open — deferred / lower priority
- [ ] smoke_rr arm debug-all hang (debug-only; production/debug-boot arm fine).
- [ ] BUG C cgroup ENOTEMPTY on destroy; BUG G getty respawn delay — re-verify on
      current build (may no longer repro, like BUG H which did not).
- [ ] phases 17–35 (docs/00§3): dynamic linker polish, libc/NSS/PAM, system
      manager, RPM, tty+login, io_uring, ptrace, bpf/seccomp — deep feature work.

## Userspace tooling backlog — vendor + install (userspace = REAL vendor sources)
Cross-build each per-arch (x86_64 + aarch64 musl) via a `tools/fetch-<tool>.sh`,
stage into the rootfs (`rootfs.rs`/`l2_deps.rs`). NEVER hand-roll a replacement.

### Already vendored / present (verify staged in rootfs)
- [x] bash, coreutils (cat/tac/head/tail/wc/sort/uniq/cut/paste/tr/tee/split/
      join/comm/nl/fmt/fold/expand/unexpand/pr/base64/od/…), grep, sed,
      gawk(awk), findutils(find/xargs), diffutils(diff/cmp), patch, tar, gzip,
      xz, zstd, bzip2, less, ncurses(tput/clear/reset), util-linux(script/
      hexdump/cal/…), procps-ng(ps/top/watch/free/uptime/pgrep/pkill), shadow
      (passwd), iproute2(ip/ss), iputils(ping), openssh(ssh/scp/sshd), vim/vi
      (+xxd), python3, make, openssl, dbus, expat, pcre2.

### Default base install — vendor NEXT (user's priority set)
- [ ] tmux, htop or btop, ncdu, lazygit, fzf, nmtui (NetworkManager),
      alsamixer (alsa-utils), lnav, yazi, dialog, whiptail (newt), mc,
      ripgrep(rg), fd, jq, yq, curl, wget, rsync, man-db(man/whatis/apropos),
      tldr, dos2unix, bat, eza.

### TUI apps (full list)
- [ ] File managers: mc, nnn, ranger, lf, yazi
- [ ] Monitors: htop, btop, atop, iotop, bottom(btm), k9s, lazydocker
- [ ] Disk: ncdu, dua-cli, dust, duf
- [ ] Network: nethogs, iftop, bmon, nmtui
- [ ] Git: lazygit, tig
- [ ] Editors: vim✓, neovim, micro, ed/ex
- [ ] Multiplexers: tmux, screen, zellij
- [ ] Sysadmin: alsamixer, systemd-analyze, visudo (sudo), passwd✓
- [ ] Logs: lnav, journalctl(systemd✓), less✓
- [ ] Mail: neomutt, aerc          
- [ ] RSS: newsboat
- [ ] DB clients: sqlite3, psql(libpq), mysql, litecli
- [ ] Transfer: lftp, rsync        
- [ ] Install/recovery: dialog, whiptail, fzf, peco, skim

### CLI text-processing (full list)
- [ ] Search: ripgrep(rg), ack, ag(silver-searcher)
- [ ] Lang: perl, awk✓, sed✓, python3✓
- [ ] Find: fd, locate(mlocate/plocate)
- [ ] Diff: sdiff, colordiff
- [ ] Editors: ed, ex
- [ ] Term utils: script✓, scriptreplay, watch✓, tput✓
- [ ] Structured: jq, yq, xq, xmlstarlet, dasel
- [ ] Modern: bat, eza, dust, duf, procs, bottom, zoxide, hyperfine, sd, choose
- [ ] Archive: zip, unzip, cpio (tar/gzip/bzip2/xz/zstd ✓)
- [ ] Encoding: iconv, recode, dos2unix, unix2dos, hexdump✓ (base64/od/xxd ✓)
- [ ] Docs: man-db, texinfo(info), tldr
- [ ] Build: cmake, pkg-config, gettext, m4 (make✓)
- [ ] Shells: dash, zsh, fish (bash✓); which, whereis
- [ ] Net: curl, wget, socat, nc (ssh/scp ✓ via openssh); rsync

## Stale / not-reproducing
- BUG H (rm -rf tmpfs rc=1): does NOT repro (returns 0). Closed.
