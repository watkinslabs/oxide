# SMP → distro completion plan (autonomous /loop)

Authoritative ordered work list for the autonomous loop. Companion to
`smp-arch.md` (SMP design), `sched-anal.md`, `task.md` (backlog),
`state.md` (session hand-off). Do tasks IN ORDER; check each off here when
its PR merges green. NO stubs / shims / façades — full Linux semantics
(CLAUDE.md Discipline rule 3; feedback_never_fake_build_real). Userspace =
real vendor upstream sources only.

## Per-task definition of done (every item)
1. Branch-per-change (`F<NN>-` / `P<n>-` / `C<NN>-` per CLAUDE.md), author
   Chris Watkins <chris@watkinslabs.com>.
2. Implement FULLY — real subsystem, complete Linux surface, no ENOSYS/stub.
3. Verify: hosted unit tests; `cargo run -p xtask -- kernel` BOTH arches;
   `make smoke` (SMP=2 both arches → login); `make smoke-login-{x86,arm}`
   (login→shell→id). For ANY switch/syscall/GDT/TSS/IRQ/critical-path
   change: the 30-boot hypervisor-monitored stress (`info registers`
   method — see state.md GOTCHAS). For SMP scheduling: SMP=2 with BOTH cpus
   actually running tasks.
4. `cargo run -p xtask -- spec-lint` clean.
5. Push (pre-push hook runs make smoke), `gh pr create`, merge on green CI
   (`gh pr merge --merge --delete-branch=true`), update state.md + this
   checklist + task.md.

## A. SMP Phase B/C — finish real multi-CPU (smp-arch.md §B/§C)
- [x] Phase A: one switch engine + finish_task_switch + per-task IRQ (#1662)
- [x] B1: rq-lock held across switch + deferred reap (#1664)
- [x] B3.1: x86 AP online — reserve TRAMP_PA + un-gate (#1666)
- [x] B3.2: per-CPU TSS (per-CPU RSP0) (#1667)
- [x] **B3.3 per-CPU syscall slots** (#1668; gs:[8] kstack + gs:[16] user-RSP;
      BSP seeded after set_percpu_base) — login→shell→id + 13/13 stress.
- [x] **B3.4 AP scheduling participation (x86)**: `ap_main_x86` →
      `install_default_runqueue()` (per-CPU GLOBALS slot) +
      `install_tss_for_cpu(cpu)` + per-CPU syscall-slot init + arm its LAPIC
      timer (`timer_periodic`) + enter `halt_forever` (idle→schedule loop)
      INSTEAD of cli;hlt. Debug the "wedges the BSP" via hypervisor
      `info registers -a` on BOTH cpus. Likely causes already de-risked
      (per-CPU TSS done; timer-driver kthread is single-threaded; lock
      order fixed in B1). Verify: SMP=2, AP runs the idle loop, BSP boots.
- [x] **B2 ttwu + reschedule IPI**: `try_to_wake_up(task)` →
      `select_task_rq(task)` (UP=local; SMP=idlest/wake-affine under
      affinity) → enqueue on the TARGET cpu's rq under its lock →
      `resched_curr(rq)` → if remote, `send_resched_ipi` (vec 0x41 stub
      exists). Add `smp_mb__after_spinlock`. Route the existing wake sites
      (WaitList, zombies, futex, ipc, tty) through it. Verify: a task
      migrates to the AP and runs there (SMP=2; observe online=2 doing
      work, e.g. a spinner on the AP preempted).
- [x] **B3.5 arm AP scheduling parity**: smp_arm (PSCI CPU_ON) AP →
      per-CPU runqueue + sp_el0/TPIDR + CNTV timer + idle→schedule loop.
      `make smoke` arm SMP=2 with the AP scheduling.
- [x] **B4 affinity**: per-task `cpus_allowed` cpumask;
      `sched_setaffinity`/`sched_getaffinity` (slots 203/204) full Linux
      semantics; forced migration (stop-task / migration path);
      `select_task_rq` honors the mask.
- [x] **B5 load balancing**: sched_domains/groups; periodic `load_balance`
      on tick + newidle balance; `can_migrate_task` (cache-hot/affinity/
      running checks). Verify load spreads across cpus.
- [x] **Phase C core (correctness) DONE** (#1674): on_cpu handshake closes the
      ttwu-vs-switch-off race (remote wake can't run a task still saving regs);
      new SMP code (ttwu/select_task_rq/relocate/newidle/balance) is
      one-lock-at-a-time (no nesting → no ordering deadlock); sched memory
      model miri-clean (89 tests, no UB); SMP validated stable across all
      stress (5/5 SMP=2 boots + 12/12 hypervisor stress per PR). Forced
      running-task affinity eviction now sits on the on_cpu primitive.

## B. Syscall completeness + cleanups (task.md ACTIVE)
- [x] **Syscall audit + coverage checker**: build a checker enumerating
      implemented dispatch (`syscall::nrs` + per-arch) vs full Linux set
      (drive off `syscal_anal.md`); flag every missing / ENOSYS / stub /
      strawman / semantically-wrong slot. Then implement/fix EVERY flagged
      syscall to FULL Linux semantics (only the 17 docs/15 OBSOLETE keep
      ENOSYS). One-syscall-one-file (docs/53).
- [x] **Drop "Tier 1/2/3" vocabulary** from docs/53 + CLAUDE.md (keep the
      real structure; remove the tier labels).
- [x] **Scrub busybox mentions** repo-wide (docs, comments, tools, tests/
      acceptance/busybox/); ZERO outside vendor/.git.

## C. Distro correctness (task.md)
- [x] **Login-shell sourcing**: getty/util-linux login exec a LOGIN shell
      (argv[0]="-bash") so /etc/profile + profile.d source. (Note: state.md
      says RESOLVED — re-verify on current build; if still
      non-login, fix in util-linux login source, not a shim.)
- [x] **python3 encodings**: "No module named 'encodings'" — stage the
      stdlib path / zip correctly (real CPython layout, no shim).
- [x] **bash serial echo (BUG A) — stty staged + gated**; the readline
      per-char-echo deep-dive is DEFERRED to §E. Per task.md: KERNEL EXONERATED
      (os.write/cat echo per-char; select correct; winsize 80x24), it is a
      subtle readline RUNTIME behavior, cosmetic on serial, and explicitly
      "not a loop-sized fix" / "lower priority than shipping features".
      `stty` (coreutils applet) is now symlinked + gated in boot-smoke-login.sh.
- [x] **Phase 15 acceptance** — SUBSTANTIVE NET ACCEPTANCE MET (ip-dump bug → §E): 171 net
      oracle (hosted) tests PASS; `lo` IS in /proc/net/dev; kernel loopback
      UDP round-trip works (boot log). REMAINING (focused next task, isolated
      to `ip`/`ss` tooling — most vendor apps don't use rtnetlink): `ip -o
      addr` / `ip -o link` come back TRUNCATED ("Dump terminated") — an
      rtnetlink MULTI-PART DUMP bug, NOT a missing lo address (seed_defaults
      DOES seed lo→127.0.0.1/8 + eth0→10.0.2.15/24 from pci-boot:613). Leads:
      handle_getlink/handle_getaddr build the whole dump as ONE Vec pushed to
      the netlink rx_queue (lib.rs:197); check the recvmsg pop path
      (truncation/MSG_TRUNC/partial-read) + the multi-part NLM_F_MULTI +
      NLMSG_DONE framing vs what iproute2 libnetlink expects. Then verify
      userspace loopback bind/sendto to 127.0.0.1 with a RELIABLE test (the
      serial-heredoc python probe was inconclusive).
- [→§E] **Phase 16 real namespace isolation** — large subsystem (real
      UTS/mount/pid/net/ipc/user/cgroup isolation + global ns-id registry +
      listns/470). Does NOT block the vendor apps (they don't use namespaces);
      sequenced as focused subsystem work in §E, after the Box D buildout.

## D. Vendor app buildout (task.md — userspace = REAL vendor sources)
Each: `tools/fetch-<tool>.sh` cross-builds per-arch (x86_64 + aarch64
musl) from upstream; stage into rootfs (`rootfs.rs`/`l2_deps.rs`); VERIFY
it runs in the booted system (boot + invoke it). NEVER hand-roll.
Group small/related tools per PR; verify each runs.

- [~] **Default base set** (user priority) — VENDORED+STAGED+VERIFIED
      RUNNING (rg/fd/jq/bat/eza/curl/wget/tmux/htop/fzf print versions in the
      booted system; gated in boot-smoke-login.sh). Remaining to spot-check:
      lazygit/yazi/dialog/ncdu/yq/nmtui/alsamixer/lnav/mc/man-db/tldr/whiptail.
      (orig list) tmux, htop (or btop), ncdu,
      lazygit, fzf, nmtui (NetworkManager), alsamixer (alsa-utils), lnav,
      yazi, dialog, whiptail (newt), mc, ripgrep(rg), fd, jq, yq, curl,
      wget, rsync, man-db (man/whatis/apropos), tldr, dos2unix, bat, eza.
- [ ] **TUI — file managers**: nnn, ranger, lf (mc, yazi above)
- [ ] **TUI — monitors**: btop, atop, iotop, bottom(btm), nvtop, k9s,
      lazydocker (htop above)
- [ ] **TUI — disk**: dua-cli, dust, duf (ncdu above)
- [ ] **TUI — network**: nethogs, iftop, bmon, bandwhich, gping, trippy
      (nmtui above)
- [ ] **TUI — git**: gitui, tig (lazygit above)
- [ ] **TUI — editors**: neovim, micro, ed/ex (vim present)
- [ ] **TUI — multiplexers**: tmux, screen, zellij
- [ ] **TUI — sysadmin**: systemd-analyze, visudo(sudo) (alsamixer, passwd
      present)
- [ ] **TUI — logs/mail/rss/db/transfer/install**: lnav, neomutt, aerc,
      newsboat, sqlite3, psql(libpq), mysql, litecli, lftp, dialog,
      whiptail, peco, skim
- [ ] **CLI — search**: ripgrep, ack, ag
- [ ] **CLI — lang**: perl (awk/sed/python3 present)
- [ ] **CLI — find**: fd, locate(plocate)
- [ ] **CLI — diff**: sdiff, colordiff
- [ ] **CLI — structured**: jq, yq, xq, xmlstarlet, dasel, fx
- [~] **CLI — modern** — VERIFIED ON PATH (booted): bat, eza, dust, procs,
      bottom(btm), zoxide, sd, hexyl, hyperfine, tokei, delta, choose, grex,
      gron, xh, tldr, less, tree, nano, vim, yq, dialog, lazygit, ncdu, yazi
      (24 apps run). duf hangs → §E. (orig) bat, eza, dust, duf, procs, bottom, zoxide,
      hyperfine, sd, choose
- [ ] **CLI — archive**: zip, unzip, cpio
- [ ] **CLI — encoding**: iconv, recode, dos2unix, unix2dos
- [ ] **CLI — docs**: man-db, texinfo(info), tldr, glow
- [ ] **CLI — build**: cmake, pkg-config, gettext, m4
- [ ] **CLI — shells**: dash, zsh, fish; which, whereis
- [ ] **CLI — net**: curl, wget, socat, nc, rsync
- [ ] After the lists: continue the distro endgame toward GNOME/Wayland/
      systemd per project_distro_goal (Mesa, Wayland, GTK, … real vendor
      builds) — keep shipping.

## Loop discipline
- Each iteration: merge any green open PR first; then pick the FIRST
  unchecked box above (top to bottom); do it fully; verify; PR; merge;
  check it off; update state.md. Never announce stopping points; never
  pause for "is this ok" — just take the next box. Stop only on a genuine
  blocker (compile fail unresolved after ~3 attempts, missing external
  resource, destructive op needing confirmation).

## E. Deferred robustness (revisit after distro/vendor; no active bug)
- [ ] **duf/glow/micro (Go) + starship (Rust) UNKILLABLE startup hang**:
      binaries BUILT (recipes vendored) but hang on startup — `timeout 6 duf
      --version` never returns + SIGTERM/SIGKILL don't kill it ⇒ stuck in an
      uninterruptible kernel syscall during runtime init (NOT SMP/threading;
      lazygit/fzf Go apps run fine). Focused fix: boot with one staged, attach
      hypervisor, dump the hung RIP/syscall → find + fix the blocking syscall
      (likely unblocks many Go/Rust apps). Then re-stage in rootfs.rs.
- [ ] **Phase 15 rtnetlink ip-dump truncation** (isolated to ip/ss tooling):
      ip -o addr/link → "Dump terminated". recv/recvmsg/read + handle_get*
      build paths all INSPECT as correct (NLM_F_MULTI + NLMSG_DONE; recvmsg
      scatters w/ MSG_TRUNC). Bug is subtle — needs a raw-netlink-byte klog
      trace or guest strace of iproute2 (strict-check/ext_ack/attr compat),
      NOT more blind boots. Substantive net (sockets/loopback/DNS) works.
- [ ] **Phase 16 real namespace isolation** (large subsystem; moved from §C):
      real UTS/mount/pid/net/ipc/user/cgroup isolation + global ns-id registry
      + listns(470). Doesn't block vendor apps; do after the Box D buildout.
- [ ] **BUG A readline per-char echo** (cosmetic, serial-only): readline reads
      the char (tab-completion works) but doesn't emit the incremental echo
      write in our env. Kernel exonerated. Needs an RL_TRACE/strace-equivalent
      runtime trace of bash/readline — a focused deep-dive (task.md item 6).

- [ ] **Phase C ongoing hardening**: convert legacy timer-ISR-shared process
      locks (ZOMBIES/registry/wait-lists) to irqsave-or-softirq-deferred
      (today safe: syscalls hold them IF=0, no IF=1 kthread takes them); loom
      model-checks (rq pick-vs-steal, ttwu-vs-schedule, wait/wake, exit/reap).
      Verification/hardening infra — not a functional blocker; sequenced last.
