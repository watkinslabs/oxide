# Handoff — 2026-08-15

The one handoff document. `HANDOVER.md` and `state.md` are removed; their
content is here, whole, so nothing has to be merged out of two files.

`main` = `0a0f89eca`. Working tree clean, no worktrees or branches left open,
no stray QEMU processes. 17 PRs merged this session: #5452 – #5468.

---

## 1. The goal is not met

The goal is a machine a person can **log in to, use a desktop on, and run
normal programs on**.

**No boot has reached a login prompt.** Not this session, not before it.

What changed is that the two deadlocks that were killing every boot are fixed,
so the boot now runs far enough to expose the next layer of problems — and two
missing filesystems landed.

---

## 2. Where the boot actually is

Best observed x86 run: `basic.target`, dbus-broker, systemd-logind, rtkit and
NetworkManager all up at ~5 s, still running at 129 s. Before this session the
same image died at 14 s.

Three things stand between that and a login prompt, in the order they bite.

### 2.1 `serial-getty@ttyS0` restart-loops — the nearest blocker

It starts, then exits **successfully** after exactly 5.000 s, 23 times in one
129 s boot at a metronomic 5.4 s period. Exit status *success* and an interval
that exact together say a timeout is expiring, not an error path being taken.

Nobody has looked at what agetty is actually doing. This is deterministic and
reproducible, which none of the others are.

### 2.2 An intermittent silent wedge at ~3.3–3.6 s

Roughly half of boots. The serial log stops mid-service-startup, nothing more
is printed for the rest of the run, QEMU sits near zero CPU (parked, not
spinning), and a typed serial sysrq gets no answer. **No watchdog fires at
all**, which is worse than a wedge that spins — the soft-lockup and no-progress
watchdogs both fired on the spinning variant.

Measured over 6 boots of one image: silent at 3.58 / 3.29 / 3.5 s; progressed
to 61 / 128 / 149 s.

### 2.3 A `scheduling while atomic` storm

From `sched/src/live/wait_event.rs:143`, `preempt_count=0x201` (one
`local_bh_disable` plus one preempt level), `in_interrupt=1`, `held=[]`.

That empty held-list was the blindness fixed in #5459 — `lock_bh` was the one
acquisition that never joined the held-lock trace. **The fix landed after this
last fired**, so what the trace prints on it is not yet observed.

### What is NOT established

2.2 and 2.3 may be the same fault seen from two sides. Nobody has shown that
either way. Do not assume it.

---

## 3. Next steps, in priority order

**1. The getty restart loop.** Start here: it is the only deterministic one and
the last thing before a login.

```
OXIDE_SERIAL_SHELL=1 tools/boot-smoke-fs.sh x86
```

That gives a root shell in the guest over serial (the harness repaired in
#5465 — see §5). From it: `systemctl status serial-getty@ttyS0`, that unit's
journal, and the tty's state. **Read what agetty does; do not infer it from the
5-second interval.**

**2. Confirm `vfat` reaches the guest's `/proc/filesystems`.** #5464 merged
saying explicitly that this was never observed — only that registering it broke
nothing. One probe through the same harness answers it.

**3. FAT create / delete / rename.** Writing to a file that exists works;
making one does not, so a volume's set of names is still whatever another
system wrote. That is the gap between a readable medium and a usable one, and
every layer beneath it is done and tested.

**4. The Tier-1 desktop rows, none of which exist at all.** Suspend/resume
(`crates/kernel/power/` is poweroff, reset, CAD and kexec only — no S3, no
s2idle, no freeze), `power_supply`, backlight, HD audio.
`scratch/system-compat.md` carries them with evidence.

---

## 4. What merged, and why it mattered

### Two boot deadlocks, root-caused

| Fault | Found by | Result |
|---|---|---|
| The reclaim LRU lock was taken plainly on the page-free path, which also runs in interrupt context — a one-CPU self-deadlock (#5452) | watchdog `kernel_pc` → disassembly → `addr2line -i` | Boot went from dying at 14 s to reaching dbus-broker, NetworkManager, resolved and udevd at 61 s |
| `replace_mm` released the departing address space while holding `mm_pin_lock`, so **every `execve` slept under a spinlock** (#5454) | the held-lock trace added in #5452, which named `task/signals.rs:478` in one line | **29,889 → 0** atomic-schedule reports; `basic.target`, logind and rtkit at 5.3 s |

Two diagnostics made those findable and are permanent: per-frame held-lock
acquisition sites captured through `#[track_caller]` (#5452), and `lock_bh`
sections joining that trace (#5459).

Worth not rebuilding: walking the frame-pointer chain from inside
`preempt_count_add` faulted the guest twice, because RBP is not a frame base in
entry paths.

### Missing Linux features

- **Loop devices** (#5457, #5458) — `NOT FOUND` → `HAVE`. `/dev/loop0..7`,
  `/dev/loop-control`, the `LOOP_*` ioctls, boot-time publication.
  `modprobe@loop.service` now finishes instead of failing.
- **FAT/VFAT** (#5460, #5461, #5462, #5463, #5464, #5466, #5467) —
  `NOT FOUND` → `HAVE`, read **and** write. `mount -t vfat` works; files read,
  write, grow and truncate; every copy of the table is updated; the dirty flag
  is maintained. 117 hosted tests across seven layers, each written against
  `fs/fat/` in the reference tree first.

### Record corrections

- `scratch/system-compat.md` re-ranked around "can a person use this machine"
  (#5455). Its stale SMP P0 was removed — APs have not parked in `cli;hlt`
  since that was replaced by the idle→schedule loop; what is true is duller,
  `SMP ?= 1` in the Makefile. Seven systems a user meets in the first five
  minutes were added as rows. A claim that `simpledrm` was missing was
  **retracted** (#5456).

### One regression, mine

#5448 moved the debug shell to a VT so `serial-getty` could own the serial
line. That broke all three in-guest probe harnesses, which drive that shell
over the serial FIFO — a login prompt was swallowing their commands as
usernames. Fixed in #5465 with an explicit opt-in. Measured both ways:

```
OXIDE_SERIAL_SHELL=0  boot-smoke-fs: FAIL — timeout waiting for proc_uptime after 3 sends
OXIDE_SERIAL_SHELL=1  boot-smoke-fs: PASS — x86 /proc /dev /sys sweep (63 steps) in 212s
```

---

## 5. Do not re-derive these

- **`simpledrm` exists** — `crates/drivers/drv-simplefb/src/driver.rs` registers
  a DRM card named `simpledrm` with a full scanout backend, and `kmain` creates
  its platform device every boot, so `/dev/dri/card0` exists on any machine with
  a boot framebuffer. A grep of that crate's `lib.rs` and `format.rs` finds only
  fbdev and is misleading. This cost a whole lane before it was retracted.
- **The aarch64 target is QEMU `virt` and nothing else.** The GIC driver is
  GICv3-only with its distributor and redistributor addresses compiled in
  (`0x0800_0000` / `0x080A_0000` in `smoke/src/device_map/arm.rs`), and exactly
  three properties are read from the device tree. **A Raspberry Pi needs four
  separate pieces of work**: a GICv2/GIC-400 driver (every Pi 4/5 uses GIC-400),
  FDT-driven device discovery replacing the fixed map, SDHCI/MMC, and BCM GENET
  or RP1 Ethernet. Not polish. `scratch/system-compat.md` has the platform
  section.
- **The spec-lint ratchet is red on untouched `main`** — 55 regressions across
  30+ crates, none from recent lanes. Every push this session used
  `SKIP_LINT_RATCHET=1`. That is a filed `INFRA` row, not a lane failure.
- **`tools/boot-smoke*.sh` need `OXIDE_SERIAL_SHELL=1`** to reach a guest shell.
  They set it themselves now; a new harness must too.

---

## 6. Working discipline that held

- **Every PR carries a positive control**: the defect was reintroduced, the
  tests confirmed RED, then restored GREEN, and the PR body names which and how
  many. Without that a green test proves nothing.
- **Read the reference before writing**, not after. Every FAT layer was built
  against `../oxide/reference/fs/fat/` — the width boundary is `0xFF4` and not
  `0xFFF`, the long-name checksum mismatch falls back to the short name rather
  than failing, the allocator wraps from a hint. The tests encode those
  contracts so they are re-checkable without citing the source.
- **Deviations are rows, not comments.** Four for FAT alone: transactional
  allocation, no create/delete/rename, no code-page translation for 8.3 names,
  `msdos` registered as an alias.
- **One boot per lane, at the end**, after the hosted gate is green. One
  documented exception: the boot-vs-boot A/B that proved the harness
  regression, where nothing cheaper could answer it.
- **One item, one lane, one worktree**, removed on merge.

---

## 7. Open rows worth knowing about

`scratch/known_issues.md` is the ledger; `scratch/system-compat.md` is the
compatibility surface. High-severity rows that are not the boot blockers above:

- A sleeping lock (the PMM page lock) serializes rmap and mapcount
  transitions, so unmap / COW / teardown sleeps under spinlocks. The reference
  takes **no** folio lock on any of those paths.
- Address-space teardown is attached to a refcount drop, so it inherits
  whatever lock context the last drop happens in. The reference splits `mmput`
  (sleeps, process context) from `mmdrop` (atomic-safe), with `mmput_async` for
  callers that cannot sleep.
- `mremap` relocates a mapping by **copying its bytes** where the reference
  relocates its page-table entries, and no lock is held across the operation.
