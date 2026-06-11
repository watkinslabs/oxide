# state — session hand-off

Branch: main @ post-#1759. Both arches boot SMP=2 → login. Per-fd poll/select
is the Linux `->poll` model (no global POLL_WAIT). /proc is being built out the
Linux way over real kernel state (no fakes; absent subsystems omitted).

## Landed this session (procfs Linux-way buildout, all merged, both arches green)
- **#1758 (B102): real /proc/interrupts.** New `arch-irq::irqstat` — per-CPU
  LOC (local timer), RES (resched IPI), device-line (MSI/SPI) counters, fed by
  the IRQ dispatcher (lapic.rs x86 timer/resched/MSI; gic.rs arm CNTV timer +
  GICv2m SPI lines). `procfs::interrupts` renders Linux `show_interrupts`:
  one column per online CPU, fired device rows, LOC/RES summary rows.
- **#1759 (B103): real /proc/uptime idle + /proc/devices.** uptime field 2 was
  a copy of field 1 → now all-CPU summed idle from `sched::cpustat` (CLK_TCK=100,
  1 idle tick = 1 cs). devices block section derives majors live from the block
  registry snapshot (dedup, Linux driver names); char section = fixed
  kernel-created set (real majors).
- **R82: real /proc/buddyinfo.** Added `Pmm::free_orders() -> [u64; ORDERS]`
  read-only per-order free-block snapshot (docs/10 R01 revision on FROZEN spec);
  `procfs::buddyinfo` renders the single Normal zone's per-order counts (Linux
  `frag_show`). docs/19 R01 note extended to list the newly-backed rows.

## Earlier this session (already merged before #1758)
- B96 rebuilt poll/select as per-fd `PollWaiter`+`PollSubscribers` (killed the
  global POLL_WAIT hack the user rejected). B97/B100 per-CPU cputime accounting
  on EVERY cpu (was BSP-only → htop/proc showed 1 active CPU). B98 loadavg EWMA.
  B99/B101 cpuinfo/vmstat/partitions/diskstats real. R80 VT alt-screen+ECH.
  R81 block per-disk DiskStats decorator. docs 17§3a/19§60/49§5 R01 amended.

## /proc status: what's REAL vs deliberately-stub
REAL now: cpuinfo, stat (per-cpu cpu0..N + ctxt), loadavg, vmstat, meminfo,
uptime (+idle), partitions, diskstats, interrupts, devices, buddyinfo, per-PID tree
(status/stat/maps/smaps/statm/cmdline/comm/environ/io/limits/sched/fd/fdinfo/
ns/cgroup/mounts/mountinfo + task/ + net/).
STILL STUB — each blocked on a discipline boundary, NOT laziness:
- softirqs — needs per-CPU per-slot counters in the `softirq` crate, whose spec
  (docs/45) is DRAFT → can't extend subsystem code (Discipline rule 1).
- zoneinfo — needs the broader per-zone watermark/stat set; lower value, still
  stubbed. (buddyinfo now REAL via R82 `free_orders()`.)
- modules — `modules::module_name` is a hardcoded "module" stub → rendering
  would emit FAKE names; empty (nothing loaded) is the honest state.
- kallsyms — needs a real symbol table; faking it is worse than empty.
- per-PID auxv (zeroed), wchan ("0"), schedstat — auxv needs a per-task
  saved_auxv field in the FROZEN task struct (R-branch); wchan needs kallsyms.

## Verification note
New /proc inodes validated by construction: `/proc/interrupts` reuses the SAME
`cpu::smp::online_count()` column loop as `/proc/stat`, which the user already
confirmed renders cpu0–cpu3 correctly. Build + spec-lint + pre-push boot-smoke
(both arches → login) all green. NOT content-captured in a boot: the rcS/
oxide-smokes path doesn't run under the default systemd PID1 boot, so a /proc
dump there wouldn't execute; a qemu-MCP login+cat (SMP=1, serial DSR-wedges at
SMP≥2) is the route if a live capture is wanted.

## First task next session
Decide direction with the user OR continue per "keep filling it out": the
remaining honest /proc fills all need an R-branch (PMM buddyinfo accessor; task
saved_auxv) or DRAFT-spec lift (softirq per-cpu counters). If continuing
autonomously, the cleanest is buddyinfo via an R-branch on docs/10 adding a
read-only `pmm::free_orders() -> [u64; ORDERS]` accessor + procfs buddyinfo
inode. Untracked `abstract-anal.md` at repo root is a prior-session scratch
artifact (asm-outside-arch inventory) — not mine, left in tree.
