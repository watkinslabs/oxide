# Firefox performance measurements — 2026-08-06

Stable comparison record for B1871. Both profiles used a clean release x86_64
build under KVM with one vCPU and no `debug-*` features. The harness observed
the graphical Wayland scanout through QMP; UART was control/diagnostic only.
Sampling used 350 non-stopping QMP `info registers` snapshots: 200 during the
valid page load and 150 during the invalid-host load.

`smoke::elf::run_as_task` is the boot task's `sti; hlt` idle anchor. A higher
percentage there means the vCPU had less kernel/userspace work to do.

## Workload constants

- Valid page: `https://one.one.one.one`
- Negative lookup: `http://oxide-no-such-host.invalid`
- Browser: Fedora image `/usr/lib64/firefox`, native Wayland
- Settling delay after GNOME readiness: 30 seconds
- Syscall control: three runs of `dd bs=1 count=200000` through `/dev/zero` to
  `/dev/null` (400,000 read/write syscalls per run)

## Before intrusive reclaim links

Raw profile: `/tmp/oxide-firefox-profile-919482.txt` at measurement time.

| Phase | Idle | User | PMM final-free LRU scan | kalloc region scan | tick yield | park yield |
|---|---:|---:|---:|---:|---:|---:|
| all (350) | 40.29% | 12.57% | 8.57% | 9.14% | 6.29% | 6.29% |
| valid (200) | 27.50% | 16.00% | 3.50% | 13.00% | 11.00% | 5.00% |
| invalid (150) | 57.33% | 8.00% | 15.33% | 4.00% | 0% | 8.00% |

Other all-phase samples: `rdtsc` 3.43%, virtio-blk completion 2.57%,
`counter_ns` 1.71%, syscall entry 0.57%.

## After intrusive reclaim links

Branch state: `B1871-firefox-resolver-lockup`, based on `dd45a1bee`, with the
uncommitted O(1) PMM reclaim-list conversion. Raw profile:
`/tmp/oxide-firefox-profile-924764.txt` at measurement time.

| Phase | Idle | User | PMM final-free LRU scan | kalloc region scan | tick yield | park yield |
|---|---:|---:|---:|---:|---:|---:|
| all (350) | 49.14% | 11.14% | **0%** | 10.29% | 5.43% | 4.29% |
| valid (200) | 26.00% | 14.00% | **0%** | 15.00% | 9.50% | 5.50% |
| invalid (150) | 80.00% | 7.33% | **0%** | 4.00% | 0% | 2.67% |

Other all-phase samples: virtio-blk completion 4.57%, `rdtsc` 4.29%,
`counter_ns` 3.14%. No syscall-entry sample was observed.

Settled pre-Firefox load was `3.12 0.85 0.28` on one vCPU. CPU leaders were
fwupd 13.2%, GNOME Shell 9.6%, systemd 4.4%, ibus-extension-gtk3 3.7%, and
GNOME Software 2.4%.

The syscall control remained Linux-class:

| Run | Real | User | Kernel |
|---|---:|---:|---:|
| 1 | 0.091 s | 0.022 s | 0.064 s |
| 2 | 0.079 s | 0.021 s | 0.057 s |
| 3 | 0.081 s | 0.022 s | 0.058 s |

The graphical framebuffer changed in both browser phases and Firefox remained
alive with its content processes. This run independently reproduced the
resolver defect: the baseline resolve1 D-Bus Ping and final negative-lookup
health check each timed out after 20 seconds while `systemd-resolved` remained
alive/sleeping with status `Processing requests...`.

## Interpretation and next comparison

The PMM scan disappeared completely and all-phase idle increased by 8.85
percentage points. The next measured kernel hotspot is
`kalloc::holes::HoleList::owns_range`: it linearly walks every separately
registered 1 MiB heap-growth region while validating ordinary allocator
operations. The next profile must keep this exact workload and sample counts;
success means that symbol disappears or materially falls without losing the
allocator's ownership/corruption checks.

## After balanced kalloc region index

Raw profile: `/tmp/oxide-firefox-profile-926932.txt` at measurement time.
This release run passed the complete graphical Firefox, valid-DNS,
invalid-DNS, and resolver-health harness.

| Phase | Idle anchor | User | kalloc region lookup | `rdtsc` | `counter_ns` | block completion wait | tick yield | park yield |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| all (350) | 7.71% | 23.43% | **0.57%** | 20.00% | 8.00% | 11.43% | 12.00% | 4.86% |
| valid (200) | 2.00% | 32.50% | **1.00%** | 13.00% | 5.50% | 10.00% | 19.50% | 0.50% |
| invalid (150) | 15.33% | 11.33% | **0%** | 29.33% | 11.33% | 13.33% | 2.00% | 10.67% |

Settled load fell from 3.12 to 2.15. The syscall control was 0.088, 0.078,
and 0.077 seconds real, with 0.056–0.061 seconds kernel time. The former
allocator hotspot fell from 10.29% overall / 15.00% valid-load to 0.57% /
1.00% while preserving every ownership check.

This exposed the next cluster: synchronous virtio-block completion waited by
polling up to 200,000 times, calling `monotonic_ns()` (`rdtsc` plus
`counter_ns`) on each iteration. Combined, those leaf samples accounted for
39.43% overall and 28.50% of valid-load samples. Linux blocks on the request
completion rather than spending a latency-sized fixed spin budget.

## After bounded IRQ bridge plus deadline-backed block sleep

Raw profile: `/tmp/oxide-firefox-profile-945478.txt` at measurement time.
This release run also passed the complete graphical Firefox, valid-DNS,
invalid-DNS, and resolver-health harness.

The first attempt to park immediately never reached the graphical session and
is deliberately excluded from performance results. Oxide currently enters the
synchronous path with IRQs masked; on one vCPU it needs a short local-IRQ
delivery window before parking. The accepted implementation probes only the
used-ring index at most 64 times with IRQs enabled (down from 200,000), performs
no clock conversion inside that loop, then uses the register/recheck wait with
a scheduler-armed five-second deadline.

| Phase | `tick_yield` halt | Idle anchor | Idle-equivalent total | User | kalloc lookup | PMM unlink | `rdtsc` | `counter_ns` | block completion wait |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| all (350) | 83.14% | 3.14% | **86.28%** | 7.14% | 0% | 0% | 0% | 0% | 0% |
| valid (200) | 77.50% | 5.50% | **83.00%** | 10.50% | 0% | 0% | 0% | 0% | 0% |
| invalid (150) | 90.67% | 0% | **90.67%** | 2.67% | 0% | 0% | 0% | 0% | 0% |

`tick_yield` ends in `sti; hlt; cli`; QMP snapshots leave the RIP in that
function while the vCPU is halted. Its dominant percentage is therefore idle
residency, not active scheduler CPU cost. No former memory-manager or block
polling hotspot remained in 350 samples.

Settled pre-Firefox load was `0.98 0.27 0.09`, versus 2.15 after only the
allocator fixes and 3.12 before them. GNOME Shell reported 5.8% CPU versus
8.4% and 9.6%. The syscall control's kernel time remained 0.056–0.057 seconds;
real times were 0.194, 0.121, and 0.079 seconds because the first two runs were
descheduled, not because syscall execution regressed.

## B1872 direct-wait IRQ correctness profiles

These are diagnostic failure profiles, not accepted performance results. They
record the lock cascade exposed when B1872 removed the bounded block polling
bridge and restored Linux-style IRQ-on syscall execution. Each run used the
same clean release x86_64 KVM guest and sampled the live vCPU through QMP. Raw
profiles were written under `/tmp`; the durable results are preserved here.

| Profile | Samples | Dominant exact RIP / symbol | Share | Confirmed conflict |
|---|---:|---|---:|---|
| `1135373` | 200 | `sched::live::ttwu::place_runnable` local runqueue lock | 85.5% | hardirq wake interrupted the same CPU while its runqueue lock was held |
| `1135873` | 200 | `0xffffffff804c3c74`, `ttwu::place_runnable` spin loop | 84.5% | exact reproduction of the local runqueue self-deadlock |
| `1142782` | 350 | `0xffffffff80076c54`, `run_completion_bottom_half` | 87.14% | block softirq interrupted a process holding the virtio inflight lock |
| `1161329` | 200 | `0xffffffff803c5c52`, `NetStack::set_iface_carrier` | 88.5% | NET_RX interrupted NetworkManager while the interface registry was held |
| `1167085` | 200 | `0xffffffff802e29a3`, `NetStack::deliver_tcp_packet_hop` | 87.0% | NET_RX interrupted a socket syscall holding `TcpEntry.conn` |
| `1172375` | 350 | `0xffffffff80523c3e`, boot idle anchor | 87.43% | no CPU hotspot remained; the post-resolver UART control command was not consumed |

The first two runs led to deferred hardirq/softirq wake placement, matching
Linux's wake-list path. The next three identify state shared with bottom halves
and therefore require `spin_lock_bh()` semantics in process context. A run is
accepted only after the full graphical, valid-DNS, invalid-DNS, and resolver
health harness passes; its 350-sample distribution and syscall controls will
be added below for direct comparison.

The `1172375` run reached GNOME at load `0.83`, completed the resolver D-Bus
probe, and measured the 400,000-call control at 0.139, 0.083, and 0.081 seconds
real (0.057--0.058 seconds kernel). It is retained as a failed control-path
run: Firefox never launched, so the 87.43% idle result is evidence that the
previous spinlocks are gone, not an accepted browser-performance result.

The `1178828` run reproduced a page-fault hard lock after graphical startup.
Of 200 QMP samples, 188 (94%) stopped at exact RIP `0xffffffff8070f92f` in
`sync::RwLock::read`, reached by `AddressSpace::find_vma` from the page-fault
path. A VMA writer could schedule while holding the spin-based per-address-
space lock, leaving the only vCPU spinning forever. B1872 replaced that lock
with a scheduler-backed reader/writer semaphore, matching the sleeping
`mmap_lock` contract.

The first release run after that change was `1183324`. GNOME reached ready at
load `0.55 0.14 0.04`; valid-page load changed the framebuffer and passed.
The clean 400,000-syscall control measured:

| Run | Real | User | Kernel | Cost per syscall |
|---|---:|---:|---:|---:|
| 1 | 0.091 s | 0.021 s | 0.059 s | 0.228 us |
| 2 | 0.081 s | 0.021 s | 0.059 s | 0.203 us |
| 3 | 0.081 s | 0.021 s | 0.059 s | 0.203 us |

The original control was 0.825 seconds, or 2.06 us/syscall. The new result is
9.1--10.2 times faster and matches the approximately 0.2 us Linux reference.
The invalid-DNS phase then exposed the next independent lock bug: after about
105 seconds the watchdog reported no reschedule for ten seconds in Firefox
`Socket Thread` tid 5178, last syscall `sendto`. QMP stopped at exact RIP
`0xffffffff802d5ca2` in `RouteTable::lookup_record_in` while acquiring the
IPv4 FIB spinlock. The stack reached it through `NetStack::route_v4_iface_in`
and `xmit_ipv4_l4_with_policy`. This run is diagnostic, not an accepted final
browser profile; it proves the syscall-exit and VMA-lock fixes held while
isolating the remaining invalid-DNS failure to route lookup synchronization.

Run `1192110` tested bottom-half-safe FIB locks plus atomic-context direct-
reclaim gating. GNOME reached graphical readiness, but the settle control
stopped before the browser phase. Its 200-sample failure profile was 79.50%
exact RIP `0xffffffff8043ad5e` in `network_namespace::registry::initial`,
spinning on the global namespace registry lock; another 16.00% sampled the
same acquire loop's compare-exchange instructions. The holder constructed
`Arc` objects and the first `BTreeMap` node while holding the lock, so a
pressure allocation could schedule the only vCPU. The initialization path now
builds all allocating state before its short publication critical section.

Run `1200147` was a deliberately rejected diagnostic experiment: making every
generic `sync::Spinlock` participate in scheduler preemption accounting, as a
Linux spinlock does, exposed existing callers that sleep after/through those
locks. The graphical console repeatedly reported `scheduling while atomic`
with preempt count 2 from virtio-block `park_blk_checked`, pipe-ring blocking
I/O, and `park_yield`; the guest then idled before the debug shell appeared.
The broad change was removed rather than normalizing the count and hiding the
violations. No performance numbers from this run are accepted. Screenshot:
`/tmp/oxide-preempt-boot.png` at measurement time.

Run `1206651` verified that the FIB and namespace-publication lockups were gone:
GNOME reached readiness at settled load `2.67 0.69 0.23`, the valid page loaded
and changed the framebuffer, and the invalid-host phase progressed to its own
independent TCP-table failure. The 400,000-syscall control measured:

| Run | Real | User | Kernel | Kernel cost per syscall |
|---|---:|---:|---:|---:|
| 1 | 0.149 s | 0.022 s | 0.061 s | 0.153 us |
| 2 | 0.119 s | 0.021 s | 0.060 s | 0.150 us |
| 3 | 0.134 s | 0.022 s | 0.060 s | 0.150 us |

The invalid-host phase then reported a ten-second watchdog lockup in Firefox
`Socket Thread` tid 5180, last syscall `connect`. Of its 150 samples, 124
(82.67%) were in the one acquisition loop at `0xffffffff802e2810`--`2820`.
Disassembly maps that loop exactly to `tables.tcp_conns.lock()` in
`deliver_tcp_packet_hop`: a socket syscall could hold the established-
connection table and be interrupted by NET_RX on the same CPU, which then
spun against its interrupted task. This is the inet-hash `spin_lock_bh()`
contract in Linux. The raw profile is
`/tmp/oxide-firefox-profile-1206651.txt` at measurement time. The transport
demux tables now enforce bottom-half exclusion at their lock type boundary;
the next run must pass the complete graphical, valid-DNS, invalid-DNS, and
resolver-health harness before this diagnostic sequence is accepted.

Run `1214714` reached graphical readiness after the transport-table change,
then failed during the 30-second settle window at 65.8 seconds. This was not a
repeat of the TCP-table lock: the console reported `scheduling while atomic`
with `preempt_count=0x101`, `in_interrupt=1`, and `irq_stack=1` from the
sleeping scheduler mutex. The only production scheduler mutex in this path is
RTNL. Source and Linux-reference comparison found virtio-net configuration
refresh running from Oxide's `NET_RX` softirq and calling
`set_iface_carrier()` under RTNL; Linux's `virtnet_config_changed()` instead
schedules `config_work`, whose process-context worker publishes carrier state.
The QMP failure profile was dominated by the framebuffer rendering the
recursive atomic-schedule diagnostics and is therefore not a performance
sample. Raw profile: `/tmp/oxide-firefox-profile-1214714.txt` at measurement
time. Oxide now queues the configuration refresh to its process-context
kworker and retains a pending bit plus process-context timer retry if the
bounded workqueue is full; `NET_RX` only drains receive packets.

Run `1217749` verified that moving carrier refresh to process work eliminated
the RTNL `scheduling while atomic` flood. GNOME reached graphical readiness,
then the guest hard-locked during the settle window before the browser phase.
Of 200 QMP samples, 173 (86.50%) stopped at exact RIP
`0xffffffff80090dd8`, with another 25 (12.50%) on adjacent instructions in
the same acquisition sequence. Kernel disassembly maps the loop to
`MODERN_DEVS.lock()` in `rx_poll_for()`: NET_RX interrupted process context
while it held the global virtio-net device registry and spun against the
interrupted holder. Raw profile:
`/tmp/oxide-firefox-profile-1217749.txt` at measurement time. Both that
device registry and the RX-runtime registry now enforce bottom-half exclusion
at their lock type boundary; hosted verification covers the full guard
lifetime, and the next release run will record the end-to-end result.

Run `1219338` reached GNOME after both virtio-net registries became BH-safe,
then reproduced the earlier scheduler symptom during settle. Its 200-sample
profile placed 174 samples (87.00%) in the CPU-0 runqueue acquisition at
`schedule()` line 228, reached from a file-backed page fault blocked on
virtio-block. Raw profile: `/tmp/oxide-firefox-profile-1219338.txt`. Because
this failure is timing-sensitive and did not identify the prior owner of the
runqueue lock, the next run armed a GDB conditional breakpoint at that
acquisition instead of treating the sampled waiter as the owner.

GDB run `1221095` passed the settle window at load `1.07 0.25 0.08` and
measured the 400,000-syscall control at 0.107, 0.103, and 0.103 seconds real;
kernel time was 0.068, 0.066, and 0.065 seconds (0.163--0.170 us/syscall).
Firefox then stalled during valid-page health without hitting the conditional
runqueue breakpoint. A live GDB stop produced the exact owner stack:
`NET_RX -> rx_drain_softirq -> deliver_rx_in -> mib::bump -> mib::counters`,
spinning at `0xffffffff802d42d2` on the global MIB namespace table. Thus a
process reader of `/proc/net/snmp` (or another process-context counter lookup)
could be interrupted by receive processing on the same CPU. The initial
network namespace now uses immortal direct counter storage—removing the global
BTreeMap lock and Arc clone from every production packet—while dynamic
namespace table access enforces `spin_lock_bh()` semantics.

Run `1227159`, after the MIB fast path, reached graphical readiness but froze
during settle. Its 200-sample profile again isolated the CPU-0 runqueue lock:
169 samples (84.50%) were the inner `spin_relax`, 13 (6.50%) were in
`schedule`, and 10 (5.00%) were its compare-exchange. This instance entered
the scheduler from `BlkState::acquire_turn`, rather than the file-backed fault
seen in `1219338`. Raw profile:
`/tmp/oxide-firefox-profile-1227159.txt`. This is retained as evidence of the
unresolved timing-sensitive scheduler handoff defect, not a performance
result.

GDB run `1227546` passed settle at load `0.39` and measured the clean
400,000-syscall control as follows:

| Run | Real | User | Kernel | Kernel cost per syscall |
|---|---:|---:|---:|---:|
| 1 | 0.096 s | 0.022 s | 0.062 s | 0.155 us |
| 2 | 0.083 s | 0.022 s | 0.060 s | 0.150 us |
| 3 | 0.086 s | 0.022 s | 0.061 s | 0.153 us |

The framebuffer changed for the valid page, but the valid-page health phase
exceeded 20 seconds. At 109.964 seconds Firefox's main thread had accumulated
247,680 `poll` calls / 3,754 seconds reported syscall time, while its Socket
Thread had accumulated 11,259 `sendto` calls / 41 seconds reported syscall
time. These values are diagnostic counters rather than elapsed CPU seconds;
their retry volume is retained for comparison with the next passing run.

The conditional runqueue breakpoint did not fire. A manual live GDB stop
instead found the exact freeze:
`NET_RX -> rx_drain_softirq -> deliver_rx_in -> nf_hook_eval_in -> eval`,
spinning on the global nftables `CHAINS` lock after interrupting a
process-context holder. The nftables state locks now enforce bottom-half
exclusion, and the ordinary no-hook packet path checks an atomic hook mask and
returns without entering nftables state. The next accepted run must show both
the complete browser harness and the post-change retry counts.

Run `1229896`, after the nftables containment fix, reached GNOME at load
`1.62 0.45 0.15`. Its controls were 0.093/0.082/0.082 seconds real and
0.061/0.060/0.060 seconds kernel (0.150--0.153 us/call). No spinlock hotspot
remained in 350 samples: 303 (86.57%) were the idle IRQ-restore anchor. The
invalid-host launcher timed out, but resolver D-Bus, `getent`, and the serial
shell remained responsive. Screenshot inspection then showed the test itself
was insufficient: the valid page was still blank and transferring, and the
invalid screenshot did not prove the invalid URL was selected. Raw profile:
`/tmp/oxide-firefox-profile-1229896.txt`.

Non-profiled run `1230486` produced a nominal harness PASS with controls
0.094/0.084/0.083 seconds real and 0.062/0.061/0.060 seconds kernel. Visual
inspection rejected that PASS: the 20-second valid screenshot was still a
blank `Waiting for one.one.one.one...` page, while the later “invalid” image
was the valid Cloudflare page finally rendered after roughly 35--55 seconds;
no invalid-host tab was visible. The harness now OCR-checks the actual monitor
and launches the invalid hostname in a separate Firefox profile, so an
unrelated later repaint cannot satisfy the test.

Corrected run `1231091` reached GNOME at load `0.60 0.17 0.05` and measured
0.099/0.083/0.083 seconds real, 0.062/0.061/0.061 seconds kernel
(0.153--0.155 us/call). At 109 seconds the valid framebuffer was still blank,
the UART command stream stopped, and the invalid framebuffer remained
bit-identical. The watchdog task dump found Firefox's Socket Thread sleeping
in `poll`, but QMP identified the kernel owner independently: exact RIP
`0xffffffff80185b7f` in `EpItem::queue`, with stack
`TCP receive -> PollSubscribers::notify_mask -> EpItem::queue`. NET_RX had
interrupted process context while the same epitem's queue/state serialization
was held. The epoll wait-queue, epitem-state, and ready-list boundaries now use
IRQ-save locking on both architectures; queue publication precedes mutable
state acquisition; ready capacity is grown when an interest is added so an RX
callback does not allocate.

Retained post-epoll run `1264889` failed before graphical readiness rather
than exercising Firefox. PID 1 reported `Failed to fork off sandboxing
environment for executing generators: Protocol error` at guest time 46.879 s
and `Freezing execution` at 46.894 s. The UART continued to echo all injected
commands but scheduled no shell to execute them. All 200 QMP samples were the
idle boot anchor (`smoke::elf::run_as_task`, RIP `0xffffffff8052675e`), and the
final register snapshot confirmed `HLT=1`; this was task-loss / no-runnable-work
behavior, not a CPU spin. IRQ counts remained live (IRQ4: 21,019; IOAPIC IRR
10 and 20 pending). Raw profile: `/tmp/oxide-firefox-profile-1264889.txt`.
Because this old image failed before the benchmark, it contributes no
throughput result. The next image converts every production runqueue acquisition
outside the scheduler's explicit IRQ-off context-switch handoff to IRQ-save,
matching Linux `raw_spin_rq_lock_irqsave`; this is the candidate correction for
the earlier 84.5% runqueue-spin failure and this runnable-task loss.

Run `1273823`, with the Linux-shaped runqueue IRQ boundary, reached GNOME and
settled at load `0.56 0.15 0.05`. The 400,000-syscall controls were:

| Run | Real | User | Kernel | Kernel cost per syscall |
|---|---:|---:|---:|---:|
| 1 | 0.111 s | 0.023 s | 0.067 s | 0.168 us |
| 2 | 0.105 s | 0.023 s | 0.067 s | 0.168 us |
| 3 | 0.112 s | 0.024 s | 0.069 s | 0.173 us |

The prior runqueue freeze/task-loss signature did not recur, and neither the
epoll nor runqueue spin address appeared in 350 load-window samples. The
profile was 290/350 (82.86%) at the instruction after the idle anchor's
`sti; hlt`; disassembly proves this is a halted CPU, not IRQ-restore work.
The remaining samples were dispersed (no kernel site exceeded 0.86%). Thus
the remaining Firefox latency is not CPU saturation, syscall-tail overhead,
or a hidden lock spin.

The valid window painted but remained blank at 20 seconds with Firefox showing
`Transferring data from one.one.one.one...`. During that window `/proc/net/snmp`
reported 24,979 IPv4 receives / 24,885 TCP segments and six established TCP
connections, an unexpectedly large receive volume for a page that had not
rendered. The invalid-host launcher created PID 1427 but the graphical screen
remained byte-identical after 15 more seconds. Resolver, D-Bus, the serial
shell, and the kernel stayed responsive. Raw profile:
`/tmp/oxide-firefox-profile-1273823.txt`. The next diagnostic run adds a small
HTTPS timing control, uses the same explicit Firefox profile for both URLs,
and captures QEMU `net0` packets so duplicate/retransmission/ACK behavior can
be compared directly.

PCAP attempt `1275108` reached GNOME but lost the UART control task during the
30-second settle, before either the HTTPS control or Firefox ran. This time the
retained profile was not idle: 171/200 samples (85.50%) were the runqueue
spin-relax hook load, 15/200 (7.50%) the runqueue compare-exchange, and 9/200
(4.50%) `schedule` itself. The frozen task's stack entered `schedule` from
`BlkState::wait_for_completion` during an ext4 `read_byte_range`. Exact spin
RIPs were `0xffffffff804baa33` / `0xffffffff804baa2b`.

The root cause is in the scheduler handoff, not virtio-block: the runqueue lock
is deliberately held across `Context::switch` and released by the incoming
task's `finish_task_switch`. The code already anticipated an incoming task
reaching another `schedule()` before that tail hook, but its recovery called
only `finish_switched_from` (clearing `on_cpu`) and did not release the
forgotten runqueue guard. The new recovery consumes the non-null
`switched_from` handoff token, clears ownership, and releases that exact guard
before the incoming task can add a new scheduling debt; duplicate tails become
no-ops. A regression test retains a real runqueue guard, proves it cannot be
acquired, completes the pending handoff, proves the guard is acquirable, and
proves the token cannot be consumed twice.

Post-handoff-fix run `1282905` passed the complete corrected graphical harness.
GNOME settled at load `1.19 0.34 0.11`; the controls were:

| Run | Real | User | Kernel | Kernel cost per syscall |
|---|---:|---:|---:|---:|
| 1 | 0.096 s | 0.022 s | 0.062 s | 0.155 us |
| 2 | 0.082 s | 0.022 s | 0.060 s | 0.150 us |
| 3 | 0.083 s | 0.022 s | 0.060 s | 0.150 us |

The new transport control fetched `https://one.one.one.one/cdn-cgi/trace`
over DNS + TCP + TLS + HTTP/1.1 in 40.876 ms (205 bytes, HTTP 200), or
67 ms including curl process startup. Firefox rendered the full
one.one.one.one page within the 20-second observation window. Navigating the
same running browser/profile to `oxide-no-such-host.invalid` then painted the
expected `Server Not Found` page with that exact hostname within the 15-second
window. Resolver, D-Bus, UART control, and graphical monitor all remained
responsive.

The 350-sample load profile contained no runqueue/epoll/network lock hotspot.
The largest bucket was the idle anchor (73, 20.86%); the next was another
IRQ-enable/halt boundary (20, 5.71%). Kernel `rep_param` memory copying was
only 4 samples (1.14%); VMA lookup, filesystem, allocation, and Arc operations
were individually at or below 0.57%. Raw profile:
`/tmp/oxide-firefox-profile-1282905.txt`.

Host PCAP `/tmp/oxide-firefox-net-next.pcap` retained 95,113 packets over
101.101 seconds: 47,365 inbound and 47,558 outbound TCP packets, 61,942,680
inbound TCP payload bytes and 308,152 outbound. Sequence-interval analysis
found zero retransmitted/overlapping payload segments and zero advertised
zero-window packets; all 61.94 MB were unique. Traffic arrived in fast bursts
(20.63 MiB during seconds 30--39 and 19.11 MiB during seconds 80--89), ruling
out a steady ~500-packet/s kernel cap. The volume is real browser/desktop
background transfer, not duplicate ACK/sequence behavior.

Non-profiled repeat `1284079` reached GNOME but again lost the control task in
the settle window, before the benchmark. QMP stopped at exact runqueue spin RIP
`0xffffffff804baa53`; the retained frame chain again entered `schedule` from
virtio-block completion wait during an ext4 read. The pending-token recovery
therefore did not close every stale-rq-lock path and the high-priority issue
remains open despite run `1282905` passing. The next reproduction uses a GDB
breakpoint on the failed runqueue CAS itself so lock/token/current-task state is
captured at first contention rather than inferred from a teardown snapshot.

GDB run `1286315` reached GNOME, settled at load `0.74 0.28 0.09`, rendered
the complete one.one.one.one page and then rendered the same-profile invalid
DNS `Server Not Found` page. Its controls were:

| Run | Real | User | Kernel | Kernel cost per syscall |
|---|---:|---:|---:|---:|
| 1 | 0.094 s | 0.022 s | 0.062 s | 0.155 us |
| 2 | 0.082 s | 0.021 s | 0.060 s | 0.150 us |
| 3 | 0.082 s | 0.022 s | 0.060 s | 0.150 us |

The HTTPS control completed DNS + TCP + TLS + HTTP in 33.654 ms (205 bytes,
HTTP 200), or 60 ms including process startup. After invalid-page rendering,
the 10-second watchdog fired on Firefox tid 5188 (`Socket Thread`, last syscall
`recvfrom`). Live GDB stopped at `net::sock::packet::deliver_packet_link_receive`
spinning on `vfs::inode_times::REALTIME_PROVIDER`; the complete stack was
`NET_RX softirq -> virtio-net RX -> packet ingress -> realtime_now_ns ->
Spinlock::lock`. This is a same-CPU interrupt self-deadlock: process context was
interrupted in the provider's lock-sized read window and packet timestamping
tried to acquire the same global lock. The provider is boot-installed and read
from IRQ/softirq context, so the candidate fix publishes its function pointer
with release/acquire atomics and makes every timestamp read lock-free. Raw
profile: `/tmp/oxide-firefox-profile-1286315.txt`; UART/QMP diagnostic log:
`/tmp/oxide-firefox-uart-1286315.log`.

First post-realtime-fix non-profiled run `1305736` reached GNOME, then lost
the UART control task during the 30-second settle before any benchmark or
Firefox launch. QMP retained RIP `0xffffffff804b7d2b`, the failed runqueue
compare-exchange branch in `schedule`, with the same virtio-block wait -> ext4
read frame chain as runs `1275108` and `1284079`. No watchdog banner was needed
to identify it: the CPU was live-spinning with `HLT=0`, the rq base remained in
R14, and IRQ4 had reached 10,819. This independently confirms that removing the
realtime-provider softirq self-deadlock does not close the older rq-lock leak.
The harness now retains R14 memory on failure so the rq lock byte, current task,
idle task, switch count and pending handoff token survive teardown together.
UART/QMP log: `/tmp/oxide-firefox-uart-1305736.log`.

Breakpoint run `1306661` stopped on the first failed rq-lock acquisition and
captured the decisive state before teardown: lock byte `GLOBALS+0x90 = 1`,
current task `+0xa0 = 0xffff800013b0c050`, and pending switch token
`+0xc0 = 0`. The 65-frame GDB stack proved this was not a lost switch token.
An outer `schedule()` held `rq.inner` at `switch.rs:372` while calling
`active_mm_drop`; the final address-space reference destroyed a file-backed
VMA, whose ext4 frame-store destructor synchronously wrote back, submitted a
virtio-block request, and entered a nested `schedule()` that self-spun on the
outer rq guard. The correction now mirrors the scheduler's deferred-mm
handoff: move the lazy-TLB reference to per-rq `prev_mm` under the rq lock,
release the rq lock in the incoming task, then consume/drop `prev_mm` where
blocking destruction is safe. The regression holds a real rq guard, proves the
mm reference remains alive through the critical section, then proves the
post-unlock finish consumes it. This run intentionally stopped before GNOME
readiness and contributes no performance number.

First post-mm-deferral run `1314402` completed every user-visible workload:
GNOME reached load `1.68`; the valid one.one.one.one page was visually ready in
4.930 s; the invalid-name `Server Not Found` page was ready in 2.618 s. Its
controls were:

| Run | Real | User | Kernel | Kernel cost per syscall |
|---|---:|---:|---:|---:|
| 1 | 0.097 s | 0.024 s | 0.061 s | 0.153 us |
| 2 | 0.083 s | 0.022 s | 0.060 s | 0.150 us |
| 3 | 0.082 s | 0.021 s | 0.060 s | 0.150 us |

The HTTPS control completed DNS + TCP + TLS + HTTP in 37.165 ms (204 bytes,
HTTP 200), or 69 ms including process startup. This is performance evidence,
not a clean acceptance pass: deferred address-space destruction ran after the
rq unlock but before the switcher's preemption debt was released, so its valid
nested block reported `[BUG] scheduling while atomic: preempt_count=2` and the
recovery path later exposed a zero count in `park_yield`. The candidate ordering
fix now releases that preemption debt immediately after the rq unlock and only
then consumes `prev_mm`; repeated graphical runs still gate closure.

Clean post-ordering run `1322255` passed the complete harness. GNOME settled at
load `0.59 0.16 0.05`; one.one.one.one was visually ready in 6.145 s and the
same-profile invalid DNS page was ready in 3.872 s. Its controls were:

| Run | Real | User | Kernel | Kernel cost per syscall |
|---|---:|---:|---:|---:|
| 1 | 0.099 s | 0.022 s | 0.063 s | 0.158 us |
| 2 | 0.093 s | 0.023 s | 0.064 s | 0.160 us |
| 3 | 0.090 s | 0.022 s | 0.063 s | 0.158 us |

The HTTPS control completed DNS + TCP + TLS + HTTP in 39.750 ms (205 bytes,
HTTP 200), or 68 ms including process startup. Both OCR assertions passed, the
independent serial control remained responsive, and no watchdog, rq-lock spin,
kernel fault, or scheduling-while-atomic/preemption-count diagnostic appeared.
UART/QMP log: `/tmp/oxide-firefox-uart-1322255.log`.

Repeat `1323037` rendered one.one.one.one in 4.919 s but then failed the
post-render health check and never accepted the invalid URL (`>15 s`, unchanged
screen). Before the freeze, its controls remained fast:

| Run | Real | User | Kernel | Kernel cost per syscall |
|---|---:|---:|---:|---:|
| 1 | 0.101 s | 0.022 s | 0.062 s | 0.155 us |
| 2 | 0.085 s | 0.022 s | 0.061 s | 0.153 us |
| 3 | 0.083 s | 0.022 s | 0.060 s | 0.150 us |

The HTTPS control completed in 34.807 ms (205 bytes, HTTP 200), or 61 ms with
process startup. QMP retained live-spin RIP `0xffffffff80520992`, resolved to
`security::network::evaluate` waiting on the global `HOOKS` spinlock in the
`NET_RX -> nf_hook_eval_in` path. This was another same-CPU process/softirq
recursion: the mutable LSM-like registry used a plain lock even though policy
evaluation runs in NET_RX. The correction gives every registry access Linux
`spin_lock_bh` exclusion, publishes an acquire/release per-operation active mask
so the normal no-hook packet path is lock-free (Linux static-key shape), and
snapshots the active hook so it executes outside the registry lock. UART/QMP
log: `/tmp/oxide-firefox-uart-1323037.log`.

First post-security-registry run `1325347` reached GNOME and completed the
micro-controls, but the foreground `runuser` used to launch Firefox never
returned to the serial shell; the monitor reached only a partial, unreadable
frame and neither page assertion completed (`>20 s` valid, `>15 s` invalid).
Controls before the sleep were:

| Run | Real | User | Kernel | Kernel cost per syscall |
|---|---:|---:|---:|---:|
| 1 | 0.107 s | 0.023 s | 0.065 s | 0.163 us |
| 2 | 0.116 s | 0.022 s | 0.062 s | 0.155 us |
| 3 | 0.105 s | 0.023 s | 0.064 s | 0.160 us |

HTTPS completed in 40.797 ms (205 bytes, HTTP 200), or 58 ms with process
startup. Unlike the preceding lockups, teardown found the CPU in the normal
idle anchor at RIP `0xffffffff80523f4e` (`sti; hlt`), runqueue lock clear,
current equal to idle, null switch token, and 992,791 prior switches. This is
a lost/unissued wakeup rather than a live spin. The serial shell was itself
waiting for the foreground launch process, so the old diagnostics could not
obtain a task dump. The harness now invokes the kernel UART SysRq prefilter
directly on failure to retain task, wait-channel, and per-CPU scheduler state
even without a prompt. UART/QMP log: `/tmp/oxide-firefox-uart-1325347.log`.

Post-security-registry acceptance run `1326672` passed the complete harness.
GNOME settled at load `0.78 0.21 0.07`; one.one.one.one was visually ready in
4.937 s and the invalid DNS page was ready in 1.450 s. Its controls were:

| Run | Real | User | Kernel | Kernel cost per syscall |
|---|---:|---:|---:|---:|
| 1 | 0.103 s | 0.024 s | 0.068 s | 0.170 us |
| 2 | 0.090 s | 0.022 s | 0.060 s | 0.150 us |
| 3 | 0.083 s | 0.022 s | 0.060 s | 0.150 us |

The HTTPS control completed in 42.938 ms (205 bytes, HTTP 200), or 75 ms with
process startup. Both OCR assertions and independent resolver/control checks
passed, with no watchdog, rq spin, kernel fault, or preemption diagnostic.
UART/QMP log: `/tmp/oxide-firefox-uart-1326672.log`.

Acceptance repeat `1327044` rendered one.one.one.one in 3.740 s, then froze
before Firefox accepted the invalid tab (`>15 s`). Its pre-freeze controls were:

| Run | Real | User | Kernel | Kernel cost per syscall |
|---|---:|---:|---:|---:|
| 1 | 0.095 s | 0.022 s | 0.062 s | 0.155 us |
| 2 | 0.084 s | 0.022 s | 0.061 s | 0.153 us |
| 3 | 0.085 s | 0.022 s | 0.062 s | 0.155 us |

HTTPS completed in 39.328 ms (205 bytes, HTTP 200), or 64 ms with process
startup. The watchdog reported zero context switches for 40 s with current tid
5185, Firefox's Socket Thread in `connect`. QMP retained live-spin RIP
`0xffffffff802bdab2`, resolved to `NetStack::try_inet_tables` waiting on the
top-level namespace-to-transport-table registry from `NET_RX -> deliver_raw4`.
The per-protocol tables already used Linux `spin_lock_bh`, but their owning
namespace registry was still a plain lock: process-side `connect` could be
interrupted while holding it and NET_RX then self-spun. The correction puts
that owner registry behind the same `InetTableLock` type as its children, so
all accesses exclude NET_RX consistently. UART/QMP log:
`/tmp/oxide-firefox-uart-1327044.log`.

First post-inet-registry run `1332408` failed during the 30-second GNOME
settle, before the syscall, HTTPS, or Firefox probes ran, so it contributes no
performance number. QMP retained live-spin RIP `0xffffffff80347373`, resolved
to the `v6_addrs` acquisition in `NetStack::ipv6_control_tick` while the
`ktimers` process-context driver ran periodic network control work. The same
IPv6 address table is acquired by NET_RX for local-address and DAD decisions,
but was a plain spinlock; its RA-pending, multicast, and anycast companion
registries had the same process/NET_RX contract defect. All five now use a
shared `StackBhLock` type whose only acquisition applies Linux
`spin_lock_bh()` semantics. UART/QMP log:
`/tmp/oxide-firefox-uart-1332408.log`.

Post-IPv6-control-lock run `1337758` passed the complete harness. GNOME settled
at load `1.64 0.45 0.15`; one.one.one.one was visually ready in 4.944 s and the
same-profile invalid DNS page was ready in 1.465 s. Its controls were:

| Run | Real | User | Kernel | Kernel cost per syscall |
|---|---:|---:|---:|---:|
| 1 | 0.095 s | 0.022 s | 0.063 s | 0.158 us |
| 2 | 0.084 s | 0.022 s | 0.061 s | 0.153 us |
| 3 | 0.086 s | 0.023 s | 0.063 s | 0.158 us |

The HTTPS control completed DNS + TCP + TLS + HTTP in 35.692 ms (204 bytes,
HTTP 200), or 66 ms including process startup. Both OCR assertions and the
independent resolver/control checks passed, with no watchdog, kernel fault, or
preemption diagnostic. UART/QMP log:
`/tmp/oxide-firefox-uart-1337758.log`.

Independent post-fix repeat `1338334` also passed the complete harness. GNOME
settled at load `0.39 0.10 0.03`; one.one.one.one was visually ready in
6.095 s and the same-profile invalid DNS page was ready in 3.854 s. Its
controls were:

| Run | Real | User | Kernel | Kernel cost per syscall |
|---|---:|---:|---:|---:|
| 1 | 0.099 s | 0.023 s | 0.066 s | 0.165 us |
| 2 | 0.099 s | 0.023 s | 0.066 s | 0.165 us |
| 3 | 0.094 s | 0.023 s | 0.064 s | 0.160 us |

The HTTPS control completed DNS + TCP + TLS + HTTP in 44.370 ms (205 bytes,
HTTP 200), or 70 ms including process startup. Both OCR assertions and the
independent resolver/control checks passed, with no watchdog, kernel fault, or
preemption diagnostic. Together with `1337758`, this supplies two consecutive
clean cold-boot acceptance runs after the IPv6 control-state correction. Both
runs used the final direct virtio-block completion wait: no 64-probe IRQ bridge,
no driver-owned polling loop, and process syscall/page-fault work inheriting
IRQs enabled so the one-vCPU completion IRQ can wake the parked task.
UART/QMP log: `/tmp/oxide-firefox-uart-1338334.log`.

## Final verification

- `make build`: PASS for both production release targets.
- `make smoke SMOKE_TIMEOUT=900`: PASS on the first attempt for both targets;
  aarch64 reached userspace in 74 s and x86_64 in 113 s, with serial RX alive.
- Direct-wait regression: PASS; temporarily restoring the 64-probe bridge made
  the regression fail, and restoring the direct park made it pass again.
- x86 process-fault IRQ inheritance regression: PASS; replacing the entry
  `sti` with `nop` made the regression fail, and restoring it made it pass.
- Hosted suites: `drv-virtio-blk` 30/30, `net` 2062/2062, `security` 245/245,
  `sched` 1204/1204, aarch64 HAL 147/147, x86_64 HAL 150/150, and VMM 334/334.
- `make lint-ratchet`: PASS at the 1,731-finding baseline.
- `git diff --check`: PASS.

## Post-own-stack acceptance

The final stack gate exposed one interaction introduced by the bottom-half-safe
locks: process-context `spin_unlock_bh()` drained pending softirqs on the task
stack, while Linux x86_64 and arm64 use `do_softirq_own_stack()` on the per-CPU
IRQ stack. Commit `fe49e882f` adds that architecture stack switch without
skipping or deferring the drain. The production frame/stack gates then passed:
x86_64 syscall entry measured 11,928 B and aarch64 measured 12,992 B against the
13,000 B task-stack ceiling, with no new allowlist entry.

Fresh paired smoke on this exact build passed first attempt: x86_64 reached a
responsive userspace and serial RX in 74 s; aarch64 did so in 121 s.

Post-switch Firefox run `1435376` passed the complete graphical harness. GNOME
settled at load `1.71 0.49 0.17`; one.one.one.one was visually ready in 6.105 s
and the invalid DNS page in 2.679 s. Its syscall controls were:

| Run | Real | User | Kernel | Kernel cost per syscall |
|---|---:|---:|---:|---:|
| 1 | 0.095 s | 0.022 s | 0.062 s | 0.155 us |
| 2 | 0.084 s | 0.022 s | 0.061 s | 0.153 us |
| 3 | 0.083 s | 0.022 s | 0.061 s | 0.153 us |

The HTTPS control completed DNS + TCP + TLS + HTTP in 34.154 ms (204 bytes,
HTTP 200), or 63 ms including process startup. Both OCR assertions and all
resolver/control checks passed. UART/QMP log:
`/tmp/oxide-firefox-uart-1435376.log`.

## B1873 nftables compiled-generation microbenchmark

The durable hosted control measures the packet evaluator itself in a clean
release build: one IPv4 base chain, 64 installed rules, no matching verdict,
then the chain's drop policy. Each run evaluates 100,000 packets. The exact
command is:

`cargo test --release -p netfilter packet_path_benchmark_64_rules -- --ignored --nocapture --test-threads=1`

| Build | Six runs, ns/packet | Median | Change |
|---|---|---:|---:|
| `87f32d9da` before B1873 | 3948, 4229, 4001, 3998, 3908, 3946 | 3973 | baseline |
| B1873 compiled RCU generation | 192, 185, 191, 193, 185, 184 | 188 | **21.1x faster** |

The before path deep-cloned the chain/rule vectors, reparsed each rule's raw
netlink expression payload, cloned the set registry per rule, and entered the
mutable counter store from packet context. B1873 moves all of that work to
control-plane publication. The measured packet path performs an atomic hook
test, one RCU read section, immutable expression walks, and relaxed atomic
counter updates. The committed ignored benchmark is the repeatable comparison
point for later netfilter changes.

## B1873 Firefox namespace-owner acceptance

Pre-fix run `1540519` rendered one.one.one.one in 7.283 s, then the invalid-DNS
probe locked the only vCPU at 83.423 s. GDB stopped the Firefox Socket Thread
inside `network_namespace::registry::lookup_u64`, reached from TCP transmit
through the raw IPv4 delivery/netfilter path. The transport table and ingress
paths were reconstructing a live namespace owner from a numeric ID on packet
delivery. The corrected ownership shape carries a concrete namespace owner
from sockets and devices into per-namespace state; packet delivery upgrades its
non-owning link and never enters the numeric namespace registry. The reverse
link is weak, so transport state cannot pin a destroyed namespace.

Profiled run `1578707` passed both graphical OCR assertions, resolver health,
and the HTTPS control. Its 350 samples found no registry lookup loop: the
invalid-DNS window was 55.33% the expected idle `sti; hlt` loop, 6.67% IRQ-state
restore, and every other symbol at or below 1.33%. The syscall controls measured
0.170–0.175 us kernel time per call; HTTPS completed in 42.075 ms. Saved output:
`/tmp/b1873-firefox-final-profile.log`, UART
`/tmp/oxide-firefox-uart-1578707.log`, profile
`/tmp/oxide-firefox-profile-1578707.txt`.

Unprofiled merge-candidate run `1909894` passed on the exact final release
kernel after the adjacent IGMP/MLD receive paths were also converted to carried
ingress ownership. GNOME settled at load `0.55 0.15 0.05` on one vCPU:

| Probe | Result |
|---|---:|
| one.one.one.one visually ready | 4.960 s |
| invalid-DNS error visually ready | 2.700 s |
| syscall control, run 1 | 0.150 us kernel/call |
| syscall control, run 2 | 0.150 us kernel/call |
| syscall control, run 3 | 0.150 us kernel/call |
| HTTPS DNS + TCP + TLS + HTTP | 54.182 ms, HTTP 200, 203 bytes |

Saved output: `/tmp/b1873-firefox-exact-final.log` and UART
`/tmp/oxide-firefox-uart-1909894.log`. Both final runs completed without a
watchdog, fault, resolver/control loss, or stalled invalid-host request.

## B1878 post-merge intermittent journal EIO

All runs used merge `5d637d985`, a clean release x86_64 build, KVM, and one
vCPU. Kernel cost divides reported system time by 400,000 read/write syscalls.

| Run | Result | Kernel us/call | HTTPS | Valid page | Invalid DNS |
|---|---|---:|---:|---:|---:|
| `2746116` | FAIL: blank Firefox window; repeated journal-create `EIO` | 0.158--0.173 | 58.593 ms | >20 s | unreadable |
| `2750629` | PASS | 0.155 | 37.201 ms | 4.936 s | 2.681 s |
| `2752392` | PASS | 0.153--0.170 | 43.971 ms | 4.954 s | 2.665 s |
| `2752865` | PASS; curl transport timeout | 0.153--0.155 | >30 s | 4.950 s | 4.038 s |
| `2753976` | PASS; QMP RIP profile | 0.155--0.158 | 34.042 ms | complete in 20 s sample | complete in 15 s sample |
| `2755218` | PASS; first real UART capture | 0.153--0.158 | 111.842 ms | 4.974 s | 1.472 s |
| `2768474` | PASS; deferred-I/O fix | 0.155--0.158 | 32.622 ms | 4.950 s | 1.465 s |
| `2769008` | PASS; deferred-I/O fix repeat | 0.155 | 48.959 ms | 6.130 s | 1.469 s |
| `2771882` | PASS; reporter build | 0.153--0.155 | 32.923 ms | 4.935 s | 2.643 s |

Profile `2753976` retained 350 non-stopping samples. The valid window had no
dominant active kernel symbol: IRQ-state restore was 10.50%, boot idle anchor
3.00%, user mode 12.00%, and every other kernel symbol at or below 2.00%.
The invalid-DNS window was 38.67% in the `sti; hlt` boot idle anchor, 15.33%
across IRQ-state restore instances, 10.67% user mode, and every other symbol
at or below 2.00%. No earlier PMM scan, allocator region scan, block polling,
namespace lookup, or network lock spin reappeared.

The original 2.06 us/call uniform syscall tax remains eliminated: every
current run measured 0.153--0.173 us/call. One journal-create EIO/blank launch
and one independent curl timeout show remaining
intermittent filesystem or transport correctness, not a uniform CPU hotspot.
The EIO remains open until reproduced with its exact ext4 error source and
fixed; passing repeats do not retire it.

Commit `71736c892` closes one independent storage stall found in this pass.
An async request queued while a synchronous virtio-blk owner held the queue
had no completion that could restart deferred dispatch; releasing the owner
only woke another owner, which could not acquire while `deferred` remained
nonempty. Release now reruns queued dispatch before waking the next owner.
The exact regression fails when that call is removed and passes when restored;
the driver suite passes 31/31 and the three post-fix browser boots above pass.

Commit `2d2807f94` makes the harness's UART artifact truthful: bytes consumed
from the serial socket go to `oxide-firefox-uart-<run>.log`, while build/QEMU
stdout has a separate `oxide-firefox-qemu-<run>.log`. Commit `3ad95d4d9` routes
mkdir/create/tmpfile backend failures through ext4's canonical filesystem-error
owner; `debug-boot` emits an allocation-free stable error kind for
structural/device failures. Its injected create-I/O positive control reports exactly once;
bypassing the owner makes the test fail with zero reports.
