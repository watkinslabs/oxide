# Ledger audit — Net/socket, first half (the gap `ledger-audit.md` left)

Doc-only, no boot. Covers the range `scratch/issues.d/ledger-audit.md` explicitly
left unaudited: old `known_issues.md` lines 136-230 (first half of `## Net /
socket`). That file has since folded (35 rows removed by `7cf5371e0`), which
shifted line numbers; the fold's diff hunks confirm **no edits landed inside
old 136-230** (first hunk after the old-135 boundary starts at old line 240),
so the range maps 1:1 onto current `known_issues.md` lines **120-210** with a
flat `-20` offset. Row 210 (`blk_mq_end_request`) is the last row of the gap;
everything from current line 211 onward (`usb_ep_free_request` etc., old lines
231+) was already covered by `ledger-audit.md`'s `231-309` audit — confirmed by
spot-checking those rows independently and getting the same LIVE verdicts
already recorded there. Not repeated here.

Method: same as `ledger-audit.md` — for each `OPEN`/`IN-PROGRESS` row, ran the
command/grep the row itself names or the nearest equivalent against current
`main` (`0e66798e4`, current as of this pass). Recent-merge hints supplied
with the task (B1698 ARP/TTL-0, B1708 TCP IP_OPTIONS, B1709 SO_NO_CHECK,
B1710-1712 TFO, B1665 NET_RX backlog, `net` ungated from `hosted`) mostly land
in the *already-audited* second half of Net/socket (TFO/TTL rows sit at
current lines 230/262, both already STALE/live-noted in `ledger-audit.md`).
Only B1665 and the IP_OPTIONS/B1660/B1708 work touch rows in this gap; noted
per-row below.

## Counts (this pass only)

- STALE: 12
- DUPLICATE: 1
- LIVE: 33
- UNVERIFIABLE: 3 (one covers an 11-row flaky-package table)

## STALE

| Row (opening text) | Evidence |
|---|---|
| `IN-PROGRESS B1660/B1661 \| med \| IP_OPTIONS on transmit and IPv6 sticky extension headers on transmit: validated and readable, never emitted...` | **Partially stale.** IPv4 half fully landed: B1660 merged (`6b4c8dd7d`), TCP IP_OPTIONS also landed since via B1708 (`4684c27be`, "tcp emits ip options"). IPv6 half is still open — `stack_ipv6::tx::xmit_ipv6_l4_with_policy`/`xmit_ipv6_payload_with_policy` (`crates/kernel/net/src/stack_ipv6/tx.rs:134-200`) take no ext-header/opts parameter at all, and no consumer of `sol_ipv6::hdr::Sticky` exists outside its own module (`grep -rln "Sticky::HopOpts" crates/kernel/net/src` → only `sock_opts/sol_ipv6/{state,hdr}.rs` and tests). This residual is the same subject as already-audited row 231 ("IPv6 sticky extension headers stored-only") — don't re-close it twice. |
| `IN-PROGRESS B1662 \| med \| IP/IPv6 options stored-but-unconsumed: ...IP_BIND_ADDRESS_NO_PORT, IP_LOCAL_PORT_RANGE (three allocation sites take the owner, not the socket), router-alert delivery (no fan-out chain)...` | **Partially stale.** `IP_BIND_ADDRESS_NO_PORT`/`IP_LOCAL_PORT_RANGE` ARE now consumed: `net::local_port::defers_port` reads the no-port bit, and `sock.opts.ip.local_port_range()` is threaded into every bind call site (`crates/kernel/net/src/sock/ops.rs:79,116`, `sock/tcp_lifecycle.rs:29,53,55`, `sock_v6.rs:36,171`) — contradicts "stored-but-unconsumed"; matches what row 129 (below, still-open) already documents as consumed-but-phantom-tested. IPv4 router-alert fan-out also now exists: `stack_forward.rs:114-115` calls `router_alert::v4_present`/`v4_deliver`. Still live: anycast (routed to the multicast helper, unchanged) and `IP_CHECKSUM`/`IP_RETOPTS`/`PKTOPTIONS`, all separately tracked by already-audited rows (139 below is the anycast duplicate; `IP_CHECKSUM` is row 261 in the already-audited range, explicitly marked "not a defect"). |
| `OPEN \| low \| recvmmsg batch rules (UIO_MAXIOV clamp removal, pending-error-before-batch, OOB ends the batch) are verified against the reference but have NO test...` | `cargo test -p syscalls --lib mmsg_batch` → **22 passed, 0 failed**. `crates/kernel/syscalls/src/mmsg_batch/tests.rs` covers exactly the three named rules: `the_batch_walks_the_whole_array_and_never_clamps_it` (UIO_MAXIOV), `a_pending_error_precedes_the_batch_except_for_an_error_queue_read`, `urgent_data_ends_the_batch_with_what_it_already_has`. The module was deliberately extracted ungated (`mmsg_batch.rs` header: "the slot file is `#[cfg(target_os = "oxide-kernel")]`... this module isn't") specifically to fix the phantom-test gap the row complains about. |
| `OPEN \| low \| Hosted Spinlock waits are now bounded by a yield, but netdev::tx_dispatch::wait() is still a spin-wait by construction...` | `crates/kernel/net/src/netdev/tx_dispatch.rs:334-343` `TxCompletion::wait` now calls `sync::relax()` in its loop, with a comment citing this exact B1653 scenario ("yields periodically in a hosted build, where 64 waiter threads can otherwise starve the one drainer"). Fixed by `6bed6a10b` "test(net): route the remaining bare tx spins through sync::relax". |
| `OPEN \| low \| sync/hosted (the yield in spin_relax::relax) is opted into per consumer crate. net, sched, slab and klog have it...` | **Partially stale — wrong crate list.** `grep -rl "sync/hosted" crates --include=Cargo.toml` → only `crates/kernel/net/Cargo.toml` and `crates/shared/slab/Cargo.toml`. `crates/kernel/sched/Cargo.toml` and `crates/shared/klog/Cargo.toml` both declare a bare `hosted = []` with no `sync/hosted` forward, and `klog/Cargo.toml` does not even depend on the `sync` crate. So the row's claim that sched and klog "have it" is contradicted; only net and slab do. The underlying point (opt-in per crate, most crates lack it) still holds. |
| `OPEN \| low \| TCP_MAX_WSCALE (14, RFC 7323 ceiling) is enforced on the TCP_REPAIR_OPTIONS path but a peer's advertised scale is taken verbatim from the wire...` | `crates/kernel/net/src/tcp_hdr.rs:173-177` `parse_wscale_option` now does `core::cmp::min(bytes[0], WSCALE_MAX)`. Added by `d4da1b5fa` "feat(net): fast-open option codec" (`git log -S "core::cmp::min(bytes[0], WSCALE_MAX)"`). Both call sites in `tcp_conn/io.rs` go through this function, so the wire value is clamped at both. |
| `OPEN \| low \| Row 103 syslog has its status cell as IMPL without backticks...` | `scratch/syscall-compliance-matrix.md:465` — the `103 \| common \| syslog` row now reads `` \`IMPL\` `` (backticked), matching every other row. Grep for the un-backticked form finds nothing at that row. |
| `OPEN \| med \| Boot smoke NOT taken for this branch: the box was at load average 66...` | Moot — this was a merge-gate note for the `F785` PKRU branch, which has since merged (F785 commits present on `main`, e.g. `crates/arch/hal-x86_64/src/pkru.rs`, `fpu.rs`). Not an actionable open item; the branch it gates no longer exists as a pending merge. |
| `OPEN \| low \| Claim refs are never deleted, by design — they are the record of which numbers were handed out. git branch -a therefore grows one claim/<T><NN> per branch ever created...` | `git branch -a \| grep -c '^  claim/'` → **0**. Claim refs now live under `refs/claims/*` (`git for-each-ref \| grep claim` → 65 hits, all `refs/claims/...`), not `refs/heads` — exactly the alternative the row itself floated ("or move the namespace out of refs/heads"). Already done. |
| `OPEN \| low \| docs/39-build-and-image.md:47,97, docs/29-init-and-userspace.md:29 and docs/29a-userspace-platform.md:162 still describe a vendored musl fork...` | `grep -n musl docs/39-build-and-image.md docs/29-init-and-userspace.md docs/29a-userspace-platform.md` → **zero hits** in all three files. Whole-tree `grep -rl musl docs/` → only `05-pre-mortem.md`, `54-asm-correctness.md`, `15-syscall-abi.md` (already-known-benign per the adjacent already-audited row on this subject). |
| `OPEN \| LOW \| docs/07§8 still documents xtask user, xtask qemu, xtask bench and the musl orchestration...` | `docs/07-toolchain-and-targets.md` `## 8 xtask` (lines 173-186) lists only `kernel/artifacts/rootfs/image/grub/test/conformance/spec-lint/doc-check` — no `user`, no `bench`, no musl orchestration. (One `xtask qemu` reference remains at line 198, but that's inside the frozen `## 9 Test contract`, not `§8`, and isn't musl-related.) |
| `OPEN \| high \| blk_mq_end_request re-dereferences rq after the driver's end_io callback returns, and discards that callback's return value...` | `crates/kernel/modules/src/linux_block/mq/request.rs:101-125` — rewritten. All fields (`status`/`state`/`end_io`) are read *before* calling the callback; the return value now drives `rq_owner_after_end_io`, which only frees when the callback reports `RQ_END_IO_FREE`-equivalent (or there was no callback) and never touches `rq` afterward. `blk_mq_complete_request` (new) likewise reads `q`/`status` before dispatching. Fixed by `eff9d6b4e` "fix(block): honour Linux's completion and page contracts in the module shim" (same commit also fixed already-audited rows 391/429). |

## DUPLICATE

| Row | Duplicates | Note |
|---|---|---|
| `OPEN \| med \| IPV6_JOIN_ANYCAST / IPV6_LEAVE_ANYCAST still route to the multicast helper — no anycast address state...` | The anycast clause of the STALE row above (`IN-PROGRESS B1662`) | Same subject, same current behavior (`sock_opts/sol_ipv6/set.rs:94-95` still sends both to the multicast path); confirmed still true, just filed twice. |

## LIVE (claim still holds — one line each, evidence run)

| Row (opening text) | Evidence |
|---|---|
| `OPEN \| low \| TCP_ZEROCOPY_RECEIVE never sets TCP_CMSG_TS in msg_flags...` | `syscalls/src/tcp_zerocopy/receive.rs:59` `op.msg_flags = 0;` unconditionally, with a comment restating exactly this. |
| `OPEN \| low \| TCP_ZEROCOPY_RECEIVE copies stream bytes into freshly allocated window pages instead of handing over the pages...` | `receive.rs::remap` calls `pmm::setup::alloc_object_frame()` then `copy_nonoverlapping` stream bytes into it — confirmed, not a page donation. |
| `OPEN \| low \| Phantom-test gap in sock_v6.rs and sock/{udp,ops,send}.rs...` | Confirmed for `sock/ops.rs` (`#[cfg(all(test, target_os = "oxide-kernel"))] mod tests`) and `sock/send.rs` (whole file `#[cfg(target_os = "oxide-kernel")]`). Imprecise for `sock_v6.rs`/`sock/udp.rs`: neither carries a target cfg at all and neither has any `#[test]` in it — not a "compiles away silently" phantom, just genuinely untested. Net effect (decision logic untested by a hosted run) is the same. |
| `OPEN \| low \| IP_MULTICAST_ALL now defaults on...we have no host-level multicast gate equivalent...` | `sock_opts/sol_ip/state.rs:26` comment confirms default-on; no host-level unjoined-group drop found. |
| `OPEN \| med \| pmm hosted test swap::tests::final_swap_reference_reclaims_zram_slot fails under a full cargo test --workspace run...` | `cargo test -p pmm swap::tests::final_swap_reference_reclaims_zram_slot` → 1 passed (matches the row's own "passes on `cargo test -p pmm`" half). The workspace-contention half is not cheaply reproducible without a full `cargo test --workspace` run; not re-run here — see UNVERIFIABLE note below on cost. |
| `OPEN \| low \| AF_UNIX poll reports EPOLLIN while the only thing queued is a spent out-of-band record...` | Explicitly marked deliberate/kept in its own text; `unix_sock/tests/oob.rs:160` still pins the `SIOCINQ` discount side. No change found. |
| `OPEN \| low \| IP_BIND_ADDRESS_NO_PORT and IP_LOCAL_PORT_RANGE wiring lives in sock/ops.rs, sock/tcp_lifecycle.rs and sock_v6.rs, all #[cfg(target_os = "oxide-kernel")]...` | Confirmed still target-gated at those call sites; `net::local_port::tests` (12 tests) still the only hosted coverage. |
| `OPEN \| med \| The report's print_vma_addr tail names the backing INODE, not a path...` | `sched/src/signal_report.rs:132` still `klog::write_raw(b" ino "); klog::write_dec_u64(v.ino);` — no path. |
| `OPEN \| low \| vsock_socket_linux_tests::blocked_scalar_io_observes_shutdown_at_retry_boundary was passing vacuously...` | Speculative/no-new-evidence row by its own admission ("nothing audits for it"); no contradicting evidence found either. |
| `OPEN \| low \| Repository comments across crates/kernel/net and crates/kernel/syscalls name and line-cite external implementation source files...~15 further sites remain...` | `grep -rn "af_vsock\|af_unix.c\|sock.h:" crates/kernel/net/src/sock_intr.rs crates/kernel/net/src/vsock_socket.rs crates/kernel/syscalls/src/043_accept.rs crates/kernel/syscalls/src/recvmsg/vsock.rs crates/kernel/syscalls/src/054_setsockopt/vsock.rs` → **15**, exact match. |
| `OPEN \| low \| crates/kernel/net/src/vsock/conn.rs is past the 500-line split cutoff...` | `wc -l` → **509**, exact match to the row's own number. |
| `OPEN \| low \| A watch on a key whose notification pipe has been closed keeps posting into a queue nobody can read...` | `watch_queue/watch.rs:15-16` `struct Watch { pub queue: Arc<WatchQueue>, ... }` — one-directional only; no reverse per-queue watch list found anywhere in `watch_queue/`. |
| `OPEN \| med \| No IPv6 packet forwarding at all: there is no forward_ipv6_in...` | `grep -rn "forward_ipv6\|forward6" crates/kernel/net/src` → zero hits. |
| `OPEN \| low \| IP_ROUTER_ALERT set on a raw IPv6 socket stores the option bit but takes no chain slot...` | `054_setsockopt/ip.rs:78-88` `Action::RouterAlert` still matches only `SockKind::Raw4`. |
| `OPEN \| low \| The loadable-module netif_rx ABI shim delivers a C driver's frame inline on the calling driver's stack instead of queueing it to the per-CPU backlog...` | `linux_netdev/core.rs::netif_rx` (line 124) still calls `stack.deliver_rx_in`/`deliver_rx_ipv6_in`/`deliver_arp_in` directly inline; no backlog enqueue found on this path (B1665's backlog work covered the loopback path, not this one, matching the row's own "last inline receive traversal" framing). |
| `OPEN \| low \| A frame sitting in the receive backlog no longer holds an ingress lease...` | Informational/deliberate; `backlog/tests.rs::frames_queued_for_a_down_interface_are_dropped_at_delivery` still present and passing. |
| `OPEN \| med \| The 16550 FIFO is never enabled — nothing programs FCR...` | `grep -n "FCR\|fifo" crates/drivers/drv-uart-16550/src/lib.rs` → zero hits. |
| `OPEN \| med \| Data segments still carry timestamps keyed on ts_enabled alone...Two more hand-rolled option writers remain...` | Informational, not a defect by its own text; `sack.rs`/`segment.rs` still assemble their own option bytes (duplicate of row 164, see DUPLICATE list in `ledger-audit.md`'s own conventions — noted, not re-filed). |
| `OPEN \| low \| Only the dumping thread's identity is per-thread: every NT_PRSTATUS past the first repeats the process-wide pr_ppid/pr_pgrp/pr_sid/times...` | `fs/src/coredump/elf/notes.rs:81-98` `prstatus(arch, id: &CoreIdentity, t: &CoreThread)` — `id.ppid/pgrp/sid/times` shared across all threads, only `t.tid`/`t.regs`/`t.fpregs` vary. |
| `OPEN \| high \| The ext4 e2fsck tests write ~1.8 GB images to fixed $TMPDIR names...` | `crates/kernel/ext4/tests/balloc_uninit_e2fsck.rs:56,77,136,179,208` still build paths via `std::env::temp_dir()` with fixed basenames (`balloc_uninit_repro.img` etc). |
| `OPEN \| low \| answerback.rs keeps a third module-private SERIAL for its own queue state...` | `crates/drivers/fbcon/src/answerback.rs:155` `static SERIAL: Spinlock<(), TtyClass> = Spinlock::new(());` still present. |
| `OPEN \| low \| ru_utime/ru_stime and times(2)'s tms_utime/tms_stime are tick-sampled per-task counters...` | `procfs/src/pid_stat.rs:26` still derives utime from `sched::clock::ns_to_clk_tck(task.sum_exec_runtime_ns...)`, the sampled counter the row describes; deliberate/negative-result row by its own text. |
| `OPEN \| med \| PKRU is deliberately kept OUT of XCR0...` | `hal-x86_64/src/fpu.rs:38` `XCR0_WANT: u64 = 0b1110_0111` — bit 9 (PKRU) not set. |
| `OPEN \| low \| setup_pku leaves CR4.PKE set on the BSP even in the impossible case where the hardware does not report OSPKE after the write...` | `pkru.rs::setup_pku` still writes CR4 unconditionally, then on OSPKE-check failure just `return`s without unsetting CR4.PKE. |
| `OPEN \| low \| init_pkru_value is settable through set_pkru_init_value but has no debugfs file behind it...` | `grep -rn "pkru" --include=*.rs \| grep -i debugfs` → zero hits. |
| `OPEN \| MED \| The dumper does not stop for a freezer request, only for a pending SIGKILL...` | `fs/src/pipe/ring.rs::write_wait_aborted` still only checks `sched::live::fatal_kill_pending_self()`; no freezer consult found. |
| `OPEN \| low \| try_fill_iter's atomicity guard carries a total <= cap term that is unreachable...` | `pipe/limits.rs::round_pipe_size` still floors at `PIPE_GROW_STEP` (= `PAGE`, matching `PIPE_BUF`); function unchanged, informational row. |
| `OPEN \| low \| crates/shared/kalloc/src/holes.rs (933) and src/tests.rs (651) are over the 500-line split cutoff...` | `wc -l` → **933 / 651**, exact match. |
| `OPEN \| low \| metadata/index.md counters drift behind git and nothing repairs them...` | `tools/next-branch.sh --check` still reports STALE for every counter (`F`, `B`, `D`, `R`, `Z`, `C`), just with different current numbers than the row's example — same defect class, unchanged. |
| `OPEN \| MED \| Docs still reference the deleted crates and the abandoned write-our-own-libc plan...docs/59...docs/00§3...docs/03, docs/52§123...` | **Count moved, still live.** `grep -rn 'crates/user' docs/` now **4 hits / 3 files** (`52a`, `52`, `MANIFEST.md`), down from the row's own recorded 13/8 — partially cleaned since filed, not closed. |
| `OPEN \| med \| POR_EL0 is not saved in or restored from the aarch64 signal frame...` | `hal-aarch64/src/signal/records.rs:63-64` still lists `POE_MAGIC` as rejected. |
| `OPEN \| low \| Only TCR2_EL1.E0POE (EL0 overlay) is set, not TCR2_EL1.POE (EL1 overlay)...` | `hal-aarch64/src/por.rs` only defines/uses `TCR2_EL1_E0POE`; no `TCR2_EL1_POE` (EL1 bit) constant or setter found. |
| `OPEN \| med \| classify_arm_abort maps every DFSC outside 0x04..=0x07 to Protection{access}...` | `mm-pmm/src/user_as/teardown.rs:205-211` — `if (0x04..=0x07).contains(&dfsc) { ... } ` else falls to `Protection{access}` at line 211; unchanged. |
| `OPEN \| med \| FEAT_S1POE could not be exercised on real silicon or emulation: QEMU 9.2.4 implements it on neither cortex-a72 nor max...` | `qemu-system-aarch64 --version` → **9.2.4**, same version cited by the row. |
| `OPEN \| low \| The overstated-IMPL regex matched PAST-TENSE prose...` | Informational/historical, no falsifiable current-state claim beyond the matrix lint existing; not independently re-run. |
| `OPEN \| high \| Process, named because this lane hit it twice in two PRs. A check must be able to OBSERVE the failure mode...` | Process/methodology note, not a code claim; no verification target. |

## UNVERIFIABLE (needs a full workspace run or is a one-off historical observation)

| Row (opening text) | What would settle it |
|---|---|
| `OPEN \| med \| pmm hosted test ... fails under a full cargo test --workspace run (install hosted zram PMM provider: Ebusy) and passes on cargo test -p pmm` | A full `cargo test --workspace` run (not attempted here — expensive and the isolated-pass half is already confirmed true, so re-running isolated proves nothing new). |
| `OPEN \| low \| A qemu-system-x86_64 from another lane was still alive 30+ minutes after start...` | One-time infra observation from a specific box state (B1672); not re-checkable after the fact. |
| The `\| Package \| Red runs \| Status \|` flaky-package table (`modules` 5/10, `klog` 3/10, `sound`/`netlink`/`drv` 2/10, `sysfs`/`nscg`/`fbdev`/`drv-zram`/`drv-virtio-gpu` 1/10, `net` "root-caused in B1683's drop") | Ran `cargo test -p <pkg> --lib` in isolation for all 9 non-fixed rows — **all 9 pass 0-failed, single run each**. Per project rule ("single runs lie about intermittent bugs"), this does NOT disprove the claim: the table's own numbers are from full-workspace parallel runs, which contend for shared global state (driver registries, PMM providers) that an isolated per-package run never exercises. Settling this needs N repeated `cargo test --workspace` runs, not per-package reruns. |
