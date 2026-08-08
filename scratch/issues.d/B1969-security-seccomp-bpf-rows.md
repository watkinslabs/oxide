# B1969 — security matrix rows 317 / 321 / 445

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED 31543903b | MISSING | HIGH | seccomp `SECCOMP_FILTER_FLAG_NEW_LISTENER` failed the install outright, so `SECCOMP_RET_USER_NOTIF` had no supervisor and every notified syscall took the no-listener ENOSYS path — a container runtime that supervises its payload's syscalls could not run at all | listener fd + RECV/SEND/ID_VALID/SET_FLAGS/ADDFD + blocking notification path; 62 hosted tests in `security::seccomp::notif`; ioctl numbers and structure sizes checked against the running reference (RECV 0xc0502100, SEND 0xc0182101, ID_VALID 0x40082102, ADDFD 0x40182103, SET_FLAGS 0x40082104; sizes 80/24/24) | B1969 |
| FIXED 31543903b | DEFECT | MED | the filter chain was walked OLDEST-first, so on a tie the oldest filter's action won; the reference walks newest-first, which is what lets a newly installed supervising filter supervise calls an older one also notifies on | `the_chain_names_the_listener_of_the_filter_that_won`; positive control: removing `.rev()` turns it red | B1969 |
| FIXED 1cfddf8a6 | DEFECT | MED | `landlock_add_rule` accepted a hierarchy rule anchored on a descriptor no path walk reaches (pipe, socket, anonymous-inode fd, non-mountable filesystem) and stored a rule that could never match — the caller believed it had granted an access it had not. Reference answers EBADFD | `only_a_descriptor_reachable_by_a_path_walk_may_anchor_a_rule` + live probes `add_path_pipe_fd` / `add_path_ruleset_fd` in `t_landlock.c`; the running reference returns errno 77 for both | B1969 |
| FIXED 0c134ab71 | MISSING | MED | `kernel.unprivileged_bpf_disabled` gated `bpf(2)` but had no `/proc/sys` leaf, so it could be neither read nor written and a distro `sysctl.d` line for it did nothing | `unprivileged_bpf_may_be_switched_off_for_good_but_only_by_an_administrator`; positive control: deleting the latch clause turns it red | B1969 |
| OPEN | COVERAGE | LOW | seccomp `SECCOMP_GET_NOTIF_SIZES` reported its two structure sizes from arithmetic local to `entry.rs`, a second copy of the wire format. Now derived from the notification module's own constants — recorded because the class (a size computed twice) is worth grepping for elsewhere | `notif::uapi::{NOTIF_BYTES, NOTIF_RESP_BYTES}` are the only definition | B1969 |
| OPEN | MISSING | MED | seccomp notification ids are drawn from one monotonic space per boot rather than a random seed per listener. Unique, which is what the protocol needs, but not the reference's defence in depth — there is no kernel entropy source reachable from `security` (`devfs::misc::random_u64` sits behind a crate this one does not depend on) | `listener.rs` `NEXT_NOTIF_ID` | unclaimed |
| OPEN | MISSING | MED | `verify_socket_filter` is an opcode whitelist with no register or pointer tracking, unlike the cgroup verifiers beside it | `bpf_verify.rs:166-211` | unclaimed |
| OPEN | MISSING | HIGH | 16 of 39 `bpf(2)` commands answer EINVAL (PROG_TEST_RUN, PROG_GET_NEXT_ID, RAW_TRACEPOINT_OPEN, TASK_FD_QUERY, four MAP_*_BATCH, LINK_UPDATE/DETACH/GET_FD_BY_ID/GET_NEXT_ID, ENABLE_STATS, ITER_CREATE, PROG_STREAM_READ_BY_FD, PROG_ASSOC_STRUCT_OPS), so `bpftool` does not work end to end | command dispatch in `security/src/bpf.rs` | unclaimed |
| OPEN | MISSING | MED | `BPF_PROG_TYPE_LSM` is not loadable, so `security::bpf_lsm`'s registration half has no possible source and no program body ever runs on the `file_open` hook it does reach. The hook itself IS called (`257_openat.rs:504`) — the previous "unreachable dead machinery" reading was wrong | `bpf/attr.rs` `prog_type_supported`; call site `257_openat.rs:504` | unclaimed |
| OPEN | INFRA | LOW | `crates/kernel/security/src/bpf.rs` is 524 lines, over the 500-line cap | `wc -l` | unclaimed |
| OPEN | COVERAGE | MED | the seccomp notification's blocking path and the ioctl router's CALL SITE are both in target-gated code, so no hosted test can fail if either is deleted. The decisions each reaches (queue transitions, listener resolution, router predicate, verdict mapping) are all ungated and covered; the two call sites rest on the arch builds and the boot smoke | `016_ioctl/core.rs` router arm; `entry.rs` UserNotif arm | unclaimed |

## Corrected stale claims (worth as much as the fixes)

Row 321's REMAINING list was five-sevenths stale. Verified present today, against
current code: a path-sensitive verifier with a typed register file, stack model,
fixpoint state set, CFG reachability and bounded-loop proof, and helper-argument
typing; four loadable program types, not one; 23 of 39 commands implemented, not
12; program/map/link/BTF id registries, a mountable bpffs with OBJ_PIN/OBJ_GET,
and BTF load/lookup/info; three map types, not one; 167 hosted bpf tests, not 38.

Row 317's "remaining: RET_USER_NOTIF/NEW_LISTENER" was accurate and is now closed.
Row 445's remaining item was an audit-log consumer, which belongs to the Landlock
logging row; the admission gap this lane found (EBADFD) was not listed anywhere.

## Notes on ownership

Three files outside this lane's area were touched, each minimally and for a
reason the owning area could not supply:

- `crates/kernel/sched/src/seccomp_filter.rs` (+1 field): the listener id has to
  travel with the filter, because a chain is copied by value onto TSYNC'd threads
  and forked children. The file exists in `sched` only because the chain lives on
  `Task`; the rule stays in `security`.
- `crates/kernel/vfs/src/fdtable/ops.rs` (+`replace_fd`): the reference's
  `replace_fd`, needed to install a handed-over file AT a chosen descriptor.
- `crates/kernel/procfs/**`: one new `/proc/sys` leaf plus the EPERM-preserving
  handler it needs.
