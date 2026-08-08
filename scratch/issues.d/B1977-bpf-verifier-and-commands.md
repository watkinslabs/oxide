# B1977 — `bpf(2)` command surface: what the newly-implemented commands still cannot reach

The 16 previously-unimplemented `bpf(2)` commands now have their real
admission ladders and dispatch entries. Several end on the reference's own
refusal because the object they operate on does not exist in this kernel
yet. Each such absence is a row below; none of them is a settled state.

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| OPEN | MISSING | high | No BPF iterator link type exists, so `BPF_ITER_CREATE` can never succeed. Every reachable input lands on the ladder's last rung — "this link is not an iterator link" `-EINVAL` — because the only link kinds this kernel mints are cgroup and LSM links. Needs iterator link targets (task/map/prog/… seq-file iterators) and the anon-inode seq-file fd `bpf_iter_new_fd()` hands back. | `bpf::command::link_cmd::tests::each_link_command_refuses_an_unsupported_kind_with_its_own_errno` pins `iter_verdict` returning `EINVAL` for both existing kinds; the positive control (making `LinkKind::Cgroup` an iterator link) goes RED. | NEXT |
| OPEN | MISSING | high | No tracepoint registry, so `BPF_RAW_TRACEPOINT_OPEN` resolves no name and every well-formed request is `-ENOENT`. The rungs above it are real: the program type gate (RAW_TRACEPOINT / RAW_TRACEPOINT_WRITABLE take a user name; TRACING/EXT/LSM must not supply one; anything else is `EINVAL`) and the `EFAULT` on a bad name pointer. Needs a `bpf_get_raw_tracepoint()`-equivalent registry and the raw-tracepoint link object. | `bpf::command::trace::tests::no_tracepoint_name_resolves_in_this_kernel` and `only_tracepoint_and_load_time_attached_program_types_may_open_one`. | NEXT |
| OPEN | MISSING | high | No perf-event descriptors and no raw-tracepoint links, so `BPF_TASK_FD_QUERY` can describe nothing and every descriptor that survives the pid/fd lookup is `-ENOTSUPP` (524). The pid → `ENOENT`, fd → `EBADF` and `CAP_SYS_ADMIN` → `EPERM` rungs are real and ordered. Needs perf events, plus the raw-tracepoint link from the row above, plus the `bpf_task_fd_query_copy()` write-back (prog_id, fd_type, probe_offset, probe_addr, tracepoint name into `task_fd_query.buf`). | `bpf::command::trace::tests::an_undescribable_descriptor_is_enotsupp_not_eopnotsupp`, `task_fd_query_checks_cap_sys_admin_before_flags_and_pid`. | NEXT |
| OPEN | MISSING | med | No `BPF_MAP_TYPE_STRUCT_OPS` map type, so `BPF_PROG_ASSOC_STRUCT_OPS` always ends on "that map is not a struct_ops map" `-EINVAL`. The flags gate, the prog-fd lookup and the "a STRUCT_OPS program may not itself be associated" `EINVAL` are real. | `bpf::command::struct_ops::tests::no_creatable_map_type_satisfies_the_association`. | NEXT |
| OPEN | MISSING | med | Program objects carry no output stream buffers, so `BPF_PROG_STREAM_READ_BY_FD` always reads 0 bytes. That is the reference's answer for an empty stream, but it means a program's runtime diagnostics are never collected: nothing writes into the streams because there is no `bpf_stream_printk`-equivalent sink on the run path. Needs the two per-program ring buffers plus the writer. | `bpf::command::stream::tests::only_the_two_named_streams_can_be_drained` (an unknown id is `ENOENT`, matching the reference's "no such stream"). | NEXT |
| OPEN | MISSING | med | `BPF_ENABLE_STATS` switches run-time statistics on and refcounts the switch correctly, but nothing accumulates them and nothing reports them. Linux gates per-run `run_cnt`/`run_time_ns` accounting on the switch and surfaces it through `bpf_prog_info`. Needs (a) the accumulation in the program run path and (b) `run_cnt`/`run_time_ns` in the `OBJ_GET_INFO_BY_FD` program-info encoder — the latter lives in `bpf/btf/info.rs`, outside this lane's file ownership. | `bpf::command::stats::tests::the_last_dropped_hold_turns_collection_off` pins the refcount; the count has no reader outside its module, which is the gap. | NEXT |
| OPEN | DEFECT | med | `BPF_PROG_TEST_RUN` on an skb context runs a flat packet: the reference splits input past the linear region (`PAGE_SIZE - headroom - tailroom`) into `MAX_SKB_FRAGS` page frags, so a program observes `data_end - data` covering the linear part only, while `skb->len` covers everything. Here `data_end - data` covers the whole input. Input past the total frag budget is `-ENOMEM`, matching the reference's exhaustion path, but the split itself is not modelled. | `bpf::command::test_run::tests::an_skb_run_needs_at_least_a_link_layer_header` pins the `ETH_HLEN` floor and the `TEST_RUN_DATA_MAX` ceiling; nothing yet pins the linear/frag boundary because there is no non-linear frame here. | NEXT |
| OPEN | DEFECT | low | `BPF_PROG_TEST_RUN` accepts `BPF_F_TEST_SKB_CHECKSUM_COMPLETE` but does not act on it: the reference computes the frame checksum before the run and re-checks it after, answering `-EBADMSG` when a program changed the payload without fixing the checksum. Here the flag is admitted and ignored, so that `EBADMSG` can never be observed. | `bpf::command::test_run::tests::an_skb_run_accepts_only_the_checksum_flag_and_no_cpu_or_batch` pins the admission; nothing pins the post-run verification because it does not exist. | NEXT |
| OPEN | DEFECT | med | `BPF_MAP_GET_NEXT_ID` was missing the `start_id >= INT_MAX` `-EINVAL`, so a caller passing a silly starting id got `EPERM` (or a walk) instead. Fixed in this branch by routing every object kind's `GET_NEXT_ID` through one ladder (`bpf/cmd/next_id.rs`); MAP and PROG and LINK now share it. | `bpf::command::next_id::tests::start_id_at_or_above_int_max_is_einval_before_the_capability`; positive control (deleting the bound) goes RED. | Chris Watkins |
| OPEN | DEFECT | low | `BPF_BTF_GET_NEXT_ID` still carries its own copy of the `GET_NEXT_ID` ladder in `bpf/btf/attr.rs` + `bpf/btf/command.rs` rather than calling the shared one. The two agree today, which is precisely why the duplication is dangerous — the MAP copy had already drifted (row above). Needs `btf::get_next_id` to delegate to `cmd::next_id::get_next_id` with `object::next_id` as its walker. Those files were outside this lane's ownership. | Compare `bpf/btf/attr.rs::get_next_id` against `bpf/cmd/next_id.rs::admit`: same four decisions, written twice. | NEXT |
| OPEN | INFRA | low | `bpf/link.rs` exports `cgroup_link_by_id`, which is now a one-line alias for the general `link_by_id` — the cgroup ordering anchors re-check the link kind themselves. The name says "cgroup" but the lookup is over the one link registry. Renaming it means touching `bpf/prog/attach.rs`, outside this lane's ownership. | `bpf/link.rs`: `pub(crate) fn cgroup_link_by_id(id: u32) -> Result<InodeRef, Errno> { link_by_id(id) }`. | NEXT |
| OPEN | COVERAGE | med | The batch commands' loop bodies (`lookup_batch`, `update_batch`, `delete_batch` in `bpf/cmd/batch.rs`) have no hosted test that drives them against a real map: they need a live `BpfMapInode`, which needs `sched::current()` for the descriptor resolution the command starts from. Their admission ladder, access modes, flag masks, address arithmetic and count write-back are all covered; the per-element walk, the skip-on-racing-delete and the end-of-map `ENOENT` are not. Needs the map-object half of the hosted fixture the element tests use. | `bpf::command::batch::tests` covers 8 decisions; `grep -c 'fn lookup_batch'` shows the walk itself has none. | NEXT |

## What the ladders now decide, and why the ordering is the load-bearing part

Every command's refusal order is pinned by a test whose positive control was
confirmed RED. The orderings that are easy to get backwards, and that the
tests hold:

- `GET_NEXT_ID`: zero-tail **and** the `INT_MAX` bound are one `EINVAL`
  decided **before** the capability, so an unprivileged malformed request is
  `EINVAL`, not `EPERM`.
- `ENABLE_STATS`: tail → capability → statistic type. An unprivileged caller
  naming an unknown statistic sees `EPERM`.
- `TASK_FD_QUERY`: tail → capability → `flags` → pid → fd. The capability
  precedes even the `flags` check.
- `PROG_TEST_RUN`: tail → the two context pairing rules → prog fd → runner.
  A bad pairing with a closed descriptor is `EINVAL`, not `EBADF`.
- `LINK_UPDATE`: tail → flag mask → link fd → new prog fd → old prog fd. A
  nonzero `old_prog_fd` without `BPF_F_REPLACE` is diagnosed **after** the new
  program's descriptor is resolved.
- The three link commands refuse an unsupported link kind with three
  *different* errnos: detach `EOPNOTSUPP` (95), update `EINVAL`, iter
  `EINVAL`. `ENOTSUPP` (524) is none of them, and is what `PROG_TEST_RUN`,
  `TASK_FD_QUERY` and a map type with no batch operation return instead.

## Errno additions

`Errno::Enotsupp = 524` and `Errno::Enolink = 67` were added to
`crates/kernel/syscall/src/errno.rs`. 524 is a kernel-internal number that
several `bpf(2)` commands return verbatim to userspace; it is distinct from
`Eopnotsupp` (95) and the two are not interchangeable.
