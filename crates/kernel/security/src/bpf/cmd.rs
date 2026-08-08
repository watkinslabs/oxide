// One module per `bpf(2)` command whose object is not owned by `prog.rs`,
// `map.rs` or `btf.rs`. Module manifest; no policy lives here.
//
// Every decision ladder below sits in an ungated module with its own
// hosted tests: slot files under `crates/kernel/syscalls/src/` are
// `#[cfg(target_os = "oxide-kernel")]` and compile their tests out.
//
//   objfd.rs      descriptor→object resolution shared by the commands here
//   next_id.rs    the one `BPF_OBJ_GET_NEXT_ID` ladder, walker supplied
//   link_cmd.rs   LINK_GET_FD_BY_ID / LINK_DETACH / LINK_UPDATE / ITER_CREATE
//   stats.rs      ENABLE_STATS and the refcounted run-time-stats fd
//   batch.rs      the four MAP_*_BATCH commands over the single-element ops
//   test_run.rs   PROG_TEST_RUN dispatch and the skb-context runner
//   skb_ctx.rs    the `__sk_buff` in/out conversion PROG_TEST_RUN performs
//   trace.rs      RAW_TRACEPOINT_OPEN and TASK_FD_QUERY
//   stream.rs     PROG_STREAM_READ_BY_FD
//   struct_ops.rs PROG_ASSOC_STRUCT_OPS

#[path = "cmd/objfd.rs"]
pub(super) mod objfd;
#[path = "cmd/next_id.rs"]
pub(super) mod next_id;
#[path = "cmd/link_cmd.rs"]
pub(super) mod link_cmd;
#[path = "cmd/stats.rs"]
pub(super) mod stats;
#[path = "cmd/batch.rs"]
pub(super) mod batch;
#[path = "cmd/test_run.rs"]
pub(super) mod test_run;
#[path = "cmd/skb_ctx.rs"]
pub(super) mod skb_ctx;
#[path = "cmd/trace.rs"]
pub(super) mod trace;
#[path = "cmd/stream.rs"]
pub(super) mod stream;
#[path = "cmd/struct_ops.rs"]
pub(super) mod struct_ops;
