// `io_uring_register(2)` work functions — module manifest.
//
// The slot file decodes the opcode and arguments and calls exactly one of
// these (docs/53).
//
// Module manifest:
//   tags     — the completion a released tagged resource posts
//   buffers  — buffer registration, tagged registration, updates, cloning
//   files    — file registration, updates, the direct-descriptor window
//   eventfd  — completion-eventfd registration
//   probe    — opcode probing and the feature query
//   rings    — personalities, restrictions, ring enabling, clock, cancel,
//              buffer-group status, cross-ring messages
//   resize   — `IORING_REGISTER_RESIZE_RINGS`: new regions, move, swap
//   mem_region — `IORING_REGISTER_MEM_REGION`: the one region a ring registers
//   napi     — the busy-poll window and the receive queues a wait drives
//   bpf_filter — per-opcode classic-BPF submission filters, ring and task
//   pbuf     — provided-buffer rings
//   iowq     — worker limits and worker processor affinity
//   ring_fds — the calling task's registered-ring array
//   task_restrict — the ring-less form of `IORING_REGISTER_RESTRICTIONS`
//   zcrx     — zero-copy receive registration and its control operations

#[path = "register/tags.rs"]     pub mod tags;
#[path = "register/buffers.rs"]  pub mod buffers;
#[path = "register/files.rs"]    pub mod files;
#[path = "register/eventfd.rs"]  pub mod eventfd;
#[path = "register/probe.rs"]    pub mod probe;
#[path = "register/rings.rs"]    pub mod rings;
#[path = "register/resize.rs"]   pub mod resize;
#[path = "register/mem_region.rs"] pub mod mem_region;
#[path = "register/napi.rs"]     pub mod napi;
#[path = "register/bpf_filter.rs"] pub mod bpf_filter;
#[path = "register/pbuf.rs"]     pub mod pbuf;
#[path = "register/iowq.rs"]     pub mod iowq;
#[path = "register/ring_fds.rs"] pub mod ring_fds;
#[path = "register/task_restrict.rs"] pub mod task_restrict;
#[path = "register/zcrx.rs"] pub mod zcrx;
