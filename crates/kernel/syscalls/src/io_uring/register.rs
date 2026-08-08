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
//   pbuf     — provided-buffer rings

#[path = "register/tags.rs"]    pub mod tags;
#[path = "register/buffers.rs"] pub mod buffers;
#[path = "register/files.rs"]   pub mod files;
#[path = "register/eventfd.rs"] pub mod eventfd;
#[path = "register/probe.rs"]   pub mod probe;
#[path = "register/rings.rs"]   pub mod rings;
#[path = "register/pbuf.rs"]    pub mod pbuf;
