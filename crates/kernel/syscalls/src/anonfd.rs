// Anonymous-fd creators (eventfd2, memfd_create) extracted from
// syscall_glue_fs.rs to keep that file under the 1000-line cap.
// Handlers moved to per-file modules (docs/53 §0): 290_eventfd2.rs, 319_memfd_create.rs.

#![cfg(target_os = "oxide-kernel")]
