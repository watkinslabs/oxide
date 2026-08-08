// `bpf(2)` attribute validation. Module manifest; every ladder lives in the
// child that owns its command.
//
// No target gate anywhere in this subtree: every rule below is exercised by
// hosted `cargo test -p security` (see `attr/tests.rs`). Slot-file modules
// under `crates/kernel/syscalls/src/` are `#[cfg(target_os = "oxide-kernel")]`
// and silently compile their tests out, so decision logic must live here.
//
//   wire.rs        the attr size/tail-zero protocol and CHECK_ATTR
//   unpriv.rs      the `unprivileged_bpf_disabled` cell and its latch
//   caps.rs        the per-call capability snapshot and prog-type classes
//   map_create.rs  MAP_CREATE field and flag validation
//   map_elem.rs    element-op access modes and flag validation
//   prog_cmd.rs    PROG_LOAD/ATTACH/QUERY/BIND_MAP and LINK_CREATE

#[cfg_attr(not(test), allow(unused_imports))]
use super::uapi;
#[cfg_attr(not(test), allow(unused_imports))]
use syscall::errno::Errno;

#[path = "attr/wire.rs"]
mod wire;
#[path = "attr/unpriv.rs"]
mod unpriv;
#[path = "attr/caps.rs"]
mod caps;
#[path = "attr/map_create.rs"]
mod map_create;
#[path = "attr/map_elem.rs"]
mod map_elem;
#[path = "attr/prog_cmd.rs"]
mod prog_cmd;

pub use wire::{Attr, check_attr, cmd_is_known, size_protocol, tail_verdict};
pub use unpriv::{
    UNPRIV_BPF_BOUNDS, set_unpriv_bpf_disabled, unpriv_bpf_disabled,
    unpriv_bpf_disabled_value, unpriv_write_verdict, write_unpriv_bpf_disabled,
};
pub use caps::{Caps, is_net_admin_prog_type, is_perfmon_prog_type, prog_type_supported};
pub use map_create::{MapCreate, get_file_flag, map_create_check};
pub use map_elem::{
    Access, check_op_flags, check_update_flags, map_access_ok, update_presence_verdict,
};
pub use prog_cmd::{
    LinkCreate, ProgBindMap, ProgLoad, ProgQuery, attach_type_to_prog_type,
    cgroup_link_flags_check, expected_attach_type_check, link_create_check,
    prog_attach_check, prog_attach_verdict, prog_bind_map_check, prog_get_fd_by_id_check,
    prog_load_check, prog_query_check,
};

#[cfg(test)]
mod tests;
