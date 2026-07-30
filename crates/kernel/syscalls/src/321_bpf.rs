// 321 bpf — pathname-bearing BPF object commands (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `bpf(2)` slot 321. OBJ_PIN and OBJ_GET alone need VFS pathname resolution;
/// all remaining commands stay in the security work owner. # C: O(path walk)
pub fn sys_bpf(args: &SyscallArgs) -> i64 {
    match security::bpf::object_path_command(args) {
        Some(security::bpf::uapi::cmd::OBJ_PIN) => obj_pin(args),
        Some(security::bpf::uapi::cmd::OBJ_GET) => obj_get(args),
        _ => security::bpf::sys_bpf(args),
    }
}

fn obj_pin(args: &SyscallArgs) -> i64 {
    let ptr = match security::bpf::obj_pin_path(args) {
        Ok(ptr) => ptr, Err(e) => return errno(e),
    };
    let raw = match crate::namei_common::read_user_path(ptr) {
        Ok(raw) => raw, Err(rv) => return rv,
    };
    let (parent, name) = match crate::namei_common::resolve_create_parent_at(
        crate::pathresolve::AT_FDCWD, &raw,
    ) {
        Ok(target) => target, Err(rv) => return rv,
    };
    match security::bpf::obj_pin(args, &parent, &name) {
        Ok(rv) => rv, Err(e) => errno(e),
    }
}

fn obj_get(args: &SyscallArgs) -> i64 {
    let ptr = match security::bpf::obj_get_path(args) {
        Ok(ptr) => ptr, Err(e) => return errno(e),
    };
    let object = match crate::pathresolve::resolve_at_lookup(
        crate::pathresolve::AT_FDCWD, ptr, vfs::LookupFlags::default(),
    ) {
        Ok(object) => object, Err(rv) => return rv,
    };
    match security::bpf::obj_get(args, &object) {
        Ok(rv) => rv, Err(e) => errno(e),
    }
}

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }
