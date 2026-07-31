// Syscall-side I/O-priority rules for slots 251/252: the capability ladder
// and the `which` decoding.
//
// The packed-value ABI, the nice-derived fallback and the fold used to pick
// the best of a target set live in `sched::ioprio`, because the block layer
// needs them too — a second copy here would be a split source of truth for
// the same field. They are re-exported so the slot files and this module's
// tests have one path to them.
//
// Deliberately NOT `#![cfg(target_os = "oxide-kernel")]`: the slot files are
// kernel-only, so a `#[cfg(test)] mod tests` inside them compiles out silently.

use syscall::errno::Errno;

pub use sched::ioprio::{
    best, effective, prio_class, prio_level, prio_valid, prio_value, CLASS_BE, CLASS_IDLE,
    CLASS_NONE, CLASS_RT, CLASS_SHIFT, DEFAULT,
};

/// Number of encodable classes; classes above `CLASS_IDLE` are undefined.
pub const NR_CLASSES: u32 = 8;
/// Class field mask, applied after shifting.
pub const CLASS_MASK: u32 = NR_CLASSES - 1;
/// Level field mask — the low THREE bits, not the low 13.
pub const LEVEL_MASK: u32 = 7;

/// `IOPRIO_WHO_PROCESS`.
pub const WHO_PROCESS: i32 = 1;
/// `IOPRIO_WHO_PGRP`.
pub const WHO_PGRP: i32 = 2;
/// `IOPRIO_WHO_USER`.
pub const WHO_USER: i32 = 3;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Which capability, if any, the caller must hold for this ioprio.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CapNeed { None, SysAdminOrSysNice }

/// The capability ladder, split from the capability lookup so the decision is
/// testable. It runs BEFORE `which` is validated, so a bad `which` combined
/// with an RT priority reports EPERM, not EINVAL.
///
/// The real-time class needs privilege; best-effort and idle need none; the
/// unset class carries no level of its own, so a non-zero level with it is
/// EINVAL, as are the undefined classes above idle.
/// # C: O(1)
pub fn check_cap(ioprio: i32) -> Result<CapNeed, i64> {
    match prio_class(ioprio) {
        CLASS_RT => Ok(CapNeed::SysAdminOrSysNice),
        CLASS_BE | CLASS_IDLE => Ok(CapNeed::None),
        CLASS_NONE => if prio_level(ioprio) != 0 { Err(err(Errno::Einval)) } else { Ok(CapNeed::None) },
        _ => Err(err(Errno::Einval)),
    }
}

/// Map `IOPRIO_WHO_*` onto the `getpriority(2)` `PRIO_*` base that
/// `priority_common::for_each_target` speaks. `Err` is the default arm of
/// both ioprio syscalls.
/// # C: O(1)
pub fn who_base(which: i32) -> Result<u64, i64> {
    match which {
        WHO_PROCESS | WHO_PGRP | WHO_USER => Ok((which - 1) as u64),
        _ => Err(err(Errno::Einval)),
    }
}

/// The class an unset task falls back to, from its scheduling policy.
/// # C: O(1)
pub fn nice_ioclass(policy_is_idle: bool, policy_is_rt_or_dl: bool) -> i32 {
    sched::ioprio::nice_to_class(policy_is_idle, policy_is_rt_or_dl) as i32
}

/// The level an unset task falls back to, from its nice value.
/// # C: O(1)
pub fn nice_ioprio(nice: i32) -> i32 { sched::ioprio::nice_to_level(nice) as i32 }

#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "ioprio/tests.rs"]
mod tests;
