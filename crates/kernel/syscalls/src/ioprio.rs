// I/O-priority decision core for slots 251/252.
//
// Linux refs (v7.2.0-rc4):
//   include/uapi/linux/ioprio.h  — IOPRIO_CLASS_*, IOPRIO_WHO_*, the shifts
//   include/linux/ioprio.h       — ioprio_valid, task_nice_ioclass,
//                                  task_nice_ioprio, __get_task_ioprio
//   block/ioprio.c               — ioprio_check_cap, sys_ioprio_{set,get},
//                                  ioprio_best
//
// Deliberately NOT `#![cfg(target_os = "oxide-kernel")]`: the slot files are
// kernel-only, so a `#[cfg(test)] mod tests` inside them compiles out silently.

use syscall::errno::Errno;

/// `IOPRIO_CLASS_SHIFT`.
pub const CLASS_SHIFT: u32 = 13;
/// `IOPRIO_NR_CLASSES`.
pub const NR_CLASSES: i32 = 8;
/// `IOPRIO_CLASS_MASK`.
pub const CLASS_MASK: i32 = NR_CLASSES - 1;
/// `IOPRIO_LEVEL_MASK` — the level is the low THREE bits, not the low 13.
pub const LEVEL_MASK: i32 = 7;

/// `IOPRIO_CLASS_NONE` — never explicitly set; the kernel derives from nice.
pub const CLASS_NONE: i32 = 0;
/// `IOPRIO_CLASS_RT`.
pub const CLASS_RT: i32 = 1;
/// `IOPRIO_CLASS_BE`.
pub const CLASS_BE: i32 = 2;
/// `IOPRIO_CLASS_IDLE`.
pub const CLASS_IDLE: i32 = 3;

/// `IOPRIO_WHO_PROCESS`.
pub const WHO_PROCESS: i32 = 1;
/// `IOPRIO_WHO_PGRP`.
pub const WHO_PGRP: i32 = 2;
/// `IOPRIO_WHO_USER`.
pub const WHO_USER: i32 = 3;

/// `IOPRIO_DEFAULT` = `IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, 0)`, the value a
/// task that never called `ioprio_set(2)` reports.
pub const DEFAULT: i32 = 0;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `IOPRIO_PRIO_CLASS()`.
/// # C: O(1)
pub fn prio_class(ioprio: i32) -> i32 { (ioprio >> CLASS_SHIFT) & CLASS_MASK }

/// `IOPRIO_PRIO_LEVEL()`.
/// # C: O(1)
pub fn prio_level(ioprio: i32) -> i32 { ioprio & LEVEL_MASK }

/// `IOPRIO_PRIO_VALUE()` with `IOPRIO_HINT_NONE`.
/// # C: O(1)
pub fn prio_value(class: i32, level: i32) -> i32 { (class << CLASS_SHIFT) | level }

/// Which capability, if any, the caller must hold for this ioprio.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CapNeed { None, SysAdminOrSysNice }

/// Linux `ioprio_check_cap()` (`block/ioprio.c:33`), split into its decision so
/// the capability lookup stays in the slot. Runs BEFORE `which` is validated,
/// so a bad `which` with an RT ioprio is `-EPERM`, not `-EINVAL`.
/// # C: O(1)
pub fn check_cap(ioprio: i32) -> Result<CapNeed, i64> {
    match prio_class(ioprio) {
        CLASS_RT => Ok(CapNeed::SysAdminOrSysNice),
        CLASS_BE | CLASS_IDLE => Ok(CapNeed::None),
        // IOPRIO_CLASS_NONE carries no level of its own.
        CLASS_NONE => if prio_level(ioprio) != 0 { Err(err(Errno::Einval)) } else { Ok(CapNeed::None) },
        // IOPRIO_CLASS_INVALID and the unassigned classes 4..6.
        _ => Err(err(Errno::Einval)),
    }
}

/// Map `IOPRIO_WHO_*` onto the `getpriority(2)` `PRIO_*` base that
/// `priority_common::for_each_target` speaks. `Err` is the `default:` arm of
/// both ioprio syscalls.
/// # C: O(1)
pub fn who_base(which: i32) -> Result<u64, i64> {
    match which {
        WHO_PROCESS | WHO_PGRP | WHO_USER => Ok((which - 1) as u64),
        _ => Err(err(Errno::Einval)),
    }
}

/// Linux `task_nice_ioclass()`: the class an unset task falls back to.
/// # C: O(1)
pub fn nice_ioclass(policy_is_idle: bool, policy_is_rt_or_dl: bool) -> i32 {
    if policy_is_idle { CLASS_IDLE } else if policy_is_rt_or_dl { CLASS_RT } else { CLASS_BE }
}

/// Linux `task_nice_ioprio()`: `(nice + 20) / 5`.
/// # C: O(1)
pub fn nice_ioprio(nice: i32) -> i32 { (nice + 20) / 5 }

/// Linux `__get_task_ioprio()`: the EFFECTIVE priority. A task whose stored
/// class is `IOPRIO_CLASS_NONE` reports a class+level derived from its
/// scheduling policy and nice value. Used by the PGRP/USER arms of
/// `ioprio_get(2)`; `IOPRIO_WHO_PROCESS` reports the RAW stored value instead
/// (`get_task_raw_ioprio`), so userspace can still see "never set".
/// # C: O(1)
pub fn effective(stored: i32, nice: i32, policy_is_idle: bool, policy_is_rt_or_dl: bool) -> i32 {
    if prio_class(stored) == CLASS_NONE {
        return prio_value(nice_ioclass(policy_is_idle, policy_is_rt_or_dl), nice_ioprio(nice));
    }
    stored
}

/// Linux `ioprio_best()`: `min()` over `unsigned short`. Lower class number and
/// lower level are both "better", and the packing makes a plain minimum do
/// both — but only over EFFECTIVE values, which never carry
/// `IOPRIO_CLASS_NONE`.
/// # C: O(1)
pub fn best(a: i32, b: i32) -> i32 {
    core::cmp::min(a as u16, b as u16) as i32
}

#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "ioprio/tests.rs"]
mod tests;
